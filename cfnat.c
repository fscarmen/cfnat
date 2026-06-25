#define CFNAT_VERSION "0.0.10"

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <wininet.h>
#include <io.h>
#include <locale.h>
#else
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif
#ifdef __APPLE__
#include <sys/event.h>
#include <sys/types.h>
#endif
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#define close closesocket
#define SHUT_RDWR SD_BOTH
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
typedef SOCKET socket_t;
static int cfnat_socket_valid(socket_t s) { return s != INVALID_SOCKET; }
static int cfnat_socket_invalid(socket_t s) { return s == INVALID_SOCKET; }
#else
typedef int socket_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
static int cfnat_socket_valid(socket_t s) { return s >= 0; }
static int cfnat_socket_invalid(socket_t s) { return s < 0; }
#endif

#define MAX_IP_LEN 64
#define MAX_COLO_LEN 8
#define MAX_REGION_LEN 64
#define MAX_CITY_LEN 64
#define MAX_LINE 512
#define COPY_BUF_SIZE 16384
#define MAX_ADDR_LEN 128
#define MAX_NAME_LEN 64
#define MAX_DOMAIN_LEN 256
#define MAX_RESOLVER_LEN 64


static const char *DEFAULT_BAIDU_DOMAIN = "cloudnproxy.baidu.com";
static const int DEFAULT_BAIDU_PORT = 443;
static const char *DEFAULT_BAIDU_SCAN_TARGET = "myip.ipip.net:80";
static const int DEFAULT_BAIDU_IPNUM = 12;
static const char *IPS_V4_URLS[] = {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/ips-v4.txt",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/ips-v4.txt",
    NULL
};

static const char *IPS_V6_URLS[] = {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/ips-v6.txt",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/ips-v6.txt",
    NULL
};

static const char *LOC_URLS[] = {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/locations.json",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/locations.json",
    NULL
};


typedef enum {
    LOG_SILENT = 0,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} LogLevel;

typedef struct {
    char colo[128], domain[256], log_name[16];
    char baidu_domain[MAX_DOMAIN_LEN], baidu_scan_target[MAX_ADDR_LEN];
    char direct_listen[MAX_ADDR_LEN], baidu_listen[MAX_ADDR_LEN];
    int code, delay_ms, ipnum, ips_type, num, port, http_port, random_mode, task, health_log;
    int use_baidu_proxy, baidu_port, baidu_ipnum;
    LogLevel log_level;
} Config;

typedef struct {
    char iata[MAX_COLO_LEN], region[MAX_REGION_LEN], city[MAX_CITY_LEN];
} Location;

typedef struct {
    char ip[MAX_IP_LEN], data_center[MAX_COLO_LEN], region[MAX_REGION_LEN], city[MAX_CITY_LEN];
    int latency_ms, loss_rate, probe_count, success_count;
    /* P0-EWMA: 指数加权移动平均延迟、抖动、连续失败次数 */
    int ewma_latency;
    int jitter_ms;
    int consecutive_fail;
} Result;

typedef struct {
    Result *items;
    size_t len, cap;
    pthread_mutex_t mu;
} ResultList;

typedef struct {
    char **items;
    size_t len, cap;
} StringList;

typedef struct BaiduProxyPool BaiduProxyPool;

/* ── CidrList 惰性展开 ─────────────────────────────────────── */
/* 只存 CIDR 范围，不展开具体 IP，支持前缀和 + 二分查找 */
typedef struct {
    uint32_t base;      /* 网络号（主机字节序） */
    uint32_t count;     /* 该 CIDR 包含的 IP 数量 */
    int prefix;         /* 前缀长度 */
} CidrEntry;

typedef struct {
    CidrEntry *entries;
    uint64_t *prefix_sum;  /* 前缀和数组，prefix_sum[i] = sum(entries[0..i].count) */
    size_t len, cap;
    uint64_t total_ips;    /* 所有 CIDR 的 IP 总数 */
    int random_mode;       /* 是否随机抽样 */
} CidrList;

typedef struct {
    char **ips;
    CidrList *cidrs;    /* v0.0.11: CIDR 惰性展开，NULL 时回退到 ips */
    size_t total;
    atomic_size_t index;
    atomic_size_t completed;
    atomic_size_t connect_fail;
    atomic_size_t header_fail;
    atomic_size_t cfray_miss;
    atomic_size_t colo_skip;
    long scan_start_ms;
    ResultList *results;
    Config *cfg;
    BaiduProxyPool *proxy_pool;
} ScanCtx;

/* ── EventLoop 抽象层 ──────────────────────────────────────── */
static void warn_msg(const char *fmt, ...);
static void debug_msg(const char *fmt, ...);
/* 事件驱动 I/O 抽象，Linux 用 epoll，macOS 用 kqueue，其他用 select() 回退 */

#define EV_READ  1
#define EV_WRITE 2

struct evloop_event {
    socket_t fd;
    int events;   /* EV_READ | EV_WRITE */
};

typedef struct {
    int epoll_fd;   /* Linux: epoll fd; macOS: kqueue fd; <0 = select fallback */
} EventLoop;

/* 创建事件循环实例 */
static EventLoop evloop_create(void) {
    EventLoop el;
    el.epoll_fd = -1;
#if defined(__linux__)
    el.epoll_fd = epoll_create1(0);
    if (el.epoll_fd < 0) {
        warn_msg("epoll_create1 失败 (%s)，回退到 select()", strerror(errno));
    }
#elif defined(__APPLE__)
    el.epoll_fd = kqueue();
    if (el.epoll_fd < 0) {
        warn_msg("kqueue 失败 (%s)，回退到 select()", strerror(errno));
    }
#endif
    return el;
}

/* 销毁事件循环 */
static void evloop_destroy(EventLoop *el) {
    if (!el) return;
#if defined(__linux__) || defined(__APPLE__)
    if (el->epoll_fd >= 0) {
        close(el->epoll_fd);
        el->epoll_fd = -1;
    }
#else
    (void)el;
#endif
}

/* 注册 fd 的可读/可写事件 */
static int evloop_add(EventLoop *el, socket_t fd, int events) {
    if (!el) return -1;
#if defined(__linux__)
    if (el->epoll_fd >= 0) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = fd;
        if (events & EV_READ)  ev.events |= EPOLLIN;
        if (events & EV_WRITE) ev.events |= EPOLLOUT;
        ev.events |= EPOLLET;  /* 边缘触发，配合非阻塞 I/O */
        return epoll_ctl(el->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    }
#elif defined(__APPLE__)
    if (el->epoll_fd >= 0) {
        struct kevent kev[2];
        int n = 0;
        if (events & EV_READ) {
            EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
        }
        if (events & EV_WRITE) {
            EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
        }
        return kevent(el->epoll_fd, kev, n, NULL, 0, NULL);
    }
#endif
    /* select fallback: 无需注册，wait 时动态构造 fd_set */
    (void)fd;
    (void)events;
    return 0;
}

/* 从事件循环中移除 fd */
static int evloop_del(EventLoop *el, socket_t fd) {
    if (!el) return -1;
#if defined(__linux__)
    if (el->epoll_fd >= 0) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        return epoll_ctl(el->epoll_fd, EPOLL_CTL_DEL, fd, &ev);
    }
#elif defined(__APPLE__)
    if (el->epoll_fd >= 0) {
        struct kevent kev[2];
        int n = 0;
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        return kevent(el->epoll_fd, kev, n, NULL, 0, NULL);
    }
#endif
    (void)fd;
    return 0;
}

/* select() 回退实现 */
static int evloop_wait_select(struct evloop_event *evs, int maxevents, int timeout_ms) {
    (void)evs;
    (void)maxevents;
    (void)timeout_ms;
    return -1;
}

/* 等待事件，返回就绪 fd 数量和具体事件 */
static int evloop_wait(EventLoop *el, struct evloop_event *evs, int maxevents, int timeout_ms) {
    if (!el || !evs || maxevents <= 0) return -1;
#if defined(__linux__)
    if (el->epoll_fd >= 0) {
        struct epoll_event epevs[64];
        int n = epoll_wait(el->epoll_fd, epevs, maxevents > 64 ? 64 : maxevents, timeout_ms);
        if (n < 0) return -1;
        for (int i = 0; i < n && i < maxevents; i++) {
            evs[i].fd = epevs[i].data.fd;
            evs[i].events = 0;
            if (epevs[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) evs[i].events |= EV_READ;
            if (epevs[i].events & EPOLLOUT) evs[i].events |= EV_WRITE;
        }
        return n;
    }
#elif defined(__APPLE__)
    if (el->epoll_fd >= 0) {
        struct kevent kevs[64];
        struct timespec ts;
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        int n = kevent(el->epoll_fd, NULL, 0, kevs, maxevents > 64 ? 64 : maxevents, timeout_ms >= 0 ? &ts : NULL);
        if (n < 0) return -1;
        for (int i = 0; i < n && i < maxevents; i++) {
            evs[i].fd = (socket_t)(intptr_t)kevs[i].ident;
            evs[i].events = 0;
            if (kevs[i].filter == EVFILT_READ)  evs[i].events |= EV_READ;
            if (kevs[i].filter == EVFILT_WRITE) evs[i].events |= EV_WRITE;
        }
        return n;
    }
#endif
    /* select fallback: 返回 -1 让调用方使用自己的 select 逻辑 */
    return evloop_wait_select(evs, maxevents, timeout_ms);
}

/* ── EventLoop 抽象层结束 ──────────────────────────────────── */

static long now_ms(void);
static void log_msg(const char *fmt, ...);
static void trim_line(char *s);
static uint32_t ipv4_to_u32(const char *s);
static void u32_to_ipv4(uint32_t v, char *out, size_t sz);
/* ── CidrList 函数实现 ──────────────────────────────────────── */

/* 添加 CIDR 条目 */
static int cidrlist_add(CidrList *cl, uint32_t base, uint32_t count, int prefix) {
    if (!cl) return -1;
    if (cl->len == cl->cap) {
        size_t nc = cl->cap ? cl->cap * 2 : 64;
        CidrEntry *ne = realloc(cl->entries, nc * sizeof(CidrEntry));
        if (!ne) return -1;
        cl->entries = ne;
        uint64_t *np = realloc(cl->prefix_sum, nc * sizeof(uint64_t));
        if (!np) return -1;
        cl->prefix_sum = np;
        cl->cap = nc;
    }
    cl->entries[cl->len].base = base;
    cl->entries[cl->len].count = count;
    cl->entries[cl->len].prefix = prefix;
    cl->total_ips += count;
    cl->prefix_sum[cl->len] = cl->total_ips;  /* 前缀和 */
    cl->len++;
    return 0;
}

/* 获取总 IP 数 */
static uint64_t cidrlist_total(CidrList *cl) {
    return cl ? cl->total_ips : 0;
}

/* 按全局索引惰性生成 IP（二分查找定位 CIDR 条目） */
static int cidrlist_get_ip(CidrList *cl, size_t global_idx, char *out, size_t outsz) {
    if (!cl || !out || outsz == 0 || global_idx >= cl->total_ips) return -1;
    /* 二分查找定位 CIDR 条目 */
    size_t lo = 0, hi = cl->len;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (cl->prefix_sum[mid] <= global_idx)
            lo = mid + 1;
        else
            hi = mid;
    }
    /* lo 即为目标条目索引 */
    uint64_t prev = lo > 0 ? cl->prefix_sum[lo - 1] : 0;
    uint32_t offset = (uint32_t)(global_idx - prev);
    u32_to_ipv4(cl->entries[lo].base + offset, out, outsz);
    return 0;
}

/* 释放 CIDR 列表 */
static void cidrlist_destroy(CidrList *cl) {
    if (!cl) return;
    free(cl->entries);
    free(cl->prefix_sum);
    memset(cl, 0, sizeof(*cl));
}

/* 从文件加载 CIDR 列表（替换 load_ip_list） */
static CidrList load_cidr_list(const char *filename, int random_mode) {
    CidrList cl = {0};
    cl.random_mode = random_mode;
    FILE *f = fopen(filename, "r");
    if (!f) return cl;
    log_msg("正在读取 %s，模式：%s", filename, random_mode ? "CIDR随机抽样" : "惰性展开CIDR");
    char line[MAX_LINE];
    long start_ms = now_ms();
    size_t cidr_count = 0;
    (void)cidr_count;
    while (fgets(line, sizeof(line), f)) {
        trim_line(line);
        if (!line[0]) continue;
        char *slash = strchr(line, '/');
        if (!slash) {
            /* 单个 IP，当作 /32 处理 */
            uint32_t ip = ipv4_to_u32(line);
            if (ip == 0) continue;
            cidrlist_add(&cl, ip, 1, 32);
            cidr_count++;
            continue;
        }
        *slash = 0;
        int prefix = atoi(slash + 1);
        uint32_t base = ipv4_to_u32(line);
        if (base == 0 || prefix < 0 || prefix > 32) continue;
        uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
        uint32_t start = base & mask;
        uint32_t count = prefix == 32 ? 1u : (1u << (32 - prefix));
        cidrlist_add(&cl, start, count, prefix);
        cidr_count++;
    }
    fclose(f);
    log_msg("CIDR 列表加载完成: %zu 个 CIDR 条目，共 %llu 个候选 IP，耗时 %ld 秒",
            cl.len, (unsigned long long)cl.total_ips, (now_ms() - start_ms) / 1000);
    return cl;
}

/* ── CidrList 结束 ──────────────────────────────────────────── */

typedef struct {
    char mode[MAX_NAME_LEN];
    char addr[MAX_ADDR_LEN];
    int use_baidu_proxy;
} CarrierListenSpec;

typedef struct {
    char addr[MAX_ADDR_LEN];
    atomic_int active;
    atomic_int failures;
    atomic_long ewma_ms;
} BaiduProxyNode;

struct BaiduProxyPool {
    char name[MAX_NAME_LEN];
    BaiduProxyNode *nodes;
    size_t len;
    size_t cap;
    /* P0-CACHE: 缓存最优节点，5 秒有效期 */
    BaiduProxyNode *cached_best;
    long cached_at_ms;
};

typedef struct {
    Result *items;
    size_t len;
    size_t current_index;
    char current_ip[MAX_IP_LEN];
    pthread_mutex_t mu;
    atomic_int cache_valid;  /* P0-1: 1=当前 IP 可直接使用，0=需要重新选择 */
} CandidatePool;

typedef struct {
    socket_t client_fd;
    int tls_port, http_port, num, delay_ms;
    char ip[MAX_IP_LEN];
    BaiduProxyPool *proxy_pool;
    int use_mixed; // 1 表示混合模式
} ConnCtx;

typedef struct {
    socket_t from, to;
} PipeCtx;

typedef struct {
    socket_t listen_fd;
    CarrierListenSpec spec;
    CandidatePool candidates;
    BaiduProxyPool *proxy_pool;
    pthread_t health_tid;
    pthread_t accept_tid;
} CarrierRuntime;

static Config g_cfg;
static Location *g_locations = NULL;
static size_t g_location_count = 0;
static atomic_int g_running = 1;
static atomic_int g_active_connections = 0;
static socket_t g_listen_fd = INVALID_SOCKET;

static BaiduProxyPool g_default_proxy_pool = {0};

static CarrierRuntime *g_carrier_runtimes = NULL;
static size_t g_carrier_runtime_count = 0;
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;

static int parse_addr(const char *addr, char *host, size_t hostsz, int *port);
static socket_t accept_interruptible(socket_t listen_fd, struct sockaddr *addr,
#ifdef _WIN32
        int *addrlen
#else
        socklen_t *addrlen
#endif
);

#ifdef _WIN32
static int cfnat_get_console_handle(FILE *stream, HANDLE *out) {
    int fd = _fileno(stream);
    if (fd < 0) return 0;

    intptr_t os_handle = _get_osfhandle(fd);
    if (os_handle == -1) return 0;

    HANDLE handle = (HANDLE)os_handle;
    DWORD mode = 0;
    if (!GetConsoleMode(handle, &mode)) return 0;

    if (out) *out = handle;
    return 1;
}

static int cfnat_write_utf8(FILE *stream, const char *text, size_t len) {
    if (!text || len == 0) return 0;

    HANDLE handle = NULL;
    if (!cfnat_get_console_handle(stream, &handle)) {
        return (int)fwrite(text, 1, len, stream);
    }

    int wlen = MultiByteToWideChar(CP_UTF8, 0, text, (int)len, NULL, 0);
    if (wlen <= 0) {
        return (int)fwrite(text, 1, len, stream);
    }

    wchar_t *wide = (wchar_t *)malloc(((size_t)wlen + 1) * sizeof(wchar_t));
    if (!wide) {
        return (int)fwrite(text, 1, len, stream);
    }

    MultiByteToWideChar(CP_UTF8, 0, text, (int)len, wide, wlen);
    wide[wlen] = L'\0';

    DWORD written = 0;
    BOOL ok = WriteConsoleW(handle, wide, (DWORD)wlen, &written, NULL);
    free(wide);

    if (!ok) {
        return (int)fwrite(text, 1, len, stream);
    }
    return (int)len;
}

static int cfnat_vfprintf(FILE *stream, const char *fmt, va_list ap) {
    char stack_buf[8192];
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int needed = vsnprintf(stack_buf, sizeof(stack_buf), fmt, ap_copy);
    va_end(ap_copy);

    if (needed < 0) return needed;
    if ((size_t)needed < sizeof(stack_buf)) {
        cfnat_write_utf8(stream, stack_buf, (size_t)needed);
        return needed;
    }

    char *buf = (char *)malloc((size_t)needed + 1);
    if (!buf) {
        cfnat_write_utf8(stream, stack_buf, strlen(stack_buf));
        return needed;
    }

    va_copy(ap_copy, ap);
    vsnprintf(buf, (size_t)needed + 1, fmt, ap_copy);
    va_end(ap_copy);

    cfnat_write_utf8(stream, buf, (size_t)needed);
    free(buf);
    return needed;
}

static int cfnat_fprintf(FILE *stream, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = cfnat_vfprintf(stream, fmt, ap);
    va_end(ap);
    return rc;
}

static int cfnat_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = cfnat_vfprintf(stdout, fmt, ap);
    va_end(ap);
    return rc;
}

static int cfnat_fputc(int ch, FILE *stream) {
    char c = (char)ch;
    cfnat_write_utf8(stream, &c, 1);
    return ch;
}

static void init_windows_console_utf8(void) {
    setlocale(LC_ALL, "");
}

#define printf cfnat_printf
#define fprintf cfnat_fprintf
#define vfprintf cfnat_vfprintf
#define fputc cfnat_fputc

#endif

static long now_ms(void) {
#ifdef _WIN32
    return (long)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + tv.tv_usec / 1000L;
#endif
}

static const char *log_level_name(LogLevel level) {
    switch (level) {
    case LOG_SILENT:
        return "silent";
    case LOG_ERROR:
        return "error";
    case LOG_WARN:
        return "warn";
    case LOG_INFO:
        return "info";
    case LOG_DEBUG:
    default:
        return "debug";
    }
}

static int parse_log_level(const char *v, LogLevel *out) {
    if (!v || !*v) return -1;
    if (!strcasecmp(v, "silent") || !strcasecmp(v, "off")) {
        *out = LOG_SILENT;
        return 0;
    }
    if (!strcasecmp(v, "error")) {
        *out = LOG_ERROR;
        return 0;
    }
    if (!strcasecmp(v, "warn") || !strcasecmp(v, "warning")) {
        *out = LOG_WARN;
        return 0;
    }
    if (!strcasecmp(v, "info")) {
        *out = LOG_INFO;
        return 0;
    }
    if (!strcasecmp(v, "debug")) {
        *out = LOG_DEBUG;
        return 0;
    }
    return -1;
}

static void vlog_line(const char *tag, const char *fmt, va_list ap) {
    time_t t = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char ts[32];
    strftime(ts, sizeof(ts), "%Y/%m/%d %H:%M:%S", &tmv);
    pthread_mutex_lock(&g_log_mu);
    fprintf(stderr, "%s [%s] ", ts, tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    pthread_mutex_unlock(&g_log_mu);
}

static void log_msg(const char *fmt, ...) {
    if (g_cfg.log_level < LOG_INFO) return;
    va_list ap;
    va_start(ap, fmt);
    vlog_line("INFO", fmt, ap);
    va_end(ap);
}

static void warn_msg(const char *fmt, ...) {
    if (g_cfg.log_level < LOG_WARN) return;
    va_list ap;
    va_start(ap, fmt);
    vlog_line("WARN", fmt, ap);
    va_end(ap);
}

static void debug_msg(const char *fmt, ...) {
    if (g_cfg.log_level < LOG_DEBUG) return;
    va_list ap;
    va_start(ap, fmt);
    vlog_line("DEBUG", fmt, ap);
    va_end(ap);
}

static void conn_msg(const char *fmt, ...) {
    if (g_cfg.log_level < LOG_INFO) return;
    va_list ap;
    va_start(ap, fmt);
    vlog_line("CONN", fmt, ap);
    va_end(ap);
}

static int sleep_interruptible_ms(int ms) {
    int left = ms;
    while (left > 0 && atomic_load(&g_running)) {
        int chunk = left > 200 ? 200 : left;
#ifdef _WIN32
        Sleep((DWORD)chunk);
#else
        struct timespec ts;
        ts.tv_sec = chunk / 1000;
        ts.tv_nsec = (long)(chunk % 1000) * 1000000L;
        nanosleep(&ts, NULL);
#endif
        left -= chunk;
    }
    return atomic_load(&g_running) ? 0 : -1;
}

static void usage(const char *p) {
    printf("cfnat v%s - Cloudflare NAT 优选工具 (C 版)\n", CFNAT_VERSION);
    printf("Usage of %s:\n", p);
    printf("  -V, -version              显示版本号\n");
    printf("  -direct-listen=value      直连优选监听地址，例如 0.0.0.0:1234\n");
    printf("  -baidu-listen=value       百度前置优选监听地址，例如 0.0.0.0:1235\n");
    printf("  -colo=value               筛选数据中心例如 HKG,SJC,LAX\n");
    printf("  -delay=value              有效延迟毫秒 (default 300)\n");
    printf("  -ipnum=value              提取的有效IP数量 (default 20)\n");
    printf("  -ips=value                指定IPv4还是IPv6 (4或6, C版优先IPv4)\n");
    printf("  -log=value                日志级别: silent,error,warn,info,debug (default info)\n");
    printf("  -num=value                每个连接的目标连接尝试次数 (default 5)\n");
    printf("  -port=value               TLS 转发目标端口 (default 443)\n");
    printf("  -http-port=value          非TLS/HTTP 转发目标端口 (default 80)\n");
    printf("  -random=value             是否随机生成IP (default true)\n");
    printf("  -task=value               扫描线程数 (default 100)\n");
}

static int parse_bool(const char *v) {
    return !v || strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0;
}

static void cfg_defaults(Config *c) {
    memset(c, 0, sizeof(*c));
    strcpy(c->domain, "cloudflaremirrors.com/debian");
    strcpy(c->log_name, "info");
    strcpy(c->baidu_domain, DEFAULT_BAIDU_DOMAIN);
    strcpy(c->baidu_scan_target, DEFAULT_BAIDU_SCAN_TARGET);
    c->code = 200;
    c->delay_ms = 300;
    c->ipnum = 20;
    c->ips_type = 4;
    c->num = 5;
    c->port = 443;
    c->http_port = 80;
    c->random_mode = 1;
    c->task = 100;
    c->health_log = 60;
    c->use_baidu_proxy = 0;
    c->baidu_port = DEFAULT_BAIDU_PORT;
    c->baidu_ipnum = DEFAULT_BAIDU_IPNUM;
    c->log_level = LOG_INFO;
}

static void parse_args(Config *c, int argc, char **argv) {
    cfg_defaults(c);
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(argv[0]);
            exit(0);
        }
        if (!strcmp(arg, "-V") || !strcmp(arg, "-version") || !strcmp(arg, "--version")) {
            printf("cfnat version %s\n", CFNAT_VERSION);
            exit(0);
        }
        if (arg[0] != '-') continue;
        char *key = arg + 1;
        if (*key == '-') key++;
        char *eq = strchr(key, '=');
        char *val = NULL;
        if (eq) {
            *eq = 0;
            val = eq + 1;
        } else if (i + 1 < argc && argv[i + 1][0] != '-') val = argv[++i];
        if (!strcmp(key, "direct-listen") && val) snprintf(c->direct_listen, sizeof(c->direct_listen), "%s", val);
        else if (!strcmp(key, "baidu-listen") && val) snprintf(c->baidu_listen, sizeof(c->baidu_listen), "%s", val);
        else if (!strcmp(key, "code") && val) c->code = atoi(val);
        else if (!strcmp(key, "colo") && val) snprintf(c->colo, sizeof(c->colo), "%s", val);
        else if (!strcmp(key, "delay") && val) c->delay_ms = atoi(val);
        else if (!strcmp(key, "domain") && val) snprintf(c->domain, sizeof(c->domain), "%s", val);
        else if (!strcmp(key, "ipnum") && val) c->ipnum = atoi(val);
        else if (!strcmp(key, "ips") && val) c->ips_type = atoi(val);
        else if (!strcmp(key, "log") && val) {
            if (parse_log_level(val, &c->log_level) != 0) {
                fprintf(stderr, "非法 -log=%s，可选值: silent, error, warn, info, debug\n", val);
                exit(1);
            }
            snprintf(c->log_name, sizeof(c->log_name), "%s", log_level_name(c->log_level));
        } else if (!strcmp(key, "num") && val) c->num = atoi(val);
        else if (!strcmp(key, "port") && val) c->port = atoi(val);
        else if (!strcmp(key, "http-port") && val) c->http_port = atoi(val);
        else if (!strcmp(key, "random")) c->random_mode = parse_bool(val);
        else if (!strcmp(key, "task") && val) c->task = atoi(val);
        else if (!strcmp(key, "health-log") && val) c->health_log = atoi(val);
    }
    if (c->delay_ms <= 0) c->delay_ms = 300;
    if (c->ipnum <= 0) c->ipnum = 20;
    if (c->num <= 0) c->num = 1;
    if (c->task <= 0) c->task = 1;
    if (c->baidu_port <= 0) c->baidu_port = 443;
    if (c->baidu_ipnum <= 0) c->baidu_ipnum = 12;
    if (c->baidu_listen[0]) c->use_baidu_proxy = 1;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

#ifdef _WIN32
static wchar_t *utf8_to_wide_alloc(const char *s) {
    if (!s) return NULL;
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (len <= 0) return NULL;
    wchar_t *w = (wchar_t *)calloc((size_t)len, sizeof(wchar_t));
    if (!w) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, len) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static int download_file_wininet(const char *url, const char *filename) {
    wchar_t *wurl = utf8_to_wide_alloc(url);
    if (!wurl) return -1;

    HINTERNET hnet = InternetOpenW(L"cfnat/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hnet) {
        free(wurl);
        return -1;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE;
    if (strncmp(url, "https://", 8) == 0) {
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    HINTERNET hurl = InternetOpenUrlW(hnet, wurl, NULL, 0, flags, 0);
    free(wurl);
    if (!hurl) {
        InternetCloseHandle(hnet);
        return -1;
    }

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", filename);
    FILE *out = fopen(tmp, "wb");
    if (!out) {
        InternetCloseHandle(hurl);
        InternetCloseHandle(hnet);
        return -1;
    }

    char buf[16384];
    DWORD got = 0;
    int rc = 0;
    for (;;) {
        if (!InternetReadFile(hurl, buf, sizeof(buf), &got)) {
            rc = -1;
            break;
        }
        if (got == 0) break;
        if (fwrite(buf, 1, got, out) != got) {
            rc = -1;
            break;
        }
    }

    fclose(out);
    InternetCloseHandle(hurl);
    InternetCloseHandle(hnet);

    if (rc != 0 || !file_exists(tmp)) {
        remove(tmp);
        return -1;
    }

    remove(filename);
    if (rename(tmp, filename) != 0) {
        remove(tmp);
        return -1;
    }
    return 0;
}
#endif

static int download_file_from_urls(const char **urls, const char *filename) {
#ifdef _WIN32
    for (int i = 0; urls[i]; i++) {
        if (download_file_wininet(urls[i], filename) == 0) return 0;
        log_msg("从 %s 下载失败，尝试下一个源", urls[i]);
    }
    return -1;
#else
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", filename);
    for (int i = 0; urls[i]; i++) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "curl -fsSL '%s' -o '%s' 2>/dev/null || wget -qO '%s' '%s' 2>/dev/null", urls[i], tmp, tmp, urls[i]);
        int rc = system(cmd);
        if (rc == 0 && file_exists(tmp)) {
            rename(tmp, filename);
            return 0;
        }
        unlink(tmp);
        log_msg("从 %s 下载失败，尝试下一个源", urls[i]);
    }
    return -1;
#endif
}

static int ensure_data_file(const char *expected, const char **urls) {
    if (file_exists(expected)) return 0;

    printf("文件 %s 不存在，正在下载数据\n", expected);
    return download_file_from_urls(urls, expected);
}

static char *read_file_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) {
        fclose(f);
        return NULL;
    }
    char *b = malloc((size_t)n + 1);
    if (!b) {
        fclose(f);
        return NULL;
    }
    size_t r = fread(b, 1, (size_t)n, f);
    fclose(f);
    b[r] = 0;
    if (out_len) * out_len = r;
    return b;
}

static void trim_line(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = 0;
}

static int strlist_add(StringList *l, const char *s) {
    if (l->len == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 256;
        char **ni = realloc(l->items, nc * sizeof(char *));
        if (!ni) return -1;
        l->items = ni;
        l->cap = nc;
    }
    l->items[l->len] = strdup(s);
    if (!l->items[l->len]) return -1;
    l->len++;
    return 0;
}

static void strlist_free(StringList *l) {
    for (size_t i = 0; i < l->len; i++) free(l->items[i]);
    free(l->items);
    memset(l, 0, sizeof(*l));
}

static uint32_t ipv4_to_u32(const char *s) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    return ntohl(a.s_addr);
}

static void u32_to_ipv4(uint32_t v, char *out, size_t sz) {
    struct in_addr a;
    a.s_addr = htonl(v);
    inet_ntop(AF_INET, &a, out, sz);
}

static StringList load_ip_list(const char *filename, int random_mode) {
    StringList out = {0};
    FILE *f = fopen(filename, "r");
    if (!f) return out;
    log_msg("正在读取 %s，模式：%s", filename, random_mode ? "CIDR随机抽样" : "完整展开CIDR");
    char line[MAX_LINE];
    long start_ms = now_ms();
    size_t cidr_count = 0;
    srand((unsigned)time(NULL));
    while (fgets(line, sizeof(line), f)) {
        trim_line(line);
        if (!line[0]) continue;
        char *slash = strchr(line, '/');
        if (!slash) {
            strlist_add(&out, line);
            continue;
        }
        cidr_count++;
        *slash = 0;
        int prefix = atoi(slash + 1);
        uint32_t base = ipv4_to_u32(line);
        if (base == 0 || prefix < 0 || prefix > 32) continue;
        uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
        uint32_t start = base & mask;
        uint32_t count = prefix == 32 ? 1u : (1u << (32 - prefix));
        if (random_mode) {
            uint32_t off = count > 1 ? (uint32_t)(rand() % count) : 0;
            char ip[MAX_IP_LEN];
            u32_to_ipv4(start + off, ip, sizeof(ip));
            strlist_add(&out, ip);
        } else {
            for (uint32_t off = 0; off < count; off++) {
                char ip[MAX_IP_LEN];
                u32_to_ipv4(start + off, ip, sizeof(ip));
                strlist_add(&out, ip);
            }
        }
        if (!random_mode && out.len > 0 && out.len % 50000 == 0) {
            log_msg("IP 列表展开进度: %zu 个", out.len);
        }
    }
    fclose(f);
    log_msg("IP 列表加载完成: %zu 个候选，CIDR 行数: %zu，耗时 %ld 秒", out.len, cidr_count, (now_ms() - start_ms) / 1000);
    if (!random_mode && out.len > 100000) {
        warn_msg("当前使用 -random=false，已完整展开大量 IP，扫描会明显变慢；需要快速启动时建议使用 -random=true");
    }
    return out;
}

static char *json_string_value(char *p, const char *key, char *out, size_t outsz) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    char *k = strstr(p, pat);
    if (!k) return NULL;
    char *colon = strchr(k + strlen(pat), ':');
    if (!colon) return NULL;
    char *q = strchr(colon, '\"');
    if (!q) return NULL;
    q++;
    char *e = strchr(q, '\"');
    if (!e) return NULL;
    size_t n = (size_t)(e - q);
    if (n >= outsz) n = outsz - 1;
    memcpy(out, q, n);
    out[n] = 0;
    return e + 1;
}

static void load_locations(void) {
    if (ensure_data_file("locations.json", LOC_URLS) != 0) {
        log_msg("下载 locations.json 失败");
        return;
    }
    size_t len = 0;
    char *json = read_file_all("locations.json", &len);
    if (!json) return;
    size_t cap = 128;
    g_locations = calloc(cap, sizeof(Location));
    g_location_count = 0;
    char *p = json;
    while ((p = strstr(p, "\"iata\""))) {
        if (g_location_count == cap) {
            cap *= 2;
            Location *nl = realloc(g_locations, cap * sizeof(Location));
            if (!nl) break;
            g_locations = nl;
        }
        Location loc = {0};
        char *np = json_string_value(p, "iata", loc.iata, sizeof(loc.iata));
        if (!np) {
            p += 6;
            continue;
        }
        json_string_value(np, "region", loc.region, sizeof(loc.region));
        json_string_value(np, "city", loc.city, sizeof(loc.city));
        if (loc.iata[0]) g_locations[g_location_count++] = loc;
        p = np;
    }
    free(json);
}

static Location *find_location(const char *iata) {
    for (size_t i = 0; i < g_location_count; i++) if (!strcasecmp(g_locations[i].iata, iata)) return &g_locations[i];
    return NULL;
}

static int colo_allowed(const char *colo) {
    if (!g_cfg.colo[0]) return 1;
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s", g_cfg.colo);
    char *save = NULL;
    char *tok = strtok_r(tmp, ",", &save);
    while (tok) {
        trim_line(tok);
        if (!strcasecmp(tok, colo)) return 1;
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}

static int set_nonblock(socket_t fd, int nb) {
#ifdef _WIN32
    u_long mode = nb ? 1UL : 0UL;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nb) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
#endif
}

static socket_t tcp_connect(const char *ip, int port, int timeout_ms, int *latency_ms) {
    long start = now_ms();
    socket_t fd = socket(strchr(ip, ':') ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
    set_nonblock(fd, 1);
    int rc;
    if (strchr(ip, ':')) {
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip, &sa6.sin6_addr) != 1) {
            close(fd);
            return INVALID_SOCKET;
        }
        rc = connect(fd, (struct sockaddr *)&sa6, sizeof(sa6));
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
            close(fd);
            return INVALID_SOCKET;
        }
        rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    }
#ifdef _WIN32
    if (rc == SOCKET_ERROR) {
        int werr = WSAGetLastError();
        if (werr != WSAEWOULDBLOCK && werr != WSAEINPROGRESS && werr != WSAEALREADY) {
            close(fd);
            return INVALID_SOCKET;
        }
    }
#else
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return INVALID_SOCKET;
    }
#endif
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv = {
        timeout_ms / 1000,
        (timeout_ms % 1000) * 1000
    };
#ifdef _WIN32
    rc = select(0, NULL, &wfds, NULL, &tv);
#else
    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
#endif
    if (rc <= 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    int err = 0;
#ifdef _WIN32
    int len = (int)sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len) < 0 || err != 0) {
#else
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
#endif
        close(fd);
        return INVALID_SOCKET;
    }
    set_nonblock(fd, 0);
    if (latency_ms) * latency_ms = (int)(now_ms() - start);
    return fd;
}

static int recv_headers(socket_t fd, char *buf, size_t bufsz, int timeout_ms) {
    size_t used = 0;
    long deadline = now_ms() + timeout_ms;
    while (used + 1 < bufsz && now_ms() < deadline) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        struct timeval tv = {
            left / 1000,
            (left % 1000) * 1000
        };
        int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) break;
        ssize_t n = recv(fd, buf + used, bufsz - used - 1, 0);
        if (n <= 0) break;
        used += (size_t)n;
        buf[used] = 0;
        if (strstr(buf, "\r\n\r\n")) return (int)used;
    }
    buf[used] = 0;
    return (int)used;
}

/* ── EventLoop 版 I/O 函数 ─────────────────────────────────── */
/* 基于 EventLoop 的 TCP 连接，替代 tcp_connect 中的 select() */
static socket_t tcp_connect_ev(const char *ip, int port, int timeout_ms, int *latency_ms, EventLoop *el) {
    long start = now_ms();
    socket_t fd = socket(strchr(ip, ':') ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
    set_nonblock(fd, 1);
    int rc;
    if (strchr(ip, ':')) {
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip, &sa6.sin6_addr) != 1) { close(fd); return INVALID_SOCKET; }
        rc = connect(fd, (struct sockaddr *)&sa6, sizeof(sa6));
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return INVALID_SOCKET; }
        rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    }
#ifdef _WIN32
    if (rc == SOCKET_ERROR) {
        int werr = WSAGetLastError();
        if (werr != WSAEWOULDBLOCK && werr != WSAEINPROGRESS && werr != WSAEALREADY) { close(fd); return INVALID_SOCKET; }
    }
#else
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return INVALID_SOCKET; }
#endif
    if (rc != 0) {
        /* 连接未立即完成，用 EventLoop 等待可写 */
        evloop_add(el, fd, EV_WRITE);
        struct evloop_event ev;
        int n = evloop_wait(el, &ev, 1, timeout_ms);
        evloop_del(el, fd);
        if (n <= 0) { close(fd); return INVALID_SOCKET; }
        /* 检查 SO_ERROR 确认连接成功 */
        int err = 0;
#ifdef _WIN32
        int len = (int)sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len) < 0 || err != 0) {
#else
        socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
#endif
            close(fd);
            return INVALID_SOCKET;
        }
    }
    set_nonblock(fd, 0);
    if (latency_ms) *latency_ms = (int)(now_ms() - start);
    return fd;
}

/* 基于 EventLoop 的 HTTP 响应头接收，带 O(n²) 防护 */
static int recv_headers_ev(socket_t fd, char *buf, size_t bufsz, int timeout_ms, EventLoop *el) {
    size_t used = 0;
    size_t search_pos = 0;  /* 避免 O(n²) 退化 */
    long deadline = now_ms() + timeout_ms;
    while (used + 1 < bufsz && now_ms() < deadline) {
        struct evloop_event ev;
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int n = evloop_wait(el, &ev, 1, left);
        if (n <= 0) break;
        ssize_t nread = recv(fd, buf + used, bufsz - used - 1, 0);
        if (nread <= 0) break;
        used += (size_t)nread;
        buf[used] = 0;
        /* 只从 search_pos 开始搜索，避免 O(n²) */
        char *found = strstr(buf + search_pos, "\r\n\r\n");
        if (found) return (int)(found - buf + 4);  /* 包含 \r\n\r\n */
        search_pos = used > 3 ? used - 3 : 0;  /* 保留末尾 3 字节防止跨边界 */
    }
    buf[used] = 0;
    return (int)used;
}

/* ── EventLoop 版 I/O 函数结束 ─────────────────────────────── */

static char *cfnat_strcasestr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    size_t nl = strlen(needle);
    if (nl == 0) return (char *)haystack;
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nl) return (char *)p;
    }
    return NULL;
}

static int extract_cfray(const char *headers, char *colo, size_t sz) {
    const char *p = cfnat_strcasestr(headers, "CF-RAY:");
    if (!p) return -1;
    const char *line_end = strstr(p, "\r\n");
    if (!line_end) line_end = p + strlen(p);
    const char *dash = NULL;
    for (const char *q = p; q < line_end; q++) if (*q == '-') dash = q;
    if (!dash || dash + 1 >= line_end) return -1;
    const char *s = dash + 1;
    size_t n = (size_t)(line_end - s);
    if (n >= sz) n = sz - 1;
    memcpy(colo, s, n);
    colo[n] = 0;
    trim_line(colo);
    return colo[0] ? 0 : -1;
}

static int str_eq_ci(const char *a, const char *b) {
    return a && b && strcasecmp(a, b) == 0;
}

static const char *carrier_display_name(const char *mode) {
    if (str_eq_ci(mode, "direct")) return "直连优选";
    if (str_eq_ci(mode, "baidu")) return "百度前置优选";
    if (str_eq_ci(mode, "mixed")) return "混合优选";
    return mode ? mode : "unknown";
}

static void append_unique_addr(StringList *list, const char *value) {
    if (!list || !value || !*value) return;
    for (size_t i = 0; i < list->len; i++) {
        if (!strcmp(list->items[i], value)) return;
    }
    strlist_add(list, value);
}

static int baidu_pool_add(BaiduProxyPool *pool, const char *addr) {
    if (!pool || !addr || !*addr) return -1;
    for (size_t i = 0; i < pool->len; i++) if (!strcmp(pool->nodes[i].addr, addr)) return 0;
    if (pool->len == pool->cap) {
        size_t nc = pool->cap ? pool->cap * 2 : 8;
        BaiduProxyNode *nn = realloc(pool->nodes, nc * sizeof(BaiduProxyNode));
        if (!nn) return -1;
        pool->nodes = nn;
        pool->cap = nc;
    }
    BaiduProxyNode *node = &pool->nodes[pool->len++];
    memset(node, 0, sizeof(*node));
    snprintf(node->addr, sizeof(node->addr), "%s", addr);
    atomic_init(&node->active, 0);
    atomic_init(&node->failures, 0);
    atomic_init(&node->ewma_ms, g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 300);
    return 0;
}

static void baidu_pool_free(BaiduProxyPool *pool) {
    if (!pool) return;
    free(pool->nodes);
    pool->nodes = NULL;
    pool->len = 0;
    pool->cap = 0;
    pool->cached_best = NULL;
    pool->cached_at_ms = 0;
}

static long proxy_node_score(const BaiduProxyNode *node) {
    long ewma = atomic_load(&node->ewma_ms);
    int active = atomic_load(&node->active);
    int failures = atomic_load(&node->failures);
    return ewma + (long)active * 50L + (long)failures * 300L;
}

/* P0-CACHE: 代理节点选择，带 5 秒缓存 */
static BaiduProxyNode *baidu_pool_pick(BaiduProxyPool *pool) {
    if (!pool || pool->len == 0) return NULL;

    /* 缓存有效期内直接返回缓存结果 */
    if (pool->cached_best && (now_ms() - pool->cached_at_ms) < 5000) {
        return pool->cached_best;
    }

    BaiduProxyNode *best = &pool->nodes[0];
    long best_score = proxy_node_score(best);
    for (size_t i = 1; i < pool->len; i++) {
        long score = proxy_node_score(&pool->nodes[i]);
        if (score < best_score) {
            best = &pool->nodes[i];
            best_score = score;
        }
    }

    /* 更新缓存 */
    pool->cached_best = best;
    pool->cached_at_ms = now_ms();
    return best;
}

static socket_t tcp_connect_via_baidu(const char *node_addr, const char *target_addr, int timeout_ms, int *latency_ms) {
    long start = now_ms();
    char host[MAX_ADDR_LEN] = {0};
    int port = 0;
    if (parse_addr(node_addr, host, sizeof(host), &port) != 0) return INVALID_SOCKET;
    socket_t fd = tcp_connect(host, port, timeout_ms, NULL);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
    char req[1024];
    snprintf(req, sizeof(req),
            "CONNECT %s HTTP/1.1\r\n"
            "Host: sptest.baidu.com\r\n"
            "X-T5-Auth: 482857715\r\n"
            "User-Agent: okhttp/3.11.0 Dalvik/2.1.0 (Linux; Build/RKQ1.200826.002) baiduboxapp/11.0.5.12 (Baidu; P1 11)\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "Connection: keep-alive\r\n\r\n", target_addr);
    if (send(fd, req, strlen(req), 0) < 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    char hdr[4096];
    int n = recv_headers(fd, hdr, sizeof(hdr), timeout_ms);
    if (n <= 0 || strstr(hdr, " 200 ") == NULL) {
        close(fd);
        return INVALID_SOCKET;
    }
    if (latency_ms) * latency_ms = (int)(now_ms() - start);
    return fd;
}

static socket_t dial_target_with_proxy(const char *ip, int port, int timeout_ms, BaiduProxyPool *pool, int *latency_ms) {
    if (!pool || pool->len == 0) return tcp_connect(ip, port, timeout_ms, latency_ms);
    char target[MAX_ADDR_LEN];
    snprintf(target, sizeof(target), "%s:%d", ip, port);
    BaiduProxyNode *node = baidu_pool_pick(pool);
    if (!node) return INVALID_SOCKET;
    atomic_fetch_add(&node->active, 1);
    socket_t fd = tcp_connect_via_baidu(node->addr, target, timeout_ms, latency_ms);
    if (cfnat_socket_valid(fd)) {
        if (latency_ms && *latency_ms > 0) atomic_store(&node->ewma_ms, (atomic_load(&node->ewma_ms) * 7 + *latency_ms) / 8);
        if (atomic_load(&node->failures) > 0) atomic_fetch_sub(&node->failures, 1);
    } else {
        atomic_fetch_add(&node->failures, 1);
    }
    atomic_fetch_sub(&node->active, 1);
    return fd;
}

static int parse_listen_modes(const Config *cfg, CarrierListenSpec **out_specs, size_t *out_len) {
    *out_specs = NULL;
    *out_len = 0;
    if (!cfg) return -1;
    size_t len = 0;
    CarrierListenSpec *specs = calloc(2, sizeof(CarrierListenSpec));
    if (!specs) return -1;

    if (cfg->direct_listen[0] && cfg->baidu_listen[0] && strcmp(cfg->direct_listen, cfg->baidu_listen) == 0) {
        // 两个监听地址一样，使用混合模式
        snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "mixed");
        snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->direct_listen);
        specs[len].use_baidu_proxy = 2; // 2 表示混合模式
        len++;
    } else {
        if (cfg->direct_listen[0]) {
            snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "direct");
            snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->direct_listen);
            specs[len].use_baidu_proxy = 0;
            len++;
        }
        if (cfg->baidu_listen[0]) {
            snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "baidu");
            snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->baidu_listen);
            specs[len].use_baidu_proxy = 1;
            len++;
        }
    }

    if (len == 0) {
        free(specs);
        return 0;
    }
    *out_specs = specs;
    *out_len = len;
    return 0;
}

static int resolve_host_ips(const char *domain, StringList *out) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    struct addrinfo * res = NULL;
    if (getaddrinfo(domain, NULL, &hints, &res) != 0) return -1;
    for (struct addrinfo * ai = res; ai; ai = ai->ai_next) {
        char ip[INET_ADDRSTRLEN] = {0};
        struct sockaddr_in * sin = (struct sockaddr_in *) ai->ai_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip))) append_unique_addr(out, ip);
    }
    freeaddrinfo(res);
    return out->len > 0 ? 0 : -1;
}

static int build_baidu_pool_for_carrier(BaiduProxyPool *pool, const char *name) {
    memset(pool, 0, sizeof(*pool));
    snprintf(pool->name, sizeof(pool->name), "%s", name ? name : "default");
    StringList ips = {0};
    if (resolve_host_ips(g_cfg.baidu_domain, &ips) != 0) return -1;
    for (size_t i = 0; i < ips.len; i++) {
        char addr[MAX_ADDR_LEN];
        snprintf(addr, sizeof(addr), "%s:%d", ips.items[i], g_cfg.baidu_port);
        int latency = 0;
        socket_t fd = tcp_connect_via_baidu(addr, g_cfg.baidu_scan_target, g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1000, &latency);
        if (cfnat_socket_valid(fd)) {
            close(fd);
            baidu_pool_add(pool, addr);
            if ((int)pool->len >= g_cfg.baidu_ipnum) break;
        }
    }
    strlist_free(&ips);
    return pool->len > 0 ? 0 : -1;
}

static void resultlist_add(ResultList *rl, const Result *r) {
    pthread_mutex_lock(&rl->mu);
    if (rl->len == rl->cap) {
        size_t nc = rl->cap ? rl->cap * 2 : 128;
        Result *ni = realloc(rl->items, nc * sizeof(Result));
        if (!ni) {
            pthread_mutex_unlock(&rl->mu);
            return;
        }
        rl->items = ni;
        rl->cap = nc;
    }
    rl->items[rl->len++] = *r;
    pthread_mutex_unlock(&rl->mu);
}

/* thread-local 结果批量写入全局列表 */
static void flush_local_results(ResultList *rl, Result *local, int *count) {
    if (!rl || !local || !count || *count <= 0) return;
    pthread_mutex_lock(&rl->mu);
    for (int i = 0; i < *count; i++) {
        if (rl->len == rl->cap) {
            size_t nc = rl->cap ? rl->cap * 2 : 128;
            Result *ni = realloc(rl->items, nc * sizeof(Result));
            if (!ni) { pthread_mutex_unlock(&rl->mu); return; }
            rl->items = ni;
            rl->cap = nc;
        }
        rl->items[rl->len++] = local[i];
    }
    pthread_mutex_unlock(&rl->mu);
    *count = 0;
}

/* 新 scan_worker：EventLoop + Keep-Alive + thread-local 结果 */
static void *scan_worker(void *arg) {
    ScanCtx *ctx = (ScanCtx *)arg;
    EventLoop el = evloop_create();

    /* thread-local 结果积累 */
#define LOCAL_MAX 256
    Result local_results[LOCAL_MAX];
    int local_count = 0;

    while (atomic_load(&g_running)) {
        size_t idx = atomic_fetch_add(&ctx->index, 1);
        if (idx >= ctx->total || !atomic_load(&g_running)) break;

        /* 从 CidrList 按需生成 IP */
        char ip[MAX_IP_LEN];
        if (ctx->cidrs) {
            if (cidrlist_get_ip(ctx->cidrs, idx, ip, sizeof(ip)) != 0) continue;
        } else {
            /* 兼容旧模式：ctx->ips 不为 NULL */
            snprintf(ip, sizeof(ip), "%s", ctx->ips[idx]);
        }

        int probes = ctx->cfg->num > 0 ? ctx->cfg->num : 1;
        int success_count = 0;
        int best_latency = 0;
        int ewma_latency = 0;
        int jitter_ms = 0;
        char best_colo[MAX_COLO_LEN] = {0};
        int header_once = 0;
        int cfray_missing_once = 0;

        /* Keep-Alive 复用连接 */
        socket_t fd = INVALID_SOCKET;
        int latency = 0;
        for (int attempt = 0; atomic_load(&g_running) && attempt < probes; attempt++) {
            if (cfnat_socket_invalid(fd)) {
                latency = 0;
                fd = dial_target_with_proxy(ip, 80, ctx->cfg->delay_ms, ctx->proxy_pool, &latency);
                if (cfnat_socket_invalid(fd)) {
                    atomic_fetch_add(&ctx->connect_fail, 1);
                    continue;
                }
                /* 记录首次连接延迟 */
                if (best_latency == 0 || latency < best_latency) best_latency = latency;
            }
            char req[512];
            if ((attempt % 2) == 0) {
                snprintf(req, sizeof(req),
                         "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
                         ip);
            } else {
                snprintf(req, sizeof(req),
                         "GET / HTTP/1.1\r\nHost: cloudflaremirrors.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n");
            }

            send(fd, req, strlen(req), 0);
            char hdr[4096];
            int n = recv_headers_ev(fd, hdr, sizeof(hdr), ctx->cfg->delay_ms > 2000 ? ctx->cfg->delay_ms : 2000, &el);
            if (n <= 0) {
                /* 连接断开，关闭后下次重连 */
                close(fd);
                fd = INVALID_SOCKET;
                atomic_fetch_add(&ctx->header_fail, 1);
                continue;
            }
            header_once = 1;

            char colo[MAX_COLO_LEN] = {0};
            if (extract_cfray(hdr, colo, sizeof(colo)) != 0) {
                cfray_missing_once = 1;
                atomic_fetch_add(&ctx->cfray_miss, 1);
                continue;
            }
            if (!colo_allowed(colo)) {
                atomic_fetch_add(&ctx->colo_skip, 1);
                continue;
            }
            success_count++;
            /* P0-EWMA: 更新平滑延迟和抖动 */
            if (ewma_latency <= 0) {
                ewma_latency = best_latency > 0 ? best_latency : ctx->cfg->delay_ms;
                jitter_ms = 0;
            } else {
                int diff = abs(best_latency - ewma_latency);
                jitter_ms = (jitter_ms * 7 + diff) / 8;
                ewma_latency = (ewma_latency * 7 + best_latency) / 8;
            }
            if (best_latency == 0 || latency < best_latency) {
                snprintf(best_colo, sizeof(best_colo), "%s", colo);
            }
        }
        if (cfnat_socket_valid(fd)) close(fd);

        if (success_count <= 0 && header_once && cfray_missing_once && !ctx->cfg->colo[0] && (!ctx->proxy_pool || ctx->proxy_pool->len == 0)) {
            success_count = 1;
            if (best_latency == 0) best_latency = ctx->cfg->delay_ms > 0 ? ctx->cfg->delay_ms : 1;
            if (ewma_latency <= 0) ewma_latency = best_latency;
            snprintf(best_colo, sizeof(best_colo), "%s", "UNK");
            debug_msg("%s HTTP 响应缺少 CF-RAY，作为 UNK 候选交给健康检查确认", ip);
        }

        uint64_t done = atomic_fetch_add(&ctx->completed, 1) + 1;
        if (done == ctx->total || done % 5000 == 0) {
            size_t found = 0;
            pthread_mutex_lock(&ctx->results->mu);
            found = ctx->results->len;
            pthread_mutex_unlock(&ctx->results->mu);
            log_msg("扫描进度: %llu/%llu，已发现有效 IP: %zu，耗时 %ld 秒",
                    (unsigned long long)done, (unsigned long long)ctx->total, found, (now_ms() - ctx->scan_start_ms) / 1000);
        }
        if (success_count <= 0 || !best_colo[0] || best_latency <= 0) continue;

        Result r;
        memset(&r, 0, sizeof(r));
        snprintf(r.ip, sizeof(r.ip), "%s", ip);
        snprintf(r.data_center, sizeof(r.data_center), "%s", best_colo);
        r.latency_ms = best_latency;
        r.probe_count = probes;
        r.success_count = success_count;
        r.loss_rate = (probes - success_count) * 100 / probes;
        r.ewma_latency = ewma_latency > 0 ? ewma_latency : best_latency;
        r.jitter_ms = jitter_ms;
        r.consecutive_fail = 0;
        Location *loc = find_location(best_colo);
        if (loc) {
            snprintf(r.region, sizeof(r.region), "%s", loc->region);
            snprintf(r.city, sizeof(r.city), "%s", loc->city);
        }
        if (!loc && !strcmp(best_colo, "UNK")) {
            snprintf(r.region, sizeof(r.region), "%s", "Unknown");
            snprintf(r.city, sizeof(r.city), "%s", "Unknown");
        }
        debug_msg("发现有效IP %s 位置信息 %s 延迟 %d 毫秒 EWMA %d 抖动 %d 丢包 %d%% (%d/%d)",
                  r.ip, r.city[0] ? r.city : "未知", r.latency_ms, r.ewma_latency, r.jitter_ms,
                  r.loss_rate, r.success_count, r.probe_count);

        /* thread-local 积累 */
        if (local_count < LOCAL_MAX) {
            local_results[local_count++] = r;
        }
        if (local_count >= LOCAL_MAX) {
            flush_local_results(ctx->results, local_results, &local_count);
        }
    }

    /* 剩余结果 flush */
    flush_local_results(ctx->results, local_results, &local_count);
    evloop_destroy(&el);
    return NULL;
}
#undef LOCAL_MAX


/* P0-EWMA: 增强评分函数，考虑 EWMA 延迟、抖动和连续失败 */
static int score_result(const Result *r) {
    int score = 0;
    /* 基础分：使用 EWMA 延迟（如果可用），否则用原始延迟 */
    int base_latency = r->ewma_latency > 0 ? r->ewma_latency : r->latency_ms;
    score += base_latency * 10;
    /* 丢包惩罚 */
    score += r->loss_rate * 25;
    /* 抖动惩罚：高抖动意味着不稳定 */
    score += r->jitter_ms * 5;
    /* 连续失败惩罚：指数级增长 */
    if (r->consecutive_fail > 0) {
        int penalty = 50;
        for (int i = 0; i < r->consecutive_fail && i < 10; i++) penalty *= 2;
        score += penalty;
    }
    return score;
}

static int cmp_result(const void *a, const void *b) {
    const Result *ra = (const Result *)a;
    const Result *rb = (const Result *)b;
    int sa = score_result(ra);
    int sb = score_result(rb);
    if (sa != sb) return sa - sb;
    if (ra->latency_ms != rb->latency_ms) return ra->latency_ms - rb->latency_ms;
    return ra->loss_rate - rb->loss_rate;
}


static int health_check_ip(const char *ip, BaiduProxyPool *proxy_pool);
static int carrier_health_check_ip(CarrierRuntime *rt, const char *ip);
static int carrier_set_current_candidate(CarrierRuntime *rt, size_t idx);
static int carrier_try_use_candidate_cache(CarrierRuntime *rt);

#define CACHE_REFRESH_INTERVAL_SECONDS 3600L
#define CACHE_QUICK_CHECK_COUNT 5

static const char *candidate_cache_file(const char *mode) {
    if (mode && strcmp(mode, "baidu") == 0) {
        return g_cfg.ips_type == 6 ? "baidu-cache-v6.txt" : "baidu-cache-v4.txt";
    }
    if (mode && strcmp(mode, "mixed") == 0) {
        return g_cfg.ips_type == 6 ? "mixed-cache-v6.txt" : "mixed-cache-v4.txt";
    }
    // default: direct mode
    return g_cfg.ips_type == 6 ? "direct-cache-v6.txt" : "direct-cache-v4.txt";
}

static void save_candidate_cache(const char *path, const Result *items, size_t len) {
    if (!path || !items || len == 0) return;
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        warn_msg("写入缓存 %s 失败", path);
        return;
    }
    /* P0-EWMA: 缓存格式升级为 v2，增加 ewma_latency, jitter_ms, consecutive_fail */
    fprintf(fp, "# cfnat-cache-v2 %ld\n", (long)time(NULL));
    size_t limit = len;
    if (g_cfg.ipnum > 0 && limit > (size_t)g_cfg.ipnum) limit = (size_t)g_cfg.ipnum;
    for (size_t i = 0; i < limit; i++) {
        const Result *r = &items[i];
        fprintf(fp, "%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d\n",
                r->ip,
                r->data_center[0] ? r->data_center : "UNK",
                r->region[0] ? r->region : "Unknown",
                r->city[0] ? r->city : "Unknown",
                r->latency_ms,
                r->loss_rate,
                r->success_count,
                r->probe_count,
                r->ewma_latency > 0 ? r->ewma_latency : r->latency_ms,
                r->jitter_ms,
                r->consecutive_fail);
    }
    fclose(fp);
    debug_msg("候选缓存已写入 %s，共 %zu 个", path, limit);
}

static ResultList load_candidate_cache(const char *path) {
    ResultList rl = {0};
    pthread_mutex_init(&rl.mu, NULL);
    if (!path || !file_exists(path)) return rl;

    FILE *fp = fopen(path, "rb");
    if (!fp) return rl;

    char line[MAX_LINE];
    int is_v2 = 0;
    if (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "# cfnat-cache-v2", 16) == 0) {
            is_v2 = 1;
        } else if (strncmp(line, "# cfnat-cache-v1", 16) != 0) {
            rewind(fp);
        }
    }

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        Result r;
        memset(&r, 0, sizeof(r));
        int parsed;
        if (is_v2) {
            /* P0-EWMA: v2 格式包含 ewma_latency, jitter_ms, consecutive_fail */
            parsed = sscanf(line, "%63[^|]|%7[^|]|%63[^|]|%63[^|]|%d|%d|%d|%d|%d|%d|%d",
                            r.ip,
                            r.data_center,
                            r.region,
                            r.city,
                            &r.latency_ms,
                            &r.loss_rate,
                            &r.success_count,
                            &r.probe_count,
                            &r.ewma_latency,
                            &r.jitter_ms,
                            &r.consecutive_fail);
        } else {
            /* v1 格式兼容 */
            parsed = sscanf(line, "%63[^|]|%7[^|]|%63[^|]|%63[^|]|%d|%d|%d|%d",
                            r.ip,
                            r.data_center,
                            r.region,
                            r.city,
                            &r.latency_ms,
                            &r.loss_rate,
                            &r.success_count,
                            &r.probe_count);
        }
        if (parsed < 8 || !r.ip[0]) continue;
        if (r.latency_ms <= 0) r.latency_ms = g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1;
        if (r.probe_count <= 0) r.probe_count = g_cfg.num > 0 ? g_cfg.num : 1;
        if (r.success_count <= 0) r.success_count = 1;
        /* P0-EWMA: 如果 v1 格式没有 EWMA 字段，用原始延迟初始化 */
        if (r.ewma_latency <= 0) r.ewma_latency = r.latency_ms;
        if (g_cfg.colo[0] && strcmp(r.data_center, "UNK") != 0 && !colo_allowed(r.data_center)) continue;
        resultlist_add(&rl, &r);
        if (g_cfg.ipnum > 0 && rl.len >= (size_t)g_cfg.ipnum) break;
    }
    fclose(fp);
    qsort(rl.items, rl.len, sizeof(Result), cmp_result);
    if (rl.len > 0) log_msg("已读取候选缓存 %s，共 %zu 个（v%d格式），开始快速健康检查", path, rl.len, is_v2 ? 2 : 1);
    return rl;
}

static int try_use_candidate_cache(BaiduProxyPool *proxy_pool, ResultList *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    const char *path = candidate_cache_file("direct");
    ResultList cached = load_candidate_cache(path);
    if (cached.len == 0) {
        pthread_mutex_destroy(&cached.mu);
        return 0;
    }

    size_t check_count = cached.len < CACHE_QUICK_CHECK_COUNT ? cached.len : CACHE_QUICK_CHECK_COUNT;
    for (size_t i = 0; i < check_count; i++) {
        if (health_check_ip(cached.items[i].ip, proxy_pool)) {
            log_msg("命中候选缓存，快速启动使用 IP: %s，后台将继续刷新候选池", cached.items[i].ip);
            *out = cached;
            return 1;
        }
    }

    warn_msg("候选缓存健康检查未命中，将执行完整扫描");
    free(cached.items);
    pthread_mutex_destroy(&cached.mu);
    return 0;
}

static int carrier_try_use_candidate_cache(CarrierRuntime *rt) {
    if (!rt) return 0;
    const char *path = candidate_cache_file(rt->spec.mode);
    ResultList cached = load_candidate_cache(path);
    if (cached.len == 0) {
        pthread_mutex_destroy(&cached.mu);
        return 0;
    }

    size_t check_count = cached.len < CACHE_QUICK_CHECK_COUNT ? cached.len : CACHE_QUICK_CHECK_COUNT;
    size_t first_good = (size_t)-1;
    for (size_t i = 0; i < check_count; i++) {
        if (carrier_health_check_ip(rt, cached.items[i].ip)) {
            first_good = i;
            break;
        }
    }
    if (first_good == (size_t)-1) {
        warn_msg("%s 候选缓存健康检查未命中，将执行完整扫描", carrier_display_name(rt->spec.mode));
        free(cached.items);
        pthread_mutex_destroy(&cached.mu);
        return 0;
    }

    // 缓存命中，将结果交给 CarrierRuntime
    rt->candidates.items = cached.items;
    rt->candidates.len = cached.len;
    carrier_set_current_candidate(rt, first_good);
    log_msg("%s 命中候选缓存，快速启动使用 IP: %s", carrier_display_name(rt->spec.mode), cached.items[first_good].ip);
    // 注意：pthread_mutex_init 已在外面初始化，此处不重复初始化
    // cached.mu 不再需要，但指向的 items 已被 rt 接管，不要销毁
    return 1;
}

static void explain_selected_result(const Result *best) {
    if (!best) return;
    if (g_cfg.log_level < LOG_DEBUG) return;
    printf("结果解释: 选择 %s，因为延迟 %d ms，丢包 %d%%，综合分 %d。\n", best->ip, best->latency_ms, best->loss_rate, score_result(best));
}

static ResultList scan_ips(StringList *ips, CidrList *cidrs, Config *cfg, BaiduProxyPool *proxy_pool) {
    ResultList rl = {0};
    pthread_mutex_init(&rl.mu, NULL);
    uint64_t total_ips = cidrs ? cidrlist_total(cidrs) : (ips ? ips->len : 0);
    int threads = cfg->task;
    if ((uint64_t)threads > total_ips) threads = (int)total_ips;
    if (threads <= 0 || total_ips == 0) {
        pthread_mutex_destroy(&rl.mu);
        return rl;
    }
    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    if (!tids) {
        pthread_mutex_destroy(&rl.mu);
        return rl;
    }
    ScanCtx ctx = {
        .ips = ips ? ips->items : NULL,
        .cidrs = cidrs,
        .total = (size_t)total_ips,
        .results = &rl,
        .cfg = cfg,
        .proxy_pool = proxy_pool,
        .scan_start_ms = now_ms()
    };
    atomic_init(&ctx.index, 0);
    atomic_init(&ctx.completed, 0);
    atomic_init(&ctx.connect_fail, 0);
    atomic_init(&ctx.header_fail, 0);
    atomic_init(&ctx.cfray_miss, 0);
    atomic_init(&ctx.colo_skip, 0);
    log_msg("开始扫描候选 IP: %llu 个，线程: %d，单 IP 探测次数: %d，超时: %d ms",
            (unsigned long long)total_ips, threads, cfg->num > 0 ? cfg->num : 1, cfg->delay_ms);
    int created = 0;
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&tids[i], NULL, scan_worker, &ctx) != 0) break;
        created++;
    }
    for (int i = 0; i < created; i++) pthread_join(tids[i], NULL);
    free(tids);
    pthread_mutex_destroy(&rl.mu);
    qsort(rl.items, rl.len, sizeof(Result), cmp_result);
    if (rl.len > (size_t)cfg->ipnum) rl.len = (size_t)cfg->ipnum;
    log_msg("扫描完成: 有效候选 %zu 个，耗时 %ld 秒", rl.len, (now_ms() - ctx.scan_start_ms) / 1000);
    if (rl.len == 0 || cfg->log_level >= LOG_DEBUG) {
        log_msg("扫描统计: 连接失败 %zu，读取响应失败 %zu，缺少 CF-RAY %zu，数据中心过滤 %zu",
                atomic_load(&ctx.connect_fail),
                atomic_load(&ctx.header_fail),
                atomic_load(&ctx.cfray_miss),
                atomic_load(&ctx.colo_skip));
        if (rl.len == 0 && atomic_load(&ctx.cfray_miss) > 0 && cfg->colo[0]) {
            warn_msg("已连接到部分 IP，但响应中没有 CF-RAY 或不匹配 -colo；可先去掉 -colo 验证网络链路");
        }
    }
    return rl;
}

static int http_probe(socket_t fd, int timeout_ms) {
    // 发送 HTTP GET 请求探测数据通路是否正常
    const char *req = "GET / HTTP/1.0\r\nHost: cloudflaremirrors.com\r\nConnection: close\r\n\r\n";
    size_t reqlen = strlen(req);
    long deadline = now_ms() + timeout_ms;
    size_t sent = 0;
    while (sent < reqlen && now_ms() < deadline) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        struct timeval tv = { left / 1000, (left % 1000) * 1000 };
        int rc = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0) break;
        ssize_t n = send(fd, req + sent, reqlen - sent, 0);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    if (sent < reqlen) return 0;
    // 读取响应头，确认收到 HTTP 响应
    char buf[256];
    size_t used = 0;
    while (used < sizeof(buf) - 1 && now_ms() < deadline) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        struct timeval tv = { left / 1000, (left % 1000) * 1000 };
        int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) break;
        ssize_t n = recv(fd, buf + used, sizeof(buf) - used - 1, 0);
        if (n <= 0) break;
        used += (size_t)n;
        buf[used] = 0;
        if (strstr(buf, "HTTP/")) return 1;  // 收到 HTTP 响应头表示数据通路正常
    }
    return 0;
}

/* P0-EWMA: 增强健康检查，更新候选池中对应 IP 的 EWMA 和连续失败计数 */
static int health_check_ip(const char *ip, BaiduProxyPool *proxy_pool) {
    int latency = 0;
    socket_t fd = dial_target_with_proxy(ip, g_cfg.port, g_cfg.delay_ms, proxy_pool, &latency);
    if (cfnat_socket_invalid(fd)) {
        debug_msg("健康检查失败: IP %s TCP 不可达", ip);
        return 0;
    }
    // TCP 握手成功后再做 HTTP 探测，确认数据通路正常
    int ok = http_probe(fd, g_cfg.delay_ms);
    close(fd);
    if (ok) {
        debug_msg("健康检查成功: IP %s 延迟 %d ms", ip, latency);
        return 1;
    }
    debug_msg("健康检查失败: IP %s TCP 可达但 HTTP 无响应", ip);
    return 0;
}


static void close_pair(socket_t a, socket_t b) {
    shutdown(a, SHUT_RDWR);
    shutdown(b, SHUT_RDWR);
}

/* P1-2: 带超时的 recv，超时返回 -1，errno = ETIMEDOUT */
static ssize_t recv_timeout(socket_t fd, void *buf, size_t len, int timeout_ms) {
    if (timeout_ms <= 0) return recv(fd, buf, len, 0);
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int rc = select((int)(fd + 1), &rfds, NULL, NULL, &tv);
    if (rc <= 0) {
        if (rc == 0) errno = ETIMEDOUT;
        return -1;
    }
    return recv(fd, buf, len, 0);
}

#ifdef __linux__
/* P1-4: Linux 零拷贝转发，使用 splice() 避免用户态内存拷贝 */
static void *pipe_worker(void *arg) {
    PipeCtx *pc = (PipeCtx *)arg;
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        /* pipe 创建失败，回退到普通 recv/send */
        char buf[COPY_BUF_SIZE];
        while (1) {
            ssize_t n = recv_timeout(pc->from, buf, sizeof(buf), 300000);
            if (n <= 0) break;
            char *p = buf;
            ssize_t left = n;
            while (left > 0) {
                ssize_t w = send(pc->to, p, (size_t)left, 0);
                if (w <= 0) goto done;
                p += w;
                left -= w;
            }
        }
        goto done;
    }
    while (1) {
        ssize_t n = splice(pc->from, NULL, pipefd[1], NULL, 65536, SPLICE_F_MOVE);
        if (n <= 0) break;
        while (n > 0) {
            ssize_t w = splice(pipefd[0], NULL, pc->to, NULL, (size_t)n, SPLICE_F_MOVE);
            if (w <= 0) goto done;
            n -= w;
        }
    }
    close(pipefd[0]);
    close(pipefd[1]);
    done : close_pair(pc->from, pc->to);
    return NULL;
}
#else
/* 非 Linux 平台使用普通 recv/send 转发 */
static void *pipe_worker(void *arg) {
    PipeCtx *pc = (PipeCtx *)arg;
    char buf[COPY_BUF_SIZE];
    while (1) {
        /* P1-2: recv 带 300 秒超时，防止空闲连接永久阻塞 */
        ssize_t n = recv_timeout(pc->from, buf, sizeof(buf), 300000);
        if (n <= 0) break;
        char *p = buf;
        ssize_t left = n;
        while (left > 0) {
            ssize_t w = send(pc->to, p, (size_t)left, 0);
            if (w <= 0) goto done;
            p += w;
            left -= w;
        }
    }
    done : close_pair(pc->from, pc->to);
    return NULL;
}
#endif

static int create_small_thread(pthread_t *tid, void *(*fn)(void *), void *arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 64 * 1024);
    int rc = pthread_create(tid, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    return rc;
}



static int relay_bidirectional(socket_t c, socket_t u) {
    pthread_t t1, t2;
    PipeCtx a = {
        c,
        u
    }
    , b = {
        u,
        c
    };
    create_small_thread(&t1, pipe_worker, &a);
    create_small_thread(&t2, pipe_worker, &b);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}

static void *connection_thread(void *arg) {
    ConnCtx *cc = (ConnCtx *)arg;
    socket_t client = cc->client_fd;
    unsigned char first = 0;
    /* P1-2: 首字节 recv 带 60 秒超时，防止空闲连接占用线程 */
    ssize_t n = recv_timeout(client, (char *) & first, 1, 60000);
    if (n <= 0) goto out;
    int is_tls = first == 0x16;
    int target_port = is_tls ? cc->tls_port : cc->http_port;
    conn_msg("识别客户端协议: %s，转发到 IP: %s 端口: %d", is_tls ? "TLS" : "非 TLS", cc->ip, target_port);
    socket_t upstream = INVALID_SOCKET;
    int best = 0;

    if (cc->use_mixed) {
        // 混合模式：先直连，不行再试百度前置
        for (int i = 0; i < cc->num; i++) {
            int lat = 0;
            socket_t fd = dial_target_with_proxy(cc->ip, target_port, cc->delay_ms, NULL, &lat);
            if (cfnat_socket_valid(fd)) {
                upstream = fd;
                best = lat;
                conn_msg("选择连接: 地址: %s:%d 延迟: %d ms (直连)", cc->ip, target_port, best);
                break;
            }
        }
        if (cfnat_socket_invalid(upstream) && cc->proxy_pool) {
            for (int i = 0; i < cc->num; i++) {
                int lat = 0;
                socket_t fd = dial_target_with_proxy(cc->ip, target_port, cc->delay_ms, cc->proxy_pool, &lat);
                if (cfnat_socket_valid(fd)) {
                    upstream = fd;
                    best = lat;
                    conn_msg("选择连接: 地址: %s:%d 延迟: %d ms (百度前置)", cc->ip, target_port, best);
                    break;
                }
            }
        }
    } else {
        // 普通模式
        for (int i = 0; i < cc->num; i++) {
            int lat = 0;
            socket_t fd = dial_target_with_proxy(cc->ip, target_port, cc->delay_ms, cc->proxy_pool, &lat);
            if (cfnat_socket_valid(fd)) {
                upstream = fd;
                best = lat;
                conn_msg("选择连接: 地址: %s:%d 延迟: %d ms", cc->ip, target_port, best);
                break;
            }
        }
    }

    if (cfnat_socket_invalid(upstream)) {
        debug_msg("未找到符合延迟要求的连接，关闭客户端连接");
        goto out;
    }
    send(upstream, (const char *) & first, 1, 0);
    relay_bidirectional(client, upstream);
    close(upstream);
    out : close(client);
    int active = atomic_fetch_sub(&g_active_connections, 1) - 1;
    conn_msg("客户端连接关闭，当前活跃连接数: %d", active);
    free(cc);
    return NULL;
}

/* P1-HC: 健康检查级别 */
typedef enum {
    HC_LIGHT = 0,   /* 仅 TCP 握手 */
    HC_MEDIUM,      /* TCP + 首字节响应 */
    HC_FULL         /* TCP + HTTP 完整探测 */
} HealthCheckLevel;

static int carrier_probe_and_check(socket_t fd, int timeout_ms) {
    // TCP 握手成功后做 HTTP 探测，确认数据通路正常
    int ok = http_probe(fd, timeout_ms);
    close(fd);
    return ok;
}

/* P1-HC: 增强 carrier 健康检查，支持级别参数 */
static int carrier_health_check_ip_level(CarrierRuntime *rt, const char *ip, HealthCheckLevel level) {
    if (!rt || !ip || !*ip) return 0;
    // 混合模式：先试直连，不行再试百度代理
    if (rt->spec.use_baidu_proxy == 2) {
        int latency = 0;
        socket_t fd = dial_target_with_proxy(ip, g_cfg.port, g_cfg.delay_ms, NULL, &latency);
        if (cfnat_socket_valid(fd)) {
            if (level == HC_LIGHT) {
                close(fd);
                debug_msg("%s 健康检查(轻量/直连)成功: IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
                return 1;
            }
            if (carrier_probe_and_check(fd, g_cfg.delay_ms)) {
                debug_msg("%s 健康检查成功(直连): IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
                return 1;
            }
        } else if (rt->proxy_pool && rt->proxy_pool->len > 0) {
            fd = dial_target_with_proxy(ip, g_cfg.port, g_cfg.delay_ms, rt->proxy_pool, &latency);
            if (cfnat_socket_valid(fd)) {
                if (level == HC_LIGHT) {
                    close(fd);
                    debug_msg("%s 健康检查(轻量/百度)成功: IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
                    return 1;
                }
                if (carrier_probe_and_check(fd, g_cfg.delay_ms)) {
                    debug_msg("%s 健康检查成功(百度前置): IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
                    return 1;
                }
            }
        }
        debug_msg("%s 健康检查失败: IP %s 暂不可用", carrier_display_name(rt->spec.mode), ip);
        return 0;
    }
    // 普通模式
    int latency = 0;
    socket_t fd = dial_target_with_proxy(ip, g_cfg.port, g_cfg.delay_ms, rt->proxy_pool, &latency);
    if (cfnat_socket_invalid(fd)) {
        debug_msg("%s 健康检查失败: IP %s 暂不可用", carrier_display_name(rt->spec.mode), ip);
        return 0;
    }
    if (level == HC_LIGHT) {
        close(fd);
        debug_msg("%s 健康检查(轻量)成功: IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
        return 1;
    }
    if (carrier_probe_and_check(fd, g_cfg.delay_ms)) {
        debug_msg("%s 健康检查成功: IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
        return 1;
    }
    debug_msg("%s 健康检查失败: IP %s TCP 可达但 HTTP 无响应", carrier_display_name(rt->spec.mode), ip);
    return 0;
}

static int carrier_health_check_ip(CarrierRuntime *rt, const char *ip) {
    if (!rt || !ip || !*ip) return 0;
    // 混合模式：先试直连，不行再试百度代理
    if (rt->spec.use_baidu_proxy == 2) {
        int latency = 0;
        socket_t fd = dial_target_with_proxy(ip, g_cfg.port, g_cfg.delay_ms, NULL, &latency);
        if (cfnat_socket_valid(fd)) {
            if (carrier_probe_and_check(fd, g_cfg.delay_ms)) {
                debug_msg("%s 健康检查成功(直连): IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
                return 1;
            }
        } else if (rt->proxy_pool && rt->proxy_pool->len > 0) {
            fd = dial_target_with_proxy(ip, g_cfg.port, g_cfg.delay_ms, rt->proxy_pool, &latency);
            if (cfnat_socket_valid(fd)) {
                if (carrier_probe_and_check(fd, g_cfg.delay_ms)) {
                    debug_msg("%s 健康检查成功(百度前置): IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
                    return 1;
                }
            }
        }
        debug_msg("%s 健康检查失败: IP %s 暂不可用", carrier_display_name(rt->spec.mode), ip);
        return 0;
    }
    // 普通模式
    int latency = 0;
    socket_t fd = dial_target_with_proxy(ip, g_cfg.port, g_cfg.delay_ms, rt->proxy_pool, &latency);
    if (cfnat_socket_invalid(fd)) {
        debug_msg("%s 健康检查失败: IP %s 暂不可用", carrier_display_name(rt->spec.mode), ip);
        return 0;
    }
    if (carrier_probe_and_check(fd, g_cfg.delay_ms)) {
        debug_msg("%s 健康检查成功: IP %s 延迟 %d ms", carrier_display_name(rt->spec.mode), ip, latency);
        return 1;
    }
    debug_msg("%s 健康检查失败: IP %s TCP 可达但 HTTP 无响应", carrier_display_name(rt->spec.mode), ip);
    return 0;
}

static int carrier_set_current_candidate(CarrierRuntime *rt, size_t idx) {
    if (!rt || idx >= rt->candidates.len) return 0;
    pthread_mutex_lock(&rt->candidates.mu);
    snprintf(rt->candidates.current_ip, sizeof(rt->candidates.current_ip), "%s", rt->candidates.items[idx].ip);
    rt->candidates.current_index = idx;
    pthread_mutex_unlock(&rt->candidates.mu);
    return 1;
}

static void carrier_get_current_ip(CarrierRuntime *rt, char *out, size_t sz) {
    if (!rt || !out || sz == 0) return;
    pthread_mutex_lock(&rt->candidates.mu);
    snprintf(out, sz, "%s", rt->candidates.current_ip);
    pthread_mutex_unlock(&rt->candidates.mu);
}

static int carrier_select_valid_ip(CarrierRuntime *rt) {
    if (!rt) return 0;
    for (size_t i = 0; i < rt->candidates.len; i++) {
        if (carrier_health_check_ip(rt, rt->candidates.items[i].ip)) {
            carrier_set_current_candidate(rt, i);
            atomic_store(&rt->candidates.cache_valid, 1);  /* P0-1: 选中有效 IP */
            log_msg("%s 可用 IP: %s (健康检查端口:%d)", carrier_display_name(rt->spec.mode), rt->candidates.items[i].ip, g_cfg.port);
            return 1;
        }
    }
    return 0;
}

static int carrier_switch_next_ip(CarrierRuntime *rt) {
    if (!rt) return 0;
    pthread_mutex_lock(&rt->candidates.mu);
    size_t start = rt->candidates.current_index + 1;
    pthread_mutex_unlock(&rt->candidates.mu);
    for (size_t i = start; i < rt->candidates.len; i++) {
        if (carrier_health_check_ip(rt, rt->candidates.items[i].ip)) {
            carrier_set_current_candidate(rt, i);
            atomic_store(&rt->candidates.cache_valid, 1);  /* P0-1: 新 IP 有效 */
            log_msg("%s 切换到下一个最优 IP: %s 候选索引: %zu", carrier_display_name(rt->spec.mode), rt->candidates.items[i].ip, i);
            return 1;
        }
    }
    return 0;
}

static int carrier_choose_ip_for_connection(CarrierRuntime *rt, char *out, size_t sz) {
    if (!rt || !out || sz == 0) return 0;
    out[0] = '\0';
    if (rt->candidates.len == 0) return 0;

    /* P0-1: 如果缓存有效，直接使用当前 IP，不做健康检查 */
    if (atomic_load(&rt->candidates.cache_valid)) {
        pthread_mutex_lock(&rt->candidates.mu);
        snprintf(out, sz, "%s", rt->candidates.current_ip);
        pthread_mutex_unlock(&rt->candidates.mu);
        if (out[0]) return 1;
    }

    /* 缓存无效或当前 IP 为空，遍历候选池做健康检查 */
    /* 加锁保护 items 数组，防止与 carrier_rescan_and_select_ip 中的 free(items) 竞态 */
    pthread_mutex_lock(&rt->candidates.mu);
    size_t len = rt->candidates.len;
    Result *items = rt->candidates.items;
    pthread_mutex_unlock(&rt->candidates.mu);

    for (size_t i = 0; i < len; i++) {
        if (carrier_health_check_ip(rt, items[i].ip)) {
            snprintf(out, sz, "%s", items[i].ip);
            carrier_set_current_candidate(rt, i);
            atomic_store(&rt->candidates.cache_valid, 1);
            return 1;
        }
    }
    return 0;
}

static int carrier_rescan_and_select_ip(CarrierRuntime *rt, const char *ipfile) {
    if (!rt || !ipfile) return 0;
    /* 加锁保护 items 的释放，防止与 carrier_choose_ip_for_connection 中的读取竞态 */
    pthread_mutex_lock(&rt->candidates.mu);
    free(rt->candidates.items);
    rt->candidates.items = NULL;
    rt->candidates.len = 0;
    rt->candidates.current_ip[0] = '\0';
    rt->candidates.current_index = 0;
    pthread_mutex_unlock(&rt->candidates.mu);
    for (;;) {
        if (!atomic_load(&g_running)) return 0;
        StringList ips = load_ip_list(ipfile, g_cfg.random_mode);
        if (ips.len == 0) {
            warn_msg("%s 没有可扫描的 IP，3 秒后重试", carrier_display_name(rt->spec.mode));
            if (sleep_interruptible_ms(3000) != 0) return 0;
            continue;
        }
        ResultList results = {0};
        if (rt->spec.use_baidu_proxy == 2) {
            // 混合模式重扫描
            ResultList results_direct = scan_ips(&ips, NULL, &g_cfg, NULL);
            ResultList results_baidu = {0};
            if (rt->proxy_pool && rt->proxy_pool->len > 0) {
                results_baidu = scan_ips(&ips, NULL, &g_cfg, rt->proxy_pool);
            }
            pthread_mutex_init(&results.mu, NULL);
            for (size_t j = 0; j < results_direct.len; j++) {
                resultlist_add(&results, &results_direct.items[j]);
            }
            for (size_t j = 0; j < results_baidu.len; j++) {
                int exists = 0;
                for (size_t k = 0; k < results.len; k++) {
                    if (strcmp(results.items[k].ip, results_baidu.items[j].ip) == 0) {
                        exists = 1;
                        break;
                    }
                }
                if (!exists) {
                    resultlist_add(&results, &results_baidu.items[j]);
                }
            }
            free(results_direct.items);
            free(results_baidu.items);
            if (results.len > 0) {
                qsort(results.items, results.len, sizeof(Result), cmp_result);
            }
        } else {
            // 普通模式重扫描
            results = scan_ips(&ips, NULL, &g_cfg, rt->proxy_pool);
        }
        strlist_free(&ips);
        if (results.len == 0) {
            warn_msg("%s 重新扫描后仍未发现有效 IP，3 秒后重试", carrier_display_name(rt->spec.mode));
            if (sleep_interruptible_ms(3000) != 0) return 0;
            continue;
        }
        /* 加锁保护 items 的赋值，防止与 carrier_choose_ip_for_connection 中的读取竞态 */
        pthread_mutex_lock(&rt->candidates.mu);
        rt->candidates.items = results.items;
        rt->candidates.len = results.len;
        pthread_mutex_unlock(&rt->candidates.mu);
        log_msg("%s 重新扫描得到 %zu 个候选 IP", carrier_display_name(rt->spec.mode), rt->candidates.len);
        if (carrier_select_valid_ip(rt)) return 1;
        pthread_mutex_lock(&rt->candidates.mu);
        free(results.items);
        rt->candidates.items = NULL;
        rt->candidates.len = 0;
        pthread_mutex_unlock(&rt->candidates.mu);
        warn_msg("%s 重新扫描得到的候选 IP 健康检查均失败，3 秒后重试", carrier_display_name(rt->spec.mode));
        if (sleep_interruptible_ms(3000) != 0) return 0;
    }
}

/* P1-HC: 渐进式健康检查线程 */
static void *carrier_health_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    int fail = 0;
    long last = 0;
    int consecutive_success = 0;  /* P1-HC: 连续成功次数，用于决定检查级别 */
    while (atomic_load(&g_running)) {
        if (sleep_interruptible_ms(10000) != 0) break;
        char ip[MAX_IP_LEN];
        carrier_get_current_ip(rt, ip, sizeof(ip));

        /* P1-HC: 渐进式健康检查级别 */
        HealthCheckLevel level;
        if (consecutive_success < 3) {
            level = HC_FULL;       /* 前 3 次用完整探测建立基线 */
        } else if (consecutive_success < 10) {
            level = HC_MEDIUM;     /* 3-10 次用中级探测 */
        } else {
            level = HC_LIGHT;      /* 10 次以上用轻量级 TCP 探测 */
        }

        if (!ip[0] || !carrier_health_check_ip_level(rt, ip, level)) {
            fail++;
            consecutive_success = 0;
            atomic_store(&rt->candidates.cache_valid, 0);
            log_msg("%s 状态检查失败 (%d/2): 当前 IP %s 暂不可用", carrier_display_name(rt->spec.mode), fail, ip[0] ? ip : "为空");
        } else {
            fail = 0;
            consecutive_success++;
            atomic_store(&rt->candidates.cache_valid, 1);
            long n = now_ms();
            if (g_cfg.health_log > 0 && n - last >= g_cfg.health_log * 1000L) {
                log_msg("%s 状态检查成功: 当前 IP %s 可用", carrier_display_name(rt->spec.mode), ip);
                last = n;
            }
        }
        if (fail >= 2) {
            log_msg("%s 连续两次状态检查失败，切换到下一个 IP", carrier_display_name(rt->spec.mode));
            if (!carrier_switch_next_ip(rt)) {
                log_msg("%s 没有更多可用 IP，开始重新扫描", carrier_display_name(rt->spec.mode));
                if (!carrier_rescan_and_select_ip(rt, g_cfg.ips_type == 6 ? "ips-v6.txt" : "ips-v4.txt")) {
                    atomic_store(&g_running, 0);
                    return NULL;
                }
            }
            fail = 0;
        }
    }
    return NULL;
}

static void *carrier_accept_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    while (atomic_load(&g_running)) {
        struct sockaddr_storage ss;
#ifdef _WIN32
        int slen = (int)sizeof(ss);
#else
        socklen_t slen = sizeof(ss);
#endif
        socket_t cfd = accept_interruptible(rt->listen_fd, (struct sockaddr *)&ss, &slen);
        if (cfnat_socket_invalid(cfd)) {
            if (!atomic_load(&g_running)) break;
#ifdef _WIN32
            {
                int e = WSAGetLastError();
                if (e == WSAEINTR || e == WSAENOTSOCK) break;
            }
#else
            if (errno == EINTR || errno == EBADF) break;
#endif
            if (sleep_interruptible_ms(1000) != 0) break;
            continue;
        }
        char ip[MAX_IP_LEN];
        if (!carrier_choose_ip_for_connection(rt, ip, sizeof(ip))) {
            close(cfd);
            continue;
        }
        int active = atomic_fetch_add(&g_active_connections, 1) + 1;
        conn_msg("%s 客户端连接建立，当前活跃连接数: %d", carrier_display_name(rt->spec.mode), active);
        ConnCtx *cc = calloc(1, sizeof(ConnCtx));
        if (!cc) {
            close(cfd);
            atomic_fetch_sub(&g_active_connections, 1);
            continue;
        }
        cc->client_fd = cfd;
        snprintf(cc->ip, sizeof(cc->ip), "%s", ip);
        cc->tls_port = g_cfg.port;
        cc->http_port = g_cfg.http_port;
        cc->num = g_cfg.num;
        cc->delay_ms = g_cfg.delay_ms;
        cc->proxy_pool = rt->proxy_pool;
        cc->use_mixed = (rt->spec.use_baidu_proxy == 2) ? 1 : 0;
        pthread_t tid;
        create_small_thread(&tid, connection_thread, cc);
        pthread_detach(tid);
    }
    return NULL;
}

static int parse_addr(const char *addr, char *host, size_t hostsz, int *port) {
    if (!addr || !host || !port) return -1;
    if (addr[0] == '[') {
        const char *end = strchr(addr, ']');
        if (!end || end[1] != ':') return -1;
        size_t n = (size_t)(end - (addr + 1));
        if (n >= hostsz) n = hostsz - 1;
        memcpy(host, addr + 1, n);
        host[n] = 0;
        *port = atoi(end + 2);
        return *port > 0 ? 0 : -1;
    }
    const char *colon = strrchr(addr, ':');
    if (!colon) {
        // 只有端口号的情况，例如 "1234"
        snprintf(host, hostsz, "0.0.0.0");
        *port = atoi(addr);
        return *port > 0 ? 0 : -1;
    }
    size_t n = (size_t)(colon - addr);
    if (n >= hostsz) n = hostsz - 1;
    memcpy(host, addr, n);
    host[n] = 0;
    *port = atoi(colon + 1);
    if (!host[0]) snprintf(host, hostsz, "0.0.0.0");
    return *port > 0 ? 0 : -1;
}

static socket_t listen_tcp(const char *addr) {
    char host[128];
    int port = 0;
    if (parse_addr(addr, host, sizeof(host), &port) != 0) return INVALID_SOCKET;
    int yes = 1;
    
    if (strchr(host, ':')) {
        socket_t fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host, &sa6.sin6_addr) != 1) {
            close(fd);
            return INVALID_SOCKET;
        }
        if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) != 0) {
            int err = errno;
            close(fd);
            errno = err;
            return INVALID_SOCKET;
        }
        if (listen(fd, 1024) != 0) {
            int err = errno;
            close(fd);
            errno = err;
            return INVALID_SOCKET;
        }
        return fd;
    }
    socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return INVALID_SOCKET;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return INVALID_SOCKET;
    }
    if (listen(fd, 1024) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return INVALID_SOCKET;
    }
    return fd;
}

static socket_t accept_interruptible(socket_t listen_fd, struct sockaddr *addr,
#ifdef _WIN32
        int *addrlen
#else
        socklen_t *addrlen
#endif
) {
    while (atomic_load(&g_running)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);

        struct timeval tv = {1, 0};
#ifdef _WIN32
        int rc = select(0, &rfds, NULL, NULL, &tv);
        if (rc == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            return INVALID_SOCKET;
        }
#else
        int rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return INVALID_SOCKET;
        }
#endif
        if (rc == 0) continue;

        socket_t cfd = accept(listen_fd, addr, addrlen);
#ifdef _WIN32
        if (cfnat_socket_invalid(cfd) && WSAGetLastError() == WSAEINTR) continue;
#else
        if (cfnat_socket_invalid(cfd) && errno == EINTR) continue;
#endif
        return cfd;
    }

#ifdef _WIN32
    WSASetLastError(WSAEINTR);
#else
    errno = EINTR;
#endif
    return INVALID_SOCKET;
}

static void on_signal(int sig) {
    (void)sig;
    atomic_store(&g_running, 0);
    if (cfnat_socket_valid(g_listen_fd)) {
        close(g_listen_fd);
        g_listen_fd = INVALID_SOCKET;
    }
    for (size_t i = 0; i < g_carrier_runtime_count; i++) {
        if (cfnat_socket_valid(g_carrier_runtimes[i].listen_fd)) {
            close(g_carrier_runtimes[i].listen_fd);
            g_carrier_runtimes[i].listen_fd = INVALID_SOCKET;
        }
    }
}

static void install_signals(void) {
#ifdef _WIN32
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
#endif
}

int main(int argc, char **argv) {
#ifdef _WIN32
    init_windows_console_utf8();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    parse_args(&g_cfg, argc, argv);
    install_signals();
    const char *ipfile = g_cfg.ips_type == 6 ? "ips-v6.txt" : "ips-v4.txt";
    const char **urls = g_cfg.ips_type == 6 ? IPS_V6_URLS : IPS_V4_URLS;
    if (ensure_data_file(ipfile, urls) != 0) {
        log_msg("下载 %s 失败", ipfile);
        return 1;
    }
    log_msg("正在加载 locations.json");
    load_locations();
    log_msg("locations 加载完成: %zu 条", g_location_count);
    CarrierListenSpec *carrier_specs = NULL;
    size_t carrier_spec_len = 0;
    if (parse_listen_modes(&g_cfg, &carrier_specs, &carrier_spec_len) != 0) {
        log_msg("解析 -direct-listen / -baidu-listen 失败");
        free(g_locations);
        return 1;
    }
    StringList ips = load_ip_list(ipfile, g_cfg.random_mode);
    if (ips.len == 0) {
        log_msg("没有可扫描的 IP");
        free(carrier_specs);
        baidu_pool_free(&g_default_proxy_pool);
        free(g_locations);
        return 1;
    }
    if (carrier_spec_len > 0) {
        size_t started_count = 0;
        g_carrier_runtimes = calloc(carrier_spec_len, sizeof(CarrierRuntime));
        if (!g_carrier_runtimes) {
            strlist_free(&ips);
            free(carrier_specs);
            baidu_pool_free(&g_default_proxy_pool);
            free(g_locations);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        g_carrier_runtime_count = carrier_spec_len;
        log_msg("双方案监听模式启动，监听器数量: %zu", carrier_spec_len);
        for (size_t i = 0; i < carrier_spec_len; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            rt->listen_fd = INVALID_SOCKET;
            rt->spec = carrier_specs[i];
            pthread_mutex_init(&rt->candidates.mu, NULL);
            atomic_init(&rt->candidates.cache_valid, 0);  /* P0-1: 初始时缓存无效 */

            ResultList carrier_results = {0};
            // 先尝试读取候选缓存
            if (carrier_try_use_candidate_cache(rt)) {
                started_count++;
                rt->listen_fd = listen_tcp(rt->spec.addr);
                if (cfnat_socket_invalid(rt->listen_fd)) {
                    log_msg("无法监听 %s(%s): %s", carrier_display_name(rt->spec.mode), rt->spec.addr, strerror(errno));
                    free(rt->candidates.items);
                    rt->candidates.items = NULL;
                    rt->candidates.len = 0;
                    continue;
                }
                log_msg("%s 正在监听 %s，TLS目标端口：%d，非TLS目标端口：%d，连接尝试次数：%d，有效延迟：%d ms，日志：%s", carrier_display_name(rt->spec.mode), rt->spec.addr, g_cfg.port, g_cfg.http_port, g_cfg.num, g_cfg.delay_ms, g_cfg.log_name);
                create_small_thread(&rt->health_tid, carrier_health_thread, rt);
                create_small_thread(&rt->accept_tid, carrier_accept_thread, rt);
                continue;
            }
            if (rt->spec.use_baidu_proxy == 2) {
                // 混合模式：同时用直连和百度扫描，合并结果
                rt->proxy_pool = calloc(1, sizeof(BaiduProxyPool));
                if (rt->proxy_pool && build_baidu_pool_for_carrier(rt->proxy_pool, rt->spec.mode) == 0) {
                    log_msg("%s 百度代理池已建立，节点数: %zu", carrier_display_name(rt->spec.mode), rt->proxy_pool->len);
                } else {
                    if (rt->proxy_pool) {
                        baidu_pool_free(rt->proxy_pool);
                        free(rt->proxy_pool);
                    }
                    rt->proxy_pool = NULL;
                    warn_msg("%s 百度代理池建立失败，只使用直连扫描", carrier_display_name(rt->spec.mode));
                }

                // 先直连扫描
                ResultList results_direct = scan_ips(&ips, NULL, &g_cfg, NULL);
                // 再百度前置扫描（如果有百度代理池的话）
                ResultList results_baidu = {0};
                if (rt->proxy_pool && rt->proxy_pool->len > 0) {
                    results_baidu = scan_ips(&ips, NULL, &g_cfg, rt->proxy_pool);
                }

                // 合并结果，去重
                pthread_mutex_init(&carrier_results.mu, NULL);
                // 先加直连的
                for (size_t j = 0; j < results_direct.len; j++) {
                    resultlist_add(&carrier_results, &results_direct.items[j]);
                }
                // 再加百度的，跳过重复 IP
                for (size_t j = 0; j < results_baidu.len; j++) {
                    int exists = 0;
                    for (size_t k = 0; k < carrier_results.len; k++) {
                        if (strcmp(carrier_results.items[k].ip, results_baidu.items[j].ip) == 0) {
                            exists = 1;
                            break;
                        }
                    }
                    if (!exists) {
                        resultlist_add(&carrier_results, &results_baidu.items[j]);
                    }
                }
                // 释放临时结果
                free(results_direct.items);
                free(results_baidu.items);

                // 对合并后的结果排序
                if (carrier_results.len > 0) {
                    qsort(carrier_results.items, carrier_results.len, sizeof(Result), cmp_result);
                }
            } else {
                // 普通模式
                if (rt->spec.use_baidu_proxy) {
                    rt->proxy_pool = calloc(1, sizeof(BaiduProxyPool));
                    if (rt->proxy_pool && build_baidu_pool_for_carrier(rt->proxy_pool, rt->spec.mode) == 0) {
                        log_msg("%s 百度代理池已建立，节点数: %zu", carrier_display_name(rt->spec.mode), rt->proxy_pool->len);
                    } else {
                        if (rt->proxy_pool) {
                            baidu_pool_free(rt->proxy_pool);
                            free(rt->proxy_pool);
                        }
                        rt->proxy_pool = NULL;
                        warn_msg("%s 百度代理池建立失败，跳过此监听", carrier_display_name(rt->spec.mode));
                        continue;
                    }
                }
                carrier_results = scan_ips(&ips, NULL, &g_cfg, rt->proxy_pool);
            }

            if (carrier_results.len == 0) {
                warn_msg("%s 未扫描到可用候选 IP", carrier_display_name(rt->spec.mode));
                continue;
            }
            rt->candidates.items = carrier_results.items;
            rt->candidates.len = carrier_results.len;
            // 扫描完成后保存缓存，供下次启动加速
            save_candidate_cache(candidate_cache_file(rt->spec.mode), carrier_results.items, carrier_results.len);
            if (!carrier_select_valid_ip(rt)) {
                warn_msg("%s 候选 IP 健康检查全部失败", carrier_display_name(rt->spec.mode));
                free(rt->candidates.items);
                rt->candidates.items = NULL;
                rt->candidates.len = 0;
                continue;
            }
            rt->listen_fd = listen_tcp(rt->spec.addr);
            if (cfnat_socket_invalid(rt->listen_fd)) {
                log_msg("无法监听 %s(%s): %s", carrier_display_name(rt->spec.mode), rt->spec.addr, strerror(errno));
                free(rt->candidates.items);
                rt->candidates.items = NULL;
                rt->candidates.len = 0;
                continue;
            }
            log_msg("%s 正在监听 %s，TLS目标端口：%d，非TLS目标端口：%d，连接尝试次数：%d，有效延迟：%d ms，日志：%s", carrier_display_name(rt->spec.mode), rt->spec.addr, g_cfg.port, g_cfg.http_port, g_cfg.num, g_cfg.delay_ms, g_cfg.log_name);
            create_small_thread(&rt->health_tid, carrier_health_thread, rt);
            create_small_thread(&rt->accept_tid, carrier_accept_thread, rt);
            started_count++;
        }
        strlist_free(&ips);
        free(carrier_specs);
        if (started_count == 0) {
            for (size_t i = 0; i < g_carrier_runtime_count; i++) {
                CarrierRuntime *rt = &g_carrier_runtimes[i];
                free(rt->candidates.items);
                pthread_mutex_destroy(&rt->candidates.mu);
                if (rt->proxy_pool) {
                    baidu_pool_free(rt->proxy_pool);
                    free(rt->proxy_pool);
                }
            }
            free(g_carrier_runtimes);
            g_carrier_runtimes = NULL;
            g_carrier_runtime_count = 0;
            baidu_pool_free(&g_default_proxy_pool);
            free(g_locations);
            g_locations = NULL;
            g_location_count = 0;
            return 1;
        }
        while (atomic_load(&g_running)) {
            if (sleep_interruptible_ms(1000) != 0) break;
        }
        for (size_t i = 0; i < g_carrier_runtime_count; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            if (cfnat_socket_valid(rt->listen_fd)) {
                close(rt->listen_fd);
                rt->listen_fd = INVALID_SOCKET;
            }
        }
        for (size_t i = 0; i < g_carrier_runtime_count; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            if (rt->health_tid) pthread_join(rt->health_tid, NULL);
            if (rt->accept_tid) pthread_join(rt->accept_tid, NULL);
            free(rt->candidates.items);
            rt->candidates.items = NULL;
            rt->candidates.len = 0;
            pthread_mutex_destroy(&rt->candidates.mu);
            if (rt->proxy_pool) {
                baidu_pool_free(rt->proxy_pool);
                free(rt->proxy_pool);
                rt->proxy_pool = NULL;
            }
        }
        free(g_carrier_runtimes);
        g_carrier_runtimes = NULL;
        g_carrier_runtime_count = 0;
        baidu_pool_free(&g_default_proxy_pool);
        free(g_locations);
        g_locations = NULL;
        g_location_count = 0;
        return 0;
    }
    long start = now_ms();
    // 先尝试读取候选缓存，如果命中且健康检查通过则跳过完整扫描
    ResultList results = {0};
    int cache_hit = try_use_candidate_cache(NULL, &results);
    if (!cache_hit) {
        results = scan_ips(&ips, NULL, &g_cfg, NULL);
        if (results.len > 0) {
            save_candidate_cache(candidate_cache_file("direct"), results.items, results.len);
        }
    }
    strlist_free(&ips);
    free(carrier_specs);
    if (!cache_hit) {
        printf("候选池统计\n");
        printf("候选总数: %zu\n", results.len);
        printf("IP 地址 | 数据中心 | 地区 | 城市 | 延迟 | 丢包 | 探测成功\n");
        for (size_t i = 0; i < results.len; i++) printf("%s | %s | %s | %s | %d ms | %d%% | %d/%d\n", results.items[i].ip, results.items[i].data_center, results.items[i].region, results.items[i].city, results.items[i].latency_ms, results.items[i].loss_rate, results.items[i].success_count, results.items[i].probe_count);
    }
    printf("成功提取 %zu 个有效IP，耗时 %ld秒\n", results.len, (now_ms() - start) / 1000);
    if (results.len > 0) {
        printf("评分最优 IP: %s\n", results.items[0].ip);
        printf("最佳延迟: %d ms\n", results.items[0].latency_ms);
        printf("最佳丢包率: %d%%\n", results.items[0].loss_rate);
        explain_selected_result(&results.items[0]);
    }
    free(results.items);
    baidu_pool_free(&g_default_proxy_pool);
    free(g_locations);
    g_locations = NULL;
    g_location_count = 0;
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
