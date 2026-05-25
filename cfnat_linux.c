#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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
static const char *DEFAULT_CARRIER_RESOLVERS = "";

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
    char addr[64], colo[128], domain[256], log_name[16];
    char baidu_domain[MAX_DOMAIN_LEN], baidu_scan_target[MAX_ADDR_LEN], carrier_listens[256], carrier_resolvers[512];
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

typedef struct {
    char **ips;
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

typedef struct {
    char carrier[MAX_NAME_LEN];
    char addr[MAX_ADDR_LEN];
} CarrierListenSpec;

typedef struct {
    char carrier[MAX_NAME_LEN];
    char addrs[16][MAX_RESOLVER_LEN];
    size_t len;
} CarrierResolverSpec;

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
};

typedef struct {
    Result *items;
    size_t len;
    size_t current_index;
    char current_ip[MAX_IP_LEN];
    pthread_mutex_t mu;
} CandidatePool;

typedef struct {
    int client_fd, tls_port, http_port, num, delay_ms;
    char ip[MAX_IP_LEN];
    BaiduProxyPool *proxy_pool;
} ConnCtx;

typedef struct {
    int from, to;
} PipeCtx;

typedef struct {
    int listen_fd;
    CarrierListenSpec spec;
    CandidatePool candidates;
    BaiduProxyPool *proxy_pool;
    pthread_t health_tid;
    pthread_t accept_tid;
} CarrierRuntime;

static Config g_cfg;
static Location *g_locations = NULL;
static size_t g_location_count = 0;
static Result *g_candidates = NULL;
static size_t g_candidate_count = 0, g_current_index = 0;

static char g_current_ip[MAX_IP_LEN] = {0};

static pthread_mutex_t g_ip_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_running = 1;
static atomic_int g_active_connections = 0;
static int g_listen_fd = -1;

static BaiduProxyPool g_default_proxy_pool = {0};

static CarrierRuntime *g_carrier_runtimes = NULL;
static size_t g_carrier_runtime_count = 0;
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;


static int parse_addr(const char *addr, char *host, size_t hostsz, int *port);
static int accept_interruptible(int listen_fd, struct sockaddr *addr, socklen_t *addrlen);

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + tv.tv_usec / 1000L;
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
    localtime_r(&t, &tmv);
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
        struct timespec ts;
        ts.tv_sec = chunk / 1000;
        ts.tv_nsec = (long)(chunk % 1000) * 1000000L;
        nanosleep(&ts, NULL);
        left -= chunk;
    }
    return atomic_load(&g_running) ? 0 : -1;
}

static void usage(const char *p) {
    printf("Usage of %s:\n", p);
    printf("  -addr=value               本地监听的 IP 和端口 (default 0.0.0.0:1234)\n");
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
    printf("  -baidu-proxy=value        是否启用百度前置代理 (default false)\n");
    printf("  -carrier-listens=value    运营商分池监听，例如 mobile=0.0.0.0:1234,telecom=0.0.0.0:1235\n");
}

static int parse_bool(const char *v) {
    return !v || strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0;
}

static void cfg_defaults(Config *c) {
    memset(c, 0, sizeof(*c));
    strcpy(c->addr, "0.0.0.0:1234");
    strcpy(c->domain, "cloudflaremirrors.com/debian");
    strcpy(c->log_name, "info");
    strcpy(c->baidu_domain, DEFAULT_BAIDU_DOMAIN);
    strcpy(c->baidu_scan_target, DEFAULT_BAIDU_SCAN_TARGET);
    strcpy(c->carrier_resolvers, DEFAULT_CARRIER_RESOLVERS);
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
        if (arg[0] != '-') continue;
        char *key = arg + 1;
        if (*key == '-') key++;
        char *eq = strchr(key, '=');
        char *val = NULL;
        if (eq) {
            *eq = 0;
            val = eq + 1;
        } else if (i + 1 < argc && argv[i + 1][0] != '-') val = argv[++i];
        if (!strcmp(key, "addr") && val) snprintf(c->addr, sizeof(c->addr), "%s", val);
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
        else if (!strcmp(key, "baidu-proxy")) c->use_baidu_proxy = parse_bool(val);
        else if (!strcmp(key, "carrier-listens") && val) snprintf(c->carrier_listens, sizeof(c->carrier_listens), "%s", val);
    }
    if (c->delay_ms <= 0) c->delay_ms = 300;
    if (c->ipnum <= 0) c->ipnum = 20;
    if (c->num <= 0) c->num = 1;
    if (c->task <= 0) c->task = 1;
    if (c->task > 512) c->task = 512;
    if (c->baidu_port <= 0) c->baidu_port = 443;
    if (c->baidu_ipnum <= 0) c->baidu_ipnum = 12;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int download_file_from_urls(const char **urls, const char *filename) {
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
    if (!file_exists("locations.json")) {
        printf("本地 locations.json 不存在，正在下载 locations.json\n");
        if (download_file_from_urls(LOC_URLS, "locations.json") != 0) {
            log_msg("下载 locations.json 失败");
            return;
        }
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

static int set_nonblock(int fd, int nb) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nb) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static int tcp_connect(const char *ip, int port, int timeout_ms, int *latency_ms) {
    long start = now_ms();
    int fd = socket(strchr(ip, ':') ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_nonblock(fd, 1);
    int rc;
    if (strchr(ip, ':')) {
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip, &sa6.sin6_addr) != 1) {
            close(fd);
            return -1;
        }
        rc = connect(fd, (struct sockaddr *)&sa6, sizeof(sa6));
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
            close(fd);
            return -1;
        }
        rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    }
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv = {
        timeout_ms / 1000,
        (timeout_ms % 1000) * 1000
    };
    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) {
        close(fd);
        return -1;
    }
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        close(fd);
        return -1;
    }
    set_nonblock(fd, 0);
    if (latency_ms) * latency_ms = (int)(now_ms() - start);
    return fd;
}

static int recv_headers(int fd, char *buf, size_t bufsz, int timeout_ms) {
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

static int extract_cfray(const char *headers, char *colo, size_t sz) {
    const char *p = strcasestr(headers, "CF-RAY:");
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

static const char *carrier_display_name(const char *carrier) {
    if (str_eq_ci(carrier, "mobile")) return "中国移动";
    if (str_eq_ci(carrier, "telecom")) return "中国电信";
    if (str_eq_ci(carrier, "unicom")) return "中国联通";
    return carrier ? carrier : "unknown";
}

static int normalize_carrier(const char *value, char *out, size_t outsz) {
    if (!value || !out || outsz == 0) return -1;
    if (!strcasecmp(value, "mobile") || !strcasecmp(value, "cmcc") || !strcasecmp(value, "china-mobile") || !strcmp(value, "移动") ||
            !strcmp(value, "中国移动")) {
        snprintf(out, outsz, "mobile");
        return 0;
    }
    if (!strcasecmp(value, "telecom") || !strcasecmp(value, "ct") || !strcasecmp(value, "chinanet") || !strcasecmp(value, "china-telecom") ||
            !strcmp(value, "电信") || !strcmp(value, "中国电信")) {
        snprintf(out, outsz, "telecom");
        return 0;
    }
    if (!strcasecmp(value, "unicom") || !strcasecmp(value, "cu") || !strcasecmp(value, "cuc") || !strcasecmp(value, "china-unicom") ||
            !strcmp(value, "联通") || !strcmp(value, "中国联通")) {
        snprintf(out, outsz, "unicom");
        return 0;
    }
    return -1;
}

static void append_unique_addr(StringList *list, const char *value) {
    if (!list || !value || !*value) return;
    for (size_t i = 0; i < list->len; i++) {
        if (!strcmp(list->items[i], value)) return;
    }
    strlist_add(list, value);
}

static int read_first_nameserver(char *out, size_t outsz) {
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (!f) {
        snprintf(out, outsz, "1.1.1.1");
        return 0;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        trim_line(line);
        if (strncmp(line, "nameserver", 10) != 0) continue;
        char *p = line + 10;
        while (*p == ' ' || *p == '	') p++;
        if (!*p || strchr(p, ':')) continue;
        char *e = p;
        while (*e && *e != ' ' && *e != '	') e++;
        *e = '\0';
        snprintf(out, outsz, "%s", p);
        fclose(f);
        return 0;
    }
    fclose(f);
    snprintf(out, outsz, "1.1.1.1");
    return 0;
}

static int dns_encode_name(const char *name, unsigned char *buf, size_t bufsz, size_t *off) {
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63 || *off + 1 + len >= bufsz) return -1;
        buf[(*off)++] = (unsigned char)len;
        memcpy(buf + *off, p, len);
        *off += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (*off >= bufsz) return -1;
    buf[(*off)++] = 0;
    return 0;
}

static int dns_skip_name(const unsigned char *buf, size_t len, size_t *off) {
    size_t p = *off;
    while (p < len) {
        unsigned char c = buf[p++];
        if (c == 0) {
            *off = p;
            return 0;
        }
        if ((c & 0xC0) == 0xC0) {
            if (p >= len) return -1;
            p++;
            *off = p;
            return 0;
        }
        if ((c & 0xC0) != 0 || p + c > len) return -1;
        p += c;
    }
    return -1;
}

static int lookup_txt_first(const char *name, char *out, size_t outsz) {
    if (!name || !out || outsz == 0) return -1;
    out[0] = '\0';

    unsigned char query[512];
    memset(query, 0, sizeof(query));
    unsigned short id = (unsigned short)((now_ms() ^ (long)getpid()) & 0xffff);
    query[0] = (unsigned char)(id >> 8);
    query[1] = (unsigned char)(id & 0xff);
    query[2] = 0x01;
    query[5] = 0x01;
    size_t qlen = 12;
    if (dns_encode_name(name, query, sizeof(query), &qlen) != 0) return -1;
    if (qlen + 4 > sizeof(query)) return -1;
    query[qlen++] = 0x00;
    query[qlen++] = 0x10;
    query[qlen++] = 0x00;
    query[qlen++] = 0x01;

    char ns[64];
    read_first_nameserver(ns, sizeof(ns));
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    if (inet_pton(AF_INET, ns, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (sendto(fd, query, qlen, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = {2, 0};
    int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) {
        close(fd);
        return -1;
    }

    unsigned char answer[4096];
    ssize_t n = recvfrom(fd, answer, sizeof(answer), 0, NULL, NULL);
    close(fd);
    if (n < 12) return -1;
    size_t len = (size_t)n;
    if (answer[0] != query[0] || answer[1] != query[1]) return -1;
    if ((answer[3] & 0x0f) != 0) return -1;

    unsigned int qd = ((unsigned int)answer[4] << 8) | answer[5];
    unsigned int an = ((unsigned int)answer[6] << 8) | answer[7];
    size_t off = 12;
    for (unsigned int i = 0; i < qd; i++) {
        if (dns_skip_name(answer, len, &off) != 0 || off + 4 > len) return -1;
        off += 4;
    }

    for (unsigned int i = 0; i < an; i++) {
        if (dns_skip_name(answer, len, &off) != 0 || off + 10 > len) return -1;
        unsigned int type = ((unsigned int)answer[off] << 8) | answer[off + 1];
        unsigned int klass = ((unsigned int)answer[off + 2] << 8) | answer[off + 3];
        unsigned int rdlen = ((unsigned int)answer[off + 8] << 8) | answer[off + 9];
        off += 10;
        if (off + rdlen > len) return -1;
        if (type == 16 && klass == 1 && rdlen > 1) {
            size_t pos = off;
            size_t end = off + rdlen;
            size_t used = 0;
            while (pos < end) {
                unsigned int part = answer[pos++];
                if (pos + part > end) break;
                size_t copy = part;
                if (used + copy >= outsz) copy = outsz - used - 1;
                memcpy(out + used, answer + pos, copy);
                used += copy;
                pos += part;
                if (used + 1 >= outsz) break;
            }
            out[used] = '\0';
            return used > 0 ? 0 : -1;
        }
        off += rdlen;
    }
    return -1;
}


static int lookup_asn_for_ip(const char *ip, char *out, size_t outsz) {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    char query[128];
    snprintf(query, sizeof(query), "%u.%u.%u.%u.origin.asn.cymru.com", d, c, b, a);
    char txt[512] = {0};
    if (lookup_txt_first(query, txt, sizeof(txt)) != 0) return -1;
    char *sep = strchr(txt, '|');
    if (sep) * sep = '\0';
    trim_line(txt);
    if (!txt[0]) return -1;
    snprintf(out, outsz, "%s", txt);
    return 0;
}

static int lookup_as_name_for_asn(const char *asn, char *out, size_t outsz) {
    char query[128];
    snprintf(query, sizeof(query), "AS%s.asn.cymru.com", asn);
    char txt[512] = {0};
    if (lookup_txt_first(query, txt, sizeof(txt)) != 0) return -1;
    char *last = NULL;
    char *save = NULL;
    for (char *tok = strtok_r(txt, "|", &save); tok; tok = strtok_r(NULL, "|", &save)) last = tok;
    if (!last) return -1;
    trim_line(last);
    snprintf(out, outsz, "%s", last);
    return 0;
}

static int carrier_from_asn(const char *asn, const char *as_name, char *out, size_t outsz) {
    if (!asn || !out) return -1;
    if (!strcmp(asn, "9808") || !strcmp(asn, "56040") || !strcmp(asn, "56041") || !strcmp(asn, "56042") || !strcmp(asn, "56044") ||
            !strcmp(asn, "56046") || !strcmp(asn, "56047") || !strcmp(asn, "56048") || !strcmp(asn, "56050") || !strcmp(asn, "56052") ||
            !strcmp(asn, "56055") || !strcmp(asn, "56056") || !strcmp(asn, "56057") || !strcmp(asn, "56058") || !strcmp(asn, "56059") ||
            !strcmp(asn, "56060") || !strcmp(asn, "56061") || !strcmp(asn, "56062")) {
        snprintf(out, outsz, "mobile");
        return 0;
    }
    if (!strcmp(asn, "4134") || !strcmp(asn, "4809") || !strcmp(asn, "4812") || !strcmp(asn, "4816") || !strcmp(asn, "4811") ||
            !strcmp(asn, "4813") || !strcmp(asn, "4815") || !strcmp(asn, "23724") || !strcmp(asn, "134756")) {
        snprintf(out, outsz, "telecom");
        return 0;
    }
    if (!strcmp(asn, "4837") || !strcmp(asn, "4808") || !strcmp(asn, "9929") || !strcmp(asn, "10099") || !strcmp(asn, "17621") ||
            !strcmp(asn, "136958") || !strcmp(asn, "140717")) {
        snprintf(out, outsz, "unicom");
        return 0;
    }
    char upper[256] = {0};
    if (as_name) {
        snprintf(upper, sizeof(upper), "%s", as_name);
        for (size_t i = 0; upper[i]; i++) if (upper[i] >= 'a' && upper[i] <= 'z') upper[i] = (char)(upper[i] - 32);
    }
    if (strstr(upper, "MOBILE") || strstr(upper, "CMNET") || strstr(upper, "CMCC") || strstr(upper, "CHINAMOBILE")) {
        snprintf(out, outsz, "mobile");
        return 0;
    }
    if (strstr(upper, "TELECOM") || strstr(upper, "CHINANET") || strstr(upper, "CHINA NET") || strstr(upper, "CN2")) {
        snprintf(out, outsz, "telecom");
        return 0;
    }
    if (strstr(upper, "UNICOM") || strstr(upper, "CHINA169") || strstr(upper, "CNCGROUP") || strstr(upper, "NETCOM")) {
        snprintf(out, outsz, "unicom");
        return 0;
    }
    return -1;
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
}

static long proxy_node_score(const BaiduProxyNode *node) {
    long ewma = atomic_load(&node->ewma_ms);
    int active = atomic_load(&node->active);
    int failures = atomic_load(&node->failures);
    return ewma + (long)active * 50L + (long)failures * 300L;
}

static BaiduProxyNode *baidu_pool_pick(BaiduProxyPool *pool) {
    if (!pool || pool->len == 0) return NULL;
    BaiduProxyNode *best = &pool->nodes[0];
    long best_score = proxy_node_score(best);
    for (size_t i = 1; i < pool->len; i++) {
        long score = proxy_node_score(&pool->nodes[i]);
        if (score < best_score) {
            best = &pool->nodes[i];
            best_score = score;
        }
    }
    return best;
}

static int tcp_connect_via_baidu(const char *node_addr, const char *target_addr, int timeout_ms, int *latency_ms) {
    long start = now_ms();
    char host[MAX_ADDR_LEN] = {0};
    int port = 0;
    if (parse_addr(node_addr, host, sizeof(host), &port) != 0) return -1;
    int fd = tcp_connect(host, port, timeout_ms, NULL);
    if (fd < 0) return -1;
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
        return -1;
    }
    char hdr[4096];
    int n = recv_headers(fd, hdr, sizeof(hdr), timeout_ms);
    if (n <= 0 || strstr(hdr, " 200 ") == NULL) {
        close(fd);
        return -1;
    }
    if (latency_ms) * latency_ms = (int)(now_ms() - start);
    return fd;
}

static int dial_target_with_proxy(const char *ip, int port, int timeout_ms, BaiduProxyPool *pool, int *latency_ms) {
    if (!pool || pool->len == 0) return tcp_connect(ip, port, timeout_ms, latency_ms);
    char target[MAX_ADDR_LEN];
    snprintf(target, sizeof(target), "%s:%d", ip, port);
    BaiduProxyNode *node = baidu_pool_pick(pool);
    if (!node) return -1;
    atomic_fetch_add(&node->active, 1);
    int fd = tcp_connect_via_baidu(node->addr, target, timeout_ms, latency_ms);
    if (fd >= 0) {
        if (latency_ms && *latency_ms > 0) atomic_store(&node->ewma_ms, (atomic_load(&node->ewma_ms) * 7 + *latency_ms) / 8);
        if (atomic_load(&node->failures) > 0) atomic_fetch_sub(&node->failures, 1);
    } else {
        atomic_fetch_add(&node->failures, 1);
    }
    atomic_fetch_sub(&node->active, 1);
    return fd;
}

static int parse_carrier_listens(const char *raw, CarrierListenSpec **out_specs, size_t *out_len) {
    *out_specs = NULL;
    *out_len = 0;
    if (!raw || !*raw) return 0;
    char *tmp = strdup(raw);
    if (!tmp) return -1;
    size_t cap = 4, len = 0;
    CarrierListenSpec *specs = calloc(cap, sizeof(CarrierListenSpec));
    if (!specs) {
        free(tmp);
        return -1;
    }
    char *save = NULL;
    for (char *part = strtok_r(tmp, ",", &save); part; part = strtok_r(NULL, ",", &save)) {
        trim_line(part);
        if (!*part) continue;
        char *eq = strchr(part, '=');
        if (!eq) {
            free(specs);
            free(tmp);
            return -1;
        }
        *eq = '\0';
        if (len == cap) {
            cap *= 2;
            CarrierListenSpec *ns = realloc(specs, cap * sizeof(CarrierListenSpec));
            if (!ns) {
                free(specs);
                free(tmp);
                return -1;
            }
            specs = ns;
        }
        if (normalize_carrier(part, specs[len].carrier, sizeof(specs[len].carrier)) != 0) {
            free(specs);
            free(tmp);
            return -1;
        }
        snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", eq + 1);
        len++;
    }
    free(tmp);
    *out_specs = specs;
    *out_len = len;
    return 0;
}

static int parse_carrier_resolvers(const char *raw, CarrierResolverSpec **out_specs, size_t *out_len) {
    *out_specs = NULL;
    *out_len = 0;
    if (!raw || !*raw) return 0;
    char *tmp = strdup(raw);
    if (!tmp) return -1;
    size_t cap = 4, len = 0;
    CarrierResolverSpec *specs = calloc(cap, sizeof(CarrierResolverSpec));
    if (!specs) {
        free(tmp);
        return -1;
    }
    char *save = NULL;
    for (char *part = strtok_r(tmp, ",", &save); part; part = strtok_r(NULL, ",", &save)) {
        trim_line(part);
        if (!*part) continue;
        char *eq = strchr(part, '=');
        if (!eq) {
            free(specs);
            free(tmp);
            return -1;
        }
        *eq = '\0';
        if (len == cap) {
            cap *= 2;
            CarrierResolverSpec *ns = realloc(specs, cap * sizeof(CarrierResolverSpec));
            if (!ns) {
                free(specs);
                free(tmp);
                return -1;
            }
            specs = ns;
        }
        if (normalize_carrier(part, specs[len].carrier, sizeof(specs[len].carrier)) != 0) {
            free(specs);
            free(tmp);
            return -1;
        }
        char *save2 = NULL;
        for (char *tok = strtok_r(eq + 1, "|", &save2); tok && specs[len].len < 16; tok = strtok_r(NULL, "|", &save2)) {
            trim_line(tok);
            snprintf(specs[len].addrs[specs[len].len++], sizeof(specs[len].addrs[0]), "%s", tok);
        }
        len++;
    }
    free(tmp);
    *out_specs = specs;
    *out_len = len;
    return 0;
}

static CarrierResolverSpec *find_resolver_spec(CarrierResolverSpec *specs, size_t len, const char *carrier) {
    for (size_t i = 0; i < len; i++) if (str_eq_ci(specs[i].carrier, carrier)) return &specs[i];
    return NULL;
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

static int build_baidu_pool_for_carrier(BaiduProxyPool *pool, const char *carrier, CarrierResolverSpec *resolver_specs, size_t resolver_len) {
    memset(pool, 0, sizeof(*pool));
    snprintf(pool->name, sizeof(pool->name), "%s", carrier ? carrier : "default");
    StringList ips = {0};
    resolve_host_ips(g_cfg.baidu_domain, &ips);
    CarrierResolverSpec *spec = find_resolver_spec(resolver_specs, resolver_len, carrier);
    (void)spec;
    for (size_t i = 0; i < ips.len; i++) {
        char asn[64] = {
            0
        }
        , as_name[256] = {
            0
        }
        , mapped[MAX_NAME_LEN] = {0};
        if (lookup_asn_for_ip(ips.items[i], asn, sizeof(asn)) != 0) continue;
        lookup_as_name_for_asn(asn, as_name, sizeof(as_name));
        if (carrier_from_asn(asn, as_name, mapped, sizeof(mapped)) != 0) continue;
        if (carrier && *carrier && !str_eq_ci(mapped, carrier)) continue;
        char addr[MAX_ADDR_LEN];
        snprintf(addr, sizeof(addr), "%s:%d", ips.items[i], g_cfg.baidu_port);
        int latency = 0;
        int fd = tcp_connect_via_baidu(addr, g_cfg.baidu_scan_target, g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1000, &latency);
        if (fd >= 0) {
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

static void *scan_worker(void *arg) {
    ScanCtx *ctx = (ScanCtx *)arg;
    while (atomic_load(&g_running)) {
        size_t idx = atomic_fetch_add(&ctx->index, 1);
        if (idx >= ctx->total || !atomic_load(&g_running)) break;
        const char *ip = ctx->ips[idx];
        int probes = ctx->cfg->num > 0 ? ctx->cfg->num : 1;
        int success_count = 0;
        int best_latency = 0;
        char best_colo[MAX_COLO_LEN] = {0};
        int header_once = 0;
        int cfray_missing_once = 0;

        for (int attempt = 0; atomic_load(&g_running) && attempt < probes; attempt++) {
            int latency = 0;
            int fd = dial_target_with_proxy(ip, 80, ctx->cfg->delay_ms, ctx->proxy_pool, &latency);
            if (fd < 0) {
                atomic_fetch_add(&ctx->connect_fail, 1);
                continue;
            }
            char req[512];
            if ((attempt % 2) == 0) {
                snprintf(req, sizeof(req),
                         "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
                         ip);
            } else {
                snprintf(req, sizeof(req),
                         "GET / HTTP/1.1\r\nHost: cloudflaremirrors.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n");
            }

            send(fd, req, strlen(req), 0);
            char hdr[4096];
            int n = recv_headers(fd, hdr, sizeof(hdr), ctx->cfg->delay_ms > 2000 ? ctx->cfg->delay_ms : 2000);
            close(fd);
            if (n <= 0) {
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
            if (best_latency == 0 || latency < best_latency) {
                best_latency = latency;
                snprintf(best_colo, sizeof(best_colo), "%s", colo);
            }
        }

        if (success_count <= 0 && header_once && cfray_missing_once && !ctx->cfg->colo[0] && (!ctx->proxy_pool || ctx->proxy_pool->len == 0)) {
            success_count = 1;
            if (best_latency == 0) best_latency = ctx->cfg->delay_ms > 0 ? ctx->cfg->delay_ms : 1;
            snprintf(best_colo, sizeof(best_colo), "%s", "UNK");
            debug_msg("%s HTTP 响应缺少 CF-RAY，作为 UNK 候选交给健康检查确认", ip);
        }

        size_t done = atomic_fetch_add(&ctx->completed, 1) + 1;
        if (done == ctx->total || done % 5000 == 0) {
            size_t found = 0;
            pthread_mutex_lock(&ctx->results->mu);
            found = ctx->results->len;
            pthread_mutex_unlock(&ctx->results->mu);
            log_msg("扫描进度: %zu/%zu，已发现有效 IP: %zu，耗时 %ld 秒", done, ctx->total, found, (now_ms() - ctx->scan_start_ms) / 1000);
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
        Location *loc = find_location(best_colo);
        if (loc) {
            snprintf(r.region, sizeof(r.region), "%s", loc->region);
            snprintf(r.city, sizeof(r.city), "%s", loc->city);
        }
        if (!loc && !strcmp(best_colo, "UNK")) {
            snprintf(r.region, sizeof(r.region), "%s", "Unknown");
            snprintf(r.city, sizeof(r.city), "%s", "Unknown");
        }
        debug_msg("发现有效IP %s 位置信息 %s 延迟 %d 毫秒 丢包 %d%% (%d/%d)", r.ip, r.city[0] ? r.city : "未知", r.latency_ms, r.loss_rate, r.success_count, r.probe_count);
        resultlist_add(ctx->results, &r);
    }
    return NULL;
}

static int score_result(const Result *r) {
    return r->latency_ms * 10 + r->loss_rate * 25;
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
static int set_current_candidate(size_t idx);

#define CACHE_REFRESH_INTERVAL_SECONDS 3600L
#define CACHE_QUICK_CHECK_COUNT 5

static const char *candidate_cache_file(void) {
    if (g_cfg.ips_type == 6) return g_cfg.use_baidu_proxy ? "cfnat-cache-v6-baidu.txt" : "cfnat-cache-v6.txt";
    return g_cfg.use_baidu_proxy ? "cfnat-cache-v4-baidu.txt" : "cfnat-cache-v4.txt";
}

static void save_candidate_cache(const char *path, const Result *items, size_t len) {
    if (!path || !items || len == 0) return;
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        warn_msg("写入缓存 %s 失败", path);
        return;
    }
    fprintf(fp, "# cfnat-cache-v1 %ld\n", (long)time(NULL));
    size_t limit = len;
    if (g_cfg.ipnum > 0 && limit > (size_t)g_cfg.ipnum) limit = (size_t)g_cfg.ipnum;
    for (size_t i = 0; i < limit; i++) {
        const Result *r = &items[i];
        fprintf(fp, "%s|%s|%s|%s|%d|%d|%d|%d\n",
                r->ip,
                r->data_center[0] ? r->data_center : "UNK",
                r->region[0] ? r->region : "Unknown",
                r->city[0] ? r->city : "Unknown",
                r->latency_ms,
                r->loss_rate,
                r->success_count,
                r->probe_count);
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
    if (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "# cfnat-cache-v1", 16) != 0) {
            rewind(fp);
        }
    }

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        Result r;
        memset(&r, 0, sizeof(r));
        int parsed = sscanf(line, "%63[^|]|%7[^|]|%63[^|]|%63[^|]|%d|%d|%d|%d",
                            r.ip,
                            r.data_center,
                            r.region,
                            r.city,
                            &r.latency_ms,
                            &r.loss_rate,
                            &r.success_count,
                            &r.probe_count);
        if (parsed < 8 || !r.ip[0]) continue;
        if (r.latency_ms <= 0) r.latency_ms = g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1;
        if (r.probe_count <= 0) r.probe_count = g_cfg.num > 0 ? g_cfg.num : 1;
        if (r.success_count <= 0) r.success_count = 1;
        if (g_cfg.colo[0] && strcmp(r.data_center, "UNK") != 0 && !colo_allowed(r.data_center)) continue;
        resultlist_add(&rl, &r);
        if (g_cfg.ipnum > 0 && rl.len >= (size_t)g_cfg.ipnum) break;
    }
    fclose(fp);
    qsort(rl.items, rl.len, sizeof(Result), cmp_result);
    if (rl.len > 0) log_msg("已读取候选缓存 %s，共 %zu 个，开始快速健康检查", path, rl.len);
    return rl;
}

static int try_use_candidate_cache(BaiduProxyPool *proxy_pool, ResultList *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    const char *path = candidate_cache_file();
    ResultList cached = load_candidate_cache(path);
    if (cached.len == 0) {
        pthread_mutex_destroy(&cached.mu);
        return 0;
    }

    g_candidates = cached.items;
    g_candidate_count = cached.len;
    size_t check_count = cached.len < CACHE_QUICK_CHECK_COUNT ? cached.len : CACHE_QUICK_CHECK_COUNT;
    for (size_t i = 0; i < check_count; i++) {
        if (health_check_ip(cached.items[i].ip, proxy_pool)) {
            set_current_candidate(i);
            log_msg("命中候选缓存，快速启动使用 IP: %s，后台将继续刷新候选池", cached.items[i].ip);
            *out = cached;
            return 1;
        }
    }

    warn_msg("候选缓存健康检查未命中，将执行完整扫描");
    g_candidates = NULL;
    g_candidate_count = 0;
    free(cached.items);
    pthread_mutex_destroy(&cached.mu);
    return 0;
}

static void explain_selected_result(const Result *best) {
    if (!best) return;
    if (g_cfg.log_level < LOG_DEBUG) return;
    printf("结果解释: 选择 %s，因为延迟 %d ms，丢包 %d%%，综合分 %d。\n", best->ip, best->latency_ms, best->loss_rate, score_result(best));
}

static ResultList scan_ips(StringList *ips, Config *cfg, BaiduProxyPool *proxy_pool) {
    ResultList rl = {0};
    pthread_mutex_init(&rl.mu, NULL);
    int threads = cfg->task;
    if ((size_t)threads > ips->len) threads = (int)ips->len;
    if (threads <= 0) {
        pthread_mutex_destroy(&rl.mu);
        return rl;
    }
    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    if (!tids) {
        pthread_mutex_destroy(&rl.mu);
        return rl;
    }
    ScanCtx ctx = {
        .ips = ips->items,
        .total = ips->len,
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
    log_msg("开始扫描候选 IP: %zu 个，线程: %d，单 IP 探测次数: %d，超时: %d ms", ips->len, threads, cfg->num > 0 ? cfg->num : 1, cfg->delay_ms);
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

static int health_check_ip(const char *ip, BaiduProxyPool *proxy_pool) {
    int latency = 0;
    int fd = dial_target_with_proxy(ip, g_cfg.port, 2000, proxy_pool, &latency);
    if (fd < 0) {
        debug_msg("健康检查失败: IP %s 暂不可用", ip);
        return 0;
    }
    close(fd);
    debug_msg("健康检查成功: IP %s 延迟 %d ms", ip, latency);
    return 1;
}

static int set_current_candidate(size_t idx) {
    if (idx >= g_candidate_count) return 0;
    pthread_mutex_lock(&g_ip_mu);
    snprintf(g_current_ip, sizeof(g_current_ip), "%s", g_candidates[idx].ip);
    g_current_index = idx;
    pthread_mutex_unlock(&g_ip_mu);
    return 1;
}

static int select_valid_ip(BaiduProxyPool *proxy_pool) {
    for (size_t i = 0; i < g_candidate_count; i++) {
        if (health_check_ip(g_candidates[i].ip, proxy_pool)) {
            set_current_candidate(i);
            log_msg("可用 IP: %s (健康检查端口:%d)", g_candidates[i].ip, g_cfg.port);
            return 1;
        }
    }
    return 0;
}

static int switch_next_ip(BaiduProxyPool *proxy_pool) {
    pthread_mutex_lock(&g_ip_mu);
    size_t start = g_current_index + 1;
    pthread_mutex_unlock(&g_ip_mu);
    for (size_t i = start; i < g_candidate_count; i++) {
        if (health_check_ip(g_candidates[i].ip, proxy_pool)) {
            set_current_candidate(i);
            log_msg("切换到下一个最优 IP: %s 候选索引: %zu", g_candidates[i].ip, i);
            return 1;
        }
    }
    return 0;
}

static int choose_ip_for_connection(char *out, size_t sz, BaiduProxyPool *proxy_pool) {
    if (!out || sz == 0) return 0;
    out[0] = '\0';
    if (g_candidate_count == 0) return 0;

    for (size_t i = 0; i < g_candidate_count; i++) {
        if (health_check_ip(g_candidates[i].ip, proxy_pool)) {
            snprintf(out, sz, "%s", g_candidates[i].ip);
            set_current_candidate(i);
            return 1;
        }
    }
    return 0;
}

static int rescan_and_select_ip(BaiduProxyPool *proxy_pool) {
    if (g_candidates) {
        free(g_candidates);
        g_candidates = NULL;
    }
    g_candidate_count = 0;
    pthread_mutex_lock(&g_ip_mu);
    g_current_ip[0] = '\0';
    g_current_index = 0;
    pthread_mutex_unlock(&g_ip_mu);
    const char *ipfile = g_cfg.ips_type == 6 ? "ips-v6.txt" : "ips-v4.txt";
    for (;;) {
        if (!atomic_load(&g_running)) return 0;
        StringList ips = load_ip_list(ipfile, g_cfg.random_mode);
        if (ips.len == 0) {
            warn_msg("没有可扫描的 IP，3 秒后重试");
            if (sleep_interruptible_ms(3000) != 0) return 0;
            continue;
        }
        ResultList results = scan_ips(&ips, &g_cfg, proxy_pool);
        strlist_free(&ips);
        if (results.len == 0) {
            warn_msg("重新扫描后仍未发现有效IP，3 秒后重试");
            if (sleep_interruptible_ms(3000) != 0) return 0;
            continue;
        }
        g_candidates = results.items;
        g_candidate_count = results.len;
        save_candidate_cache(candidate_cache_file(), results.items, results.len);
        log_msg("重新扫描得到 %zu 个候选 IP", g_candidate_count);
        if (select_valid_ip(proxy_pool)) return 1;
        free(results.items);
        g_candidates = NULL;
        g_candidate_count = 0;
        warn_msg("重新扫描得到的候选 IP 健康检查均失败，3 秒后重试");
        if (sleep_interruptible_ms(3000) != 0) return 0;
    }
}

static void get_current_ip(char *out, size_t sz) {
    pthread_mutex_lock(&g_ip_mu);
    snprintf(out, sz, "%s", g_current_ip);
    pthread_mutex_unlock(&g_ip_mu);
}

static void *health_thread(void *arg) {
    BaiduProxyPool *proxy_pool = (BaiduProxyPool *)arg;
    int fail = 0;
    long last = 0;
    while (atomic_load(&g_running)) {
        if (sleep_interruptible_ms(10000) != 0) break;
        char ip[MAX_IP_LEN];
        get_current_ip(ip, sizeof(ip));
        if (!ip[0] || !health_check_ip(ip, proxy_pool)) {
            fail++;
            log_msg("状态检查失败 (%d/2): 当前 IP %s 暂不可用", fail, ip[0] ? ip : "为空");
        } else {
            fail = 0;
            long n = now_ms();
            if (g_cfg.health_log > 0 && n - last >= g_cfg.health_log * 1000L) {
                log_msg("状态检查成功: 当前 IP %s 可用", ip);
                last = n;
            }
        }
        if (fail >= 2) {
            log_msg("连续两次状态检查失败，切换到下一个 IP");
            if (!switch_next_ip(proxy_pool)) {
                log_msg("没有更多可用 IP，开始重新扫描");
                if (!rescan_and_select_ip(proxy_pool)) {
                    atomic_store(&g_running, 0);
                    return NULL;
                }
            }
            fail = 0;
        }
    }
    return NULL;
}

static void close_pair(int a, int b) {
    shutdown(a, SHUT_RDWR);
    shutdown(b, SHUT_RDWR);
}

static void *pipe_worker(void *arg) {
    PipeCtx *pc = (PipeCtx *)arg;
    char buf[COPY_BUF_SIZE];
    while (1) {
        ssize_t n = recv(pc->from, buf, sizeof(buf), 0);
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

static int create_small_thread(pthread_t *tid, void *(*fn)(void *), void *arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 64 * 1024);
    int rc = pthread_create(tid, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    return rc;
}


typedef struct {
    BaiduProxyPool *proxy_pool;
} RefreshCtx;

static void replace_candidates_from_refresh(ResultList *results, BaiduProxyPool *proxy_pool) {
    if (!results || results->len == 0) return;
    save_candidate_cache(candidate_cache_file(), results->items, results->len);
    if (!health_check_ip(results->items[0].ip, proxy_pool)) {
        warn_msg("后台刷新得到候选，但首选 IP 健康检查失败，暂不替换当前候选池");
        free(results->items);
        results->items = NULL;
        results->len = 0;
        return;
    }

    Result *old_items = g_candidates;
    (void)old_items;
    g_candidates = results->items;
    g_candidate_count = results->len;
    set_current_candidate(0);
    log_msg("后台刷新完成，当前最优 IP 已更新为 %s", results->items[0].ip);
    results->items = NULL;
    results->len = 0;
}

static void *refresh_thread(void *arg) {
    RefreshCtx *ctx = (RefreshCtx *)arg;
    int first = 1;
    while (atomic_load(&g_running)) {
        if (!first) {
            if (sleep_interruptible_ms(CACHE_REFRESH_INTERVAL_SECONDS * 1000) != 0) break;
        }
        first = 0;
        if (!atomic_load(&g_running)) break;

        const char *ipfile = g_cfg.ips_type == 6 ? "ips-v6.txt" : "ips-v4.txt";
        log_msg("后台开始刷新候选 IP，服务保持监听中");
        StringList ips = load_ip_list(ipfile, g_cfg.random_mode);
        if (ips.len == 0) {
            warn_msg("后台刷新未读取到可扫描 IP");
            continue;
        }
        ResultList results = scan_ips(&ips, &g_cfg, ctx ? ctx->proxy_pool : NULL);
        strlist_free(&ips);
        if (results.len == 0) {
            warn_msg("后台刷新未发现有效候选 IP，继续使用当前候选池");
            free(results.items);
            pthread_mutex_destroy(&results.mu);
            continue;
        }
        replace_candidates_from_refresh(&results, ctx ? ctx->proxy_pool : NULL);
        pthread_mutex_destroy(&results.mu);
    }
    return NULL;
}

static int relay_bidirectional(int c, int u) {
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
    int client = cc->client_fd;
    unsigned char first = 0;
    ssize_t n = recv(client, &first, 1, 0);
    if (n <= 0) goto out;
    int is_tls = first == 0x16;
    int target_port = is_tls ? cc->tls_port : cc->http_port;
    conn_msg("识别客户端协议: %s，转发到 IP: %s 端口: %d", is_tls ? "TLS" : "非 TLS", cc->ip, target_port);
    int upstream = -1, best = 0;
    for (int i = 0; i < cc->num; i++) {
        int lat = 0;
        int fd = dial_target_with_proxy(cc->ip, target_port, cc->delay_ms, cc->proxy_pool, &lat);
        if (fd >= 0) {
            upstream = fd;
            best = lat;
            break;
        }
    }
    if (upstream < 0) {
        debug_msg("未找到符合延迟要求的连接，关闭客户端连接");
        goto out;
    }
    send(upstream, &first, 1, 0);
    conn_msg("选择连接: 地址: %s:%d 延迟: %d ms", cc->ip, target_port, best);
    relay_bidirectional(client, upstream);
    close(upstream);
    out : close(client);
    int active = atomic_fetch_sub(&g_active_connections, 1) - 1;
    conn_msg("客户端连接关闭，当前活跃连接数: %d", active);
    free(cc);
    return NULL;
}

static int carrier_health_check_ip(CarrierRuntime *rt, const char *ip) {
    if (!rt || !ip || !*ip) return 0;
    int latency = 0;
    int fd = dial_target_with_proxy(ip, g_cfg.port, 2000, rt->proxy_pool, &latency);
    if (fd < 0) {
        debug_msg("%s 健康检查失败: IP %s 暂不可用", carrier_display_name(rt->spec.carrier), ip);
        return 0;
    }
    close(fd);
    debug_msg("%s 健康检查成功: IP %s 延迟 %d ms", carrier_display_name(rt->spec.carrier), ip, latency);
    return 1;
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
            log_msg("%s 可用 IP: %s (健康检查端口:%d)", carrier_display_name(rt->spec.carrier), rt->candidates.items[i].ip, g_cfg.port);
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
            log_msg("%s 切换到下一个最优 IP: %s 候选索引: %zu", carrier_display_name(rt->spec.carrier), rt->candidates.items[i].ip, i);
            return 1;
        }
    }
    return 0;
}

static int carrier_choose_ip_for_connection(CarrierRuntime *rt, char *out, size_t sz) {
    if (!rt || !out || sz == 0) return 0;
    out[0] = '\0';
    if (rt->candidates.len == 0) return 0;

    for (size_t i = 0; i < rt->candidates.len; i++) {
        if (carrier_health_check_ip(rt, rt->candidates.items[i].ip)) {
            snprintf(out, sz, "%s", rt->candidates.items[i].ip);
            carrier_set_current_candidate(rt, i);
            return 1;
        }
    }
    return 0;
}

static int carrier_rescan_and_select_ip(CarrierRuntime *rt, const char *ipfile) {
    if (!rt || !ipfile) return 0;
    free(rt->candidates.items);
    rt->candidates.items = NULL;
    rt->candidates.len = 0;
    pthread_mutex_lock(&rt->candidates.mu);
    rt->candidates.current_ip[0] = '\0';
    rt->candidates.current_index = 0;
    pthread_mutex_unlock(&rt->candidates.mu);
    for (;;) {
        if (!atomic_load(&g_running)) return 0;
        StringList ips = load_ip_list(ipfile, g_cfg.random_mode);
        if (ips.len == 0) {
            warn_msg("%s 没有可扫描的 IP，3 秒后重试", carrier_display_name(rt->spec.carrier));
            if (sleep_interruptible_ms(3000) != 0) return 0;
            continue;
        }
        ResultList results = scan_ips(&ips, &g_cfg, rt->proxy_pool);
        strlist_free(&ips);
        if (results.len == 0) {
            warn_msg("%s 重新扫描后仍未发现有效 IP，3 秒后重试", carrier_display_name(rt->spec.carrier));
            if (sleep_interruptible_ms(3000) != 0) return 0;
            continue;
        }
        rt->candidates.items = results.items;
        rt->candidates.len = results.len;
        log_msg("%s 重新扫描得到 %zu 个候选 IP", carrier_display_name(rt->spec.carrier), rt->candidates.len);
        if (carrier_select_valid_ip(rt)) return 1;
        free(results.items);
        rt->candidates.items = NULL;
        rt->candidates.len = 0;
        warn_msg("%s 重新扫描得到的候选 IP 健康检查均失败，3 秒后重试", carrier_display_name(rt->spec.carrier));
        if (sleep_interruptible_ms(3000) != 0) return 0;
    }
}

static void *carrier_health_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    int fail = 0;
    long last = 0;
    while (atomic_load(&g_running)) {
        if (sleep_interruptible_ms(10000) != 0) break;
        char ip[MAX_IP_LEN];
        carrier_get_current_ip(rt, ip, sizeof(ip));
        if (!ip[0] || !carrier_health_check_ip(rt, ip)) {
            fail++;
            log_msg("%s 状态检查失败 (%d/2): 当前 IP %s 暂不可用", carrier_display_name(rt->spec.carrier), fail, ip[0] ? ip : "为空");
        } else {
            fail = 0;
            long n = now_ms();
            if (g_cfg.health_log > 0 && n - last >= g_cfg.health_log * 1000L) {
                log_msg("%s 状态检查成功: 当前 IP %s 可用", carrier_display_name(rt->spec.carrier), ip);
                last = n;
            }
        }
        if (fail >= 2) {
            log_msg("%s 连续两次状态检查失败，切换到下一个 IP", carrier_display_name(rt->spec.carrier));
            if (!carrier_switch_next_ip(rt)) {
                log_msg("%s 没有更多可用 IP，开始重新扫描", carrier_display_name(rt->spec.carrier));
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
        socklen_t slen = sizeof(ss);
        int cfd = accept_interruptible(rt->listen_fd, (struct sockaddr *)&ss, &slen);
        if (cfd < 0) {
            if (!atomic_load(&g_running)) break;
            if (errno == EINTR || errno == EBADF) break;
            if (sleep_interruptible_ms(1000) != 0) break;
            continue;
        }
        char ip[MAX_IP_LEN];
        if (!carrier_choose_ip_for_connection(rt, ip, sizeof(ip))) {
            close(cfd);
            continue;
        }
        int active = atomic_fetch_add(&g_active_connections, 1) + 1;
        conn_msg("%s 客户端连接建立，当前活跃连接数: %d", carrier_display_name(rt->spec.carrier), active);
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
    if (!colon) return -1;
    size_t n = (size_t)(colon - addr);
    if (n >= hostsz) n = hostsz - 1;
    memcpy(host, addr, n);
    host[n] = 0;
    *port = atoi(colon + 1);
    if (!host[0]) snprintf(host, hostsz, "0.0.0.0");
    return *port > 0 ? 0 : -1;
}

static int listen_tcp(const char *addr) {
    char host[128];
    int port = 0;
    if (parse_addr(addr, host, sizeof(host), &port) != 0) return -1;
    int yes = 1;
    if (strchr(host, ':')) {
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host, &sa6.sin6_addr) != 1) {
            close(fd);
            return -1;
        }
        if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) != 0) {
            close(fd);
            return -1;
        }
        if (listen(fd, 1024) != 0) {
            close(fd);
            return -1;
        }
        return fd;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 1024) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int accept_interruptible(int listen_fd, struct sockaddr *addr, socklen_t *addrlen) {
    while (atomic_load(&g_running)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);

        struct timeval tv = {1, 0};
        int rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc == 0) continue;

        int cfd = accept(listen_fd, addr, addrlen);
        if (cfd < 0 && errno == EINTR) continue;
        return cfd;
    }

    errno = EINTR;
    return -1;
}

static void on_signal(int sig) {
    (void)sig;
    atomic_store(&g_running, 0);
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    for (size_t i = 0; i < g_carrier_runtime_count; i++) {
        if (g_carrier_runtimes[i].listen_fd >= 0) {
            close(g_carrier_runtimes[i].listen_fd);
            g_carrier_runtimes[i].listen_fd = -1;
        }
    }
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

int main(int argc, char **argv) {
    parse_args(&g_cfg, argc, argv);
    install_signals();
    const char *ipfile = g_cfg.ips_type == 6 ? "ips-v6.txt" : "ips-v4.txt";
    const char **urls = g_cfg.ips_type == 6 ? IPS_V6_URLS : IPS_V4_URLS;
    if (!file_exists(ipfile)) {
        printf("文件 %s 不存在，正在下载数据\n", ipfile);
        if (download_file_from_urls(urls, ipfile) != 0) {
            log_msg("下载 %s 失败", ipfile);
            return 1;
        }
    }
    log_msg("正在加载 locations.json");
    load_locations();
    log_msg("locations 加载完成: %zu 条", g_location_count);
    CarrierListenSpec *carrier_specs = NULL;
    size_t carrier_spec_len = 0;
    CarrierResolverSpec *resolver_specs = NULL;
    size_t resolver_spec_len = 0;
    if (parse_carrier_listens(g_cfg.carrier_listens, &carrier_specs, &carrier_spec_len) != 0) {
        log_msg("解析 -carrier-listens 失败");
        free(g_locations);
        return 1;
    }
    if (parse_carrier_resolvers(g_cfg.carrier_resolvers, &resolver_specs, &resolver_spec_len) != 0) {
        log_msg("解析 -carrier-resolvers 失败");
        free(carrier_specs);
        free(g_locations);
        return 1;
    }
    if (g_cfg.use_baidu_proxy) {
        if (build_baidu_pool_for_carrier(&g_default_proxy_pool, NULL, resolver_specs, resolver_spec_len) == 0) {
            log_msg("默认百度代理池已建立，节点数: %zu", g_default_proxy_pool.len);
        } else {
            warn_msg("默认百度代理池建立失败，回退为直连拨号");
        }
    }
    StringList ips = load_ip_list(ipfile, g_cfg.random_mode);
    if (ips.len == 0) {
        log_msg("没有可扫描的 IP");
        free(resolver_specs);
        free(carrier_specs);
        baidu_pool_free(&g_default_proxy_pool);
        free(g_locations);
        return 1;
    }
    if (carrier_spec_len > 0) {
        g_carrier_runtimes = calloc(carrier_spec_len, sizeof(CarrierRuntime));
        if (!g_carrier_runtimes) {
            strlist_free(&ips);
            free(resolver_specs);
            free(carrier_specs);
            baidu_pool_free(&g_default_proxy_pool);
            free(g_locations);
            return 1;
        }
        g_carrier_runtime_count = carrier_spec_len;
        log_msg("运营商分池模式启动，监听器数量: %zu", carrier_spec_len);
        for (size_t i = 0; i < carrier_spec_len; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            rt->listen_fd = -1;
            rt->spec = carrier_specs[i];
            pthread_mutex_init(&rt->candidates.mu, NULL);
            if (g_cfg.use_baidu_proxy) {
                rt->proxy_pool = calloc(1, sizeof(BaiduProxyPool));
                if (rt->proxy_pool && build_baidu_pool_for_carrier(rt->proxy_pool, rt->spec.carrier, resolver_specs, resolver_spec_len) == 0) {
                    log_msg("%s 百度代理池已建立，节点数: %zu", carrier_display_name(rt->spec.carrier), rt->proxy_pool->len);
                } else {
                    if (rt->proxy_pool) {
                        baidu_pool_free(rt->proxy_pool);
                        free(rt->proxy_pool);
                    }
                    rt->proxy_pool = NULL;
                    warn_msg("%s 百度代理池建立失败，回退为直连拨号", carrier_display_name(rt->spec.carrier));
                }
            }
            ResultList carrier_results = scan_ips(&ips, &g_cfg, rt->proxy_pool);
            if (carrier_results.len == 0) {
                warn_msg("%s 未扫描到可用候选 IP", carrier_display_name(rt->spec.carrier));
                continue;
            }
            rt->candidates.items = carrier_results.items;
            rt->candidates.len = carrier_results.len;
            if (!carrier_select_valid_ip(rt)) {
                warn_msg("%s 候选 IP 健康检查全部失败", carrier_display_name(rt->spec.carrier));
                free(rt->candidates.items);
                rt->candidates.items = NULL;
                rt->candidates.len = 0;
                continue;
            }
            rt->listen_fd = listen_tcp(rt->spec.addr);
            if (rt->listen_fd < 0) {
                log_msg("无法监听 %s(%s): %s", carrier_display_name(rt->spec.carrier), rt->spec.addr, strerror(errno));
                free(rt->candidates.items);
                rt->candidates.items = NULL;
                rt->candidates.len = 0;
                continue;
            }
            log_msg("%s 正在监听 %s，TLS目标端口：%d，非TLS目标端口：%d，连接尝试次数：%d，有效延迟：%d ms，日志：%s", carrier_display_name(rt->spec.carrier), rt->spec.addr, g_cfg.port, g_cfg.http_port, g_cfg.num, g_cfg.delay_ms, g_cfg.log_name);
            create_small_thread(&rt->health_tid, carrier_health_thread, rt);
            create_small_thread(&rt->accept_tid, carrier_accept_thread, rt);
        }
        strlist_free(&ips);
        free(resolver_specs);
        free(carrier_specs);
        while (atomic_load(&g_running)) {
            if (sleep_interruptible_ms(1000) != 0) break;
        }
        for (size_t i = 0; i < g_carrier_runtime_count; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            if (rt->listen_fd >= 0) {
                close(rt->listen_fd);
                rt->listen_fd = -1;
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
    long start = 0;
    ResultList results = {0};
    int used_cache = try_use_candidate_cache(g_cfg.use_baidu_proxy ? &g_default_proxy_pool : NULL, &results);
    for (;;) {
        if (used_cache) break;
        start = now_ms();
        results = scan_ips(&ips, &g_cfg, g_cfg.use_baidu_proxy ? &g_default_proxy_pool : NULL);
        if (results.len > 0) {
            save_candidate_cache(candidate_cache_file(), results.items, results.len);
            break;
        }
        warn_msg("未发现有效IP，可尝试放宽 -delay 或提高 -log=debug 查看细节，3 秒后重试");
        if (!atomic_load(&g_running)) {
            strlist_free(&ips);
            free(resolver_specs);
            free(carrier_specs);
            baidu_pool_free(&g_default_proxy_pool);
            free(g_locations);
            return 0;
        }
        if (sleep_interruptible_ms(3000) != 0) {
            strlist_free(&ips);
            free(resolver_specs);
            free(carrier_specs);
            baidu_pool_free(&g_default_proxy_pool);
            free(g_locations);
            return 0;
        }
    }
    printf("候选池统计\n");
    printf("候选总数: %zu\n", results.len);
    printf("IP 地址 | 数据中心 | 地区 | 城市 | 延迟 | 丢包 | 探测成功\n");
    for (size_t i = 0; i < results.len; i++) printf("%s | %s | %s | %s | %d ms | %d%% | %d/%d\n", results.items[i].ip, results.items[i].data_center, results.items[i].region, results.items[i].city, results.items[i].latency_ms, results.items[i].loss_rate, results.items[i].success_count, results.items[i].probe_count);
    printf("成功提取 %zu 个有效IP，耗时 %ld秒\n", results.len, (now_ms() - start) / 1000);
    if (results.len > 0) {
        printf("评分最优 IP: %s\n", results.items[0].ip);
        printf("最佳延迟: %d ms\n", results.items[0].latency_ms);
        printf("最佳丢包率: %d%%\n", results.items[0].loss_rate);
        explain_selected_result(&results.items[0]);
    }
    g_candidates = results.items;
    g_candidate_count = results.len;
    if (!select_valid_ip(g_cfg.use_baidu_proxy ? &g_default_proxy_pool : NULL)) {
        log_msg("没有有效的 IP 可用");
        strlist_free(&ips);
        free(resolver_specs);
        free(carrier_specs);
        free(results.items);
        baidu_pool_free(&g_default_proxy_pool);
        free(g_locations);
        return 1;
    }
    strlist_free(&ips);
    free(resolver_specs);
    free(carrier_specs);
    int lfd = listen_tcp(g_cfg.addr);
    if (lfd < 0) {
        log_msg("无法监听 %s: %s", g_cfg.addr, strerror(errno));
        free(results.items);
        baidu_pool_free(&g_default_proxy_pool);
        free(g_locations);
        return 1;
    }
    g_listen_fd = lfd;
    log_msg("正在监听 %s，TLS目标端口：%d，非TLS目标端口：%d，连接尝试次数：%d，有效延迟：%d ms，日志：%s", g_cfg.addr, g_cfg.port, g_cfg.http_port, g_cfg.num, g_cfg.delay_ms, g_cfg.log_name);
    pthread_t ht;
    pthread_t rt;
    RefreshCtx refresh_ctx = { .proxy_pool = g_cfg.use_baidu_proxy ? &g_default_proxy_pool : NULL };
    create_small_thread(&ht, health_thread, g_cfg.use_baidu_proxy ? &g_default_proxy_pool : NULL);
    create_small_thread(&rt, refresh_thread, &refresh_ctx);
    while (atomic_load(&g_running)) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int cfd = accept_interruptible(lfd, (struct sockaddr *)&ss, &slen);
        if (cfd < 0) {
            if (!atomic_load(&g_running)) break;
            if (errno == EINTR || errno == EBADF) break;
            if (sleep_interruptible_ms(1000) != 0) break;
            continue;
        }
        char ip[MAX_IP_LEN];
        if (!choose_ip_for_connection(ip, sizeof(ip), g_cfg.use_baidu_proxy ? &g_default_proxy_pool : NULL)) {
            close(cfd);
            continue;
        }
        int active = atomic_fetch_add(&g_active_connections, 1) + 1;
        conn_msg("客户端连接建立，当前活跃连接数: %d", active);
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
        cc->proxy_pool = g_cfg.use_baidu_proxy ? &g_default_proxy_pool : NULL;
        pthread_t tid;
        create_small_thread(&tid, connection_thread, cc);
        pthread_detach(tid);
    }
    if (lfd >= 0) close(lfd);
    g_listen_fd = -1;
    pthread_join(ht, NULL);
    pthread_join(rt, NULL);
    free(results.items);
    g_candidates = NULL;
    g_candidate_count = 0;
    baidu_pool_free(&g_default_proxy_pool);
    free(g_locations);
    g_locations = NULL;
    g_location_count = 0;
    return 0;
}
