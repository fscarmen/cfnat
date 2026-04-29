#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <ctype.h>
#define close closesocket
#define sleep(sec) Sleep((DWORD)((sec) * 1000))
#define SHUT_RDWR SD_BOTH
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
typedef SOCKET socket_t;


static const char *cfnat_sock_error(void)  {
    static char buf[64];
    snprintf(buf, sizeof(buf), "WSA error %d", WSAGetLastError());
    return buf;
}


static int cfnat_socket_valid(socket_t s)  {
    return s != INVALID_SOCKET;
}


static int cfnat_socket_invalid(socket_t s)  {
    return s == INVALID_SOCKET;
}


static char *cfnat_strcasestr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    size_t nl=strlen(needle);
    if (nl==0) return (char*)haystack;
    for (const char *p=haystack;
    *p;
    p++) {
        size_t i=0;
        while (i<nl && p[i] && tolower((unsigned char)p[i])==tolower((unsigned char)needle[i])) i++;
        if (i==nl) return (char*)p;
    }
    return NULL;
}
#define MAX_IP_LEN 64
#define MAX_COLO_LEN 8
#define MAX_REGION_LEN 64
#define MAX_CITY_LEN 64
#define MAX_LINE 512
#define COPY_BUF_SIZE 16384
static const char *IPS_V4_URLS[] =  {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/ips-v4",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/ips-v4",
    NULL
}
;
static const char *IPS_V6_URLS[] =  {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/ips-v6",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/ips-v6",
    NULL
}
;
static const char *LOC_URLS[] =  {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/locations",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/locations",
    NULL
}
;
typedef struct  {
    char addr[64], colo[128], domain[256];
    int code, delay_ms, ipnum, ips_type, num, port, http_port, random_mode, task, health_log, verbose, log_conn;
}
Config;
typedef struct  {
    char iata[MAX_COLO_LEN], region[MAX_REGION_LEN], city[MAX_CITY_LEN];
}
Location;
typedef struct  {
    char ip[MAX_IP_LEN], data_center[MAX_COLO_LEN], region[MAX_REGION_LEN], city[MAX_CITY_LEN];
    int latency_ms;
}
Result;
typedef struct  {
    Result *items;
    size_t len, cap;
    pthread_mutex_t mu;
}
ResultList;
typedef struct  {
    char **items;
    size_t len, cap;
}
StringList;
typedef struct  {
    char **ips;
    size_t total;
    atomic_size_t index;
    ResultList *results;
    Config *cfg;
}
ScanCtx;
typedef struct  {
    socket_t client_fd;
    int tls_port, http_port, num, delay_ms;
    char ip[MAX_IP_LEN];
}
ConnCtx;
typedef struct  {
    socket_t from, to;
}
PipeCtx;
static Config g_cfg;
static Location *g_locations = NULL;
static size_t g_location_count = 0;
static Result *g_candidates = NULL;
static size_t g_candidate_count = 0, g_current_index = 0;
static char g_current_ip[MAX_IP_LEN] =  {
    0
}
;
static pthread_mutex_t g_ip_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_running = 1;
static atomic_int g_active_connections = 0;
static socket_t g_listen_fd = INVALID_SOCKET;


static long now_ms(void)  {
    return (long)GetTickCount64();
}


static void vlog_line(const char *fmt, va_list ap)  {
    time_t t=time(NULL);
    struct tm tmv;
    localtime_s(&tmv,&t);
    char ts[32];
    strftime(ts,sizeof(ts),"%Y/%m/%d %H:%M:%S",&tmv);
    fprintf(stderr,"%s ",ts);
    vfprintf(stderr,fmt,ap);
    fputc('\n',stderr);
}


static void log_msg(const char *fmt, ...)  {
    va_list ap;
    va_start(ap,fmt);
    vlog_line(fmt,ap);
    va_end(ap);
}


static void debug_msg(const char *fmt, ...)  {
    if (!g_cfg.verbose) return;
    va_list ap;
    va_start(ap,fmt);
    vlog_line(fmt,ap);
    va_end(ap);
}


static void conn_msg(const char *fmt, ...)  {
    if (!g_cfg.verbose && !g_cfg.log_conn) return;
    va_list ap;
    va_start(ap,fmt);
    vlog_line(fmt,ap);
    va_end(ap);
}


static void usage(const char *p)  {
    printf("Usage of %s:\n", p);
    printf("  -addr=value        本地监听的 IP 和端口 (default 0.0.0.0:1234)\n");
    printf("  -colo=value        筛选数据中心例如 HKG,SJC,LAX\n");
    printf("  -delay=value       有效延迟毫秒 (default 300)\n");
    printf("  -ipnum=value       提取的有效IP数量 (default 20)\n");
    printf("  -ips=value         指定IPv4还是IPv6 (4或6, C版优先IPv4)\n");
    printf("  -num=value         每个连接的目标连接尝试次数 (default 5)\n");
    printf("  -port=value        TLS 转发目标端口 (default 443)\n");
    printf("  -http-port=value   非TLS/HTTP 转发目标端口 (default 80)\n");
    printf("  -random=value      是否随机生成IP (default true)\n");
    printf("  -task=value        扫描线程数 (default 100)\n");
    printf("  -verbose=value     详细日志 (default false)\n");
    printf("  -log-conn=value    连接日志 (default false)\n");
}


static int parse_bool(const char *v)  {
    return !v || strcmp(v,"1")==0 || strcasecmp(v,"true")==0 || strcasecmp(v,"yes")==0 || strcasecmp(v,"on")==0;
}


static void cfg_defaults(Config *c)  {
    memset(c,0,sizeof(*c));
    strcpy(c->addr,"0.0.0.0:1234");
    strcpy(c->domain,"cloudflaremirrors.com/debian");
    c->code=200;
    c->delay_ms=300;
    c->ipnum=20;
    c->ips_type=4;
    c->num=5;
    c->port=443;
    c->http_port=80;
    c->random_mode=1;
    c->task=100;
    c->health_log=60;
}


static void parse_args(Config *c, int argc, char **argv)  {
    cfg_defaults(c);
    for (int i=1;
    i<argc;
    i++) {
        char *arg=argv[i];
        if (!strcmp(arg,"-h")||!strcmp(arg,"--help")) {
            usage(argv[0]);
            exit(0);
        }
        if (arg[0]!='-') continue;
        char *key=arg+1;
        if (*key=='-') key++;
        char *eq=strchr(key,'=');
        char *val=NULL;
        if (eq) {
            *eq=0;
            val=eq+1;
        }
        else if (i+1<argc && argv[i+1][0]!='-') val=argv[++i];
        if (!strcmp(key,"addr")&&val) snprintf(c->addr,sizeof(c->addr),"%s",val);
        else if (!strcmp(key,"code")&&val) c->code=atoi(val);
        else if (!strcmp(key,"colo")&&val) snprintf(c->colo,sizeof(c->colo),"%s",val);
        else if (!strcmp(key,"delay")&&val) c->delay_ms=atoi(val);
        else if (!strcmp(key,"domain")&&val) snprintf(c->domain,sizeof(c->domain),"%s",val);
        else if (!strcmp(key,"ipnum")&&val) c->ipnum=atoi(val);
        else if (!strcmp(key,"ips")&&val) c->ips_type=atoi(val);
        else if (!strcmp(key,"num")&&val) c->num=atoi(val);
        else if (!strcmp(key,"port")&&val) c->port=atoi(val);
        else if (!strcmp(key,"http-port")&&val) c->http_port=atoi(val);
        else if (!strcmp(key,"random")) c->random_mode=parse_bool(val);
        else if (!strcmp(key,"task")&&val) c->task=atoi(val);
        else if (!strcmp(key,"health-log")&&val) c->health_log=atoi(val);
        else if (!strcmp(key,"verbose")) c->verbose=parse_bool(val);
        else if (!strcmp(key,"log-conn")) c->log_conn=parse_bool(val);
    }
    if (c->delay_ms<=0)c->delay_ms=300;
    if (c->ipnum<=0)c->ipnum=20;
    if (c->num<=0)c->num=1;
    if (c->task<=0)c->task=1;
    if (c->task>512)c->task=512;
}


static int file_exists(const char *path) {
    struct stat st;
    return stat(path,&st)==0 && S_ISREG(st.st_mode);
}


static int download_file_from_urls(const char **urls, const char *filename) {
    char tmp[256];

    snprintf(tmp, sizeof(tmp), "%s.tmp", filename);
    for (int i = 0; urls[i]; i++) {
        char cmd[2048];

        snprintf(
            cmd,
            sizeof(cmd),
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$ProgressPreference='SilentlyContinue'; try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('%s','%s'); exit 0 } catch { exit 1 }\"",
            urls[i],
            tmp
        );
        int rc = system(cmd);
        if (rc == 0 && file_exists(tmp)) {
            rename(tmp, filename);
            return 0;
        }
        remove(tmp);
        log_msg("从 %s 下载失败，尝试下一个源", urls[i]);
    }
    return -1;
}


static char *read_file_all(const char *path,size_t *out_len) {
    FILE*f=fopen(path,"rb");
    if (!f)return NULL;
    fseek(f,0,SEEK_END);
    long n=ftell(f);
    fseek(f,0,SEEK_SET);
    if (n<0) {
        fclose(f);
        return NULL;
    }
    char*b=malloc((size_t)n+1);
    if (!b) {
        fclose(f);
        return NULL;
    }
    size_t r=fread(b,1,(size_t)n,f);
    fclose(f);
    b[r]=0;
    if (out_len)*out_len=r;
    return b;
}


static void trim_line(char*s) {
    char*p=s;
    while (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')p++;
    if (p!=s)memmove(s,p,strlen(p)+1);
    size_t n=strlen(s);
    while (n&&(s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\r'||s[n-1]=='\n'))s[--n]=0;
}


static int strlist_add(StringList*l,const char*s) {
    if (l->len==l->cap) {
        size_t nc=l->cap?l->cap*2:256;
        char**ni=realloc(l->items,nc*sizeof(char*));
        if (!ni)return-1;
        l->items=ni;
        l->cap=nc;
    }
    l->items[l->len]=strdup(s);
    if (!l->items[l->len])return-1;
    l->len++;
    return 0;
}


static void strlist_free(StringList*l) {
    for (size_t i=0;
    i<l->len;
    i++)free(l->items[i]);
    free(l->items);
    memset(l,0,sizeof(*l));
}


static uint32_t ipv4_to_u32(const char*s) {
    struct in_addr a;
    if (inet_pton(AF_INET,s,&a)!=1)return 0;
    return ntohl(a.s_addr);
}


static void u32_to_ipv4(uint32_t v,char*out,size_t sz) {
    struct in_addr a;
    a.s_addr=htonl(v);
    inet_ntop(AF_INET,&a,out,sz);
}


static StringList load_ip_list(const char *filename,int random_mode) {
    StringList out= {
        0
    }
    ;
    FILE*f=fopen(filename,"r");
    if (!f)return out;
    char line[MAX_LINE];
    srand((unsigned)time(NULL));
    while (fgets(line,sizeof(line),f)) {
        trim_line(line);
        if (!line[0])continue;
        char*slash=strchr(line,'/');
        if (!slash) {
            strlist_add(&out,line);
            continue;
        }
        *slash=0;
        int prefix=atoi(slash+1);
        uint32_t base=ipv4_to_u32(line);
        if (base==0||prefix<0||prefix>32)continue;
        uint32_t mask=prefix==0?0:(0xffffffffu<<(32-prefix));
        uint32_t start=base&mask;
        uint32_t count=prefix==32?1u:(1u<<(32-prefix));
        if (random_mode) {
            uint32_t off=count>1?(uint32_t)(rand()%count):0;
            char ip[MAX_IP_LEN];
            u32_to_ipv4(start+off,ip,sizeof(ip));
            strlist_add(&out,ip);
        }
        else {
            for (uint32_t off=0;
            off<count;
            off++) {
                char ip[MAX_IP_LEN];
                u32_to_ipv4(start+off,ip,sizeof(ip));
                strlist_add(&out,ip);
            }
        }
    }
    fclose(f);
    return out;
}


static char* json_string_value(char*p,const char*key,char*out,size_t outsz) {
    char pat[64];
    snprintf(pat,sizeof(pat),"\"%s\"",key);
    char*k=strstr(p,pat);
    if (!k)return NULL;
    char*colon=strchr(k+strlen(pat),':');
    if (!colon)return NULL;
    char*q=strchr(colon,'\"');
    if (!q)return NULL;
    q++;
    char*e=strchr(q,'\"');
    if (!e)return NULL;
    size_t n=(size_t)(e-q);
    if (n>=outsz)n=outsz-1;
    memcpy(out,q,n);
    out[n]=0;
    return e+1;
}


static void load_locations(void) {
    if (!file_exists("locations.json")) {
        printf("本地 locations.json 不存在，正在下载 locations.json\n");
        if (download_file_from_urls(LOC_URLS,"locations.json")!=0) {
            log_msg("下载 locations.json 失败");
            return;
        }
    }
    size_t len=0;
    char*json=read_file_all("locations.json",&len);
    if (!json)return;
    size_t cap=128;
    g_locations=calloc(cap,sizeof(Location));
    g_location_count=0;
    char*p=json;
    while ((p=strstr(p,"\"iata\""))) {
        if (g_location_count==cap) {
            cap*=2;
            Location*nl=realloc(g_locations,cap*sizeof(Location));
            if (!nl)break;
            g_locations=nl;
        }
        Location loc= {
            0
        }
        ;
        char*np=json_string_value(p,"iata",loc.iata,sizeof(loc.iata));
        if (!np) {
            p+=6;
            continue;
        }
        json_string_value(np,"region",loc.region,sizeof(loc.region));
        json_string_value(np,"city",loc.city,sizeof(loc.city));
        if (loc.iata[0])g_locations[g_location_count++]=loc;
        p=np;
    }
    free(json);
}


static Location* find_location(const char*iata) {
    for (size_t i=0;
    i<g_location_count;
    i++)if (!strcasecmp(g_locations[i].iata,iata))return &g_locations[i];
    return NULL;
}


static int colo_allowed(const char*colo) {
    if (!g_cfg.colo[0])return 1;
    char tmp[128];
    snprintf(tmp,sizeof(tmp),"%s",g_cfg.colo);
    char*save=NULL;
    char*tok=strtok_r(tmp,",",&save);
    while (tok) {
        trim_line(tok);
        if (!strcasecmp(tok,colo))return 1;
        tok=strtok_r(NULL,",",&save);
    }
    return 0;
}


static int set_nonblock(socket_t fd,int nb) {
    u_long mode=nb?1UL:0UL;
    return ioctlsocket(fd,FIONBIO,&mode);
}


static socket_t tcp_connect(const char*ip,int port,int timeout_ms,int*latency_ms) {
    long start=now_ms();
    socket_t fd=socket(strchr(ip,':')?AF_INET6:AF_INET,SOCK_STREAM,0);
    if (cfnat_socket_invalid(fd))return INVALID_SOCKET;
    set_nonblock(fd,1);
    int rc;
    if (strchr(ip,':')) {
        struct sockaddr_in6 sa6;
        memset(&sa6,0,sizeof(sa6));
        sa6.sin6_family=AF_INET6;
        sa6.sin6_port=htons((uint16_t)port);
        if (inet_pton(AF_INET6,ip,&sa6.sin6_addr)!=1) {
            close(fd);
            return INVALID_SOCKET;
        }
        rc=connect(fd,(struct sockaddr*)&sa6,sizeof(sa6));
    }
    else {
        struct sockaddr_in sa;
        memset(&sa,0,sizeof(sa));
        sa.sin_family=AF_INET;
        sa.sin_port=htons((uint16_t)port);
        if (inet_pton(AF_INET,ip,&sa.sin_addr)!=1) {
            close(fd);
            return INVALID_SOCKET;
        }
        rc=connect(fd,(struct sockaddr*)&sa,sizeof(sa));
    }
    if (rc<0) {
        int e=WSAGetLastError();
        if (e!=WSAEWOULDBLOCK&&e!=WSAEINPROGRESS) {
            close(fd);
            return INVALID_SOCKET;
        }
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd,&wfds);
    struct timeval tv= {
        timeout_ms/1000,(timeout_ms%1000)*1000
    }
    ;
    rc=select(fd+1,NULL,&wfds,NULL,&tv);
    if (rc<=0) {
        close(fd);
        return INVALID_SOCKET;
    }
    int err=0;
    socklen_t len=sizeof(err);
    if (getsockopt(fd,SOL_SOCKET,SO_ERROR,(char*)&err,&len)<0||err!=0) {
        close(fd);
        return INVALID_SOCKET;
    }
    set_nonblock(fd,0);
    if (latency_ms)*latency_ms=(int)(now_ms()-start);
    return fd;
}


static int recv_headers(socket_t fd,char*buf,size_t bufsz,int timeout_ms) {
    size_t used=0;
    long deadline=now_ms()+timeout_ms;
    while (used+1<bufsz&&now_ms()<deadline) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd,&rfds);
        int left=(int)(deadline-now_ms());
        if (left<=0)break;
        struct timeval tv= {
            left/1000,(left%1000)*1000
        }
        ;
        int rc=select(fd+1,&rfds,NULL,NULL,&tv);
        if (rc<=0)break;
        ssize_t n=recv(fd,buf+used,bufsz-used-1,0);
        if (n<=0)break;
        used+=(size_t)n;
        buf[used]=0;
        if (strstr(buf,"\r\n\r\n"))return (int)used;
    }
    buf[used]=0;
    return (int)used;
}


static int extract_cfray(const char*headers,char*colo,size_t sz) {
    const char*p=cfnat_strcasestr(headers,"CF-RAY:");
    if (!p)return-1;
    const char*line_end=strstr(p,"\r\n");
    if (!line_end)line_end=p+strlen(p);
    const char*dash=NULL;
    for (const char*q=p;
    q<line_end;
    q++)if (*q=='-')dash=q;
    if (!dash||dash+1>=line_end)return-1;
    const char*s=dash+1;
    size_t n=(size_t)(line_end-s);
    if (n>=sz)n=sz-1;
    memcpy(colo,s,n);
    colo[n]=0;
    trim_line(colo);
    return colo[0]?0:-1;
}


static void resultlist_add(ResultList*rl,const Result*r) {
    pthread_mutex_lock(&rl->mu);
    if (rl->len==rl->cap) {
        size_t nc=rl->cap?rl->cap*2:128;
        Result*ni=realloc(rl->items,nc*sizeof(Result));
        if (!ni) {
            pthread_mutex_unlock(&rl->mu);
            return;
        }
        rl->items=ni;
        rl->cap=nc;
    }
    rl->items[rl->len++]=*r;
    pthread_mutex_unlock(&rl->mu);
}


static void* scan_worker(void*arg) {
    ScanCtx*ctx=(ScanCtx*)arg;
    while (1) {
        size_t idx=atomic_fetch_add(&ctx->index,1);
        if (idx>=ctx->total)break;
        const char*ip=ctx->ips[idx];
        int latency=0;
        socket_t fd=tcp_connect(ip,80,ctx->cfg->delay_ms,&latency);
        if (cfnat_socket_invalid(fd))continue;
        const char*req="GET / HTTP/1.1\r\nHost: cloudflaremirrors.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
        send(fd,req,strlen(req),0);
        char hdr[4096];
        int n=recv_headers(fd,hdr,sizeof(hdr),2000);
        close(fd);
        if (n<=0)continue;
        char colo[MAX_COLO_LEN]= {
            0
        }
        ;
        if (extract_cfray(hdr,colo,sizeof(colo))!=0)continue;
        if (!colo_allowed(colo))continue;
        Result r;
        memset(&r,0,sizeof(r));
        snprintf(r.ip,sizeof(r.ip),"%s",ip);
        snprintf(r.data_center,sizeof(r.data_center),"%s",colo);
        r.latency_ms=latency;
        Location*loc=find_location(colo);
        if (loc) {
            snprintf(r.region,sizeof(r.region),"%s",loc->region);
            snprintf(r.city,sizeof(r.city),"%s",loc->city);
        }
        debug_msg("发现有效IP %s 位置信息 %s 延迟 %d 毫秒",r.ip,r.city[0]?r.city:"未知",latency);
        resultlist_add(ctx->results,&r);
    }
    return NULL;
}


static int cmp_result(const void*a,const void*b) {
    const Result*ra=(const Result*)a;
    const Result*rb=(const Result*)b;
    return ra->latency_ms-rb->latency_ms;
}


static ResultList scan_ips(StringList*ips,Config*cfg) {
    ResultList rl= {
        0
    }
    ;
    pthread_mutex_init(&rl.mu,NULL);
    int threads=cfg->task;
    if ((size_t)threads>ips->len)threads=(int)ips->len;
    if (threads<=0)return rl;
    pthread_t*tids=calloc((size_t)threads,sizeof(pthread_t));
    ScanCtx ctx= {
        .ips=ips->items,.total=ips->len,.results=&rl,.cfg=cfg
    }
    ;
    atomic_init(&ctx.index,0);
    for (int i=0;
    i<threads;
    i++)pthread_create(&tids[i],NULL,scan_worker,&ctx);
    for (int i=0;
    i<threads;
    i++)pthread_join(tids[i],NULL);
    free(tids);
    qsort(rl.items,rl.len,sizeof(Result),cmp_result);
    if (rl.len>(size_t)cfg->ipnum)rl.len=(size_t)cfg->ipnum;
    return rl;
}


static int health_check_ip(const char*ip) {
    int latency=0;
    socket_t fd=tcp_connect(ip,g_cfg.port,2000,&latency);
    if (cfnat_socket_invalid(fd)) {
        debug_msg("健康检查失败: IP %s 暂不可用",ip);
        return 0;
    }
    close(fd);
    debug_msg("健康检查成功: IP %s 延迟 %d ms",ip,latency);
    return 1;
}


static int select_valid_ip(void) {
    for (size_t i=0;
    i<g_candidate_count;
    i++) {
        if (health_check_ip(g_candidates[i].ip)) {
            pthread_mutex_lock(&g_ip_mu);
            snprintf(g_current_ip,sizeof(g_current_ip),"%s",g_candidates[i].ip);
            g_current_index=i;
            pthread_mutex_unlock(&g_ip_mu);
            log_msg("可用 IP: %s (健康检查端口:%d)",g_candidates[i].ip,g_cfg.port);
            return 1;
        }
    }
    return 0;
}


static int switch_next_ip(void) {
    pthread_mutex_lock(&g_ip_mu);
    size_t start=g_current_index+1;
    pthread_mutex_unlock(&g_ip_mu);
    for (size_t i=start;
    i<g_candidate_count;
    i++) {
        if (health_check_ip(g_candidates[i].ip)) {
            pthread_mutex_lock(&g_ip_mu);
            snprintf(g_current_ip,sizeof(g_current_ip),"%s",g_candidates[i].ip);
            g_current_index=i;
            pthread_mutex_unlock(&g_ip_mu);
            log_msg("切换到新的有效 IP: %s 更新 IP 索引: %zu",g_candidates[i].ip,i);
            return 1;
        }
    }
    return 0;
}


static int rescan_and_select_ip(void) {
    if (g_candidates) {
        free(g_candidates);
        g_candidates=NULL;
    }
    g_candidate_count=0;
    pthread_mutex_lock(&g_ip_mu);
    g_current_ip[0]='\0';
    g_current_index=0;
    pthread_mutex_unlock(&g_ip_mu);
    const char*ipfile=g_cfg.ips_type==6?"ips-v6.txt":"ips-v4.txt";
    for (;
    ;
    ) {
        if (!atomic_load(&g_running))return 0;
        StringList ips=load_ip_list(ipfile,g_cfg.random_mode);
        if (ips.len==0) {
            log_msg("没有可扫描的 IP，3 秒后重试");
            sleep(3);
            continue;
        }
        ResultList results=scan_ips(&ips,&g_cfg);
        strlist_free(&ips);
        if (results.len==0) {
            log_msg("重新扫描后仍未发现有效IP，3 秒后重试");
            sleep(3);
            continue;
        }
        g_candidates=results.items;
        g_candidate_count=results.len;
        log_msg("重新扫描得到 %zu 个候选 IP",g_candidate_count);
        if (select_valid_ip())return 1;
        free(results.items);
        g_candidates=NULL;
        g_candidate_count=0;
        log_msg("重新扫描得到的候选 IP 健康检查均失败，3 秒后重试");
        sleep(3);
    }
}


static void get_current_ip(char*out,size_t sz) {
    pthread_mutex_lock(&g_ip_mu);
    snprintf(out,sz,"%s",g_current_ip);
    pthread_mutex_unlock(&g_ip_mu);
}


static void* health_thread(void*arg) {
    (void)arg;
    int fail=0;
    long last=0;
    while (atomic_load(&g_running)) {
        sleep(10);
        char ip[MAX_IP_LEN];
        get_current_ip(ip,sizeof(ip));
        if (!ip[0]||!health_check_ip(ip)) {
            fail++;
            log_msg("状态检查失败 (%d/2): 当前 IP %s 暂不可用",fail,ip[0]?ip:"为空");
        }
        else {
            fail=0;
            long n=now_ms();
            if (g_cfg.health_log>0&&n-last>=g_cfg.health_log*1000L) {
                log_msg("状态检查成功: 当前 IP %s 可用",ip);
                last=n;
            }
        }
        if (fail>=2) {
            log_msg("连续两次状态检查失败，切换到下一个 IP");
            if (!switch_next_ip()) {
                log_msg("没有更多可用 IP，开始重新扫描");
                if (!rescan_and_select_ip()) {
                    atomic_store(&g_running,0);
                    return NULL;
                }
            }
            fail=0;
        }
    }
    return NULL;
}


static void close_pair(socket_t a,socket_t b) {
    shutdown(a,SHUT_RDWR);
    shutdown(b,SHUT_RDWR);
}


static void* pipe_worker(void*arg) {
    PipeCtx*pc=(PipeCtx*)arg;
    char buf[COPY_BUF_SIZE];
    while (1) {
        ssize_t n=recv(pc->from,buf,sizeof(buf),0);
        if (n<=0)break;
        char*p=buf;
        ssize_t left=n;
        while (left>0) {
            ssize_t w=send(pc->to,p,(size_t)left,0);
            if (w<=0)goto done;
            p+=w;
            left-=w;
        }
    }
    done:close_pair(pc->from,pc->to);
    return NULL;
}


static int create_small_thread(pthread_t*tid,void*(*fn)(void*),void*arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr,64*1024);
    int rc=pthread_create(tid,&attr,fn,arg);
    pthread_attr_destroy(&attr);
    return rc;
}


static int relay_bidirectional(socket_t c, socket_t u) {
    pthread_t t1, t2;
    PipeCtx a = {c, u};
    PipeCtx b = {u, c};

    create_small_thread(&t1, pipe_worker, &a);
    create_small_thread(&t2, pipe_worker, &b);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}


static void* connection_thread(void *arg) {
    ConnCtx *cc = (ConnCtx *)arg;
    socket_t client = cc->client_fd;
    unsigned char first = 0;
    ssize_t n = recv(client, (char *)&first, 1, 0);

    if (n <= 0) {
        goto out;
    }

    int is_tls = first == 0x16;
    int target_port = is_tls ? cc->tls_port : cc->http_port;
    conn_msg("识别客户端协议: %s，转发到 IP: %s 端口: %d", is_tls ? "TLS" : "非 TLS", cc->ip, target_port);

    socket_t upstream = INVALID_SOCKET;
    int best = 0;
    for (int i = 0; i < cc->num; i++) {
        int lat = 0;
        socket_t fd = tcp_connect(cc->ip, target_port, cc->delay_ms, &lat);

        if (cfnat_socket_valid(fd)) {
            upstream = fd;
            best = lat;
            break;
        }
    }

    if (cfnat_socket_invalid(upstream)) {
        debug_msg("未找到符合延迟要求的连接，关闭客户端连接");
        goto out;
    }

    send(upstream, (const char *)&first, 1, 0);
    conn_msg("选择连接: 地址: %s:%d 延迟: %d ms", cc->ip, target_port, best);
    relay_bidirectional(client, upstream);
    close(upstream);

out:
    close(client);
    int active = atomic_fetch_sub(&g_active_connections, 1) - 1;
    conn_msg("客户端连接关闭，当前活跃连接数: %d", active);
    free(cc);
    return NULL;
}


static int parse_addr(const char*addr,char*host,size_t hostsz,int*port) {
    const char*colon=strrchr(addr,':');
    if (!colon)return-1;
    size_t n=(size_t)(colon-addr);
    if (n>=hostsz)n=hostsz-1;
    memcpy(host,addr,n);
    host[n]=0;
    *port=atoi(colon+1);
    if (!host[0])snprintf(host,hostsz,"0.0.0.0");
    return *port>0?0:-1;
}


static socket_t listen_tcp(const char *addr) {
    char host[128];
    int port = 0;

    if (parse_addr(addr, host, sizeof(host), &port) != 0) {
        return INVALID_SOCKET;
    }

    socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfnat_socket_invalid(fd)) {
        return INVALID_SOCKET;
    }

    BOOL yes = TRUE;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return INVALID_SOCKET;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    if (listen(fd, 1024) != 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    return fd;
}


static void on_signal(int sig) {
    (void)sig;
    atomic_store(&g_running,0);
    if (cfnat_socket_valid(g_listen_fd)) {
        close(g_listen_fd);
        g_listen_fd=INVALID_SOCKET;
    }
}


static void install_signals(void) {
    signal(SIGINT,on_signal);
    signal(SIGTERM,on_signal);
}


int main(int argc,char**argv) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2),&wsa)!=0) {
        fprintf(stderr,"WSAStartup failed\n");
        return 1;
    }
    parse_args(&g_cfg,argc,argv);
    install_signals();
    const char*ipfile=g_cfg.ips_type==6?"ips-v6.txt":"ips-v4.txt";
    const char**urls=g_cfg.ips_type==6?IPS_V6_URLS:IPS_V4_URLS;
    if (!file_exists(ipfile)) {
        printf("文件 %s 不存在，正在下载数据\n",ipfile);
        if (download_file_from_urls(urls,ipfile)!=0) {
            log_msg("下载 %s 失败",ipfile);
            return 1;
        }
    }
    log_msg("正在加载 locations.json");
    load_locations();
    log_msg("locations 加载完成: %zu 条", g_location_count);
    StringList ips=load_ip_list(ipfile,g_cfg.random_mode);
    if (ips.len==0) {
        log_msg("没有可扫描的 IP");
        return 1;
    }
    long start=0;
    ResultList results= {
        0
    }
    ;
    for (;
    ;
    ) {
        start=now_ms();
        results=scan_ips(&ips,&g_cfg);
        if (results.len>0)break;
        log_msg("未发现有效IP，可尝试放宽 -delay 或开启 -verbose=true 查看细节，3 秒后重试");
        if (!atomic_load(&g_running)) {
            strlist_free(&ips);
            free(g_locations);
            WSACleanup();
            return 0;
        }
        sleep(3);
    }
    printf("IP 地址 | 数据中心 | 地区 | 城市 | 延迟\n");
    for (size_t i=0;
    i<results.len;
    i++)printf("%s | %s | %s | %s | %d ms\n",results.items[i].ip,results.items[i].data_center,results.items[i].region,results.items[i].city,results.items[i].latency_ms);
    printf("成功提取 %zu 个有效IP，耗时 %ld秒\n",results.len,(now_ms()-start)/1000);
    g_candidates=results.items;
    g_candidate_count=results.len;
    if (!select_valid_ip()) {
        log_msg("没有有效的 IP 可用");
        strlist_free(&ips);
        free(results.items);
        return 1;
    }
    socket_t lfd=listen_tcp(g_cfg.addr);
    if (cfnat_socket_invalid(lfd)) {
        log_msg("无法监听 %s: %s",g_cfg.addr,cfnat_sock_error());
        strlist_free(&ips);
        free(results.items);
        return 1;
    }
    g_listen_fd=lfd;
    log_msg("正在监听 %s，TLS目标端口：%d，非TLS目标端口：%d，连接尝试次数：%d，有效延迟：%d ms",g_cfg.addr,g_cfg.port,g_cfg.http_port,g_cfg.num,g_cfg.delay_ms);
    pthread_t ht;
    create_small_thread(&ht,health_thread,NULL);
    while (atomic_load(&g_running)) {
        struct sockaddr_storage ss;
        socklen_t slen=sizeof(ss);
        socket_t cfd=accept(lfd,(struct sockaddr*)&ss,&slen);
        if (cfnat_socket_invalid(cfd)) {
            int e=WSAGetLastError();
            if (!atomic_load(&g_running))break;
            if (e==WSAEINTR||e==WSAENOTSOCK)break;
            sleep(1);
            continue;
        }
        char ip[MAX_IP_LEN];
        get_current_ip(ip,sizeof(ip));
        if (!ip[0]) {
            close(cfd);
            continue;
        }
        int active=atomic_fetch_add(&g_active_connections,1)+1;
        conn_msg("客户端连接建立，当前活跃连接数: %d",active);
        ConnCtx*cc=calloc(1,sizeof(ConnCtx));
        if (!cc) {
            close(cfd);
            atomic_fetch_sub(&g_active_connections,1);
            continue;
        }
        cc->client_fd=cfd;
        snprintf(cc->ip,sizeof(cc->ip),"%s",ip);
        cc->tls_port=g_cfg.port;
        cc->http_port=g_cfg.http_port;
        cc->num=g_cfg.num;
        cc->delay_ms=g_cfg.delay_ms;
        pthread_t tid;
        create_small_thread(&tid,connection_thread,cc);
        pthread_detach(tid);
    }
    if (cfnat_socket_valid(lfd))close(lfd);
    g_listen_fd=INVALID_SOCKET;
    pthread_join(ht,NULL);
    strlist_free(&ips);
    free(results.items);
    free(g_locations);
    WSACleanup();
    return 0;
}