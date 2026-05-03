#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
typedef enum  {
    SELECT_BEST=0,
    SELECT_FIRST,
    SELECT_ROTATE,
    SELECT_RANDOM
}
SelectStrategy;
typedef enum  {
    LOG_SILENT=0,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
}
LogLevel;
typedef struct  {
    char addr[64], colo[128], domain[256], select_name[32], log_name[16];
    int code, delay_ms, ipnum, ips_type, num, port, http_port, random_mode, task, health_log;
    SelectStrategy select_strategy;
    LogLevel log_level;
}
Config;
typedef struct  {
    char iata[MAX_COLO_LEN], region[MAX_REGION_LEN], city[MAX_CITY_LEN];
}
Location;
typedef struct  {
    char ip[MAX_IP_LEN], data_center[MAX_COLO_LEN], region[MAX_REGION_LEN], city[MAX_CITY_LEN];
    int latency_ms, loss_rate, probe_count, success_count;
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
    int client_fd, tls_port, http_port, num, delay_ms;
    char ip[MAX_IP_LEN];
}
ConnCtx;
typedef struct  {
    int from, to;
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
static int g_listen_fd = -1;


static long now_ms(void)  {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + tv.tv_usec / 1000L;
}


static const char* log_level_name(LogLevel level) {
    switch (level) {
        case LOG_SILENT:return "silent";
        case LOG_ERROR:return "error";
        case LOG_WARN:return "warn";
        case LOG_INFO:return "info";
        case LOG_DEBUG:
        default:return "debug";
    }
}


static int parse_log_level(const char *v, LogLevel *out) {
    if (!v||!*v)return -1;
    if (!strcasecmp(v,"silent")||!strcasecmp(v,"off")) {
        *out=LOG_SILENT;
        return 0;
    }
    if (!strcasecmp(v,"error")) {
        *out=LOG_ERROR;
        return 0;
    }
    if (!strcasecmp(v,"warn")||!strcasecmp(v,"warning")) {
        *out=LOG_WARN;
        return 0;
    }
    if (!strcasecmp(v,"info")) {
        *out=LOG_INFO;
        return 0;
    }
    if (!strcasecmp(v,"debug")) {
        *out=LOG_DEBUG;
        return 0;
    }
    return -1;
}


static void vlog_line(const char *tag,const char *fmt, va_list ap)  {
    time_t t=time(NULL);
    struct tm tmv;
    localtime_r(&t,&tmv);
    char ts[32];
    strftime(ts,sizeof(ts),"%Y/%m/%d %H:%M:%S",&tmv);
    fprintf(stderr,"%s [%s] ",ts,tag);
    vfprintf(stderr,fmt,ap);
    fputc('\n',stderr);
}


static void log_msg(const char *fmt, ...)  {
    if (g_cfg.log_level<LOG_INFO) return;
    va_list ap;
    va_start(ap,fmt);
    vlog_line("INFO",fmt,ap);
    va_end(ap);
}


static void warn_msg(const char *fmt, ...)  {
    if (g_cfg.log_level<LOG_WARN) return;
    va_list ap;
    va_start(ap,fmt);
    vlog_line("WARN",fmt,ap);
    va_end(ap);
}


static void debug_msg(const char *fmt, ...)  {
    if (g_cfg.log_level<LOG_DEBUG) return;
    va_list ap;
    va_start(ap,fmt);
    vlog_line("DEBUG",fmt,ap);
    va_end(ap);
}


static void conn_msg(const char *fmt, ...)  {
    if (g_cfg.log_level<LOG_INFO) return;
    va_list ap;
    va_start(ap,fmt);
    vlog_line("CONN",fmt,ap);
    va_end(ap);
}


static int sleep_interruptible_ms(int ms) {
    int left=ms;
    while (left>0&&atomic_load(&g_running)) {
        int chunk=left>200?200:left;
        struct timespec ts;
        ts.tv_sec=chunk/1000;
        ts.tv_nsec=(long)(chunk%1000)*1000000L;
        nanosleep(&ts,NULL);
        left-=chunk;
    }
    return atomic_load(&g_running)?0:-1;
}


static const char* select_name(SelectStrategy strategy) {
    switch (strategy) {
        case SELECT_FIRST:return "first";
        case SELECT_ROTATE:return "rotate";
        case SELECT_RANDOM:return "random";
        case SELECT_BEST:
        default:return "best";
    }
}


static int parse_select_value(const char *v, SelectStrategy *out) {
    if (!v||!*v)return -1;
    if (!strcasecmp(v,"best")) {
        *out=SELECT_BEST;
        return 0;
    }
    if (!strcasecmp(v,"first")) {
        *out=SELECT_FIRST;
        return 0;
    }
    if (!strcasecmp(v,"rotate")) {
        *out=SELECT_ROTATE;
        return 0;
    }
    if (!strcasecmp(v,"random")) {
        *out=SELECT_RANDOM;
        return 0;
    }
    return -1;
}


static void usage(const char *p)  {
    printf("Usage of %s:\n", p);
    printf("  -addr=value        本地监听的 IP 和端口 (default 0.0.0.0:1234)\n");
    printf("  -colo=value        筛选数据中心例如 HKG,SJC,LAX\n");
    printf("  -delay=value       有效延迟毫秒 (default 300)\n");
    printf("  -ipnum=value       提取的有效IP数量 (default 20)\n");
    printf("  -ips=value         指定IPv4还是IPv6 (4或6, C版优先IPv4)\n");
    printf("  -select=value      best=综合评分最优, first=固定首个可用, rotate=轮转候选, random=随机候选 (default best)\n");
    printf("  -log=value         日志级别: silent,error,warn,info,debug (default info)\n");
    printf("  -num=value         每个连接的目标连接尝试次数 (default 5)\n");
    printf("  -port=value        TLS 转发目标端口 (default 443)\n");
    printf("  -http-port=value   非TLS/HTTP 转发目标端口 (default 80)\n");
    printf("  -random=value      是否随机生成IP (default true)\n");
    printf("  -task=value        扫描线程数 (default 100)\n");
}


static int parse_bool(const char *v)  {
    return !v || strcmp(v,"1")==0 || strcasecmp(v,"true")==0 || strcasecmp(v,"yes")==0 || strcasecmp(v,"on")==0;
}


static void cfg_defaults(Config *c)  {
    memset(c,0,sizeof(*c));
    strcpy(c->addr,"0.0.0.0:1234");
    strcpy(c->domain,"cloudflaremirrors.com/debian");
    strcpy(c->select_name,"best");
    strcpy(c->log_name,"info");
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
    c->select_strategy=SELECT_BEST;
    c->log_level=LOG_INFO;
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
        else if (!strcmp(key,"select")&&val) {
            if (parse_select_value(val,&c->select_strategy)!=0) {
                fprintf(stderr,"非法 -select=%s，可选值: best, first, rotate, random\n",val);
                exit(1);
            }
            snprintf(c->select_name,sizeof(c->select_name),"%s",select_name(c->select_strategy));
        }
        else if (!strcmp(key,"log")&&val) {
            if (parse_log_level(val,&c->log_level)!=0) {
                fprintf(stderr,"非法 -log=%s，可选值: silent, error, warn, info, debug\n",val);
                exit(1);
            }
            snprintf(c->log_name,sizeof(c->log_name),"%s",log_level_name(c->log_level));
        }
        else if (!strcmp(key,"num")&&val) c->num=atoi(val);
        else if (!strcmp(key,"port")&&val) c->port=atoi(val);
        else if (!strcmp(key,"http-port")&&val) c->http_port=atoi(val);
        else if (!strcmp(key,"random")) c->random_mode=parse_bool(val);
        else if (!strcmp(key,"task")&&val) c->task=atoi(val);
        else if (!strcmp(key,"health-log")&&val) c->health_log=atoi(val);
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


static int download_file_from_urls(const char **urls,const char *filename) {
    char tmp[256];
    snprintf(tmp,sizeof(tmp),"%s.tmp",filename);
    for (int i=0;
    urls[i];
    i++) {
        char cmd[1024];
        snprintf(cmd,sizeof(cmd),"curl -fsSL '%s' -o '%s' 2>/dev/null || wget -qO '%s' '%s' 2>/dev/null",urls[i],tmp,tmp,urls[i]);
        int rc=system(cmd);
        if (rc==0&&file_exists(tmp)) {
            rename(tmp,filename);
            return 0;
        }
        unlink(tmp);
        log_msg("从 %s 下载失败，尝试下一个源",urls[i]);
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


static int set_nonblock(int fd,int nb) {
    int flags=fcntl(fd,F_GETFL,0);
    if (flags<0)return-1;
    if (nb)flags|=O_NONBLOCK;
    else flags&=~O_NONBLOCK;
    return fcntl(fd,F_SETFL,flags);
}


static int tcp_connect(const char*ip,int port,int timeout_ms,int*latency_ms) {
    long start=now_ms();
    int fd=socket(strchr(ip,':')?AF_INET6:AF_INET,SOCK_STREAM,0);
    if (fd<0)return-1;
    set_nonblock(fd,1);
    int rc;
    if (strchr(ip,':')) {
        struct sockaddr_in6 sa6;
        memset(&sa6,0,sizeof(sa6));
        sa6.sin6_family=AF_INET6;
        sa6.sin6_port=htons((uint16_t)port);
        if (inet_pton(AF_INET6,ip,&sa6.sin6_addr)!=1) {
            close(fd);
            return-1;
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
            return-1;
        }
        rc=connect(fd,(struct sockaddr*)&sa,sizeof(sa));
    }
    if (rc<0&&errno!=EINPROGRESS) {
        close(fd);
        return-1;
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
        return-1;
    }
    int err=0;
    socklen_t len=sizeof(err);
    if (getsockopt(fd,SOL_SOCKET,SO_ERROR,&err,&len)<0||err!=0) {
        close(fd);
        return-1;
    }
    set_nonblock(fd,0);
    if (latency_ms)*latency_ms=(int)(now_ms()-start);
    return fd;
}


static int recv_headers(int fd,char*buf,size_t bufsz,int timeout_ms) {
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
    const char*p=strcasestr(headers,"CF-RAY:");
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
    const char*req="GET / HTTP/1.1\r\nHost: cloudflaremirrors.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
    while (1) {
        size_t idx=atomic_fetch_add(&ctx->index,1);
        if (idx>=ctx->total)break;
        const char*ip=ctx->ips[idx];
        int probes=ctx->cfg->num>0?ctx->cfg->num:1;
        int success_count=0;
        int best_latency=0;
        char best_colo[MAX_COLO_LEN]= {0};
        for (int attempt=0; attempt<probes; attempt++) {
            int latency=0;
            int fd=tcp_connect(ip,80,ctx->cfg->delay_ms,&latency);
            if (fd<0)continue;
            send(fd,req,strlen(req),0);
            char hdr[4096];
            int n=recv_headers(fd,hdr,sizeof(hdr),2000);
            close(fd);
            if (n<=0)continue;
            char colo[MAX_COLO_LEN]= {0};
            if (extract_cfray(hdr,colo,sizeof(colo))!=0)continue;
            if (!colo_allowed(colo))continue;
            success_count++;
            if (best_latency==0||latency<best_latency) {
                best_latency=latency;
                snprintf(best_colo,sizeof(best_colo),"%s",colo);
            }
        }
        if (success_count<=0||!best_colo[0]||best_latency<=0)continue;
        Result r;
        memset(&r,0,sizeof(r));
        snprintf(r.ip,sizeof(r.ip),"%s",ip);
        snprintf(r.data_center,sizeof(r.data_center),"%s",best_colo);
        r.latency_ms=best_latency;
        r.probe_count=probes;
        r.success_count=success_count;
        r.loss_rate=(probes-success_count)*100/probes;
        Location*loc=find_location(best_colo);
        if (loc) {
            snprintf(r.region,sizeof(r.region),"%s",loc->region);
            snprintf(r.city,sizeof(r.city),"%s",loc->city);
        }
        debug_msg("发现有效IP %s 位置信息 %s 延迟 %d 毫秒 丢包 %d%% (%d/%d)",r.ip,r.city[0]?r.city:"未知",r.latency_ms,r.loss_rate,r.success_count,r.probe_count);
        resultlist_add(ctx->results,&r);
    }
    return NULL;
}


static int score_result(const Result*r) {
    return r->latency_ms*10+r->loss_rate*25;
}


static int cmp_result(const void*a,const void*b) {
    const Result*ra=(const Result*)a;
    const Result*rb=(const Result*)b;
    int sa=score_result(ra);
    int sb=score_result(rb);
    if (sa!=sb)return sa-sb;
    if (ra->latency_ms!=rb->latency_ms)return ra->latency_ms-rb->latency_ms;
    return ra->loss_rate-rb->loss_rate;
}


static const char* select_summary(SelectStrategy strategy) {
    switch (strategy) {
        case SELECT_FIRST:return "first=启动时固定首个可用 IP，失败后才切换";
        case SELECT_ROTATE:return "rotate=按候选顺序轮转使用可用 IP";
        case SELECT_RANDOM:return "random=每次连接从可用候选中随机选择 IP";
        case SELECT_BEST:
        default:return "best=按延迟和丢包率综合评分选择当前最优 IP";
    }
}


static void explain_selected_result(const Result*best) {
    if (!best)return;
    if (g_cfg.log_level<LOG_INFO) return;
    printf("选择策略: %s\n",select_summary(g_cfg.select_strategy));
    if (g_cfg.log_level>=LOG_DEBUG) {
        printf("结果解释: 选择 %s，因为延迟 %d ms，丢包 %d%%，综合分 %d。\n",best->ip,best->latency_ms,best->loss_rate,score_result(best));
    }
}


static ResultList scan_ips(StringList*ips,Config*cfg) {
    ResultList rl= {
        0
    }
    ;
    pthread_mutex_init(&rl.mu,NULL);
    int threads=cfg->task;
    if ((size_t)threads>ips->len)threads=(int)ips->len;
    if (threads<=0) {
        pthread_mutex_destroy(&rl.mu);
        return rl;
    }
    pthread_t*tids=calloc((size_t)threads,sizeof(pthread_t));
    if (!tids) {
        pthread_mutex_destroy(&rl.mu);
        return rl;
    }
    ScanCtx ctx= {
        .ips=ips->items,.total=ips->len,.results=&rl,.cfg=cfg
    }
    ;
    atomic_init(&ctx.index,0);
    int created=0;
    for (int i=0;
    i<threads;
    i++) {
        if (pthread_create(&tids[i],NULL,scan_worker,&ctx)!=0) break;
        created++;
    }
    for (int i=0;
    i<created;
    i++)pthread_join(tids[i],NULL);
    free(tids);
    pthread_mutex_destroy(&rl.mu);
    qsort(rl.items,rl.len,sizeof(Result),cmp_result);
    if (rl.len>(size_t)cfg->ipnum)rl.len=(size_t)cfg->ipnum;
    return rl;
}


static int health_check_ip(const char*ip) {
    int latency=0;
    int fd=tcp_connect(ip,g_cfg.port,2000,&latency);
    if (fd<0) {
        debug_msg("健康检查失败: IP %s 暂不可用",ip);
        return 0;
    }
    close(fd);
    debug_msg("健康检查成功: IP %s 延迟 %d ms",ip,latency);
    return 1;
}


static int set_current_candidate(size_t idx) {
    if (idx>=g_candidate_count)return 0;
    pthread_mutex_lock(&g_ip_mu);
    snprintf(g_current_ip,sizeof(g_current_ip),"%s",g_candidates[idx].ip);
    g_current_index=idx;
    pthread_mutex_unlock(&g_ip_mu);
    return 1;
}


static int select_valid_ip(void) {
    for (size_t i=0;
    i<g_candidate_count;
    i++) {
        if (health_check_ip(g_candidates[i].ip)) {
            set_current_candidate(i);
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
            set_current_candidate(i);
            log_msg("切换到新的有效 IP: %s 更新 IP 索引: %zu",g_candidates[i].ip,i);
            return 1;
        }
    }
    return 0;
}


static int choose_ip_for_connection(char*out,size_t sz) {
    if (!out||sz==0)return 0;
    out[0]='\0';
    if (g_candidate_count==0)return 0;
    if (g_cfg.select_strategy==SELECT_FIRST) {
        pthread_mutex_lock(&g_ip_mu);
        snprintf(out,sz,"%s",g_current_ip);
        pthread_mutex_unlock(&g_ip_mu);
        return out[0]!=0;
    }
    if (g_cfg.select_strategy==SELECT_RANDOM) {
        size_t start=(size_t)(rand()%((int)g_candidate_count));
        for (size_t step=0; step<g_candidate_count; step++) {
            size_t idx=(start+step)%g_candidate_count;
            if (health_check_ip(g_candidates[idx].ip)) {
                snprintf(out,sz,"%s",g_candidates[idx].ip);
                return 1;
            }
        }
        return 0;
    }
    if (g_cfg.select_strategy==SELECT_ROTATE) {
        pthread_mutex_lock(&g_ip_mu);
        size_t start=g_current_index;
        pthread_mutex_unlock(&g_ip_mu);
        for (size_t step=1; step<=g_candidate_count; step++) {
            size_t idx=(start+step)%g_candidate_count;
            if (health_check_ip(g_candidates[idx].ip)) {
                set_current_candidate(idx);
                snprintf(out,sz,"%s",g_candidates[idx].ip);
                return 1;
            }
        }
        return 0;
    }
    for (size_t i=0; i<g_candidate_count; i++) {
        if (health_check_ip(g_candidates[i].ip)) {
            snprintf(out,sz,"%s",g_candidates[i].ip);
            set_current_candidate(i);
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
            warn_msg("没有可扫描的 IP，3 秒后重试");
            if (sleep_interruptible_ms(3000)!=0) return 0;
            continue;
        }
        ResultList results=scan_ips(&ips,&g_cfg);
        strlist_free(&ips);
        if (results.len==0) {
            warn_msg("重新扫描后仍未发现有效IP，3 秒后重试");
            if (sleep_interruptible_ms(3000)!=0) return 0;
            continue;
        }
        g_candidates=results.items;
        g_candidate_count=results.len;
        log_msg("重新扫描得到 %zu 个候选 IP",g_candidate_count);
        if (select_valid_ip())return 1;
        free(results.items);
        g_candidates=NULL;
        g_candidate_count=0;
        warn_msg("重新扫描得到的候选 IP 健康检查均失败，3 秒后重试");
        if (sleep_interruptible_ms(3000)!=0) return 0;
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
        if (sleep_interruptible_ms(10000)!=0) break;
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


static void close_pair(int a,int b) {
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


static int relay_bidirectional(int c,int u) {
    pthread_t t1,t2;
    PipeCtx a= {
        c,u
    }
    ,b= {
        u,c
    }
    ;
    create_small_thread(&t1,pipe_worker,&a);
    create_small_thread(&t2,pipe_worker,&b);
    pthread_join(t1,NULL);
    pthread_join(t2,NULL);
    return 0;
}


static void* connection_thread(void*arg) {
    ConnCtx*cc=(ConnCtx*)arg;
    int client=cc->client_fd;
    unsigned char first=0;
    ssize_t n=recv(client,&first,1,0);
    if (n<=0)goto out;
    int is_tls=first==0x16;
    int target_port=is_tls?cc->tls_port:cc->http_port;
    conn_msg("识别客户端协议: %s，转发到 IP: %s 端口: %d",is_tls?"TLS":"非 TLS",cc->ip,target_port);
    int upstream=-1,best=0;
    for (int i=0;
    i<cc->num;
    i++) {
        int lat=0;
        int fd=tcp_connect(cc->ip,target_port,cc->delay_ms,&lat);
        if (fd>=0) {
            upstream=fd;
            best=lat;
            break;
        }
    }
    if (upstream<0) {
        debug_msg("未找到符合延迟要求的连接，关闭客户端连接");
        goto out;
    }
    send(upstream,&first,1,0);
    conn_msg("选择连接: 地址: %s:%d 延迟: %d ms",cc->ip,target_port,best);
    relay_bidirectional(client,upstream);
    close(upstream);
    out:close(client);
    int active=atomic_fetch_sub(&g_active_connections,1)-1;
    conn_msg("客户端连接关闭，当前活跃连接数: %d",active);
    free(cc);
    return NULL;
}


static int parse_addr(const char*addr,char*host,size_t hostsz,int*port) {
    if (!addr||!host||!port)return-1;
    if (addr[0]=='[') {
        const char*end=strchr(addr,']');
        if (!end||end[1]!=':')return-1;
        size_t n=(size_t)(end-(addr+1));
        if (n>=hostsz)n=hostsz-1;
        memcpy(host,addr+1,n);
        host[n]=0;
        *port=atoi(end+2);
        return *port>0?0:-1;
    }
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


static int listen_tcp(const char*addr) {
    char host[128];
    int port=0;
    if (parse_addr(addr,host,sizeof(host),&port)!=0)return-1;
    int yes=1;
    if (strchr(host,':')) {
        int fd=socket(AF_INET6,SOCK_STREAM,0);
        if (fd<0)return-1;
        setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
        struct sockaddr_in6 sa6;
        memset(&sa6,0,sizeof(sa6));
        sa6.sin6_family=AF_INET6;
        sa6.sin6_port=htons((uint16_t)port);
        if (inet_pton(AF_INET6,host,&sa6.sin6_addr)!=1) {
            close(fd);
            return-1;
        }
        if (bind(fd,(struct sockaddr*)&sa6,sizeof(sa6))!=0) {
            close(fd);
            return-1;
        }
        if (listen(fd,1024)!=0) {
            close(fd);
            return-1;
        }
        return fd;
    }
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd<0)return-1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
    struct sockaddr_in sa;
    memset(&sa,0,sizeof(sa));
    sa.sin_family=AF_INET;
    sa.sin_port=htons((uint16_t)port);
    if (inet_pton(AF_INET,host,&sa.sin_addr)!=1) {
        close(fd);
        return-1;
    }
    if (bind(fd,(struct sockaddr*)&sa,sizeof(sa))!=0) {
        close(fd);
        return-1;
    }
    if (listen(fd,1024)!=0) {
        close(fd);
        return-1;
    }
    return fd;
}


static void on_signal(int sig) {
    (void)sig;
    atomic_store(&g_running,0);
    if (g_listen_fd>=0) {
        close(g_listen_fd);
        g_listen_fd=-1;
    }
}


static void install_signals(void) {
    struct sigaction sa;
    memset(&sa,0,sizeof(sa));
    sa.sa_handler=on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags=0;
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGTERM,&sa,NULL);
    signal(SIGPIPE,SIG_IGN);
}


int main(int argc,char**argv) {
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
        warn_msg("未发现有效IP，可尝试放宽 -delay 或提高 -log=debug 查看细节，3 秒后重试");
        if (!atomic_load(&g_running)) {
            strlist_free(&ips);
            free(g_locations);
            return 0;
        }
        if (sleep_interruptible_ms(3000)!=0) {
            strlist_free(&ips);
            free(g_locations);
            return 0;
        }
    }
    printf("候选池统计\n");
    printf("当前策略: %s\n",g_cfg.select_name);
    printf("候选总数: %zu\n",results.len);
    if (g_cfg.log_level>=LOG_INFO) {
        printf("策略说明: %s\n",select_summary(g_cfg.select_strategy));
    }
    printf("IP 地址 | 数据中心 | 地区 | 城市 | 延迟 | 丢包 | 探测成功\n");
    for (size_t i=0;
    i<results.len;
    i++)printf("%s | %s | %s | %s | %d ms | %d%% | %d/%d\n",results.items[i].ip,results.items[i].data_center,results.items[i].region,results.items[i].city,results.items[i].latency_ms,results.items[i].loss_rate,results.items[i].success_count,results.items[i].probe_count);
    printf("成功提取 %zu 个有效IP，耗时 %ld秒\n",results.len,(now_ms()-start)/1000);
    if (results.len>0) {
        printf("评分最优 IP: %s\n",results.items[0].ip);
        printf("最佳延迟: %d ms\n",results.items[0].latency_ms);
        printf("最佳丢包率: %d%%\n",results.items[0].loss_rate);
        explain_selected_result(&results.items[0]);
    }
    g_candidates=results.items;
    g_candidate_count=results.len;
    if (!select_valid_ip()) {
        log_msg("没有有效的 IP 可用");
        strlist_free(&ips);
        free(results.items);
        return 1;
    }
    strlist_free(&ips);
    int lfd=listen_tcp(g_cfg.addr);
    if (lfd<0) {
        log_msg("无法监听 %s: %s",g_cfg.addr,strerror(errno));
        free(results.items);
        return 1;
    }
    g_listen_fd=lfd;
    log_msg("正在监听 %s，TLS目标端口：%d，非TLS目标端口：%d，连接尝试次数：%d，有效延迟：%d ms，策略：%s，日志：%s",g_cfg.addr,g_cfg.port,g_cfg.http_port,g_cfg.num,g_cfg.delay_ms,g_cfg.select_name,g_cfg.log_name);
    pthread_t ht;
    create_small_thread(&ht,health_thread,NULL);
    while (atomic_load(&g_running)) {
        struct sockaddr_storage ss;
        socklen_t slen=sizeof(ss);
        int cfd=accept(lfd,(struct sockaddr*)&ss,&slen);
        if (cfd<0) {
            if (!atomic_load(&g_running))break;
            if (errno==EINTR||errno==EBADF)break;
            if (sleep_interruptible_ms(1000)!=0) break;
            continue;
        }
        char ip[MAX_IP_LEN];
        if (!choose_ip_for_connection(ip,sizeof(ip))) {
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
    if (lfd>=0)close(lfd);
    g_listen_fd=-1;
    pthread_join(ht,NULL);
    free(results.items);
    g_candidates=NULL;
    g_candidate_count=0;
    free(g_locations);
    g_locations=NULL;
    g_location_count=0;
    return 0;
}