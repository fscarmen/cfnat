# cfnat C 版

面向低内存环境的 **Cloudflare IP 扫描 + 单端口 TCP 转发** 工具。

C 版基于 [`cfnat.go`](cfnat.go) 移植，目标不是把功能做得更复杂，而是在保留扫描、优选、转发、健康检查、百度前置代理和运营商分池等核心能力的同时，尽量降低常驻内存占用，适合 OpenWrt、路由器、小内存 VPS、ARM 小板机等资源受限环境。

---

## 目录

- [项目定位](#项目定位)
- [核心特性](#核心特性)
- [快速开始](#快速开始)
- [运行参数](#运行参数)
- [常用示例](#常用示例)
- [工作原理](#工作原理)
- [快速启动缓存](#快速启动缓存)
- [百度前置代理与运营商分池](#百度前置代理与运营商分池)
- [构建与发布](#构建与发布)
- [仓库文件说明](#仓库文件说明)
- [数据文件说明](#数据文件说明)
- [日志与排错](#日志与排错)
- [资源占用说明](#资源占用说明)
- [常见问题](#常见问题)
- [免责声明](#免责声明)

---

## 项目定位

cfnat C 版做三件事：

1. 扫描 Cloudflare IP，按数据中心、延迟、丢包率筛出候选节点。
2. 在本机监听一个 TCP 端口，自动识别 TLS / 非 TLS 流量。
3. 把客户端连接转发到当前可用的 Cloudflare 优选 IP，并在失败时自动切换。

它不是 HTTP 反向代理，也不会解密或篡改业务数据。它只做 TCP 字节转发。

典型链路：

```text
客户端
  ↓
cfnat 本地监听端口
  ↓
Cloudflare 优选 IP:443 或 :80
```

启用百度前置代理时：

```text
客户端
  ↓
cfnat 本地监听端口
  ↓
百度前置节点（HTTP CONNECT）
  ↓
Cloudflare 优选 IP:443 或 :80
```

---

## 核心特性

- 支持 IPv4 / IPv6 扫描入口。
- 支持 IPv4 / IPv6 监听地址。
- 支持按 Cloudflare 数据中心过滤，例如 `HKG`、`SJC`、`LAX`。
- 候选 IP 按延迟和丢包率综合评分，始终使用当前 score 最低的最优 IP。
- 默认启用候选缓存，二次启动时先快速健康检查缓存 IP，命中后立即监听，再后台刷新。
- 单端口同时承接 TLS 与非 TLS / HTTP 流量。
- 根据客户端首字节自动分流到 `-port` 或 `-http-port`。
- 支持定时健康检查与失败自动切换。
- 支持百度前置代理。
- 支持运营商分池监听，可按移动、电信、联通分别建立监听入口。
- Linux / macOS / Windows 三平台实现。
- Linux / macOS 使用 `pthread` + POSIX/BSD socket，并内置轻量 DNS TXT 查询，避免依赖 glibc resolver 静态链接。
- Windows 使用 Winsock2 + Windows DNS API + MinGW-w64 `winpthread`，控制台输出通过 `WriteConsoleW` 直接写入 Unicode，兼容 Windows 7 中文显示。
- 统一日志级别：`silent`、`error`、`warn`、`info`、`debug`。

---

## 快速开始

### 1. 本地编译

Linux（glibc 动态版，推荐给常规发行版）：

```bash
gcc -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_linux.c -o ./cfnat-linux \
  -pthread
```

Linux（musl 静态版，推荐给 OpenWrt / Alpine / 小系统）：

```bash
zig cc -target x86_64-linux-musl -O2 -pipe -std=c11 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_linux.c -o ./cfnat-linux-amd64-musl \
  -pthread -static -s
```

macOS：

```bash
clang -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_macos.c -o ./cfnat-macos \
  -pthread
```

Windows（MinGW-w64）：

```bash
x86_64-w64-mingw32-gcc \
  -O2 -pipe -std=c11 -D_WIN32_WINNT=0x0601 \
  -finput-charset=UTF-8 -fexec-charset=UTF-8 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_windows.c -o ./cfnat.exe \
  -lws2_32 -ldnsapi -lwininet -lwinpthread -static -s
```

### 2. 启动

Linux 示例：

```bash
./cfnat-linux -addr=0.0.0.0:40000 -colo=HKG -delay=120 -random=true
```

macOS 示例：

```bash
./cfnat-macos -addr=0.0.0.0:40000 -colo=HKG -delay=120 -random=true
```

Windows 示例：

```bash
cfnat.exe -addr=0.0.0.0:40000 -colo=HKG -delay=120 -random=true
```

### 3. 客户端访问

客户端统一连接同一个端口：

```text
服务器IP:40000
```

程序会自动识别连接类型：

```text
TLS 流量           → Cloudflare IP:443
非 TLS / HTTP 流量 → Cloudflare IP:80
```

---

## 运行参数

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `-addr` | 本地监听地址，例如 `0.0.0.0:1234` 或 `[::]:1234` | `0.0.0.0:1234` |
| `-colo` | Cloudflare 数据中心过滤，多个用逗号分隔，例如 `HKG,SJC,LAX` | 空 |
| `-delay` | 有效延迟阈值，单位毫秒 | `300` |
| `-ipnum` | 保留的候选 IP 数量 | `20` |
| `-ips` | 扫描 IPv4 或 IPv6，取值 `4` 或 `6` | `4` |
| `-num` | 每个客户端连接的目标连接尝试次数 | `5` |
| `-port` | TLS 流量转发目标端口 | `443` |
| `-http-port` | 非 TLS / HTTP 流量转发目标端口 | `80` |
| `-random` | 是否从 CIDR 随机抽样 IP；`true` 启动快，`false` 会完整展开 CIDR，扫描量很大 | `true` |
| `-task` | 扫描线程数，上限为 `512` | `100` |
| `-code` | HTTP / HTTPS 探测期望状态码 | `200` |
| `-domain` | 健康检查目标域名与路径 | `cloudflaremirrors.com/debian` |
| `-health-log` | 健康检查成功日志输出间隔，单位秒；设为 `0` 可关闭成功日志 | `60` |
| `-log` | 日志级别：`silent`、`error`、`warn`、`info`、`debug` | `info` |
| `-baidu-proxy` | 是否启用百度前置代理 | `false` |
| `-carrier-listens` | 运营商分池监听配置 | 空 |

### 已固定为源码常量的项目

为了减少参数污染，以下配置不再作为命令行参数暴露，而是放在三个 C 源文件顶部：

| 配置 | 源码常量 |
| --- | --- |
| 百度前置代理域名 | `DEFAULT_BAIDU_DOMAIN` |
| 百度前置代理端口 | `DEFAULT_BAIDU_PORT` |
| 百度代理扫描目标 | `DEFAULT_BAIDU_SCAN_TARGET` |
| 每个百度代理池保留节点数 | `DEFAULT_BAIDU_IPNUM` |
| 运营商解析器配置 | `DEFAULT_CARRIER_RESOLVERS` |

需要调整这些值时，直接修改对应平台源码顶部的默认常量：

```text
cfnat_linux.c
cfnat_macos.c
cfnat_windows.c
```

---

## 常用示例

### 扫描香港机房并监听单端口

```bash
./cfnat-linux -addr=0.0.0.0:40000 -colo=HKG -delay=120 -random=true
```

### 同时接受多个数据中心

```bash
./cfnat-linux -addr=0.0.0.0:40000 -colo=HKG,SJC,LAX -delay=120
```

### 使用 IPv6 扫描源

```bash
./cfnat-linux -addr=[::]:40000 -ips=6 -colo=HKG -delay=120
```

### 打开调试日志

```bash
./cfnat-linux -log=debug
```

### 提高候选池规模和扫描并发

```bash
./cfnat-linux -ipnum=50 -task=200
```

### 启用百度前置代理

```bash
./cfnat-linux -baidu-proxy=true -addr=0.0.0.0:40000 -colo=HKG
```

### 启用运营商分池监听

```bash
./cfnat-linux \
  -baidu-proxy=true \
  -carrier-listens="mobile=0.0.0.0:1234,telecom=0.0.0.0:1235,unicom=0.0.0.0:1236"
```

分池模式下，可以给不同运营商分配不同本地入口：

```text
移动用户 → 服务器IP:1234
电信用户 → 服务器IP:1235
联通用户 → 服务器IP:1236
```

---

## 工作原理

### 1. 加载 IP 段

程序启动后根据 `-ips` 选择 IPv4 或 IPv6 扫描源：

```text
-ips=4 → IPv4
-ips=6 → IPv6
```

本地数据文件不存在时，会尝试自动下载。

### 2. 生成待测 IP

根据 `-random` 决定扫描方式：

```text
-random=true   从每个 CIDR 随机抽取 IP，启动快，适合日常使用
-random=false  完整展开 CIDR 后按顺序测试，扫描更全面，但 IP 数量可能超过百万，耗时明显更长
```

程序会输出 IP 列表加载进度和扫描进度。Windows 下如果看到“默认百度代理池已建立”后短时间没有发现有效 IP，通常是在完整展开或扫描大量候选，并不是卡死。需要快速启动时优先使用默认的 `-random=true`。

---

## 快速启动缓存

程序默认启用候选缓存，用来解决“每次启动都要重新扫描一遍”的问题。

首次运行时仍会正常扫描 IP。扫描成功后，程序会把当前候选池写入缓存文件。后续启动时会先读取缓存，对前几个候选 IP 做快速健康检查：

```text
启动
→ 读取候选缓存
→ 快速检查缓存里的前几个 IP
→ 命中可用 IP 后立即开始监听
→ 后台继续扫描刷新候选池
→ 刷新完成后写回缓存
```

这样第二次及之后启动通常不需要等待完整扫描完成，命中缓存后可以先进入监听状态，再慢慢刷新更优结果。

缓存文件按 IP 类型和是否启用百度前置代理区分：

```text
cfnat-cache-v4.txt          IPv4 直连缓存
cfnat-cache-v6.txt          IPv6 直连缓存
cfnat-cache-v4-baidu.txt    IPv4 百度前置代理缓存
cfnat-cache-v6-baidu.txt    IPv6 百度前置代理缓存
```

缓存不按时间失效。程序启动时只看健康检查结果：缓存 IP 可用就立即使用，不可用才等待完整扫描。

后台刷新不会阻塞监听服务。刷新成功后会重新按 score 排序，并把扫描结果写回缓存。

需要完全重新扫描时，删除对应的 `cfnat-cache-*.txt` 文件即可。


### 3. TCP 连通性测试

对待测 IP 发起 TCP 连接测试，并记录建连耗时。

这个耗时会作为基础延迟，后续用于候选评分。

### 4. 识别 Cloudflare 数据中心

程序向目标 IP 发起 HTTP 探测，并优先从响应头中读取 `CF-RAY`。

探测时会先使用目标 IP 作为 `Host` 发起请求，行为更接近原 Go 版；随后再尝试默认域名。这样可以避免部分 Windows / 网络环境下请求有响应但没有命中预期 Host，导致一直扫不到 IP。

示例：

```text
xxxx-HKG
xxxx-SJC
xxxx-LAX
```

后缀就是 Cloudflare 数据中心代码。程序会结合 `locations.json` 映射地区与城市信息。

如果 HTTP 响应能正常返回但没有 `CF-RAY`，并且没有指定 `-colo`，程序会把这个 IP 作为 `UNK` 候选保留下来，再由后续健康检查确认是否可用。

仅 TCP 连接成功但没有读到 HTTP 响应时，不再直接加入候选池，避免 Windows 多线程扫描或百度前置代理场景下把大量不可确认节点误判为有效 IP。

### 5. 按 `-colo` 过滤

如果指定：

```bash
-colo=HKG,SJC,LAX
```

程序只保留匹配这些数据中心的结果。

不指定 `-colo` 时，不按数据中心过滤。

### 6. 综合评分

候选 IP 会根据延迟和丢包率计算综合分，分数越低越优。

可以近似理解为：

```text
score = latency * 10 + loss_rate * 25
```

所以程序不是单纯选择最低延迟，而是同时考虑速度和稳定性。

### 优选原则

程序没有多套选择逻辑，只有一套固定的自动优选逻辑：

```text
扫描候选
→ 按 score 排序
→ 永远取 score 最低的 IP
→ 健康检查失败
→ 切换到下一个最优候选
→ 候选池耗尽后重新扫描并重新排序
```

这个模型可以避免轮询或随机选择带来的链路漂移，让行为更稳定、代码更简单。

### 7. 健康检查

程序会对候选 IP 做目标端口健康检查。

只有健康检查通过的 IP 才会成为当前转发 IP。

### 8. 自动切换

运行期间会定时检查当前 IP。

当当前 IP 连续失败两次后，程序会切换到下一个可用候选；如果候选池耗尽，会重新扫描。

### 9. 单端口自动分流

客户端只需要连接同一个本地端口。程序接收连接后读取客户端首字节：

```text
首字节是 0x16 → 认为是 TLS 流量
其他情况      → 认为是非 TLS / HTTP 流量
```

然后转发到不同目标端口：

```text
TLS 流量           → Cloudflare IP:-port
非 TLS / HTTP 流量 → Cloudflare IP:-http-port
```

默认等价于：

```text
TLS 流量           → Cloudflare IP:443
非 TLS / HTTP 流量 → Cloudflare IP:80
```

---

## 百度前置代理与运营商分池

### 百度前置代理

启用 `-baidu-proxy=true` 后，扫描和转发会通过百度前置节点建立 HTTP CONNECT 链路。

简化链路：

```text
客户端
  ↓
cfnat
  ↓
百度前置节点
  ↓
Cloudflare IP
```

这个模式适合本机直连 Cloudflare 不稳定、但经前置节点链路更稳定的网络环境。

注意：百度前置代理不是万能加速器。它的价值在于让扫描路径和实际转发路径尽量一致，减少“扫得通但转发不稳”的偏差。

### 运营商分池

启用 `-carrier-listens` 后，程序可以按运营商建立独立监听入口和独立候选池。

示例：

```bash
-carrier-listens="mobile=0.0.0.0:1234,telecom=0.0.0.0:1235,unicom=0.0.0.0:1236"
```

典型用途：

- 移动、电信、联通到前置节点的路径差异明显。
- 单一候选池容易出现某个运营商可用、另一个运营商劣化。
- 想给不同入口分别维护更贴近各自网络路径的候选 IP。

---

## 构建与发布

本仓库当前维护三个 C 入口文件：

| 平台 | 源文件 | 主要依赖 |
| --- | --- | --- |
| Linux | [`cfnat_linux.c`](cfnat_linux.c) | `pthread`、POSIX socket、内置 DNS TXT 查询 |
| macOS | [`cfnat_macos.c`](cfnat_macos.c) | `pthread`、BSD socket、内置 DNS TXT 查询 |
| Windows | [`cfnat_windows.c`](cfnat_windows.c) | Winsock2、Windows DNS API、`winpthread` |


### Linux 发布版本选择

Release 同时提供两类 Linux 文件：

| 类型 | 适合用户 | 说明 |
| --- | --- | --- |
| glibc 动态版 | Debian、Ubuntu、Arch、CentOS、Fedora 等常规发行版 | 默认推荐，运行时使用系统自己的 glibc，避免静态 glibc 与系统环境错位 |
| musl 静态版 | Alpine、OpenWrt、ImmortalWrt、极简容器、小内存系统 | 完全静态，更适合轻量系统和无 glibc 环境 |

glibc fully-static 在部分发行版和新内核环境下可能出现 resolver、pthread、NSS、IPv6 或 DNS 初始化兼容问题，因此不再作为默认发布产物。需要完全静态时，请优先使用 musl 静态版。

### Linux 构建

glibc 动态版：

```bash
gcc -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_linux.c -o ./cfnat-linux \
  -pthread
```

musl 静态版示例：

```bash
zig cc -target x86_64-linux-musl -O2 -pipe -std=c11 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_linux.c -o ./cfnat-linux-amd64-musl \
  -pthread -static -s
```

说明：

- 默认推荐 glibc 动态版，适合常规 Linux 发行版。
- 如需完全静态二进制，推荐 musl 静态版。
- 源码已内置轻量 DNS TXT 查询，不再依赖 glibc `res_query` / `ns_initparse` / `ns_parserr`。

### macOS 构建

```bash
clang -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_macos.c -o ./cfnat-macos \
  -pthread
```

交叉指定架构示例：

```bash
clang -O2 -pipe -std=c11 \
  -arch x86_64 -mmacosx-version-min=10.13 \
  ./cfnat_macos.c -o ./cfnat-darwin-amd64 \
  -pthread
```

```bash
clang -O2 -pipe -std=c11 \
  -arch arm64 -mmacosx-version-min=11.0 \
  ./cfnat_macos.c -o ./cfnat-darwin-arm64 \
  -pthread
```

说明：

- macOS amd64 最低目标可设为 `10.13`。
- macOS arm64 最低目标通常设为 `11.0`，因为 Apple Silicon 从 macOS 11 开始支持。
- macOS 不支持像 Linux musl 那样生成完全静态的系统 libc 二进制。
- macOS 版同样使用内置 DNS TXT 查询，不再需要 `-lresolv`。


### Windows 中文显示

Windows 7 的传统 CMD 对 UTF-8 控制台支持不稳定，单纯调用 `SetConsoleOutputCP(CP_UTF8)` 或执行 `chcp 65001` 仍可能乱码。

Windows 版现在不再依赖控制台代码页显示中文。程序会把内部 UTF-8 日志转换为 Unicode，并通过 `WriteConsoleW` 直接写入控制台。

这样在 Windows 7 / Windows 10 / Windows 11 下都更稳定：

- 直接在 CMD 运行时，中文走 Unicode 控制台输出。
- 输出重定向到文件时，仍保留 UTF-8 文本。
- 不需要用户手动执行 `chcp 65001`。

如果 Windows 7 下仍显示方块，通常是控制台字体缺少中文字形，建议把 CMD 字体改成支持中文的字体，或使用 PowerShell。

### Windows 构建

64 位：

```bash
x86_64-w64-mingw32-gcc \
  -O2 -pipe -std=c11 -D_WIN32_WINNT=0x0601 \
  -finput-charset=UTF-8 -fexec-charset=UTF-8 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_windows.c -o ./cfnat-windows-amd64.exe \
  -lws2_32 -ldnsapi -lwininet -lwinpthread -static -s
```

32 位：

```bash
i686-w64-mingw32-gcc \
  -O2 -pipe -std=c11 -D_WIN32_WINNT=0x0601 \
  -finput-charset=UTF-8 -fexec-charset=UTF-8 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat_windows.c -o ./cfnat-windows-386.exe \
  -lws2_32 -ldnsapi -lwininet -lwinpthread -static -s
```

说明：

- `_WIN32_WINNT=0x0601` 表示目标为 Windows 7 或更高版本。
- `-finput-charset=UTF-8 -fexec-charset=UTF-8` 确保源码中的中文字符串按 UTF-8 编译，配合 `WriteConsoleW` 避免 Windows 7 控制台乱码。
- Windows 网络层使用 Winsock2，因此需要 `-lws2_32`。
- Windows TXT 查询使用 `DnsQuery_A()` / `DnsFree()`，因此需要 `-ldnsapi`。
- Windows 自动下载数据文件使用 WinINet，不再依赖 curl/wget，因此需要 `-lwininet`。
- Windows 线程兼容层使用 MinGW-w64 `winpthread`，因此需要 `-lwinpthread`。


### Windows 数据文件下载说明

Windows 版不再调用外部 `curl` / `wget` 命令下载数据文件，而是使用系统 WinINet API 下载。

启动时会优先查找：

```text
ips-v4.txt
ips-v6.txt
locations.json
```

Win7 如果系统 TLS 组件过旧，HTTPS 下载仍可能失败。这种情况下把上述三个数据文件放到 exe 同目录即可离线运行。

### GitHub Actions

多平台构建工作流位于：

```text
.github/workflows/build.yml
```

当前工作流包含：

- Linux glibc 动态版：amd64、386、armv5、armv6、armv7、arm64、mips、mipsel、mips64、mips64el、ppc64、ppc64le、riscv64、s390x。
- Linux musl 静态版：amd64、386、armv6、armv7、arm64、mips、mipsel、riscv64。
- armv5、mips64、mips64el、ppc64、ppc64le、s390x 当前使用 glibc 动态版发布；Zig 0.15.1 在 armv5 musl 下会因 32 位原子内建符号缺失导致链接失败，在 mips64 / ppc64 / s390x 等架构下也不能稳定提供 musl libc，因此不放入必跑 musl 矩阵，避免 release 出现红叉。
- Windows：amd64、386。
- macOS：amd64、arm64。
- tag 触发发布：推送 `v*` 标签后打包 release 文件和校验和。
- 手动触发：支持 `workflow_dispatch`。

发布包会把二进制文件放入 `bin/`，并附带源码、README 和基础数据文件。

### 常见构建失败

| 现象 | 原因 | 修复 |
| --- | --- | --- |
| 旧版 macOS 源码出现 `_res_9_query`、`_res_9_ns_initparse`、`_res_9_ns_parserr` undefined symbols | 使用了系统 resolver API 但未链接 resolver 库 | 当前源码已改为内置 DNS TXT 查询；如使用旧源码才需要 `-lresolv` |
| 旧版 Linux 源码出现 `res_query`、`ns_initparse`、`ns_parserr` undefined reference | 使用了 glibc resolver API 但未链接 resolver 库 | 当前源码已改为内置 DNS TXT 查询；如使用旧源码才需要 `-lresolv` |
| Windows 出现 `undefined reference to DnsQuery_A` / `DnsFree` | 没有链接 Windows DNS API | 在链接参数末尾加 `-ldnsapi` |
| Windows 出现 Winsock 相关 undefined reference | 没有链接 Winsock2 | 加 `-lws2_32` |
| 出现 `choose_name`、`parse_choose_value`、`choose_summary` unused warning | 遗留辅助函数未被调用 | 不影响链接；追求干净日志时可删除遗留函数 |
| Windows 出现 `SOCKET` 与 `< 0` / `>= 0` 比较 warning | Windows `SOCKET` 是无符号类型，应使用 `INVALID_SOCKET` 判断 | 不一定导致编译失败；如开启 `-Werror` 需修正判断方式 |

---

## 仓库文件说明

```text
cfnat.go                         Go 版实现 / 参考实现
cfnat-origin.go                  原始 Go 版留档
cfnat_linux.c                    Linux C 版入口
cfnat_macos.c                    macOS C 版入口
cfnat_windows.c                  Windows C 版入口
ips-v4.txt                       IPv4 数据文件
ips-v6.txt                       IPv6 数据文件
locations.json                   Cloudflare 数据中心位置文件
README.md                        主说明文档
.github/workflows/build.yml      C 版多平台构建工作流
.github/workflows/build_go.yml   Go 版构建工作流
```

`README-build.md` 已合并进本文件，不再单独维护，避免构建说明和主文档互相漂移。

---

## 数据文件说明

源码运行时会查找以下本地文件：

```text
ips-v4.txt
ips-v6.txt
locations.json
```

如果文件不存在，程序会自动从上游地址下载并保存为上述文件名。

离线运行时请直接把下面三个文件放在程序同目录：

```text
ips-v4.txt
ips-v6.txt
locations.json
```

Linux、macOS、Windows 三个平台统一使用这三个带扩展名的数据文件，避免 Windows 用户看不到文件类型或手动复制时混淆。

---

## 日志与排错

### 日志级别

```text
-log=silent  不输出普通日志
-log=error   仅输出错误
-log=warn    输出警告和错误
-log=info    输出常规运行日志
-log=debug   输出调试信息
```

### 正常日志示例

```text
可用 IP: 104.18.x.x (健康检查端口:443)
正在监听 0.0.0.0:40000，TLS目标端口：443，非TLS目标端口：80
状态检查成功: 当前 IP 104.18.x.x 可用
```

### 自动切换日志示例

```text
状态检查失败 (1/2): 当前 IP 104.18.x.x 暂不可用
连续两次状态检查失败，切换到下一个 IP
切换到下一个最优 IP: 104.18.x.x 候选索引: 3
```

### 没有扫到有效 IP

```text
未发现有效IP，可尝试放宽 -delay 或提高 -log=debug 查看细节，3 秒后重试
```

建议按下面顺序排查：

1. 开启 `-log=debug`，查看扫描统计里的连接失败、读取响应失败、缺少 `CF-RAY`、数据中心过滤数量；如果读取响应失败很高，说明 TCP 可连但 HTTP 探测未成功，不会再被直接当作有效 IP。
2. 暂时去掉 `-colo`，确认不是数据中心过滤过严。
3. 放宽延迟限制，例如 `-delay=300` 或更高。
4. 日常使用保持默认 `-random=true`；只有需要完整扫描时才使用 `-random=false`。
5. 提高扫描并发，例如 `-task=200`。
6. 网络直连 Cloudflare 不稳定时，尝试 `-baidu-proxy=true`。

---

## 资源占用说明

C 版的核心价值是降低常驻资源占用。

相较于 Go 版，C 版没有 Go 运行时、GC 和 goroutine 调度器的额外常驻成本，并在实现上做了更保守的资源控制：

- 双向转发缓冲区固定为 `16 KB`。
- 每个转发方向使用固定缓冲区。
- 连接线程使用较小栈空间。
- 候选结果只保留必要字段。
- 使用原生 `pthread` / Winsock / BSD socket。
- 健康检查逻辑固定频率执行，不引入复杂后台状态机。

更适合：

- OpenWrt / ImmortalWrt 路由器。
- 小内存 VPS。
- ARM 小板机。
- 需要长期驻留的网络中转环境。
- 连接数波动较大但希望内存可控的场景。

Go 版仍然适合快速开发、维护和功能扩展；C 版更适合资源受限和长期常驻。

---

## 常见问题

### 1. 为什么只监听一个端口，却能同时处理 TLS 和非 TLS？

程序读取客户端连接的首字节：

```text
0x16 → TLS
其他 → 非 TLS / HTTP
```

然后分别转发到 `-port` 和 `-http-port`。

### 2. `-choose` 参数去哪了？

当前三平台固定使用综合评分最低的候选 IP，不再暴露 `-choose` 参数。

这样可以减少参数复杂度，也避免三平台行为不一致。

### 3. 百度前置代理一定更快吗？

不一定。

它主要解决的是部分网络环境下直连 Cloudflare 不稳定的问题。是否更快取决于本机、前置节点、Cloudflare IP 三者之间的实际链路。

### 4. 运营商分池什么时候有必要启用？

当移动、电信、联通到 Cloudflare 或百度前置节点的路径差异明显时，分池更有意义。

如果你的用户来源单一，或者不同运营商表现差异不大，可以不启用。

### 5. C 版是不是功能一定比 Go 版强？

不是。

C 版的优势是低内存和更可控的运行时开销。Go 版在开发效率、可维护性和扩展速度上仍然更有优势。

### 6. 为什么编译能过，但运行时提示找不到 IP 文件？

C 源码运行时默认查找 `ips-v4.txt`、`ips-v6.txt` 和 `locations.json`。

请确认程序同目录下存在 `ips-v4.txt`、`ips-v6.txt`、`locations.json`，或允许程序联网自动下载。

---

## 免责声明

本工具仅用于网络测试与学习用途。

请在合法、合规的网络环境下使用。使用者需要自行承担因错误配置、滥用或违反当地法律法规造成的后果。
