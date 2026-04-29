# cfnat C 版

一个面向低内存环境的 Cloudflare IP 扫描 + 单端口 TCP 转发工具。

C 版是对 cf中转群主的[`cfnat.go`](cfnat.go) 的移植实现。核心目标是保留扫描、优选、转发和健康检查能力的同时，将内存占用降至 Go 版的约 5%，专为路由器、OpenWrt、小内存 VPS 等资源受限环境打造。

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [工作原理](#工作原理)
- [快速开始](#快速开始)
- [命令行参数](#命令行参数)
- [使用示例](#使用示例)
- [日志说明](#日志说明)
- [内存与资源占用](#内存与资源占用)
- [平台差异说明](#平台差异说明)
- [构建方式](#构建方式)
- [常见问题](#常见问题)
- [免责声明](#免责声明)

---

## 项目简介

cfnat C 版用于：

- 扫描 Cloudflare IP
- 按延迟筛选优质节点
- 通过 `CF-RAY` 识别数据中心
- 自动选择可用 IP
- 提供单端口 TCP 转发
- 自动识别 TLS / 非 TLS 流量并转发到不同目标端口
- 定时健康检查并在 IP 失效时自动切换

它不是 HTTP 反向代理，也不处理业务层协议，而是一个更轻量的 TCP 中转器。

---

## 核心特性

- 支持 IPv4 / IPv6 参数入口（C 版实际优先 IPv4）
- 支持按 Cloudflare 数据中心筛选，例如 `HKG`、`SJC`、`LAX`
- 自动按 TCP 延迟排序
- 自动健康检查 + 失效切换
- 单端口同时承接 TLS / 非 TLS 流量
- 自动协议识别，无需手工拆分监听端口
- Linux / macOS / Windows 三平台实现
- 小线程栈设计，减少每连接内存占用
- 低日志噪音，支持 `-verbose` 与 `-log-conn` 调试
- 适合路由器和小内存机器长期运行

---

## 工作原理

cfnat C 版的目标很简单：**本地只监听一个端口，但同时接收 TLS 和非 TLS 流量，并自动转发到合适的 Cloudflare 目标端口。**

### 整体链路

```text
客户端
  ↓
本地监听端口（-addr，例如 0.0.0.0:40000）
  ↓
cfnat 自动识别连接类型
  ↓
Cloudflare 优选 IP
```

### 单端口分流逻辑

客户端只需要连接同一个本地端口，例如：

```text
服务器IP:40000
```

程序接收连接后，会先读取客户端首字节：

```text
首字节是 0x16  → 认为是 TLS 流量
其他情况       → 认为是非 TLS / HTTP 流量
```

然后分别转发到不同的 Cloudflare 目标端口：

```text
TLS 流量
  客户端 → 本地端口 → cfnat → Cloudflare IP:443

非 TLS / HTTP 流量
  客户端 → 本地端口 → cfnat → Cloudflare IP:80
```

### IP 扫描与筛选流程

#### 1. 获取 IP 段

程序优先读取本地文件：

```text
ips-v4.txt
ips-v6.txt
locations.json
```

如果缺失，会自动下载。

#### 2. 生成待测 IP

根据 `-random` 决定扫描方式：

```text
-random=true   从每个 CIDR 随机抽取 IP
-random=false  将 CIDR 展开后逐个测试
```

#### 3. TCP 连通性测试

对待测 IP 先连接 `80` 端口，记录 TCP 建连耗时，作为基础延迟。

#### 4. 识别数据中心

向目标 IP 发送 HTTP 请求，从响应头提取：

```text
CF-RAY
```

例如：

```text
xxxx-HKG
xxxx-SJC
xxxx-LAX
```

程序会读取后缀机房代码，并结合 `locations.json` 映射地区和城市信息。

#### 5. 按 `-colo` 过滤

如果指定：

```bash
-colo=HKG,SJC,LAX
```

则只保留匹配机房的结果。

#### 6. 按延迟排序

有效结果会按照 TCP 延迟从低到高排序，并只保留前 `-ipnum` 个候选。

#### 7. 健康检查

候选 IP 还会通过目标 TLS 端口做存活检查，只有通过检查的 IP 才会成为当前转发 IP。

#### 8. 自动切换

运行期间每 10 秒检查一次当前 IP，连续失败两次就切换到下一个可用候选。

### 数据转发方式

cfnat C 版不会解密 TLS，也不会篡改 HTTP 内容。

它只做 TCP 字节转发：

```text
客户端发什么字节 → cfnat 原样转发给 Cloudflare IP
Cloudflare 返回什么字节 → cfnat 原样返回给客户端
```

所以它本质上是轻量级 TCP relay，不是七层代理。

---

## 快速开始

### Linux

```bash
gcc -O2 -pthread -o cfnat-linux ./cfnat_linux.c
./cfnat-linux -addr=0.0.0.0:40000 -colo=HKG -delay=50 -random=false
```

### macOS

```bash
clang -O2 -pthread -o cfnat-macos ./cfnat_macos.c
./cfnat-macos -addr=0.0.0.0:40000 -colo=HKG -delay=50 -random=false
```

### Windows（MinGW-w64）

```bash
gcc -O2 -o cfnat.exe ./cfnat_windows.c -lws2_32 -lwinpthread -static
cfnat.exe -addr=0.0.0.0:40000 -colo=HKG -delay=50 -random=false
```

访问方式：

```text
服务器IP:40000
```

---

## 命令行参数

| 参数          | 说明                         | 默认值                         |
| ------------- | ---------------------------- | ------------------------------ |
| `-addr`       | 本地监听地址                 | `0.0.0.0:1234`                 |
| `-code`       | HTTP/HTTPS 期望状态码        | `200`                          |
| `-colo`       | 数据中心筛选，多个用逗号分隔 | 空                             |
| `-delay`      | 有效延迟阈值，单位毫秒       | `300`                          |
| `-domain`     | 健康检查目标域名/路径        | `cloudflaremirrors.com/debian` |
| `-ipnum`      | 保留候选 IP 数量             | `20`                           |
| `-ips`        | 选择 IPv4 或 IPv6            | `4`                            |
| `-num`        | 每个连接的目标连接尝试次数   | `5`                            |
| `-port`       | TLS 转发目标端口             | `443`                          |
| `-http-port`  | 非 TLS 转发目标端口          | `80`                           |
| `-random`     | 是否随机生成 IP              | `true`                         |
| `-task`       | 扫描线程数                   | `100`                          |
| `-health-log` | 健康检查成功日志间隔秒数     | `60`                           |
| `-verbose`    | 详细调试日志                 | `false`                        |
| `-log-conn`   | 连接日志                     | `false`                        |

---

## 使用示例

### 1. 扫描香港机房并监听单端口

```bash
./cfnat-linux -addr=0.0.0.0:40000 -colo=HKG -delay=80 -random=false
```

### 2. 同时接受多个地区

```bash
./cfnat-linux -addr=0.0.0.0:40000 -colo=HKG,SJC,LAX -delay=120
```

### 3. 打开详细日志排查

```bash
./cfnat-linux -verbose=true -log-conn=true
```

### 4. 提高候选池规模

```bash
./cfnat-linux -ipnum=50 -task=200
```

---

## 日志说明

### 正常输出

```text
可用 IP: 104.18.x.x (健康检查端口:443)
状态检查成功: 当前 IP 104.18.x.x 可用
```

### 异常输出

```text
状态检查失败 (1/2): 当前 IP 104.18.x.x 暂不可用
连续两次状态检查失败，切换到下一个 IP
切换到新的有效 IP: 104.18.x.x 更新 IP 索引: 3
```

### 没扫到结果

```text
未发现有效IP，可尝试放宽 -delay 或开启 -verbose=true 查看细节
```

---

## 内存与资源占用

这部分才是 C 版真正该看的，不然你移植它干什么。

### 结论

**C 版内存占用约为 Go 版的 5%。**

也可以换个更直白的说法：

- Go 版更适合快速开发、维护和扩展
- C 版更适合把资源压到极低，尤其是常驻运行场景

### 为什么 C 版更省内存

相较于 [`cfnat.go`](cfnat.go)，C 版没有 Go 运行时、GC 和 goroutine 调度器的额外常驻成本，同时在实现上做了更保守的资源控制：

- 双向转发缓冲区固定为 `16 KB`，定义见 [`COPY_BUF_SIZE`](cfnat_linux.c:28)
- 每个转发方向使用固定栈上缓冲，而不是动态分配对象池
- 连接线程显式设置为 `64 KB` 小栈，见 [`create_small_thread()`](cfnat_linux.c:127)
- 候选结果只保留必要字段，不引入更重的数据结构
- 采用原生 `pthread` / Winsock / BSD socket，减少运行时抽象层
- 健康检查逻辑直接、固定频率，不引入复杂状态机或额外后台组件

### 适用场景

如果你的设备属于下面这些情况，C 版比 Go 版更像正解：

- OpenWrt / ImmortalWrt 路由器
- 小内存 VPS
- ARM 小板机
- 需要长期驻留、连接数波动较大的网络中转环境

如果你机器内存富余，只是为了“看起来更底层”，那不是需求，那是情绪。

---

## 平台差异说明

### Linux

- 源文件：[`cfnat_linux.c`](cfnat_linux.c)
- 使用 `pthread` + POSIX socket
- 忽略 `SIGPIPE`，避免对端关闭时进程被信号打断

### macOS

- 源文件：[`cfnat_macos.c`](cfnat_macos.c)
- 同样基于 `pthread` + BSD socket
- 用自定义大小写查找函数替代部分 GNU 扩展接口，兼容更稳

### Windows

- 源文件：[`cfnat_windows.c`](cfnat_windows.c)
- 基于 Winsock2
- 需要先执行 `WSAStartup`
- 下载远程文件时通过 PowerShell 完成
- 构建时通常需要 `-lws2_32 -lwinpthread -static`

### 当前实现取舍

C 版保留了 Go 版的核心行为，但不是逐行等价复刻。当前重点是：

- 扫描
- 机房识别
- 延迟排序
- 自动选 IP
- 健康检查
- 单端口转发
- 低内存运行

这才是有价值的部分。其余细枝末节，如果会显著抬高内存和复杂度，就没必要强行搬过去。

---

## 构建方式

- `cfnat_linux.c`：Linux 版本。使用 pthread 和 POSIX socket。
- `cfnat_windows.c`：Windows 7+ 版本。使用 Winsock2 和 MinGW-w64 winpthread。
- `cfnat_macos.c`：适用于 amd64 和 arm64 的 macOS 版本。
- `build-all.yml`：用于 Linux、Windows 和 macOS 发布制品的 GitHub Actions 工作流。

仓库放置位置：

```text
cfnat.c
cfnat_windows.c
cfnat_macos.c
.github/workflows/build-all.yml
```

Windows 构建说明：

- 目标系统：通过 `_WIN32_WINNT=0x0601` 支持 Windows 7 或更高版本。
- 编译器：MinGW-w64。
- 链接库：`-lws2_32 -lwinpthread -static`。

macOS 构建说明：

- amd64 最低目标：macOS 10.13。
- arm64 最低目标：macOS 11.0，因为 Apple Silicon 从此版本开始支持。
- macOS 不像 Linux 那样支持完全静态的 libc 二进制文件。

### Linux

```bash
gcc -O2 -pthread -o cfnat-linux ./cfnat_linux.c
```

### macOS

```bash
clang -O2 -pthread -o cfnat-macos ./cfnat_macos.c
```

### Windows（MinGW-w64）

```bash
gcc -O2 -o cfnat.exe ./cfnat_windows.c -lws2_32 -lwinpthread -static
```

仓库内现有文件：

```text
cfnat.go
cfnat_linux.c
cfnat_macos.c
cfnat_windows.c
README-build.md
README.md
```

---

## 常见问题

### 1. 提示没有可用 IP

可以按下面顺序排查：

- 放宽 `-delay`
- 更换 `-colo`
- 提高 `-task`
- 使用 `-random=false` 全量测试
- 开启 `-verbose=true` 观察失败阶段

### 2. 为什么只监听一个端口却能同时处理 TLS 和非 TLS？

因为程序只看客户端首字节：

- `0x16` 认为是 TLS
- 其他流量按非 TLS 处理

然后分别转发到 `-port` 和 `-http-port`。

### 3. C 版是不是功能一定比 Go 版强？

不是。C 版的价值不是“功能更多”，而是“同类核心能力下更省内存”。

### 4. 为什么说 C 版更适合路由器？

因为这种设备最缺的通常不是 CPU，而是稳定可控的内存占用。

---

## 免责声明

本工具仅用于网络测试与学习用途。

请在合法、合规的环境下使用。
