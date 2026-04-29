package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	timeout     = 1 * time.Second // 超时时间
	maxDuration = 2 * time.Second // 最大持续时间
)

var (
	activeConnections int32 // 用于跟踪活跃连接的数量
	randomMu          sync.Mutex
	randomGenerator   = rand.New(rand.NewSource(time.Now().UnixNano()))
	verboseLog        bool
	connLog           bool
	copyBufferPool    = sync.Pool{New: func() interface{} { b := make([]byte, 32*1024); return &b }}
)

var (
	ipsV4URLs = []string{
		"https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/ips-v4",
		"https://raw.githubusercontent.com/fscarmen/cfnat/main/ips-v4",
	}
	ipsV6URLs = []string{
		"https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/ips-v6",
		"https://raw.githubusercontent.com/fscarmen/cfnat/main/ips-v6",
	}
	locationsURLs = []string{
		"https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/locations",
		"https://raw.githubusercontent.com/fscarmen/cfnat/main/locations",
	}
)

func debugf(format string, v ...interface{}) {
	if verboseLog {
		log.Printf(format, v...)
	}
}

func connf(format string, v ...interface{}) {
	if connLog || verboseLog {
		log.Printf(format, v...)
	}
}

// IPManager 用于安全管理 IP 地址状态
type IPManager struct {
	mu            sync.RWMutex
	currentIP     string
	ipAddresses   []string
	currentIndex  int
	allIPsChecked bool
}

func NewIPManager() *IPManager {
	return &IPManager{}
}

func (m *IPManager) SetIPAddresses(ips []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAddresses = ips
	m.currentIndex = 0
	m.allIPsChecked = false
}

func (m *IPManager) GetCurrentIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentIP
}

func (m *IPManager) SetCurrentIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentIP = ip
}

func (m *IPManager) GetIPAddresses() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ipAddresses
}

func (m *IPManager) IsAllIPsChecked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allIPsChecked
}

func (m *IPManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAddresses = []string{}
	m.currentIP = ""
	m.currentIndex = 0
	m.allIPsChecked = false
}

func (m *IPManager) switchToNextValidIP(tlsPort int, domain string, code int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 尝试从当前索引的下一个 IP 开始检查
	for i := m.currentIndex + 1; i < len(m.ipAddresses); i++ {
		ip := m.ipAddresses[i]

		// 跳过当前 IP
		if ip == m.currentIP {
			continue
		}

		if checkTLSIP(ip, tlsPort, domain, code) {
			m.currentIP = ip
			m.currentIndex = i
			m.allIPsChecked = false
			log.Printf("切换到新的有效 IP: %s 更新 IP 索引: %d", m.currentIP, m.currentIndex)
			return true
		}
	}

	m.allIPsChecked = true
	log.Println("所有 IP 都已检查过，程序将退出")
	return false
}

type result struct {
	ip          string        // IP地址
	dataCenter  string        // 数据中心
	region      string        // 地区
	city        string        // 城市
	latency     string        // 延迟
	tcpDuration time.Duration // TCP请求延迟
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

func main() {
	localAddr := flag.String("addr", "0.0.0.0:1234", "本地监听的 IP 和端口")
	code := flag.Int("code", 200, "HTTP/HTTPS 响应状态码")
	coloFilter := flag.String("colo", "", "筛选数据中心例如 HKG,SJC,LAX (多个数据中心用逗号隔开,留空则忽略匹配)")
	Delay := flag.Int("delay", 300, "有效延迟（毫秒），超过此延迟将断开连接")
	domain := flag.String("domain", "cloudflaremirrors.com/debian", "响应状态码检查的域名地址")
	ipCount := flag.Int("ipnum", 20, "提取的有效IP数量")
	ipsType := flag.String("ips", "4", "指定生成IPv4还是IPv6地址 (4或6)")
	num := flag.Int("num", 5, "目标负载 IP 数量")
	port := flag.Int("port", 443, "TLS 转发的目标端口")
	httpPort := flag.Int("http-port", 80, "非 TLS/HTTP 转发的目标端口")
	random := flag.Bool("random", true, "是否随机生成IP，如果为false，则从CIDR中拆分出所有IP")
	maxThreads := flag.Int("task", 100, "并发请求最大协程数")
	healthLogInterval := flag.Int("health-log", 60, "健康检查成功日志间隔（秒），0 表示不打印成功日志")
	verbose := flag.Bool("verbose", false, "打印详细调试日志，包括每个 IP 的检查过程和每条候选连接")
	logConn := flag.Bool("log-conn", false, "打印每个客户端连接的建立、协议识别和关闭日志")
	_ = flag.Bool("tls", true, "兼容旧参数，当前版本会自动识别 TLS/非 TLS 流量")

	flag.Parse()
	verboseLog = *verbose
	connLog = *logConn
	debug.SetGCPercent(75)

	// 创建 IP 管理器
	ipManager := NewIPManager()

	// 启动 TCP 监听
	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("无法监听 %s: %v", *localAddr, err)
	}
	defer listener.Close()

	log.Printf("正在监听 %s，TLS目标端口：%d，非TLS目标端口：%d，负载连接数：%d，有效延迟：%d ms", *localAddr, *port, *httpPort, *num, *Delay)

	for {
		startTime := time.Now()

		// 使用函数处理 locations.json，确保 defer 正确执行
		locations, err := loadLocations()
		if err != nil {
			log.Printf("加载位置信息失败: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		locationMap := make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}

		var filename string
		var downloadURLs []string

		// 使用 switch 替代 if-else
		switch *ipsType {
		case "6":
			filename = "ips-v6.txt"
			downloadURLs = ipsV6URLs
		case "4":
			filename = "ips-v4.txt"
			downloadURLs = ipsV4URLs
		default:
			fmt.Println("无效的IP类型。请使用 '4' 或 '6'")
			return
		}

		var content string

		// 检查本地是否有文件
		if _, err = os.Stat(filename); os.IsNotExist(err) {
			fmt.Printf("文件 %s 不存在，正在下载数据\n", filename)
			content, err = getURLContentFromList(downloadURLs)
			if err != nil {
				fmt.Println("获取URL内容出错:", err)
				return
			}
			err = saveToFile(filename, content)
			if err != nil {
				fmt.Println("保存文件出错:", err)
				return
			}
		} else {
			content, err = getFileContent(filename)
			if err != nil {
				fmt.Println("读取本地文件出错:", err)
				return
			}
		}

		var ipList []string
		if *random {
			ipList = parseIPList(content)
			switch *ipsType {
			case "6":
				ipList = getRandomIPv6s(ipList)
			case "4":
				ipList = getRandomIPv4s(ipList)
			}
		} else {
			ipList, err = readIPs(filename)
			if err != nil {
				fmt.Println("读取IP出错:", err)
				return
			}
		}

		// 从生成的 IP 列表进行处理
		results := scanIPs(ipList, locationMap, *maxThreads)

		if len(results) == 0 {
			fmt.Println("未发现有效IP")
			time.Sleep(3 * time.Second)
			continue
		}

		// 应用数据中心筛选
		if *coloFilter != "" {
			filters := strings.Split(*coloFilter, ",")
			var filteredResults []result
			for _, r := range results {
				for _, filter := range filters {
					if strings.EqualFold(r.dataCenter, filter) {
						filteredResults = append(filteredResults, r)
						break
					}
				}
			}
			results = filteredResults
		}

		// 按 TCP 延迟排序
		sort.Slice(results, func(i, j int) bool {
			return results[i].tcpDuration < results[j].tcpDuration
		})

		// 只显示指定数量的 IP
		if len(results) > *ipCount {
			results = results[:*ipCount]
		}

		fmt.Println("IP 地址 | 数据中心 | 地区 | 城市 | 延迟")
		for _, r := range results {
			fmt.Printf("%s | %s | %s | %s | %s\n", r.ip, r.dataCenter, r.region, r.city, r.latency)
		}

		fmt.Printf("成功提取 %d 个有效IP，耗时 %d秒\n", len(results), time.Since(startTime)/time.Second)

		// 设置 IP 地址列表
		var ips []string
		for _, r := range results {
			ips = append(ips, r.ip)
		}
		ipManager.SetIPAddresses(ips)

		// 选择一个有效 IP
		currentIP := selectValidIP(ipManager, *port, *domain, *code)
		if currentIP == "" {
			log.Printf("没有有效的 IP 可用")
			continue
		}
		ipManager.SetCurrentIP(currentIP)

		// 创建用于控制 goroutine 退出的 context
		ctx, cancel := context.WithCancel(context.Background())

		// 用于状态检查完成的信号
		done := make(chan bool)

		var loopWG sync.WaitGroup
		loopWG.Add(2)

		// 启动状态检查线程
		go func() {
			defer loopWG.Done()
			statusCheck(ctx, *port, done, *domain, *code, ipManager, time.Duration(*healthLogInterval)*time.Second)
		}()

		// 主循环，接收连接
		go func() {
			defer loopWG.Done()
			for {
				select {
				case <-ctx.Done():
					log.Println("连接接受 goroutine 收到退出信号")
					return
				default:
					// 设置接受连接的超时，以便能够检查 context
					if tcpListener, ok := listener.(*net.TCPListener); ok {
						tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
					}
					conn, err := listener.Accept()
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
							return
						}
						log.Printf("接受连接时发生错误: %v", err)
						continue
					}

					clientAddr := conn.RemoteAddr().String()
					atomic.AddInt32(&activeConnections, 1)
					connf("客户端来源: %s 连接建立，当前活跃连接数: %d", clientAddr, atomic.LoadInt32(&activeConnections))

					currIP := ipManager.GetCurrentIP()
					go handleConnection(conn, currIP, *port, *httpPort, *num, time.Duration(*Delay)*time.Millisecond)
				}
			}
		}()

		<-done
		cancel() // 取消 context，通知所有 goroutine 退出
		loopWG.Wait()

		// 清空 IP 地址
		ipManager.Clear()
		log.Println("主函数将退出当前循环，因为所有 IP 都已用尽")
	}
}

// loadLocations 加载位置信息，使用函数封装确保 defer 正确执行
func loadLocations() ([]location, error) {
	var locations []location

	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("本地 locations.json 不存在，正在下载 locations.json")
		body, err := getURLBytesFromList(locationsURLs)
		if err != nil {
			return nil, fmt.Errorf("无法从URL中获取JSON: %v", err)
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			return nil, fmt.Errorf("无法解析JSON: %v", err)
		}

		file, err := os.Create("locations.json")
		if err != nil {
			return nil, fmt.Errorf("无法创建文件: %v", err)
		}
		defer file.Close()

		_, err = file.Write(body)
		if err != nil {
			return nil, fmt.Errorf("无法写入文件: %v", err)
		}
	} else {
		file, err := os.Open("locations.json")
		if err != nil {
			return nil, fmt.Errorf("无法打开文件: %v", err)
		}
		defer file.Close()

		body, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("无法读取文件: %v", err)
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			return nil, fmt.Errorf("无法解析JSON: %v", err)
		}
	}

	return locations, nil
}

// scanIPs 扫描 IP 列表并返回结果
func scanIPs(ipList []string, locationMap map[string]location, maxThreads int) []result {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []result

	thread := make(chan struct{}, maxThreads)

	var count int32
	total := len(ipList)

	for _, ip := range ipList {
		wg.Add(1)
		thread <- struct{}{}
		go func(ipAddr string) {
			defer func() {
				<-thread
				wg.Done()
				current := atomic.AddInt32(&count, 1)
				percentage := float64(current) / float64(total) * 100
				fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\r", current, total, percentage)
				if int(current) == total {
					fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\n", current, total, percentage)
				}
			}()

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ipAddr, "80"))
			if err != nil {
				return
			}
			defer conn.Close()

			tcpDuration := time.Since(start)

			// 通过根路径响应头里的 CF-RAY 提取机房信息
			requestURL := "http://" + net.JoinHostPort(ipAddr, "80")
			req, err := http.NewRequest("GET", requestURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true

			conn.SetDeadline(time.Now().Add(maxDuration))
			err = req.Write(conn)
			if err != nil {
				return
			}

			reader := bufio.NewReader(conn)
			resp, err := http.ReadResponse(reader, req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			cfRay := strings.TrimSpace(resp.Header.Get("CF-RAY"))
			if cfRay == "" {
				return
			}

			parts := strings.Split(cfRay, "-")
			if len(parts) < 2 {
				return
			}

			dataCenter := strings.TrimSpace(parts[len(parts)-1])
			if dataCenter == "" {
				return
			}

			loc, ok := locationMap[dataCenter]
			mu.Lock()
			if ok {
				debugf("发现有效IP %s 位置信息 %s 延迟 %d 毫秒", ipAddr, loc.City, tcpDuration.Milliseconds())
				results = append(results, result{ipAddr, dataCenter, loc.Region, loc.City, fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration})
			} else {
				debugf("发现有效IP %s 位置信息未知 延迟 %d 毫秒", ipAddr, tcpDuration.Milliseconds())
				results = append(results, result{ipAddr, dataCenter, "", "", fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration})
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// 获取URL内容
func getURLContent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}

	var content strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			content.WriteString(line + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return content.String(), nil
}

func getURLContentFromList(urls []string) (string, error) {
	var lastErr error
	for _, url := range urls {
		content, err := getURLContent(url)
		if err == nil {
			return content, nil
		}
		lastErr = err
		log.Printf("从 %s 下载失败: %v", url, err)
	}
	return "", lastErr
}

func getURLBytesFromList(urls []string) ([]byte, error) {
	var lastErr error
	for _, url := range urls {
		body, err := getURLBytes(url)
		if err == nil {
			return body, nil
		}
		lastErr = err
		log.Printf("从 %s 下载失败: %v", url, err)
	}
	return nil, lastErr
}

func getURLBytes(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// 从本地文件读取内容
func getFileContent(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 将内容保存到本地文件
func saveToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

// 解析IP列表，跳过空行
func parseIPList(content string) []string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var ipList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ipList = append(ipList, line)
		}
	}
	return ipList
}

func nextRandomIntn(n int) int {
	randomMu.Lock()
	defer randomMu.Unlock()
	return randomGenerator.Intn(n)
}

// 从每个/24子网随机提取一个IPv4
func getRandomIPv4s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		// 跳过空行
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		baseIP := strings.TrimSuffix(subnet, "/24")
		octets := strings.Split(baseIP, ".")
		if len(octets) >= 4 {
			octets[3] = fmt.Sprintf("%d", nextRandomIntn(256))
			randomIP := strings.Join(octets, ".")
			randomIPs = append(randomIPs, randomIP)
		}
	}
	return randomIPs
}

// 从每个/48子网随机提取一个IPv6
func getRandomIPv6s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		// 跳过空行
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		baseIP := strings.TrimSuffix(subnet, "/48")
		sections := strings.Split(baseIP, ":")
		if len(sections) >= 3 {
			sections = sections[:3]
			for i := 3; i < 8; i++ {
				sections = append(sections, fmt.Sprintf("%x", nextRandomIntn(65536)))
			}
			randomIP := strings.Join(sections, ":")
			randomIPs = append(randomIPs, randomIP)
		}
	}
	return randomIPs
}

// 从CIDR中拆分出所有IP
func readIPs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行
		if line == "" {
			continue
		}
		if strings.Contains(line, "/") {
			ipAddr, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				return nil, err
			}
			// 使用新变量避免遮蔽
			for currentIP := ipAddr.Mask(ipNet.Mask); ipNet.Contains(currentIP); incrementIP(currentIP) {
				ips = append(ips, currentIP.String())
			}
		} else {
			ips = append(ips, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

// 增加IP
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func formatTarget(ip string, port int) string {
	return net.JoinHostPort(ip, fmt.Sprintf("%d", port))
}

func splitDomainPath(domain string) (string, string) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	if domain == "" {
		return "cloudflaremirrors.com", "/"
	}
	parts := strings.SplitN(domain, "/", 2)
	host := parts[0]
	path := "/"
	if len(parts) == 2 && parts[1] != "" {
		path = "/" + parts[1]
	}
	return host, path
}

func checkValidIP(ip string, port int, useTLS bool, domain string, code int) bool {
	host, path := splitDomainPath(domain)
	address := ip
	if strings.Contains(ip, ":") {
		address = fmt.Sprintf("[%s]", ip)
	}

	scheme := "http"
	name := "非 TLS"
	if useTLS {
		scheme = "https"
		name = "TLS"
	}

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			debugf("尝试 %s 连接 IP: %s 端口: %d Host: %s", name, ip, port, host)
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			return dialer.DialContext(ctx, network, fmt.Sprintf("%s:%d", address, port))
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	targetURL := fmt.Sprintf("%s://%s%s", scheme, host, path)
	debugf("开始 %s 检查 IP: %s 端口: %d URL: %s", name, ip, port, targetURL)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		debugf("创建 %s 检查请求失败: %v", name, err)
		return false
	}
	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		debugf("%s 检查 IP %s 时发生错误: %v", name, ip, err)
		return false
	}
	defer resp.Body.Close()

	debugf("IP %s %s 检查响应状态码: %d", ip, name, resp.StatusCode)
	if resp.StatusCode != code {
		debugf("IP %s 未通过 %s 检查，期望状态码: %d，实际状态码: %d", ip, name, code, resp.StatusCode)
		return false
	}
	debugf("IP %s 通过 %s 检查", ip, name)
	return true
}

func checkTLSIP(ip string, tlsPort int, domain string, code int) bool {
	debugf("开始 TLS 检查 IP: %s TLS端口: %d", ip, tlsPort)
	if !checkValidIP(ip, tlsPort, true, domain, code) {
		debugf("IP %s 未通过 TLS 检查", ip)
		return false
	}
	log.Printf("可用 IP: %s (健康检查端口:%d)", ip, tlsPort)
	return true
}

func selectValidIP(ipManager *IPManager, tlsPort int, domain string, code int) string {
	for _, ip := range ipManager.GetIPAddresses() {
		if checkTLSIP(ip, tlsPort, domain, code) {
			return ip
		}
	}
	return ""
}

func statusCheck(ctx context.Context, tlsPort int, done chan bool, domain string, code int, ipManager *IPManager, healthLogInterval time.Duration) {
	failCount := 0
	lastSuccessLog := time.Time{}
	for {
		select {
		case <-ctx.Done():
			log.Println("状态检查收到退出信号")
			return
		case <-time.After(10 * time.Second):
		}

		currentIP := ipManager.GetCurrentIP()
		if currentIP == "" {
			failCount++
			log.Printf("状态检查失败 (%d/2): 当前 IP 为空", failCount)
		} else if checkTLSIP(currentIP, tlsPort, domain, code) {
			wasFailing := failCount > 0
			failCount = 0
			if wasFailing || (healthLogInterval > 0 && time.Since(lastSuccessLog) >= healthLogInterval) {
				log.Printf("状态检查成功: 当前 IP %s 可用", currentIP)
				lastSuccessLog = time.Now()
			}
		} else {
			failCount++
			log.Printf("状态检查失败 (%d/2): 当前 IP %s 暂不可用", failCount, currentIP)
		}

		if failCount >= 2 {
			log.Println("连续两次状态检查失败，切换到下一个 IP")
			if !ipManager.switchToNextValidIP(tlsPort, domain, code) {
				log.Println("所有 IP 都已检查过，状态检查停止")
				done <- true
				return
			}
			failCount = 0
		}
	}
}

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func sniffFirstByte(conn net.Conn, delay time.Duration) ([]byte, bool, error) {
	first := make([]byte, 1)
	readTimeout := 2 * time.Second
	if delay > readTimeout {
		readTimeout = delay
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	n, err := conn.Read(first)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, false, err
	}
	if n == 0 {
		return nil, false, io.EOF
	}
	return first[:n], first[0] == 0x16, nil
}

// 处理客户端连接，自动识别 TLS/非 TLS，并转发到对应 Cloudflare 端口
func handleConnection(conn net.Conn, ip string, tlsPort int, httpPort int, num int, delay time.Duration) {
	defer func() {
		clientAddr := conn.RemoteAddr().String()
		atomic.AddInt32(&activeConnections, -1)
		connf("客户端来源: %s 连接关闭，当前活跃连接数: %d", clientAddr, atomic.LoadInt32(&activeConnections))
		conn.Close()
	}()

	first, isTLS, err := sniffFirstByte(conn, delay)
	if err != nil {
		log.Printf("读取客户端首字节失败，关闭连接: %v", err)
		return
	}

	targetPort := httpPort
	protocolName := "非 TLS"
	if isTLS {
		targetPort = tlsPort
		protocolName = "TLS"
	}
	connf("识别客户端协议: %s，转发到 IP: %s 端口: %d", protocolName, ip, targetPort)

	clientConn := &prefixedConn{Conn: conn, prefix: first}
	targetAddr := formatTarget(ip, targetPort)

	type connResult struct {
		conn  net.Conn
		delay time.Duration
		err   error
	}

	results := make(chan connResult, num)
	for i := 0; i < num; i++ {
		go func() {
			start := time.Now()
			forwardConn, err := net.DialTimeout("tcp", targetAddr, delay)
			results <- connResult{conn: forwardConn, delay: time.Since(start), err: err}
		}()
	}

	var bestConn net.Conn
	var bestDelay time.Duration
	for i := 0; i < num; i++ {
		res := <-results
		if res.err != nil || res.conn == nil {
			debugf("连接到 %s 超时或失败: %v", targetAddr, res.err)
			continue
		}

		if verboseLog {
			log.Printf("候选连接: %s 延迟: %d ms", targetAddr, res.delay.Milliseconds())
		}

		if bestConn == nil || res.delay < bestDelay {
			if bestConn != nil {
				bestConn.Close()
			}
			bestConn = res.conn
			bestDelay = res.delay
		} else {
			res.conn.Close()
		}
	}

	if bestConn != nil {
		connf("选择最佳连接: 地址: %s 延迟: %d ms", targetAddr, bestDelay.Milliseconds())
		pipeConnections(clientConn, bestConn)
	} else {
		debugf("未找到符合延迟要求的连接，关闭客户端连接")
	}
}

func pipeWithPool(dst, src net.Conn) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)
	_, _ = io.CopyBuffer(dst, src, *bufPtr)
}

func pipeConnections(src, dst net.Conn) {
	var wg sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			src.Close()
			dst.Close()
		})
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		pipeWithPool(src, dst)
		closeBoth()
	}()

	go func() {
		defer wg.Done()
		pipeWithPool(dst, src)
		closeBoth()
	}()

	wg.Wait()
}
