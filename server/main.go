// HTTP/2 隧道代理 - 服务端
//
// 功能：接收客户端的 HTTP/2 连接请求，根据协议类型将数据转发到目标 TCP、UDP 服务器，
// 或通过 TUN 虚拟网络接口实现 IP 层互联互通。
//
// 数据流向：
//   TCP 模式: 客户端 HTTP/2 stream ↔ 服务端 ↔ 目标 TCP 连接
//   UDP 模式: 客户端 HTTP/2 stream ↔ 服务端(帧封装/解封) ↔ 目标 UDP 端点
//   TUN 模式: 客户端 TUN ↔ HTTP/2 stream ↔ 服务端 TUN（IP 层点对点隧道）
//
// 协议设计：
//   - 客户端通过 POST /tunnel 发起 TCP/UDP 隧道请求
//   - 客户端通过 POST /tun 发起 TUN IP 隧道请求
//   - X-Target 头指定目标地址 (host:port)
//   - X-Protocol 头指定协议类型（"tcp" 或 "udp"，默认 "tcp"）
//   - X-Token 头用于可选的认证令牌校验
//   - X-TUN-IP 头指定客户端 TUN 接口 IP（仅 TUN 模式）
//   - TCP 模式：请求体/响应体直接承载字节流
//   - UDP/TUN 模式：请求体/响应体使用帧封装 [2字节长度][数据报/IP包]
//   - 利用 HTTP/2 多路复用，多条隧道共享单个 TLS 连接

package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"http2tunnel/tun"

	"golang.org/x/net/http2"
)

// ==================== 性能调优常量 ====================

const (
	// copyBufSize 是 io.CopyBuffer 使用的缓冲区大小。
	// 默认 io.Copy 使用 32KB，对于隧道大流量场景太小，增大到 256KB
	// 可以减少系统调用次数，提升吞吐量。
	copyBufSize = 256 * 1024

	// maxFrameSize 是 HTTP/2 SETTINGS_MAX_FRAME_SIZE。
	// 默认 16KB 对于隧道场景太小，帧头开销比例过高。
	// 增大到 1MB 减少帧数量，降低协议开销。
	maxFrameSize = 1 << 20 // 1MB

	// flowControlWindow 是 HTTP/2 流控窗口大小。
	// 默认 64KB 严重限制高延迟网络下的吞吐量（吞吐量 ≈ 窗口大小 / RTT）。
	// 增大到 16MB 可大幅提升长距离传输性能。
	flowControlWindow = 16 << 20 // 16MB

	// tcpBufSize 是目标 TCP socket 的读写缓冲区大小。
	tcpBufSize = 4 * 1024 * 1024 // 4MB

	// udpReadBufSize 是 UDP 读取缓冲区大小。
	udpReadBufSize = 65535
)

// bufPool 是 io.CopyBuffer 使用的缓冲区池，避免每次传输都分配新内存。
var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, copyBufSize)
		return &buf
	},
}

// udpBufPool 是 UDP 数据报读取缓冲区池。
var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, udpReadBufSize)
		return &buf
	},
}

// ServerConfig 服务端配置结构体，对应 JSON 配置文件
type ServerConfig struct {
	Addr        string `json:"addr"`         // 监听地址，如 ":8443"
	Cert        string `json:"cert"`         // TLS 证书文件路径
	Key         string `json:"key"`          // TLS 私钥文件路径
	Token       string `json:"token"`        // 认证令牌
	DialTimeout string `json:"dial_timeout"` // 连接超时时间，如 "10s"、"30s"

	// TUN 隧道配置
	TunEnabled bool   `json:"tun_enabled"` // 是否启用 TUN 隧道功能
	TunIP      string `json:"tun_ip"`      // TUN 接口 IP 地址（CIDR 格式），如 "10.0.0.1/24"
	TunName    string `json:"tun_name"`    // TUN 接口名称（留空自动分配）
	TunMTU     int    `json:"tun_mtu"`     // TUN 接口 MTU，默认 1400
}

// loadConfig 从 JSON 配置文件加载配置，若文件不存在则返回空配置（使用默认值）
func loadConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[配置] 配置文件 %s 不存在，使用默认值", path)
			return &ServerConfig{}, nil
		}
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	log.Printf("[配置] 已加载配置文件: %s", path)
	return &cfg, nil
}

// flushWriter 包装 http.ResponseWriter，每次 Write 后自动调用 Flush，
// 确保 HTTP/2 DATA 帧及时发送，不会因缓冲导致数据延迟。
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.f.Flush()
	}
	return n, err
}

// setTCPSocketOptions 设置目标 TCP 连接的性能优化参数
func setTCPSocketOptions(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)                     // 禁用 Nagle 算法，降低延迟
		tc.SetReadBuffer(tcpBufSize)            // 增大内核读缓冲区
		tc.SetWriteBuffer(tcpBufSize)           // 增大内核写缓冲区
		tc.SetKeepAlive(true)                   // 启用 TCP Keep-Alive
		tc.SetKeepAlivePeriod(30 * time.Second) // 30秒发送一次探测
	}
}

// copyBuffered 使用缓冲池的 io.CopyBuffer，减少内存分配和 GC 压力
func copyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	return io.CopyBuffer(dst, src, *bufp)
}

// activeConns 记录当前活跃的隧道连接数，用于状态监控
var activeConns int64

// ==================== TUN 隧道管理 ====================

// tunClient 表示一个已连接的 TUN 客户端
type tunClient struct {
	writer *flushWriter
	mu     sync.Mutex
	closed bool
}

// tunManager 管理服务端 TUN 设备和客户端路由
type tunManager struct {
	dev     *tun.Device
	mu      sync.RWMutex
	clients map[string]*tunClient // 客户端 IP → 连接
}

func newTUNManager(dev *tun.Device) *tunManager {
	return &tunManager{
		dev:     dev,
		clients: make(map[string]*tunClient),
	}
}

// register 将客户端加入路由表
func (m *tunManager) register(ip string, client *tunClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[ip] = client
	log.Printf("[TUN] 注册客户端: %s (当前客户端数: %d)", ip, len(m.clients))
}

// unregister 从路由表移除客户端
func (m *tunManager) unregister(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[ip]; ok {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		delete(m.clients, ip)
	}
	log.Printf("[TUN] 注销客户端: %s (当前客户端数: %d)", ip, len(m.clients))
}

// readLoop 持续从 TUN 设备读取 IP 包，根据目的 IP 路由到对应客户端
//
// IP 包路由逻辑：
//   - 解析 IP 包头获取目的 IP 地址
//   - 在路由表中查找对应客户端
//   - 帧封装后通过 HTTP/2 响应体发送给客户端
func (m *tunManager) readLoop() {
	buf := make([]byte, m.dev.MTU+100)
	frameBuf := make([]byte, 2+m.dev.MTU+100)
	for {
		n, err := m.dev.Read(buf)
		if err != nil {
			log.Printf("[TUN] 读取设备错误: %v", err)
			return
		}
		if n < 1 {
			continue
		}

		// 从 IP 包头解析目的地址
		version := buf[0] >> 4
		var destIP string
		switch version {
		case 4:
			if n < 20 {
				continue
			}
			destIP = net.IP(buf[16:20]).String()
		case 6:
			if n < 40 {
				continue
			}
			destIP = net.IP(buf[24:40]).String()
		default:
			continue
		}

		m.mu.RLock()
		client, ok := m.clients[destIP]
		m.mu.RUnlock()
		if !ok {
			continue
		}

		// 帧封装：[2字节长度][IP包]
		binary.BigEndian.PutUint16(frameBuf[:2], uint16(n))
		copy(frameBuf[2:], buf[:n])

		client.mu.Lock()
		if !client.closed {
			if _, err := client.writer.Write(frameBuf[:2+n]); err != nil {
				log.Printf("[TUN] 发送到客户端 %s 错误: %v", destIP, err)
			}
		}
		client.mu.Unlock()
	}
}

// handleTUNTunnel 处理 TUN 隧道请求
//
// 协议：
//   - 客户端通过 X-TUN-IP 头注册自己的 TUN IP
//   - 请求体承载客户端→服务端的帧封装 IP 包
//   - 响应体承载服务端→客户端的帧封装 IP 包
//   - 帧格式与 UDP 模式相同：[2字节大端序长度][IP包]
func handleTUNTunnel(w http.ResponseWriter, r *http.Request, token string, mgr *tunManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 认证校验
	if token != "" {
		if r.Header.Get("X-Token") != token {
			log.Printf("[TUN] 认证失败: %s", r.RemoteAddr)
			http.Error(w, "认证失败", http.StatusForbidden)
			return
		}
	}

	// 获取客户端 TUN IP
	clientIP := r.Header.Get("X-TUN-IP")
	if clientIP == "" {
		http.Error(w, "缺少 X-TUN-IP 头", http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		http.Error(w, "X-TUN-IP 格式错误", http.StatusBadRequest)
		return
	}

	// 验证客户端 IP 在服务端 TUN 子网范围内
	if !mgr.dev.Net.Contains(ip) {
		http.Error(w, fmt.Sprintf("客户端 IP %s 不在 TUN 子网 %s 内", clientIP, mgr.dev.Net.String()), http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("[TUN] ResponseWriter 不支持 Flusher")
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	client := &tunClient{
		writer: &flushWriter{w: w, f: flusher},
	}

	mgr.register(clientIP, client)
	defer mgr.unregister(clientIP)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[TUN] 客户端已连接: %s (来源: %s, 活跃: %d)", clientIP, r.RemoteAddr, current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[TUN] 客户端已断开: %s (来源: %s, 活跃: %d)", clientIP, r.RemoteAddr, cur)
	}()

	// 读取客户端发来的帧封装 IP 包，写入本地 TUN 设备
	lenBuf := make([]byte, 2)
	pktBuf := make([]byte, mgr.dev.MTU+100)
	var totalBytes int64
	for {
		if _, err := io.ReadFull(r.Body, lenBuf); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Printf("[TUN] 读客户端帧头错误 (%s): %v", clientIP, err)
			}
			break
		}
		pktLen := binary.BigEndian.Uint16(lenBuf)
		if pktLen == 0 {
			continue
		}
		if int(pktLen) > len(pktBuf) {
			log.Printf("[TUN] IP 包过大: %d 字节 (客户端: %s, MTU: %d)", pktLen, clientIP, mgr.dev.MTU)
			// 跳过超大包
			if _, err := io.CopyN(io.Discard, r.Body, int64(pktLen)); err != nil {
				break
			}
			continue
		}
		if _, err := io.ReadFull(r.Body, pktBuf[:pktLen]); err != nil {
			log.Printf("[TUN] 读客户端数据错误 (%s): %v", clientIP, err)
			break
		}
		if _, err := mgr.dev.Write(pktBuf[:pktLen]); err != nil {
			log.Printf("[TUN] 写 TUN 设备错误: %v", err)
			break
		}
		totalBytes += int64(pktLen)
	}
	log.Printf("[TUN] 客户端→TUN: %d 字节 (%s)", totalBytes, clientIP)
}

func main() {
	// ========== 命令行参数 ==========
	configFile := flag.String("config", "server_config.json", "配置文件路径")
	flagAddr := flag.String("addr", "", "服务端监听地址")
	flagCert := flag.String("cert", "", "TLS 证书文件路径")
	flagKey := flag.String("key", "", "TLS 私钥文件路径")
	flagToken := flag.String("token", "", "认证令牌（留空则不启用认证）")
	flagDialTimeout := flag.String("dial-timeout", "", "连接目标服务器的超时时间（如 10s、30s）")

	// TUN 隧道参数
	flagTunEnabled := flag.Bool("tun", false, "启用 TUN 隧道功能")
	flagTunIP := flag.String("tun-ip", "", "TUN 接口 IP 地址（CIDR 格式，如 10.0.0.1/24）")
	flagTunName := flag.String("tun-name", "", "TUN 接口名称（留空自动分配）")
	flagTunMTU := flag.Int("tun-mtu", 0, "TUN 接口 MTU（默认 1400）")

	flag.Parse()

	// ========== 加载配置文件 ==========
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("[致命] %v", err)
	}

	// ========== 合并参数（命令行 > 配置文件 > 默认值） ==========
	addr := mergeString(*flagAddr, cfg.Addr, ":8443")
	certFile := mergeString(*flagCert, cfg.Cert, "cert.pem")
	keyFile := mergeString(*flagKey, cfg.Key, "key.pem")
	token := mergeString(*flagToken, cfg.Token, "")
	dialTimeoutStr := mergeString(*flagDialTimeout, cfg.DialTimeout, "10s")

	dialTimeout, err := time.ParseDuration(dialTimeoutStr)
	if err != nil {
		log.Fatalf("[致命] 解析连接超时时间失败 %q: %v", dialTimeoutStr, err)
	}

	// TUN 参数合并
	tunEnabled := *flagTunEnabled || cfg.TunEnabled
	tunIP := mergeString(*flagTunIP, cfg.TunIP, "10.0.0.1/24")
	tunName := mergeString(*flagTunName, cfg.TunName, "")
	tunMTU := cfg.TunMTU
	if *flagTunMTU > 0 {
		tunMTU = *flagTunMTU
	}
	if tunMTU <= 0 {
		tunMTU = tun.DefaultMTU
	}

	// 检查证书文件是否存在
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatalf("[致命] 证书文件不存在: %s\n请使用以下命令生成自签名证书:\n"+
			"  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 "+
			"-keyout key.pem -out cert.pem -days 365 -nodes -subj \"/CN=http2tunnel\"", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("[致命] 私钥文件不存在: %s", keyFile)
	}

	mux := http.NewServeMux()

	// /tunnel - TCP/UDP 隧道请求处理端点
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		handleTunnel(w, r, token, dialTimeout)
	})

	// /status - 健康检查和状态监控端点
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tunStatus := "disabled"
		if tunEnabled {
			tunStatus = "enabled"
		}
		fmt.Fprintf(w, `{"status":"ok","active_connections":%d,"protocol":"%s","tun":"%s"}`,
			atomic.LoadInt64(&activeConns), r.Proto, tunStatus)
	})

	// ========== TUN 隧道设置 ==========
	if tunEnabled {
		tunDev, err := tun.CreateTUN(tunName, tunIP, tunMTU)
		if err != nil {
			log.Fatalf("[致命] 创建 TUN 接口失败: %v", err)
		}
		defer tunDev.Close()

		mgr := newTUNManager(tunDev)
		go mgr.readLoop()

		// /tun - TUN IP 隧道端点
		mux.HandleFunc("/tun", func(w http.ResponseWriter, r *http.Request) {
			handleTUNTunnel(w, r, token, mgr)
		})

		log.Printf("[TUN] 接口已创建: %s (IP: %s, MTU: %d)", tunDev.Name(), tunIP, tunMTU)
	}

	// ========== 配置 TLS ==========
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// 优先使用高性能密码套件（AES-GCM 硬件加速 > ChaCha20）
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		// 优先使用 X25519 密钥交换（比 P-256 更快）
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	// ========== 配置 HTTP/2 服务器 ==========
	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
		// 长连接隧道不设读写超时，避免中断活跃隧道
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       300 * time.Second,
	}

	// 显式配置 HTTP/2，使用优化后的参数
	h2srv := &http2.Server{
		MaxConcurrentStreams:         1000,              // 单连接最大并发 stream 数
		MaxReadFrameSize:             maxFrameSize,      // 增大帧大小，减少帧数量
		MaxUploadBufferPerConnection: flowControlWindow, // 连接级流控窗口 16MB
		MaxUploadBufferPerStream:     flowControlWindow, // 流级流控窗口 16MB
		IdleTimeout:                  300 * time.Second, // 空闲超时
	}
	if err := http2.ConfigureServer(server, h2srv); err != nil {
		log.Fatalf("[致命] 配置 HTTP/2 失败: %v", err)
	}

	log.Printf("[启动] HTTP/2 隧道服务端（性能优化版）")
	log.Printf("[配置] 配置文件: %s", *configFile)
	log.Printf("[配置] 监听地址: %s", addr)
	log.Printf("[配置] 证书文件: %s", certFile)
	log.Printf("[配置] 私钥文件: %s", keyFile)
	log.Printf("[配置] 连接超时: %s", dialTimeout)
	log.Printf("[性能] HTTP/2 帧大小: %d KB", maxFrameSize/1024)
	log.Printf("[性能] HTTP/2 流控窗口: %d MB", flowControlWindow/(1<<20))
	log.Printf("[性能] 传输缓冲区: %d KB", copyBufSize/1024)
	log.Printf("[性能] TCP Socket 缓冲区: %d MB", tcpBufSize/(1<<20))
	if token != "" {
		log.Printf("[配置] 认证令牌: 已启用")
	} else {
		log.Printf("[配置] 认证令牌: 未启用")
	}
	if tunEnabled {
		log.Printf("[TUN] 隧道功能: 已启用 (IP: %s, MTU: %d)", tunIP, tunMTU)
	} else {
		log.Printf("[TUN] 隧道功能: 未启用")
	}

	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("[致命] 服务启动失败: %v", err)
	}
}

// mergeString 按优先级合并配置：命令行参数 > 配置文件 > 默认值
func mergeString(flagVal, cfgVal, defaultVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if cfgVal != "" {
		return cfgVal
	}
	return defaultVal
}

// handleTunnel 处理单个隧道请求，根据 X-Protocol 头分发到 TCP 或 UDP 处理逻辑
func handleTunnel(w http.ResponseWriter, r *http.Request, token string, dialTimeout time.Duration) {
	// 仅允许 POST 方法（用于承载请求体数据流）
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 认证校验
	if token != "" {
		if r.Header.Get("X-Token") != token {
			log.Printf("[拒绝] 认证失败: %s", r.RemoteAddr)
			http.Error(w, "认证失败", http.StatusForbidden)
			return
		}
	}

	// 获取目标地址
	target := r.Header.Get("X-Target")
	if target == "" {
		http.Error(w, "缺少 X-Target 头", http.StatusBadRequest)
		return
	}

	// 检查目标地址格式（必须包含 host:port）
	if _, _, err := net.SplitHostPort(target); err != nil {
		http.Error(w, "X-Target 格式错误，需要 host:port", http.StatusBadRequest)
		return
	}

	// 确保 ResponseWriter 支持 Flusher 接口（HTTP/2 必须支持）
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("[错误] ResponseWriter 不支持 Flusher 接口")
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
		return
	}

	// 根据 X-Protocol 头选择协议处理路径
	protocol := r.Header.Get("X-Protocol")
	if protocol == "udp" {
		handleUDPTunnel(w, r, flusher, target, dialTimeout)
	} else {
		handleTCPTunnel(w, r, flusher, target, dialTimeout)
	}
}

// handleTCPTunnel 处理 TCP 隧道请求
func handleTCPTunnel(w http.ResponseWriter, r *http.Request, flusher http.Flusher, target string, dialTimeout time.Duration) {
	log.Printf("[连接] TCP 隧道请求: %s → %s (协议: %s)", r.RemoteAddr, target, r.Proto)

	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("[错误] 连接目标失败 %s: %v", target, err)
		http.Error(w, fmt.Sprintf("连接目标失败: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// 设置目标 TCP 连接的性能参数
	setTCPSocketOptions(targetConn)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[隧道] TCP 已建立: %s ↔ %s (活跃连接: %d)", r.RemoteAddr, target, current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[断开] TCP 隧道关闭: %s ↔ %s (活跃连接: %d)", r.RemoteAddr, target, cur)
	}()

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 → 目标（使用 256KB 缓冲区池）
	go func() {
		defer wg.Done()
		n, err := copyBuffered(targetConn, r.Body)
		if err != nil {
			log.Printf("[数据] 客户端→目标 TCP 传输错误 (%s → %s): %v", r.RemoteAddr, target, err)
		}
		log.Printf("[数据] 客户端→目标 TCP: %d 字节 (%s → %s)", n, r.RemoteAddr, target)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// 目标 → 客户端（使用 256KB 缓冲区池 + flushWriter）
	go func() {
		defer wg.Done()
		fw := &flushWriter{w: w, f: flusher}
		n, err := copyBuffered(fw, targetConn)
		if err != nil {
			log.Printf("[数据] 目标→客户端 TCP 传输错误 (%s ← %s): %v", r.RemoteAddr, target, err)
		}
		log.Printf("[数据] 目标→客户端 TCP: %d 字节 (%s ← %s)", n, r.RemoteAddr, target)
	}()

	wg.Wait()
}

// handleUDPTunnel 处理 UDP 隧道请求
func handleUDPTunnel(w http.ResponseWriter, r *http.Request, flusher http.Flusher, target string, dialTimeout time.Duration) {
	log.Printf("[连接] UDP 隧道请求: %s → %s (协议: %s)", r.RemoteAddr, target, r.Proto)

	// 解析目标地址
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Printf("[错误] 解析 UDP 地址失败 %s: %v", target, err)
		http.Error(w, fmt.Sprintf("解析 UDP 地址失败: %v", err), http.StatusBadGateway)
		return
	}

	// 建立到目标的 UDP "连接"（绑定目标地址，后续 Read/Write 自动关联）
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("[错误] 连接 UDP 目标失败 %s: %v", target, err)
		http.Error(w, fmt.Sprintf("连接 UDP 目标失败: %v", err), http.StatusBadGateway)
		return
	}
	defer udpConn.Close()

	// 增大 UDP socket 缓冲区
	udpConn.SetReadBuffer(4 * 1024 * 1024)
	udpConn.SetWriteBuffer(4 * 1024 * 1024)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[隧道] UDP 已建立: %s ↔ %s (活跃连接: %d)", r.RemoteAddr, target, current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[断开] UDP 隧道关闭: %s ↔ %s (活跃连接: %d)", r.RemoteAddr, target, cur)
	}()

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var wg sync.WaitGroup
	wg.Add(2)

	// 方向1: 客户端 → 目标 UDP
	go func() {
		defer wg.Done()
		var totalBytes int64
		lenBuf := make([]byte, 2)
		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		pktBuf := *bufp
		for {
			if _, err := io.ReadFull(r.Body, lenBuf); err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					log.Printf("[数据] 客户端→目标 UDP 读帧头错误 (%s → %s): %v", r.RemoteAddr, target, err)
				}
				break
			}
			pktLen := binary.BigEndian.Uint16(lenBuf)
			if pktLen == 0 {
				continue
			}

			if _, err := io.ReadFull(r.Body, pktBuf[:pktLen]); err != nil {
				log.Printf("[数据] 客户端→目标 UDP 读数据报错误 (%s → %s): %v", r.RemoteAddr, target, err)
				break
			}

			if _, err := udpConn.Write(pktBuf[:pktLen]); err != nil {
				log.Printf("[数据] 客户端→目标 UDP 发送错误 (%s → %s): %v", r.RemoteAddr, target, err)
				break
			}
			totalBytes += int64(pktLen)
		}
		log.Printf("[数据] 客户端→目标 UDP: %d 字节 (%s → %s)", totalBytes, r.RemoteAddr, target)
	}()

	// 方向2: 目标 UDP → 客户端
	go func() {
		defer wg.Done()
		fw := &flushWriter{w: w, f: flusher}
		var totalBytes int64
		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		buf := *bufp
		for {
			n, err := udpConn.Read(buf[2:])
			if err != nil {
				log.Printf("[数据] 目标→客户端 UDP 接收错误 (%s ← %s): %v", r.RemoteAddr, target, err)
				break
			}

			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			if _, err := fw.Write(buf[:2+n]); err != nil {
				log.Printf("[数据] 目标→客户端 UDP 写帧错误 (%s ← %s): %v", r.RemoteAddr, target, err)
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[数据] 目标→客户端 UDP: %d 字节 (%s ← %s)", totalBytes, r.RemoteAddr, target)
	}()

	wg.Wait()
}
