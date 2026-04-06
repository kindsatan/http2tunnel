// HTTP/2 隧道代理 - 服务端
//
// 功能：接收客户端的 HTTP/2 连接请求，根据协议类型将数据转发到目标 TCP 或 UDP 服务器。
//
// 数据流向：
//   TCP 模式: 客户端 HTTP/2 stream ↔ 服务端 ↔ 目标 TCP 连接
//   UDP 模式: 客户端 HTTP/2 stream ↔ 服务端(帧封装/解封) ↔ 目标 UDP 端点
//
// 协议设计：
//   - 客户端通过 POST /tunnel 发起隧道请求
//   - X-Target 头指定目标地址 (host:port)
//   - X-Protocol 头指定协议类型（"tcp" 或 "udp"，默认 "tcp"）
//   - X-Token 头用于可选的认证令牌校验
//   - TCP 模式：请求体/响应体直接承载字节流
//   - UDP 模式：请求体/响应体使用帧封装 [2字节长度][数据报]
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

	"golang.org/x/net/http2"
)

// ServerConfig 服务端配置结构体，对应 JSON 配置文件
type ServerConfig struct {
	Addr        string `json:"addr"`         // 监听地址，如 ":8443"
	Cert        string `json:"cert"`         // TLS 证书文件路径
	Key         string `json:"key"`          // TLS 私钥文件路径
	Token       string `json:"token"`        // 认证令牌
	DialTimeout string `json:"dial_timeout"` // 连接超时时间，如 "10s"、"30s"
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

// activeConns 记录当前活跃的隧道连接数，用于状态监控
var activeConns int64

func main() {
	// ========== 命令行参数 ==========
	configFile := flag.String("config", "server_config.json", "配置文件路径")
	flagAddr := flag.String("addr", "", "服务端监听地址")
	flagCert := flag.String("cert", "", "TLS 证书文件路径")
	flagKey := flag.String("key", "", "TLS 私钥文件路径")
	flagToken := flag.String("token", "", "认证令牌（留空则不启用认证）")
	flagDialTimeout := flag.String("dial-timeout", "", "连接目标服务器的超时时间（如 10s、30s）")
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

	// /tunnel - 隧道请求处理端点
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		handleTunnel(w, r, token, dialTimeout)
	})

	// /status - 健康检查和状态监控端点
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","active_connections":%d,"protocol":"%s"}`,
			atomic.LoadInt64(&activeConns), r.Proto)
	})

	// ========== 配置 HTTP/2 服务器 ==========
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		// 长连接隧道不设读写超时，避免中断活跃隧道
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       300 * time.Second,
	}

	// 显式配置 HTTP/2，确保 HTTP/2 协议栈完整启用
	if err := http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams: 1000, // 单连接最大并发 stream 数
	}); err != nil {
		log.Fatalf("[致命] 配置 HTTP/2 失败: %v", err)
	}

	log.Printf("[启动] HTTP/2 隧道服务端")
	log.Printf("[配置] 配置文件: %s", *configFile)
	log.Printf("[配置] 监听地址: %s", addr)
	log.Printf("[配置] 证书文件: %s", certFile)
	log.Printf("[配置] 私钥文件: %s", keyFile)
	log.Printf("[配置] 连接超时: %s", dialTimeout)
	if token != "" {
		log.Printf("[配置] 认证令牌: 已启用")
	} else {
		log.Printf("[配置] 认证令牌: 未启用")
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
//
// 流程：
//  1. 建立到目标的 TCP 连接
//  2. 发送 200 响应，开始双向字节流转发
//  3. 等待任一方向的数据传输完成后关闭隧道
func handleTCPTunnel(w http.ResponseWriter, r *http.Request, flusher http.Flusher, target string, dialTimeout time.Duration) {
	log.Printf("[连接] TCP 隧道请求: %s → %s (协议: %s)", r.RemoteAddr, target, r.Proto)

	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("[错误] 连接目标失败 %s: %v", target, err)
		http.Error(w, fmt.Sprintf("连接目标失败: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

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

	// 客户端 → 目标
	go func() {
		defer wg.Done()
		n, err := io.Copy(targetConn, r.Body)
		if err != nil {
			log.Printf("[数据] 客户端→目标 TCP 传输错误 (%s → %s): %v", r.RemoteAddr, target, err)
		}
		log.Printf("[数据] 客户端→目标 TCP: %d 字节 (%s → %s)", n, r.RemoteAddr, target)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// 目标 → 客户端
	go func() {
		defer wg.Done()
		fw := &flushWriter{w: w, f: flusher}
		n, err := io.Copy(fw, targetConn)
		if err != nil {
			log.Printf("[数据] 目标→客户端 TCP 传输错误 (%s ← %s): %v", r.RemoteAddr, target, err)
		}
		log.Printf("[数据] 目标→客户端 TCP: %d 字节 (%s ← %s)", n, r.RemoteAddr, target)
	}()

	wg.Wait()
}

// handleUDPTunnel 处理 UDP 隧道请求
//
// UDP 数据报通过 HTTP/2 字节流传输时，使用长度前缀帧封装以保留包边界：
//
//	+----------+-------------------+
//	| LEN (2B) | UDP 数据报 (LEN B) |
//	+----------+-------------------+
//	  大端序      最大 65535 字节
//
// 流程：
//  1. 建立到目标的 UDP 连接
//  2. 发送 200 响应，开始双向帧封装/解封转发
//  3. 任一方向结束后清理资源
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
	// 从 HTTP/2 请求体读取帧封装的 UDP 数据报，解封后发送到目标
	go func() {
		defer wg.Done()
		var totalBytes int64
		lenBuf := make([]byte, 2)
		for {
			// 读取 2 字节长度前缀
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

			// 读取数据报内容
			pkt := make([]byte, pktLen)
			if _, err := io.ReadFull(r.Body, pkt); err != nil {
				log.Printf("[数据] 客户端→目标 UDP 读数据报错误 (%s → %s): %v", r.RemoteAddr, target, err)
				break
			}

			// 发送到目标 UDP 端点
			if _, err := udpConn.Write(pkt); err != nil {
				log.Printf("[数据] 客户端→目标 UDP 发送错误 (%s → %s): %v", r.RemoteAddr, target, err)
				break
			}
			totalBytes += int64(pktLen)
		}
		log.Printf("[数据] 客户端→目标 UDP: %d 字节 (%s → %s)", totalBytes, r.RemoteAddr, target)
	}()

	// 方向2: 目标 UDP → 客户端
	// 从目标读取 UDP 数据报，帧封装后通过 HTTP/2 响应体发送给客户端
	go func() {
		defer wg.Done()
		fw := &flushWriter{w: w, f: flusher}
		var totalBytes int64
		buf := make([]byte, 65535)
		lenBuf := make([]byte, 2)
		for {
			// 从目标 UDP 端点读取数据报
			n, err := udpConn.Read(buf)
			if err != nil {
				log.Printf("[数据] 目标→客户端 UDP 接收错误 (%s ← %s): %v", r.RemoteAddr, target, err)
				break
			}

			// 写入 2 字节长度前缀
			binary.BigEndian.PutUint16(lenBuf, uint16(n))
			if _, err := fw.Write(lenBuf); err != nil {
				log.Printf("[数据] 目标→客户端 UDP 写帧头错误 (%s ← %s): %v", r.RemoteAddr, target, err)
				break
			}

			// 写入数据报内容
			if _, err := fw.Write(buf[:n]); err != nil {
				log.Printf("[数据] 目标→客户端 UDP 写数据报错误 (%s ← %s): %v", r.RemoteAddr, target, err)
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[数据] 目标→客户端 UDP: %d 字节 (%s ← %s)", totalBytes, r.RemoteAddr, target)
	}()

	wg.Wait()
}
