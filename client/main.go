// HTTP/2 隧道代理 - 客户端（多模式 + 多传输）
//
// 支持四种工作模式：
//
// 模式1 - TCP 固定目标转发（-target + 默认）：
//   将本地 TCP 端口的所有连接直接转发到固定目标地址。
//
// 模式2 - UDP 固定目标转发（-target + -udp）：
//   将本地 UDP 端口的数据报通过隧道转发到目标 UDP 端点。
//
// 模式3 - SOCKS5 代理（不指定 -target）：
//   在本地提供 SOCKS5 代理服务，由浏览器动态指定目标地址。
//
// 模式4 - TUN IP 隧道（-tun）：
//   创建本地 TUN 虚拟网络接口，实现 IP 层点对点连接。
//
// 支持三种传输方式（-transport 参数）：
//
//   http2（默认）- HTTP/2 over TLS：
//     加密传输，协议兼容性好，有 TLS + HTTP/2 帧开销
//     -server 使用 URL 格式：https://host:port
//
//   tcp - TCP 明文传输：
//     无加密，最低开销，支持所有隧道模式
//     -server 使用地址格式：host:port
//
//   udp - UDP 明文传输：
//     无加密，无队头阻塞，仅支持 UDP 转发和 TUN 模式
//     -server 使用地址格式：host:port

package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"http2tunnel/tun"

	"golang.org/x/net/http2"
)

// ==================== 性能调优常量 ====================

const (
	// copyBufSize 是 io.CopyBuffer 使用的缓冲区大小（256KB）。
	// 默认 io.Copy 使用 32KB，增大到 256KB 减少系统调用次数。
	copyBufSize = 256 * 1024

	// maxFrameSize 是客户端 HTTP/2 SETTINGS_MAX_FRAME_SIZE（1MB）。
	// 默认 16KB 太小，增大帧大小可减少帧头开销。
	maxFrameSize = 1 << 20

	// flowControlWindow 是 HTTP/2 初始流控窗口大小（16MB）。
	// 默认 64KB 在高延迟网络下严重限制吞吐量。
	flowControlWindow = 16 << 20

	// udpReadBufSize 是 UDP 读取缓冲区大小。
	udpReadBufSize = 65535
)

// bufPool 是用于 io.CopyBuffer 的缓冲区池。
var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, copyBufSize)
		return &buf
	},
}

// udpBufPool 是 UDP 数据报读取缓冲区池。
var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, udpReadBufSize+2) // +2 给帧头预留
		return &buf
	},
}

// copyBuffered 使用缓冲池的 io.CopyBuffer
func copyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	return io.CopyBuffer(dst, src, *bufp)
}

// ==================== SOCKS5 协议常量 ====================

const (
	socks5Version = 0x05

	// 认证方式
	authNone         = 0x00 // 无需认证
	authUserPass     = 0x02 // 用户名/密码认证
	authNoAcceptable = 0xFF // 无可接受的认证方式

	// 用户名密码认证子协议版本 (RFC 1929)
	authUserPassVersion = 0x01
	authStatusSuccess   = 0x00
	authStatusFailure   = 0x01

	// SOCKS5 命令
	cmdConnect = 0x01

	// 地址类型
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04

	// 响应状态码
	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repNotAllowed       = 0x02
	repNetworkUnreach   = 0x03
	repHostUnreach      = 0x04
	repConnRefused      = 0x05
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
)

// activeConns 记录当前活跃的隧道连接数
var activeConns int64

func main() {
	// ========== 命令行参数 ==========
	localAddr := flag.String("local", ":1080", "本地监听地址")
	serverURL := flag.String("server", "https://127.0.0.1:8443", "服务端地址 (HTTP/2: https://host:port, TCP/UDP: host:port)")
	target := flag.String("target", "", "固定目标地址 (host:port)，留空则启用 SOCKS5 模式")
	udpMode := flag.Bool("udp", false, "启用 UDP 转发模式（需配合 -target 使用）")
	token := flag.String("token", "", "服务端认证令牌")
	insecure := flag.Bool("insecure", false, "跳过 TLS 证书验证（仅 HTTP/2 传输，自签名证书时使用）")
	socksUser := flag.String("socks-user", "", "SOCKS5 用户名（仅 SOCKS5 模式，留空则不启用认证）")
	socksPass := flag.String("socks-pass", "", "SOCKS5 密码（仅 SOCKS5 模式）")
	transportType := flag.String("transport", "http2", "传输协议类型: http2, tcp, udp")

	// TUN 隧道参数
	tunMode := flag.Bool("tun", false, "启用 TUN 隧道模式")
	tunIP := flag.String("tun-ip", "10.0.0.2/24", "TUN 接口 IP 地址（CIDR 格式）")
	tunName := flag.String("tun-name", "", "TUN 接口名称（留空自动分配）")
	tunMTU := flag.Int("tun-mtu", tun.DefaultMTU, "TUN 接口 MTU")

	flag.Parse()

	// 参数校验
	if *tunMode {
		if *udpMode || *target != "" {
			log.Fatal("[致命] -tun 模式不能与 -udp 或 -target 同时使用")
		}
	} else {
		if *udpMode && *target == "" {
			log.Fatal("[致命] -udp 模式必须配合 -target 使用")
		}
		if *target != "" {
			if _, _, err := net.SplitHostPort(*target); err != nil {
				log.Fatalf("[致命] 目标地址格式错误: %v，需要 host:port 格式", err)
			}
		}
	}

	// 验证传输类型
	switch *transportType {
	case "http2", "tcp", "udp":
		// OK
	default:
		log.Fatalf("[致命] 不支持的传输类型: %s (可选: http2, tcp, udp)", *transportType)
	}

	// UDP 传输仅支持 UDP 转发和 TUN 模式
	if *transportType == "udp" {
		if !*tunMode && !*udpMode {
			log.Fatal("[致命] UDP 传输仅支持 -udp 转发模式和 -tun 隧道模式（TCP 流式数据需要可靠传输）")
		}
	}

	// ========== 根据传输类型和模式启动 ==========
	switch *transportType {
	case "http2":
		startHTTP2Transport(*localAddr, *serverURL, *target, *udpMode, *tunMode,
			*token, *insecure, *socksUser, *socksPass,
			*tunIP, *tunName, *tunMTU)
	case "tcp":
		startTCPTransport(*localAddr, *serverURL, *target, *udpMode, *tunMode,
			*token, *socksUser, *socksPass,
			*tunIP, *tunName, *tunMTU)
	case "udp":
		startUDPTransport(*localAddr, *serverURL, *target, *udpMode, *tunMode,
			*token, *tunIP, *tunName, *tunMTU)
	}
}

// ==================== HTTP/2 传输模式 ====================

func startHTTP2Transport(localAddr, serverURL, target string, udpMode, tunMode bool,
	token string, insecure bool, socksUser, socksPass string,
	tunIP, tunName string, tunMTU int) {

	// 配置 TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	// 配置 HTTP/2 传输层
	transport := &http2.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		MaxReadFrameSize:   maxFrameSize,
		AllowHTTP:          false,
		ReadIdleTimeout:    90 * time.Second,
		PingTimeout:        15 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
	}

	if tunMode {
		tunURL := serverURL + "/tun"
		startTUNMode(tunIP, tunName, tunMTU, client, tunURL, token, insecure)
	} else if udpMode {
		tunnelURL := serverURL + "/tunnel"
		startUDPMode(localAddr, client, tunnelURL, target, token, insecure)
	} else {
		tunnelURL := serverURL + "/tunnel"
		startTCPForwardMode(localAddr, client, tunnelURL, target, token, insecure, socksUser, socksPass)
	}
}

// ==================== TCP 明文传输模式 ====================

func startTCPTransport(localAddr, serverAddr, target string, udpMode, tunMode bool,
	token, socksUser, socksPass string,
	tunIP, tunName string, tunMTU int) {

	if tunMode {
		startTUNModeRawTCP(tunIP, tunName, tunMTU, serverAddr, token)
	} else if udpMode {
		startUDPModeRawTCP(localAddr, serverAddr, target, token)
	} else {
		startTCPForwardModeRawTCP(localAddr, serverAddr, target, token, socksUser, socksPass)
	}
}

// ==================== UDP 明文传输模式 ====================

func startUDPTransport(localAddr, serverAddr, target string, udpMode, tunMode bool,
	token string, tunIP, tunName string, tunMTU int) {

	if tunMode {
		startTUNModeRawUDP(tunIP, tunName, tunMTU, serverAddr, token)
	} else if udpMode {
		startUDPModeRawUDP(localAddr, serverAddr, target, token)
	}
	// TCP/SOCKS5 模式已在 main() 中排除
}

// ==================== TUN 隧道模式（HTTP/2 传输） ====================

// startTUNMode 启动 TUN IP 隧道模式（HTTP/2 传输）
func startTUNMode(tunIPCIDR, tunName string, tunMTU int, client *http.Client, tunURL, token string, insecure bool) {
	ip, _, err := net.ParseCIDR(tunIPCIDR)
	if err != nil {
		log.Fatalf("[致命] 解析 TUN IP 失败: %v", err)
	}

	tunDev, err := tun.CreateTUN(tunName, tunIPCIDR, tunMTU)
	if err != nil {
		log.Fatalf("[致命] 创建 TUN 接口失败: %v", err)
	}
	defer tunDev.Close()

	log.Printf("[启动] HTTP/2 隧道客户端 (TUN 隧道模式)")
	log.Printf("[TUN] 接口: %s (IP: %s, MTU: %d)", tunDev.Name(), tunIPCIDR, tunMTU)
	log.Printf("[配置] 服务端: %s", tunURL)
	log.Printf("[性能] HTTP/2 帧大小: %d KB, 流控窗口: %d MB",
		maxFrameSize/1024, flowControlWindow/(1<<20))
	if insecure {
		log.Printf("[警告] TLS 证书验证已禁用")
	}

	pr, pw := io.Pipe()

	req, err := http.NewRequest(http.MethodPost, tunURL, pr)
	if err != nil {
		log.Fatalf("[致命] 创建请求失败: %v", err)
	}
	req.Header.Set("X-TUN-IP", ip.String())
	if token != "" {
		req.Header.Set("X-Token", token)
	}

	type result struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		respCh <- result{resp, err}
	}()

	res := <-respCh
	if res.err != nil {
		pw.Close()
		log.Fatalf("[致命] 连接服务端失败: %v", res.err)
	}
	resp := res.resp
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		pw.Close()
		log.Fatalf("[致命] 服务端拒绝 TUN 隧道: %s", resp.Status)
	}

	log.Printf("[TUN] 隧道建立成功 (协议: %s)", resp.Proto)

	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 TUN → 帧封装 → HTTP/2 请求体 → 服务端
	go func() {
		defer wg.Done()
		defer pw.Close()
		buf := make([]byte, tunMTU+100)
		frameBuf := make([]byte, 2+tunMTU+100)
		var totalBytes int64
		for {
			n, err := tunDev.Read(buf)
			if err != nil {
				log.Printf("[TUN] 读取本地 TUN 错误: %v", err)
				break
			}
			binary.BigEndian.PutUint16(frameBuf[:2], uint16(n))
			copy(frameBuf[2:], buf[:n])
			if _, err := pw.Write(frameBuf[:2+n]); err != nil {
				log.Printf("[TUN] 写入 HTTP/2 失败: %v", err)
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[TUN] 本地→服务端: %d 字节", totalBytes)
	}()

	// 服务端 HTTP/2 响应体 → 帧解封 → 本地 TUN
	go func() {
		defer wg.Done()
		lenBuf := make([]byte, 2)
		pktBuf := make([]byte, tunMTU+100)
		var totalBytes int64
		for {
			if _, err := io.ReadFull(resp.Body, lenBuf); err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					log.Printf("[TUN] 读取服务端帧头错误: %v", err)
				}
				break
			}
			pktLen := binary.BigEndian.Uint16(lenBuf)
			if pktLen == 0 {
				continue
			}
			if int(pktLen) > len(pktBuf) {
				log.Printf("[TUN] IP 包过大: %d 字节 (MTU: %d)", pktLen, tunMTU)
				io.CopyN(io.Discard, resp.Body, int64(pktLen))
				continue
			}
			if _, err := io.ReadFull(resp.Body, pktBuf[:pktLen]); err != nil {
				log.Printf("[TUN] 读取服务端数据错误: %v", err)
				break
			}
			if _, err := tunDev.Write(pktBuf[:pktLen]); err != nil {
				log.Printf("[TUN] 写入本地 TUN 错误: %v", err)
				break
			}
			totalBytes += int64(pktLen)
		}
		log.Printf("[TUN] 服务端→本地: %d 字节", totalBytes)
		tunDev.Close()
	}()

	wg.Wait()
}

// ==================== TCP/SOCKS5 模式（HTTP/2 传输） ====================

// startTCPForwardMode 启动 TCP 监听（固定目标转发或 SOCKS5 模式）
func startTCPForwardMode(localAddr string, client *http.Client, tunnelURL, target, token string, insecure bool, socksUser, socksPass string) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("[致命] 本地端口监听失败: %v", err)
	}
	defer listener.Close()

	if target != "" {
		log.Printf("[启动] HTTP/2 隧道客户端 (TCP 固定目标转发模式)")
		log.Printf("[配置] 本地监听: %s", localAddr)
		log.Printf("[配置] 目标地址: %s", target)
	} else {
		log.Printf("[启动] HTTP/2 隧道客户端 (SOCKS5 模式)")
		log.Printf("[配置] SOCKS5 监听: %s", localAddr)
		if socksUser != "" {
			log.Printf("[配置] SOCKS5 认证: 已启用")
		}
	}
	log.Printf("[性能] HTTP/2 帧大小: %d KB, 流控窗口: %d MB, 缓冲区: %d KB",
		maxFrameSize/1024, flowControlWindow/(1<<20), copyBufSize/1024)
	if insecure {
		log.Printf("[警告] TLS 证书验证已禁用")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[错误] 接受连接失败: %v", err)
			continue
		}
		if target != "" {
			go handleForward(conn, client, tunnelURL, target, token)
		} else {
			go handleSocks5(conn, client, tunnelURL, token, socksUser, socksPass)
		}
	}
}

// ==================== UDP 转发模式（HTTP/2 传输） ====================

// startUDPMode 启动 UDP 监听并建立单条 HTTP/2 隧道转发所有 UDP 数据报
func startUDPMode(localAddr string, client *http.Client, tunnelURL, target, token string, insecure bool) {
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		log.Fatalf("[致命] 解析本地 UDP 地址失败: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("[致命] 本地 UDP 端口监听失败: %v", err)
	}
	defer udpConn.Close()

	udpConn.SetReadBuffer(4 * 1024 * 1024)
	udpConn.SetWriteBuffer(4 * 1024 * 1024)

	log.Printf("[启动] HTTP/2 隧道客户端 (UDP 转发模式)")
	log.Printf("[配置] 本地 UDP 监听: %s", localAddr)
	log.Printf("[配置] 目标地址: %s (UDP)", target)
	log.Printf("[性能] HTTP/2 帧大小: %d KB, 流控窗口: %d MB",
		maxFrameSize/1024, flowControlWindow/(1<<20))
	if insecure {
		log.Printf("[警告] TLS 证书验证已禁用")
	}

	pr, pw := io.Pipe()

	req, err := http.NewRequest(http.MethodPost, tunnelURL, pr)
	if err != nil {
		log.Fatalf("[致命] 创建请求失败: %v", err)
	}
	req.Header.Set("X-Target", target)
	req.Header.Set("X-Protocol", "udp")
	if token != "" {
		req.Header.Set("X-Token", token)
	}

	type result struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		respCh <- result{resp, err}
	}()

	res := <-respCh
	if res.err != nil {
		log.Fatalf("[致命] 连接服务端失败: %v", res.err)
	}
	resp := res.resp
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("[致命] 服务端拒绝 UDP 隧道: %s", resp.Status)
	}

	log.Printf("[隧道] UDP 隧道建立成功 (协议: %s)", resp.Proto)

	var peerAddr atomic.Value

	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 UDP → 帧封装 → HTTP/2 请求体 → 服务端
	go func() {
		defer wg.Done()
		defer pw.Close()
		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		buf := *bufp
		var totalBytes int64
		for {
			n, addr, err := udpConn.ReadFromUDP(buf[2:])
			if err != nil {
				log.Printf("[数据] 本地 UDP 读取错误: %v", err)
				break
			}
			peerAddr.Store(addr)

			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			if _, err := pw.Write(buf[:2+n]); err != nil {
				log.Printf("[数据] 写帧到 HTTP/2 失败: %v", err)
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[数据] 本地→服务端 UDP: %d 字节", totalBytes)
	}()

	// 服务端 HTTP/2 响应体 → 帧解封 → 本地 UDP
	go func() {
		defer wg.Done()
		lenBuf := make([]byte, 2)
		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		pktBuf := *bufp
		var totalBytes int64
		for {
			if _, err := io.ReadFull(resp.Body, lenBuf); err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					log.Printf("[数据] 从 HTTP/2 读帧头错误: %v", err)
				}
				break
			}
			pktLen := binary.BigEndian.Uint16(lenBuf)
			if pktLen == 0 {
				continue
			}

			if _, err := io.ReadFull(resp.Body, pktBuf[:pktLen]); err != nil {
				log.Printf("[数据] 从 HTTP/2 读数据报错误: %v", err)
				break
			}

			if addr, ok := peerAddr.Load().(*net.UDPAddr); ok && addr != nil {
				if _, err := udpConn.WriteToUDP(pktBuf[:pktLen], addr); err != nil {
					log.Printf("[数据] 发送 UDP 数据报到本地错误: %v", err)
					break
				}
			}
			totalBytes += int64(pktLen)
		}
		log.Printf("[数据] 服务端→本地 UDP: %d 字节", totalBytes)
		udpConn.Close()
	}()

	wg.Wait()
}

// ==================== TCP 转发处理（HTTP/2 传输） ====================

// handleForward 处理固定目标 TCP 转发模式的连接
func handleForward(conn net.Conn, client *http.Client, tunnelURL, target, token string) {
	defer conn.Close()

	connID := fmt.Sprintf("%s→%s", conn.RemoteAddr(), target)
	log.Printf("[连接] 新建: %s", connID)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[状态] 活跃连接: %d", current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[断开] %s (活跃连接: %d)", connID, cur)
	}()

	pr, pw := io.Pipe()

	req, err := http.NewRequest(http.MethodPost, tunnelURL, pr)
	if err != nil {
		log.Printf("[错误] 创建请求失败: %v", err)
		pw.Close()
		return
	}
	req.Header.Set("X-Target", target)
	if token != "" {
		req.Header.Set("X-Token", token)
	}

	type result struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		respCh <- result{resp, err}
	}()

	res := <-respCh
	if res.err != nil {
		log.Printf("[错误] 连接服务端失败: %v", res.err)
		pw.Close()
		return
	}
	resp := res.resp
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[错误] 服务端拒绝: %s (目标: %s)", resp.Status, target)
		pw.Close()
		return
	}

	log.Printf("[隧道] 建立成功: %s (协议: %s)", connID, resp.Proto)

	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 → 服务端
	go func() {
		defer wg.Done()
		n, err := copyBuffered(pw, conn)
		if err != nil {
			log.Printf("[数据] 本地→服务端 传输错误 (%s): %v", connID, err)
		}
		log.Printf("[数据] 本地→服务端: %d 字节 (%s)", n, connID)
		pw.Close()
	}()

	// 服务端 → 本地
	go func() {
		defer wg.Done()
		n, err := copyBuffered(conn, resp.Body)
		if err != nil {
			log.Printf("[数据] 服务端→本地 传输错误 (%s): %v", connID, err)
		}
		log.Printf("[数据] 服务端→本地: %d 字节 (%s)", n, connID)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// ==================== SOCKS5 处理（HTTP/2 传输） ====================

// handleSocks5 处理单个 SOCKS5 连接
func handleSocks5(conn net.Conn, client *http.Client, tunnelURL, token, socksUser, socksPass string) {
	defer conn.Close()

	target, err := socks5Handshake(conn, socksUser, socksPass)
	if err != nil {
		log.Printf("[SOCKS5] 握手失败 (%s): %v", conn.RemoteAddr(), err)
		return
	}

	connID := fmt.Sprintf("%s→%s", conn.RemoteAddr(), target)
	log.Printf("[SOCKS5] 请求连接: %s", connID)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[状态] 活跃连接: %d", current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[断开] %s (活跃连接: %d)", connID, cur)
	}()

	pr, pw := io.Pipe()

	req, err := http.NewRequest(http.MethodPost, tunnelURL, pr)
	if err != nil {
		log.Printf("[错误] 创建请求失败: %v", err)
		pw.Close()
		sendSocks5Reply(conn, repGeneralFailure, nil)
		return
	}
	req.Header.Set("X-Target", target)
	if token != "" {
		req.Header.Set("X-Token", token)
	}

	type result struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan result, 1)

	go func() {
		resp, err := client.Do(req)
		respCh <- result{resp, err}
	}()

	res := <-respCh
	if res.err != nil {
		log.Printf("[错误] 连接服务端失败: %v", res.err)
		pw.Close()
		sendSocks5Reply(conn, repHostUnreach, nil)
		return
	}
	resp := res.resp
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[错误] 服务端拒绝: %s (目标: %s)", resp.Status, target)
		pw.Close()
		sendSocks5Reply(conn, repConnRefused, nil)
		return
	}

	if err := sendSocks5Reply(conn, repSuccess, nil); err != nil {
		log.Printf("[错误] 发送 SOCKS5 响应失败: %v", err)
		pw.Close()
		return
	}

	log.Printf("[隧道] 建立成功: %s (协议: %s)", connID, resp.Proto)

	var wg sync.WaitGroup
	wg.Add(2)

	// 浏览器 → 服务端
	go func() {
		defer wg.Done()
		n, err := copyBuffered(pw, conn)
		if err != nil {
			log.Printf("[数据] 浏览器→服务端 传输错误 (%s): %v", connID, err)
		}
		log.Printf("[数据] 浏览器→服务端: %d 字节 (%s)", n, connID)
		pw.Close()
	}()

	// 服务端 → 浏览器
	go func() {
		defer wg.Done()
		n, err := copyBuffered(conn, resp.Body)
		if err != nil {
			log.Printf("[数据] 服务端→浏览器 传输错误 (%s): %v", connID, err)
		}
		log.Printf("[数据] 服务端→浏览器: %d 字节 (%s)", n, connID)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

// ==================== SOCKS5 协议实现 ====================

// socks5Handshake 执行完整的 SOCKS5 握手，返回目标地址 "host:port"
func socks5Handshake(conn net.Conn, validUser, validPass string) (string, error) {
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", fmt.Errorf("读取问候头失败: %w", err)
	}

	ver, nMethods := buf[0], buf[1]
	if ver != socks5Version {
		return "", fmt.Errorf("不支持的 SOCKS 版本: %d", ver)
	}
	if nMethods == 0 {
		return "", errors.New("客户端未提供认证方式")
	}

	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return "", fmt.Errorf("读取认证方式列表失败: %w", err)
	}
	methods := buf[:nMethods]

	var selectedAuth byte
	if validUser != "" {
		if containsByte(methods, authUserPass) {
			selectedAuth = authUserPass
		} else {
			conn.Write([]byte{socks5Version, authNoAcceptable})
			return "", errors.New("客户端不支持用户名密码认证")
		}
	} else {
		if containsByte(methods, authNone) {
			selectedAuth = authNone
		} else {
			conn.Write([]byte{socks5Version, authNoAcceptable})
			return "", errors.New("客户端不支持无认证方式")
		}
	}

	if _, err := conn.Write([]byte{socks5Version, selectedAuth}); err != nil {
		return "", fmt.Errorf("发送认证方式选择失败: %w", err)
	}

	if selectedAuth == authUserPass {
		if err := handleUserPassAuth(conn, validUser, validPass); err != nil {
			return "", err
		}
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", fmt.Errorf("读取请求头失败: %w", err)
	}

	if buf[0] != socks5Version {
		return "", fmt.Errorf("请求版本不匹配: %d", buf[0])
	}

	cmd := buf[1]
	if cmd != cmdConnect {
		sendSocks5Reply(conn, repCmdNotSupported, nil)
		return "", fmt.Errorf("不支持的命令: 0x%02x (仅支持 CONNECT)", cmd)
	}

	addrType := buf[3]

	var host string
	switch addrType {
	case addrTypeIPv4:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", fmt.Errorf("读取 IPv4 地址失败: %w", err)
		}
		host = net.IP(buf[:4]).String()

	case addrTypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", fmt.Errorf("读取域名长度失败: %w", err)
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return "", fmt.Errorf("读取域名失败: %w", err)
		}
		host = string(buf[:domainLen])

	case addrTypeIPv6:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", fmt.Errorf("读取 IPv6 地址失败: %w", err)
		}
		host = net.IP(buf[:16]).String()

	default:
		sendSocks5Reply(conn, repAddrNotSupported, nil)
		return "", fmt.Errorf("不支持的地址类型: 0x%02x", addrType)
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", fmt.Errorf("读取端口失败: %w", err)
	}
	port := binary.BigEndian.Uint16(buf[:2])

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// handleUserPassAuth 处理用户名密码认证子协议 (RFC 1929)
func handleUserPassAuth(conn net.Conn, validUser, validPass string) error {
	buf := make([]byte, 513)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return fmt.Errorf("读取认证请求失败: %w", err)
	}

	if buf[0] != authUserPassVersion {
		return fmt.Errorf("不支持的认证子协议版本: %d", buf[0])
	}

	uLen := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:uLen]); err != nil {
		return fmt.Errorf("读取用户名失败: %w", err)
	}
	username := string(buf[:uLen])

	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return fmt.Errorf("读取密码长度失败: %w", err)
	}
	pLen := int(buf[0])
	if _, err := io.ReadFull(conn, buf[:pLen]); err != nil {
		return fmt.Errorf("读取密码失败: %w", err)
	}
	password := string(buf[:pLen])

	if username != validUser || password != validPass {
		conn.Write([]byte{authUserPassVersion, authStatusFailure})
		return fmt.Errorf("认证失败: 用户名 %q", username)
	}

	_, err := conn.Write([]byte{authUserPassVersion, authStatusSuccess})
	if err != nil {
		return fmt.Errorf("发送认证结果失败: %w", err)
	}
	return nil
}

// sendSocks5Reply 发送 SOCKS5 应答
func sendSocks5Reply(conn net.Conn, rep byte, bindAddr net.Addr) error {
	reply := []byte{
		socks5Version, rep, 0x00, addrTypeIPv4,
		0, 0, 0, 0, // BND.ADDR: 0.0.0.0
		0, 0, // BND.PORT: 0
	}
	_, err := conn.Write(reply)
	return err
}

// containsByte 检查字节切片中是否包含指定字节
func containsByte(s []byte, b byte) bool {
	for _, v := range s {
		if v == b {
			return true
		}
	}
	return false
}
