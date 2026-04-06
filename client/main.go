// HTTP/2 隧道代理 - 客户端（多模式）
//
// 支持三种工作模式：
//
// 模式1 - TCP 固定目标转发（-target + 默认）：
//   将本地 TCP 端口的所有连接直接转发到固定目标地址。
//   数据流向：本地 TCP → HTTP/2 stream → HTTPS → 服务端 → 目标 TCP
//
// 模式2 - UDP 固定目标转发（-target + -udp）：
//   将本地 UDP 端口的数据报通过 HTTP/2 隧道转发到目标 UDP 端点。
//   数据流向：本地 UDP → 帧封装 → HTTP/2 stream → HTTPS → 服务端 → 目标 UDP
//   典型场景：WireGuard (UDP 51820)
//
// 模式3 - SOCKS5 代理（不指定 -target）：
//   在本地提供 SOCKS5 代理服务，由浏览器动态指定目标地址。
//   数据流向：浏览器 ←SOCKS5→ 客户端 ←HTTP/2 stream→ 服务端 ←TCP→ 目标网站
//
// UDP 帧封装格式（在 HTTP/2 字节流上保留 UDP 数据报边界）：
//   +----------+-------------------+
//   | LEN (2B) | UDP 数据报 (LEN B) |
//   +----------+-------------------+
//     大端序      最大 65535 字节
//
// HTTP/2 连接复用：
//   所有隧道共享同一个底层 TLS 连接（HTTP/2 多路复用），
//   每个连接对应一个 HTTP/2 stream。

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

	"golang.org/x/net/http2"
)

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
	serverURL := flag.String("server", "https://127.0.0.1:8443", "服务端 URL")
	target := flag.String("target", "", "固定目标地址 (host:port)，留空则启用 SOCKS5 模式")
	udpMode := flag.Bool("udp", false, "启用 UDP 转发模式（需配合 -target 使用）")
	token := flag.String("token", "", "服务端认证令牌")
	insecure := flag.Bool("insecure", false, "跳过 TLS 证书验证（自签名证书时使用）")
	socksUser := flag.String("socks-user", "", "SOCKS5 用户名（仅 SOCKS5 模式，留空则不启用认证）")
	socksPass := flag.String("socks-pass", "", "SOCKS5 密码（仅 SOCKS5 模式）")
	flag.Parse()

	// 参数校验
	if *udpMode && *target == "" {
		log.Fatal("[致命] -udp 模式必须配合 -target 使用")
	}
	if *target != "" {
		if _, _, err := net.SplitHostPort(*target); err != nil {
			log.Fatalf("[致命] 目标地址格式错误: %v，需要 host:port 格式", err)
		}
	}

	// ========== 配置 HTTP/2 传输层 ==========
	tlsConfig := &tls.Config{
		InsecureSkipVerify: *insecure,
	}

	transport := &http2.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: false,
	}

	client := &http.Client{
		Transport: transport,
	}

	tunnelURL := *serverURL + "/tunnel"

	// ========== 根据模式启动 ==========
	if *udpMode {
		// UDP 转发模式：监听本地 UDP 端口
		startUDPMode(*localAddr, client, tunnelURL, *target, *token, *insecure)
	} else if *target != "" {
		// TCP 固定目标转发模式
		startTCPForwardMode(*localAddr, client, tunnelURL, *target, *token, *insecure, *socksUser, *socksPass)
	} else {
		// SOCKS5 代理模式
		startTCPForwardMode(*localAddr, client, tunnelURL, *target, *token, *insecure, *socksUser, *socksPass)
	}
}

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

// startUDPMode 启动 UDP 监听并建立单条 HTTP/2 隧道转发所有 UDP 数据报
//
// 工作原理：
//   - 监听本地 UDP 端口
//   - 建立一条到服务端的 HTTP/2 stream（带 X-Protocol: udp）
//   - 将本地收到的 UDP 数据报帧封装后写入 HTTP/2 请求体
//   - 将 HTTP/2 响应体中的帧解封后作为 UDP 数据报发回本地来源
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

	log.Printf("[启动] HTTP/2 隧道客户端 (UDP 转发模式)")
	log.Printf("[配置] 本地 UDP 监听: %s", localAddr)
	log.Printf("[配置] 目标地址: %s (UDP)", target)
	if insecure {
		log.Printf("[警告] TLS 证书验证已禁用")
	}

	// 创建管道，用于将 UDP 数据报帧封装后送入 HTTP/2 请求体
	pr, pw := io.Pipe()

	// 构建 HTTP/2 隧道请求
	req, err := http.NewRequest(http.MethodPost, tunnelURL, pr)
	if err != nil {
		log.Fatalf("[致命] 创建请求失败: %v", err)
	}
	req.Header.Set("X-Target", target)
	req.Header.Set("X-Protocol", "udp")
	if token != "" {
		req.Header.Set("X-Token", token)
	}

	// 异步发送请求
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

	// peerAddr 记录最近一次收到 UDP 数据报的来源地址，
	// 用于将服务端返回的数据发回正确的本地客户端。
	var peerAddr atomic.Value

	var wg sync.WaitGroup
	wg.Add(2)

	// 方向1: 本地 UDP → 帧封装 → HTTP/2 请求体 → 服务端
	go func() {
		defer wg.Done()
		defer pw.Close()
		buf := make([]byte, 65535)
		lenBuf := make([]byte, 2)
		var totalBytes int64
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("[数据] 本地 UDP 读取错误: %v", err)
				break
			}
			// 记录来源地址
			peerAddr.Store(addr)

			// 写入长度前缀帧
			binary.BigEndian.PutUint16(lenBuf, uint16(n))
			if _, err := pw.Write(lenBuf); err != nil {
				log.Printf("[数据] 写帧头到 HTTP/2 失败: %v", err)
				break
			}
			if _, err := pw.Write(buf[:n]); err != nil {
				log.Printf("[数据] 写数据报到 HTTP/2 失败: %v", err)
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[数据] 本地→服务端 UDP: %d 字节", totalBytes)
	}()

	// 方向2: 服务端 HTTP/2 响应体 → 帧解封 → 本地 UDP
	go func() {
		defer wg.Done()
		lenBuf := make([]byte, 2)
		var totalBytes int64
		for {
			// 读取 2 字节长度前缀
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

			// 读取数据报内容
			pkt := make([]byte, pktLen)
			if _, err := io.ReadFull(resp.Body, pkt); err != nil {
				log.Printf("[数据] 从 HTTP/2 读数据报错误: %v", err)
				break
			}

			// 发回本地来源
			if addr, ok := peerAddr.Load().(*net.UDPAddr); ok && addr != nil {
				if _, err := udpConn.WriteToUDP(pkt, addr); err != nil {
					log.Printf("[数据] 发送 UDP 数据报到本地错误: %v", err)
					break
				}
			}
			totalBytes += int64(pktLen)
		}
		log.Printf("[数据] 服务端→本地 UDP: %d 字节", totalBytes)
		// 关闭 UDP 连接以终止另一个 goroutine
		udpConn.Close()
	}()

	wg.Wait()
}

// ==================== TCP 转发处理 ====================

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
		n, err := io.Copy(pw, conn)
		if err != nil {
			log.Printf("[数据] 本地→服务端 传输错误 (%s): %v", connID, err)
		}
		log.Printf("[数据] 本地→服务端: %d 字节 (%s)", n, connID)
		pw.Close()
	}()

	// 服务端 → 本地
	go func() {
		defer wg.Done()
		n, err := io.Copy(conn, resp.Body)
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

// ==================== SOCKS5 处理 ====================

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

	go func() {
		defer wg.Done()
		n, err := io.Copy(pw, conn)
		if err != nil {
			log.Printf("[数据] 浏览器→服务端 传输错误 (%s): %v", connID, err)
		}
		log.Printf("[数据] 浏览器→服务端: %d 字节 (%s)", n, connID)
		pw.Close()
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(conn, resp.Body)
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
