// TCP 明文传输客户端
//
// 通过 TCP 明文连接到服务端（无 TLS、无 HTTP/2），
// 使用二进制握手协议建立隧道。
//
// 支持所有隧道模式：
//   - TCP 转发: 本地 TCP → TCP 明文 → 服务端 → 目标 TCP
//   - SOCKS5:   浏览器 ←SOCKS5→ 客户端 ←TCP 明文→ 服务端 → 目标
//   - UDP 转发: 本地 UDP → 帧封装 → TCP 明文 → 服务端 → 目标 UDP
//   - TUN 隧道: 本地 TUN → 帧封装 → TCP 明文 → 服务端 TUN

package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"http2tunnel/transport"
	"http2tunnel/tun"
)

// handleForwardRawTCP 处理 TCP 明文传输的固定目标 TCP 转发
func handleForwardRawTCP(conn net.Conn, serverAddr, target, token string) {
	defer conn.Close()

	connID := conn.RemoteAddr().String() + "→" + target

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[TCP传输] 新连接: %s (活跃: %d)", connID, current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[TCP传输] 断开: %s (活跃: %d)", connID, cur)
	}()

	// 连接服务端
	serverConn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		log.Printf("[TCP传输] 连接服务端失败: %v", err)
		return
	}
	defer serverConn.Close()

	// TCP 性能优化
	if tc, ok := serverConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// 握手
	if err := transport.WriteHandshake(serverConn, &transport.Handshake{
		Token: token,
		Cmd:   transport.CmdTCP,
		Arg:   target,
	}); err != nil {
		log.Printf("[TCP传输] 握手写入失败: %v", err)
		return
	}

	status, err := transport.ReadStatus(serverConn)
	if err != nil {
		log.Printf("[TCP传输] 读取状态失败: %v", err)
		return
	}
	if status != transport.StatusOK {
		log.Printf("[TCP传输] 服务端拒绝: %s", transport.StatusText(status))
		return
	}

	log.Printf("[TCP传输] 隧道建立: %s", connID)

	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 → 服务端
	go func() {
		defer wg.Done()
		n, _ := copyBuffered(serverConn, conn)
		if tc, ok := serverConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		log.Printf("[TCP传输] 本地→服务端: %d 字节 (%s)", n, connID)
	}()

	// 服务端 → 本地
	go func() {
		defer wg.Done()
		n, _ := copyBuffered(conn, serverConn)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		log.Printf("[TCP传输] 服务端→本地: %d 字节 (%s)", n, connID)
	}()

	wg.Wait()
}

// handleSocks5RawTCP 处理 TCP 明文传输的 SOCKS5 连接
func handleSocks5RawTCP(conn net.Conn, serverAddr, token, socksUser, socksPass string) {
	defer conn.Close()

	target, err := socks5Handshake(conn, socksUser, socksPass)
	if err != nil {
		log.Printf("[SOCKS5] 握手失败 (%s): %v", conn.RemoteAddr(), err)
		return
	}

	connID := conn.RemoteAddr().String() + "→" + target

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[SOCKS5] TCP传输请求: %s (活跃: %d)", connID, current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[SOCKS5] TCP传输断开: %s (活跃: %d)", connID, cur)
	}()

	// 连接服务端
	serverConn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		log.Printf("[TCP传输] 连接服务端失败: %v", err)
		sendSocks5Reply(conn, repHostUnreach, nil)
		return
	}
	defer serverConn.Close()

	if tc, ok := serverConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// 握手
	if err := transport.WriteHandshake(serverConn, &transport.Handshake{
		Token: token,
		Cmd:   transport.CmdTCP,
		Arg:   target,
	}); err != nil {
		sendSocks5Reply(conn, repGeneralFailure, nil)
		return
	}

	status, err := transport.ReadStatus(serverConn)
	if err != nil {
		sendSocks5Reply(conn, repGeneralFailure, nil)
		return
	}
	if status != transport.StatusOK {
		sendSocks5Reply(conn, repConnRefused, nil)
		return
	}

	if err := sendSocks5Reply(conn, repSuccess, nil); err != nil {
		return
	}

	log.Printf("[SOCKS5] TCP传输隧道建立: %s", connID)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := copyBuffered(serverConn, conn)
		if tc, ok := serverConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		log.Printf("[SOCKS5] 本地→服务端: %d 字节 (%s)", n, connID)
	}()

	go func() {
		defer wg.Done()
		n, _ := copyBuffered(conn, serverConn)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		log.Printf("[SOCKS5] 服务端→本地: %d 字节 (%s)", n, connID)
	}()

	wg.Wait()
}

// startTCPForwardModeRawTCP 以 TCP 明文传输启动 TCP 转发/SOCKS5 模式
func startTCPForwardModeRawTCP(localAddr, serverAddr, target, token, socksUser, socksPass string) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("[致命] 本地端口监听失败: %v", err)
	}
	defer listener.Close()

	if target != "" {
		log.Printf("[启动] TCP 明文传输客户端 (TCP 固定目标转发模式)")
		log.Printf("[配置] 本地监听: %s", localAddr)
		log.Printf("[配置] 目标地址: %s", target)
	} else {
		log.Printf("[启动] TCP 明文传输客户端 (SOCKS5 模式)")
		log.Printf("[配置] SOCKS5 监听: %s", localAddr)
		if socksUser != "" {
			log.Printf("[配置] SOCKS5 认证: 已启用")
		}
	}
	log.Printf("[配置] 服务端: %s (TCP 明文)", serverAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[错误] 接受连接失败: %v", err)
			continue
		}
		if target != "" {
			go handleForwardRawTCP(conn, serverAddr, target, token)
		} else {
			go handleSocks5RawTCP(conn, serverAddr, token, socksUser, socksPass)
		}
	}
}

// startUDPModeRawTCP 以 TCP 明文传输启动 UDP 转发模式
func startUDPModeRawTCP(localAddr, serverAddr, target, token string) {
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

	log.Printf("[启动] TCP 明文传输客户端 (UDP 转发模式)")
	log.Printf("[配置] 本地 UDP 监听: %s", localAddr)
	log.Printf("[配置] 目标地址: %s (UDP)", target)
	log.Printf("[配置] 服务端: %s (TCP 明文)", serverAddr)

	// 连接服务端
	serverConn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		log.Fatalf("[致命] 连接服务端失败: %v", err)
	}
	defer serverConn.Close()

	if tc, ok := serverConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// 握手
	if err := transport.WriteHandshake(serverConn, &transport.Handshake{
		Token: token,
		Cmd:   transport.CmdUDP,
		Arg:   target,
	}); err != nil {
		log.Fatalf("[致命] 握手写入失败: %v", err)
	}

	status, err := transport.ReadStatus(serverConn)
	if err != nil {
		log.Fatalf("[致命] 读取状态失败: %v", err)
	}
	if status != transport.StatusOK {
		log.Fatalf("[致命] 服务端拒绝: %s", transport.StatusText(status))
	}

	log.Printf("[隧道] UDP 隧道建立成功 (TCP 明文传输)")

	var peerAddr atomic.Value
	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 UDP → 帧封装 → TCP 明文 → 服务端
	go func() {
		defer wg.Done()
		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		buf := *bufp
		var totalBytes int64
		for {
			n, addr, err := udpConn.ReadFromUDP(buf[2:])
			if err != nil {
				break
			}
			peerAddr.Store(addr)
			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			if _, err := serverConn.Write(buf[:2+n]); err != nil {
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[数据] 本地→服务端 UDP: %d 字节", totalBytes)
	}()

	// 服务端 → 帧解封 → 本地 UDP
	go func() {
		defer wg.Done()
		lenBuf := make([]byte, 2)
		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		pktBuf := *bufp
		var totalBytes int64
		for {
			if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					log.Printf("[数据] 读帧头错误: %v", err)
				}
				break
			}
			pktLen := binary.BigEndian.Uint16(lenBuf)
			if pktLen == 0 {
				continue
			}
			if _, err := io.ReadFull(serverConn, pktBuf[:pktLen]); err != nil {
				break
			}
			if addr, ok := peerAddr.Load().(*net.UDPAddr); ok && addr != nil {
				if _, err := udpConn.WriteToUDP(pktBuf[:pktLen], addr); err != nil {
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

// startTUNModeRawTCP 以 TCP 明文传输启动 TUN 隧道模式
func startTUNModeRawTCP(tunIPCIDR, tunName string, tunMTU int, serverAddr, token string) {
	ip, _, err := net.ParseCIDR(tunIPCIDR)
	if err != nil {
		log.Fatalf("[致命] 解析 TUN IP 失败: %v", err)
	}

	tunDev, err := tun.CreateTUN(tunName, tunIPCIDR, tunMTU)
	if err != nil {
		log.Fatalf("[致命] 创建 TUN 接口失败: %v", err)
	}
	defer tunDev.Close()

	log.Printf("[启动] TCP 明文传输客户端 (TUN 隧道模式)")
	log.Printf("[TUN] 接口: %s (IP: %s, MTU: %d)", tunDev.Name(), tunIPCIDR, tunMTU)
	log.Printf("[配置] 服务端: %s (TCP 明文)", serverAddr)

	// 连接服务端
	serverConn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		log.Fatalf("[致命] 连接服务端失败: %v", err)
	}
	defer serverConn.Close()

	if tc, ok := serverConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// 握手
	if err := transport.WriteHandshake(serverConn, &transport.Handshake{
		Token: token,
		Cmd:   transport.CmdTUN,
		Arg:   ip.String(),
	}); err != nil {
		log.Fatalf("[致命] 握手写入失败: %v", err)
	}

	status, err := transport.ReadStatus(serverConn)
	if err != nil {
		log.Fatalf("[致命] 读取状态失败: %v", err)
	}
	if status != transport.StatusOK {
		log.Fatalf("[致命] 服务端拒绝: %s", transport.StatusText(status))
	}

	log.Printf("[TUN] 隧道建立成功 (TCP 明文传输)")

	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 TUN → 帧封装 → TCP 明文 → 服务端
	go func() {
		defer wg.Done()
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
			if _, err := serverConn.Write(frameBuf[:2+n]); err != nil {
				log.Printf("[TUN] 写入服务端失败: %v", err)
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[TUN] 本地→服务端: %d 字节", totalBytes)
	}()

	// 服务端 → 帧解封 → 本地 TUN
	go func() {
		defer wg.Done()
		lenBuf := make([]byte, 2)
		pktBuf := make([]byte, tunMTU+100)
		var totalBytes int64
		for {
			if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
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
				io.CopyN(io.Discard, serverConn, int64(pktLen))
				continue
			}
			if _, err := io.ReadFull(serverConn, pktBuf[:pktLen]); err != nil {
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
