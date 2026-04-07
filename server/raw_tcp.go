// TCP 明文传输服务端
//
// 在 TCP 端口上接受客户端连接，使用二进制握手协议（无 TLS、无 HTTP/2），
// 根据命令类型建立 TCP、UDP 或 TUN 隧道。
//
// 优势：
//   - 无 TLS 加解密开销
//   - 无 HTTP/2 帧封装开销
//   - 支持所有隧道模式（TCP 转发、UDP 转发、TUN 隧道）
//
// 每个客户端 TCP 连接对应一条隧道，协议格式见 transport/protocol.go

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
)

// startRawTCPListener 启动 TCP 明文传输监听器
func startRawTCPListener(addr, token string, dialTimeout time.Duration, tunMgr *tunManager) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[致命] TCP 明文传输监听失败 %s: %v", addr, err)
	}
	log.Printf("[TCP传输] 监听地址: %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TCP传输] 接受连接失败: %v", err)
			continue
		}
		go handleRawTCPConn(conn, token, dialTimeout, tunMgr)
	}
}

// handleRawTCPConn 处理一个 TCP 明文传输连接
func handleRawTCPConn(conn net.Conn, token string, dialTimeout time.Duration, tunMgr *tunManager) {
	defer conn.Close()

	setTCPSocketOptions(conn)

	// 设置握手超时
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	hs, err := transport.ReadHandshake(conn)
	if err != nil {
		log.Printf("[TCP传输] 握手失败 (%s): %v", conn.RemoteAddr(), err)
		return
	}

	// 清除超时
	conn.SetReadDeadline(time.Time{})

	// 认证校验
	if token != "" && hs.Token != token {
		transport.WriteStatus(conn, transport.StatusAuthFail)
		log.Printf("[TCP传输] 认证失败: %s", conn.RemoteAddr())
		return
	}

	switch hs.Cmd {
	case transport.CmdTCP:
		handleRawTCPTunnelTCP(conn, hs.Arg, dialTimeout)
	case transport.CmdUDP:
		handleRawTCPTunnelUDP(conn, hs.Arg, dialTimeout)
	case transport.CmdTUN:
		if tunMgr == nil {
			transport.WriteStatus(conn, transport.StatusBadRequest)
			log.Printf("[TCP传输] TUN 未启用，拒绝请求: %s", conn.RemoteAddr())
			return
		}
		handleRawTCPTunnelTUN(conn, hs.Arg, tunMgr)
	default:
		transport.WriteStatus(conn, transport.StatusBadRequest)
		log.Printf("[TCP传输] 未知命令: 0x%02x (%s)", hs.Cmd, conn.RemoteAddr())
	}
}

// handleRawTCPTunnelTCP 处理 TCP 明文传输 + TCP 隧道
//
// 握手完成后，客户端 TCP 连接和目标 TCP 连接之间直接双向转发字节流，
// 无帧封装开销，性能接近直连。
func handleRawTCPTunnelTCP(conn net.Conn, target string, dialTimeout time.Duration) {
	if _, _, err := net.SplitHostPort(target); err != nil {
		transport.WriteStatus(conn, transport.StatusBadRequest)
		log.Printf("[TCP传输] 目标地址格式错误: %s", target)
		return
	}

	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		transport.WriteStatus(conn, transport.StatusConnectFail)
		log.Printf("[TCP传输] 连接目标失败 %s: %v", target, err)
		return
	}
	defer targetConn.Close()
	setTCPSocketOptions(targetConn)

	transport.WriteStatus(conn, transport.StatusOK)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[TCP传输] TCP 隧道建立: %s → %s (活跃: %d)", conn.RemoteAddr(), target, current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[TCP传输] TCP 隧道关闭: %s → %s (活跃: %d)", conn.RemoteAddr(), target, cur)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 → 目标
	go func() {
		defer wg.Done()
		n, _ := copyBuffered(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		log.Printf("[TCP传输] 客户端→目标: %d 字节 (%s → %s)", n, conn.RemoteAddr(), target)
	}()

	// 目标 → 客户端
	go func() {
		defer wg.Done()
		n, _ := copyBuffered(conn, targetConn)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		log.Printf("[TCP传输] 目标→客户端: %d 字节 (%s ← %s)", n, conn.RemoteAddr(), target)
	}()

	wg.Wait()
}

// handleRawTCPTunnelUDP 处理 TCP 明文传输 + UDP 隧道
//
// 在 TCP 连接上使用 [2B长度][数据报] 帧封装传输 UDP 数据报。
func handleRawTCPTunnelUDP(conn net.Conn, target string, dialTimeout time.Duration) {
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		transport.WriteStatus(conn, transport.StatusBadRequest)
		log.Printf("[TCP传输] UDP 地址解析失败: %s", target)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		transport.WriteStatus(conn, transport.StatusConnectFail)
		log.Printf("[TCP传输] 连接 UDP 目标失败 %s: %v", target, err)
		return
	}
	defer udpConn.Close()
	udpConn.SetReadBuffer(4 * 1024 * 1024)
	udpConn.SetWriteBuffer(4 * 1024 * 1024)

	transport.WriteStatus(conn, transport.StatusOK)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[TCP传输] UDP 隧道建立: %s → %s (活跃: %d)", conn.RemoteAddr(), target, current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[TCP传输] UDP 隧道关闭: %s → %s (活跃: %d)", conn.RemoteAddr(), target, cur)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 → 目标 UDP（帧解封）
	go func() {
		defer wg.Done()
		var totalBytes int64
		lenBuf := make([]byte, 2)
		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		pktBuf := *bufp
		for {
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					log.Printf("[TCP传输] UDP 读帧头错误 (%s): %v", conn.RemoteAddr(), err)
				}
				break
			}
			pktLen := binary.BigEndian.Uint16(lenBuf)
			if pktLen == 0 {
				continue
			}
			if _, err := io.ReadFull(conn, pktBuf[:pktLen]); err != nil {
				break
			}
			if _, err := udpConn.Write(pktBuf[:pktLen]); err != nil {
				break
			}
			totalBytes += int64(pktLen)
		}
		log.Printf("[TCP传输] 客户端→目标 UDP: %d 字节 (%s)", totalBytes, target)
	}()

	// 目标 UDP → 客户端（帧封装）
	go func() {
		defer wg.Done()
		var totalBytes int64
		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		buf := *bufp
		for {
			n, err := udpConn.Read(buf[2:])
			if err != nil {
				break
			}
			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			if _, err := conn.Write(buf[:2+n]); err != nil {
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[TCP传输] 目标→客户端 UDP: %d 字节 (%s)", totalBytes, target)
	}()

	wg.Wait()
}

// handleRawTCPTunnelTUN 处理 TCP 明文传输 + TUN 隧道
//
// 在 TCP 连接上使用 [2B长度][IP包] 帧封装传输 IP 数据包。
// 注册到 tunManager 后，TUN 设备读取的 IP 包会通过 makeFrameWriter 回传。
func handleRawTCPTunnelTUN(conn net.Conn, clientIP string, mgr *tunManager) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		transport.WriteStatus(conn, transport.StatusBadRequest)
		log.Printf("[TCP传输] TUN IP 格式错误: %s", clientIP)
		return
	}
	if !mgr.dev.Net.Contains(ip) {
		transport.WriteStatus(conn, transport.StatusBadRequest)
		log.Printf("[TCP传输] TUN IP %s 不在子网 %s 内", clientIP, mgr.dev.Net.String())
		return
	}

	transport.WriteStatus(conn, transport.StatusOK)

	client := &tunClient{
		writePacket: makeFrameWriter(conn),
	}

	mgr.register(clientIP, client)
	defer mgr.unregister(clientIP)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[TCP传输] TUN 隧道建立: %s (来源: %s, 活跃: %d)", clientIP, conn.RemoteAddr(), current)
	defer func() {
		cur := atomic.AddInt64(&activeConns, -1)
		log.Printf("[TCP传输] TUN 隧道关闭: %s (来源: %s, 活跃: %d)", clientIP, conn.RemoteAddr(), cur)
	}()

	// 读取客户端帧封装 IP 包，写入 TUN 设备
	lenBuf := make([]byte, 2)
	pktBuf := make([]byte, mgr.dev.MTU+100)
	var totalBytes int64
	for {
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Printf("[TCP传输] TUN 读帧头错误 (%s): %v", clientIP, err)
			}
			break
		}
		pktLen := binary.BigEndian.Uint16(lenBuf)
		if pktLen == 0 {
			continue
		}
		if int(pktLen) > len(pktBuf) {
			io.CopyN(io.Discard, conn, int64(pktLen))
			continue
		}
		if _, err := io.ReadFull(conn, pktBuf[:pktLen]); err != nil {
			break
		}
		if _, err := mgr.dev.Write(pktBuf[:pktLen]); err != nil {
			log.Printf("[TCP传输] TUN 写设备错误: %v", err)
			break
		}
		totalBytes += int64(pktLen)
	}
	log.Printf("[TCP传输] 客户端→TUN: %d 字节 (%s)", totalBytes, clientIP)
}
