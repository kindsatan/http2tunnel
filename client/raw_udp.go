// UDP 明文传输客户端
//
// 通过 UDP 明文连接到服务端（无 TLS、无 HTTP/2），
// 使用二进制握手协议建立隧道。
//
// 支持的隧道模式：
//   - UDP 转发: 本地 UDP → UDP 明文 → 服务端 → 目标 UDP
//   - TUN 隧道: 本地 TUN → UDP 明文 → 服务端 TUN
//
// 注意：UDP 传输不支持 TCP 转发和 SOCKS5 模式（TCP 需要可靠传输）。
//
// 每个 UDP 数据报直接承载一个数据报/IP包，无帧封装开销，
// 避免 TCP 队头阻塞，适合实时性要求高的场景。

package main

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"http2tunnel/transport"
	"http2tunnel/tun"
)

const (
	// udpHandshakeRetries 是 UDP 握手的最大重试次数
	udpHandshakeRetries = 3
	// udpHandshakeTimeout 是 UDP 握手的超时时间
	udpHandshakeTimeout = 5 * time.Second
)

// udpDoHandshake 执行 UDP 握手，带重试机制
func udpDoHandshake(conn *net.UDPConn, hs *transport.Handshake) error {
	hsData := transport.MarshalUDPHandshake(hs)

	for i := 0; i < udpHandshakeRetries; i++ {
		if _, err := conn.Write(hsData); err != nil {
			return err
		}

		conn.SetReadDeadline(time.Now().Add(udpHandshakeTimeout))
		var statusBuf [1]byte
		_, err := conn.Read(statusBuf[:])
		conn.SetReadDeadline(time.Time{})

		if err != nil {
			if i < udpHandshakeRetries-1 {
				log.Printf("[UDP传输] 握手超时，重试 %d/%d", i+1, udpHandshakeRetries)
				continue
			}
			return err
		}

		if statusBuf[0] != transport.StatusOK {
			log.Fatalf("[致命] 服务端拒绝: %s", transport.StatusText(statusBuf[0]))
		}
		return nil
	}
	return nil
}

// startUDPModeRawUDP 以 UDP 明文传输启动 UDP 转发模式
//
// 数据流向：
//
//	本地 UDP 客户端 ↔ 本地 UDP 监听 ↔ UDP 明文 ↔ 服务端 ↔ 目标 UDP
//
// 每个 UDP 数据报在传输通道上直接传输，无帧封装开销。
func startUDPModeRawUDP(localAddr, serverAddr, target, token string) {
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		log.Fatalf("[致命] 解析本地 UDP 地址失败: %v", err)
	}

	localUDPConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("[致命] 本地 UDP 端口监听失败: %v", err)
	}
	defer localUDPConn.Close()
	localUDPConn.SetReadBuffer(4 * 1024 * 1024)
	localUDPConn.SetWriteBuffer(4 * 1024 * 1024)

	log.Printf("[启动] UDP 明文传输客户端 (UDP 转发模式)")
	log.Printf("[配置] 本地 UDP 监听: %s", localAddr)
	log.Printf("[配置] 目标地址: %s (UDP)", target)
	log.Printf("[配置] 服务端: %s (UDP 明文)", serverAddr)

	// 连接服务端 UDP
	sAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		log.Fatalf("[致命] 解析服务端地址失败: %v", err)
	}
	serverUDPConn, err := net.DialUDP("udp", nil, sAddr)
	if err != nil {
		log.Fatalf("[致命] 连接服务端失败: %v", err)
	}
	defer serverUDPConn.Close()
	serverUDPConn.SetReadBuffer(4 * 1024 * 1024)
	serverUDPConn.SetWriteBuffer(4 * 1024 * 1024)

	// 握手
	if err := udpDoHandshake(serverUDPConn, &transport.Handshake{
		Token: token,
		Cmd:   transport.CmdUDP,
		Arg:   target,
	}); err != nil {
		log.Fatalf("[致命] UDP 握手失败: %v", err)
	}

	log.Printf("[隧道] UDP 隧道建立成功 (UDP 明文传输)")

	var peerAddr atomic.Value
	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 UDP → 服务端 UDP（直接转发，无帧封装）
	go func() {
		defer wg.Done()
		buf := make([]byte, udpReadBufSize)
		var totalBytes int64
		for {
			n, addr, err := localUDPConn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			peerAddr.Store(addr)
			if _, err := serverUDPConn.Write(buf[:n]); err != nil {
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[数据] 本地→服务端 UDP: %d 字节", totalBytes)
	}()

	// 服务端 UDP → 本地 UDP（直接转发，无帧封装）
	go func() {
		defer wg.Done()
		buf := make([]byte, udpReadBufSize)
		var totalBytes int64
		for {
			n, err := serverUDPConn.Read(buf)
			if err != nil {
				break
			}
			if addr, ok := peerAddr.Load().(*net.UDPAddr); ok && addr != nil {
				if _, err := localUDPConn.WriteToUDP(buf[:n], addr); err != nil {
					break
				}
			}
			totalBytes += int64(n)
		}
		log.Printf("[数据] 服务端→本地 UDP: %d 字节", totalBytes)
		localUDPConn.Close()
	}()

	wg.Wait()
}

// startTUNModeRawUDP 以 UDP 明文传输启动 TUN 隧道模式
//
// 数据流向：
//
//	本地 TUN ↔ UDP 明文 ↔ 服务端 TUN
//
// 每个 IP 包作为一个 UDP 数据报直接传输，无帧封装开销。
// 天然适合 TUN 场景：IP 包是独立的数据报，不依赖有序传输。
func startTUNModeRawUDP(tunIPCIDR, tunName string, tunMTU int, serverAddr, token string) {
	ip, _, err := net.ParseCIDR(tunIPCIDR)
	if err != nil {
		log.Fatalf("[致命] 解析 TUN IP 失败: %v", err)
	}

	tunDev, err := tun.CreateTUN(tunName, tunIPCIDR, tunMTU)
	if err != nil {
		log.Fatalf("[致命] 创建 TUN 接口失败: %v", err)
	}
	defer tunDev.Close()

	log.Printf("[启动] UDP 明文传输客户端 (TUN 隧道模式)")
	log.Printf("[TUN] 接口: %s (IP: %s, MTU: %d)", tunDev.Name(), tunIPCIDR, tunMTU)
	log.Printf("[配置] 服务端: %s (UDP 明文)", serverAddr)

	// 连接服务端 UDP
	sAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		log.Fatalf("[致命] 解析服务端地址失败: %v", err)
	}
	serverUDPConn, err := net.DialUDP("udp", nil, sAddr)
	if err != nil {
		log.Fatalf("[致命] 连接服务端失败: %v", err)
	}
	defer serverUDPConn.Close()
	serverUDPConn.SetReadBuffer(4 * 1024 * 1024)
	serverUDPConn.SetWriteBuffer(4 * 1024 * 1024)

	// 握手
	if err := udpDoHandshake(serverUDPConn, &transport.Handshake{
		Token: token,
		Cmd:   transport.CmdTUN,
		Arg:   ip.String(),
	}); err != nil {
		log.Fatalf("[致命] UDP 握手失败: %v", err)
	}

	log.Printf("[TUN] 隧道建立成功 (UDP 明文传输)")

	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 TUN → 服务端 UDP（直接发送 IP 包）
	go func() {
		defer wg.Done()
		buf := make([]byte, tunMTU+100)
		var totalBytes int64
		for {
			n, err := tunDev.Read(buf)
			if err != nil {
				log.Printf("[TUN] 读取本地 TUN 错误: %v", err)
				break
			}
			if _, err := serverUDPConn.Write(buf[:n]); err != nil {
				log.Printf("[TUN] 发送到服务端失败: %v", err)
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[TUN] 本地→服务端: %d 字节", totalBytes)
	}()

	// 服务端 UDP → 本地 TUN（直接接收 IP 包）
	go func() {
		defer wg.Done()
		buf := make([]byte, tunMTU+100)
		var totalBytes int64
		for {
			n, err := serverUDPConn.Read(buf)
			if err != nil {
				break
			}
			if _, err := tunDev.Write(buf[:n]); err != nil {
				log.Printf("[TUN] 写入本地 TUN 错误: %v", err)
				break
			}
			totalBytes += int64(n)
		}
		log.Printf("[TUN] 服务端→本地: %d 字节", totalBytes)
		tunDev.Close()
	}()

	wg.Wait()
}
