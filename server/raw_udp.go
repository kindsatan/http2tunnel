// UDP 明文传输服务端
//
// 在 UDP 端口上接收客户端数据报，使用二进制握手协议建立会话。
// 每个客户端地址（IP:端口）对应一个会话。
//
// 支持的隧道模式：
//   - UDP 隧道: 客户端 UDP 数据报 ↔ 服务端 ↔ 目标 UDP
//   - TUN 隧道: 客户端 IP 包 ↔ 服务端 ↔ TUN 设备
//
// 注意：UDP 传输不支持 TCP 隧道模式（TCP 是流式协议，需要可靠传输保证）。
//
// 会话管理：
//   - 首包为握手数据（含魔数），识别新客户端
//   - 会话超时 120 秒无活动自动清理
//   - 反向路径由 goroutine 处理（目标 UDP → 客户端）

package main

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"http2tunnel/transport"
)

// rawUDPSession 表示一个 UDP 传输会话
type rawUDPSession struct {
	clientAddr    *net.UDPAddr
	cmd           byte
	targetUDPConn *net.UDPConn // UDP 隧道: 目标 UDP 连接
	tunIP         string       // TUN 隧道: 客户端 TUN IP
	lastActive    int64        // 最后活跃时间（Unix 时间戳）
}

// rawUDPServer 管理 UDP 传输的所有会话
type rawUDPServer struct {
	conn        *net.UDPConn
	token       string
	dialTimeout time.Duration
	tunMgr      *tunManager

	mu       sync.RWMutex
	sessions map[string]*rawUDPSession // clientAddr.String() → session
}

// startRawUDPListener 启动 UDP 明文传输监听器
func startRawUDPListener(addr, token string, dialTimeout time.Duration, tunMgr *tunManager) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("[致命] UDP 明文传输地址解析失败 %s: %v", addr, err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("[致命] UDP 明文传输监听失败 %s: %v", addr, err)
	}

	// 增大 UDP socket 缓冲区
	udpConn.SetReadBuffer(4 * 1024 * 1024)
	udpConn.SetWriteBuffer(4 * 1024 * 1024)

	log.Printf("[UDP传输] 监听地址: %s", addr)

	s := &rawUDPServer{
		conn:        udpConn,
		token:       token,
		dialTimeout: dialTimeout,
		tunMgr:      tunMgr,
		sessions:    make(map[string]*rawUDPSession),
	}

	go s.cleanupLoop()
	s.serve()
}

// serve 主读取循环，分发数据包到对应会话
func (s *rawUDPServer) serve() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[UDP传输] 读取错误: %v", err)
			continue
		}
		if n < 1 {
			continue
		}

		key := addr.String()
		s.mu.RLock()
		session, exists := s.sessions[key]
		s.mu.RUnlock()

		if exists {
			// 已有会话：转发数据
			atomic.StoreInt64(&session.lastActive, time.Now().Unix())
			s.forwardData(session, buf[:n])
		} else {
			// 新客户端：尝试握手
			s.handleHandshake(addr, buf[:n])
		}
	}
}

// handleHandshake 处理新客户端的握手请求
func (s *rawUDPServer) handleHandshake(addr *net.UDPAddr, data []byte) {
	hs, err := transport.UnmarshalUDPHandshake(data)
	if err != nil {
		log.Printf("[UDP传输] 握手解析失败 (%s): %v", addr, err)
		return
	}

	// 认证校验
	if s.token != "" && hs.Token != s.token {
		s.conn.WriteToUDP([]byte{transport.StatusAuthFail}, addr)
		log.Printf("[UDP传输] 认证失败: %s", addr)
		return
	}

	switch hs.Cmd {
	case transport.CmdUDP:
		s.setupUDPSession(addr, hs.Arg)
	case transport.CmdTUN:
		s.setupTUNSession(addr, hs.Arg)
	case transport.CmdTCP:
		// TCP 隧道不支持 UDP 传输
		s.conn.WriteToUDP([]byte{transport.StatusBadRequest}, addr)
		log.Printf("[UDP传输] 拒绝 TCP 隧道请求（UDP 传输不支持 TCP 隧道）: %s", addr)
	default:
		s.conn.WriteToUDP([]byte{transport.StatusBadRequest}, addr)
		log.Printf("[UDP传输] 未知命令: 0x%02x (%s)", hs.Cmd, addr)
	}
}

// setupUDPSession 建立 UDP 隧道会话
func (s *rawUDPServer) setupUDPSession(addr *net.UDPAddr, target string) {
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		s.conn.WriteToUDP([]byte{transport.StatusBadRequest}, addr)
		log.Printf("[UDP传输] UDP 地址解析失败 %s: %v", target, err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		s.conn.WriteToUDP([]byte{transport.StatusConnectFail}, addr)
		log.Printf("[UDP传输] 连接 UDP 目标失败 %s: %v", target, err)
		return
	}
	udpConn.SetReadBuffer(4 * 1024 * 1024)
	udpConn.SetWriteBuffer(4 * 1024 * 1024)

	session := &rawUDPSession{
		clientAddr:    addr,
		cmd:           transport.CmdUDP,
		targetUDPConn: udpConn,
		lastActive:    time.Now().Unix(),
	}

	s.mu.Lock()
	s.sessions[addr.String()] = session
	s.mu.Unlock()

	// 发送成功状态
	s.conn.WriteToUDP([]byte{transport.StatusOK}, addr)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[UDP传输] UDP 隧道建立: %s → %s (活跃: %d)", addr, target, current)

	// 启动反向路径：目标 UDP → 客户端
	go s.udpTargetToClient(session, target)
}

// udpTargetToClient 从目标 UDP 读取数据，转发给客户端
func (s *rawUDPServer) udpTargetToClient(session *rawUDPSession, target string) {
	buf := make([]byte, udpReadBufSize)
	var totalBytes int64
	for {
		n, err := session.targetUDPConn.Read(buf)
		if err != nil {
			break
		}
		if _, err := s.conn.WriteToUDP(buf[:n], session.clientAddr); err != nil {
			break
		}
		totalBytes += int64(n)
		atomic.StoreInt64(&session.lastActive, time.Now().Unix())
	}
	log.Printf("[UDP传输] 目标→客户端 UDP: %d 字节 (%s ← %s)", totalBytes, session.clientAddr, target)
}

// setupTUNSession 建立 TUN 隧道会话
func (s *rawUDPServer) setupTUNSession(addr *net.UDPAddr, clientIP string) {
	if s.tunMgr == nil {
		s.conn.WriteToUDP([]byte{transport.StatusBadRequest}, addr)
		log.Printf("[UDP传输] TUN 未启用，拒绝请求: %s", addr)
		return
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		s.conn.WriteToUDP([]byte{transport.StatusBadRequest}, addr)
		log.Printf("[UDP传输] TUN IP 格式错误: %s", clientIP)
		return
	}
	if !s.tunMgr.dev.Net.Contains(ip) {
		s.conn.WriteToUDP([]byte{transport.StatusBadRequest}, addr)
		log.Printf("[UDP传输] TUN IP %s 不在子网 %s 内", clientIP, s.tunMgr.dev.Net.String())
		return
	}

	session := &rawUDPSession{
		clientAddr: addr,
		cmd:        transport.CmdTUN,
		tunIP:      clientIP,
		lastActive: time.Now().Unix(),
	}

	s.mu.Lock()
	s.sessions[addr.String()] = session
	s.mu.Unlock()

	// 注册到 TUN 管理器，使用 UDP 直接发送（无帧封装）
	client := &tunClient{
		writePacket: func(data []byte) error {
			_, err := s.conn.WriteToUDP(data, addr)
			return err
		},
	}
	s.tunMgr.register(clientIP, client)

	// 发送成功状态
	s.conn.WriteToUDP([]byte{transport.StatusOK}, addr)

	current := atomic.AddInt64(&activeConns, 1)
	log.Printf("[UDP传输] TUN 隧道建立: %s (IP: %s, 活跃: %d)", addr, clientIP, current)
}

// forwardData 将数据转发到对应目标
func (s *rawUDPServer) forwardData(session *rawUDPSession, data []byte) {
	switch session.cmd {
	case transport.CmdUDP:
		// UDP 隧道：直接转发到目标 UDP
		if session.targetUDPConn != nil {
			session.targetUDPConn.Write(data)
		}
	case transport.CmdTUN:
		// TUN 隧道：写入 TUN 设备
		if s.tunMgr != nil {
			s.tunMgr.dev.Write(data)
		}
	}
}

// cleanupLoop 定期清理超时会话
func (s *rawUDPServer) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	const sessionTimeout = 120 // 秒

	for range ticker.C {
		now := time.Now().Unix()
		s.mu.Lock()
		for key, session := range s.sessions {
			if now-atomic.LoadInt64(&session.lastActive) > sessionTimeout {
				// 清理会话
				switch session.cmd {
				case transport.CmdUDP:
					if session.targetUDPConn != nil {
						session.targetUDPConn.Close()
					}
				case transport.CmdTUN:
					if s.tunMgr != nil && session.tunIP != "" {
						s.tunMgr.unregister(session.tunIP)
					}
				}
				delete(s.sessions, key)
				atomic.AddInt64(&activeConns, -1)
				log.Printf("[UDP传输] 会话超时清理: %s", key)
			}
		}
		s.mu.Unlock()
	}
}
