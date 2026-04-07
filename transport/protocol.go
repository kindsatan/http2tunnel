// 传输层协议定义
//
// 定义 TCP/UDP 明文传输方式的握手协议格式，供服务端和客户端共享。
//
// TCP 明文传输握手协议：
//   Client → Server:
//     [4B 魔数 "H2T\x01"] [2B 令牌长度] [令牌] [1B 命令类型] [2B 参数长度] [参数]
//   Server → Client:
//     [1B 状态码]
//
// UDP 明文传输握手协议（首包）：
//   Client → Server:
//     [4B 魔数 "H2T\x01"] [2B 令牌长度] [令牌] [1B 命令类型] [2B 参数长度] [参数]
//   Server → Client:
//     [1B 状态码]
//
// 命令类型：
//   0x01 = TCP 隧道（参数: 目标地址 host:port）
//   0x02 = UDP 隧道（参数: 目标地址 host:port）
//   0x03 = TUN 隧道（参数: 客户端 TUN IP）
//
// 状态码：
//   0x00 = 成功
//   0x01 = 认证失败
//   0x02 = 连接目标失败
//   0x03 = 请求格式错误

package transport

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Magic 是协议魔数，用于识别有效的握手请求
var Magic = [4]byte{'H', '2', 'T', 0x01}

// 命令类型常量
const (
	CmdTCP byte = 0x01 // TCP 隧道
	CmdUDP byte = 0x02 // UDP 隧道
	CmdTUN byte = 0x03 // TUN 隧道
)

// 状态码常量
const (
	StatusOK          byte = 0x00 // 成功
	StatusAuthFail    byte = 0x01 // 认证失败
	StatusConnectFail byte = 0x02 // 连接目标失败
	StatusBadRequest  byte = 0x03 // 请求格式错误
)

// Handshake 表示一个握手请求
type Handshake struct {
	Token string // 认证令牌
	Cmd   byte   // 命令类型
	Arg   string // 参数（TCP/UDP: 目标地址, TUN: 客户端 IP）
}

// WriteHandshake 将握手请求写入流式 Writer（用于 TCP 传输）
func WriteHandshake(w io.Writer, h *Handshake) error {
	if _, err := w.Write(Magic[:]); err != nil {
		return fmt.Errorf("写入魔数失败: %w", err)
	}

	tokenBytes := []byte(h.Token)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(tokenBytes)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("写入令牌长度失败: %w", err)
	}
	if len(tokenBytes) > 0 {
		if _, err := w.Write(tokenBytes); err != nil {
			return fmt.Errorf("写入令牌失败: %w", err)
		}
	}

	if _, err := w.Write([]byte{h.Cmd}); err != nil {
		return fmt.Errorf("写入命令类型失败: %w", err)
	}

	argBytes := []byte(h.Arg)
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(argBytes)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("写入参数长度失败: %w", err)
	}
	if len(argBytes) > 0 {
		if _, err := w.Write(argBytes); err != nil {
			return fmt.Errorf("写入参数失败: %w", err)
		}
	}

	return nil
}

// ReadHandshake 从流式 Reader 读取握手请求（用于 TCP 传输）
func ReadHandshake(r io.Reader) (*Handshake, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("读取魔数失败: %w", err)
	}
	if magic != Magic {
		return nil, fmt.Errorf("无效魔数: %x", magic)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("读取令牌长度失败: %w", err)
	}
	tokenLen := binary.BigEndian.Uint16(lenBuf[:])
	tokenBuf := make([]byte, tokenLen)
	if tokenLen > 0 {
		if _, err := io.ReadFull(r, tokenBuf); err != nil {
			return nil, fmt.Errorf("读取令牌失败: %w", err)
		}
	}

	var cmdBuf [1]byte
	if _, err := io.ReadFull(r, cmdBuf[:]); err != nil {
		return nil, fmt.Errorf("读取命令类型失败: %w", err)
	}

	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("读取参数长度失败: %w", err)
	}
	argLen := binary.BigEndian.Uint16(lenBuf[:])
	argBuf := make([]byte, argLen)
	if argLen > 0 {
		if _, err := io.ReadFull(r, argBuf); err != nil {
			return nil, fmt.Errorf("读取参数失败: %w", err)
		}
	}

	return &Handshake{
		Token: string(tokenBuf),
		Cmd:   cmdBuf[0],
		Arg:   string(argBuf),
	}, nil
}

// WriteStatus 写入状态码（1 字节）
func WriteStatus(w io.Writer, status byte) error {
	_, err := w.Write([]byte{status})
	return err
}

// ReadStatus 读取状态码（1 字节）
func ReadStatus(r io.Reader) (byte, error) {
	var buf [1]byte
	_, err := io.ReadFull(r, buf[:])
	return buf[0], err
}

// StatusText 返回状态码的文字描述
func StatusText(status byte) string {
	switch status {
	case StatusOK:
		return "成功"
	case StatusAuthFail:
		return "认证失败"
	case StatusConnectFail:
		return "连接目标失败"
	case StatusBadRequest:
		return "请求格式错误"
	default:
		return fmt.Sprintf("未知状态: 0x%02x", status)
	}
}

// MarshalUDPHandshake 将握手请求序列化为 UDP 数据报
func MarshalUDPHandshake(h *Handshake) []byte {
	tokenBytes := []byte(h.Token)
	argBytes := []byte(h.Arg)
	size := 4 + 2 + len(tokenBytes) + 1 + 2 + len(argBytes)
	buf := make([]byte, size)

	copy(buf[0:4], Magic[:])
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(tokenBytes)))
	pos := 6
	copy(buf[pos:pos+len(tokenBytes)], tokenBytes)
	pos += len(tokenBytes)
	buf[pos] = h.Cmd
	pos++
	binary.BigEndian.PutUint16(buf[pos:pos+2], uint16(len(argBytes)))
	pos += 2
	copy(buf[pos:], argBytes)

	return buf
}

// UnmarshalUDPHandshake 从 UDP 数据报解析握手请求
func UnmarshalUDPHandshake(data []byte) (*Handshake, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("数据太短: 缺少魔数")
	}
	var magic [4]byte
	copy(magic[:], data[:4])
	if magic != Magic {
		return nil, fmt.Errorf("无效魔数: %x", magic)
	}

	pos := 4
	if pos+2 > len(data) {
		return nil, fmt.Errorf("数据太短: 缺少令牌长度")
	}
	tokenLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+tokenLen > len(data) {
		return nil, fmt.Errorf("数据太短: 缺少令牌")
	}
	token := string(data[pos : pos+tokenLen])
	pos += tokenLen

	if pos+1 > len(data) {
		return nil, fmt.Errorf("数据太短: 缺少命令类型")
	}
	cmd := data[pos]
	pos++

	if pos+2 > len(data) {
		return nil, fmt.Errorf("数据太短: 缺少参数长度")
	}
	argLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+argLen > len(data) {
		return nil, fmt.Errorf("数据太短: 缺少参数")
	}
	arg := string(data[pos : pos+argLen])

	return &Handshake{
		Token: token,
		Cmd:   cmd,
		Arg:   arg,
	}, nil
}
