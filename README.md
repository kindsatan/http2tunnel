# HTTP/2 Tunnel

基于纯 HTTP/2 协议的隧道代理系统，支持 TCP 转发、SOCKS5 代理和 UDP 转发。

## 功能特性

- **TCP 固定目标转发**：将本地端口流量通过 HTTP/2 隧道转发到指定目标
- **SOCKS5 代理**：在本地提供标准 SOCKS5 代理服务，支持浏览器动态指定目标
- **UDP 转发**：通过 HTTP/2 隧道转发 UDP 数据报（如 WireGuard）
- **HTTP/2 多路复用**：多条隧道共享单个 TLS 连接
- **令牌认证**：可选的 X-Token 头认证机制
- **配置文件支持**：服务端支持 JSON 配置文件，简化部署
- **跨平台编译**：支持 Windows、Linux (amd64/arm64/armv7)

## 项目结构

```
http2tunnel/
├── server/
│   └── main.go              # 服务端源码
├── client/
│   └── main.go              # 客户端源码
├── go.mod                   # Go 模块定义
├── go.sum                   # 依赖校验
├── server_config.json       # 服务端配置文件示例
└── README.md
```

## 系统架构

```
TCP 模式:
  本地应用 → 客户端(TCP) → HTTP/2 stream → HTTPS → 服务端 → 目标 TCP

SOCKS5 模式:
  浏览器 ←SOCKS5→ 客户端 ←HTTP/2 stream→ 服务端 ←TCP→ 目标网站

UDP 模式:
  本地应用 → 客户端(UDP) → 帧封装 → HTTP/2 stream → 服务端 → 目标 UDP
```

## 编译

### 前置要求

- Go 1.21 或更高版本

### 安装依赖

```bash
go mod download
```

如果下载缓慢，可设置国内代理：

```bash
go env -w GOPROXY=https://goproxy.cn,direct
```

### 编译 Windows 版本

```bash
go build -o server.exe ./server/
go build -o client.exe ./client/
```

### 交叉编译 Linux 版本

```bash
# Linux amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server_linux_amd64 ./server/
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o client_linux_amd64 ./client/

# Linux arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o server_linux_arm64 ./server/
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o client_linux_arm64 ./client/

# Linux armv7
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o server_linux_armv7 ./server/
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o client_linux_armv7 ./client/
```

> Windows CMD 下交叉编译需使用 bash 环境（如 Git Bash），或使用 `set` 命令分别设置环境变量。

## 生成 TLS 证书

服务端需要 TLS 证书。可使用 OpenSSL 生成自签名证书：

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=http2tunnel"
```

## 配置

### 服务端配置文件

服务端支持 JSON 配置文件（默认读取 `server_config.json`）：

```json
{
    "addr": ":8443",
    "cert": "cert.pem",
    "key": "key.pem",
    "token": "your_token",
    "dial_timeout": "10s"
}
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `addr` | 监听地址和端口 | `:8443` |
| `cert` | TLS 证书文件路径 | `cert.pem` |
| `key` | TLS 私钥文件路径 | `key.pem` |
| `token` | 认证令牌（留空则不启用） | 空 |
| `dial_timeout` | 连接目标超时时间 | `10s` |

配置优先级：**命令行参数 > 配置文件 > 默认值**

### 服务端命令行参数

```
-config     配置文件路径（默认 server_config.json）
-addr       监听地址
-cert       TLS 证书文件路径
-key        TLS 私钥文件路径
-token      认证令牌
-dial-timeout 连接超时时间（如 10s、30s）
```

### 客户端命令行参数

```
-local      本地监听地址（默认 :1080）
-server     服务端 URL（默认 https://127.0.0.1:8443）
-target     固定目标地址（留空则启用 SOCKS5 模式）
-udp        启用 UDP 转发模式（需配合 -target）
-token      服务端认证令牌
-insecure   跳过 TLS 证书验证（自签名证书时使用）
-socks-user SOCKS5 用户名（仅 SOCKS5 模式）
-socks-pass SOCKS5 密码（仅 SOCKS5 模式）
```

## 使用示例

### 启动服务端

```bash
# 使用配置文件（推荐）
./server

# 指定配置文件
./server -config /path/to/config.json

# 命令行参数覆盖配置文件
./server -addr :9443 -token mytoken

# 纯命令行参数（不使用配置文件）
./server -config none.json -addr :8443 -cert cert.pem -key key.pem -token zhc
```

### SOCKS5 代理模式

浏览器通过 SOCKS5 代理访问互联网：

```bash
./client -local :1080 -server https://your-server:8443 -token zhc -insecure
```

浏览器设置 SOCKS5 代理为 `127.0.0.1:1080` 即可。

### TCP 固定目标转发

将本地端口转发到远端指定目标：

```bash
./client -local :1080 -server https://your-server:8443 -target 192.168.1.1:5201 -token zhc -insecure
```

### UDP 转发（WireGuard）

转发 WireGuard UDP 流量：

```bash
./client -local :51820 -server https://your-server:8443 -target 192.168.1.1:51820 -udp -token zhc -insecure
```

### 状态监控

```bash
curl -k https://your-server:8443/status
```

返回示例：

```json
{"status":"ok","active_connections":3,"protocol":"HTTP/2.0"}
```

## 协议设计

### HTTP/2 隧道协议

客户端通过 `POST /tunnel` 发起隧道请求，使用自定义 HTTP 头传递参数：

| 头部 | 说明 |
|------|------|
| `X-Target` | 目标地址 `host:port` |
| `X-Protocol` | 协议类型：`tcp`（默认）或 `udp` |
| `X-Token` | 认证令牌 |

### UDP 帧封装

UDP 数据报在 HTTP/2 字节流上传输时使用长度前缀帧封装，以保留数据报边界：

```
+----------+-------------------+
| LEN (2B) | UDP 数据报 (LEN B) |
+----------+-------------------+
  大端序      最大 65535 字节
```

## 许可证

MIT License
