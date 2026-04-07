// TUN 虚拟网络接口管理包
//
// 提供跨平台的 TUN 设备创建和配置功能。
// Linux 使用 /dev/net/tun 内核接口，Windows 使用 OpenVPN TAP-Windows6 适配器。
//
// 使用前需确保：
//   - Linux: 具有 root 权限或 CAP_NET_ADMIN 能力
//   - Windows: 已安装 OpenVPN TAP-Windows6 驱动

package tun

import (
	"fmt"
	"net"

	"github.com/songgao/water"
)

// DefaultMTU 是 TUN 接口的默认 MTU 值。
// 设为 1400 以容纳 HTTP/2 + TLS 的协议开销，避免 IP 分片。
const DefaultMTU = 1400

// Device 封装 TUN 设备及其网络配置
type Device struct {
	*water.Interface
	IP  net.IP     // 接口 IP 地址
	Net *net.IPNet // 子网信息
	MTU int        // MTU 大小
}

// CreateTUN 创建并配置一个 TUN 网络接口
//
// 参数：
//   - name: 接口名称（Linux 如 "tun0"，Windows 为适配器名称，留空自动分配）
//   - ipCIDR: IP 地址（CIDR 格式），如 "10.0.0.1/24"
//   - mtu: MTU 大小，0 或负数使用默认值 1400
func CreateTUN(name, ipCIDR string, mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return nil, fmt.Errorf("解析 IP 地址 %q 失败: %w", ipCIDR, err)
	}

	cfg := water.Config{DeviceType: water.TUN}
	platformConfig(&cfg, name)

	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN 设备失败: %w", err)
	}

	if err := configureInterface(iface.Name(), ip, ipNet, mtu); err != nil {
		iface.Close()
		return nil, fmt.Errorf("配置 TUN 接口失败: %w", err)
	}

	return &Device{
		Interface: iface,
		IP:        ip,
		Net:       ipNet,
		MTU:       mtu,
	}, nil
}
