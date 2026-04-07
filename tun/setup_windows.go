//go:build windows

package tun

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/songgao/water"
)

func platformConfig(cfg *water.Config, name string) {
	// TAP-Windows6 驱动的组件 ID
	cfg.ComponentID = "tap0901"
	if name != "" {
		cfg.InterfaceName = name
	}
}

func configureInterface(name string, ip net.IP, ipNet *net.IPNet, mtu int) error {
	mask := net.IP(ipNet.Mask).String()

	// 设置 IP 地址
	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		name, "static", ip.String(), mask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置 IP 地址失败: %w (输出: %s)", err, string(out))
	}

	// 设置 MTU
	out, err = exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		name, fmt.Sprintf("mtu=%d", mtu), "store=persistent").CombinedOutput()
	if err != nil {
		// MTU 设置在某些 Windows 版本可能失败，仅警告不中断
		fmt.Printf("[TUN] 设置 MTU 警告: %v (输出: %s)\n", err, string(out))
	}

	return nil
}
