//go:build linux

package tun

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/songgao/water"
)

func platformConfig(cfg *water.Config, name string) {
	if name != "" {
		cfg.Name = name
	}
}

func configureInterface(name string, ip net.IP, ipNet *net.IPNet, mtu int) error {
	cidr, _ := ipNet.Mask.Size()
	addr := fmt.Sprintf("%s/%d", ip.String(), cidr)

	cmds := [][]string{
		{"ip", "addr", "add", addr, "dev", name},
		{"ip", "link", "set", name, "mtu", fmt.Sprintf("%d", mtu)},
		{"ip", "link", "set", name, "up"},
	}

	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("执行 %v 失败: %w (输出: %s)", args, err, string(out))
		}
	}
	return nil
}
