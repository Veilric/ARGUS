//go:build linux

package dhcp

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type linuxInspector struct{}

func newPlatformInspector() Inspector {
	return &linuxInspector{}
}

func (l *linuxInspector) Inspect(ifaceName string) (*DHCPConfig, error) {
	// 1. Try NetworkManager CLI
	if _, err := exec.LookPath("nmcli"); err == nil && ifaceName != "" {
		cmd := exec.Command("nmcli", "-t", "-f", "IP4,DHCP4", "device", "show", ifaceName)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil && out.Len() > 0 {
			cfg, pErr := ParseNMCLI(out.String(), ifaceName)
			if pErr == nil && cfg != nil && cfg.IPv4Address != "" {
				l.populateMAC(cfg)
				return cfg, nil
			}
		}
	}

	// 2. Try lease files in standard system directories
	leaseDirs := []string{
		"/run/systemd/netif/leases",
		"/var/lib/NetworkManager",
		"/var/lib/dhcp",
		"/var/lib/dhclient",
	}

	for _, dir := range leaseDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			content, rErr := os.ReadFile(path)
			if rErr != nil {
				continue
			}
			cStr := string(content)

			// Try systemd-networkd lease format
			if strings.Contains(cStr, "ADDRESS=") && strings.Contains(cStr, "SERVER_ADDRESS=") {
				if cfg, pErr := ParseSystemdNetworkdLease(cStr, ifaceName); pErr == nil && cfg != nil {
					l.populateMAC(cfg)
					return cfg, nil
				}
			}

			// Try dhclient lease format
			if strings.Contains(cStr, "lease {") {
				if cfg, pErr := ParseDHClientLease(cStr, ifaceName); pErr == nil && cfg != nil {
					l.populateMAC(cfg)
					return cfg, nil
				}
			}
		}
	}

	// 3. Fallback: Extract live kernel and interface state (Assignment remains Unknown if lease unavailable)
	cfg := &DHCPConfig{
		InterfaceName: ifaceName,
		Assignment:    AssignmentUnknown,
		Source:        "Kernel Interface / OS Route",
		ObservedAt:    time.Now(),
	}

	if ifaceName != "" {
		if iface, err := net.InterfaceByName(ifaceName); err == nil {
			cfg.MACAddress = iface.HardwareAddr.String()
			if addrs, aErr := iface.Addrs(); aErr == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
						cfg.IPv4Address = ipNet.IP.String()
						ones, _ := ipNet.Mask.Size()
						cfg.IPv4Prefix = ones
						break
					}
				}
			}
		}
	}

	if cfg.IPv4Address == "" {
		return nil, fmt.Errorf("no active IPv4 address found for interface %q", ifaceName)
	}

	return cfg, nil
}

func (l *linuxInspector) populateMAC(cfg *DHCPConfig) {
	if cfg.InterfaceName != "" && cfg.MACAddress == "" {
		if iface, err := net.InterfaceByName(cfg.InterfaceName); err == nil {
			cfg.MACAddress = iface.HardwareAddr.String()
		}
	}
}
