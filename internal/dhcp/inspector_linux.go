//go:build linux

package dhcp

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type linuxInspector struct{}

func newPlatformInspector() Inspector {
	return &linuxInspector{}
}

func (l *linuxInspector) Inspect(ifaceName string) (*DHCPConfig, error) {
	// Query active kernel interface state first for validation
	var iface *net.Interface
	var activeIPv4 string
	var activePrefix int
	if ifaceName != "" {
		if i, err := net.InterfaceByName(ifaceName); err == nil {
			iface = i
			if addrs, aErr := iface.Addrs(); aErr == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
						activeIPv4 = ipNet.IP.String()
						ones, _ := ipNet.Mask.Size()
						activePrefix = ones
						break
					}
				}
			}
		}
	}

	// 1. Authoritative Source: NetworkManager CLI (nmcli)
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

	// 2. systemd-networkd: check interface-specific lease by ifindex (/run/systemd/netif/leases/<ifindex>)
	if iface != nil && iface.Index > 0 {
		leasePath := filepath.Join("/run/systemd/netif/leases", strconv.Itoa(iface.Index))
		if fi, sErr := os.Stat(leasePath); sErr == nil {
			if content, err := os.ReadFile(leasePath); err == nil {
				if cfg, pErr := ParseSystemdNetworkdLeaseWithAcquisition(string(content), ifaceName, fi.ModTime()); pErr == nil && cfg != nil {
					// Verify lease address against active kernel IP to prevent stale attribution
					if activeIPv4 == "" || cfg.IPv4Address == activeIPv4 {
						l.populateMAC(cfg)
						return cfg, nil
					}
				}
			}
		}
	}

	// 3. dhclient lease files in standard system directories
	dhclientDirs := []string{
		"/var/lib/NetworkManager",
		"/var/lib/dhcp",
		"/var/lib/dhclient",
	}

	for _, dir := range dhclientDirs {
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

			if strings.Contains(cStr, "lease {") {
				if cfg, pErr := ParseDHClientLease(cStr, ifaceName); pErr == nil && cfg != nil {
					// Verify lease address against active kernel IP
					if activeIPv4 == "" || cfg.IPv4Address == activeIPv4 {
						l.populateMAC(cfg)
						return cfg, nil
					}
				}
			}
		}
	}

	// 4. Fallback: Active kernel interface state without unverified DHCP attribution
	if activeIPv4 == "" {
		return nil, fmt.Errorf("no active IPv4 address found for interface %q", ifaceName)
	}

	cfg := &DHCPConfig{
		InterfaceName: ifaceName,
		IPv4Address:   activeIPv4,
		IPv4Prefix:    activePrefix,
		Assignment:    AssignmentUnknown,
		Source:        "Kernel Interface / OS Route",
		ObservedAt:    time.Now(),
	}
	l.populateMAC(cfg)

	return cfg, nil
}

func (l *linuxInspector) populateMAC(cfg *DHCPConfig) {
	if cfg.InterfaceName != "" && cfg.MACAddress == "" {
		if iface, err := net.InterfaceByName(cfg.InterfaceName); err == nil {
			cfg.MACAddress = iface.HardwareAddr.String()
		}
	}
}
