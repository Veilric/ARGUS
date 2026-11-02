//go:build !windows

package platform

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// LinuxAdapter implements NetworkAdapter on Linux platforms.
type LinuxAdapter struct{}

func NewAdapter() NetworkAdapter {
	return &LinuxAdapter{}
}

func (a *LinuxAdapter) IsElevated() bool {
	return IsElevated()
}

// GetDefaultInterface returns the active non-loopback interface associated with default route.
func (a *LinuxAdapter) GetDefaultInterface() (*InterfaceInfo, error) {
	gwIP, ifaceName, err := parseDefaultRoute()
	if err == nil && ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err == nil {
			return toInterfaceInfo(iface), nil
		}
	}

	// Fallback: search net.Interfaces for first active non-loopback with valid IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if (iface.Flags&net.FlagLoopback) != 0 || (iface.Flags&net.FlagUp) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					return toInterfaceInfo(&iface), nil
				}
			}
		}
	}

	_ = gwIP
	return nil, fmt.Errorf("no active network interface found")
}

// GetDefaultGateway parses default gateway from /proc/net/route.
func (a *LinuxAdapter) GetDefaultGateway() (net.IP, error) {
	gwIP, _, err := parseDefaultRoute()
	if err != nil {
		return nil, err
	}
	return gwIP, nil
}

// GetDNSServers reads nameserver lines from /etc/resolv.conf.
func (a *LinuxAdapter) GetDNSServers() ([]string, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to open /etc/resolv.conf: %w", err)
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				servers = append(servers, parts[1])
			}
		}
	}
	return servers, scanner.Err()
}

// GetARPTable reads active neighbors from /proc/net/arp.
func (a *LinuxAdapter) GetARPTable() ([]NeighborEntry, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/arp: %w", err)
	}
	defer file.Close()

	var neighbors []NeighborEntry
	scanner := bufio.NewScanner(file)
	// Skip header line
	if scanner.Scan() {
		// Header line: IP address HW type Flags HW address Mask Device
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 6 {
			ip := fields[0]
			flags := fields[2]
			mac := fields[3]
			device := fields[5]

			// Flags 0x0 indicates incomplete entry
			if flags == "0x0" || mac == "00:00:00:00:00:00" {
				continue
			}

			neighbors = append(neighbors, NeighborEntry{
				IP:        ip,
				MAC:       mac,
				Interface: device,
				State:     "REACHABLE",
			})
		}
	}

	return neighbors, scanner.Err()
}

func parseDefaultRoute() (net.IP, string, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, "", fmt.Errorf("failed to open /proc/net/route: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header
	if scanner.Scan() {
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			iface := fields[0]
			destHex := fields[1]
			gwHex := fields[2]

			// Destination "00000000" signifies default route
			if destHex == "00000000" {
				gwBytes, err := hex.DecodeString(gwHex)
				if err == nil && len(gwBytes) == 4 {
					// Hex in /proc/net/route is little-endian IPv4
					gwIP := net.IPv4(gwBytes[3], gwBytes[2], gwBytes[1], gwBytes[0])
					return gwIP, iface, nil
				}
			}
		}
	}
	return nil, "", fmt.Errorf("default route not found")
}

func toInterfaceInfo(iface *net.Interface) *InterfaceInfo {
	info := &InterfaceInfo{
		Name:         iface.Name,
		Index:        iface.Index,
		HardwareAddr: iface.HardwareAddr,
		Flags:        iface.Flags,
		MTU:          iface.MTU,
		IsUp:         (iface.Flags & net.FlagUp) != 0,
		IsLoopback:   (iface.Flags & net.FlagLoopback) != 0,
	}

	addrs, err := iface.Addrs()
	if err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				info.IPs = append(info.IPs, *ipNet)
			}
		}
	}
	return info
}
