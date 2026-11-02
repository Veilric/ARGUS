//go:build windows

package platform

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// WindowsAdapter implements NetworkAdapter on Windows platforms.
type WindowsAdapter struct{}

func NewAdapter() NetworkAdapter {
	return &WindowsAdapter{}
}

func (a *WindowsAdapter) IsElevated() bool {
	return IsElevated()
}

// GetDefaultInterface returns the primary active network adapter.
func (a *WindowsAdapter) GetDefaultInterface() (*InterfaceInfo, error) {
	gwIP, err := a.GetDefaultGateway()
	ifaces, netErr := net.Interfaces()
	if netErr != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", netErr)
	}

	// If gateway IP is known, match interface by subnet
	if err == nil && gwIP != nil {
		for _, iface := range ifaces {
			if (iface.Flags&net.FlagLoopback) != 0 || (iface.Flags&net.FlagUp) == 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					if ipNet.Contains(gwIP) {
						return toInterfaceInfo(&iface), nil
					}
				}
			}
		}
	}

	// Fallback: search for first active non-loopback with valid IPv4
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

	return nil, fmt.Errorf("no active network interface found")
}

// GetDefaultGateway parses default gateway from 'route print 0.0.0.0'.
func (a *WindowsAdapter) GetDefaultGateway() (net.IP, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute route print: %w", err)
	}

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		// Active Routes: Network Destination, Netmask, Gateway, Interface, Metric
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := net.ParseIP(fields[2])
			if gw != nil && gw.To4() != nil {
				return gw, nil
			}
		}
	}
	return nil, fmt.Errorf("default gateway not found in route table")
}

// GetDNSServers parses DNS servers via 'ipconfig /all'.
func (a *WindowsAdapter) GetDNSServers() ([]string, error) {
	cmd := exec.Command("ipconfig", "/all")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return []string{"1.1.1.1", "8.8.8.8"}, nil
	}

	var servers []string
	dnsRegex := regexp.MustCompile(`(?i)DNS Servers[ .:]+:\s*([0-9.]+)`)
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		matches := dnsRegex.FindStringSubmatch(scanner.Text())
		if len(matches) > 1 {
			servers = append(servers, matches[1])
		}
	}

	if len(servers) == 0 {
		return []string{"1.1.1.1", "8.8.8.8"}, nil
	}
	return servers, nil
}

// GetARPTable parses entries from 'arp -a'.
func (a *WindowsAdapter) GetARPTable() ([]NeighborEntry, error) {
	cmd := exec.Command("arp", "-a")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run arp -a: %w", err)
	}

	var neighbors []NeighborEntry
	scanner := bufio.NewScanner(&out)
	currentInterface := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentInterface = parts[1]
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			ip := net.ParseIP(fields[0])
			if ip != nil && ip.To4() != nil {
				mac := strings.ReplaceAll(fields[1], "-", ":")
				entryType := fields[2]
				if mac != "ff:ff:ff:ff:ff:ff" && entryType != "invalid" {
					neighbors = append(neighbors, NeighborEntry{
						IP:        fields[0],
						MAC:       mac,
						Interface: currentInterface,
						State:     strings.ToUpper(entryType),
					})
				}
			}
		}
	}

	return neighbors, nil
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
