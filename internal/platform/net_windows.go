//go:build windows

package platform

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// WindowsAdapter implements NetworkAdapter on Windows platforms.
type WindowsAdapter struct {
	configuredIface string
}

func NewAdapter(ifaceName ...string) NetworkAdapter {
	name := ""
	if len(ifaceName) > 0 {
		name = ifaceName[0]
	}
	return &WindowsAdapter{configuredIface: name}
}

func (a *WindowsAdapter) IsElevated() bool {
	return IsElevated()
}

// GetDefaultInterface returns the primary active network adapter, or the explicitly configured interface.
func (a *WindowsAdapter) GetDefaultInterface() (*InterfaceInfo, error) {
	if a.configuredIface != "" {
		iface, err := net.InterfaceByName(a.configuredIface)
		if err != nil {
			return nil, fmt.Errorf("requested interface %q cannot be found: %w", a.configuredIface, err)
		}
		return toInterfaceInfo(iface), nil
	}

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

	var allowedIPs map[string]bool
	if a.configuredIface != "" {
		allowedIPs = make(map[string]bool)
		if iface, err := net.InterfaceByName(a.configuredIface); err == nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
						allowedIPs[ipNet.IP.String()] = true
					}
				}
			}
		}
	}

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		// Active Routes: Network Destination, Netmask, Gateway, Interface, Metric
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := net.ParseIP(fields[2])
			ifaceIP := fields[3]
			if gw != nil && gw.To4() != nil {
				if a.configuredIface != "" {
					if allowedIPs[ifaceIP] {
						return gw, nil
					}
					// Route belongs to a different interface; do not silently use it
					continue
				}
				return gw, nil
			}
		}
	}
	if a.configuredIface != "" {
		return nil, fmt.Errorf("no default gateway route found for interface %q", a.configuredIface)
	}
	return nil, fmt.Errorf("default gateway not found in route table")
}

// GetRouteStatus inspects default routes, their interface attribution, and metrics on Windows.
func (a *WindowsAdapter) GetRouteStatus() (RouteStatus, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return RouteStatus{
			HasDefaultRoute: false,
			IsPrimary:       false,
			Details:         fmt.Sprintf("Failed to query route table: %v", err),
		}, nil
	}

	var allowedIPs map[string]bool
	if a.configuredIface != "" {
		allowedIPs = make(map[string]bool)
		if iface, err := net.InterfaceByName(a.configuredIface); err == nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
						allowedIPs[ipNet.IP.String()] = true
					}
				}
			}
		}
	}

	type winRoute struct {
		gwIP    net.IP
		ifaceIP string
		metric  int
	}

	var defaultRoutes []winRoute
	lowestMetric := 999999

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := net.ParseIP(fields[2])
			ifaceIP := fields[3]
			metric, _ := strconv.Atoi(fields[4])
			if gw != nil && gw.To4() != nil {
				defaultRoutes = append(defaultRoutes, winRoute{
					gwIP:    gw,
					ifaceIP: ifaceIP,
					metric:  metric,
				})
				if metric < lowestMetric {
					lowestMetric = metric
				}
			}
		}
	}

	if len(defaultRoutes) == 0 {
		return RouteStatus{
			HasDefaultRoute: false,
			IsPrimary:       false,
			Details:         "No default route found in Windows routing table",
		}, nil
	}

	if a.configuredIface != "" {
		for _, r := range defaultRoutes {
			if allowedIPs[r.ifaceIP] {
				isPrimary := (r.metric == lowestMetric)
				details := fmt.Sprintf("Selected interface %s is primary default route (metric %d)", a.configuredIface, r.metric)
				if !isPrimary {
					details = fmt.Sprintf("Selected interface %s has default route (metric %d), but primary route has lower metric (%d)", a.configuredIface, r.metric, lowestMetric)
				}
				return RouteStatus{
					HasDefaultRoute: true,
					IsPrimary:       isPrimary,
					GatewayIP:       r.gwIP,
					InterfaceName:   a.configuredIface,
					Metric:          r.metric,
					Details:         details,
				}, nil
			}
		}
		return RouteStatus{
			HasDefaultRoute: false,
			IsPrimary:       false,
			InterfaceName:   a.configuredIface,
			Details:         fmt.Sprintf("No default gateway route configured on selected interface %s", a.configuredIface),
		}, nil
	}

	return RouteStatus{
		HasDefaultRoute: true,
		IsPrimary:       true,
		GatewayIP:       defaultRoutes[0].gwIP,
		InterfaceName:   defaultRoutes[0].ifaceIP,
		Metric:          defaultRoutes[0].metric,
		Details:         "System-wide default route",
	}, nil
}

// GetDNSServers parses DNS servers via 'ipconfig /all' and 'netsh' without inventing fallback servers.
func (a *WindowsAdapter) GetDNSServers() ([]string, error) {
	var targetIPs []string
	if a.configuredIface != "" {
		if iface, err := net.InterfaceByName(a.configuredIface); err == nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok {
						targetIPs = append(targetIPs, ipNet.IP.String())
					}
				}
			}
		}
	}

	// 1. Primary discovery: ipconfig /all
	cmd := exec.Command("ipconfig", "/all")
	var out bytes.Buffer
	cmd.Stdout = &out
	var ipconfigErr error
	if err := cmd.Run(); err == nil {
		servers, pErr := ParseWindowsIPConfigDNS(out.String(), a.configuredIface, targetIPs)
		if pErr == nil && len(servers) > 0 {
			return servers, nil
		}
		ipconfigErr = pErr
	} else {
		ipconfigErr = err
	}

	// 2. Secondary discovery: netsh interface ip/ipv6 show dnsservers
	var v4Out, v6Out bytes.Buffer
	cmdV4 := exec.Command("netsh", "interface", "ip", "show", "dnsservers")
	cmdV4.Stdout = &v4Out
	_ = cmdV4.Run()

	cmdV6 := exec.Command("netsh", "interface", "ipv6", "show", "dnsservers")
	cmdV6.Stdout = &v6Out
	_ = cmdV6.Run()

	if v4Out.Len() > 0 || v6Out.Len() > 0 {
		servers, netshErr := ParseWindowsNetshDNS(v4Out.String(), v6Out.String(), a.configuredIface)
		if netshErr == nil && len(servers) > 0 {
			return servers, nil
		}
	}

	if ipconfigErr != nil {
		return nil, fmt.Errorf("failed to discover Windows DNS configuration: %w", ipconfigErr)
	}
	return nil, fmt.Errorf("no DNS servers configured on interface %q", a.configuredIface)
}

// GetARPTable parses entries from 'arp -a'.
func (a *WindowsAdapter) GetARPTable() ([]NeighborEntry, error) {
	cmd := exec.Command("arp", "-a")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run arp -a: %w", err)
	}

	var allowedIPs map[string]bool
	if a.configuredIface != "" {
		allowedIPs = make(map[string]bool)
		if iface, err := net.InterfaceByName(a.configuredIface); err == nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
						allowedIPs[ipNet.IP.String()] = true
					}
				}
			}
		}
	}

	var neighbors []NeighborEntry
	scanner := bufio.NewScanner(&out)
	currentInterface := ""
	currentMatchesConfig := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentInterface = parts[1]
				if a.configuredIface != "" {
					currentMatchesConfig = allowedIPs[currentInterface]
				}
			}
			continue
		}

		if a.configuredIface != "" && !currentMatchesConfig {
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
