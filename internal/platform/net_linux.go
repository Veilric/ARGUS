//go:build !windows

package platform

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// LinuxAdapter implements NetworkAdapter on Linux platforms.
type LinuxAdapter struct {
	configuredIface string
}

func NewAdapter(ifaceName ...string) NetworkAdapter {
	name := ""
	if len(ifaceName) > 0 {
		name = ifaceName[0]
	}
	return &LinuxAdapter{configuredIface: name}
}

func (a *LinuxAdapter) IsElevated() bool {
	return IsElevated()
}

// GetDefaultInterface returns the active non-loopback interface associated with default route,
// or the explicitly configured interface when specified.
func (a *LinuxAdapter) GetDefaultInterface() (*InterfaceInfo, error) {
	if a.configuredIface != "" {
		iface, err := net.InterfaceByName(a.configuredIface)
		if err != nil {
			return nil, fmt.Errorf("requested interface %q cannot be found: %w", a.configuredIface, err)
		}
		return toInterfaceInfo(iface), nil
	}

	gwIP, ifaceName, err := parseDefaultRoute("")
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
	gwIP, _, err := parseDefaultRoute(a.configuredIface)
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

			// Filter to configured interface when explicitly specified
			if a.configuredIface != "" && device != a.configuredIface {
				continue
			}

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

// GetRouteStatus returns detailed route status including route presence, priority, and metric.
func (a *LinuxAdapter) GetRouteStatus() (RouteStatus, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return RouteStatus{}, fmt.Errorf("failed to open /proc/net/route: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		// skip header
	}

	type defaultRouteEntry struct {
		iface  string
		gwIP   net.IP
		metric int
	}

	var defaultRoutes []defaultRouteEntry
	lowestMetric := 999999
	var primaryIface string

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 7 {
			iface := fields[0]
			destHex := fields[1]
			gwHex := fields[2]
			metricStr := fields[6]

			if destHex == "00000000" {
				gwBytes, err := hex.DecodeString(gwHex)
				if err == nil && len(gwBytes) == 4 {
					gwIP := net.IPv4(gwBytes[3], gwBytes[2], gwBytes[1], gwBytes[0])
					metric, _ := strconv.Atoi(metricStr)
					defaultRoutes = append(defaultRoutes, defaultRouteEntry{
						iface:  iface,
						gwIP:   gwIP,
						metric: metric,
					})
					if metric < lowestMetric {
						lowestMetric = metric
						primaryIface = iface
					}
				}
			}
		}
	}

	if len(defaultRoutes) == 0 {
		return RouteStatus{
			HasDefaultRoute: false,
			IsPrimary:       false,
			Details:         "No default route found in system routing table",
		}, nil
	}

	if a.configuredIface != "" {
		for _, r := range defaultRoutes {
			if r.iface == a.configuredIface {
				isPrimary := (r.metric == lowestMetric)
				details := fmt.Sprintf("Selected interface %s is primary default route (metric %d)", a.configuredIface, r.metric)
				if !isPrimary {
					details = fmt.Sprintf("Selected interface %s has default route (metric %d), but primary route is via %s (metric %d)", a.configuredIface, r.metric, primaryIface, lowestMetric)
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

	// Auto-select primary default route
	for _, r := range defaultRoutes {
		if r.iface == primaryIface {
			return RouteStatus{
				HasDefaultRoute: true,
				IsPrimary:       true,
				GatewayIP:       r.gwIP,
				InterfaceName:   r.iface,
				Metric:          r.metric,
				Details:         fmt.Sprintf("System-wide primary default route via %s (metric %d)", r.iface, r.metric),
			}, nil
		}
	}

	return RouteStatus{
		HasDefaultRoute: true,
		IsPrimary:       true,
		GatewayIP:       defaultRoutes[0].gwIP,
		InterfaceName:   defaultRoutes[0].iface,
		Metric:          defaultRoutes[0].metric,
		Details:         "System-wide default route",
	}, nil
}

func parseDefaultRoute(preferIface string) (net.IP, string, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, "", fmt.Errorf("failed to open /proc/net/route: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header
	if scanner.Scan() {
	}

	var fallbackGW net.IP
	var fallbackIface string

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
					if preferIface != "" && iface == preferIface {
						return gwIP, iface, nil
					}
					if preferIface == "" && fallbackGW == nil {
						fallbackGW = gwIP
						fallbackIface = iface
					}
				}
			}
		}
	}
	if preferIface == "" && fallbackGW != nil {
		return fallbackGW, fallbackIface, nil
	}
	if preferIface != "" {
		return nil, "", fmt.Errorf("no default gateway route found for interface %q", preferIface)
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
