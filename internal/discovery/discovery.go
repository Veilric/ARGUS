package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"argus/internal/platform"
)

// Device represents an identified endpoint on the local subnet.
type Device struct {
	IP        string
	MAC       string
	Vendor    string
	Hostname  string
	Interface string
	State     string
	LastSeen  time.Time
}

// Scanner manages passive ARP reads and throttled active discovery.
type Scanner struct {
	adapter   platform.NetworkAdapter
	mu        sync.RWMutex
	devices   map[string]*Device
	isScanning bool
}

func NewScanner(adapter platform.NetworkAdapter) *Scanner {
	s := &Scanner{
		adapter: adapter,
		devices: make(map[string]*Device),
	}
	s.RefreshPassive()
	return s
}

func (s *Scanner) Devices() []*Device {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*Device, 0, len(s.devices))
	for _, dev := range s.devices {
		list = append(list, dev)
	}
	return list
}

func (s *Scanner) IsScanning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isScanning
}

// RefreshPassive populates discovered devices strictly from system ARP cache (0 packets sent).
func (s *Scanner) RefreshPassive() int {
	neighbors, err := s.adapter.GetARPTable()
	if err != nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, n := range neighbors {
		if n.IP == "" || n.MAC == "" || n.MAC == "00:00:00:00:00:00" {
			continue
		}
		dev, exists := s.devices[n.IP]
		if !exists {
			dev = &Device{
				IP:        n.IP,
				MAC:       n.MAC,
				Vendor:    LookupOUI(n.MAC),
				Interface: n.Interface,
				State:     n.State,
				LastSeen:  time.Now(),
			}
			s.devices[n.IP] = dev
			count++
		} else {
			dev.MAC = n.MAC
			dev.State = n.State
			dev.LastSeen = time.Now()
		}
	}
	return count
}

// RunGentleSweep executes a strictly throttled discovery sweep across the local /24 subnet.
// Strictly rate-limited to 15 packets/sec to stay IDS/switch-safe.
func (s *Scanner) RunGentleSweep(ctx context.Context, progressFn func(current, total int)) error {
	s.mu.Lock()
	if s.isScanning {
		s.mu.Unlock()
		return fmt.Errorf("scan already in progress")
	}
	s.isScanning = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.isScanning = false
		s.mu.Unlock()
	}()

	iface, err := s.adapter.GetDefaultInterface()
	if err != nil || len(iface.IPs) == 0 {
		return fmt.Errorf("no active interface with IP address found")
	}

	// Determine IPv4 subnet
	var targetSubnet *net.IPNet
	for _, addr := range iface.IPs {
		if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
			targetSubnet = &addr
			break
		}
	}
	if targetSubnet == nil {
		return fmt.Errorf("no IPv4 subnet found for active interface")
	}

	// Generate target IPs (limit to /24 or 254 hosts to avoid wide scanning)
	targets := generateSubnetHosts(targetSubnet)
	total := len(targets)
	if total == 0 {
		return nil
	}

	rateLimiter := time.NewTicker(66 * time.Millisecond) // ~15 packets per second
	defer rateLimiter.Stop()

	for idx, ip := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rateLimiter.C:
			go probeHostForARP(ip)
			if progressFn != nil {
				progressFn(idx+1, total)
			}
		}
	}

	// Allow 1 second for kernel ARP table to update
	time.Sleep(1 * time.Second)
	s.RefreshPassive()
	return nil
}

func probeHostForARP(ip string) {
	// Send safe TCP probe to trigger ARP resolution in kernel
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return
	}
	// Fallback UDP probe
	uconn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "12345"), 150*time.Millisecond)
	if err == nil {
		uconn.Close()
	}
}

func generateSubnetHosts(ipNet *net.IPNet) []string {
	var ips []string
	ip := ipNet.IP.To4()
	if ip == nil {
		return ips
	}

	mask := ipNet.Mask
	// If subnet is larger than /24 (e.g. /16 or /8), clamp sweep to the local /24 boundary
	baseIP := ip.Mask(mask)
	if len(mask) == 4 && (mask[0] != 255 || mask[1] != 255 || mask[2] != 255) {
		// Clamp to current /24
		baseIP = net.IPv4(ip[0], ip[1], ip[2], 0)
	}

	for host := 1; host <= 254; host++ {
		curIP := net.IPv4(baseIP[0], baseIP[1], baseIP[2], byte(host))
		// Skip network and broadcast
		if curIP.Equal(ip) {
			continue // skip self
		}
		ips = append(ips, curIP.String())
	}
	return ips
}

// LookupOUI returns known hardware vendors for common prefix ranges
func LookupOUI(mac string) string {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
	if len(clean) < 6 {
		return "Unknown"
	}
	prefix := clean[:6]

	ouiMap := map[string]string{
		"B827EB": "Raspberry Pi",
		"DCA632": "Raspberry Pi",
		"E45F01": "Raspberry Pi",
		"001A2B": "Cisco",
		"00000C": "Cisco",
		"00180A": "Cisco Meraki",
		"F09FC2": "Ubiquiti",
		"B4FBE4": "Ubiquiti",
		"788A20": "Ubiquiti",
		"001788": "Philips Lighting",
		"3C5AB4": "Google",
		"94EB2C": "Google",
		"F88FCA": "Google",
		"AC84C6": "TP-Link",
		"50C7BF": "TP-Link",
		"984827": "TP-Link",
		"001132": "Synology",
		"005056": "VMware",
		"000C29": "VMware",
		"525400": "QEMU/KVM",
		"080027": "VirtualBox",
		"F01898": "Apple",
		"A483E7": "Apple",
		"38F9D3": "Apple",
		"BC9FE4": "Dell",
		"D89EF3": "Dell",
		"F8BC12": "Dell",
		"001E67": "Intel",
		"A44CC8": "Intel",
	}

	if vendor, ok := ouiMap[prefix]; ok {
		return vendor
	}
	return "Generic Device"
}
