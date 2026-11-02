package discovery

import (
	"context"
	"encoding/binary"
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

// Scanner manages passive ARP reads and bounded, rate-limited active discovery.
type Scanner struct {
	adapter    platform.NetworkAdapter
	mu         sync.RWMutex
	devices    map[string]*Device
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

// AddDevice registers an observed endpoint into the discovered devices inventory.
func (s *Scanner) AddDevice(dev *Device) {
	if dev == nil || dev.IP == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[dev.IP] = dev
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
		if n.IP == "" || n.MAC == "" || n.MAC == "00:00:00:00:00:00" || strings.ToLower(n.MAC) == "incomplete" {
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

// SweepPlan specifies the exact parameters and authorized scope for an active subnet discovery sweep.
type SweepPlan struct {
	InterfaceName  string   `json:"interface_name"`
	LocalIP        string   `json:"local_ip"`
	CIDR           string   `json:"cidr"`
	TargetRange    string   `json:"target_range"`
	TargetCount    int      `json:"target_count"`
	Targets        []string `json:"targets"`
	ProbeType      string   `json:"probe_type"`
	MaxRate        int      `json:"max_rate"`        // packets per second
	MaxConcurrency int      `json:"max_concurrency"` // concurrent workers
}

// PrepareSweepPlan inspects the active interface and calculates the exact target scope.
// The resulting plan is presented to the user for explicit authorization prior to probing.
func (s *Scanner) PrepareSweepPlan() (*SweepPlan, error) {
	iface, err := s.adapter.GetDefaultInterface()
	if err != nil || len(iface.IPs) == 0 {
		return nil, fmt.Errorf("no active network interface with IP address found")
	}

	var targetSubnet *net.IPNet
	var localIP string
	for _, addr := range iface.IPs {
		if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
			targetSubnet = &addr
			localIP = addr.IP.String()
			break
		}
	}
	if targetSubnet == nil {
		return nil, fmt.Errorf("no IPv4 subnet found for active interface %s", iface.Name)
	}

	targets := GenerateSubnetHosts(targetSubnet, 254)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no scannable host addresses found in subnet %s", targetSubnet.String())
	}

	targetRange := fmt.Sprintf("%s – %s", targets[0], targets[len(targets)-1])
	if len(targets) == 1 {
		targetRange = targets[0]
	}

	ones, _ := targetSubnet.Mask.Size()
	networkCIDR := fmt.Sprintf("%s/%d", targetSubnet.IP.Mask(targetSubnet.Mask).String(), ones)

	return &SweepPlan{
		InterfaceName:  iface.Name,
		LocalIP:        localIP,
		CIDR:           networkCIDR,
		TargetRange:    targetRange,
		TargetCount:    len(targets),
		Targets:        targets,
		ProbeType:      "TCP SYN (Port 80)",
		MaxRate:        15,
		MaxConcurrency: 3,
	}, nil
}

// RunGentleSweep executes a rate-limited discovery sweep across the local IPv4 subnet.
// It is intended for backwards compatibility; interactive callers should use PrepareSweepPlan + ExecuteSweepPlan.
func (s *Scanner) RunGentleSweep(ctx context.Context, progressFn func(current, total int)) error {
	plan, err := s.PrepareSweepPlan()
	if err != nil {
		return err
	}
	return s.ExecuteSweepPlan(ctx, plan, progressFn)
}

// ExecuteSweepPlan executes an authorized sweep using the exact targets from an approved SweepPlan.
func (s *Scanner) ExecuteSweepPlan(ctx context.Context, plan *SweepPlan, progressFn func(current, total int)) error {
	if plan == nil || len(plan.Targets) == 0 {
		return fmt.Errorf("invalid or empty sweep plan")
	}

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
		// Always refresh passive ARP cache to capture responses received prior to completion or cancellation
		s.RefreshPassive()
	}()

	targets := plan.Targets
	total := len(targets)

	// Controlled rate limiting: 15 packets per second
	rateTicker := time.NewTicker(66 * time.Millisecond)
	defer rateTicker.Stop()

	// Worker pool: max 3 concurrent in-flight probes
	jobsChan := make(chan string, 3)
	var wg sync.WaitGroup

	workerCount := 3
	if total < workerCount {
		workerCount = total
	}

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-jobsChan:
					if !ok {
						return
					}
					probeHost(ctx, ip, 250*time.Millisecond)
				}
			}
		}()
	}

	// Dispatcher
	var scanErr error
	for idx, ip := range targets {
		select {
		case <-ctx.Done():
			scanErr = ctx.Err()
			break
		case <-rateTicker.C:
			select {
			case <-ctx.Done():
				scanErr = ctx.Err()
				break
			case jobsChan <- ip:
				if progressFn != nil {
					progressFn(idx+1, total)
				}
			}
		}
		if scanErr != nil {
			break
		}
	}

	close(jobsChan)
	wg.Wait()

	if scanErr != nil {
		return scanErr
	}

	// Brief pause for kernel ARP cache update, then refresh passive inventory
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(400 * time.Millisecond):
	}

	return nil
}

func probeHost(ctx context.Context, ip string, timeout time.Duration) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "80"))
	if err == nil {
		conn.Close()
	}
}

// GenerateSubnetHosts calculates all valid host addresses inside ipNet.
// It excludes the network address, broadcast address, and self IP.
// For /31 point-to-point subnets (RFC 3021), both addresses are host addresses.
// For large networks (< /24), it bounds the sweep to the local /24 segment of the host.
func GenerateSubnetHosts(ipNet *net.IPNet, maxHosts int) []string {
	if ipNet == nil {
		return nil
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}
	mask := ipNet.Mask
	if len(mask) != 4 {
		return nil
	}

	ones, bits := mask.Size()
	if bits != 32 {
		return nil
	}

	ipUint := binary.BigEndian.Uint32(ip)
	maskUint := binary.BigEndian.Uint32(mask)
	netUint := ipUint & maskUint
	bcastUint := netUint | (^maskUint)

	var targets []string

	// Case 1: Host-only /32
	if ones == 32 {
		return nil
	}

	// Case 2: RFC 3021 /31 point-to-point (both .0 and .1 are valid hosts)
	if ones == 31 {
		for candidate := netUint; candidate <= bcastUint; candidate++ {
			if candidate != ipUint {
				candIP := make(net.IP, 4)
				binary.BigEndian.PutUint32(candIP, candidate)
				targets = append(targets, candIP.String())
			}
		}
		return targets
	}

	// Case 3: Subnets /24 to /30
	if ones >= 24 {
		for candidate := netUint + 1; candidate < bcastUint; candidate++ {
			if candidate == ipUint {
				continue // skip self
			}
			candIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(candIP, candidate)
			if ipNet.Contains(candIP) {
				targets = append(targets, candIP.String())
				if maxHosts > 0 && len(targets) >= maxHosts {
					break
				}
			}
		}
		return targets
	}

	// Case 4: Larger subnets (< /24, e.g. /16 or /8)
	// Bounded strictly to the local /24 block of the host to prevent broad network scanning
	local24Net := ipUint & 0xFFFFFF00
	local24Bcast := local24Net | 0x000000FF

	for candidate := local24Net + 1; candidate < local24Bcast; candidate++ {
		if candidate == ipUint {
			continue // skip self
		}
		candIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(candIP, candidate)
		if ipNet.Contains(candIP) {
			targets = append(targets, candIP.String())
			if maxHosts > 0 && len(targets) >= maxHosts {
				break
			}
		}
	}

	return targets
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
