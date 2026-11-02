package discovery

import (
	"context"
	"net"
	"testing"
	"time"

	"argus/internal/platform"
)

func TestGenerateSubnetHosts(t *testing.T) {
	tests := []struct {
		name          string
		cidr          string
		selfIP        string
		expectedCount int
		checkFunc     func(t *testing.T, hosts []string)
	}{
		{
			name:          "Standard /24 subnet",
			cidr:          "192.168.1.0/24",
			selfIP:        "192.168.1.50",
			expectedCount: 253, // 254 usable - 1 self
			checkFunc: func(t *testing.T, hosts []string) {
				for _, h := range hosts {
					ip := net.ParseIP(h)
					if ip[15] == 0 || ip[15] == 255 || ip[15] == 50 {
						t.Errorf("Unexpected host in /24: %s", h)
					}
				}
			},
		},
		{
			name:          "Subnet /25 (upper half 128-255)",
			cidr:          "192.168.1.128/25",
			selfIP:        "192.168.1.130",
			expectedCount: 125, // 128 total - 1 network (.128) - 1 bcast (.255) - 1 self (.130)
			checkFunc: func(t *testing.T, hosts []string) {
				for _, h := range hosts {
					ip := net.ParseIP(h)
					if ip[15] < 129 || ip[15] > 254 || ip[15] == 130 {
						t.Errorf("Host escaped /25 boundary: %s", h)
					}
				}
			},
		},
		{
			name:          "Subnet /26 (middle block 64-127)",
			cidr:          "10.0.0.64/26",
			selfIP:        "10.0.0.70",
			expectedCount: 61, // 64 total - 1 net (.64) - 1 bcast (.127) - 1 self (.70)
			checkFunc: func(t *testing.T, hosts []string) {
				for _, h := range hosts {
					ip := net.ParseIP(h)
					if ip[15] < 65 || ip[15] > 126 || ip[15] == 70 {
						t.Errorf("Host escaped /26 boundary: %s", h)
					}
				}
			},
		},
		{
			name:          "Subnet /27 (block 32-63)",
			cidr:          "172.16.0.32/27",
			selfIP:        "172.16.0.35",
			expectedCount: 29, // 32 total - 1 net (.32) - 1 bcast (.63) - 1 self (.35)
			checkFunc: func(t *testing.T, hosts []string) {
				for _, h := range hosts {
					ip := net.ParseIP(h)
					if ip[15] < 33 || ip[15] > 62 || ip[15] == 35 {
						t.Errorf("Host escaped /27 boundary: %s", h)
					}
				}
			},
		},
		{
			name:          "Point-to-point /30 subnet (block 0-3)",
			cidr:          "192.168.10.0/30",
			selfIP:        "192.168.10.1",
			expectedCount: 1, // Only peer .2
			checkFunc: func(t *testing.T, hosts []string) {
				if len(hosts) != 1 || hosts[0] != "192.168.10.2" {
					t.Errorf("Expected only peer 192.168.10.2, got: %v", hosts)
				}
			},
		},
		{
			name:          "RFC 3021 /31 subnet (2 addresses, no net/bcast)",
			cidr:          "192.168.10.0/31",
			selfIP:        "192.168.10.0",
			expectedCount: 1, // Peer .1
			checkFunc: func(t *testing.T, hosts []string) {
				if len(hosts) != 1 || hosts[0] != "192.168.10.1" {
					t.Errorf("Expected only peer 192.168.10.1, got: %v", hosts)
				}
			},
		},
		{
			name:          "Single host /32",
			cidr:          "192.168.1.1/32",
			selfIP:        "192.168.1.1",
			expectedCount: 0,
			checkFunc: func(t *testing.T, hosts []string) {
				if len(hosts) != 0 {
					t.Errorf("Expected 0 hosts for /32, got: %v", hosts)
				}
			},
		},
		{
			name:          "Large /16 bounded scan",
			cidr:          "10.0.5.0/16",
			selfIP:        "10.0.5.10",
			expectedCount: 253, // Bounded to 10.0.5.1 - 10.0.5.254 minus self
			checkFunc: func(t *testing.T, hosts []string) {
				if len(hosts) > 255 {
					t.Errorf("Bounded scan exceeded safe limit: got %d hosts", len(hosts))
				}
				for _, h := range hosts {
					ip := net.ParseIP(h)
					if ip[12] != 10 || ip[13] != 0 || ip[14] != 5 {
						t.Errorf("Host escaped bounded /24 window: %s", h)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.cidr, err)
			}
			self := net.ParseIP(tt.selfIP).To4()
			ipNetWithSelf := &net.IPNet{
				IP:   self,
				Mask: ipNet.Mask,
			}

			hosts := GenerateSubnetHosts(ipNetWithSelf, 256)
			if len(hosts) != tt.expectedCount {
				t.Fatalf("Expected %d hosts, got %d", tt.expectedCount, len(hosts))
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, hosts)
			}
		})
	}
}

// MockAdapter for testing scanner cancellation and isolation
type mockAdapter struct {
	iface *platform.InterfaceInfo
}

func (m *mockAdapter) GetDefaultInterface() (*platform.InterfaceInfo, error) {
	return m.iface, nil
}
func (m *mockAdapter) GetDefaultGateway() (net.IP, error) {
	return net.ParseIP("192.168.1.1"), nil
}
func (m *mockAdapter) GetDNSServers() ([]string, error) {
	return []string{"1.1.1.1"}, nil
}
func (m *mockAdapter) GetARPTable() ([]platform.NeighborEntry, error) {
	return nil, nil
}
func (m *mockAdapter) GetRouteStatus() (platform.RouteStatus, error) {
	return platform.RouteStatus{
		HasDefaultRoute: true,
		IsPrimary:       true,
		GatewayIP:       net.ParseIP("192.168.1.1"),
		InterfaceName:   "eth0",
		Details:         "Verified primary default route on eth0",
	}, nil
}
func (m *mockAdapter) IsElevated() bool {
	return false
}

func TestPrepareSweepPlan(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.5.0/24")
	ipNet.IP = net.ParseIP("192.168.5.42").To4()

	adapter := &mockAdapter{
		iface: &platform.InterfaceInfo{
			Name: "eth0",
			IsUp: true,
			IPs:  []net.IPNet{*ipNet},
		},
	}

	scanner := NewScanner(adapter)
	plan, err := scanner.PrepareSweepPlan()
	if err != nil {
		t.Fatalf("PrepareSweepPlan failed: %v", err)
	}

	if plan.InterfaceName != "eth0" {
		t.Errorf("Expected interface eth0, got %s", plan.InterfaceName)
	}
	if plan.LocalIP != "192.168.5.42" {
		t.Errorf("Expected local IP 192.168.5.42, got %s", plan.LocalIP)
	}
	if plan.CIDR != "192.168.5.0/24" {
		t.Errorf("Expected CIDR 192.168.5.0/24, got %s", plan.CIDR)
	}
	if plan.TargetCount != 253 {
		t.Errorf("Expected 253 targets, got %d", plan.TargetCount)
	}
	if len(plan.Targets) != 253 {
		t.Errorf("Expected 253 targets in slice, got %d", len(plan.Targets))
	}
	if plan.MaxRate != 15 {
		t.Errorf("Expected MaxRate 15, got %d", plan.MaxRate)
	}
	if plan.MaxConcurrency != 3 {
		t.Errorf("Expected MaxConcurrency 3, got %d", plan.MaxConcurrency)
	}
}

func TestExecuteSweepPlanCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	ipNet.IP = net.ParseIP("192.168.1.50").To4()

	adapter := &mockAdapter{
		iface: &platform.InterfaceInfo{
			Name: "eth0",
			IsUp: true,
			IPs:  []net.IPNet{*ipNet},
		},
	}

	scanner := NewScanner(adapter)
	plan, err := scanner.PrepareSweepPlan()
	if err != nil {
		t.Fatalf("PrepareSweepPlan failed: %v", err)
	}

	// Cancel after short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err = scanner.ExecuteSweepPlan(ctx, plan, nil)
	elapsed := time.Since(start)

	if err != context.Canceled {
		t.Logf("ExecuteSweepPlan finished with error: %v", err)
	}

	// Should stop promptly after cancel, well before scanning all 253 targets at 15 pkts/sec (which would take ~17s)
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Sweep did not abort promptly on cancellation, took: %v", elapsed)
	}
}

func TestRunGentleSweepCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	ipNet.IP = net.ParseIP("192.168.1.50").To4()

	adapter := &mockAdapter{
		iface: &platform.InterfaceInfo{
			Name: "eth0",
			IsUp: true,
			IPs:  []net.IPNet{*ipNet},
		},
	}

	scanner := NewScanner(adapter)

	start := time.Now()
	err := scanner.RunGentleSweep(ctx, nil)
	elapsed := time.Since(start)

	if err != nil && err != context.Canceled {
		t.Logf("Sweep returned expected cancellation note: %v", err)
	}

	if elapsed > 300*time.Millisecond {
		t.Errorf("Cancelled sweep took too long to exit: %v", elapsed)
	}
}
