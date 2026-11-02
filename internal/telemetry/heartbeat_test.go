package telemetry

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"argus/internal/config"
	"argus/internal/dhcp"
	"argus/internal/platform"
)

type mockAttributionAdapter struct {
	iface       *platform.InterfaceInfo
	routeStatus platform.RouteStatus
}

func (m *mockAttributionAdapter) GetDefaultInterface() (*platform.InterfaceInfo, error) {
	return m.iface, nil
}
func (m *mockAttributionAdapter) GetDefaultGateway() (net.IP, error) {
	return m.routeStatus.GatewayIP, nil
}
func (m *mockAttributionAdapter) GetDNSServers() ([]string, error) {
	return []string{"1.1.1.1"}, nil
}
func (m *mockAttributionAdapter) GetARPTable() ([]platform.NeighborEntry, error) {
	return nil, nil
}
func (m *mockAttributionAdapter) GetRouteStatus() (platform.RouteStatus, error) {
	return m.routeStatus, nil
}
func (m *mockAttributionAdapter) IsElevated() bool {
	return false
}

// Regression Test 13: Selected-interface diagnostics do not silently use another interface's connectivity as verified evidence.
func TestHeartbeatAttribution_UnroutedInterfaceUnverified(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.50.0.5/24")
	adapter := &mockAttributionAdapter{
		iface: &platform.InterfaceInfo{
			Name: "eth_isolated",
			IsUp: true,
			IPs:  []net.IPNet{*ipNet},
		},
		routeStatus: platform.RouteStatus{
			HasDefaultRoute: false,
			IsPrimary:       false,
			InterfaceName:   "eth_isolated",
			Details:         "No default gateway route configured on selected interface eth_isolated",
		},
	}

	cfg := config.DefaultConfig()
	poller := NewPoller(cfg, adapter)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	status := poller.ProbeOnce(ctx)

	// Since the selected interface has no default gateway route,
	// attribution must be UNVERIFIED and not falsely claimed as verified.
	if status.Attribution != "UNVERIFIED" {
		t.Errorf("Expected Attribution to be UNVERIFIED for unrouted interface, got: %s", status.Attribution)
	}
	if !strings.Contains(status.AttributionDetails, "No default gateway route") {
		t.Errorf("Expected AttributionDetails to state missing default route, got: %s", status.AttributionDetails)
	}
}

// Regression Test 14: Verified interface attribution when adapter is primary default route.
func TestHeartbeatAttribution_PrimaryInterfaceVerified(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.100/24")
	adapter := &mockAttributionAdapter{
		iface: &platform.InterfaceInfo{
			Name: "eth0",
			IsUp: true,
			IPs:  []net.IPNet{*ipNet},
		},
		routeStatus: platform.RouteStatus{
			HasDefaultRoute: true,
			IsPrimary:       true,
			GatewayIP:       net.ParseIP("192.168.1.1"),
			InterfaceName:   "eth0",
			Metric:          100,
			Details:         "Selected interface eth0 is primary default route (metric 100)",
		},
	}

	cfg := config.DefaultConfig()
	poller := NewPoller(cfg, adapter)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	status := poller.ProbeOnce(ctx)

	if status.Attribution != "SELECTED_INTERFACE" {
		t.Errorf("Expected Attribution to be SELECTED_INTERFACE, got: %s", status.Attribution)
	}
	if !strings.Contains(status.AttributionDetails, "primary default route") {
		t.Errorf("Expected primary default route details, got: %s", status.AttributionDetails)
	}
}

type mockHeartbeatDHCPInspector struct {
	cfg *dhcp.DHCPConfig
}

func (m *mockHeartbeatDHCPInspector) Inspect(ifaceName string) (*dhcp.DHCPConfig, error) {
	return m.cfg, nil
}

func TestHeartbeat_BaselineTouchDoesNotRewriteDisk(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, err := dhcp.NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create baseline store: %v", err)
	}

	_, ipNet, _ := net.ParseCIDR("192.168.1.100/24")
	adapter := &mockAttributionAdapter{
		iface: &platform.InterfaceInfo{
			Name: "eth0",
			IsUp: true,
			IPs:  []net.IPNet{*ipNet},
		},
		routeStatus: platform.RouteStatus{
			HasDefaultRoute: true,
			IsPrimary:       true,
			GatewayIP:       net.ParseIP("192.168.1.1"),
			InterfaceName:   "eth0",
		},
	}

	cfg := config.DefaultConfig()
	poller := NewPoller(cfg, adapter)

	dhcpCfg := &dhcp.DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "192.168.1.100",
		GatewayIP:     "192.168.1.1",
		Assignment:    dhcp.AssignmentDHCP,
	}
	inspector := &mockHeartbeatDHCPInspector{cfg: dhcpCfg}
	poller.SetDHCPComponents(store, inspector)

	ctx := context.Background()

	// Probe 1: establishes initial baseline
	poller.ProbeOnce(ctx)

	fiBefore, _ := os.Stat(dbPath)
	modBefore := fiBefore.ModTime()

	// Probes 2..4: routine unchanged checks
	for i := 0; i < 3; i++ {
		poller.ProbeOnce(ctx)
	}

	fiAfter, _ := os.Stat(dbPath)
	if !fiAfter.ModTime().Equal(modBefore) {
		t.Errorf("baseline file was rewritten to disk during routine heartbeat probes! Before: %v, After: %v", modBefore, fiAfter.ModTime())
	}
}

func TestHeartbeat_RecurringConfigChangesEmitted(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, _ := dhcp.NewBaselineStore(dbPath)

	_, ipNet, _ := net.ParseCIDR("192.168.1.100/24")
	adapter := &mockAttributionAdapter{
		iface: &platform.InterfaceInfo{
			Name: "eth0",
			IsUp: true,
			IPs:  []net.IPNet{*ipNet},
		},
		routeStatus: platform.RouteStatus{
			HasDefaultRoute: true,
			IsPrimary:       true,
			GatewayIP:       net.ParseIP("192.168.1.1"),
			InterfaceName:   "eth0",
		},
	}

	cfg := config.DefaultConfig()
	poller := NewPoller(cfg, adapter)

	initialDHCP := &dhcp.DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "192.168.1.100",
		GatewayIP:     "192.168.1.1",
		Assignment:    dhcp.AssignmentDHCP,
	}
	inspector := &mockHeartbeatDHCPInspector{cfg: initialDHCP}
	poller.SetDHCPComponents(store, inspector)

	ctx := context.Background()
	poller.ProbeOnce(ctx) // establish initial baseline (Gateway: 192.168.1.1)

	// Step 1: Gateway changes to 192.168.1.254 (A -> B)
	driftedDHCP := &dhcp.DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "192.168.1.100",
		GatewayIP:     "192.168.1.254",
		Assignment:    dhcp.AssignmentDHCP,
	}
	inspector.cfg = driftedDHCP
	poller.ProbeOnce(ctx)

	logs := poller.EventLogs()
	foundDrift := false
	for _, l := range logs {
		if strings.Contains(l, "[CONFIG] Default gateway changed") {
			foundDrift = true
			break
		}
	}
	if !foundDrift {
		t.Fatalf("expected [CONFIG] drift log event, logs: %v", logs)
	}

	// Step 2: Second probe with same drifted gateway (B -> B)
	logCountBefore := len(poller.EventLogs())
	poller.ProbeOnce(ctx)
	if len(poller.EventLogs()) != logCountBefore {
		t.Errorf("duplicate drift should not have added new log entries: before %d, after %d", logCountBefore, len(poller.EventLogs()))
	}

	// Step 3: Gateway restores to 192.168.1.1 (B -> A)
	inspector.cfg = initialDHCP
	poller.ProbeOnce(ctx)

	logs = poller.EventLogs()
	foundRecov := false
	for _, l := range logs {
		if strings.Contains(l, "[RECOV]") && strings.Contains(strings.ToLower(l), "default gateway restored to baseline value") {
			foundRecov = true
			break
		}
	}
	if !foundRecov {
		t.Errorf("expected [RECOV] restoration log event, logs: %v", logs)
	}

	// Step 4: Gateway drifts again to 192.168.1.254 (A -> B recurring)
	inspector.cfg = driftedDHCP
	poller.ProbeOnce(ctx)

	logs = poller.EventLogs()
	lastLog := logs[len(logs)-1]
	if !strings.Contains(lastLog, "[CONFIG] Default gateway changed") {
		t.Errorf("expected new [CONFIG] alert for recurring drift, got: %s", lastLog)
	}
}
