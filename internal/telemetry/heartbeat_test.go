package telemetry

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"argus/internal/config"
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
