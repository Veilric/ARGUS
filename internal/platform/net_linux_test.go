//go:build linux

package platform

import (
	"strings"
	"testing"
)

func TestParseDefaultRoute_InterfaceIsolation(t *testing.T) {
	// Querying a non-existent or unrouted interface should yield an explicit error
	// and must NOT silently fall back to whatever default gateway exists on another interface!
	gw, iface, err := parseDefaultRoute("argus_dummy_nonexistent_iface")
	if err == nil {
		t.Fatalf("Expected error for nonexistent interface route, got gw=%v iface=%s", gw, iface)
	}

	if !strings.Contains(err.Error(), "no default gateway route found for interface") {
		t.Errorf("Expected route isolation error message, got: %v", err)
	}
}

func TestLinuxAdapter_InterfaceFiltering(t *testing.T) {
	adapter := NewAdapter("argus_dummy_nonexistent_iface")
	_, err := adapter.GetDefaultGateway()
	if err == nil {
		t.Fatalf("Expected error getting default gateway on dummy interface, got nil")
	}

	// Neighbor/ARP table filtering should yield empty slice for nonexistent interface
	neighbors, err := adapter.GetARPTable()
	if err != nil {
		t.Logf("GetARPTable returned note: %v", err)
	}
	for _, n := range neighbors {
		if n.Interface != "argus_dummy_nonexistent_iface" {
			t.Errorf("ARP table contained neighbor for wrong interface: %s (expected argus_dummy_nonexistent_iface)", n.Interface)
		}
	}
}

func TestLinuxAdapter_GetRouteStatus_Isolation(t *testing.T) {
	adapter := NewAdapter("argus_dummy_nonexistent_iface")
	status, err := adapter.GetRouteStatus()
	if err != nil {
		t.Fatalf("Unexpected error from GetRouteStatus: %v", err)
	}

	if status.HasDefaultRoute {
		t.Errorf("Expected HasDefaultRoute = false for dummy interface")
	}
	if status.IsPrimary {
		t.Errorf("Expected IsPrimary = false for dummy interface")
	}
	if !strings.Contains(status.Details, "No default gateway route configured") {
		t.Errorf("Expected missing route details, got: %s", status.Details)
	}
}
