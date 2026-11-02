package diagnostics

import (
	"context"
	"strings"
	"testing"
	"time"

	"argus/internal/dhcp"
)

func TestDHCPIntelligenceCheck_Unavailable_ReturnsInconclusive(t *testing.T) {
	check := NewDHCPIntelligenceCheck(nil, nil)
	netCtx := &NetworkContext{
		InterfaceName: "eth0",
		DHCPConfig:    nil,
		Baseline:      nil,
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Category != CategoryInconclusive {
		t.Errorf("expected CategoryInconclusive when DHCP data is unavailable, got %v", res.Category)
	}
	if !strings.Contains(res.Summary, "inconclusive") {
		t.Errorf("expected summary to mention inconclusive, got %q", res.Summary)
	}
}

func TestDHCPIntelligenceCheck_MatchesBaseline_ReturnsHealthy(t *testing.T) {
	check := NewDHCPIntelligenceCheck(nil, nil)
	baseline := &dhcp.ConfigBaseline{
		InterfaceName: "eth0",
		Assignment:    dhcp.AssignmentDHCP,
		IPv4Address:   "192.168.1.50",
		IPv4Prefix:    24,
		GatewayIP:     "192.168.1.1",
		DNSServers:    []string{"192.168.1.1"},
		DHCPServerIP:  "192.168.1.1",
		EstablishedAt: time.Now().Add(-2 * time.Hour),
		LastSeenAt:    time.Now(),
	}

	cfg := &dhcp.DHCPConfig{
		InterfaceName: "eth0",
		Assignment:    dhcp.AssignmentDHCP,
		IPv4Address:   "192.168.1.50",
		IPv4Prefix:    24,
		GatewayIP:     "192.168.1.1",
		DNSServers:    []string{"192.168.1.1"},
		DHCPServerIP:  "192.168.1.1",
		ObservedAt:    time.Now(),
	}

	netCtx := &NetworkContext{
		InterfaceName: "eth0",
		DHCPConfig:    cfg,
		Baseline:      baseline,
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Category != CategoryHealthy {
		t.Errorf("expected CategoryHealthy when matching baseline, got %v", res.Category)
	}
}

func TestDHCPIntelligenceCheck_DHCPServerDrift_SuspectedAnomaly(t *testing.T) {
	check := NewDHCPIntelligenceCheck(nil, nil)
	baseline := &dhcp.ConfigBaseline{
		InterfaceName: "eth0",
		Assignment:    dhcp.AssignmentDHCP,
		IPv4Address:   "192.168.1.50",
		IPv4Prefix:    24,
		GatewayIP:     "192.168.1.1",
		DNSServers:    []string{"192.168.1.1"},
		DHCPServerIP:  "192.168.1.1",
	}

	// New DHCP server offering leases (e.g. Deco mesh in router mode or secondary router)
	cfg := &dhcp.DHCPConfig{
		InterfaceName: "eth0",
		Assignment:    dhcp.AssignmentDHCP,
		IPv4Address:   "192.168.68.105",
		IPv4Prefix:    24,
		GatewayIP:     "192.168.68.1",
		DNSServers:    []string{"192.168.68.1"},
		DHCPServerIP:  "192.168.68.1",
		ObservedAt:    time.Now(),
	}

	netCtx := &NetworkContext{
		InterfaceName: "eth0",
		DHCPConfig:    cfg,
		Baseline:      baseline,
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Category != CategorySuspected {
		t.Errorf("expected CategorySuspected, got %v", res.Category)
	}
	if res.Severity != SeverityWarning {
		t.Errorf("expected SeverityWarning for DHCP server change, got %v", res.Severity)
	}
	if !strings.Contains(res.Summary, "SUSPECTED DHCP ANOMALY") {
		t.Errorf("expected summary to indicate SUSPECTED DHCP ANOMALY, got %q", res.Summary)
	}
	// Verify it does NOT claim unproven rogue server
	if strings.Contains(strings.ToLower(res.Summary), "confirmed rogue") {
		t.Errorf("diagnostic should not declare confirmed rogue server, got %q", res.Summary)
	}
}

func TestDHCPIntelligenceCheck_GatewayDrift_SuspectedWarning(t *testing.T) {
	check := NewDHCPIntelligenceCheck(nil, nil)
	baseline := &dhcp.ConfigBaseline{
		InterfaceName: "eth0",
		Assignment:    dhcp.AssignmentDHCP,
		IPv4Address:   "192.168.1.50",
		IPv4Prefix:    24,
		GatewayIP:     "192.168.1.1",
		DHCPServerIP:  "192.168.1.1",
	}

	// Only gateway shifted
	cfg := &dhcp.DHCPConfig{
		InterfaceName: "eth0",
		Assignment:    dhcp.AssignmentDHCP,
		IPv4Address:   "192.168.1.50",
		IPv4Prefix:    24,
		GatewayIP:     "192.168.1.254",
		DHCPServerIP:  "192.168.1.1",
		ObservedAt:    time.Now(),
	}

	netCtx := &NetworkContext{
		InterfaceName: "eth0",
		DHCPConfig:    cfg,
		Baseline:      baseline,
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Category != CategorySuspected {
		t.Errorf("expected CategorySuspected, got %v", res.Category)
	}
	if !strings.Contains(res.Summary, "SUSPECTED GATEWAY DRIFT") {
		t.Errorf("expected summary to indicate SUSPECTED GATEWAY DRIFT, got %q", res.Summary)
	}
}

func TestDHCPIntelligenceCheck_DHCPServerDiffersFromGateway_EvidenceNotice(t *testing.T) {
	check := NewDHCPIntelligenceCheck(nil, nil)
	cfg := &dhcp.DHCPConfig{
		InterfaceName: "eth0",
		Assignment:    dhcp.AssignmentDHCP,
		IPv4Address:   "10.0.0.15",
		IPv4Prefix:    24,
		GatewayIP:     "10.0.0.1",
		DHCPServerIP:  "10.0.0.254", // Centralized DHCP relay/server
		ObservedAt:    time.Now(),
	}

	netCtx := &NetworkContext{
		InterfaceName: "eth0",
		DHCPConfig:    cfg,
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundNotice := false
	for _, ev := range res.Evidence {
		if strings.Contains(ev, "Architecture Notice: DHCP Server (10.0.0.254) differs from Default Gateway (10.0.0.1)") {
			foundNotice = true
			break
		}
	}
	if !foundNotice {
		t.Errorf("expected evidence to contain architecture notice about differing DHCP and Gateway IPs")
	}
}
