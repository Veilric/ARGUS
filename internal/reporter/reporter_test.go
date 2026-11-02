package reporter

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"argus/internal/config"
	"argus/internal/diagnostics"
	"argus/internal/discovery"
	"argus/internal/platform"
	"argus/internal/telemetry"
)

type mockAdapter struct{}

func (m *mockAdapter) GetDefaultInterface() (*platform.InterfaceInfo, error) {
	return &platform.InterfaceInfo{
		Name:         "eth0",
		HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		IsUp:         true,
	}, nil
}
func (m *mockAdapter) GetDefaultGateway() (net.IP, error) {
	return net.ParseIP("192.168.1.1"), nil
}
func (m *mockAdapter) GetDNSServers() ([]string, error) {
	return []string{"1.1.1.1", "8.8.8.8"}, nil
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
		Details:         "System-wide default route",
	}, nil
}
func (m *mockAdapter) IsElevated() bool {
	return false
}

func TestExportReport_GeneratesFilesAndPreventsCollision(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "argus-report-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &config.Config{
		ReportDir: tmpDir,
	}
	adapter := &mockAdapter{}
	status := telemetry.PipelineStatus{
		LinkOK:        true,
		GatewayOK:     true,
		GatewayState:  "REACHABLE",
		GatewayMethod: "TCP SYN-ACK (port 80)",
		GatewayRTT:    2 * time.Millisecond,
		DNSOK:         true,
		DNSRTT:        5 * time.Millisecond,
		DNSServer:     "1.1.1.1",
		InternetOK:    true,
		InternetRTT:   15 * time.Millisecond,
		CaptiveState:  "CLEAN",
	}

	diagResults := []diagnostics.DiagnosticResult{
		{
			ID:          "ip_conflict",
			Title:       "IP Conflict Check",
			Category:    diagnostics.CategoryHealthy,
			Severity:    diagnostics.SeverityNone,
			Summary:     "No conflicting IP observed",
			Remediation: "",
		},
	}

	devices := []*discovery.Device{
		{
			IP:        "192.168.1.10",
			MAC:       "AA:BB:CC:DD:EE:01",
			Vendor:    "TestVendor",
			Interface: "eth0",
			State:     "REACHABLE",
		},
	}

	logs := []string{"[INFO] Telemetry started"}

	// 1. Export First Report
	md1, json1, err := ExportReport(cfg, adapter, status, diagResults, devices, logs, tmpDir)
	if err != nil {
		t.Fatalf("First ExportReport failed: %v", err)
	}
	if _, err := os.Stat(md1); os.IsNotExist(err) {
		t.Fatalf("Markdown report not found on disk: %s", md1)
	}
	if _, err := os.Stat(json1); os.IsNotExist(err) {
		t.Fatalf("JSON report not found on disk: %s", json1)
	}

	// Read and verify JSON report content
	jsonData, err := os.ReadFile(json1)
	if err != nil {
		t.Fatalf("Failed to read JSON report: %v", err)
	}
	var parsedReport IncidentReport
	if err := json.Unmarshal(jsonData, &parsedReport); err != nil {
		t.Fatalf("Failed to unmarshal JSON report: %v", err)
	}
	if parsedReport.Brand != "ARGUS by Veilric" {
		t.Errorf("Expected Brand 'ARGUS by Veilric', got %q", parsedReport.Brand)
	}
	if len(parsedReport.Diagnostics) != 1 || parsedReport.Diagnostics[0].ID != "ip_conflict" {
		t.Errorf("Diagnostic findings mismatched in JSON: %v", parsedReport.Diagnostics)
	}

	// Read and verify Markdown report content
	mdData, err := os.ReadFile(md1)
	if err != nil {
		t.Fatalf("Failed to read MD report: %v", err)
	}
	mdContent := string(mdData)
	if !strings.Contains(mdContent, "ARGUS by Veilric") {
		t.Errorf("Expected 'ARGUS by Veilric' branding in Markdown report")
	}
	if !strings.Contains(mdContent, "TCP SYN-ACK (port 80)") {
		t.Errorf("Expected gateway probe method in Markdown report")
	}

	// 2. Export Second Report immediately (tests filename collision avoidance)
	md2, json2, err := ExportReport(cfg, adapter, status, diagResults, devices, logs, tmpDir)
	if err != nil {
		t.Fatalf("Second ExportReport failed: %v", err)
	}

	if md1 == md2 {
		t.Fatalf("Collision detection failed! md1 == md2: %s", md1)
	}
	if json1 == json2 {
		t.Fatalf("Collision detection failed! json1 == json2: %s", json1)
	}
	if !strings.Contains(filepath.Base(md2), "_1.md") {
		t.Errorf("Expected collision suffix '_1.md' in md2, got: %s", md2)
	}
}
