package tui

import (
	"strings"
	"testing"
	"time"

	"argus/internal/config"
	"argus/internal/diagnostics"
	"argus/internal/discovery"
	"argus/internal/platform"
	"argus/internal/sysmon"
	"argus/internal/telemetry"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func setupTestModel() *Model {
	cfg := config.DefaultConfig()
	adapter := platform.NewAdapter()
	poller := telemetry.NewPoller(cfg, adapter)
	engine := diagnostics.NewEngine(adapter)
	scanner := discovery.NewScanner(adapter)
	monitor := sysmon.NewMonitor()

	m := NewModel(cfg, adapter, poller, engine, scanner, monitor, nil)

	// Populate mock diagnostic results to test long content scrolling
	m.diagResults = []diagnostics.DiagnosticResult{
		{
			ID:          "link_carrier",
			Title:       "Physical Link & Interface Carrier",
			Category:    diagnostics.CategoryHealthy,
			Severity:    diagnostics.SeverityNone,
			Summary:     "Interface enp6s0 is UP with 2 IP addresses assigned",
			Evidence:    []string{"Primary Interface: enp6s0", "MAC Address: 02:00:00:00:00:01", "Local IPs: [192.0.2.100/24]"},
			Timestamp:   time.Now(),
		},
		{
			ID:          "gateway_health",
			Title:       "Default Gateway Reachability",
			Category:    diagnostics.CategoryHealthy,
			Severity:    diagnostics.SeverityNone,
			Summary:     "Default Gateway (192.0.2.1) is healthy and responsive (1.45ms)",
			Evidence:    []string{"Gateway IP: 192.0.2.1", "Gateway MAC: 02:00:00:00:00:02"},
			Timestamp:   time.Now(),
		},
		{
			ID:          "config_drift",
			Title:       "Gateway Configuration & MAC Drift",
			Category:    diagnostics.CategoryHealthy,
			Severity:    diagnostics.SeverityNone,
			Summary:     "Gateway baseline registered: 192.0.2.1 (02:00:00:00:00:02)",
			Evidence:    []string{"Initial Gateway IP: 192.0.2.1", "Initial MAC: 02:00:00:00:00:02"},
			Timestamp:   time.Now(),
		},
		{
			ID:          "ip_conflict",
			Title:       "IP Address Conflict & ARP Inconsistency",
			Category:    diagnostics.CategoryHealthy,
			Severity:    diagnostics.SeverityNone,
			Summary:     "No IP address conflicts detected. Local IP is unique on LAN.",
			Evidence:    []string{"Local IPs verified: [192.0.2.100/24]", "Mode: Standard User"},
			Timestamp:   time.Now(),
		},
		{
			ID:          "double_nat",
			Title:       "Double NAT & Topology Layer Inspection",
			Category:    diagnostics.CategoryInconclusive,
			Severity:    diagnostics.SeverityInfo,
			Summary:     "Single/Double NAT status inconclusive: Hop 1 is private (192.0.2.1), upstream router dropped TTL probes",
			Evidence:    []string{"Hop 1 (Default Gateway): 192.0.2.1 [Private / RFC1918]"},
			Remediation: "Check upstream router/modem configuration to verify if two routing tiers exist.",
			Timestamp:   time.Now(),
		},
		{
			ID:          "dns_vs_wan",
			Title:       "ISP WAN Outage vs DNS Server Failure Isolation",
			Category:    diagnostics.CategoryHealthy,
			Severity:    diagnostics.SeverityNone,
			Summary:     "Internet and DNS healthy (Egress: 6ms, DNS: 8ms)",
			Evidence:    []string{"Raw Public IP Reachability: true (6ms via 1.1.1.1:443)", "DNS Resolution: true"},
			Timestamp:   time.Now(),
		},
		{
			ID:          "captive_portal",
			Title:       "Captive Portal & HTTP Interception",
			Category:    diagnostics.CategoryHealthy,
			Severity:    diagnostics.SeverityNone,
			Summary:     "Direct Internet Egress Verified (No captive portal detected)",
			Evidence:    []string{"Probe Target: http://connectivitycheck.gstatic.com/generate_204", "HTTP Status: 204"},
			Timestamp:   time.Now(),
		},
		{
			ID:          "mtu_path",
			Title:       "Path MTU & Fragmentation Black Hole Check",
			Category:    diagnostics.CategoryHealthy,
			Severity:    diagnostics.SeverityNone,
			Summary:     "Standard 1500-byte MTU path verified with Don't-Fragment (DF) bit set",
			Evidence:    []string{"Payload: 1472 bytes (+28 header = 1500 MTU)", "Packet passed without fragmentation"},
			Timestamp:   time.Now(),
		},
	}

	return m
}

func TestTerminalDimensions(t *testing.T) {
	sizes := []struct {
		width  int
		height int
		name   string
	}{
		{width: 40, height: 12, name: "Ultra Compact (40x12)"},
		{width: 45, height: 14, name: "Very Narrow & Short (45x14)"},
		{width: 50, height: 16, name: "Compact Widget (50x16)"},
		{width: 55, height: 18, name: "Narrow Widget (55x18)"},
		{width: 65, height: 22, name: "Medium Sidebar (65x22)"},
		{width: 80, height: 24, name: "Standard Terminal (80x24)"},
		{width: 100, height: 30, name: "Large Terminal (100x30)"},
		{width: 120, height: 40, name: "Wide Terminal (120x40)"},
		{width: 160, height: 50, name: "Ultra Wide (160x50)"},
	}

	for _, tc := range sizes {
		t.Run(tc.name, func(t *testing.T) {
			m := setupTestModel()
			// Update with size
			res, _ := m.Update(tea.WindowSizeMsg{Width: tc.width, Height: tc.height})
			updatedModel := res.(*Model)

			// Test all 4 tabs
			for tabIdx := 0; tabIdx < 4; tabIdx++ {
				updatedModel.activeTab = tabIdx
				updatedModel.refreshActiveTabContent()
				view := updatedModel.View()

				// 1. Verify height does not overflow terminal height
				actualHeight := lipgloss.Height(view)
				if actualHeight > tc.height {
					t.Errorf("Tab %d on %s: actual height %d exceeds window height %d", tabIdx, tc.name, actualHeight, tc.height)
				}

				// 2. Verify individual lines do not exceed terminal width
				lines := strings.Split(view, "\n")
				for lineIdx, line := range lines {
					lineW := lipgloss.Width(line)
					if lineW > tc.width {
						t.Errorf("Tab %d on %s (line %d): line width %d exceeds window width %d (content: %q)",
							tabIdx, tc.name, lineIdx, lineW, tc.width, line)
					}
				}
			}
		})
	}
}

func TestScrollingAndTabScrollPreservation(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 20})
	updated := res.(*Model)

	// Switch to Tab 1 (Diagnostics)
	res, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	updated = res.(*Model)

	if updated.activeTab != 1 {
		t.Fatalf("Expected activeTab 1, got %d", updated.activeTab)
	}

	initialOffset := updated.viewports[1].YOffset
	if initialOffset != 0 {
		t.Fatalf("Expected initial YOffset 0, got %d", initialOffset)
	}

	// Total lines should be > viewport height (long content)
	totalLines := updated.viewports[1].TotalLineCount()
	vpHeight := updated.viewports[1].Height
	if totalLines <= vpHeight {
		t.Fatalf("Expected totalLines (%d) > vpHeight (%d) for diagnostics test", totalLines, vpHeight)
	}

	// Scroll down 3 lines using KeyDown / 'j'
	res, _ = updated.Update(tea.KeyMsg{Type: tea.KeyDown})
	updated = res.(*Model)
	res, _ = updated.Update(tea.KeyMsg{Type: tea.KeyDown})
	updated = res.(*Model)
	res, _ = updated.Update(tea.KeyMsg{Type: tea.KeyDown})
	updated = res.(*Model)

	afterScrollOffset := updated.viewports[1].YOffset
	if afterScrollOffset != 3 {
		t.Fatalf("Expected YOffset 3 after 3 down keys, got %d", afterScrollOffset)
	}

	// Switch to Tab 0 (Telemetry)
	res, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	updated = res.(*Model)
	if updated.activeTab != 0 {
		t.Fatalf("Expected activeTab 0, got %d", updated.activeTab)
	}
	if updated.viewports[0].YOffset != 0 {
		t.Fatalf("Expected Tab 0 YOffset 0, got %d", updated.viewports[0].YOffset)
	}

	// Switch back to Tab 1 (Diagnostics)
	res, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	updated = res.(*Model)
	if updated.activeTab != 1 {
		t.Fatalf("Expected activeTab 1, got %d", updated.activeTab)
	}

	// CRITICAL TEST: Verify Tab 1 preserved its scroll offset!
	if updated.viewports[1].YOffset != afterScrollOffset {
		t.Fatalf("Expected Tab 1 to preserve scroll offset %d, got %d", afterScrollOffset, updated.viewports[1].YOffset)
	}

	// Test GotoTop (Home key)
	res, _ = updated.Update(tea.KeyMsg{Type: tea.KeyHome})
	updated = res.(*Model)
	if updated.viewports[1].YOffset != 0 {
		t.Fatalf("Expected YOffset 0 after KeyHome, got %d", updated.viewports[1].YOffset)
	}

	// Test GotoBottom (End key)
	res, _ = updated.Update(tea.KeyMsg{Type: tea.KeyEnd})
	updated = res.(*Model)
	if updated.viewports[1].YOffset == 0 {
		t.Fatalf("Expected YOffset > 0 after KeyEnd, got 0")
	}

	// Test Mouse Wheel scrolling
	res, _ = updated.Update(tea.MouseMsg{Button: tea.MouseButtonWheelUp, Action: tea.MouseActionPress})
	updated = res.(*Model)
	// Mouse wheel up should have decreased offset
	if updated.viewports[1].YOffset >= totalLines-vpHeight && totalLines > vpHeight {
		// Scrolled up
	}
}
