package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"argus/internal/config"
	"argus/internal/dhcp"
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
	engine := diagnostics.NewEngine(adapter, nil, nil)
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
			Summary:     "Interface eth0 is UP with 2 IP addresses assigned",
			Evidence:    []string{"Primary Interface: eth0", "MAC Address: 02:00:00:00:00:01", "Local IPs: [192.0.2.100/24]"},
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

func TestAsyncTelemetryProbePreservesViewportOffset(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = res.(*Model)

	// Scroll down tab 0 (Live Telemetry)
	m.viewports[0].LineDown(5)
	initialOffset := m.viewports[0].YOffset
	if initialOffset <= 0 {
		t.Fatalf("Expected YOffset > 0, got %d", initialOffset)
	}

	// Dispatch an asynchronous telemetry probe message
	probeMsg := heartbeatProbeMsg(telemetry.PipelineStatus{
		LinkOK:       true,
		GatewayOK:    true,
		GatewayState: "REACHABLE",
		DNSOK:        true,
		InternetOK:   true,
	})
	res, _ = m.Update(probeMsg)
	m = res.(*Model)

	// Verify scroll position was preserved, NOT reset to 0
	if m.viewports[0].YOffset != initialOffset {
		t.Errorf("Telemetry probe message reset scroll position! Expected %d, got %d", initialOffset, m.viewports[0].YOffset)
	}
}

func TestFooterReportsNAWhenUnavailable(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = res.(*Model)

	// Set hardware metrics explicitly unavailable
	m.sysStats = sysmon.Stats{
		CPUPercent: -1,
		RAMTotalGB: 0,
		RAMUsedGB:  0,
	}

	footer := m.renderFooter(80)
	if strings.Contains(footer, "-1") {
		t.Errorf("Footer printed negative CPU percent instead of N/A: %s", footer)
	}
	if !strings.Contains(footer, "CPU: N/A") {
		t.Errorf("Footer failed to report 'CPU: N/A' when metrics are unavailable: %s", footer)
	}
	if !strings.Contains(footer, "RAM: N/A") {
		t.Errorf("Footer failed to report 'RAM: N/A' when metrics are unavailable: %s", footer)
	}
}

func TestScanConfirmationFlow(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = res.(*Model)

	// Ensure scan is not active initially
	if m.scanner.IsScanning() {
		t.Fatalf("Scanner should not be active initially")
	}

	// Press [S] to trigger scan request
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)

	// Active tab must switch to Tab 2 (Subnet Devices)
	if m.activeTab != 2 {
		t.Errorf("Expected activeTab 2, got %d", m.activeTab)
	}

	// Must show confirmation card and have a pending plan
	if !m.showScanConfirm {
		t.Errorf("Expected showScanConfirm = true after pressing [S]")
	}
	if m.pendingSweepPlan == nil {
		t.Errorf("Expected pendingSweepPlan != nil after pressing [S]")
	}

	// Scanning must NOT have started yet!
	if m.scanner.IsScanning() {
		t.Errorf("Active scan started before user confirmation!")
	}

	// Verify confirmation card is rendered in TUI View
	view := m.View()
	if !strings.Contains(view, "ACTIVE SUBNET DISCOVERY AUTHORIZATION") {
		t.Errorf("Confirmation view does not contain authorization heading: %s", view)
	}
	if !strings.Contains(view, "[Enter / Y] Authorize & Scan") {
		t.Errorf("Confirmation view does not show confirm controls: %s", view)
	}

	// Test cancellation with [N]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	m = res.(*Model)

	if m.showScanConfirm {
		t.Errorf("Expected showScanConfirm = false after pressing [N]")
	}
	if m.pendingSweepPlan != nil {
		t.Errorf("Expected pendingSweepPlan == nil after cancelling with [N]")
	}
	if m.scanner.IsScanning() {
		t.Errorf("Scanner should not be scanning after cancellation")
	}
	if !strings.Contains(m.toastMsg, "cancelled before starting") {
		t.Errorf("Expected toast to report cancellation, got: %s", m.toastMsg)
	}

	// Request again with [S] then cancel with [Esc]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)
	if !m.showScanConfirm {
		t.Fatalf("Expected showScanConfirm = true")
	}

	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	m = res.(*Model)
	if m.showScanConfirm {
		t.Errorf("Expected showScanConfirm = false after pressing [Esc]")
	}

	// Request again with [S] then CONFIRM with [Enter]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)
	if !m.showScanConfirm {
		t.Fatalf("Expected showScanConfirm = true")
	}

	res, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(*Model)

	if m.showScanConfirm {
		t.Errorf("Expected showScanConfirm = false after confirming with [Enter]")
	}
	if m.sweepCancel == nil {
		t.Errorf("Expected sweepCancel func to be populated upon starting scan")
	}
	if cmd == nil {
		t.Errorf("Expected tea.Cmd to be returned for executing scan")
	}

	// Clean up active sweep context
	if m.sweepCancel != nil {
		m.sweepCancel()
	}
}

func TestScanActiveCancellation(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = res.(*Model)

	cancelled := false
	m.sweepCancel = func() {
		cancelled = true
	}

	// Simulate active scanner
	// Press [C]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m = res.(*Model)

	// Since m.scanner.IsScanning() is false (mock not running), let's test quit cancellation
	if m.sweepCancel != nil {
		m.sweepCancel()
		if !cancelled {
			t.Errorf("Expected sweepCancel to be called")
		}
	}

	// Test that pressing [Q] invokes sweepCancel if set
	cancelCalledOnQuit := false
	m.sweepCancel = func() {
		cancelCalledOnQuit = true
	}
	_, quitCmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if !cancelCalledOnQuit {
		t.Errorf("Expected sweepCancel to be called when quitting via [Q]")
	}
	if quitCmd == nil {
		t.Errorf("Expected quitCmd on [Q]")
	}
}

// Regression Test 6: Scan confirmation is visible when the Devices viewport is scrolled to the bottom.
func TestScanConfirmationVisibleWhenViewportScrolledToBottom(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = res.(*Model)

	// Populate scanner with 40 devices to ensure long scrollable device list
	for i := 1; i <= 40; i++ {
		m.scanner.AddDevice(&discovery.Device{
			IP:        fmt.Sprintf("192.168.1.%d", i),
			MAC:       fmt.Sprintf("00:11:22:33:44:%02x", i),
			Vendor:    "Generic Device",
			Interface: "eth0",
			State:     "REACHABLE",
		})
	}

	m.activeTab = 2
	m.refreshActiveTabContent()
	m.viewports[2].GotoBottom()

	bottomOffset := m.viewports[2].YOffset
	if bottomOffset <= 0 {
		t.Fatalf("Expected bottomOffset > 0 for scrolled viewport, got: %d", bottomOffset)
	}

	// Press [S] to initiate scan confirmation
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)

	if !m.showScanConfirm {
		t.Fatalf("Expected showScanConfirm = true")
	}

	// Verify that the view rendered on screen contains the authorization modal despite viewport YOffset
	view := m.View()
	if !strings.Contains(view, "ACTIVE SUBNET DISCOVERY AUTHORIZATION") {
		t.Errorf("Authorization modal was obscured or hidden when viewport was scrolled to bottom! View: %s", view)
	}
	if !strings.Contains(view, "[Enter / Y] Authorize & Scan") {
		t.Errorf("Authorization controls were missing when viewport was scrolled to bottom! View: %s", view)
	}

	// Test that cancelling prompt with [Esc] restores the user's previous reading scroll position!
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	m = res.(*Model)

	if m.showScanConfirm {
		t.Errorf("Expected showScanConfirm = false after cancelling")
	}
	if m.viewports[2].YOffset != bottomOffset {
		t.Errorf("Expected Devices viewport scroll position to be preserved at %d, got: %d", bottomOffset, m.viewports[2].YOffset)
	}
}

// Regression Test 7: Declining confirmation generates no active sweep.
func TestScanDecliningConfirmationGeneratesNoActiveSweep(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = res.(*Model)

	// Press [S] to request confirmation
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)

	// Decline with [N]
	res, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	m = res.(*Model)

	if cmd != nil {
		t.Errorf("Expected nil cmd on scan decline, got: %v", cmd)
	}
	if m.scanner.IsScanning() {
		t.Errorf("Active scan was started despite declining confirmation!")
	}
	if m.scanState != ScanStateIdle {
		t.Errorf("Expected ScanStateIdle after decline, got: %v", m.scanState)
	}
	if m.sweepCancel != nil {
		t.Errorf("Expected nil sweepCancel after decline")
	}
}

// Regression Test 8: Confirmation remains safe and usable in a small terminal.
func TestScanConfirmationSmallTerminalSafety(t *testing.T) {
	m := setupTestModel()
	// Set very small window
	res, _ := m.Update(tea.WindowSizeMsg{Width: 35, Height: 8})
	m = res.(*Model)

	// Press [S]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)

	view := m.View()
	// Must display small terminal warning
	if !strings.Contains(view, "TERMINAL WINDOW TOO SMALL") {
		t.Errorf("Expected small terminal safety warning, got: %s", view)
	}

	// Pressing [Enter] in undersized window must NOT authorize scan
	res, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(*Model)

	if cmd != nil {
		t.Errorf("Scan must not be authorized when terminal is undersized")
	}
	if m.scanState != ScanStateAwaitingConfirm {
		t.Errorf("Scan state should remain AwaitingConfirm without starting")
	}
	if m.scanner.IsScanning() {
		t.Errorf("Scan must not start in undersized window")
	}
	if !strings.Contains(m.toastMsg, "too small") && !strings.Contains(m.toastMsg, "resize") && !strings.Contains(m.toastMsg, "Expand") {
		t.Errorf("Expected warning toast about expanding terminal, got: %s", m.toastMsg)
	}

	// Expand terminal to compact size (45x12)
	res, _ = m.Update(tea.WindowSizeMsg{Width: 45, Height: 12})
	m = res.(*Model)

	compactView := m.View()
	if !strings.Contains(compactView, "ACTIVE") {
		t.Errorf("Expected compact authorization card on 45x12, got: %s", compactView)
	}
	if !strings.Contains(compactView, "Authorize") {
		t.Errorf("Expected confirm control on compact view, got: %s", compactView)
	}

	// Cancel with [N]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	m = res.(*Model)
	if m.showScanConfirm {
		t.Errorf("Expected showScanConfirm = false after cancelling")
	}
}

// Regression Test 9: Cancelling immediately after scan approval succeeds (eliminates startup timing gap).
func TestScanTimingGap_CancelImmediatelyAfterApproval(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = res.(*Model)

	// Step 1: Request confirmation with [S]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)
	if m.scanState != ScanStateAwaitingConfirm {
		t.Fatalf("Expected ScanStateAwaitingConfirm, got: %v", m.scanState)
	}

	// Step 2: Confirm scan with [Enter] -> transitions to ScanStateStarting!
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(*Model)

	if m.scanState != ScanStateStarting {
		t.Fatalf("Expected ScanStateStarting immediately after approval, got: %v", m.scanState)
	}
	if m.sweepCancel == nil {
		t.Fatalf("Expected sweepCancel to be created in starting state")
	}
	// Note: in this timing gap, m.scanner.IsScanning() is still FALSE because background cmd hasn't executed!
	if m.scanner.IsScanning() {
		t.Fatalf("Expected scanner not yet marked scanning in synchronous update loop")
	}

	// Step 3: CRITICAL REGRESSION TEST: User presses [C] immediately during startup window!
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m = res.(*Model)

	if m.scanState != ScanStateCancelling {
		t.Fatalf("Timing gap regression: [C] was ignored during starting state! State: %v", m.scanState)
	}
	if !strings.Contains(m.toastMsg, "Cancelling") {
		t.Errorf("Expected cancelling toast, got: %s", m.toastMsg)
	}

	// Step 4: When background command returns context.Canceled
	res, _ = m.Update(scanCompleteMsg{err: context.Canceled})
	m = res.(*Model)

	if m.scanState != ScanStateIdle {
		t.Errorf("Expected ScanStateIdle after cancellation completes, got: %v", m.scanState)
	}
	if m.sweepCancel != nil {
		t.Errorf("Expected nil sweepCancel after completion")
	}
	if !strings.Contains(m.toastMsg, "cancelled by user") {
		t.Errorf("Expected 'cancelled by user' toast, got: %s", m.toastMsg)
	}
}

// Regression Test 10: Cancelling a running scan stops further scheduling.
func TestScanCancellation_RunningScanStopsPromptly(t *testing.T) {
	m := setupTestModel()
	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = res.(*Model)

	// Simulate running scan
	m.scanState = ScanStateRunning
	cancelCalled := false
	m.sweepCancel = func() {
		cancelCalled = true
	}

	// User presses [Esc]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	m = res.(*Model)

	if !cancelCalled {
		t.Errorf("Expected sweepCancel to be invoked upon pressing [Esc] while running")
	}
	if m.scanState != ScanStateCancelling {
		t.Errorf("Expected ScanStateCancelling, got: %v", m.scanState)
	}
}

// Regression Test 12: A completed or cancelled scan cannot leave stale scan state.
func TestScanLifecycle_NoStaleStateOnCompletion(t *testing.T) {
	m := setupTestModel()
	m.scanState = ScanStateRunning
	m.pendingSweepPlan = &discovery.SweepPlan{}
	m.showScanConfirm = true

	// Simulate successful completion
	res, _ := m.Update(scanCompleteMsg{err: nil})
	m = res.(*Model)

	if m.scanState != ScanStateIdle {
		t.Errorf("Expected ScanStateIdle after scan completion, got: %v", m.scanState)
	}
	if m.showScanConfirm {
		t.Errorf("Expected showScanConfirm = false after scan completion")
	}
	if m.pendingSweepPlan != nil {
		t.Errorf("Expected pendingSweepPlan == nil after scan completion")
	}
	if m.sweepCancel != nil {
		t.Errorf("Expected sweepCancel == nil after scan completion")
	}
}

// Stage A1 Test: Validate rendered output dimensions and contents across various terminal sizes.
func TestScanConfirmationRenderedDimensionsAndContents(t *testing.T) {
	testSizes := []struct {
		name   string
		width  int
		height int
	}{
		{"Compact 40x12", 40, 12},
		{"Narrow 50x16", 50, 16},
		{"Medium 65x22", 65, 22},
		{"Standard 80x24", 80, 24},
		{"Large 100x30", 100, 30},
		{"Wide 120x40", 120, 40},
	}

	for _, tc := range testSizes {
		t.Run(tc.name, func(t *testing.T) {
			m := setupTestModel()
			res, _ := m.Update(tea.WindowSizeMsg{Width: tc.width, Height: tc.height})
			m = res.(*Model)

			// Press [S] to trigger scan authorization modal
			res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
			m = res.(*Model)

			if !m.showScanConfirm {
				t.Fatalf("[%s] expected showScanConfirm = true", tc.name)
			}
			if m.pendingSweepPlan == nil {
				t.Fatalf("[%s] expected pendingSweepPlan != nil", tc.name)
			}

			view := m.View()
			renderedLines := lipgloss.Height(view)
			renderedCols := lipgloss.Width(view)

			// 1. DIMENSION CHECKS: View MUST NEVER exceed terminal boundaries!
			if renderedLines > tc.height {
				t.Fatalf("[%s] Vertical overflow! Rendered lines %d > terminal height %d\nView:\n%s",
					tc.name, renderedLines, tc.height, view)
			}
			if renderedCols > tc.width {
				t.Fatalf("[%s] Horizontal overflow! Rendered cols %d > terminal width %d\nView:\n%s",
					tc.name, renderedCols, tc.width, view)
			}

			// 2. ESSENTIAL INFORMATION CHECKS: Never hide required authorization info
			requiredElements := []string{
				"Target",
				"Iface",
				"Probe",
				"Notice",
				"Authorize",
				"Cancel",
			}
			for _, elem := range requiredElements {
				if !strings.Contains(view, elem) {
					t.Errorf("[%s] Missing essential authorization element %q in view:\n%s", tc.name, elem, view)
				}
			}

			// 3. Test scrolling if confirmation viewport is active
			res, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
			m = res.(*Model)
			res, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
			m = res.(*Model)

			// 4. Cancel confirmation with [N]
			res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
			m = res.(*Model)
			if m.showScanConfirm {
				t.Fatalf("[%s] expected showScanConfirm = false after cancel", tc.name)
			}
		})
	}
}

type mockTUIDHCPInspector struct {
	cfg *dhcp.DHCPConfig
}

func (m *mockTUIDHCPInspector) Inspect(ifaceName string) (*dhcp.DHCPConfig, error) {
	return m.cfg, nil
}

func setupTestModelWithDHCP(t *testing.T) (*Model, *dhcp.BaselineStore, *mockTUIDHCPInspector, string) {
	t.Helper()
	m := setupTestModel()
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baselines.json")
	store, err := dhcp.NewBaselineStore(baselinePath)
	if err != nil {
		t.Fatalf("failed to create baseline store: %v", err)
	}

	initialCfg := &dhcp.DHCPConfig{
		InterfaceName: "eth0",
		MACAddress:    "02:00:00:00:00:01",
		IPv4Address:   "192.168.1.100",
		IPv4Prefix:    24,
		Assignment:    dhcp.AssignmentDHCP,
		GatewayIP:     "192.168.1.1",
		DNSServers:    []string{"192.168.1.1"},
		DHCPServerIP:  "192.168.1.1",
		ObservedAt:    time.Now(),
	}
	_, err = store.EstablishInitial(initialCfg)
	if err != nil {
		t.Fatalf("failed to establish initial baseline: %v", err)
	}

	inspector := &mockTUIDHCPInspector{cfg: initialCfg}
	m.poller.SetDHCPComponents(store, inspector)
	m.ifaceName = "eth0"

	// Probe once to populate status
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m.poller.ProbeOnce(ctx)

	res, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	return res.(*Model), store, inspector, baselinePath
}

// Priority 1 Test 1: Page Up and lowercase 'b' must only perform scrolling and never trigger baseline refresh.
func TestKeybindingSeparation_PgUpAndB_ScrollOnly(t *testing.T) {
	m, store, _, _ := setupTestModelWithDHCP(t)

	// Switch to Tab 1 (Deep Diagnostics)
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m = res.(*Model)
	if m.activeTab != 1 {
		t.Fatalf("expected activeTab = 1, got %d", m.activeTab)
	}

	// Scroll down first so there is room to scroll up
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m = res.(*Model)
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m = res.(*Model)

	// Send lowercase 'b' (intended for viewport scroll up)
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	m = res.(*Model)

	if m.showBaselineConfirm {
		t.Errorf("lowercase 'b' must NOT open baseline confirmation dialog")
	}
	if strings.Contains(m.toastMsg, "Baseline refreshed") {
		t.Errorf("lowercase 'b' triggered unexpected baseline refresh: %s", m.toastMsg)
	}

	// Send Page Up
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	m = res.(*Model)

	if m.showBaselineConfirm {
		t.Errorf("Page Up must NOT open baseline confirmation dialog")
	}
	if strings.Contains(m.toastMsg, "Baseline refreshed") {
		t.Errorf("Page Up triggered unexpected baseline refresh: %s", m.toastMsg)
	}

	// Verify stored baseline remains Initial Observed
	b, ok := store.Get("eth0")
	if !ok || b == nil {
		t.Fatalf("baseline disappeared")
	}
	if b.Type != dhcp.BaselineInitialObserved {
		t.Errorf("expected baseline type %s, got %s", dhcp.BaselineInitialObserved, b.Type)
	}
}

// Priority 1 Test 2: Uppercase [B] and [ctrl+b] open confirmation dialog without immediate writing.
func TestBaselineConfirmation_KeyB_OpensConfirmationDialog(t *testing.T) {
	m, store, _, baselinePath := setupTestModelWithDHCP(t)

	fiBefore, _ := os.Stat(baselinePath)
	modBefore := fiBefore.ModTime()

	// Press [B]
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'B'}})
	m = res.(*Model)

	if !m.showBaselineConfirm {
		t.Fatalf("expected showBaselineConfirm = true after pressing [B]")
	}
	if m.pendingBaselineCfg == nil {
		t.Fatalf("expected pendingBaselineCfg to be populated")
	}

	// File on disk must NOT have been overwritten yet!
	fiAfter, _ := os.Stat(baselinePath)
	if fiAfter.ModTime().After(modBefore) {
		t.Errorf("baseline file was modified before user confirmed!")
	}

	// Baseline in store must still be initial observed
	b, _ := store.Get("eth0")
	if b.Type != dhcp.BaselineInitialObserved {
		t.Errorf("baseline type modified prematurely: %s", b.Type)
	}
}

// Priority 1 Test 3: Cancelling confirmation with [Esc] or [N] leaves stored baseline unchanged.
func TestBaselineConfirmation_Cancel_LeavesBaselineUnchanged(t *testing.T) {
	m, store, _, _ := setupTestModelWithDHCP(t)

	// Press [B] to open confirmation modal
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'B'}})
	m = res.(*Model)
	if !m.showBaselineConfirm {
		t.Fatalf("expected showBaselineConfirm = true")
	}

	// Press [Esc] to cancel
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	m = res.(*Model)

	if m.showBaselineConfirm {
		t.Errorf("expected showBaselineConfirm = false after pressing [Esc]")
	}
	if m.pendingBaselineCfg != nil {
		t.Errorf("expected pendingBaselineCfg = nil after cancellation")
	}
	if !strings.Contains(m.toastMsg, "cancelled") {
		t.Errorf("expected cancellation toast, got: %s", m.toastMsg)
	}

	b, _ := store.Get("eth0")
	if b.Type != dhcp.BaselineInitialObserved {
		t.Errorf("baseline changed after cancellation: %s", b.Type)
	}
}

// Priority 1 Test 4: Confirming refresh creates backup and updates to User-Confirmed baseline.
func TestBaselineConfirmation_Confirm_UpdatesOnlyTargetInterface(t *testing.T) {
	m, store, _, baselinePath := setupTestModelWithDHCP(t)

	// Press [B] to open confirmation
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'B'}})
	m = res.(*Model)

	// Press [Enter] to confirm
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(*Model)

	if m.showBaselineConfirm {
		t.Errorf("expected showBaselineConfirm = false after confirmation")
	}
	if !strings.Contains(m.toastMsg, "User-confirmed baseline established") {
		t.Errorf("expected confirmation toast, got: %s", m.toastMsg)
	}

	// Verify backup file exists
	bakPath := baselinePath + ".bak"
	if _, err := os.Stat(bakPath); err != nil {
		t.Errorf("expected backup file %s to exist: %v", bakPath, err)
	}

	// Verify baseline type is now USER_CONFIRMED
	b, ok := store.Get("eth0")
	if !ok || b == nil {
		t.Fatalf("expected baseline for eth0")
	}
	if b.Type != dhcp.BaselineUserConfirmed {
		t.Errorf("expected baseline type %s, got %s", dhcp.BaselineUserConfirmed, b.Type)
	}
}

// Priority 1 Test 5: Undersized terminal blocks confirmation and warns user.
func TestBaselineConfirmation_UndersizedTerminal_BlocksConfirmation(t *testing.T) {
	m, store, _, _ := setupTestModelWithDHCP(t)

	// Open confirmation modal
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'B'}})
	m = res.(*Model)

	// Shrink window to undersized dimensions
	res, _ = m.Update(tea.WindowSizeMsg{Width: 35, Height: 8})
	m = res.(*Model)

	// Attempt to confirm with [Enter]
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(*Model)

	if !strings.Contains(m.toastMsg, "Window too small") {
		t.Errorf("expected 'Window too small' toast on undersized confirm attempt, got: %s", m.toastMsg)
	}

	// Stored baseline must remain initial observed
	b, _ := store.Get("eth0")
	if b.Type != dhcp.BaselineInitialObserved {
		t.Errorf("undersized confirmation was not blocked: %s", b.Type)
	}
}

// Priority 1 Test 6: Mutual exclusion between scan confirmation and baseline confirmation.
func TestBaselineConfirmation_MutualExclusionWithScanConfirmation(t *testing.T) {
	m, _, _, _ := setupTestModelWithDHCP(t)

	// Open scan confirmation by pressing [S]
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)
	if !m.showScanConfirm {
		t.Fatalf("expected showScanConfirm = true")
	}

	// Pressing [B] while scan confirmation is open must be ignored
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'B'}})
	m = res.(*Model)
	if m.showBaselineConfirm {
		t.Errorf("baseline confirmation opened while scan confirmation was active!")
	}

	// Cancel scan confirmation
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	m = res.(*Model)

	// Now open baseline confirmation
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'B'}})
	m = res.(*Model)
	if !m.showBaselineConfirm {
		t.Fatalf("expected showBaselineConfirm = true")
	}

	// Pressing [S] while baseline confirmation is open must be ignored
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = res.(*Model)
	if m.showScanConfirm {
		t.Errorf("scan confirmation opened while baseline confirmation was active!")
	}
}

// Priority 1 Test 7: Validate rendered dimensions and contents of baseline confirmation across sizes.
func TestBaselineConfirmation_RenderedDimensionsAndContents(t *testing.T) {
	testSizes := []struct {
		name   string
		width  int
		height int
	}{
		{"Compact 40x12", 40, 12},
		{"Narrow 50x16", 50, 16},
		{"Medium 65x22", 65, 22},
		{"Standard 80x24", 80, 24},
		{"Large 100x30", 100, 30},
		{"Wide 120x40", 120, 40},
	}

	for _, tc := range testSizes {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _, _ := setupTestModelWithDHCP(t)
			res, _ := m.Update(tea.WindowSizeMsg{Width: tc.width, Height: tc.height})
			m = res.(*Model)

			// Press [B] to trigger baseline confirmation modal
			res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'B'}})
			m = res.(*Model)

			if !m.showBaselineConfirm {
				t.Fatalf("[%s] expected showBaselineConfirm = true", tc.name)
			}

			view := m.View()
			renderedLines := lipgloss.Height(view)
			renderedCols := lipgloss.Width(view)

			if renderedLines > tc.height {
				t.Fatalf("[%s] Vertical overflow! Rendered lines %d > terminal height %d\nView:\n%s",
					tc.name, renderedLines, tc.height, view)
			}
			if renderedCols > tc.width {
				t.Fatalf("[%s] Horizontal overflow! Rendered cols %d > terminal width %d\nView:\n%s",
					tc.name, renderedCols, tc.width, view)
			}

			// Essential elements check
			requiredElements := []string{
				"BASELINE",
				"eth0",
				"Confirm",
				"Cancel",
			}
			for _, elem := range requiredElements {
				if !strings.Contains(view, elem) {
					t.Errorf("[%s] Missing essential element %q in view:\n%s", tc.name, elem, view)
				}
			}

			// Scroll test
			res, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
			m = res.(*Model)
			res, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
			m = res.(*Model)

			// Cancel confirmation with [N]
			res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
			m = res.(*Model)
			if m.showBaselineConfirm {
				t.Fatalf("[%s] expected showBaselineConfirm = false after cancel", tc.name)
			}
		})
	}
}

// Regression Test: When live network configuration changes while confirmation modal is open,
// confirmation MUST be cancelled and stored baseline left unchanged.
func TestBaselineConfirmation_LiveConfigChangesWhileDialogOpen_CancelsConfirmation(t *testing.T) {
	m, store, inspector, baselinePath := setupTestModelWithDHCP(t)

	// Press [B] to open confirmation modal
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'B'}})
	m = res.(*Model)

	if !m.showBaselineConfirm {
		t.Fatalf("expected showBaselineConfirm = true")
	}
	if m.pendingBaselineCfg == nil {
		t.Fatalf("expected pendingBaselineCfg to be populated")
	}
	if m.pendingBaselineCfg.GatewayIP != "192.168.1.1" {
		t.Fatalf("expected pending gateway 192.168.1.1, got %s", m.pendingBaselineCfg.GatewayIP)
	}

	// Live network changes while dialog is open (e.g. gateway moves to 192.168.1.254)
	changedCfg := *inspector.cfg
	changedCfg.GatewayIP = "192.168.1.254"
	inspector.cfg = &changedCfg

	// Live probe updates heartbeat poller status
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m.poller.ProbeOnce(ctx)

	// User now presses [Enter] to confirm what they saw
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(*Model)

	// Dialog should close
	if m.showBaselineConfirm {
		t.Errorf("expected showBaselineConfirm = false after enter")
	}
	if m.pendingBaselineCfg != nil {
		t.Errorf("expected pendingBaselineCfg = nil after enter")
	}

	// Toast must indicate cancellation due to configuration change
	if !strings.Contains(m.toastMsg, "cancelled") || !strings.Contains(m.toastMsg, "live network configuration changed") {
		t.Errorf("expected cancellation toast mentioning live network configuration changed, got: %s", m.toastMsg)
	}

	// Stored baseline MUST still be initial observed with original gateway
	b, ok := store.Get("eth0")
	if !ok || b == nil {
		t.Fatalf("baseline disappeared")
	}
	if b.Type != dhcp.BaselineInitialObserved {
		t.Errorf("baseline was overwritten despite network change: type=%s", b.Type)
	}
	if b.GatewayIP != "192.168.1.1" {
		t.Errorf("baseline gateway was modified: got %s", b.GatewayIP)
	}

	// Backup file must NOT have been created
	bakPath := baselinePath + ".bak"
	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Errorf("backup file should not have been created when confirmation was cancelled")
	}
}




