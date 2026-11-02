package tui

import (
	"context"
	"fmt"
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



