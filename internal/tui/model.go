package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"argus/internal/config"
	"argus/internal/diagnostics"
	"argus/internal/discovery"
	"argus/internal/platform"
	"argus/internal/reporter"
	"argus/internal/sysmon"
	"argus/internal/telemetry"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tickMsg time.Time
type sysmonMsg sysmon.Stats
type diagCompleteMsg []diagnostics.DiagnosticResult
type scanProgressMsg struct {
	Current int
	Total   int
}
type scanCompleteMsg struct {
	err error
}

// ScanLifecycleState models the explicit lifecycle of active discovery operations.
type ScanLifecycleState string

const (
	ScanStateIdle            ScanLifecycleState = "IDLE"
	ScanStateAwaitingConfirm ScanLifecycleState = "AWAITING_CONFIRM"
	ScanStateStarting        ScanLifecycleState = "STARTING"
	ScanStateRunning         ScanLifecycleState = "RUNNING"
	ScanStateCancelling      ScanLifecycleState = "CANCELLING"
	ScanStateCompleted       ScanLifecycleState = "COMPLETED"
	ScanStateFailed          ScanLifecycleState = "FAILED"
)

// Model encapsulates the full TUI state for ARGUS.
type Model struct {
	cfg                   *config.Config
	adapter               platform.NetworkAdapter
	poller                *telemetry.Poller
	engine                *diagnostics.Engine
	scanner               *discovery.Scanner
	monitor               *sysmon.Monitor
	logger                *reporter.SessionLogger

	// Window dimensions
	width                 int
	height                int

	// Active tab index (0: Telemetry, 1: Diagnostics, 2: Devices, 3: Logs)
	activeTab             int

	// Viewports: one for each tab to preserve independent scroll positions
	viewports             [4]viewport.Model
	viewportReady         bool
	confirmViewport       viewport.Model
	confirmVpReady        bool

	// State cache
	hostName              string
	ifaceName             string
	localIP               string
	gatewayIP             string
	gatewayMAC            string
	isElevated            bool
	sysStats              sysmon.Stats

	// Diagnostics state
	diagResults           []diagnostics.DiagnosticResult
	isScanningDiagnostics bool
	latestDoubleNAT       string
	latestConflict        string
	latestMTU             string

	// Subnet scan state
	scanProgressCurrent   int
	scanProgressTotal     int
	scanState             ScanLifecycleState
	showScanConfirm       bool
	pendingSweepPlan      *discovery.SweepPlan
	sweepCancel           context.CancelFunc
	savedDeviceScrollY    int

	// Toast notification
	toastMsg              string
	toastTimer            *time.Timer
}

func NewModel(
	cfg *config.Config,
	adapter platform.NetworkAdapter,
	poller *telemetry.Poller,
	engine *diagnostics.Engine,
	scanner *discovery.Scanner,
	monitor *sysmon.Monitor,
	logger *reporter.SessionLogger,
) *Model {
	h, _ := os.Hostname()
	m := &Model{
		cfg:        cfg,
		adapter:    adapter,
		poller:     poller,
		engine:     engine,
		scanner:    scanner,
		monitor:    monitor,
		logger:     logger,
		hostName:   h,
		isElevated: adapter.IsElevated(),
		width:      80,
		height:     24,
	}

	m.refreshHostDetails()
	m.updateViewportDimensions()
	return m
}

func (m *Model) refreshHostDetails() {
	iface, err := m.adapter.GetDefaultInterface()
	if err == nil && iface != nil {
		m.ifaceName = iface.Name
		if len(iface.IPs) > 0 {
			m.localIP = iface.IPs[0].String()
		}
	}
	gw, err := m.adapter.GetDefaultGateway()
	if err == nil && gw != nil {
		m.gatewayIP = gw.String()
	}
	neighbors, err := m.adapter.GetARPTable()
	if err == nil {
		for _, n := range neighbors {
			if m.gatewayIP != "" && n.IP == m.gatewayIP {
				m.gatewayMAC = n.MAC
				break
			}
		}
	}
}

func (m *Model) updateViewportDimensions() {
	if m.width <= 0 || m.height <= 0 {
		return
	}

	headerStr := m.renderHeader(m.width)
	tabsStr := m.renderTabs(m.width)
	footerStr := m.renderFooter(m.width)

	headerHeight := lipgloss.Height(headerStr)
	tabsHeight := lipgloss.Height(tabsStr)
	footerHeight := lipgloss.Height(footerStr)

	vpHeight := m.height - headerHeight - tabsHeight - footerHeight
	if vpHeight < 2 {
		vpHeight = 2
	}

	vpWidth := m.width
	if vpWidth < 10 {
		vpWidth = 10
	}

	for i := 0; i < 4; i++ {
		if !m.viewportReady {
			m.viewports[i] = viewport.New(vpWidth, vpHeight)
			// Configure keymap: disable HalfPageDown so 'd' stays bound to Deep Scan
			km := viewport.DefaultKeyMap()
			km.HalfPageDown.SetEnabled(false)
			m.viewports[i].KeyMap = km
			m.viewports[i].MouseWheelEnabled = true
			m.viewports[i].MouseWheelDelta = 2
		} else {
			m.viewports[i].Width = vpWidth
			m.viewports[i].Height = vpHeight
		}
	}
	m.viewportReady = true
	m.refreshAllTabContents()
}

func (m *Model) refreshActiveTabContent() {
	if !m.viewportReady || m.showScanConfirm {
		return
	}
	vpWidth := m.width
	switch m.activeTab {
	case 0:
		y := m.viewports[0].YOffset
		m.viewports[0].SetContent(renderTelemetryView(m, vpWidth))
		m.viewports[0].SetYOffset(y)
	case 1:
		y := m.viewports[1].YOffset
		m.viewports[1].SetContent(renderDiagnosticsView(m, vpWidth))
		m.viewports[1].SetYOffset(y)
	case 2:
		y := m.viewports[2].YOffset
		m.viewports[2].SetContent(renderDiscoveryView(m, vpWidth))
		m.viewports[2].SetYOffset(y)
	case 3:
		y := m.viewports[3].YOffset
		m.viewports[3].SetContent(renderLogsView(m, vpWidth))
		m.viewports[3].SetYOffset(y)
	}
}

func (m *Model) refreshAllTabContents() {
	if !m.viewportReady || m.showScanConfirm {
		return
	}
	vpWidth := m.width
	y0 := m.viewports[0].YOffset
	m.viewports[0].SetContent(renderTelemetryView(m, vpWidth))
	m.viewports[0].SetYOffset(y0)

	y1 := m.viewports[1].YOffset
	m.viewports[1].SetContent(renderDiagnosticsView(m, vpWidth))
	m.viewports[1].SetYOffset(y1)

	y2 := m.viewports[2].YOffset
	m.viewports[2].SetContent(renderDiscoveryView(m, vpWidth))
	m.viewports[2].SetYOffset(y2)

	y3 := m.viewports[3].YOffset
	m.viewports[3].SetContent(renderLogsView(m, vpWidth))
	m.viewports[3].SetYOffset(y3)
}

type heartbeatProbeMsg telemetry.PipelineStatus

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		m.probeHeartbeatCmd(),
		m.sysmonCmd(),
		m.runInitialDiagnosticsCmd(),
	)
}

func (m *Model) tickCmd() tea.Cmd {
	return tea.Tick(m.cfg.HeartbeatRate, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *Model) probeHeartbeatCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		defer cancel()
		status := m.poller.ProbeOnce(ctx)
		return heartbeatProbeMsg(status)
	}
}

func (m *Model) sysmonCmd() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return sysmonMsg(m.monitor.Sample())
	})
}

func (m *Model) runInitialDiagnosticsCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		results, _ := m.engine.RunDiagnostics(ctx)
		return diagCompleteMsg(results)
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateViewportDimensions()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			if m.sweepCancel != nil {
				m.sweepCancel()
			}
			m.scanState = ScanStateIdle
			if m.logger != nil {
				m.logger.Close()
			}
			return m, tea.Quit

		case "enter", "y", "Y":
			if m.showScanConfirm && m.pendingSweepPlan != nil {
				headerStr := m.renderHeader(m.width)
				tabsStr := m.renderTabs(m.width)
				footerStr := m.renderFooter(m.width)
				availHeight := m.height - lipgloss.Height(headerStr) - lipgloss.Height(tabsStr) - lipgloss.Height(footerStr)

				if m.height < 12 || m.width < 40 || availHeight < 6 {
					m.toastMsg = "Window too small: resize terminal to at least 40x12 to review scan scope before authorizing"
					return m, nil
				}
				plan := m.pendingSweepPlan
				m.pendingSweepPlan = nil
				m.showScanConfirm = false
				m.scanState = ScanStateStarting
				m.toastMsg = "Active subnet sweep authorized. Starting probe..."
				m.refreshActiveTabContent()

				ctx, cancel := context.WithCancel(context.Background())
				m.sweepCancel = cancel

				cmds = append(cmds, func() tea.Msg {
					err := m.scanner.ExecuteSweepPlan(ctx, plan, nil)
					return scanCompleteMsg{err: err}
				})
				return m, tea.Batch(cmds...)
			}

		case "esc":
			if m.showScanConfirm {
				m.showScanConfirm = false
				m.pendingSweepPlan = nil
				m.scanState = ScanStateIdle
				if m.viewportReady {
					m.viewports[2].SetYOffset(m.savedDeviceScrollY)
				}
				m.toastMsg = "Subnet sweep cancelled before starting."
				m.refreshActiveTabContent()
				return m, nil
			}
			if (m.scanState == ScanStateStarting || m.scanState == ScanStateRunning || m.scanner.IsScanning()) && m.sweepCancel != nil {
				m.scanState = ScanStateCancelling
				m.sweepCancel()
				m.toastMsg = "Cancelling active subnet sweep..."
				return m, nil
			}

		case "n", "N":
			if m.showScanConfirm {
				m.showScanConfirm = false
				m.pendingSweepPlan = nil
				m.scanState = ScanStateIdle
				if m.viewportReady {
					m.viewports[2].SetYOffset(m.savedDeviceScrollY)
				}
				m.toastMsg = "Subnet sweep cancelled before starting."
				m.refreshActiveTabContent()
				return m, nil
			}

		case "c", "C":
			if (m.scanState == ScanStateStarting || m.scanState == ScanStateRunning || m.scanner.IsScanning()) && m.sweepCancel != nil {
				m.scanState = ScanStateCancelling
				m.sweepCancel()
				m.toastMsg = "Cancelling active subnet sweep..."
				return m, nil
			}

		case "tab":
			if m.showScanConfirm {
				return m, nil
			}
			m.activeTab = (m.activeTab + 1) % 4
			m.refreshActiveTabContent()

		case "shift+tab":
			if m.showScanConfirm {
				return m, nil
			}
			m.activeTab = (m.activeTab + 3) % 4
			m.refreshActiveTabContent()

		case "1":
			if m.showScanConfirm {
				return m, nil
			}
			m.activeTab = 0
			m.refreshActiveTabContent()
		case "2":
			if m.showScanConfirm {
				return m, nil
			}
			m.activeTab = 1
			m.refreshActiveTabContent()
		case "3":
			if m.showScanConfirm {
				return m, nil
			}
			m.activeTab = 2
			m.refreshActiveTabContent()
		case "4":
			if m.showScanConfirm {
				return m, nil
			}
			m.activeTab = 3
			m.refreshActiveTabContent()

		case "d", " ":
			if m.showScanConfirm {
				return m, nil
			}
			// Trigger deep diagnostics
			if !m.isScanningDiagnostics {
				m.isScanningDiagnostics = true
				m.toastMsg = "Running comprehensive diagnostic suite..."
				m.refreshActiveTabContent()
				cmds = append(cmds, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
					defer cancel()
					results, _ := m.engine.RunDiagnostics(ctx)
					return diagCompleteMsg(results)
				})
			}

		case "s", "S":
			// Prevent overlapping or duplicate active sweeps
			if m.scanState == ScanStateStarting || m.scanState == ScanStateRunning || m.scanState == ScanStateCancelling || m.scanner.IsScanning() {
				m.toastMsg = "Active sweep in progress or cancelling. Press [C] or [Esc] to cancel."
				return m, nil
			}
			plan, err := m.scanner.PrepareSweepPlan()
			if err != nil {
				m.toastMsg = "Cannot initiate sweep: " + err.Error()
				return m, nil
			}
			if m.viewportReady {
				m.savedDeviceScrollY = m.viewports[2].YOffset
			}
			m.pendingSweepPlan = plan
			m.showScanConfirm = true
			m.scanState = ScanStateAwaitingConfirm
			m.activeTab = 2 // Switch to Subnet Devices tab to display confirmation overlay
			m.refreshActiveTabContent()
			return m, nil

		case "r":
			if m.showScanConfirm {
				return m, nil
			}
			m.refreshHostDetails()
			m.scanner.RefreshPassive()
			m.toastMsg = "Refreshed network interfaces and ARP cache"
			m.refreshAllTabContents()

		case "e":
			if m.showScanConfirm {
				return m, nil
			}
			// Export incident report (Markdown + JSON)
			mdPath, jsonPath, err := reporter.ExportReport(
				m.cfg,
				m.adapter,
				m.poller.Status(),
				m.diagResults,
				m.scanner.Devices(),
				m.poller.EventLogs(),
				m.cfg.ReportDir,
			)
			if err == nil {
				m.toastMsg = fmt.Sprintf("Report exported: %s and %s", mdPath, jsonPath)
				if m.logger != nil {
					m.logger.Log("Report exported by user to " + mdPath)
				}
			} else {
				m.toastMsg = "Export failed: " + err.Error()
			}

		case "home", "g":
			if m.showScanConfirm {
				if m.confirmVpReady {
					m.confirmViewport.GotoTop()
				}
				return m, nil
			}
			if m.viewportReady {
				m.viewports[m.activeTab].GotoTop()
			}
		case "end", "G":
			if m.showScanConfirm {
				if m.confirmVpReady {
					m.confirmViewport.GotoBottom()
				}
				return m, nil
			}
			if m.viewportReady {
				m.viewports[m.activeTab].GotoBottom()
			}
		case "up", "k":
			if m.showScanConfirm {
				if m.confirmVpReady {
					m.confirmViewport.LineUp(1)
				}
				return m, nil
			}
			if m.viewportReady {
				m.viewports[m.activeTab].LineUp(1)
			}
		case "down", "j":
			if m.showScanConfirm {
				if m.confirmVpReady {
					m.confirmViewport.LineDown(1)
				}
				return m, nil
			}
			if m.viewportReady {
				m.viewports[m.activeTab].LineDown(1)
			}
		case "pgup", "b", "B", "ctrl+b":
			if m.showScanConfirm {
				if m.confirmVpReady {
					m.confirmViewport.ViewUp()
				}
				return m, nil
			}
			if msg.String() == "B" || msg.String() == "ctrl+b" || m.activeTab == 1 {
				if m.poller != nil {
					b, err := m.poller.RefreshBaseline(m.ifaceName)
					if err == nil && b != nil {
						m.toastMsg = fmt.Sprintf("Baseline refreshed for %s", m.ifaceName)
						m.refreshAllTabContents()
						return m, nil
					} else if err != nil {
						m.toastMsg = fmt.Sprintf("Baseline refresh failed: %v", err)
						return m, nil
					}
				}
			}
			if m.viewportReady {
				m.viewports[m.activeTab].ViewUp()
			}
		case "pgdown", "f":
			if m.showScanConfirm {
				if m.confirmVpReady {
					m.confirmViewport.ViewDown()
				}
				return m, nil
			}
			if m.viewportReady {
				m.viewports[m.activeTab].ViewDown()
			}
		}

	case tea.MouseMsg:
		if m.showScanConfirm {
			if m.confirmVpReady {
				var cmd tea.Cmd
				m.confirmViewport, cmd = m.confirmViewport.Update(msg)
				if cmd != nil {
					cmds = append(cmds, cmd)
				}
			}
			return m, nil
		}
		if m.viewportReady {
			var cmd tea.Cmd
			m.viewports[m.activeTab], cmd = m.viewports[m.activeTab].Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}

	case tickMsg:
		// Heartbeat probe dispatched asynchronously to avoid blocking Bubble Tea update loop
		cmds = append(cmds, m.probeHeartbeatCmd())

	case heartbeatProbeMsg:
		if m.viewportReady {
			vp0Y := m.viewports[0].YOffset
			m.viewports[0].SetContent(renderTelemetryView(m, m.width))
			m.viewports[0].SetYOffset(vp0Y)

			if m.activeTab == 3 {
				vp3Y := m.viewports[3].YOffset
				m.viewports[3].SetContent(renderLogsView(m, m.width))
				m.viewports[3].SetYOffset(vp3Y)
			}
		}
		cmds = append(cmds, m.tickCmd())

	case sysmonMsg:
		m.sysStats = sysmon.Stats(msg)
		cmds = append(cmds, m.sysmonCmd())

	case diagCompleteMsg:
		m.diagResults = []diagnostics.DiagnosticResult(msg)
		m.isScanningDiagnostics = false
		m.toastMsg = "Diagnostic scan completed successfully"

		// Update telemetry vitals cache from results with strict classification
		for _, r := range m.diagResults {
			if r.ID == "double_nat" {
				if r.Category == diagnostics.CategoryConfirmed {
					m.latestDoubleNAT = lipgloss.NewStyle().Foreground(ColorCoral).Bold(true).Render(r.Summary)
				} else if r.Category == diagnostics.CategorySuspected {
					m.latestDoubleNAT = lipgloss.NewStyle().Foreground(ColorAmber).Render(r.Summary)
				} else if r.Category == diagnostics.CategoryInconclusive {
					m.latestDoubleNAT = lipgloss.NewStyle().Foreground(ColorMuted).Render(r.Summary)
				} else {
					m.latestDoubleNAT = lipgloss.NewStyle().Foreground(ColorEmerald).Render("Single NAT (Verified)")
				}
			} else if r.ID == "ip_conflict" {
				if r.Category == diagnostics.CategoryConfirmed {
					m.latestConflict = lipgloss.NewStyle().Foreground(ColorCoral).Bold(true).Render("CONFLICT DETECTED!")
				} else if r.Category == diagnostics.CategoryInconclusive {
					m.latestConflict = lipgloss.NewStyle().Foreground(ColorMuted).Render("Passive (No ARP duplicate seen)")
				} else {
					m.latestConflict = lipgloss.NewStyle().Foreground(ColorEmerald).Render("Passive Clean (0 duplicates in ARP)")
				}
			} else if r.ID == "mtu_path" {
				if r.Category == diagnostics.CategoryConfirmed {
					m.latestMTU = lipgloss.NewStyle().Foreground(ColorAmber).Render(r.Summary)
				} else if r.Category == diagnostics.CategoryInconclusive {
					m.latestMTU = lipgloss.NewStyle().Foreground(ColorMuted).Render(r.Summary)
				} else {
					m.latestMTU = lipgloss.NewStyle().Foreground(ColorEmerald).Render("Standard 1500 (Verified)")
				}
			}
		}

		if m.viewportReady {
			vp1Y := m.viewports[1].YOffset
			m.viewports[1].SetContent(renderDiagnosticsView(m, m.width))
			m.viewports[1].SetYOffset(vp1Y)

			vp0Y := m.viewports[0].YOffset
			m.viewports[0].SetContent(renderTelemetryView(m, m.width))
			m.viewports[0].SetYOffset(vp0Y)
		}

	case scanCompleteMsg:
		m.sweepCancel = nil
		m.pendingSweepPlan = nil
		m.showScanConfirm = false

		if m.scanState == ScanStateCancelling || msg.err == context.Canceled {
			m.toastMsg = "Active subnet sweep cancelled by user."
			m.scanState = ScanStateIdle
		} else if msg.err != nil {
			m.toastMsg = fmt.Sprintf("Subnet sweep halted: %v", msg.err)
			m.scanState = ScanStateFailed
		} else {
			m.toastMsg = fmt.Sprintf("Subnet sweep complete. %d device(s) found.", len(m.scanner.Devices()))
			m.scanState = ScanStateCompleted
		}
		m.scanState = ScanStateIdle

		if m.viewportReady {
			m.viewports[2].SetContent(renderDiscoveryView(m, m.width))
			m.viewports[2].SetYOffset(m.savedDeviceScrollY)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) View() string {
	viewWidth := m.width
	if viewWidth <= 0 {
		viewWidth = 80
	}

	if !m.viewportReady {
		return "Initializing ARGUS by Veilric..."
	}

	// 1. Fixed Header
	header := m.renderHeader(viewWidth)

	// 2. Fixed Tab Navigation with Scroll Indicator
	tabs := m.renderTabs(viewWidth)

	// 3. Fixed Compact System & Key Hints Footer
	footer := m.renderFooter(viewWidth)

	headerHeight := lipgloss.Height(header)
	tabsHeight := lipgloss.Height(tabs)
	footerHeight := lipgloss.Height(footer)

	availHeight := m.height - headerHeight - tabsHeight - footerHeight
	if availHeight < 0 {
		availHeight = 0
	}

	// 4. Main Content Area (Overlay during confirmation, or Scrollable Viewport)
	var content string
	if m.showScanConfirm && m.pendingSweepPlan != nil {
		content = renderScanConfirmationOverlay(m, viewWidth, availHeight)
	} else {
		content = m.viewports[m.activeTab].View()
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, tabs, content, footer)
}

func (m *Model) renderHeader(width int) string {
	badge := BadgeElevatedUser.Render("[USER]")
	if m.isElevated {
		badge = BadgeElevatedAdmin.Render("[ADMIN/ROOT]")
	}

	cardWidth := width - 4
	if cardWidth < 20 {
		cardWidth = width - 2
	}
	if cardWidth < 10 {
		cardWidth = 10
	}

	// For short terminal heights or when confirmation dialog is showing on tight screens (< 20 lines)
	if m.height < 16 || (m.showScanConfirm && m.height < 20) {
		var line string
		if width < 50 {
			line = fmt.Sprintf("%s %s │ %s",
				TitleStyle.Render("ARGUS"),
				badge,
				lipgloss.NewStyle().Foreground(ColorCyan).Render(truncateString(m.hostName, 12)),
			)
		} else {
			line = fmt.Sprintf("%s %s │ %s │ %s",
				TitleStyle.Render("ARGUS"),
				badge,
				lipgloss.NewStyle().Foreground(ColorCyan).Render(m.hostName),
				lipgloss.NewStyle().Foreground(ColorEmerald).Render(m.localIP),
			)
		}
		return lipgloss.NewStyle().Width(width).Render(line)
	}

	// Title line
	var titleLine string
	if width >= 65 {
		title := TitleStyle.Render("ARGUS // NETWORK OBSERVATION & DIAGNOSTICS")
		byLine := lipgloss.NewStyle().Foreground(ColorMuted).Render("by Veilric")
		titleLine = fmt.Sprintf("%s %s  %s", title, byLine, badge)
	} else if width >= 45 {
		title := TitleStyle.Render("ARGUS // TELEMETRY")
		byLine := lipgloss.NewStyle().Foreground(ColorMuted).Render("by Veilric")
		titleLine = fmt.Sprintf("%s %s %s", title, byLine, badge)
	} else {
		titleLine = fmt.Sprintf("%s %s", TitleStyle.Render("ARGUS"), badge)
	}

	// Host details line(s)
	var details string
	if width >= 85 {
		// Single wide row
		details = fmt.Sprintf("%s: %s │ %s: %s │ %s: %s │ %s: %s",
			lipgloss.NewStyle().Foreground(ColorMuted).Render("Host"),
			lipgloss.NewStyle().Foreground(ColorCyan).Render(m.hostName),
			lipgloss.NewStyle().Foreground(ColorMuted).Render("Iface"),
			lipgloss.NewStyle().Foreground(ColorWhite).Render(m.ifaceName),
			lipgloss.NewStyle().Foreground(ColorMuted).Render("IP"),
			lipgloss.NewStyle().Foreground(ColorEmerald).Render(m.localIP),
			lipgloss.NewStyle().Foreground(ColorMuted).Render("GW"),
			lipgloss.NewStyle().Foreground(ColorWhite).Render(fmt.Sprintf("%s (%s)", m.gatewayIP, m.gatewayMAC)),
		)
	} else if width >= 55 {
		// Clean two-row details
		row1 := fmt.Sprintf("%s: %s │ %s: %s",
			lipgloss.NewStyle().Foreground(ColorMuted).Render("Host"),
			lipgloss.NewStyle().Foreground(ColorCyan).Render(m.hostName),
			lipgloss.NewStyle().Foreground(ColorMuted).Render("Iface"),
			lipgloss.NewStyle().Foreground(ColorWhite).Render(m.ifaceName),
		)
		gwText := m.gatewayIP
		if m.gatewayMAC != "" && width >= 68 {
			gwText = fmt.Sprintf("%s (%s)", m.gatewayIP, m.gatewayMAC)
		}
		row2 := fmt.Sprintf("%s: %s │ %s: %s",
			lipgloss.NewStyle().Foreground(ColorMuted).Render("IP"),
			lipgloss.NewStyle().Foreground(ColorEmerald).Render(m.localIP),
			lipgloss.NewStyle().Foreground(ColorMuted).Render("GW"),
			lipgloss.NewStyle().Foreground(ColorWhite).Render(gwText),
		)
		details = fmt.Sprintf("%s\n%s", row1, row2)
	} else {
		// Compact two-row details
		row1 := fmt.Sprintf("%s (%s)",
			lipgloss.NewStyle().Foreground(ColorCyan).Render(m.hostName),
			lipgloss.NewStyle().Foreground(ColorWhite).Render(m.ifaceName),
		)
		row2 := fmt.Sprintf("%s │ GW: %s",
			lipgloss.NewStyle().Foreground(ColorEmerald).Render(m.localIP),
			lipgloss.NewStyle().Foreground(ColorWhite).Render(m.gatewayIP),
		)
		details = fmt.Sprintf("%s\n%s", row1, row2)
	}

	return CardStyle.Width(cardWidth).Render(fmt.Sprintf("%s\n%s", titleLine, details))
}

func (m *Model) renderTabs(width int) string {
	var tabNames []string
	if width >= 88 {
		tabNames = []string{"[1] Live Telemetry", "[2] Deep Diagnostics", "[3] Subnet Devices", "[4] Incident Logs"}
	} else if width >= 60 {
		tabNames = []string{"[1] Telemetry", "[2] Diagnostics", "[3] Devices", "[4] Logs"}
	} else if width >= 45 {
		tabNames = []string{"[1] Telem", "[2] Diag", "[3] Devs", "[4] Logs"}
	} else {
		tabNames = []string{"[1]TLM", "[2]DIAG", "[3]DEV", "[4]LOG"}
	}

	var renderedTabs []string
	for i, name := range tabNames {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, ActiveTabStyle.Render(name))
		} else {
			renderedTabs = append(renderedTabs, InactiveTabStyle.Render(name))
		}
	}

	tabsBar := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)

	// Scroll indicator badge on right side if content exceeds visible area
	if m.viewportReady {
		vp := m.viewports[m.activeTab]
		if vp.TotalLineCount() > vp.Height && vp.Height > 0 {
			pct := int(vp.ScrollPercent() * 100)
			var scrollBadge string
			if vp.AtTop() {
				scrollBadge = ScrollIndicatorStyle.Render("[▲ TOP ▼]")
			} else if vp.AtBottom() {
				scrollBadge = ScrollIndicatorStyle.Render("[▲ END]")
			} else {
				scrollBadge = ScrollIndicatorStyle.Render(fmt.Sprintf("[▲ %d%% ▼]", pct))
			}

			badgeW := lipgloss.Width(scrollBadge)
			tabW := lipgloss.Width(tabsBar)
			availSpace := width - tabW - badgeW - 1
			if availSpace > 1 {
				tabsBar = lipgloss.JoinHorizontal(lipgloss.Top, tabsBar, strings.Repeat(" ", availSpace), scrollBadge)
			}
		}
	}

	if m.height < 16 {
		return tabsBar
	}
	return tabsBar + "\n"
}

func (m *Model) renderFooter(width int) string {
	// For short terminal heights or when confirmation dialog is showing on tight screens (< 20 lines)
	if m.height < 16 || (m.showScanConfirm && m.height < 20) {
		if m.showScanConfirm {
			line := lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render("[Enter/Y] Authorize  [Esc/N] Cancel")
			return lipgloss.NewStyle().Width(width).Render(line)
		}

		cpuStr := "N/A"
		if m.sysStats.CPUPercent >= 0 {
			cpuStr = fmt.Sprintf("%.0f%%", m.sysStats.CPUPercent)
		}
		ramStr := "N/A"
		if m.sysStats.RAMTotalGB > 0 {
			ramStr = fmt.Sprintf("%.1fG", m.sysStats.RAMUsedGB)
		}
		statsPart := fmt.Sprintf("CPU:%s RAM:%s", cpuStr, ramStr)
		hintsPart := "[1-4]Tabs [D]Scan [E]Exp [Q]Quit"
		if m.scanState == ScanStateStarting || m.scanState == ScanStateRunning || m.scanner.IsScanning() {
			hintsPart = "[C/Esc]Cancel [Q]Quit"
		} else if m.scanState == ScanStateCancelling {
			hintsPart = "Cancelling... [Q]Quit"
		} else if width < 45 {
			hintsPart = "[1-4]Tabs [Q]Quit"
		}
		if width < 50 {
			statsPart = fmt.Sprintf("CPU:%s", cpuStr)
		}
		line := fmt.Sprintf("%s │ %s",
			lipgloss.NewStyle().Foreground(ColorMuted).Render(statsPart),
			lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(hintsPart),
		)
		return lipgloss.NewStyle().Width(width).Render(line)
	}

	cardWidth := width - 4
	if cardWidth < 20 {
		cardWidth = width - 2
	}
	if cardWidth < 10 {
		cardWidth = 10
	}

	cpuStr := "N/A"
	if m.sysStats.CPUPercent >= 0 {
		cpuStr = fmt.Sprintf("%.1f%%", m.sysStats.CPUPercent)
	}
	ramFullStr := "N/A"
	ramShortStr := "N/A"
	if m.sysStats.RAMTotalGB > 0 {
		ramFullStr = fmt.Sprintf("%.1f/%.1f GB (%.0f%%)", m.sysStats.RAMUsedGB, m.sysStats.RAMTotalGB, m.sysStats.RAMPercent)
		ramShortStr = fmt.Sprintf("%.1fGB", m.sysStats.RAMUsedGB)
	}

	var hostTelemetry string
	if width >= 70 {
		hostTelemetry = fmt.Sprintf("HOST: CPU: %s │ RAM: %s │ RX: %s  TX: %s",
			cpuStr,
			ramFullStr,
			sysmon.FormatRate(m.sysStats.RxBytesSec),
			sysmon.FormatRate(m.sysStats.TxBytesSec),
		)
	} else if width >= 50 {
		hostTelemetry = fmt.Sprintf("CPU: %s │ RAM: %s │ RX: %s TX: %s",
			cpuStr,
			ramShortStr,
			sysmon.FormatRate(m.sysStats.RxBytesSec),
			sysmon.FormatRate(m.sysStats.TxBytesSec),
		)
	} else {
		hostTelemetry = fmt.Sprintf("CPU: %s │ RAM: %s │ %s↑ %s↓",
			cpuStr,
			ramShortStr,
			sysmon.FormatRate(m.sysStats.TxBytesSec),
			sysmon.FormatRate(m.sysStats.RxBytesSec),
		)
	}

	var keyHints string
	if m.showScanConfirm {
		keyHints = "[Enter / Y] Authorize & Scan │ [Esc / N] Cancel Sweep Authorization │ [Q] Quit"
	} else if m.scanState == ScanStateStarting || m.scanState == ScanStateRunning || m.scanner.IsScanning() {
		keyHints = "[C / Esc] Cancel Active Sweep │ [1-4/Tab] Views │ [E] Export │ [Q] Quit"
	} else if m.scanState == ScanStateCancelling {
		keyHints = "Cancelling active sweep... aborting probe workers │ [Q] Quit"
	} else if width >= 75 {
		keyHints = "[1-4/Tab] Views │ [D] Scan │ [B] Baseline │ [S] Sweep │ [E] Export │ [↑/↓] Scroll │ [Q] Quit"
	} else if width >= 55 {
		keyHints = "[1-4] Tabs │ [D] Scan │ [B] Base │ [S] Sweep │ [E] Exp │ [Q] Quit"
	} else {
		keyHints = "[1-4] Tabs │ [D] Scan │ [B] Base │ [E] Exp │ [Q] Quit"
	}

	var toastPart string
	if m.toastMsg != "" {
		toastPart = "\n" + ToastStyle.Render(m.toastMsg)
	}

	content := fmt.Sprintf("%s\n%s%s",
		lipgloss.NewStyle().Foreground(ColorMuted).Render(hostTelemetry),
		lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(keyHints),
		toastPart,
	)

	return CardStyle.Width(cardWidth).Render(content)
}
