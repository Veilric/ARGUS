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
type scanCompleteMsg struct{}

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
	if !m.viewportReady {
		return
	}
	vpWidth := m.width
	switch m.activeTab {
	case 0:
		m.viewports[0].SetContent(renderTelemetryView(m, vpWidth))
	case 1:
		m.viewports[1].SetContent(renderDiagnosticsView(m, vpWidth))
	case 2:
		m.viewports[2].SetContent(renderDiscoveryView(m, vpWidth))
	case 3:
		m.viewports[3].SetContent(renderLogsView(m, vpWidth))
	}
}

func (m *Model) refreshAllTabContents() {
	if !m.viewportReady {
		return
	}
	vpWidth := m.width
	m.viewports[0].SetContent(renderTelemetryView(m, vpWidth))
	m.viewports[1].SetContent(renderDiagnosticsView(m, vpWidth))
	m.viewports[2].SetContent(renderDiscoveryView(m, vpWidth))
	m.viewports[3].SetContent(renderLogsView(m, vpWidth))
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		m.tickCmd(),
		m.sysmonCmd(),
		m.runInitialDiagnosticsCmd(),
	)
}

func (m *Model) tickCmd() tea.Cmd {
	return tea.Tick(m.cfg.HeartbeatRate, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
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
			if m.logger != nil {
				m.logger.Close()
			}
			return m, tea.Quit

		case "tab":
			m.activeTab = (m.activeTab + 1) % 4
			m.refreshActiveTabContent()

		case "shift+tab":
			m.activeTab = (m.activeTab + 3) % 4
			m.refreshActiveTabContent()

		case "1":
			m.activeTab = 0
			m.refreshActiveTabContent()
		case "2":
			m.activeTab = 1
			m.refreshActiveTabContent()
		case "3":
			m.activeTab = 2
			m.refreshActiveTabContent()
		case "4":
			m.activeTab = 3
			m.refreshActiveTabContent()

		case "d", " ":
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

		case "s":
			// Trigger gentle subnet sweep
			if !m.scanner.IsScanning() {
				m.toastMsg = "Initiating gentle, rate-limited subnet sweep..."
				m.refreshActiveTabContent()
				cmds = append(cmds, func() tea.Msg {
					_ = m.scanner.RunGentleSweep(context.Background(), nil)
					return scanCompleteMsg{}
				})
			}

		case "r":
			m.refreshHostDetails()
			m.scanner.RefreshPassive()
			m.toastMsg = "Refreshed network interfaces and ARP cache"
			m.refreshAllTabContents()

		case "e":
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
			if m.viewportReady {
				m.viewports[m.activeTab].GotoTop()
			}
		case "end", "G":
			if m.viewportReady {
				m.viewports[m.activeTab].GotoBottom()
			}
		case "up", "k":
			if m.viewportReady {
				m.viewports[m.activeTab].LineUp(1)
			}
		case "down", "j":
			if m.viewportReady {
				m.viewports[m.activeTab].LineDown(1)
			}
		case "pgup", "b":
			if m.viewportReady {
				m.viewports[m.activeTab].ViewUp()
			}
		case "pgdown", "f":
			if m.viewportReady {
				m.viewports[m.activeTab].ViewDown()
			}
		}

	case tea.MouseMsg:
		if m.viewportReady {
			var cmd tea.Cmd
			m.viewports[m.activeTab], cmd = m.viewports[m.activeTab].Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}

	case tickMsg:
		// Heartbeat probe
		status := m.poller.ProbeOnce(context.Background())
		if m.logger != nil {
			if !status.GatewayOK {
				m.logger.Log("ALERT: Default gateway unreachable")
			}
			if !status.InternetOK && status.GatewayOK {
				m.logger.Log("ALERT: Upstream ISP WAN connection drop detected")
			}
		}
		if m.viewportReady {
			m.viewports[0].SetContent(renderTelemetryView(m, m.width))
			if m.activeTab == 3 {
				m.viewports[3].SetContent(renderLogsView(m, m.width))
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

		// Update telemetry vitals cache from results
		for _, r := range m.diagResults {
			if r.ID == "double_nat" {
				if r.Category == diagnostics.CategoryConfirmed {
					m.latestDoubleNAT = lipgloss.NewStyle().Foreground(ColorCoral).Bold(true).Render(r.Summary)
				} else if r.Category == diagnostics.CategorySuspected {
					m.latestDoubleNAT = lipgloss.NewStyle().Foreground(ColorAmber).Render(r.Summary)
				} else {
					m.latestDoubleNAT = lipgloss.NewStyle().Foreground(ColorEmerald).Render("Single NAT [Clean]")
				}
			} else if r.ID == "ip_conflict" {
				if r.Category == diagnostics.CategoryConfirmed {
					m.latestConflict = lipgloss.NewStyle().Foreground(ColorCoral).Bold(true).Render("CONFLICT DETECTED!")
				} else {
					m.latestConflict = lipgloss.NewStyle().Foreground(ColorEmerald).Render("Clean (0 detected)")
				}
			} else if r.ID == "mtu_path" {
				if r.Category == diagnostics.CategoryConfirmed {
					m.latestMTU = lipgloss.NewStyle().Foreground(ColorAmber).Render(r.Summary)
				} else {
					m.latestMTU = lipgloss.NewStyle().Foreground(ColorEmerald).Render("1500 bytes (Clean)")
				}
			}
		}

		if m.viewportReady {
			m.viewports[1].SetContent(renderDiagnosticsView(m, m.width))
			m.viewports[0].SetContent(renderTelemetryView(m, m.width))
		}

	case scanCompleteMsg:
		m.toastMsg = fmt.Sprintf("Subnet sweep complete. %d device(s) found.", len(m.scanner.Devices()))
		if m.viewportReady {
			m.viewports[2].SetContent(renderDiscoveryView(m, m.width))
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

	// 3. Scrollable Viewport for Active Tab
	content := m.viewports[m.activeTab].View()

	// 4. Fixed Compact System & Key Hints Footer
	footer := m.renderFooter(viewWidth)

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

	// For very short terminal heights (< 15 lines), render an ultra-compact 1-line header
	if m.height < 15 {
		line := fmt.Sprintf("%s %s │ %s │ %s",
			TitleStyle.Render("ARGUS"),
			badge,
			lipgloss.NewStyle().Foreground(ColorCyan).Render(m.hostName),
			lipgloss.NewStyle().Foreground(ColorEmerald).Render(m.localIP),
		)
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

	return tabsBar + "\n"
}

func (m *Model) renderFooter(width int) string {
	// For very short heights (< 15 lines), render a single line footer without box
	if m.height < 15 {
		statsPart := fmt.Sprintf("CPU:%.0f%% RAM:%.1fG", m.sysStats.CPUPercent, m.sysStats.RAMUsedGB)
		hintsPart := "[1-4]Tabs [D]Scan [E]Exp [Q]Quit"
		if width < 45 {
			hintsPart = "[1-4]Tabs [Q]Quit"
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

	var hostTelemetry string
	if width >= 70 {
		hostTelemetry = fmt.Sprintf("HOST: CPU: %.1f%% │ RAM: %.1f/%.1f GB (%.0f%%) │ RX: %s  TX: %s",
			m.sysStats.CPUPercent,
			m.sysStats.RAMUsedGB,
			m.sysStats.RAMTotalGB,
			m.sysStats.RAMPercent,
			sysmon.FormatRate(m.sysStats.RxBytesSec),
			sysmon.FormatRate(m.sysStats.TxBytesSec),
		)
	} else if width >= 50 {
		hostTelemetry = fmt.Sprintf("CPU: %.1f%% │ RAM: %.1fGB │ RX: %s TX: %s",
			m.sysStats.CPUPercent,
			m.sysStats.RAMUsedGB,
			sysmon.FormatRate(m.sysStats.RxBytesSec),
			sysmon.FormatRate(m.sysStats.TxBytesSec),
		)
	} else {
		hostTelemetry = fmt.Sprintf("CPU: %.0f%% │ RAM: %.1fG │ %s↑ %s↓",
			m.sysStats.CPUPercent,
			m.sysStats.RAMUsedGB,
			sysmon.FormatRate(m.sysStats.TxBytesSec),
			sysmon.FormatRate(m.sysStats.RxBytesSec),
		)
	}

	var keyHints string
	if width >= 75 {
		keyHints = "[1-4/Tab] Views │ [D] Scan │ [S] Sweep │ [E] Export │ [↑/↓/PgUp/PgDn] Scroll │ [Q] Quit"
	} else if width >= 55 {
		keyHints = "[1-4] Tabs │ [D] Scan │ [S] Sweep │ [E] Export │ [↑/↓] Scroll │ [Q] Quit"
	} else {
		keyHints = "[1-4] Tabs │ [D] Scan │ [E] Export │ [↑/↓] Scroll │ [Q] Quit"
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
