package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func renderTelemetryView(m *Model, width int) string {
	var sb strings.Builder

	cardWidth := width - 4
	if cardWidth < 20 {
		cardWidth = width - 2
	}
	if cardWidth < 10 {
		cardWidth = 10
	}

	// 1. Chain of Reachability
	pipelineCard := renderPipeline(m, cardWidth)
	sb.WriteString(pipelineCard)
	sb.WriteString("\n\n")

	// 2. Vital Signs Card
	vitalsCard := renderVitals(m, cardWidth)
	sb.WriteString(vitalsCard)
	sb.WriteString("\n\n")

	// 3. Live Latency Sparklines Card
	sparklineCard := renderSparklines(m, cardWidth)
	sb.WriteString(sparklineCard)
	sb.WriteString("\n\n")

	// 4. Incident Ticker Card
	tickerCard := renderTicker(m, cardWidth)
	sb.WriteString(tickerCard)

	return sb.String()
}

func renderPipeline(m *Model, width int) string {
	pipe := m.poller.Status()

	gwTime := formatDuration(pipe.GatewayRTT)
	dnsTime := formatDuration(pipe.DNSRTT)
	netTime := formatDuration(pipe.InternetRTT)

	var line1 string

	if width >= 64 {
		// Full wide format
		nodeYou := NodeOnline.Render("[YOU]")
		arrow1 := ArrowStyle.Render("──")
		nodeGW := NodeOffline.Render("[GATEWAY ✗]")
		if pipe.GatewayOK {
			nodeGW = NodeOnline.Render(fmt.Sprintf("[GATEWAY ✔ %s]", gwTime))
		}

		arrow2 := ArrowStyle.Render("──")
		nodeDNS := NodeOffline.Render("[DNS ✗]")
		if pipe.DNSOK {
			nodeDNS = NodeOnline.Render(fmt.Sprintf("[DNS ✔ %s]", dnsTime))
		}

		arrow3 := ArrowStyle.Render("──")
		nodeNet := NodeOffline.Render("[INTERNET ✗]")
		if pipe.InternetOK {
			nodeNet = NodeOnline.Render(fmt.Sprintf("[INTERNET ✔ %s]", netTime))
		}

		line1 = fmt.Sprintf("%s%s%s%s%s%s%s", nodeYou, arrow1, nodeGW, arrow2, nodeDNS, arrow3, nodeNet)
	} else if width >= 44 {
		// Medium compact format
		nodeGW := NodeOffline.Render("[GW: ✗]")
		if pipe.GatewayOK {
			nodeGW = NodeOnline.Render(fmt.Sprintf("[GW: %s]", gwTime))
		}
		nodeDNS := NodeOffline.Render("[DNS: ✗]")
		if pipe.DNSOK {
			nodeDNS = NodeOnline.Render(fmt.Sprintf("[DNS: %s]", dnsTime))
		}
		nodeNet := NodeOffline.Render("[NET: ✗]")
		if pipe.InternetOK {
			nodeNet = NodeOnline.Render(fmt.Sprintf("[NET: %s]", netTime))
		}

		line1 = fmt.Sprintf("%s ─> %s ─> %s ─> %s",
			NodeOnline.Render("[YOU]"),
			nodeGW,
			nodeDNS,
			nodeNet,
		)
	} else {
		// Narrow stacked format
		nodeGW := NodeOffline.Render("[GW ✗]")
		if pipe.GatewayOK {
			nodeGW = NodeOnline.Render(fmt.Sprintf("[GW ✔ %s]", gwTime))
		}
		nodeDNS := NodeOffline.Render("[DNS ✗]")
		if pipe.DNSOK {
			nodeDNS = NodeOnline.Render(fmt.Sprintf("[DNS ✔ %s]", dnsTime))
		}
		nodeNet := NodeOffline.Render("[NET ✗]")
		if pipe.InternetOK {
			nodeNet = NodeOnline.Render(fmt.Sprintf("[NET ✔ %s]", netTime))
		}

		line1 = fmt.Sprintf("%s ─> %s\n └──> %s ─> %s",
			NodeOnline.Render("[YOU]"),
			nodeGW,
			nodeDNS,
			nodeNet,
		)
	}

	summary := "Physical link active"
	if !pipe.LinkOK {
		summary = NodeOffline.Render("PHYSICAL LINK DOWN / DISCONNECTED")
	} else if !pipe.GatewayOK {
		summary = NodeOffline.Render("GATEWAY UNREACHABLE — Internal LAN / Switch failure")
	} else if !pipe.InternetOK && !pipe.DNSOK {
		summary = NodeOffline.Render("UPSTREAM ISP OUTAGE — WAN connection dropped beyond gateway")
	} else if !pipe.DNSOK && pipe.InternetOK {
		summary = NodeWarning.Render("DNS SERVER FAILURE — Internet alive, name resolution broken")
	} else {
		summary = NodeOnline.Render("All reachability checkpoints nominal")
	}

	content := fmt.Sprintf("%s\n\n%s: %s",
		lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("CHAIN OF REACHABILITY"),
		lipgloss.NewStyle().Foreground(ColorMuted).Render("Status"),
		summary,
	)

	return CardStyle.Width(width).Render(fmt.Sprintf("%s\n%s", line1, content))
}

func renderVitals(m *Model, width int) string {
	pipe := m.poller.Status()

	natStr := lipgloss.NewStyle().Foreground(ColorEmerald).Render("Single NAT [Clean]")
	if m.latestDoubleNAT != "" {
		natStr = m.latestDoubleNAT
	}

	conflictStr := lipgloss.NewStyle().Foreground(ColorEmerald).Render("Clean (0 detected)")
	if m.latestConflict != "" {
		conflictStr = m.latestConflict
	}

	captiveStr := lipgloss.NewStyle().Foreground(ColorEmerald).Render("Direct Egress Verified")
	if pipe.CaptiveState == "DETECTED" {
		captiveStr = lipgloss.NewStyle().Foreground(ColorCoral).Bold(true).Render("CAPTIVE PORTAL DETECTED")
	}

	mtuStr := lipgloss.NewStyle().Foreground(ColorEmerald).Render("1500 bytes (Clean)")
	if m.latestMTU != "" {
		mtuStr = m.latestMTU
	}

	lblWidth := 16
	if width < 48 {
		lblWidth = 14
	}

	lblStyle := lipgloss.NewStyle().Foreground(ColorMuted).Width(lblWidth)
	content := fmt.Sprintf("%s\n%s %s\n%s %s\n%s %s\n%s %s",
		lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("TOPOLOGY & DIAGNOSTIC VITALS"),
		lblStyle.Render("• NAT Mode:"), natStr,
		lblStyle.Render("• IP Conflicts:"), conflictStr,
		lblStyle.Render("• Captive Portal:"), captiveStr,
		lblStyle.Render("• Path MTU:"), mtuStr,
	)

	return CardStyle.Width(width).Render(content)
}

func renderSparklines(m *Model, width int) string {
	gwBuf := m.poller.GatewayBuffer()
	pubBuf := m.poller.PublicBuffer()

	gwMin, gwMax, gwAvg, gwLoss := gwBuf.Stats()
	pubMin, pubMax, pubAvg, pubLoss := pubBuf.Stats()

	lblStyle := lipgloss.NewStyle().Bold(true).Width(10)
	statStyle := lipgloss.NewStyle().Foreground(ColorMuted)

	var content string

	if width >= 65 {
		// Single-line sparkline + stats
		sparkWidth := width - 36
		if sparkWidth < 8 {
			sparkWidth = 8
		}
		if sparkWidth > 25 {
			sparkWidth = 25
		}

		gwSpark := lipgloss.NewStyle().Foreground(ColorCyan).Render(gwBuf.RenderSparkline(sparkWidth))
		pubSpark := lipgloss.NewStyle().Foreground(ColorEmerald).Render(pubBuf.RenderSparkline(sparkWidth))

		gwStat := statStyle.Render(fmt.Sprintf("%.1fms (Loss: %.0f%% | Min: %.1f | Max: %.1f)", gwAvg, gwLoss, gwMin, gwMax))
		pubStat := statStyle.Render(fmt.Sprintf("%.1fms (Loss: %.0f%% | Min: %.1f | Max: %.1f)", pubAvg, pubLoss, pubMin, pubMax))

		content = fmt.Sprintf("%s\n%s %s  %s\n%s %s  %s",
			lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("LIVE LATENCY TELEMETRY"),
			lblStyle.Render("Gateway:"), gwSpark, gwStat,
			lblStyle.Render("Internet:"), pubSpark, pubStat,
		)
	} else {
		// Responsive two-line per target for narrow screens
		sparkWidth := width - 14
		if sparkWidth < 8 {
			sparkWidth = 8
		}
		if sparkWidth > 30 {
			sparkWidth = 30
		}

		gwSpark := lipgloss.NewStyle().Foreground(ColorCyan).Render(gwBuf.RenderSparkline(sparkWidth))
		pubSpark := lipgloss.NewStyle().Foreground(ColorEmerald).Render(pubBuf.RenderSparkline(sparkWidth))

		gwStat := statStyle.Render(fmt.Sprintf("  %.1fms · Loss: %.0f%% · Min: %.1f · Max: %.1f", gwAvg, gwLoss, gwMin, gwMax))
		pubStat := statStyle.Render(fmt.Sprintf("  %.1fms · Loss: %.0f%% · Min: %.1f · Max: %.1f", pubAvg, pubLoss, pubMin, pubMax))

		content = fmt.Sprintf("%s\n%s %s\n%s\n%s %s\n%s",
			lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("LIVE LATENCY TELEMETRY"),
			lblStyle.Render("Gateway:"), gwSpark,
			gwStat,
			lblStyle.Render("Internet:"), pubSpark,
			pubStat,
		)
	}

	return CardStyle.Width(width).Render(content)
}

func renderTicker(m *Model, width int) string {
	logs := m.poller.EventLogs()
	start := 0
	if len(logs) > 3 {
		start = len(logs) - 3
	}
	recent := logs[start:]

	wrapWidth := width - 4
	if wrapWidth < 10 {
		wrapWidth = 10
	}
	lineStyle := lipgloss.NewStyle().Foreground(ColorWhite).Width(wrapWidth)

	var logLines []string
	for _, l := range recent {
		logLines = append(logLines, lineStyle.Render(l))
	}

	if len(logLines) == 0 {
		logLines = append(logLines, lipgloss.NewStyle().Foreground(ColorMuted).Render("Awaiting network events..."))
	}

	content := fmt.Sprintf("%s\n%s",
		lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("RECENT EVENT TICKER"),
		strings.Join(logLines, "\n"),
	)

	return CardStyle.Width(width).Render(content)
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000.0)
}
