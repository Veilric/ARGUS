package tui

import (
	"fmt"
	"strings"

	"argus/internal/discovery"

	"github.com/charmbracelet/lipgloss"
)

func renderDiscoveryView(m *Model, width int) string {
	var sb strings.Builder

	cardWidth := width - 4
	if cardWidth < 20 {
		cardWidth = width - 2
	}
	if cardWidth < 10 {
		cardWidth = 10
	}

	textWidth := cardWidth - 4
	if textWidth < 10 {
		textWidth = 10
	}

	statusText := "Passive Mode (Zero network packets emitted)"
	if m.scanner.IsScanning() {
		statusText = fmt.Sprintf("Gentle Sweep in Progress... (%d/%d)", m.scanProgressCurrent, m.scanProgressTotal)
	}

	headerTitle := lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("LOCAL SUBNET DEVICE INVENTORY")
	modeLine := fmt.Sprintf("%s: %s",
		lipgloss.NewStyle().Foreground(ColorMuted).Render("Mode"),
		lipgloss.NewStyle().Foreground(ColorEmerald).Render(statusText),
	)

	var helpLine string
	if m.showScanConfirm {
		helpLine = lipgloss.NewStyle().Foreground(ColorAmber).Bold(true).Width(textWidth).Render("AUTHORIZATION PENDING: Press [Enter / Y] to start, [Esc / N] to cancel")
	} else if m.scanner.IsScanning() {
		helpLine = lipgloss.NewStyle().Foreground(ColorCoral).Bold(true).Width(textWidth).Render("Active sweep in progress... Press [C] or [Esc] to cancel")
	} else {
		helpLine = lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render("Press [S] to configure sweep, [R] to reload ARP cache")
	}

	header := fmt.Sprintf("%s\n%s\n%s", headerTitle, modeLine, helpLine)
	sb.WriteString(CardStyle.Width(cardWidth).Render(header))
	sb.WriteString("\n\n")

	devices := m.scanner.Devices()
	if len(devices) == 0 {
		msg := lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render("No devices discovered in ARP cache yet. Press [S] to run gentle sweep.")
		sb.WriteString(CardStyle.Width(cardWidth).Render(msg))
		return sb.String()
	}

	var rowLines []string

	if cardWidth >= 65 {
		// Wide 4-column table
		ipCol := lipgloss.NewStyle().Bold(true).Width(16).Render("IP Address")
		macCol := lipgloss.NewStyle().Bold(true).Width(18).Render("MAC Address")
		vendorCol := lipgloss.NewStyle().Bold(true).Width(18).Render("Vendor")
		ifaceCol := lipgloss.NewStyle().Bold(true).Width(8).Render("Iface")

		tableHeader := fmt.Sprintf("%s %s %s %s", ipCol, macCol, vendorCol, ifaceCol)
		divider := lipgloss.NewStyle().Foreground(lipgloss.Color("#30363D")).Render(strings.Repeat("─", textWidth))
		rowLines = append(rowLines, tableHeader, divider)

		for _, dev := range devices {
			ip := lipgloss.NewStyle().Foreground(ColorCyan).Width(16).Render(dev.IP)
			mac := lipgloss.NewStyle().Foreground(ColorWhite).Width(18).Render(dev.MAC)
			vendor := lipgloss.NewStyle().Foreground(ColorAmber).Width(18).Render(truncateString(dev.Vendor, 17))
			iface := lipgloss.NewStyle().Foreground(ColorMuted).Width(8).Render(dev.Interface)

			rowLines = append(rowLines, fmt.Sprintf("%s %s %s %s", ip, mac, vendor, iface))
		}
	} else if cardWidth >= 48 {
		// Medium 3-column table
		ipCol := lipgloss.NewStyle().Bold(true).Width(15).Render("IP Address")
		macCol := lipgloss.NewStyle().Bold(true).Width(17).Render("MAC Address")
		vendorWidth := textWidth - 34
		if vendorWidth < 10 {
			vendorWidth = 10
		}
		vendorCol := lipgloss.NewStyle().Bold(true).Width(vendorWidth).Render("Vendor")

		tableHeader := fmt.Sprintf("%s %s %s", ipCol, macCol, vendorCol)
		divider := lipgloss.NewStyle().Foreground(lipgloss.Color("#30363D")).Render(strings.Repeat("─", textWidth))
		rowLines = append(rowLines, tableHeader, divider)

		for _, dev := range devices {
			ip := lipgloss.NewStyle().Foreground(ColorCyan).Width(15).Render(dev.IP)
			mac := lipgloss.NewStyle().Foreground(ColorWhite).Width(17).Render(dev.MAC)
			vendor := lipgloss.NewStyle().Foreground(ColorAmber).Width(vendorWidth).Render(truncateString(dev.Vendor, vendorWidth-1))

			rowLines = append(rowLines, fmt.Sprintf("%s %s %s", ip, mac, vendor))
		}
	} else {
		// Narrow 2-line compact list
		for i, dev := range devices {
			line1 := fmt.Sprintf("• %s (%s)",
				lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(dev.IP),
				lipgloss.NewStyle().Foreground(ColorAmber).Render(truncateString(dev.Vendor, 16)),
			)
			line2 := fmt.Sprintf("  MAC: %s │ %s",
				lipgloss.NewStyle().Foreground(ColorWhite).Render(dev.MAC),
				lipgloss.NewStyle().Foreground(ColorMuted).Render(dev.State),
			)
			rowLines = append(rowLines, line1, line2)
			if i < len(devices)-1 {
				rowLines = append(rowLines, "")
			}
		}
	}

	totalText := fmt.Sprintf("\n%s: %d", lipgloss.NewStyle().Foreground(ColorMuted).Render("Total Endpoints Discovered"), len(devices))
	rowLines = append(rowLines, totalText)

	sb.WriteString(CardStyle.Width(cardWidth).Render(strings.Join(rowLines, "\n")))
	return sb.String()
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-2] + ".."
}

// renderScanConfirmationOverlay renders the active sweep authorization dialog responsively.
// It adapts to the actual available content height (availHeight) and width.
func renderScanConfirmationOverlay(m *Model, width, availHeight int) string {
	cardWidth := width - 4
	if cardWidth < 20 {
		cardWidth = width - 2
	}
	if cardWidth < 10 {
		cardWidth = 10
	}
	textWidth := cardWidth - 4
	if textWidth < 10 {
		textWidth = 10
	}

	plan := m.pendingSweepPlan
	if plan == nil {
		return ""
	}

	// 1. Safety check for undersized terminal windows or content areas
	if availHeight < 6 || width < 40 {
		return renderUndersizedTerminalWarning(cardWidth, textWidth)
	}

	// 2. Select card layout responsively: prefer fullest card that fits inside availHeight
	var cardContent string

	if availHeight >= 18 && cardWidth >= 55 {
		fullCard := renderFullScanConfirmationCard(plan, cardWidth, textWidth)
		if lipgloss.Height(fullCard) <= availHeight {
			cardContent = fullCard
		}
	}

	if cardContent == "" && availHeight >= 8 && cardWidth >= 40 {
		medCard := renderMediumScanConfirmationCard(plan, cardWidth, textWidth)
		if lipgloss.Height(medCard) <= availHeight {
			cardContent = medCard
		}
	}

	if cardContent == "" {
		compactCard := renderCompactScanConfirmationCard(plan, cardWidth, textWidth)
		if lipgloss.Height(compactCard) <= availHeight {
			cardContent = compactCard
		} else if availHeight >= 6 {
			cardContent = compactCard
		} else {
			return renderUndersizedTerminalWarning(cardWidth, textWidth)
		}
	}

	// 3. If card content fits within available content height, return directly
	cardLines := lipgloss.Height(cardContent)
	if cardLines <= availHeight {
		return cardContent
	}

	// 4. If card content exceeds available height, use dedicated scrollable confirmation viewport
	if !m.confirmVpReady || m.confirmViewport.Width != width || m.confirmViewport.Height != availHeight {
		m.confirmViewport.Width = width
		m.confirmViewport.Height = availHeight
		m.confirmVpReady = true
	}
	m.confirmViewport.SetContent(cardContent)
	return m.confirmViewport.View()
}

func renderUndersizedTerminalWarning(cardWidth, textWidth int) string {
	title := lipgloss.NewStyle().Bold(true).Foreground(ColorCoral).Render("⚠ TERMINAL WINDOW TOO SMALL")
	desc := lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render(
		"Terminal window must be at least 40x12 to review scan scope, safety parameters, and authorization notice before probing.",
	)
	ctrl := lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("Press [Esc / N] to dismiss.")

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorCoral).
		Padding(0, 1).
		Width(cardWidth).
		Render(fmt.Sprintf("%s\n%s\n%s", title, desc, ctrl))
}

func renderCompactScanConfirmationCard(plan *discovery.SweepPlan, cardWidth, textWidth int) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorAmber)
	lblStyle := lipgloss.NewStyle().Foreground(ColorMuted)
	valStyle := lipgloss.NewStyle().Foreground(ColorWhite).Bold(true)
	warnStyle := lipgloss.NewStyle().Foreground(ColorCoral)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("⚠ ACTIVE SWEEP AUTH"))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s %s (%dh)\n",
		lblStyle.Render("Target:"),
		lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(plan.CIDR),
		plan.TargetCount,
	))
	sb.WriteString(fmt.Sprintf("%s %s │ %s %s\n",
		lblStyle.Render("Iface:"),
		valStyle.Render(truncateString(plan.InterfaceName, 8)),
		lblStyle.Render("Probe:"),
		valStyle.Render(truncateString(plan.ProbeType, 12)),
	))
	sb.WriteString(fmt.Sprintf("%s %d/s (%dw) │ %s\n",
		lblStyle.Render("Limits:"),
		plan.MaxRate,
		plan.MaxConcurrency,
		valStyle.Render(truncateString(plan.TargetRange, 14)),
	))
	sb.WriteString(warnStyle.Width(textWidth).Render("Notice: Real packets (IDS/IPS visible)"))
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("[Enter/Y] Authorize  [Esc/N] Cancel"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAmber).
		Padding(0, 1).
		Width(cardWidth).
		Render(sb.String())
}

func renderMediumScanConfirmationCard(plan *discovery.SweepPlan, cardWidth, textWidth int) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorAmber)
	lblStyle := lipgloss.NewStyle().Foreground(ColorMuted)
	valStyle := lipgloss.NewStyle().Foreground(ColorWhite).Bold(true)
	warnStyle := lipgloss.NewStyle().Foreground(ColorCoral)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("⚠ ACTIVE SUBNET DISCOVERY AUTHORIZATION REQUIRED"))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s %s  │  %s %s (%d hosts)\n",
		lblStyle.Render("• Iface:"),
		valStyle.Render(truncateString(plan.InterfaceName, 12)),
		lblStyle.Render("• Target:"),
		lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(plan.CIDR),
		plan.TargetCount,
	))
	sb.WriteString(fmt.Sprintf("%s %s  │  %s %s\n",
		lblStyle.Render("• Range:"),
		valStyle.Render(truncateString(plan.TargetRange, 16)),
		lblStyle.Render("• Probe:"),
		valStyle.Render(truncateString(plan.ProbeType, 16)),
	))
	sb.WriteString(fmt.Sprintf("%s %s  │  %s %s\n",
		lblStyle.Render("• Limits:"),
		valStyle.Render(fmt.Sprintf("%d/s throttle", plan.MaxRate)),
		lblStyle.Render("• Concurrency:"),
		valStyle.Render(fmt.Sprintf("%d workers max", plan.MaxConcurrency)),
	))
	sb.WriteString(warnStyle.Width(textWidth).Render("Notice: Active probing transmits real network packets (IDS/IPS observable)."))
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("[Enter / Y] Authorize & Scan      [Esc / N] Cancel"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAmber).
		Padding(0, 1).
		Width(cardWidth).
		Render(sb.String())
}

func renderFullScanConfirmationCard(plan *discovery.SweepPlan, cardWidth, textWidth int) string {
	lblWidth := 18
	if textWidth < 46 {
		lblWidth = 14
	}
	lblStyle := lipgloss.NewStyle().Foreground(ColorMuted).Width(lblWidth)
	valStyle := lipgloss.NewStyle().Foreground(ColorWhite).Bold(true)
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorAmber)
	warnStyle := lipgloss.NewStyle().Foreground(ColorCoral)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("⚠ ACTIVE SUBNET DISCOVERY AUTHORIZATION"))
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render(
		"Explicit authorization required before transmitting active probe packets across the local broadcast domain.",
	))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Selected Interface:"), valStyle.Render(plan.InterfaceName)))
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Local Host IP:"), valStyle.Render(plan.LocalIP)))
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Target Subnet CIDR:"), valStyle.Render(plan.CIDR)))
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Target IP Range:"), valStyle.Render(plan.TargetRange)))
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Target Count:"), valStyle.Render(fmt.Sprintf("%d addresses (Net/Bcast/Self excluded)", plan.TargetCount))))
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Probe Method:"), valStyle.Render(plan.ProbeType)))
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Max Probe Rate:"), valStyle.Render(fmt.Sprintf("%d pkts/sec (Conservative throttle)", plan.MaxRate))))
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Concurrency:"), valStyle.Render(fmt.Sprintf("%d workers max", plan.MaxConcurrency))))
	sb.WriteString("\n")
	sb.WriteString(warnStyle.Width(textWidth).Render("Notice: Active probing generates real network packets. Active discovery may be observed by network security monitoring, IDS/IPS, or managed switches."))
	sb.WriteString("\n\n")
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("[Enter / Y] Authorize & Scan      [Esc / N] Cancel"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAmber).
		Padding(1, 2).
		Width(cardWidth).
		Render(sb.String())
}
