package tui

import (
	"fmt"
	"strings"

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
	helpLine := lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render("Press [S] for gentle sweep, [R] to reload")

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
