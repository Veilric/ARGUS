package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"argus/internal/dhcp"
)

// renderBaselineConfirmationOverlay renders the baseline refresh confirmation dialog responsively.
func renderBaselineConfirmationOverlay(m *Model, width, availHeight int) string {
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

	cfg := m.pendingBaselineCfg
	oldB := m.pendingOldBaseline
	if cfg == nil {
		return ""
	}

	// 1. Safety check for undersized terminal windows or content areas
	if availHeight < 6 || width < 40 {
		return renderUndersizedBaselineWarning(cardWidth, textWidth)
	}

	// 2. Select card layout responsively: prefer fullest card that fits inside availHeight
	var cardContent string

	if availHeight >= 16 && cardWidth >= 55 {
		fullCard := renderFullBaselineConfirmationCard(m.ifaceName, oldB, cfg, cardWidth, textWidth)
		if lipgloss.Height(fullCard) <= availHeight {
			cardContent = fullCard
		}
	}

	if cardContent == "" && availHeight >= 8 && cardWidth >= 40 {
		medCard := renderMediumBaselineConfirmationCard(m.ifaceName, oldB, cfg, cardWidth, textWidth)
		if lipgloss.Height(medCard) <= availHeight {
			cardContent = medCard
		}
	}

	if cardContent == "" {
		compactCard := renderCompactBaselineConfirmationCard(m.ifaceName, oldB, cfg, cardWidth, textWidth)
		if lipgloss.Height(compactCard) <= availHeight {
			cardContent = compactCard
		} else if availHeight >= 6 {
			cardContent = compactCard
		} else {
			return renderUndersizedBaselineWarning(cardWidth, textWidth)
		}
	}

	// 3. If card content fits within available content height, return directly
	cardLines := lipgloss.Height(cardContent)
	if cardLines <= availHeight {
		return cardContent
	}

	// 4. If card content exceeds available height, use dedicated scrollable baseline confirmation viewport
	if !m.baselineConfirmVpReady || m.baselineConfirmVp.Width != width || m.baselineConfirmVp.Height != availHeight {
		m.baselineConfirmVp.Width = width
		m.baselineConfirmVp.Height = availHeight
		m.baselineConfirmVpReady = true
	}
	m.baselineConfirmVp.SetContent(cardContent)
	return m.baselineConfirmVp.View()
}

func renderUndersizedBaselineWarning(cardWidth, textWidth int) string {
	title := lipgloss.NewStyle().Bold(true).Foreground(ColorCoral).Render("⚠ TERMINAL WINDOW TOO SMALL")
	desc := lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render(
		"Terminal window must be at least 40x12 to review baseline differences before confirming.",
	)
	ctrl := lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("Press [Esc / N] to dismiss.")

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorCoral).
		Padding(0, 1).
		Width(cardWidth).
		Render(fmt.Sprintf("%s\n%s\n%s", title, desc, ctrl))
}

func renderFullBaselineConfirmationCard(ifaceName string, oldB *dhcp.ConfigBaseline, cfg *dhcp.DHCPConfig, cardWidth, textWidth int) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorAmber)
	lblStyle := lipgloss.NewStyle().Foreground(ColorMuted).Width(16)
	valStyle := lipgloss.NewStyle().Foreground(ColorWhite).Bold(true)
	diffStyle := lipgloss.NewStyle().Foreground(ColorCoral).Bold(true)
	sameStyle := lipgloss.NewStyle().Foreground(ColorEmerald)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("⚠ CONFIRM NETWORK BASELINE REFRESH"))
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render(
		"Refreshing will establish a User-Confirmed baseline and save a backup (baselines.json.bak).",
	))
	sb.WriteString("\n\n")

	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("Interface:"), lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(ifaceName)))

	oldTypeStr := "None (New Baseline)"
	if oldB != nil {
		if oldB.Type == dhcp.BaselineUserConfirmed {
			oldTypeStr = fmt.Sprintf("User-Confirmed (Established: %s)", oldB.EstablishedAt.Format("15:04:05"))
		} else {
			oldTypeStr = fmt.Sprintf("Initial Observed (Established: %s)", oldB.EstablishedAt.Format("15:04:05"))
		}
	}
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("Current Type:"), valStyle.Render(oldTypeStr)))
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("New Type:"), lipgloss.NewStyle().Foreground(ColorEmerald).Bold(true).Render("USER_CONFIRMED (User-Approved Reference)")))

	divider := lipgloss.NewStyle().Foreground(lipgloss.Color("#30363D")).Render(strings.Repeat("─", textWidth))
	sb.WriteString(divider + "\n")

	// Field comparisons
	renderFieldDiff := func(name, oldVal, newVal string) {
		if oldVal == "" {
			oldVal = "—"
		}
		if newVal == "" {
			newVal = "—"
		}
		var status string
		if oldVal != newVal {
			status = diffStyle.Render(fmt.Sprintf("%s ──> %s [CHANGED]", oldVal, newVal))
		} else {
			status = sameStyle.Render(fmt.Sprintf("%s [UNCHANGED]", newVal))
		}
		sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render(name+":"), status))
	}

	oldIP := ""
	oldPrefix := 0
	oldGW := ""
	oldDHCP := ""
	oldDNS := ""
	oldAssign := ""
	if oldB != nil {
		oldIP = oldB.IPv4Address
		oldPrefix = oldB.IPv4Prefix
		oldGW = oldB.GatewayIP
		oldDHCP = oldB.DHCPServerIP
		oldDNS = strings.Join(oldB.DNSServers, ", ")
		oldAssign = string(oldB.Assignment)
	}

	renderFieldDiff("IPv4 Address", oldIP, cfg.IPv4Address)
	if cfg.IPv4Prefix > 0 || oldPrefix > 0 {
		renderFieldDiff("Subnet Prefix", fmt.Sprintf("/%d", oldPrefix), fmt.Sprintf("/%d", cfg.IPv4Prefix))
	}
	renderFieldDiff("Default Gateway", oldGW, cfg.GatewayIP)
	renderFieldDiff("DHCP Server", oldDHCP, cfg.DHCPServerIP)
	renderFieldDiff("DNS Servers", oldDNS, strings.Join(cfg.DNSServers, ", "))
	renderFieldDiff("Assignment Mode", oldAssign, string(cfg.Assignment))

	sb.WriteString(divider + "\n")
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render(
		"[Enter / Y] Confirm Baseline Refresh   [Esc / N] Cancel & Keep Current",
	))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAmber).
		Padding(0, 1).
		Width(cardWidth).
		Render(sb.String())
}

func renderMediumBaselineConfirmationCard(ifaceName string, oldB *dhcp.ConfigBaseline, cfg *dhcp.DHCPConfig, cardWidth, textWidth int) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorAmber)
	lblStyle := lipgloss.NewStyle().Foreground(ColorMuted)
	valStyle := lipgloss.NewStyle().Foreground(ColorWhite).Bold(true)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("⚠ CONFIRM BASELINE REFRESH"))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s %s │ %s %s\n",
		lblStyle.Render("Iface:"),
		lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(ifaceName),
		lblStyle.Render("Mode:"),
		valStyle.Render("User-Confirmed"),
	))

	oldGW := "—"
	if oldB != nil && oldB.GatewayIP != "" {
		oldGW = oldB.GatewayIP
	}
	newGW := "—"
	if cfg.GatewayIP != "" {
		newGW = cfg.GatewayIP
	}
	sb.WriteString(fmt.Sprintf("%s %s ──> %s\n", lblStyle.Render("Gateway:"), oldGW, valStyle.Render(newGW)))

	oldIP := "—"
	if oldB != nil && oldB.IPv4Address != "" {
		oldIP = oldB.IPv4Address
	}
	newIP := "—"
	if cfg.IPv4Address != "" {
		newIP = cfg.IPv4Address
	}
	sb.WriteString(fmt.Sprintf("%s %s ──> %s\n", lblStyle.Render("IPv4:"), oldIP, valStyle.Render(newIP)))

	sb.WriteString(lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render("Backup baselines.json.bak will be saved.") + "\n")
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("[Enter/Y] Confirm  [Esc/N] Cancel"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAmber).
		Padding(0, 1).
		Width(cardWidth).
		Render(sb.String())
}

func renderCompactBaselineConfirmationCard(ifaceName string, oldB *dhcp.ConfigBaseline, cfg *dhcp.DHCPConfig, cardWidth, textWidth int) string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorAmber)
	lblStyle := lipgloss.NewStyle().Foreground(ColorMuted)
	valStyle := lipgloss.NewStyle().Foreground(ColorWhite).Bold(true)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("⚠ REFRESH BASELINE?"))
	sb.WriteString(fmt.Sprintf(" %s (%s)\n",
		lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(ifaceName),
		valStyle.Render(cfg.IPv4Address),
	))
	oldGW := "—"
	if oldB != nil && oldB.GatewayIP != "" {
		oldGW = oldB.GatewayIP
	}
	sb.WriteString(fmt.Sprintf("%s %s -> %s\n", lblStyle.Render("GW:"), oldGW, cfg.GatewayIP))
	sb.WriteString(lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("[Enter/Y] Confirm  [Esc/N] Cancel"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAmber).
		Padding(0, 1).
		Width(cardWidth).
		Render(sb.String())
}
