package tui

import (
	"fmt"
	"strings"

	"argus/internal/dhcp"
	"argus/internal/diagnostics"
	"github.com/charmbracelet/lipgloss"
)

func renderDiagnosticsView(m *Model, width int) string {
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

	headerText := lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("MODULAR DIAGNOSTIC FAULT ISOLATION")
	subText := lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render("Press [D] to re-run all diagnostic modules | [B] to refresh baseline")

	header := fmt.Sprintf("%s\n%s", headerText, subText)
	sb.WriteString(CardStyle.Width(cardWidth).Render(header))
	sb.WriteString("\n\n")

	// Dedicated Section: DHCP Intelligence & Configuration Baseline
	sb.WriteString(renderDHCPSection(m, cardWidth, textWidth))
	sb.WriteString("\n\n")

	if m.isScanningDiagnostics {
		spinner := lipgloss.NewStyle().Foreground(ColorAmber).Bold(true).Render("Running deep network diagnostics across all modules...")
		sb.WriteString(CardStyle.Width(cardWidth).Render(spinner))
		return sb.String()
	}

	if len(m.diagResults) == 0 {
		msg := lipgloss.NewStyle().Foreground(ColorMuted).Render("No diagnostic scan executed yet. Press [D] to run full suite.")
		sb.WriteString(CardStyle.Width(cardWidth).Render(msg))
		return sb.String()
	}

	for i, res := range m.diagResults {
		// Avoid duplicate rendering if dhcp_intel is also in diagResults
		if res.ID == "dhcp_intel" {
			continue
		}
		sb.WriteString(renderDiagCard(res, cardWidth))
		if i < len(m.diagResults)-1 {
			sb.WriteString("\n\n")
		}
	}

	return sb.String()
}

func renderDHCPSection(m *Model, cardWidth, textWidth int) string {
	pipe := m.poller.Status()
	cfg := pipe.DHCPConfig
	baseline := pipe.Baseline

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorCyan)
	lblStyle := lipgloss.NewStyle().Foreground(ColorMuted).Width(16)
	valStyle := lipgloss.NewStyle().Foreground(ColorWhite).Bold(true)

	var sb strings.Builder
	sb.WriteString(titleStyle.Render("DHCP INTELLIGENCE & CONFIGURATION BASELINE"))
	sb.WriteString("\n")

	// IP Assignment Mode
	assignMode := "Unknown / Uninspected"
	assignColor := ColorMuted
	if cfg != nil {
		switch cfg.Assignment {
		case dhcp.AssignmentDHCP:
			assignMode = "DHCP (Dynamic Leasing)"
			assignColor = ColorEmerald
		case dhcp.AssignmentStatic:
			assignMode = "Static IP (Manual)"
			assignColor = ColorCyan
		default:
			assignMode = "Unknown / Unmanaged"
		}
	}
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• IP Mode:"), lipgloss.NewStyle().Foreground(assignColor).Bold(true).Render(assignMode)))

	// DHCP Server
	dhcpServer := "None / Unavailable"
	if cfg != nil && cfg.DHCPServerIP != "" {
		dhcpServer = cfg.DHCPServerIP
		if cfg.LeaseExpires != nil {
			dhcpServer += fmt.Sprintf(" (Expires: %s)", cfg.LeaseExpires.Format("15:04:05"))
		}
	}
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• DHCP Server:"), valStyle.Render(dhcpServer)))

	// Current Gateway & DNS
	gw := "None"
	if cfg != nil && cfg.GatewayIP != "" {
		gw = cfg.GatewayIP
	} else if m.gatewayIP != "" {
		gw = m.gatewayIP
	}
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Gateway:"), valStyle.Render(gw)))

	dnsStr := "None"
	if cfg != nil && len(cfg.DNSServers) > 0 {
		dnsStr = strings.Join(cfg.DNSServers, ", ")
	}
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• DNS Servers:"), valStyle.Render(dnsStr)))

	// Baseline Status
	baselineStatus := "No Baseline Established"
	baselineColor := ColorMuted
	if baseline != nil {
		typeLabel := "Initial Observed"
		if baseline.Type == dhcp.BaselineUserConfirmed {
			typeLabel = "User-Confirmed"
		}
		if len(pipe.RecentChanges) > 0 {
			baselineStatus = fmt.Sprintf("Drift Detected (%s, %d change(s))", typeLabel, len(pipe.RecentChanges))
			baselineColor = ColorAmber
		} else {
			baselineStatus = fmt.Sprintf("Stable (%s, Established: %s)", typeLabel, baseline.EstablishedAt.Format("15:04:05"))
			baselineColor = ColorEmerald
		}
	}
	sb.WriteString(fmt.Sprintf("%s %s\n", lblStyle.Render("• Baseline:"), lipgloss.NewStyle().Foreground(baselineColor).Bold(true).Render(baselineStatus)))

	// Changes list if any
	if len(pipe.RecentChanges) > 0 {
		sb.WriteString("\n" + lipgloss.NewStyle().Bold(true).Foreground(ColorAmber).Render("Observed Changes from Baseline:") + "\n")
		for _, chg := range pipe.RecentChanges {
			sb.WriteString(fmt.Sprintf("  ⚠ %s (%s -> %s)\n", chg.FieldName, chg.OldValue, chg.NewValue))
		}
	}

	sb.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorMuted).Render("Press [B] to manage baseline (requires confirmation)"))

	return CardStyle.Width(cardWidth).Render(sb.String())
}

func renderDiagCard(res diagnostics.DiagnosticResult, width int) string {
	var badgeStyle lipgloss.Style
	badgeText := fmt.Sprintf("[%s]", res.Category)

	switch res.Category {
	case diagnostics.CategoryConfirmed:
		if res.Severity == diagnostics.SeverityCritical || res.Severity == diagnostics.SeverityWarning {
			badgeStyle = lipgloss.NewStyle().Background(ColorCoral).Foreground(lipgloss.Color("#000000")).Bold(true)
		} else {
			badgeStyle = lipgloss.NewStyle().Background(ColorEmerald).Foreground(lipgloss.Color("#000000")).Bold(true)
		}
	case diagnostics.CategorySuspected:
		badgeStyle = lipgloss.NewStyle().Background(ColorAmber).Foreground(lipgloss.Color("#000000")).Bold(true)
	case diagnostics.CategoryHealthy:
		badgeStyle = lipgloss.NewStyle().Background(ColorEmerald).Foreground(lipgloss.Color("#000000")).Bold(true)
		badgeText = "[HEALTHY ✔]"
	default:
		badgeStyle = lipgloss.NewStyle().Background(ColorMuted).Foreground(lipgloss.Color("#000000"))
	}

	textWidth := width - 4
	if textWidth < 10 {
		textWidth = 10
	}

	badgeRendered := badgeStyle.Render(" " + badgeText + " ")
	titleRendered := lipgloss.NewStyle().Bold(true).Foreground(ColorWhite).Width(textWidth).Render(res.Title)
	titleLine := fmt.Sprintf("%s\n%s", badgeRendered, titleRendered)

	summaryLine := fmt.Sprintf("%s: %s",
		lipgloss.NewStyle().Foreground(ColorMuted).Render("Summary"),
		lipgloss.NewStyle().Foreground(ColorWhite).Width(textWidth).Render(res.Summary),
	)

	var evidenceLines []string
	for _, e := range res.Evidence {
		wrappedEvidence := lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth - 2).Render(e)
		evidenceLines = append(evidenceLines, "  • "+wrappedEvidence)
	}

	content := fmt.Sprintf("%s\n%s", titleLine, summaryLine)
	if len(evidenceLines) > 0 {
		content += fmt.Sprintf("\n%s\n%s", lipgloss.NewStyle().Foreground(ColorCyan).Render("Evidence:"), strings.Join(evidenceLines, "\n"))
	}
	if res.Remediation != "" {
		remed := lipgloss.NewStyle().Foreground(ColorAmber).Width(textWidth).Render("Action: " + res.Remediation)
		content += "\n" + remed
	}

	return CardStyle.Width(width).Render(content)
}
