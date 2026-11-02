package tui

import (
	"fmt"
	"strings"

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

	headerText := lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("MODULAR DIAGNOSTIC FAULT ISOLATION")
	subText := lipgloss.NewStyle().Foreground(ColorMuted).Width(cardWidth - 4).Render("Press [D] to re-run all diagnostic modules | Evidence-backed root cause engine")

	header := fmt.Sprintf("%s\n%s", headerText, subText)
	sb.WriteString(CardStyle.Width(cardWidth).Render(header))
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
		sb.WriteString(renderDiagCard(res, cardWidth))
		if i < len(m.diagResults)-1 {
			sb.WriteString("\n\n")
		}
	}

	return sb.String()
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
