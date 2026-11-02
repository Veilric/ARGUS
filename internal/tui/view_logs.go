package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func renderLogsView(m *Model, width int) string {
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

	headerTitle := lipgloss.NewStyle().Bold(true).Foreground(ColorCyan).Render("SESSION INCIDENT & TRANSITION LOGS")
	headerSub := lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render(
		fmt.Sprintf("Logging to %s/argus.log | Auto-rotating at %dMB", m.cfg.LogDir, m.cfg.MaxLogSizeMB),
	)

	header := fmt.Sprintf("%s\n%s", headerTitle, headerSub)
	sb.WriteString(CardStyle.Width(cardWidth).Render(header))
	sb.WriteString("\n\n")

	logs := m.poller.EventLogs()
	if len(logs) == 0 {
		msg := lipgloss.NewStyle().Foreground(ColorMuted).Width(textWidth).Render("No recorded state transitions or incidents yet.")
		sb.WriteString(CardStyle.Width(cardWidth).Render(msg))
		return sb.String()
	}

	logWrapStyle := lipgloss.NewStyle().Width(textWidth)
	var formattedLogs []string
	for _, l := range logs {
		var styled string
		if strings.Contains(l, "FAIL") || strings.Contains(l, "UNREACHABLE") || strings.Contains(l, "CRITICAL") {
			styled = lipgloss.NewStyle().Foreground(ColorCoral).Bold(true).Render(l)
		} else if strings.Contains(l, "WARN") || strings.Contains(l, "DRIFT") || strings.Contains(l, "[CONFIG]") {
			styled = lipgloss.NewStyle().Foreground(ColorAmber).Render(l)
		} else if strings.Contains(l, "[BASELINE]") {
			styled = lipgloss.NewStyle().Foreground(ColorCyan).Render(l)
		} else if strings.Contains(l, "OK") || strings.Contains(l, "CLEAN") || strings.Contains(l, "HEALTHY") {
			styled = lipgloss.NewStyle().Foreground(ColorEmerald).Render(l)
		} else {
			styled = lipgloss.NewStyle().Foreground(ColorWhite).Render(l)
		}
		formattedLogs = append(formattedLogs, logWrapStyle.Render(styled))
	}

	sb.WriteString(CardStyle.Width(cardWidth).Render(strings.Join(formattedLogs, "\n")))
	return sb.String()
}
