package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// Palette
	ColorCyan    = lipgloss.Color("#00D2FF")
	ColorEmerald = lipgloss.Color("#00FF88")
	ColorAmber   = lipgloss.Color("#FFB800")
	ColorCoral   = lipgloss.Color("#FF4D4D")
	ColorMuted   = lipgloss.Color("#6C7A89")
	ColorDarkBg  = lipgloss.Color("#0E1217")
	ColorCardBg  = lipgloss.Color("#161B22")
	ColorWhite   = lipgloss.Color("#F0F6FC")

	// Base container
	ContainerStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorCyan).
			Padding(0, 1)

	// Card box
	CardStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#30363D")).
			Padding(0, 1)

	// Scroll indicator badge
	ScrollIndicatorStyle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true)

	// Header styles
	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true)

	BadgeElevatedAdmin = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#000000")).
				Background(ColorCoral).
				Bold(true).
				Padding(0, 1)

	BadgeElevatedUser = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#000000")).
				Background(ColorCyan).
				Bold(true).
				Padding(0, 1)

	// Pipeline Node Styles
	NodeOnline = lipgloss.NewStyle().
			Foreground(ColorEmerald).
			Bold(true)

	NodeOffline = lipgloss.NewStyle().
			Foreground(ColorCoral).
			Bold(true)

	NodeWarning = lipgloss.NewStyle().
			Foreground(ColorAmber).
			Bold(true)

	ArrowStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// Tab styles
	ActiveTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorCyan).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(ColorCyan).
			Padding(0, 1)

	InactiveTabStyle = lipgloss.NewStyle().
				Foreground(ColorMuted).
				Padding(0, 1)

	// Footer style
	FooterStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Border(lipgloss.NormalBorder(), true, false, false, false).
			BorderForeground(lipgloss.Color("#30363D")).
			PaddingTop(0)

	// Help / Toast popup
	ToastStyle = lipgloss.NewStyle().
			Foreground(ColorWhite).
			Background(lipgloss.Color("#21262D")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorEmerald).
			Padding(0, 1)
)
