package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"argus/internal/config"
	"argus/internal/diagnostics"
	"argus/internal/discovery"
	"argus/internal/platform"
	"argus/internal/reporter"
	"argus/internal/sysmon"
	"argus/internal/telemetry"
	"argus/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
)

const version = "1.0.0"

func main() {
	scanFlag := flag.Bool("scan", false, "Run one-shot headless diagnostic scan without opening TUI")
	exportFlag := flag.String("export", "", "Directory path to export Markdown and JSON incident report")
	ifaceFlag := flag.String("iface", "", "Override network interface name (auto-detected if omitted)")
	logDirFlag := flag.String("log-dir", "./logs", "Directory for session event logs")
	reportDirFlag := flag.String("report-dir", "./reports", "Directory for exported incident reports")
	versionFlag := flag.Bool("version", false, "Display ARGUS version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ARGUS by Veilric — Portable Network Observation, Diagnostics & Discovery Toolkit (v%s)\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  argus [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nInteractive Controls (TUI Mode):\n")
		fmt.Fprintf(os.Stderr, "  [1-4 / Tab]   Switch between Telemetry, Diagnostics, Devices, and Logs\n")
		fmt.Fprintf(os.Stderr, "  [D / Space]   Run comprehensive diagnostic scan\n")
		fmt.Fprintf(os.Stderr, "  [S]           Run gentle, rate-limited subnet device sweep\n")
		fmt.Fprintf(os.Stderr, "  [E]           Export timestamped Markdown & JSON incident report\n")
		fmt.Fprintf(os.Stderr, "  [R]           Refresh interface, gateway, and ARP cache\n")
		fmt.Fprintf(os.Stderr, "  [Q / Ctrl+C]  Quit\n")
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("ARGUS by Veilric v%s (Go static binary, cross-platform)\n", version)
		os.Exit(0)
	}

	cfg := config.DefaultConfig()
	if *ifaceFlag != "" {
		cfg.InterfaceName = *ifaceFlag
	}
	if *logDirFlag != "" {
		cfg.LogDir = *logDirFlag
	}
	if *reportDirFlag != "" {
		cfg.ReportDir = *reportDirFlag
	}

	adapter := platform.NewAdapter()
	poller := telemetry.NewPoller(cfg, adapter)
	engine := diagnostics.NewEngine(adapter)
	scanner := discovery.NewScanner(adapter)
	monitor := sysmon.NewMonitor()
	logger, _ := reporter.NewSessionLogger(cfg)

	// Mode 1: One-shot CLI Scan
	if *scanFlag {
		runHeadlessScan(cfg, adapter, poller, engine, scanner, *exportFlag)
		return
	}

	// Mode 2: Interactive TUI Widget
	model := tui.NewModel(cfg, adapter, poller, engine, scanner, monitor, logger)
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting ARGUS TUI: %v\n", err)
		os.Exit(1)
	}
}

func runHeadlessScan(
	cfg *config.Config,
	adapter platform.NetworkAdapter,
	poller *telemetry.Poller,
	engine *diagnostics.Engine,
	scanner *discovery.Scanner,
	exportDir string,
) {
	fmt.Printf("====================================================================\n")
	fmt.Printf("  ARGUS by Veilric — Headless Diagnostic Scanner (v%s)\n", version)
	fmt.Printf("====================================================================\n\n")

	elevation := "[USER]"
	if adapter.IsElevated() {
		elevation = "[ADMIN/ROOT]"
	}
	fmt.Printf("[*] Elevation Mode: %s\n", elevation)

	// Probe pipeline
	fmt.Printf("[*] Probing hop-by-hop reachability chain...\n")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	status := poller.ProbeOnce(ctx)
	fmt.Printf("    • Physical Link : %s\n", boolText(status.LinkOK))
	fmt.Printf("    • Gateway Ping  : %s (%s)\n", boolText(status.GatewayOK), status.GatewayRTT.Round(time.Microsecond))
	fmt.Printf("    • DNS Resolver  : %s (%s)\n", boolText(status.DNSOK), status.DNSRTT.Round(time.Microsecond))
	fmt.Printf("    • Public Egress : %s (%s)\n", boolText(status.InternetOK), status.InternetRTT.Round(time.Microsecond))
	fmt.Printf("    • Captive Portal: %s\n\n", status.CaptiveState)

	// Run all diagnostics
	fmt.Printf("[*] Running modular diagnostic rule engine...\n")
	results, err := engine.RunDiagnostics(ctx)
	if err != nil {
		fmt.Printf("    [!] Diagnostic execution error: %v\n", err)
	} else {
		for _, r := range results {
			fmt.Printf("    [%s] %s: %s\n", r.Category, r.Title, r.Summary)
			for _, e := range r.Evidence {
				fmt.Printf("         - %s\n", e)
			}
			if r.Remediation != "" {
				fmt.Printf("         * Action: %s\n", r.Remediation)
			}
		}
	}

	// Read subnet inventory
	scanner.RefreshPassive()
	devices := scanner.Devices()
	fmt.Printf("\n[*] Local Subnet Inventory (Passive ARP cache): %d device(s) found\n", len(devices))
	for _, dev := range devices {
		fmt.Printf("    • %-16s %-18s %-20s (%s)\n", dev.IP, dev.MAC, dev.Vendor, dev.State)
	}

	// Export report
	targetDir := exportDir
	if targetDir == "" {
		targetDir = cfg.ReportDir
	}
	mdPath, jsonPath, err := reporter.ExportReport(cfg, adapter, status, results, devices, poller.EventLogs(), targetDir)
	if err == nil {
		fmt.Printf("\n[✔] Incident Report successfully generated:\n")
		fmt.Printf("    Markdown: %s\n", mdPath)
		fmt.Printf("    JSON    : %s\n", jsonPath)
	} else {
		fmt.Printf("\n[!] Failed to export report: %v\n", err)
	}

	fmt.Printf("\n====================================================================\n")
	fmt.Printf("  Scan complete. ARGUS by Veilric.\n")
	fmt.Printf("====================================================================\n")
}

func boolText(b bool) string {
	if b {
		return "ONLINE ✔"
	}
	return "OFFLINE ✗"
}
