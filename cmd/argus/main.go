package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"argus/internal/config"
	"argus/internal/dhcp"
	"argus/internal/diagnostics"
	"argus/internal/discovery"
	"argus/internal/platform"
	"argus/internal/reporter"
	"argus/internal/sysmon"
	"argus/internal/telemetry"
	"argus/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
)

const version = "1.1.0"

func main() {
	scanFlag := flag.Bool("scan", false, "Run one-shot headless diagnostic scan without opening TUI")
	exportFlag := flag.String("export", "", "Directory path to export Markdown and JSON incident report")
	ifaceFlag := flag.String("iface", "", "Override network interface name (auto-detected if omitted)")
	logDirFlag := flag.String("log-dir", "./logs", "Directory for session event logs")
	reportDirFlag := flag.String("report-dir", "./reports", "Directory for exported incident reports")
	versionFlag := flag.Bool("version", false, "Display ARGUS version information")
	refreshBaselineFlag := flag.Bool("refresh-baseline", false, "Deliberately establish or refresh network configuration baseline for the active interface")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ARGUS by Veilric — Portable Network Observation, Diagnostics & Discovery Toolkit (v%s)\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  argus [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nInteractive Controls (TUI Mode):\n")
		fmt.Fprintf(os.Stderr, "  [1-4 / Tab]   Switch between Telemetry, Diagnostics, Devices, and Logs\n")
		fmt.Fprintf(os.Stderr, "  [D / Space]   Run comprehensive diagnostic scan\n")
		fmt.Fprintf(os.Stderr, "  [B]           Refresh network configuration baseline\n")
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
		// Strictly validate requested interface
		if _, err := net.InterfaceByName(*ifaceFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: requested network interface %q cannot be used: %v\n", *ifaceFlag, err)
			os.Exit(1)
		}
		cfg.InterfaceName = *ifaceFlag
	}
	if *logDirFlag != "" {
		cfg.LogDir = *logDirFlag
	}
	if *reportDirFlag != "" {
		cfg.ReportDir = *reportDirFlag
	}

	baselineStore, _ := dhcp.NewBaselineStore("config/baselines.json")
	dhcpInspector := dhcp.NewInspector()

	adapter := platform.NewAdapter(cfg.InterfaceName)
	poller := telemetry.NewPoller(cfg, adapter)
	poller.SetDHCPComponents(baselineStore, dhcpInspector)
	engine := diagnostics.NewEngine(adapter, baselineStore, dhcpInspector)
	scanner := discovery.NewScanner(adapter)
	monitor := sysmon.NewMonitor()
	logger, _ := reporter.NewSessionLogger(cfg)
	if logger != nil {
		poller.SetLogSink(logger)
		defer logger.Close()
	}

	// Mode 0: CLI Refresh Baseline
	if *refreshBaselineFlag {
		iface, err := adapter.GetDefaultInterface()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error detecting default interface: %v\n", err)
			os.Exit(1)
		}
		cfgObserved, err := dhcpInspector.Inspect(iface.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error inspecting interface %q: %v\n", iface.Name, err)
			os.Exit(1)
		}
		b, err := baselineStore.Establish(cfgObserved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving baseline: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[✔] Baseline established for interface %q at %s\n", b.InterfaceName, b.EstablishedAt.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("    • IPv4 Address : %s/%d (%s)\n", b.IPv4Address, b.IPv4Prefix, b.Assignment)
		fmt.Printf("    • Gateway IP   : %s\n", b.GatewayIP)
		fmt.Printf("    • DNS Servers  : %v\n", b.DNSServers)
		if b.DHCPServerIP != "" {
			fmt.Printf("    • DHCP Server  : %s\n", b.DHCPServerIP)
		}
		os.Exit(0)
	}

	// Mode 1: One-shot CLI Scan
	if *scanFlag {
		exitCode := runHeadlessScan(cfg, adapter, poller, engine, scanner, *exportFlag)
		os.Exit(exitCode)
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
) int {
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
	gwText := boolText(status.GatewayOK)
	if status.GatewayState == "INCONCLUSIVE" {
		gwText = "INCONCLUSIVE ?"
	} else if status.GatewayState == "UNAVAILABLE" {
		gwText = "UNAVAILABLE —"
	}

	fmt.Printf("    • Physical Link : %s\n", boolText(status.LinkOK))
	fmt.Printf("    • Gateway Ping  : %s (%s via %s)\n", gwText, status.GatewayRTT.Round(time.Microsecond), status.GatewayMethod)

	dnsServerLabel := status.DNSServer
	if dnsServerLabel == "" {
		dnsServerLabel = "System Resolver"
	}
	dnsDetail := fmt.Sprintf("%s via %s", status.DNSRTT.Round(time.Microsecond), dnsServerLabel)
	if !status.DNSOK && status.DNSError != "" {
		dnsDetail = fmt.Sprintf("FAILED: %s (Server port reachable: %t)", status.DNSError, status.DNSServerReachable)
	}
	fmt.Printf("    • DNS Resolver  : %s (%s)\n", boolText(status.DNSOK), dnsDetail)
	egressScope := ""
	if status.Attribution != "" {
		egressScope = fmt.Sprintf(" [Attribution: %s]", status.Attribution)
	}
	fmt.Printf("    • Public Egress : %s (%s)%s\n", boolText(status.InternetOK), status.InternetRTT.Round(time.Microsecond), egressScope)
	fmt.Printf("    • Captive Portal: %s\n\n", status.CaptiveState)

	// Run all diagnostics
	fmt.Printf("[*] Running modular diagnostic rule engine...\n")
	results, err := engine.RunDiagnostics(ctx)
	hasCritical := false
	if !status.LinkOK {
		hasCritical = true
	}

	if err != nil {
		fmt.Printf("    [!] Diagnostic execution error: %v\n", err)
	} else {
		for _, r := range results {
			if r.Category == diagnostics.CategoryConfirmed && r.Severity == diagnostics.SeverityCritical {
				hasCritical = true
			}
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

	if hasCritical {
		return 1
	}
	return 0
}

func boolText(b bool) string {
	if b {
		return "ONLINE ✔"
	}
	return "OFFLINE ✗"
}
