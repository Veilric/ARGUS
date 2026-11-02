package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"argus/internal/config"
	"argus/internal/diagnostics"
	"argus/internal/discovery"
	"argus/internal/platform"
	"argus/internal/telemetry"
)

// IncidentReport represents the structured report exported to disk or USB.
type IncidentReport struct {
	Brand         string                          `json:"brand"`
	Timestamp     time.Time                       `json:"timestamp"`
	ElevationMode string                          `json:"elevation_mode"`
	Host          HostInfo                        `json:"host"`
	Pipeline      telemetry.PipelineStatus        `json:"pipeline"`
	Diagnostics   []diagnostics.DiagnosticResult  `json:"diagnostics"`
	Devices       []*discovery.Device             `json:"devices"`
	RecentLogs    []string                        `json:"recent_logs"`
}

type HostInfo struct {
	Hostname      string   `json:"hostname"`
	InterfaceName string   `json:"interface_name"`
	MAC           string   `json:"mac"`
	IPs           []string `json:"ips"`
	GatewayIP     string   `json:"gateway_ip"`
	DNSServers    []string `json:"dns_servers"`
}

// ExportReport generates both Markdown (.md) and JSON (.json) reports with 'ARGUS by Veilric' branding.
func ExportReport(
	cfg *config.Config,
	adapter platform.NetworkAdapter,
	status telemetry.PipelineStatus,
	diagResults []diagnostics.DiagnosticResult,
	devices []*discovery.Device,
	recentLogs []string,
	outputDir string,
) (mdPath string, jsonPath string, err error) {
	if outputDir == "" {
		outputDir = cfg.ReportDir
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create report output dir: %w", err)
	}

	timestamp := time.Now()
	tsFormatted := timestamp.Format("2006-01-02-150405")
	baseName := fmt.Sprintf("argus-report-%s", tsFormatted)
	mdPath = filepath.Join(outputDir, baseName+".md")
	jsonPath = filepath.Join(outputDir, baseName+".json")

	// Collision avoidance: ensure unique filename if multiple reports are exported rapidly
	counter := 1
	for {
		_, mdErr := os.Stat(mdPath)
		_, jsonErr := os.Stat(jsonPath)
		if os.IsNotExist(mdErr) && os.IsNotExist(jsonErr) {
			break
		}
		baseName = fmt.Sprintf("argus-report-%s_%d", tsFormatted, counter)
		mdPath = filepath.Join(outputDir, baseName+".md")
		jsonPath = filepath.Join(outputDir, baseName+".json")
		counter++
	}

	host := HostInfo{
		DNSServers: []string{"Unknown"},
	}
	if h, err := os.Hostname(); err == nil {
		host.Hostname = h
	}
	if iface, err := adapter.GetDefaultInterface(); err == nil && iface != nil {
		host.InterfaceName = iface.Name
		host.MAC = iface.HardwareAddr.String()
		for _, addr := range iface.IPs {
			host.IPs = append(host.IPs, addr.String())
		}
	}
	if gw, err := adapter.GetDefaultGateway(); err == nil && gw != nil {
		host.GatewayIP = gw.String()
	}
	if dns, err := adapter.GetDNSServers(); err == nil && len(dns) > 0 {
		host.DNSServers = dns
	}

	elevation := "[USER]"
	if adapter.IsElevated() {
		elevation = "[ADMIN/ROOT]"
	}

	report := IncidentReport{
		Brand:         "ARGUS by Veilric",
		Timestamp:     timestamp,
		ElevationMode: elevation,
		Host:          host,
		Pipeline:      status,
		Diagnostics:   diagResults,
		Devices:       devices,
		RecentLogs:    recentLogs,
	}

	// 1. Export JSON report with full error handling
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("failed to encode JSON incident report: %w", err)
	}
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return "", "", fmt.Errorf("failed to write JSON report to %s: %w", jsonPath, err)
	}

	// 2. Export Markdown report with full error handling
	mdContent := renderMarkdownReport(&report)
	if err := os.WriteFile(mdPath, []byte(mdContent), 0644); err != nil {
		return "", "", fmt.Errorf("failed to write markdown report to %s: %w", mdPath, err)
	}

	return mdPath, jsonPath, nil
}

func renderMarkdownReport(r *IncidentReport) string {
	var sb strings.Builder

	sb.WriteString("# ARGUS Network Incident & Observation Report\n")
	sb.WriteString(fmt.Sprintf("**Toolkit:** %s\n", r.Brand))
	sb.WriteString(fmt.Sprintf("**Timestamp:** %s | **Mode:** %s\n\n", r.Timestamp.Format("2006-01-02 15:04:05 MST"), r.ElevationMode))

	sb.WriteString("---\n\n")
	sb.WriteString("## 1. Executive Summary & Chain of Reachability\n\n")
	sb.WriteString("| Component | Status | Latency | Measurement Details |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- |\n")
	gwDetails := fmt.Sprintf("Target: `%s`", r.Host.GatewayIP)
	if r.Pipeline.GatewayMethod != "" {
		gwDetails += fmt.Sprintf(" (Method: %s)", r.Pipeline.GatewayMethod)
	}
	dnsServerLabel := r.Pipeline.DNSServer
	if dnsServerLabel == "" {
		dnsServerLabel = "System Resolver"
	}
	dnsDetails := fmt.Sprintf("Server: `%s`", dnsServerLabel)
	if !r.Pipeline.DNSOK && r.Pipeline.DNSError != "" {
		dnsDetails += fmt.Sprintf(" (Error: %s, Port 53 Reachable: %t)", r.Pipeline.DNSError, r.Pipeline.DNSServerReachable)
	}

	sb.WriteString(fmt.Sprintf("| **Physical Link** | %s | — | Interface: `%s` (%s) |\n", boolStatus(r.Pipeline.LinkOK), r.Host.InterfaceName, r.Host.MAC))
	sb.WriteString(fmt.Sprintf("| **Default Gateway** | %s | %s | %s |\n", gatewayStatusText(r.Pipeline), r.Pipeline.GatewayRTT.Round(time.Microsecond), gwDetails))
	sb.WriteString(fmt.Sprintf("| **DNS Resolution** | %s | %s | %s |\n", boolStatus(r.Pipeline.DNSOK), r.Pipeline.DNSRTT.Round(time.Microsecond), dnsDetails))
	egressDetails := "Public Egress Verified"
	if r.Pipeline.Attribution != "" {
		egressDetails = fmt.Sprintf("Scope: %s (%s)", r.Pipeline.Attribution, r.Pipeline.AttributionDetails)
	}
	sb.WriteString(fmt.Sprintf("| **Internet Egress** | %s | %s | %s |\n", boolStatus(r.Pipeline.InternetOK), r.Pipeline.InternetRTT.Round(time.Microsecond), egressDetails))
	sb.WriteString(fmt.Sprintf("| **Captive Portal** | %s | — | State: `%s` |\n\n", r.Pipeline.CaptiveState, r.Pipeline.CaptiveState))

	sb.WriteString("## 2. Evidence-Based Diagnostic Findings\n\n")
	sb.WriteString("> *Findings are strictly categorized into Confirmed Observations, Suspected Causes, and Inconclusive Findings.* \n\n")

	for _, d := range r.Diagnostics {
		badge := badgeForCategory(d.Category)
		sb.WriteString(fmt.Sprintf("### %s %s\n", badge, d.Title))
		sb.WriteString(fmt.Sprintf("- **Classification:** `%s` (Severity: `%s`)\n", d.Category, d.Severity))
		sb.WriteString(fmt.Sprintf("- **Summary:** %s\n", d.Summary))
		if len(d.Evidence) > 0 {
			sb.WriteString("- **Evidence Backing:**\n")
			for _, e := range d.Evidence {
				sb.WriteString(fmt.Sprintf("  - %s\n", e))
			}
		}
		if d.Remediation != "" {
			sb.WriteString(fmt.Sprintf("- **Actionable Remediation:** %s\n", d.Remediation))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## 3. DHCP Intelligence & Network Configuration History\n\n")

	dhcpMode := "Unknown / Uninspected"
	dhcpServer := "None / Unavailable"
	gwIP := "None"
	dnsList := "None"
	leaseExp := "—"
	baselineDesc := "No Baseline Established"

	if r.Pipeline.DHCPConfig != nil {
		cfg := r.Pipeline.DHCPConfig
		dhcpMode = string(cfg.Assignment)
		if cfg.DHCPServerIP != "" {
			dhcpServer = cfg.DHCPServerIP
		}
		if cfg.GatewayIP != "" {
			gwIP = cfg.GatewayIP
		}
		if len(cfg.DNSServers) > 0 {
			dnsList = strings.Join(cfg.DNSServers, ", ")
		}
		if cfg.LeaseExpires != nil {
			leaseExp = cfg.LeaseExpires.Format("2006-01-02 15:04:05 MST")
		}
	} else if r.Host.GatewayIP != "" {
		gwIP = r.Host.GatewayIP
		if len(r.Host.DNSServers) > 0 {
			dnsList = strings.Join(r.Host.DNSServers, ", ")
		}
	}

	if r.Pipeline.Baseline != nil {
		b := r.Pipeline.Baseline
		baselineDesc = fmt.Sprintf("Established at %s (Gateway: `%s`, DNS: `%v`, DHCP: `%s`)",
			b.EstablishedAt.Format("2006-01-02 15:04:05 MST"),
			b.GatewayIP,
			b.DNSServers,
			b.DHCPServerIP,
		)
	}

	sb.WriteString("| Property | Observed Value | Baseline Context |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| **IP Configuration Mode** | `%s` | Baseline Ref: %s |\n", dhcpMode, baselineDesc))
	sb.WriteString(fmt.Sprintf("| **Default Gateway** | `%s` | Target Gateway Address |\n", gwIP))
	sb.WriteString(fmt.Sprintf("| **Observed DHCP Server** | `%s` | Lease Server Identifier |\n", dhcpServer))
	sb.WriteString(fmt.Sprintf("| **Configured DNS** | `%s` | Resolver List |\n", dnsList))
	sb.WriteString(fmt.Sprintf("| **Lease Expiration** | `%s` | Dynamic Lease Lifecycle |\n\n", leaseExp))

	if len(r.Pipeline.RecentChanges) > 0 {
		sb.WriteString("### Observed Configuration Drift\n\n")
		for _, chg := range r.Pipeline.RecentChanges {
			sb.WriteString(fmt.Sprintf("- **%s:** `%s` → `%s` (Observed at %s)\n",
				chg.FieldName, chg.OldValue, chg.NewValue, chg.Timestamp.Format("2006-01-02 15:04:05 MST")))
			sb.WriteString(fmt.Sprintf("  - *Analysis:* %s\n", chg.Implication))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("> *Notice: DHCP inspection relies on local operating system state and lease metadata. ARGUS operates strictly read-only and does not transmit rogue-server solicitations or inject packets.*\n\n")

	if len(r.Devices) > 0 {
		sb.WriteString("## 4. Discovered Local Subnet Inventory\n\n")
		sb.WriteString("| IP Address | MAC Address | Hardware Vendor | Interface | State |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
		for _, dev := range r.Devices {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s | %s |\n", dev.IP, dev.MAC, dev.Vendor, dev.Interface, dev.State))
		}
		sb.WriteString("\n")
	}

	if len(r.RecentLogs) > 0 {
		sb.WriteString("## 5. Recent Incident Log Feed\n\n```text\n")
		for _, log := range r.RecentLogs {
			sb.WriteString(log + "\n")
		}
		sb.WriteString("```\n\n")
	}

	sb.WriteString("---\n*Report generated autonomously by ARGUS by Veilric.*\n")
	return sb.String()
}

func gatewayStatusText(s telemetry.PipelineStatus) string {
	switch s.GatewayState {
	case "REACHABLE":
		return "✔ ONLINE"
	case "INCONCLUSIVE":
		return "? INCONCLUSIVE (Silent/Unverified)"
	case "UNAVAILABLE":
		return "— UNAVAILABLE (No Gateway Route)"
	default:
		return "✗ OFFLINE / UNREACHABLE"
	}
}

func boolStatus(b bool) string {
	if b {
		return "✔ ONLINE"
	}
	return "✗ OFFLINE / FAILED"
}

func badgeForCategory(c diagnostics.ResultCategory) string {
	switch c {
	case diagnostics.CategoryConfirmed:
		return "[CONFIRMED]"
	case diagnostics.CategorySuspected:
		return "[SUSPECTED]"
	case diagnostics.CategoryInconclusive:
		return "[INCONCLUSIVE]"
	case diagnostics.CategoryHealthy:
		return "[HEALTHY]"
	default:
		return "[INFO]"
	}
}

// SessionLogger provides USB-safe rotating logs.
type SessionLogger struct {
	dir         string
	maxSize     int64
	maxBackups  int
	currentFile *os.File
	currentSize int64
}

func NewSessionLogger(cfg *config.Config) (*SessionLogger, error) {
	if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
		return nil, err
	}
	filePath := filepath.Join(cfg.LogDir, "argus.log")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	stat, _ := file.Stat()
	size := int64(0)
	if stat != nil {
		size = stat.Size()
	}

	return &SessionLogger{
		dir:         cfg.LogDir,
		maxSize:     int64(cfg.MaxLogSizeMB) * 1024 * 1024,
		maxBackups:  cfg.MaxLogRotations,
		currentFile: file,
		currentSize: size,
	}, nil
}

func (l *SessionLogger) Log(entry string) {
	if l.currentFile == nil {
		return
	}
	formatted := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), entry)
	n, err := l.currentFile.WriteString(formatted)
	if err == nil {
		l.currentSize += int64(n)
		if l.currentSize > l.maxSize {
			l.rotate()
		}
	}
}

func (l *SessionLogger) rotate() {
	_ = l.currentFile.Close()
	logPath := filepath.Join(l.dir, "argus.log")

	// Rotate backups
	for i := l.maxBackups - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", logPath, i)
		newPath := fmt.Sprintf("%s.%d", logPath, i+1)
		_ = os.Rename(oldPath, newPath)
	}
	_ = os.Rename(logPath, logPath+".1")

	newFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		l.currentFile = newFile
		l.currentSize = 0
	}
}

func (l *SessionLogger) Close() {
	if l.currentFile != nil {
		_ = l.currentFile.Close()
	}
}
