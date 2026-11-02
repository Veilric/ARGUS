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

	// 1. Export JSON report
	jsonPath = filepath.Join(outputDir, baseName+".json")
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		_ = os.WriteFile(jsonPath, jsonData, 0644)
	}

	// 2. Export Markdown report
	mdPath = filepath.Join(outputDir, baseName+".md")
	mdContent := renderMarkdownReport(&report)
	err = os.WriteFile(mdPath, []byte(mdContent), 0644)
	if err != nil {
		return "", "", fmt.Errorf("failed to write markdown report: %w", err)
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
	sb.WriteString(fmt.Sprintf("| **Physical Link** | %s | — | Interface: `%s` (%s) |\n", boolStatus(r.Pipeline.LinkOK), r.Host.InterfaceName, r.Host.MAC))
	sb.WriteString(fmt.Sprintf("| **Default Gateway** | %s | %s | Target: `%s` |\n", boolStatus(r.Pipeline.GatewayOK), r.Pipeline.GatewayRTT.Round(time.Microsecond), r.Host.GatewayIP))
	sb.WriteString(fmt.Sprintf("| **DNS Resolution** | %s | %s | Server: `%v` |\n", boolStatus(r.Pipeline.DNSOK), r.Pipeline.DNSRTT.Round(time.Microsecond), r.Host.DNSServers))
	sb.WriteString(fmt.Sprintf("| **Internet Egress** | %s | %s | Public Egress Verified |\n", boolStatus(r.Pipeline.InternetOK), r.Pipeline.InternetRTT.Round(time.Microsecond)))
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

	if len(r.Devices) > 0 {
		sb.WriteString("## 3. Discovered Local Subnet Inventory\n\n")
		sb.WriteString("| IP Address | MAC Address | Hardware Vendor | Interface | State |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
		for _, dev := range r.Devices {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s | %s |\n", dev.IP, dev.MAC, dev.Vendor, dev.Interface, dev.State))
		}
		sb.WriteString("\n")
	}

	if len(r.RecentLogs) > 0 {
		sb.WriteString("## 4. Recent Incident Log Feed\n\n```text\n")
		for _, log := range r.RecentLogs {
			sb.WriteString(log + "\n")
		}
		sb.WriteString("```\n\n")
	}

	sb.WriteString("---\n*Report generated autonomously by ARGUS by Veilric.*\n")
	return sb.String()
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
