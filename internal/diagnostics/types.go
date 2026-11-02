package diagnostics

import (
	"context"
	"time"

	"argus/internal/dhcp"
)

// ResultCategory defines the diagnostic confidence level.
// Per ARGUS guidelines: distinguish confirmed observations, suspected causes, and inconclusive findings.
type ResultCategory string

const (
	CategoryConfirmed    ResultCategory = "CONFIRMED"
	CategorySuspected    ResultCategory = "SUSPECTED"
	CategoryInconclusive ResultCategory = "INCONCLUSIVE"
	CategoryHealthy      ResultCategory = "HEALTHY"
)

// Severity indicates visual urgency.
type Severity string

const (
	SeverityNone     Severity = "NONE"
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// DiagnosticResult represents the outcome of an independent diagnostic check module.
type DiagnosticResult struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Category    ResultCategory `json:"category"`
	Severity    Severity       `json:"severity"`
	Summary     string         `json:"summary"`
	Evidence    []string       `json:"evidence"`
	Remediation string         `json:"remediation,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
}

// NetworkContext encapsulates observed topology state passed into diagnostic modules.
type NetworkContext struct {
	InterfaceName   string
	InterfaceUp     bool
	MACAddress      string
	LocalIPs        []string
	GatewayIP       string
	GatewayMAC      string
	GatewayOnline   bool
	GatewayRTT      time.Duration
	DNSOnline       bool
	DNSServers      []string
	DNSRTT          time.Duration
	PublicIP        string
	PublicReachable bool
	PublicRTT       time.Duration
	IsElevated         bool
	ARPTable           map[string]string // IP -> MAC
	Attribution        string
	AttributionDetails string
	DHCPConfig         *dhcp.DHCPConfig
	Baseline           *dhcp.ConfigBaseline
	DetectedChanges    []dhcp.ConfigChange
}

// DiagnosticModule represents an independent check.
type DiagnosticModule interface {
	ID() string
	Name() string
	Description() string
	Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error)
}
