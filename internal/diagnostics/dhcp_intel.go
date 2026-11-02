package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"time"

	"argus/internal/dhcp"
)

// DHCPIntelligenceCheck evaluates observable DHCP leasing, configuration baseline drift,
// and potential rogue/secondary DHCP symptoms without transmitting active broadcasts.
type DHCPIntelligenceCheck struct {
	baselineStore *dhcp.BaselineStore
	inspector     dhcp.Inspector
}

// NewDHCPIntelligenceCheck creates a new read-only DHCP intelligence diagnostic module.
func NewDHCPIntelligenceCheck(store *dhcp.BaselineStore, inspector dhcp.Inspector) *DHCPIntelligenceCheck {
	return &DHCPIntelligenceCheck{
		baselineStore: store,
		inspector:     inspector,
	}
}

func (c *DHCPIntelligenceCheck) ID() string {
	return "dhcp_intel"
}

func (c *DHCPIntelligenceCheck) Name() string {
	return "DHCP Intelligence & Configuration Baseline"
}

func (c *DHCPIntelligenceCheck) Description() string {
	return "Inspects DHCP leasing, configuration drift against baseline, and DHCP server consistency"
}

func (c *DHCPIntelligenceCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	cfg := netCtx.DHCPConfig
	if cfg == nil && c.inspector != nil && netCtx.InterfaceName != "" {
		if inspected, err := c.inspector.Inspect(netCtx.InterfaceName); err == nil && inspected != nil {
			cfg = inspected
			netCtx.DHCPConfig = cfg
		}
	}

	baseline := netCtx.Baseline
	if baseline == nil && c.baselineStore != nil && netCtx.InterfaceName != "" {
		if b, ok := c.baselineStore.Get(netCtx.InterfaceName); ok && b != nil {
			baseline = b
			netCtx.Baseline = baseline
		}
	}

	var changes []dhcp.ConfigChange
	if len(netCtx.DetectedChanges) > 0 {
		changes = netCtx.DetectedChanges
	} else if baseline != nil && cfg != nil {
		changes = dhcp.DetectChanges(baseline, cfg)
	}

	var evidence []string

	if cfg != nil {
		evidence = append(evidence, fmt.Sprintf("Observed Interface: %s (MAC: %s)", cfg.InterfaceName, cfg.MACAddress))
		evidence = append(evidence, fmt.Sprintf("IP Configuration Mode: %s (Source: %s)", cfg.Assignment, cfg.Source))
		if cfg.IPv4Address != "" {
			evidence = append(evidence, fmt.Sprintf("Assigned IPv4: %s/%d", cfg.IPv4Address, cfg.IPv4Prefix))
		}
		if cfg.GatewayIP != "" {
			evidence = append(evidence, fmt.Sprintf("Configured Gateway: %s", cfg.GatewayIP))
		}
		if len(cfg.DNSServers) > 0 {
			evidence = append(evidence, fmt.Sprintf("Configured DNS Resolvers: %v", cfg.DNSServers))
		}
		if cfg.DHCPServerIP != "" {
			evidence = append(evidence, fmt.Sprintf("Observed DHCP Server ID: %s", cfg.DHCPServerIP))
		}
		if cfg.LeaseExpires != nil {
			evidence = append(evidence, fmt.Sprintf("DHCP Lease Expiration: %s", cfg.LeaseExpires.Format("2006-01-02 15:04:05 MST")))
		}
		if cfg.DomainName != "" {
			evidence = append(evidence, fmt.Sprintf("Domain Name / Search: %s", cfg.DomainName))
		}

		// Split DHCP vs Gateway observation
		if cfg.DHCPServerIP != "" && cfg.GatewayIP != "" && cfg.DHCPServerIP != cfg.GatewayIP {
			evidence = append(evidence, fmt.Sprintf("Architecture Notice: DHCP Server (%s) differs from Default Gateway (%s). Typical in enterprise subnets, but may also indicate secondary router DHCP server.", cfg.DHCPServerIP, cfg.GatewayIP))
		}
	} else {
		evidence = append(evidence, "DHCP configuration inspection could not be performed for this interface")
	}

	// Baseline comparison evidence
	if baseline != nil {
		evidence = append(evidence, fmt.Sprintf("Baseline Established: %s (Last Seen: %s)", baseline.EstablishedAt.Format("2006-01-02 15:04:05 MST"), baseline.LastSeenAt.Format("2006-01-02 15:04:05 MST")))
		evidence = append(evidence, fmt.Sprintf("Baseline Values: Gateway: %s, DNS: %v, DHCP Server: %s", baseline.GatewayIP, baseline.DNSServers, baseline.DHCPServerIP))
	} else {
		evidence = append(evidence, "Baseline Status: No baseline established yet for this interface")
	}

	for _, chg := range changes {
		evidence = append(evidence, fmt.Sprintf("Detected Change [%s]: %s (Old: %s -> New: %s)", chg.Kind, chg.Summary, chg.OldValue, chg.NewValue))
	}

	// -------------------------------------------------------------------------
	// Decision Logic
	// -------------------------------------------------------------------------

	// Scenario 1: Changes detected compared to established baseline
	if len(changes) > 0 {
		var summaries []string
		hasDHCPServerChange := false
		hasGatewayChange := false

		for _, chg := range changes {
			summaries = append(summaries, chg.Summary)
			if chg.Kind == dhcp.ChangeDHCPServerChanged {
				hasDHCPServerChange = true
			}
			if chg.Kind == dhcp.ChangeGatewayChanged {
				hasGatewayChange = true
			}
		}

		remediation := "Review network topology. If you recently connected to a new Wi-Fi network or toggled a VPN, configuration changes are expected. If unexpected, check for secondary routers or mesh nodes (e.g. TP-Link Deco in Router mode instead of AP mode)."

		if hasDHCPServerChange {
			return &DiagnosticResult{
				ID:          c.ID(),
				Title:       c.Name(),
				Category:    CategorySuspected,
				Severity:    SeverityWarning,
				Summary:     fmt.Sprintf("SUSPECTED DHCP ANOMALY: %s", strings.Join(summaries, "; ")),
				Evidence:    evidence,
				Remediation: remediation,
				Timestamp:   time.Now(),
			}, nil
		}

		if hasGatewayChange {
			return &DiagnosticResult{
				ID:          c.ID(),
				Title:       c.Name(),
				Category:    CategorySuspected,
				Severity:    SeverityWarning,
				Summary:     fmt.Sprintf("SUSPECTED GATEWAY DRIFT: %s", strings.Join(summaries, "; ")),
				Evidence:    evidence,
				Remediation: remediation,
				Timestamp:   time.Now(),
			}, nil
		}

		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategorySuspected,
			Severity:    SeverityInfo,
			Summary:     fmt.Sprintf("CONFIGURATION DRIFT DETECTED: %s", strings.Join(summaries, "; ")),
			Evidence:    evidence,
			Remediation: remediation,
			Timestamp:   time.Now(),
		}, nil
	}

	// Scenario 2: Stable matching baseline
	if baseline != nil && cfg != nil {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   fmt.Sprintf("Network configuration matches established baseline (%s mode stable)", cfg.Assignment),
			Evidence:  evidence,
			Timestamp: time.Now(),
		}, nil
	}

	// Scenario 3: Static configuration without baseline
	if cfg != nil && cfg.Assignment == dhcp.AssignmentStatic {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   fmt.Sprintf("Static IPv4 configuration active on %s (No active DHCP leasing)", cfg.InterfaceName),
			Evidence:  evidence,
			Timestamp: time.Now(),
		}, nil
	}

	// Scenario 4: Dynamic DHCP configuration without baseline
	if cfg != nil && cfg.Assignment == dhcp.AssignmentDHCP {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   fmt.Sprintf("DHCP lease active on %s (Server: %s)", cfg.InterfaceName, cfg.DHCPServerIP),
			Evidence:  evidence,
			Timestamp: time.Now(),
		}, nil
	}

	// Scenario 5: Unavailable metadata
	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryInconclusive,
		Severity:  SeverityInfo,
		Summary:   "DHCP lease metadata unavailable from operating system (Inspection inconclusive)",
		Evidence:  evidence,
		Timestamp: time.Now(),
	}, nil
}
