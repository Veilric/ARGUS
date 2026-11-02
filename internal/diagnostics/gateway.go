package diagnostics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"argus/internal/platform"
)

var (
	driftMu        sync.Mutex
	lastKnownGwIP  string
	lastKnownGwMAC string
)

type GatewayHealthCheck struct{}

func (c *GatewayHealthCheck) ID() string          { return "gateway_health" }
func (c *GatewayHealthCheck) Name() string        { return "Default Gateway Reachability" }
func (c *GatewayHealthCheck) Description() string { return "Verifies local default router response, verified probe method, and RTT" }

func (c *GatewayHealthCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	if netCtx.GatewayIP == "" {
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     "No default gateway found in system routing table",
			Evidence:    []string{"Destination 0.0.0.0/0 missing from route table", "Host cannot reach outside local subnet"},
			Remediation: "Check DHCP lease configuration or manually set default gateway route.",
			Timestamp:   time.Now(),
		}, nil
	}

	probe := platform.ProbeGatewayReachability(ctx, netCtx.GatewayIP, netCtx.GatewayMAC, 1500*time.Millisecond)

	evidence := []string{
		fmt.Sprintf("Default Gateway IP: %s", netCtx.GatewayIP),
		fmt.Sprintf("Gateway MAC: %s", netCtx.GatewayMAC),
		fmt.Sprintf("Verification Method: %s", probe.Method),
		fmt.Sprintf("Probe Details: %s", probe.Details),
	}

	if probe.State == platform.ReachabilityConfirmed {
		evidence = append(evidence, fmt.Sprintf("Response Latency: %s", probe.RTT.Round(time.Microsecond)))
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   fmt.Sprintf("Default Gateway (%s) is reachable via %s (%s)", netCtx.GatewayIP, probe.Method, probe.RTT.Round(time.Microsecond)),
			Evidence:  evidence,
			Timestamp: time.Now(),
		}, nil
	}

	if probe.State == platform.ReachabilityInconclusive {
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryInconclusive,
			Severity:    SeverityWarning,
			Summary:     fmt.Sprintf("Default Gateway (%s) reachability inconclusive (drops active probes, present in ARP)", netCtx.GatewayIP),
			Evidence:    evidence,
			Remediation: "Router firewall may be dropping ICMP echo and unsolicited TCP packets. Check router administrative interface or client communication.",
			Timestamp:   time.Now(),
		}, nil
	}

	// ReachabilityUnreachable
	return &DiagnosticResult{
		ID:          c.ID(),
		Title:       c.Name(),
		Category:    CategoryConfirmed,
		Severity:    SeverityCritical,
		Summary:     fmt.Sprintf("Default Gateway (%s) is UNREACHABLE", netCtx.GatewayIP),
		Evidence:    evidence,
		Remediation: "Inspect physical connection to local switch/router, Wi-Fi association, or router power.",
		Timestamp:   time.Now(),
	}, nil
}

type ConfigDriftCheck struct{}

func (c *ConfigDriftCheck) ID() string          { return "config_drift" }
func (c *ConfigDriftCheck) Name() string        { return "Gateway Configuration & MAC Drift" }
func (c *ConfigDriftCheck) Description() string { return "Monitors sudden changes in default gateway IP or MAC address (ARP spoofing / rogue router)" }

func (c *ConfigDriftCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	driftMu.Lock()
	defer driftMu.Unlock()

	if lastKnownGwIP == "" && netCtx.GatewayIP != "" {
		lastKnownGwIP = netCtx.GatewayIP
		lastKnownGwMAC = netCtx.GatewayMAC
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   fmt.Sprintf("Gateway baseline registered: %s (%s)", netCtx.GatewayIP, netCtx.GatewayMAC),
			Evidence:  []string{fmt.Sprintf("Initial Gateway IP: %s", netCtx.GatewayIP), fmt.Sprintf("Initial MAC: %s", netCtx.GatewayMAC)},
			Timestamp: time.Now(),
		}, nil
	}

	// Check if IP changed
	if netCtx.GatewayIP != "" && lastKnownGwIP != "" && netCtx.GatewayIP != lastKnownGwIP {
		prevIP := lastKnownGwIP
		lastKnownGwIP = netCtx.GatewayIP
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityWarning,
			Summary:     fmt.Sprintf("Default Gateway IP changed from %s to %s", prevIP, netCtx.GatewayIP),
			Evidence:    []string{fmt.Sprintf("Previous Gateway: %s", prevIP), fmt.Sprintf("Current Gateway: %s", netCtx.GatewayIP)},
			Remediation: "Verify if network administrator altered DHCP options or default route.",
			Timestamp:   time.Now(),
		}, nil
	}

	// Check if MAC changed (potential ARP poisoning or router swap)
	if netCtx.GatewayMAC != "" && lastKnownGwMAC != "" && netCtx.GatewayMAC != lastKnownGwMAC {
		prevMAC := lastKnownGwMAC
		lastKnownGwMAC = netCtx.GatewayMAC
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     fmt.Sprintf("Gateway MAC address drifted from %s to %s for IP %s", prevMAC, netCtx.GatewayMAC, netCtx.GatewayIP),
			Evidence:    []string{fmt.Sprintf("Gateway IP: %s", netCtx.GatewayIP), fmt.Sprintf("Previous MAC: %s", prevMAC), fmt.Sprintf("New MAC: %s", netCtx.GatewayMAC), "Potential ARP spoofing or redundant router VRRP/HSRP failover"},
			Remediation: "Check switch logs for VRRP/HSRP failover or investigate possible ARP spoofing attack on LAN.",
			Timestamp:   time.Now(),
		}, nil
	}

	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryHealthy,
		Severity:  SeverityNone,
		Summary:   "Gateway IP and MAC mappings are stable (no drift detected)",
		Evidence:  []string{fmt.Sprintf("Gateway IP: %s", netCtx.GatewayIP), fmt.Sprintf("Gateway MAC: %s", netCtx.GatewayMAC)},
		Timestamp: time.Now(),
	}, nil
}
