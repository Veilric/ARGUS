package diagnostics

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"argus/internal/platform"
)

type DNSvsWANCheck struct {
	probePublicFn  func(target string, timeout time.Duration) (time.Duration, error)
	probeDNSFn     func(ctx context.Context, server, domain string, timeout time.Duration) platform.DNSProbeResult
	probeGatewayFn func(ctx context.Context, gwIP, gwMAC string, timeout time.Duration) platform.GatewayProbeResult
}

func (c *DNSvsWANCheck) ID() string          { return "dns_vs_wan" }
func (c *DNSvsWANCheck) Name() string        { return "ISP WAN Outage vs DNS Server Failure Isolation" }
func (c *DNSvsWANCheck) Description() string { return "Distinguishes between upstream ISP circuit/route drops and DNS resolution failures" }

func (c *DNSvsWANCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	// 1. Test raw public IP reachability across independent endpoints (bypasses DNS entirely)
	publicIPs := []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	var successfulTargets []string
	var failedTargets []string
	var minRTT time.Duration

	// Extract local IP for interface binding where available
	var localTCPAddr *net.TCPAddr
	if len(netCtx.LocalIPs) > 0 {
		rawIP := netCtx.LocalIPs[0]
		if idx := strings.Index(rawIP, "/"); idx != -1 {
			rawIP = rawIP[:idx]
		}
		if ip := net.ParseIP(rawIP); ip != nil && ip.To4() != nil {
			localTCPAddr = &net.TCPAddr{IP: ip}
		}
	}

	for _, target := range publicIPs {
		start := time.Now()
		var err error
		var rtt time.Duration

		if c.probePublicFn != nil {
			rtt, err = c.probePublicFn(target, 500*time.Millisecond)
		} else {
			dialer := &net.Dialer{
				Timeout:   500 * time.Millisecond,
				LocalAddr: localTCPAddr,
			}
			conn, dErr := dialer.DialContext(ctx, "tcp", target)
			if dErr == nil {
				rtt = time.Since(start)
				conn.Close()
			} else {
				err = dErr
			}
		}

		if err == nil {
			successfulTargets = append(successfulTargets, fmt.Sprintf("%s (%s)", target, rtt.Round(time.Millisecond)))
			if minRTT == 0 || rtt < minRTT {
				minRTT = rtt
			}
		} else {
			failedTargets = append(failedTargets, target)
		}
	}

	publicReachable := len(successfulTargets) > 0

	// 2. Test actual DNS resolution (with response validation)
	dnsServer := ""
	if len(netCtx.DNSServers) > 0 {
		dnsServer = netCtx.DNSServers[0]
	}

	var dnsResult platform.DNSProbeResult
	if c.probeDNSFn != nil {
		dnsResult = c.probeDNSFn(ctx, dnsServer, "one.one.one.one", 1200*time.Millisecond)
	} else {
		dnsResult = platform.ProbeDNSResolution(ctx, dnsServer, "one.one.one.one", 1200*time.Millisecond)
	}
	dnsHealthy := dnsResult.Resolved

	evidence := []string{
		fmt.Sprintf("Raw Public IP Reachability: %d/%d responsive (Best RTT: %s, Responsive: %v)", len(successfulTargets), len(publicIPs), minRTT.Round(time.Millisecond), successfulTargets),
		fmt.Sprintf("DNS Query Resolution: %v (Method: %s, RTT: %s)", dnsHealthy, dnsResult.Method, dnsResult.RTT.Round(time.Millisecond)),
	}

	// Attribution evidence
	if netCtx.Attribution != "" {
		evidence = append(evidence, fmt.Sprintf("Attribution Scope: %s (%s)", netCtx.Attribution, netCtx.AttributionDetails))
	} else if netCtx.InterfaceName != "" {
		evidence = append(evidence, fmt.Sprintf("Attribution Scope: Evaluated on interface %s (Local IP: %v)", netCtx.InterfaceName, netCtx.LocalIPs))
	}

	if len(failedTargets) > 0 && len(successfulTargets) > 0 {
		evidence = append(evidence, fmt.Sprintf("Individual destination notice: %v timed out while other public destinations responded", failedTargets))
	}
	if len(netCtx.DNSServers) > 0 {
		evidence = append(evidence, fmt.Sprintf("Configured System DNS: %v", netCtx.DNSServers))
	}
	if dnsResult.Error != "" {
		evidence = append(evidence, fmt.Sprintf("DNS Query Error: %s", dnsResult.Error))
		evidence = append(evidence, fmt.Sprintf("DNS Server Port 53 Reachable: %v", dnsResult.ServerPortReachable))
	}

	// -------------------------------------------------------------------------
	// Decision Matrix Handling
	// -------------------------------------------------------------------------

	// Scenario 1: External targets reachable AND DNS resolution works
	if publicReachable && dnsHealthy {
		if len(failedTargets) > 0 {
			// Some external targets succeeded, but not all: qualified healthy result
			return &DiagnosticResult{
				ID:        c.ID(),
				Title:     c.Name(),
				Category:  CategoryHealthy,
				Severity:  SeverityInfo,
				Summary:   fmt.Sprintf("External reachability partially verified (%d/%d targets responsive; individual endpoint failure, DNS healthy)", len(successfulTargets), len(publicIPs)),
				Evidence:  evidence,
				Timestamp: time.Now(),
			}, nil
		}
		// All external targets succeeded
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   fmt.Sprintf("External reachability and DNS resolution verified (All %d external targets responsive, min RTT: %s, DNS: %s)", len(successfulTargets), minRTT.Round(time.Millisecond), dnsResult.RTT.Round(time.Millisecond)),
			Evidence:  evidence,
			Timestamp: time.Now(),
		}, nil
	}

	// Scenario 2: External targets reachable, but DNS lookup fails
	if publicReachable && !dnsHealthy {
		evidence = append(evidence, "Public IP connects successfully via TCP, proving physical Internet routing is intact")
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     "DNS RESOLUTION FAILURE: Internet connection is alive, but DNS resolution is failing",
			Evidence:    evidence,
			Remediation: "Switch DNS server to a reliable public resolver (e.g. 1.1.1.1, 8.8.8.8) or verify local DNS forwarder/Pi-hole.",
			Timestamp:   time.Now(),
		}, nil
	}

	// Scenario 3: All external targets fail, but DNS resolution succeeds
	// (e.g., DNS handled by local proxy/cache, or transport blocking non-DNS traffic; NEVER globally healthy!)
	if !publicReachable && dnsHealthy {
		evidence = append(evidence, "DNS query succeeded (possibly via local resolver cache or port 53 exemption), but all raw TCP connections to public external destinations failed.")
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategorySuspected,
			Severity:    SeverityCritical,
			Summary:     "EXTERNAL EGRESS IMPAIRED: External destinations timed out across all tested endpoints, despite successful DNS resolution",
			Evidence:    evidence,
			Remediation: "Check for upstream firewall, proxy requirement, captive portal, or carrier transport drop blocking standard egress ports (TCP 443/80).",
			Timestamp:   time.Now(),
		}, nil
	}

	// Scenario 4: Neither external targets nor DNS are reachable
	// Probe the local default gateway to isolate LAN fault vs upstream ISP/WAN fault
	var gwProbe platform.GatewayProbeResult
	if c.probeGatewayFn != nil {
		gwProbe = c.probeGatewayFn(ctx, netCtx.GatewayIP, netCtx.GatewayMAC, 800*time.Millisecond)
	} else {
		gwProbe = platform.ProbeGatewayReachability(ctx, netCtx.GatewayIP, netCtx.GatewayMAC, 800*time.Millisecond)
	}

	switch gwProbe.State {
	case platform.ReachabilityConfirmed:
		// Gateway responds -> LAN hop is intact; fault is upstream (ISP/WAN/carrier)
		evidence = append(evidence, fmt.Sprintf("Default Gateway (%s) responded to probe via %s (%s)", netCtx.GatewayIP, gwProbe.Method, gwProbe.RTT.Round(time.Microsecond)))
		evidence = append(evidence, "External public destinations beyond Gateway timed out across all tested ports")
		evidence = append(evidence, "Note: upstream packet filtering, enterprise egress firewalls, or WAN route failures can cause this without a complete physical circuit drop")
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategorySuspected,
			Severity:    SeverityCritical,
			Summary:     "EXTERNAL CONNECTIVITY IMPAIRED: Local default gateway is responsive, but external destinations and DNS timed out (Suspected upstream routing or ISP issue)",
			Evidence:    evidence,
			Remediation: "Check ISP modem/fiber ONT status lights, contact ISP support, or check for organizational WAN firewall rules.",
			Timestamp:   time.Now(),
		}, nil

	case platform.ReachabilityUnreachable:
		// Gateway is confirmed unreachable -> LAN reachability failure
		evidence = append(evidence, fmt.Sprintf("Default Gateway (%s) is unresponsive to reachability probes: %s", netCtx.GatewayIP, gwProbe.Details))
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     "LOCAL GATEWAY UNREACHABLE: Default Gateway did not respond to reachability probes",
			Evidence:    evidence,
			Remediation: "Check local network link, router power, or IP configuration.",
			Timestamp:   time.Now(),
		}, nil

	case platform.ReachabilityUnavailable:
		// Gateway is unavailable (e.g., no default route exists on this interface)
		evidence = append(evidence, fmt.Sprintf("Default Gateway status is unavailable: %s", gwProbe.Details))
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryInconclusive,
			Severity:    SeverityInfo,
			Summary:     "CONNECTIVITY OUTAGE UNRESOLVED: No valid default gateway configured or route is unavailable",
			Evidence:    evidence,
			Remediation: "Verify local IP address assignment and default gateway route configuration on the active adapter.",
			Timestamp:   time.Now(),
		}, nil

	default: // platform.ReachabilityInconclusive
		// Probes dropped without RST/ARP resolution, or probe inconclusive
		evidence = append(evidence, fmt.Sprintf("Default Gateway status is inconclusive: %s", gwProbe.Details))
		evidence = append(evidence, "Probes to both the gateway and public internet did not receive definitive responses; cannot verify whether fault is local LAN or external WAN.")
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryInconclusive,
			Severity:    SeverityInfo,
			Summary:     "CONNECTIVITY OUTAGE UNRESOLVED: External destinations and DNS failed; gateway status is inconclusive",
			Evidence:    evidence,
			Remediation: "Verify gateway reachability with active ARP or administrative access, as local firewall may drop probes silently.",
			Timestamp:   time.Now(),
		}, nil
	}
}
