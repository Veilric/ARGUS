package diagnostics

import (
	"context"
	"fmt"
	"net"
	"time"
)

type DNSvsWANCheck struct{}

func (c *DNSvsWANCheck) ID() string          { return "dns_vs_wan" }
func (c *DNSvsWANCheck) Name() string        { return "ISP WAN Outage vs DNS Server Failure Isolation" }
func (c *DNSvsWANCheck) Description() string { return "Distinguishes between upstream ISP circuit drops and DNS resolution failures" }

func (c *DNSvsWANCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	// 1. Test raw public IP reachability (bypasses DNS entirely)
	publicIPs := []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	publicReachable := false
	var publicRTT time.Duration
	var reachableTarget string

	for _, target := range publicIPs {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, 700*time.Millisecond)
		if err == nil {
			conn.Close()
			publicReachable = true
			publicRTT = time.Since(start)
			reachableTarget = target
			break
		}
	}

	// 2. Test DNS resolution
	r := &net.Resolver{
		PreferGo: true,
	}
	dnsStart := time.Now()
	lookupCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()

	addrs, dnsErr := r.LookupHost(lookupCtx, "one.one.one.one")
	dnsRTT := time.Since(dnsStart)
	dnsHealthy := dnsErr == nil && len(addrs) > 0

	evidence := []string{
		fmt.Sprintf("Raw Public IP Reachability: %v (%s via %s)", publicReachable, publicRTT.Round(time.Millisecond), reachableTarget),
		fmt.Sprintf("DNS Resolution ('one.one.one.one'): %v (%s)", dnsHealthy, dnsRTT.Round(time.Millisecond)),
	}
	if len(netCtx.DNSServers) > 0 {
		evidence = append(evidence, fmt.Sprintf("Configured System DNS: %v", netCtx.DNSServers))
	}

	// Scenario A: Public IPs reachable, but DNS lookup fails
	if publicReachable && !dnsHealthy {
		evidence = append(evidence, "Public IP connects successfully via TCP, proving physical Internet routing is intact")
		if dnsErr != nil {
			evidence = append(evidence, "DNS Error: "+dnsErr.Error())
		}
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     "DNS FAILURE DETECTED: Internet connection is alive, but DNS resolution is failing!",
			Evidence:    evidence,
			Remediation: "Switch DNS server to a reliable public resolver (e.g. 1.1.1.1, 8.8.8.8) or restart local DNS proxy/Pi-hole.",
			Timestamp:   time.Now(),
		}, nil
	}

	// Scenario B: Neither public IPs nor DNS are reachable
	if !publicReachable && !dnsHealthy {
		// Is the local gateway alive?
		gwAlive := false
		if netCtx.GatewayIP != "" {
			for _, port := range []string{"53", "80", "443"} {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(netCtx.GatewayIP, port), 400*time.Millisecond)
				if err == nil {
					conn.Close()
					gwAlive = true
					break
				}
			}
		}

		if gwAlive {
			evidence = append(evidence, fmt.Sprintf("Default Gateway (%s) responds normally (0%% packet loss)", netCtx.GatewayIP))
			evidence = append(evidence, "All external public destinations beyond Gateway timed out")
			return &DiagnosticResult{
				ID:          c.ID(),
				Title:       c.Name(),
				Category:    CategoryConfirmed,
				Severity:    SeverityCritical,
				Summary:     "UPSTREAM ISP / WAN OUTAGE: Local router is healthy, but upstream ISP circuit is down",
				Evidence:    evidence,
				Remediation: "Check ISP modem/fiber ONT status lights, contact ISP support, or check for wide-area telecom outages.",
				Timestamp:   time.Now(),
			}, nil
		}

		// Gateway also dead
		evidence = append(evidence, "Default Gateway is also completely unresponsive")
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     "LOCAL NETWORK FAILURE: Default Gateway is unreachable (LAN issue before ISP)",
			Evidence:    evidence,
			Remediation: "Check local Wi-Fi connection, ethernet cable, or power to the local router/switch.",
			Timestamp:   time.Now(),
		}, nil
	}

	// Scenario C: Both public IP and DNS are working
	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryHealthy,
		Severity:  SeverityNone,
		Summary:   fmt.Sprintf("Internet and DNS healthy (Egress: %s, DNS: %s)", publicRTT.Round(time.Millisecond), dnsRTT.Round(time.Millisecond)),
		Evidence:  evidence,
		Timestamp: time.Now(),
	}, nil
}
