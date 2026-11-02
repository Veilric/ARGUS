package diagnostics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"argus/internal/platform"
)

func TestIPConflictCheck_PassiveDoesNotClaimUniqueness(t *testing.T) {
	check := &IPConflictCheck{}

	netCtx := &NetworkContext{
		InterfaceName: "eth0",
		InterfaceUp:   true,
		LocalIPs:      []string{"192.168.1.50"},
		GatewayIP:     "192.168.1.1",
		IsElevated:    false,
		ARPTable: map[string]string{
			"192.168.1.1":  "00:11:22:33:44:01",
			"192.168.1.20": "00:11:22:33:44:02",
		},
	}

	result, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	// Must be CategoryInconclusive, NOT CategoryHealthy
	if result.Category != CategoryInconclusive {
		t.Errorf("Expected CategoryInconclusive for passive ARP absence, got: %v", result.Category)
	}

	// Must explicitly state that IP uniqueness has not been verified
	if !strings.Contains(result.Summary, "IP uniqueness has not been verified") {
		t.Errorf("Expected summary to explain that IP uniqueness has not been verified, got: %s", result.Summary)
	}

	// Must NOT claim that an active scan ran
	if strings.Contains(strings.ToLower(result.Summary), "active") {
		t.Errorf("Diagnostic falsely claimed active ARP ran when only passive inspection ran: %s", result.Summary)
	}
}

func TestDoubleNATCheck_MultiplePrivateHopsSuspectedNotConfirmed(t *testing.T) {
	check := &DoubleNATCheck{}

	netCtx := &NetworkContext{
		GatewayIP: "192.168.1.1",
	}

	result, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	// Result category must NOT be Confirmed Double NAT merely from private hops without actual NAT traversal proof
	if result.Category == CategoryConfirmed && strings.Contains(result.Summary, "Double NAT") {
		t.Errorf("Multiple private hops must be classified as CategorySuspected, not CategoryConfirmed!")
	}
}

func TestDoubleNATCheck_PublicGatewayInconclusive(t *testing.T) {
	check := &DoubleNATCheck{}

	// Public gateway IP (e.g., routed direct egress or public IP on WAN)
	netCtx := &NetworkContext{
		GatewayIP: "203.0.113.1",
	}

	result, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	// Public first-hop gateway must be CategoryInconclusive, NOT CategoryHealthy ("No NAT")
	if result.Category != CategoryInconclusive {
		t.Errorf("Public first hop gateway should be CategoryInconclusive (carrier NAT cannot be ruled out), got: %v", result.Category)
	}

	if !strings.Contains(result.Summary, "carrier/transparent NAT cannot be ruled out") {
		t.Errorf("Expected summary to explain upstream carrier NAT cannot be ruled out, got: %s", result.Summary)
	}
}

// -----------------------------------------------------------------------------
// Regression Tests for DNS / WAN Decision Matrix
// -----------------------------------------------------------------------------

// Regression Test 1: All external destinations fail while DNS succeeds; result must NOT be HEALTHY.
func TestDNSvsWANCheck_AllExternalFailDNSSucceeds_NotHealthy(t *testing.T) {
	check := &DNSvsWANCheck{
		probePublicFn: func(target string, timeout time.Duration) (time.Duration, error) {
			return 0, errors.New("connection timed out")
		},
		probeDNSFn: func(ctx context.Context, server, domain string, timeout time.Duration) platform.DNSProbeResult {
			return platform.DNSProbeResult{
				Resolved:  true,
				RTT:       15 * time.Millisecond,
				Method:    "Direct Server (1.1.1.1:53)",
				Addresses: []string{"1.1.1.1"},
			}
		},
	}

	netCtx := &NetworkContext{
		GatewayIP:  "192.168.1.1",
		DNSServers: []string{"1.1.1.1"},
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if res.Category == CategoryHealthy {
		t.Fatalf("Regression detected! All external destinations failed, but diagnostic returned CategoryHealthy: %s", res.Summary)
	}
	if res.Category != CategorySuspected {
		t.Errorf("Expected CategorySuspected for impaired external egress, got: %v", res.Category)
	}
	if !strings.Contains(res.Summary, "EXTERNAL EGRESS IMPAIRED") {
		t.Errorf("Expected summary to indicate impaired egress, got: %s", res.Summary)
	}
}

// Regression Test 2: External connectivity and DNS fail while gateway status is INCONCLUSIVE;
// result must NOT claim a confirmed local gateway failure.
func TestDNSvsWANCheck_ExternalFailDNSFail_GatewayInconclusive_NotLocalFailure(t *testing.T) {
	check := &DNSvsWANCheck{
		probePublicFn: func(target string, timeout time.Duration) (time.Duration, error) {
			return 0, errors.New("network unreachable")
		},
		probeDNSFn: func(ctx context.Context, server, domain string, timeout time.Duration) platform.DNSProbeResult {
			return platform.DNSProbeResult{
				Resolved: false,
				Error:    "DNS query timeout",
			}
		},
		probeGatewayFn: func(ctx context.Context, gwIP, gwMAC string, timeout time.Duration) platform.GatewayProbeResult {
			return platform.GatewayProbeResult{
				State:   platform.ReachabilityInconclusive,
				Method:  "Passive ARP (Probes Dropped)",
				Details: "Gateway dropped probes without response",
			}
		},
	}

	netCtx := &NetworkContext{
		GatewayIP:  "192.168.1.1",
		GatewayMAC: "00:11:22:33:44:55",
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	// Must be CategoryInconclusive, NOT CategoryConfirmed
	if res.Category == CategoryConfirmed {
		t.Fatalf("Regression detected! Gateway inconclusive, but diagnostic claimed CategoryConfirmed failure: %s", res.Summary)
	}
	if res.Category != CategoryInconclusive {
		t.Errorf("Expected CategoryInconclusive, got: %v", res.Category)
	}
	if strings.Contains(res.Summary, "LOCAL GATEWAY UNREACHABLE") {
		t.Errorf("Inconclusive gateway probe must NOT declare confirmed local gateway failure: %s", res.Summary)
	}
}

// Regression Test 3: The same scenario with gateway status UNAVAILABLE.
func TestDNSvsWANCheck_ExternalFailDNSFail_GatewayUnavailable_NotLocalFailure(t *testing.T) {
	check := &DNSvsWANCheck{
		probePublicFn: func(target string, timeout time.Duration) (time.Duration, error) {
			return 0, errors.New("network unreachable")
		},
		probeDNSFn: func(ctx context.Context, server, domain string, timeout time.Duration) platform.DNSProbeResult {
			return platform.DNSProbeResult{
				Resolved: false,
				Error:    "DNS server unreachable",
			}
		},
		probeGatewayFn: func(ctx context.Context, gwIP, gwMAC string, timeout time.Duration) platform.GatewayProbeResult {
			return platform.GatewayProbeResult{
				State:   platform.ReachabilityUnavailable,
				Method:  "None",
				Details: "No default gateway route configured",
			}
		},
	}

	netCtx := &NetworkContext{
		GatewayIP: "",
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if res.Category == CategoryConfirmed {
		t.Fatalf("Unavailable gateway must NOT produce CategoryConfirmed local failure: %s", res.Summary)
	}
	if res.Category != CategoryInconclusive {
		t.Errorf("Expected CategoryInconclusive, got: %v", res.Category)
	}
}

// Regression Test 4: External connectivity and DNS fail with confirmed gateway response.
// Must report suspected upstream trouble without claiming confirmed ISP circuit outage.
func TestDNSvsWANCheck_ExternalFailDNSFail_GatewayConfirmed_SuspectedUpstream(t *testing.T) {
	check := &DNSvsWANCheck{
		probePublicFn: func(target string, timeout time.Duration) (time.Duration, error) {
			return 0, errors.New("connection timed out")
		},
		probeDNSFn: func(ctx context.Context, server, domain string, timeout time.Duration) platform.DNSProbeResult {
			return platform.DNSProbeResult{
				Resolved: false,
				Error:    "query timeout",
			}
		},
		probeGatewayFn: func(ctx context.Context, gwIP, gwMAC string, timeout time.Duration) platform.GatewayProbeResult {
			return platform.GatewayProbeResult{
				State:  platform.ReachabilityConfirmed,
				RTT:    1200 * time.Microsecond,
				Method: "TCP SYN-ACK (port 80)",
			}
		},
	}

	netCtx := &NetworkContext{
		GatewayIP: "192.168.1.1",
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if res.Category == CategoryConfirmed {
		t.Fatalf("Expected CategorySuspected for upstream WAN trouble, not CategoryConfirmed: %s", res.Summary)
	}
	if res.Category != CategorySuspected {
		t.Errorf("Expected CategorySuspected, got: %v", res.Category)
	}
	if !strings.Contains(res.Summary, "EXTERNAL CONNECTIVITY IMPAIRED") {
		t.Errorf("Expected external connectivity impaired summary, got: %s", res.Summary)
	}
}

// Regression Test 5: Partial external target failures produce qualified results.
func TestDNSvsWANCheck_PartialExternalFail_QualifiedResult(t *testing.T) {
	check := &DNSvsWANCheck{
		probePublicFn: func(target string, timeout time.Duration) (time.Duration, error) {
			if strings.Contains(target, "1.1.1.1") {
				return 8 * time.Millisecond, nil
			}
			// 8.8.8.8 and 9.9.9.9 fail
			return 0, errors.New("target timed out")
		},
		probeDNSFn: func(ctx context.Context, server, domain string, timeout time.Duration) platform.DNSProbeResult {
			return platform.DNSProbeResult{
				Resolved: true,
				RTT:      10 * time.Millisecond,
				Method:   "Direct Server",
			}
		},
	}

	netCtx := &NetworkContext{
		GatewayIP:  "192.168.1.1",
		DNSServers: []string{"1.1.1.1"},
	}

	res, err := check.Run(context.Background(), netCtx)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if !strings.Contains(res.Summary, "partially verified") {
		t.Errorf("Expected partial verification notice in summary, got: %s", res.Summary)
	}
	if !strings.Contains(res.Summary, "1/3") {
		t.Errorf("Expected 1/3 responsive ratio in summary, got: %s", res.Summary)
	}
	// Evidence should mention the individual destinations that timed out
	foundNotice := false
	for _, ev := range res.Evidence {
		if strings.Contains(ev, "Individual destination notice") {
			foundNotice = true
			break
		}
	}
	if !foundNotice {
		t.Errorf("Expected evidence to contain individual destination notice for partial failure: %v", res.Evidence)
	}
}
