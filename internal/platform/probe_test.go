package platform

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbeGatewayReachability_NoUDPFalsePositive(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737), guaranteed to not respond
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	result := ProbeGatewayReachability(ctx, "192.0.2.1", "", 250*time.Millisecond)

	// In the past, net.DialTimeout("udp", "192.0.2.1:12345") would return nil error
	// and falsely mark the host as REACHABLE.
	// We verify that ProbeGatewayReachability NEVER marks this host Confirmed!
	if result.State == ReachabilityConfirmed {
		t.Fatalf("CRITICAL REGRESSION: UDP dial false-positive detected! Dummy IP marked as CONFIRMED reachability: %v", result)
	}
}

func TestProbeDNSResolution_DistinguishPortFromQuery(t *testing.T) {
	// Open a local TCP listener on an ephemeral port that accepts connections
	// but does NOT speak DNS protocol.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("Cannot open local listener: %v", err)
	}
	defer ln.Close()

	// Handle connection by keeping it open briefly without sending DNS response
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(200 * time.Millisecond)
			}(conn)
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Test with local listener as a dummy port
	// In ARGUS, port 53 reachability check must not count as DNS query resolution.
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	// Query an invalid/non-DNS port
	probe := ProbeDNSResolution(ctx, "127.0.0.1:"+port, "example.com", 200*time.Millisecond)

	if probe.Resolved {
		t.Errorf("Probe reported Resolved=true for non-DNS endpoint!")
	}
}

func TestProbeGatewayReachability_UnavailableOnEmptyGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := ProbeGatewayReachability(ctx, "", "", 100*time.Millisecond)
	if result.State != ReachabilityUnavailable {
		t.Errorf("Expected ReachabilityUnavailable for empty gateway IP, got: %s", result.State)
	}
}

