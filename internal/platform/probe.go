package platform

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ReachabilityState represents the verified status of a target.
type ReachabilityState string

const (
	ReachabilityConfirmed    ReachabilityState = "CONFIRMED"
	ReachabilityUnreachable  ReachabilityState = "UNREACHABLE"
	ReachabilityInconclusive ReachabilityState = "INCONCLUSIVE"
	ReachabilityUnavailable  ReachabilityState = "UNAVAILABLE"
)

// GatewayProbeResult encapsulates full measurement and evidence.
type GatewayProbeResult struct {
	State   ReachabilityState
	RTT     time.Duration
	Method  string
	Details string
}

// ProbeGatewayReachability verifies whether a gateway is responsive using TCP handshake/RST,
// system ICMP ping, and passive ARP cache fallbacks.
// It NEVER declares reachability solely based on UDP socket creation.
func ProbeGatewayReachability(ctx context.Context, gwIP string, gwMAC string, timeout time.Duration) GatewayProbeResult {
	if gwIP == "" {
		return GatewayProbeResult{
			State:   ReachabilityUnavailable,
			Method:  "None",
			Details: "No gateway IP address provided or configured",
		}
	}

	// 1. Try TCP handshake / RST on standard gateway ports (80, 443, 53, 8080)
	ports := []string{"80", "443", "53", "8080"}
	perPortTimeout := timeout / time.Duration(len(ports)+1)
	if perPortTimeout < 150*time.Millisecond {
		perPortTimeout = 150 * time.Millisecond
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return GatewayProbeResult{
				State:   ReachabilityInconclusive,
				Method:  "Cancelled",
				Details: "Probe cancelled before completion",
			}
		default:
		}

		target := net.JoinHostPort(gwIP, port)
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, perPortTimeout)
		rtt := time.Since(start)

		if err == nil {
			conn.Close()
			return GatewayProbeResult{
				State:   ReachabilityConfirmed,
				RTT:     rtt,
				Method:  fmt.Sprintf("TCP SYN-ACK (port %s)", port),
				Details: fmt.Sprintf("TCP handshake completed successfully in %s", rtt.Round(time.Microsecond)),
			}
		}

		// Check if target actively returned a TCP RST (connection refused)
		// Active refusal requires the target host's IP stack to receive SYN and generate RST!
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "actively refused") ||
			strings.Contains(errStr, "refused") {
			return GatewayProbeResult{
				State:   ReachabilityConfirmed,
				RTT:     rtt,
				Method:  fmt.Sprintf("TCP RST-Refusal (port %s)", port),
				Details: fmt.Sprintf("Target host actively refused connection with TCP RST in %s", rtt.Round(time.Microsecond)),
			}
		}
	}

	// 2. Try System ICMP Ping
	pingTimeout := timeout / 2
	if pingTimeout < 400*time.Millisecond {
		pingTimeout = 400 * time.Millisecond
	}
	if rtt, ok, detail := RunSystemPing(ctx, gwIP, pingTimeout); ok {
		return GatewayProbeResult{
			State:   ReachabilityConfirmed,
			RTT:     rtt,
			Method:  "ICMP Echo Reply",
			Details: fmt.Sprintf("Host replied to ICMP echo probe in %s: %s", rtt.Round(time.Microsecond), detail),
		}
	}

	// 3. Fallback: Check ARP cache.
	// If the host is silent (drops TCP and ICMP without replying) but MAC is known in ARP cache:
	if gwMAC != "" && gwMAC != "00:00:00:00:00:00" && strings.ToLower(gwMAC) != "incomplete" {
		return GatewayProbeResult{
			State:   ReachabilityInconclusive,
			RTT:     0,
			Method:  "Passive ARP (Probes Dropped)",
			Details: fmt.Sprintf("Host dropped TCP and ICMP probes; MAC %s present in ARP cache but active response unconfirmed", gwMAC),
		}
	}

	return GatewayProbeResult{
		State:   ReachabilityUnreachable,
		RTT:     0,
		Method:  "None (Timed Out)",
		Details: "Gateway did not respond to TCP or ICMP probes, and no valid ARP resolution observed",
	}
}

var (
	linuxPingTimeRegex = regexp.MustCompile(`time=([0-9.]+)\s*ms`)
	winPingTimeRegex   = regexp.MustCompile(`time[=<]([0-9.]+)ms`)
)

// RunSystemPing executes a single-packet ping and parses the response.
func RunSystemPing(ctx context.Context, target string, timeout time.Duration) (time.Duration, bool, string) {
	var cmd *exec.Cmd
	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}
	timeoutMs := int(timeout.Milliseconds())
	if timeoutMs < 300 {
		timeoutMs = 300
	}

	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), target)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), target)
	}

	start := time.Now()
	out, err := cmd.CombinedOutput()
	measuredRTT := time.Since(start)

	outStr := string(out)
	if err == nil {
		if strings.Contains(outStr, "1 packets transmitted, 1 received") ||
			strings.Contains(outStr, "1 packets transmitted, 1 packets received") ||
			strings.Contains(outStr, "bytes from") ||
			strings.Contains(outStr, "Reply from") {

			// Attempt to parse actual ping latency reported by tool
			if matches := linuxPingTimeRegex.FindStringSubmatch(outStr); len(matches) > 1 {
				if ms, parseErr := strconv.ParseFloat(matches[1], 64); parseErr == nil {
					return time.Duration(ms * float64(time.Millisecond)), true, "Reply received"
				}
			}
			if matches := winPingTimeRegex.FindStringSubmatch(outStr); len(matches) > 1 {
				if ms, parseErr := strconv.ParseFloat(matches[1], 64); parseErr == nil {
					return time.Duration(ms * float64(time.Millisecond)), true, "Reply received"
				}
			}
			return measuredRTT, true, "Reply received"
		}
	}

	return 0, false, strings.TrimSpace(outStr)
}

// DNSProbeResult stores detailed DNS resolution verification.
type DNSProbeResult struct {
	Resolved            bool
	RTT                 time.Duration
	Server              string
	Domain              string
	Addresses           []string
	Method              string
	Error               string
	ServerPortReachable bool
}

// ProbeDNSResolution executes an actual DNS query against the specified server (or default),
// validating that real IP addresses are returned within the timeout.
// It distinguishes resolution failures from port reachability failures without changing OS settings.
func ProbeDNSResolution(ctx context.Context, dnsServer string, domain string, timeout time.Duration) DNSProbeResult {
	if domain == "" {
		domain = "one.one.one.one"
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var r *net.Resolver
	var method string

	if dnsServer != "" {
		serverHost := dnsServer
		serverPort := "53"
		if h, p, splitErr := net.SplitHostPort(dnsServer); splitErr == nil {
			serverHost = h
			serverPort = p
		}
		targetAddr := net.JoinHostPort(serverHost, serverPort)
		method = fmt.Sprintf("Direct Server (%s)", targetAddr)
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(dialCtx, "udp", targetAddr)
			},
		}
	} else {
		method = "System Resolver"
		r = net.DefaultResolver
	}

	start := time.Now()
	addrs, err := r.LookupHost(queryCtx, domain)
	rtt := time.Since(start)

	if err == nil && len(addrs) > 0 {
		return DNSProbeResult{
			Resolved:            true,
			RTT:                 rtt,
			Server:              dnsServer,
			Domain:              domain,
			Addresses:           addrs,
			Method:              method,
			ServerPortReachable: true,
		}
	}

	// Query failed: check if server's port 53 is at least reachable via TCP or UDP connect
	portReachable := false
	if dnsServer != "" {
		host := dnsServer
		port := "53"
		if h, p, splitErr := net.SplitHostPort(dnsServer); splitErr == nil {
			host = h
			port = p
		}
		pConn, pErr := net.DialTimeout("tcp", net.JoinHostPort(host, port), 400*time.Millisecond)
		if pErr == nil {
			pConn.Close()
			portReachable = true
		}
	}

	errStr := "no addresses returned"
	if err != nil {
		errStr = err.Error()
	}

	return DNSProbeResult{
		Resolved:            false,
		RTT:                 rtt,
		Server:              dnsServer,
		Domain:              domain,
		Method:              method,
		Error:               errStr,
		ServerPortReachable: portReachable,
	}
}
