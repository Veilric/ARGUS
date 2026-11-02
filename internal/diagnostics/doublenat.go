package diagnostics

import (
	"bufio"
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

type DoubleNATCheck struct{}

func (c *DoubleNATCheck) ID() string          { return "double_nat" }
func (c *DoubleNATCheck) Name() string        { return "Double NAT & Topology Layer Inspection" }
func (c *DoubleNATCheck) Description() string { return "Detects cascaded private routers (Hop 1 and Hop 2 both in private subnets)" }

func (c *DoubleNATCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	if netCtx.GatewayIP == "" {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryInconclusive,
			Severity:  SeverityInfo,
			Summary:   "Default gateway unknown; cannot trace upstream NAT topology",
			Evidence:  []string{"Gateway IP missing"},
			Timestamp: time.Now(),
		}, nil
	}

	gwIP := net.ParseIP(netCtx.GatewayIP)
	if gwIP == nil {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryInconclusive,
			Severity:  SeverityInfo,
			Summary:   fmt.Sprintf("Invalid gateway IP: %s", netCtx.GatewayIP),
			Evidence:  []string{fmt.Sprintf("Raw Gateway: %s", netCtx.GatewayIP)},
			Timestamp: time.Now(),
		}, nil
	}

	gwIsPrivate := isPrivateOrCGNAT(gwIP)
	if !gwIsPrivate {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryInconclusive,
			Severity:  SeverityInfo,
			Summary:   fmt.Sprintf("Default gateway (%s) is a public IP. Local private NAT hop not present, but upstream carrier/transparent NAT cannot be ruled out.", gwIP.String()),
			Evidence: []string{
				fmt.Sprintf("Hop 1 Gateway (%s) is a publicly routable IP", gwIP.String()),
				"A public first-hop gateway indicates no local RFC 1918 NAT router, but does not independently prove the complete absence of upstream network address translation.",
			},
			Timestamp: time.Now(),
		}, nil
	}

	// Gateway is private. Now determine Hop 2.
	hop2IP, hop3IP, hopsEvidence := traceFirstHops(ctx, "1.1.1.1", 3)

	evidence := []string{
		fmt.Sprintf("Hop 1 (Default Gateway): %s [Private / RFC1918]", gwIP.String()),
	}
	evidence = append(evidence, hopsEvidence...)

	if hop2IP != nil {
		if isPrivateOrCGNAT(hop2IP) {
			return &DiagnosticResult{
				ID:       c.ID(),
				Title:    c.Name(),
				Category: CategorySuspected,
				Severity: SeverityWarning,
				Summary:  fmt.Sprintf("Multiple private routing hops observed (Hop 1: %s, Hop 2: %s). Potential Double NAT suspected.", gwIP.String(), hop2IP.String()),
				Evidence: append(evidence, "Note: internal enterprise transit routing without NAT can also produce multiple private hops; double NAT is suspected, not conclusively proven without port mapping verification"),
				Remediation: "Inspect upstream modem/router configuration to verify whether two cascaded NAT layers exist, or configure Bridge / IP Passthrough mode.",
				Timestamp: time.Now(),
			}, nil
		}

		// Hop 2 is public IP -> Single NAT
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   fmt.Sprintf("Clean Single Private Hop: Hop 1 (%s) is private, Hop 2 (%s) is public WAN", gwIP.String(), hop2IP.String()),
			Evidence:  evidence,
			Timestamp: time.Now(),
		}, nil
	}

	// Hop 2 timed out, check Hop 3
	if hop3IP != nil && isPrivateOrCGNAT(hop3IP) {
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategorySuspected,
			Severity:    SeverityWarning,
			Summary:     fmt.Sprintf("SUSPECTED DOUBLE NAT: Hop 1 (%s) and Hop 3 (%s) are private (Hop 2 dropped ICMP)", gwIP.String(), hop3IP.String()),
			Evidence:    evidence,
			Remediation: "Check upstream router/modem configuration to verify if two routing tiers exist.",
			Timestamp:   time.Now(),
		}, nil
	}

	// Hop 2 could not be verified
	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryInconclusive,
		Severity:  SeverityInfo,
		Summary:   fmt.Sprintf("Single/Double NAT status inconclusive: Hop 1 is private (%s), but upstream router dropped TTL probes", gwIP.String()),
		Evidence:  evidence,
		Timestamp: time.Now(),
	}, nil
}

func isPrivateOrCGNAT(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Check RFC 1918
	if ip.IsPrivate() {
		return true
	}
	// Check Carrier-Grade NAT (CGNAT) 100.64.0.0/10
	_, cgnatNet, _ := net.ParseCIDR("100.64.0.0/10")
	if cgnatNet != nil && cgnatNet.Contains(ip) {
		return true
	}
	return false
}

// traceFirstHops runs a short traceroute for the first few hops with streaming output
func traceFirstHops(ctx context.Context, target string, maxHops int) (hop2 net.IP, hop3 net.IP, evidence []string) {
	shortCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(shortCtx, "tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", "500", target)
	} else {
		// Linux: try traceroute or tracepath
		if _, err := exec.LookPath("traceroute"); err == nil {
			cmd = exec.CommandContext(shortCtx, "traceroute", "-n", "-m", strconv.Itoa(maxHops), "-w", "1", "-q", "1", target)
		} else if _, err := exec.LookPath("tracepath"); err == nil {
			cmd = exec.CommandContext(shortCtx, "tracepath", "-n", "-m", strconv.Itoa(maxHops), target)
		}
	}

	if cmd == nil {
		evidence = append(evidence, "System traceroute utility not available for deep TTL probe")
		return nil, nil, evidence
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		evidence = append(evidence, "Failed to capture traceroute pipe: "+err.Error())
		return nil, nil, evidence
	}

	if err := cmd.Start(); err != nil {
		evidence = append(evidence, "Failed to start traceroute: "+err.Error())
		return nil, nil, evidence
	}

	ipRegex := regexp.MustCompile(`\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b`)
	scanner := bufio.NewScanner(stdout)

	// Stream lines as they arrive
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Handle tracepath format: " 2:  10.0.0.1" or " 2:  no reply"
			// Handle tracert/traceroute format: "2   10.0.0.1" or " 2  * * *"
			if strings.HasPrefix(line, "2:") || strings.HasPrefix(line, "2 ") {
				if strings.Contains(line, "no reply") || strings.Contains(line, "*") {
					evidence = append(evidence, "Hop 2: * * * (timed out / ICMP TTL drops)")
				} else {
					matches := ipRegex.FindAllString(line, -1)
					if len(matches) > 0 {
						hop2 = net.ParseIP(matches[0])
						evidence = append(evidence, fmt.Sprintf("Hop 2: %s", matches[0]))
					}
				}
			} else if strings.HasPrefix(line, "3:") || strings.HasPrefix(line, "3 ") {
				if strings.Contains(line, "no reply") || strings.Contains(line, "*") {
					evidence = append(evidence, "Hop 3: * * * (timed out / ICMP TTL drops)")
				} else {
					matches := ipRegex.FindAllString(line, -1)
					if len(matches) > 0 {
						hop3 = net.ParseIP(matches[0])
						evidence = append(evidence, fmt.Sprintf("Hop 3: %s", matches[0]))
					}
				}
			}
		}
	}()

	select {
	case <-doneCh:
		_ = cmd.Wait()
	case <-shortCtx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}

	return hop2, hop3, evidence
}
