package diagnostics

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type MTUPathCheck struct{}

func (c *MTUPathCheck) ID() string          { return "mtu_path" }
func (c *MTUPathCheck) Name() string        { return "Path MTU & Fragmentation Black Hole Check" }
func (c *MTUPathCheck) Description() string { return "Tests whether standard 1500-byte packets pass without fragmentation black-holes" }

func (c *MTUPathCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	target := "1.1.1.1"

	// 1472 payload + 20 IP header + 8 ICMP header = 1500 MTU
	success1500, err1500 := testDFPing(ctx, target, 1472)
	if success1500 {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   "Standard 1500-byte MTU path verified with Don't-Fragment (DF) bit set",
			Evidence:  []string{"Payload: 1472 bytes (+28 header = 1500 MTU)", "Packet passed without fragmentation"},
			Timestamp: time.Now(),
		}, nil
	}

	// 1500 failed. Test 1492 MTU (PPPoE - payload 1464)
	success1492, _ := testDFPing(ctx, target, 1464)
	if success1492 {
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityWarning,
			Summary:     "PATH MTU CLAMPED TO 1492 (PPPoE / DSL encapsulation detected)",
			Evidence:    []string{"1500 MTU packet dropped with DF flag set", "1492 MTU packet passed successfully", err1500},
			Remediation: "Ensure router MSS clamping is set to 1452 or configure local interface MTU to 1492.",
			Timestamp:   time.Now(),
		}, nil
	}

	// Test 1400 MTU (VPN / Tunnel encapsulation - payload 1372)
	success1400, _ := testDFPing(ctx, target, 1372)
	if success1400 {
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityWarning,
			Summary:     "RESTRICTED PATH MTU: Large packets dropped below 1492 (Tunnel / VPN / WireGuard / IPsec in path)",
			Evidence:    []string{"1500 and 1492 MTU packets dropped", "1400 MTU packet passed successfully"},
			Remediation: "Set interface MTU to 1400 or enable TCP MSS clamping on upstream firewall/gateway.",
			Timestamp:   time.Now(),
		}, nil
	}

	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryInconclusive,
		Severity:  SeverityInfo,
		Summary:   "MTU path test inconclusive (ICMP echo probes blocked or rate-limited upstream)",
		Evidence:  []string{"Probes to " + target + " timed out: " + err1500},
		Timestamp: time.Now(),
	}, nil
}

func testDFPing(ctx context.Context, target string, payloadSize int) (bool, string) {
	var cmd *exec.Cmd
	sizeStr := strconv.Itoa(payloadSize)

	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-f", "-l", sizeStr, "-w", "1000", target)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-M", "do", "-s", sizeStr, "-W", "1", target)
	}

	out, err := cmd.CombinedOutput()
	outputStr := string(out)

	if err == nil {
		if strings.Contains(outputStr, "1 packets transmitted, 1 received") ||
			strings.Contains(outputStr, "1 packets transmitted, 1 packets received") ||
			strings.Contains(outputStr, "bytes from") ||
			strings.Contains(outputStr, "Reply from") {
			return true, ""
		}
	}

	// Parse failure reason
	if strings.Contains(outputStr, "frag needed") ||
		strings.Contains(outputStr, "Packet needs to be fragmented") ||
		strings.Contains(outputStr, "Message too long") {
		return false, "DF bit set: packet exceeds path MTU"
	}

	return false, strings.TrimSpace(outputStr)
}
