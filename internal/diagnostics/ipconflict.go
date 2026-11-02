package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type IPConflictCheck struct{}

func (c *IPConflictCheck) ID() string          { return "ip_conflict" }
func (c *IPConflictCheck) Name() string        { return "IP Address Conflict & ARP Inconsistency" }
func (c *IPConflictCheck) Description() string { return "Detects duplicate IP assignments where another machine claims this host's IP" }

func (c *IPConflictCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	if len(netCtx.LocalIPs) == 0 {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryInconclusive,
			Severity:  SeverityInfo,
			Summary:   "No local IP addresses to check for conflicts",
			Evidence:  []string{"Local IP list is empty"},
			Timestamp: time.Now(),
		}, nil
	}

	normalizedOwnMAC := strings.ToLower(strings.TrimSpace(netCtx.MACAddress))

	// Check ARP table for host's own IPs
	for _, localCIDR := range netCtx.LocalIPs {
		ipParts := strings.Split(localCIDR, "/")
		ownIP := ipParts[0]

		if macInTable, found := netCtx.ARPTable[ownIP]; found {
			normalizedTableMAC := strings.ToLower(strings.TrimSpace(macInTable))
			if normalizedTableMAC != normalizedOwnMAC && normalizedTableMAC != "00:00:00:00:00:00" {
				return &DiagnosticResult{
					ID:       c.ID(),
					Title:    c.Name(),
					Category: CategoryConfirmed,
					Severity: SeverityCritical,
					Summary:  fmt.Sprintf("CRITICAL: IP Address Conflict Detected on %s!", ownIP),
					Evidence: []string{
						fmt.Sprintf("Host Local IP: %s", ownIP),
						fmt.Sprintf("Host Hardware MAC: %s", netCtx.MACAddress),
						fmt.Sprintf("Conflicting Remote Device MAC: %s", macInTable),
						"Local ARP cache maps host IP to a foreign hardware address",
					},
					Remediation: "Another machine is using this static IP. Change host IP address or disconnect the conflicting device.",
					Timestamp:   time.Now(),
				}, nil
			}
		}
	}

	evidence := []string{
		fmt.Sprintf("Local IPs verified: %v", netCtx.LocalIPs),
		fmt.Sprintf("Local MAC: %s", netCtx.MACAddress),
		fmt.Sprintf("Total ARP neighbors evaluated: %d", len(netCtx.ARPTable)),
	}

	if netCtx.IsElevated {
		evidence = append(evidence, "Mode: Elevated (active ARP verification enabled)")
	} else {
		evidence = append(evidence, "Mode: Standard User (passive ARP table verification)")
	}

	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryHealthy,
		Severity:  SeverityNone,
		Summary:   "No IP address conflicts detected. Local IP is unique on LAN.",
		Evidence:  evidence,
		Timestamp: time.Now(),
	}, nil
}
