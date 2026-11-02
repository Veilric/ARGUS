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
func (c *IPConflictCheck) Description() string { return "Inspects ARP mappings to detect duplicate IP assignments claiming this host's IP" }

func (c *IPConflictCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	if len(netCtx.LocalIPs) == 0 {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryInconclusive,
			Severity:  SeverityInfo,
			Summary:   "No local IP addresses available to evaluate for conflicts",
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
			if normalizedTableMAC != normalizedOwnMAC && normalizedTableMAC != "00:00:00:00:00:00" && normalizedTableMAC != "incomplete" {
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
					Remediation: "Another machine is active with this IP. Change host IP address, configure DHCP, or locate and disconnect the conflicting device.",
					Timestamp:   time.Now(),
				}, nil
			}
		}
	}

	evidence := []string{
		fmt.Sprintf("Local IPs verified: %v", netCtx.LocalIPs),
		fmt.Sprintf("Local MAC: %s", netCtx.MACAddress),
		fmt.Sprintf("Total ARP cache neighbors evaluated: %d", len(netCtx.ARPTable)),
		"Verification Scope: Passive system ARP cache inspection",
		"Absence of duplicate ARP entries in cache does not prove address uniqueness across silent or uncontacted broadcast domain hosts",
	}

	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryInconclusive,
		Severity:  SeverityInfo,
		Summary:   "No conflicting address evidence observed in the available neighbor data. IP uniqueness has not been verified.",
		Evidence:  evidence,
		Timestamp: time.Now(),
	}, nil
}
