package diagnostics

import (
	"context"
	"fmt"
	"time"
)

type LinkCarrierCheck struct{}

func (c *LinkCarrierCheck) ID() string          { return "link_carrier" }
func (c *LinkCarrierCheck) Name() string        { return "Physical Link & Interface Carrier" }
func (c *LinkCarrierCheck) Description() string { return "Verifies local NIC state, link carrier, and IPv4 assignment" }

func (c *LinkCarrierCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	if netCtx.InterfaceName == "" {
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     "No active network interface discovered on system",
			Evidence:    []string{"Default route query returned no interface", "No active adapters with valid IPv4"},
			Remediation: "Ensure network cable is connected or Wi-Fi radio is enabled.",
			Timestamp:   time.Now(),
		}, nil
	}

	if !netCtx.InterfaceUp {
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     fmt.Sprintf("Interface %s is administratively DOWN or disconnected", netCtx.InterfaceName),
			Evidence:    []string{fmt.Sprintf("Interface: %s", netCtx.InterfaceName), "Flags: NetLink reports interface DOWN"},
			Remediation: "Bring interface up via network manager or verify physical cable.",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(netCtx.LocalIPs) == 0 {
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityCritical,
			Summary:     fmt.Sprintf("Interface %s is UP but has no IP address assigned", netCtx.InterfaceName),
			Evidence:    []string{"Link state: UP", "IP addresses assigned: 0"},
			Remediation: "Check DHCP server or configure a valid static IP address.",
			Timestamp:   time.Now(),
		}, nil
	}

	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryHealthy,
		Severity:  SeverityNone,
		Summary:   fmt.Sprintf("Interface %s is UP with %d IP address(es)", netCtx.InterfaceName, len(netCtx.LocalIPs)),
		Evidence:  []string{fmt.Sprintf("Primary Interface: %s", netCtx.InterfaceName), fmt.Sprintf("MAC Address: %s", netCtx.MACAddress), fmt.Sprintf("Local IPs: %v", netCtx.LocalIPs)},
		Timestamp: time.Now(),
	}, nil
}
