package dhcp

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// DetectChanges compares an established baseline against the current observed configuration.
func DetectChanges(baseline *ConfigBaseline, current *DHCPConfig) []ConfigChange {
	if baseline == nil || current == nil {
		return nil
	}

	var changes []ConfigChange
	now := current.ObservedAt
	if now.IsZero() {
		now = time.Now()
	}

	// 1. Gateway Change
	if baseline.GatewayIP != "" && current.GatewayIP != "" && baseline.GatewayIP != current.GatewayIP {
		changes = append(changes, ConfigChange{
			Kind:          ChangeGatewayChanged,
			InterfaceName: current.InterfaceName,
			FieldName:     "Default Gateway",
			OldValue:      baseline.GatewayIP,
			NewValue:      current.GatewayIP,
			Timestamp:     now,
			Summary:       fmt.Sprintf("Default gateway changed from %s to %s", baseline.GatewayIP, current.GatewayIP),
			Implication:   "Routing changed. May be caused by network switching, DHCP reassignment, or the introduction of a secondary router.",
		})
	}

	// 2. Local IP Address Change
	if baseline.IPv4Address != "" && current.IPv4Address != "" && baseline.IPv4Address != current.IPv4Address {
		changes = append(changes, ConfigChange{
			Kind:          ChangeIPChanged,
			InterfaceName: current.InterfaceName,
			FieldName:     "IPv4 Address",
			OldValue:      baseline.IPv4Address,
			NewValue:      current.IPv4Address,
			Timestamp:     now,
			Summary:       fmt.Sprintf("Assigned IPv4 address changed from %s to %s", baseline.IPv4Address, current.IPv4Address),
			Implication:   "Host received a new IP lease or was assigned a different static address.",
		})
	}

	// 3. Subnet Prefix Change
	if baseline.IPv4Prefix > 0 && current.IPv4Prefix > 0 && baseline.IPv4Prefix != current.IPv4Prefix {
		changes = append(changes, ConfigChange{
			Kind:          ChangePrefixChanged,
			InterfaceName: current.InterfaceName,
			FieldName:     "Subnet Prefix",
			OldValue:      fmt.Sprintf("/%d", baseline.IPv4Prefix),
			NewValue:      fmt.Sprintf("/%d", current.IPv4Prefix),
			Timestamp:     now,
			Summary:       fmt.Sprintf("Subnet prefix changed from /%d to /%d", baseline.IPv4Prefix, current.IPv4Prefix),
			Implication:   "Subnet mask boundaries altered. Broadens or restricts local broadcast domain.",
		})
	}

	// 4. DHCP Server Identifier Change
	if baseline.DHCPServerIP != "" && current.DHCPServerIP != "" && baseline.DHCPServerIP != current.DHCPServerIP {
		changes = append(changes, ConfigChange{
			Kind:          ChangeDHCPServerChanged,
			InterfaceName: current.InterfaceName,
			FieldName:     "DHCP Server",
			OldValue:      baseline.DHCPServerIP,
			NewValue:      current.DHCPServerIP,
			Timestamp:     now,
			Summary:       fmt.Sprintf("Observed DHCP server changed from %s to %s", baseline.DHCPServerIP, current.DHCPServerIP),
			Implication:   "A different DHCP server responded to lease requests. May indicate network roaming, access point mode shift (e.g. Deco Smart DHCP), or multiple competing DHCP servers on the same broadcast domain.",
		})
	}

	// 5. DNS Server List Change
	if !dnsEqual(baseline.DNSServers, current.DNSServers) && len(baseline.DNSServers) > 0 && len(current.DNSServers) > 0 {
		oldList := strings.Join(baseline.DNSServers, ", ")
		newList := strings.Join(current.DNSServers, ", ")
		changes = append(changes, ConfigChange{
			Kind:          ChangeDNSChanged,
			InterfaceName: current.InterfaceName,
			FieldName:     "DNS Servers",
			OldValue:      fmt.Sprintf("[%s]", oldList),
			NewValue:      fmt.Sprintf("[%s]", newList),
			Timestamp:     now,
			Summary:       fmt.Sprintf("Configured DNS servers changed from [%s] to [%s]", oldList, newList),
			Implication:   "Resolver list modified via DHCP option update, VPN client connection, or manual configuration.",
		})
	}

	// 6. Assignment Mode Change
	if baseline.Assignment != current.Assignment &&
		baseline.Assignment != AssignmentUnknown &&
		current.Assignment != AssignmentUnknown {
		changes = append(changes, ConfigChange{
			Kind:          ChangeAssignmentChanged,
			InterfaceName: current.InterfaceName,
			FieldName:     "Assignment Mode",
			OldValue:      string(baseline.Assignment),
			NewValue:      string(current.Assignment),
			Timestamp:     now,
			Summary:       fmt.Sprintf("IP configuration mode shifted from %s to %s", baseline.Assignment, current.Assignment),
			Implication:   "Network stack transitioned between static addressing and dynamic DHCP leasing.",
		})
	}

	return changes
}

func dnsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int)
	for _, x := range a {
		m[x]++
	}
	for _, y := range b {
		m[y]--
		if m[y] < 0 {
			return false
		}
	}
	return true
}

// ChangeTracker deduplicates detected configuration changes so identical observations do not spam alerts.
type ChangeTracker struct {
	mu          sync.Mutex
	lastAlerted map[string]string // Key: iface:fieldName, Value: last Alerted NewValue
}

// NewChangeTracker creates a deduplicating change tracker.
func NewChangeTracker() *ChangeTracker {
	return &ChangeTracker{
		lastAlerted: make(map[string]string),
	}
}

// FilterNewChanges filters out changes that have already been reported with the same value.
func (t *ChangeTracker) FilterNewChanges(changes []ConfigChange) []ConfigChange {
	t.mu.Lock()
	defer t.mu.Unlock()

	var newChanges []ConfigChange
	for _, c := range changes {
		key := fmt.Sprintf("%s:%s", c.InterfaceName, c.FieldName)
		if prev, ok := t.lastAlerted[key]; ok && prev == c.NewValue {
			continue // Already reported
		}
		t.lastAlerted[key] = c.NewValue
		newChanges = append(newChanges, c)
	}
	return newChanges
}
