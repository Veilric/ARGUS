package dhcp

import (
	"time"
)

// IPAssignmentType defines how an interface obtained its IP configuration.
type IPAssignmentType string

const (
	AssignmentDHCP    IPAssignmentType = "DHCP"
	AssignmentStatic  IPAssignmentType = "STATIC"
	AssignmentUnknown IPAssignmentType = "UNKNOWN"
)

// BaselineType classifies how the network baseline was established.
type BaselineType string

const (
	BaselineInitialObserved BaselineType = "INITIAL_OBSERVED"
	BaselineUserConfirmed   BaselineType = "USER_CONFIRMED"
)

// DHCPConfig represents the observable network and DHCP configuration of an interface.
type DHCPConfig struct {
	InterfaceName string           `json:"interface_name"`
	MACAddress    string           `json:"mac_address,omitempty"`
	IPv4Address   string           `json:"ipv4_address,omitempty"`
	IPv4Prefix    int              `json:"ipv4_prefix,omitempty"`
	Assignment    IPAssignmentType `json:"assignment"`
	GatewayIP     string           `json:"gateway_ip,omitempty"`
	DNSServers    []string         `json:"dns_servers,omitempty"`
	DHCPServerIP  string           `json:"dhcp_server_ip,omitempty"`
	LeaseObtained *time.Time       `json:"lease_obtained,omitempty"`
	LeaseExpires  *time.Time       `json:"lease_expires,omitempty"`
	DomainName    string           `json:"domain_name,omitempty"`
	DomainSearch  []string         `json:"domain_search,omitempty"`
	Source        string           `json:"source"`
	ObservedAt    time.Time        `json:"observed_at"`
}

// ConfigBaseline stores a persistent reference observation for an interface.
type ConfigBaseline struct {
	Type          BaselineType     `json:"type,omitempty"`
	InterfaceName string           `json:"interface_name"`
	MACAddress    string           `json:"mac_address,omitempty"`
	IPv4Address   string           `json:"ipv4_address,omitempty"`
	IPv4Prefix    int              `json:"ipv4_prefix,omitempty"`
	Assignment    IPAssignmentType `json:"assignment"`
	GatewayIP     string           `json:"gateway_ip,omitempty"`
	DNSServers    []string         `json:"dns_servers,omitempty"`
	DHCPServerIP  string           `json:"dhcp_server_ip,omitempty"`
	DomainName    string           `json:"domain_name,omitempty"`
	EstablishedAt time.Time        `json:"established_at"`
	LastSeenAt    time.Time        `json:"last_seen_at"`
}

// ChangeKind represents specific configuration change types.
type ChangeKind string

const (
	ChangeGatewayChanged    ChangeKind = "GATEWAY_CHANGED"
	ChangeIPChanged         ChangeKind = "IP_CHANGED"
	ChangePrefixChanged     ChangeKind = "PREFIX_CHANGED"
	ChangeDNSChanged        ChangeKind = "DNS_CHANGED"
	ChangeDHCPServerChanged ChangeKind = "DHCP_SERVER_CHANGED"
	ChangeLeaseRenewed      ChangeKind = "LEASE_RENEWED"
	ChangeAssignmentChanged ChangeKind = "ASSIGNMENT_CHANGED"
	ChangeRestored          ChangeKind = "CONFIG_RESTORED"
)

// ConfigChange records a detected transition between observed configurations.
type ConfigChange struct {
	Kind          ChangeKind `json:"kind"`
	InterfaceName string     `json:"interface_name"`
	FieldName     string     `json:"field_name"`
	OldValue      string     `json:"old_value"`
	NewValue      string     `json:"new_value"`
	Timestamp     time.Time  `json:"timestamp"`
	Summary       string     `json:"summary"`
	Implication   string     `json:"implication"`
}

// ConfigEquals reports whether two DHCP configurations have identical network addressing and routing parameters.
func ConfigEquals(a, b *DHCPConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.InterfaceName != b.InterfaceName ||
		a.IPv4Address != b.IPv4Address ||
		a.IPv4Prefix != b.IPv4Prefix ||
		a.Assignment != b.Assignment ||
		a.GatewayIP != b.GatewayIP ||
		a.DHCPServerIP != b.DHCPServerIP ||
		a.DomainName != b.DomainName {
		return false
	}
	if len(a.DNSServers) != len(b.DNSServers) {
		return false
	}
	m := make(map[string]int)
	for _, s := range a.DNSServers {
		m[s]++
	}
	for _, s := range b.DNSServers {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	return true
}
