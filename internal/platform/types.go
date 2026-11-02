package platform

import (
	"net"
)

// InterfaceInfo stores local adapter telemetry and state.
type InterfaceInfo struct {
	Name         string
	Index        int
	HardwareAddr net.HardwareAddr
	IPs          []net.IPNet
	Flags        net.Flags
	MTU          int
	IsUp         bool
	IsLoopback   bool
}

// NeighborEntry represents an entry from the system ARP/neighbor table.
type NeighborEntry struct {
	IP        string
	MAC       string
	Interface string
	State     string
	Hostname  string
}

// Route represents a network routing table entry.
type Route struct {
	Destination *net.IPNet
	Gateway     net.IP
	Interface   string
	Metric      int
}

// RouteStatus describes the routing table status and attribution certainty for an adapter.
type RouteStatus struct {
	HasDefaultRoute bool
	IsPrimary       bool
	GatewayIP       net.IP
	InterfaceName   string
	Metric          int
	Details         string
}

// AttributionKind classifies measurement attribution certainty.
type AttributionKind string

const (
	AttributionSelectedInterface AttributionKind = "SELECTED_INTERFACE"
	AttributionSystemWide        AttributionKind = "SYSTEM_WIDE"
	AttributionUnverified        AttributionKind = "UNVERIFIED"
)

// NetworkAdapter provides cross-platform inspection functions.
type NetworkAdapter interface {
	GetDefaultInterface() (*InterfaceInfo, error)
	GetDefaultGateway() (net.IP, error)
	GetDNSServers() ([]string, error)
	GetARPTable() ([]NeighborEntry, error)
	GetRouteStatus() (RouteStatus, error)
	IsElevated() bool
}
