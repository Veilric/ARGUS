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

// NetworkAdapter provides cross-platform inspection functions.
type NetworkAdapter interface {
	GetDefaultInterface() (*InterfaceInfo, error)
	GetDefaultGateway() (net.IP, error)
	GetDNSServers() ([]string, error)
	GetARPTable() ([]NeighborEntry, error)
	IsElevated() bool
}
