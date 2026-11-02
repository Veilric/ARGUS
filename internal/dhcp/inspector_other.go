//go:build !linux && !windows

package dhcp

import (
	"fmt"
	"net"
	"time"
)

type otherInspector struct{}

func newPlatformInspector() Inspector {
	return &otherInspector{}
}

func (o *otherInspector) Inspect(ifaceName string) (*DHCPConfig, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("interface name not specified")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	cfg := &DHCPConfig{
		InterfaceName: ifaceName,
		MACAddress:    iface.HardwareAddr.String(),
		Assignment:    AssignmentUnknown,
		Source:        "Generic OS Network Interface",
		ObservedAt:    time.Now(),
	}

	addrs, err := iface.Addrs()
	if err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				cfg.IPv4Address = ipNet.IP.String()
				ones, _ := ipNet.Mask.Size()
				cfg.IPv4Prefix = ones
				break
			}
		}
	}

	return cfg, nil
}
