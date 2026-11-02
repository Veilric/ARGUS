//go:build windows

package dhcp

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
)

type windowsInspector struct{}

func newPlatformInspector() Inspector {
	return &windowsInspector{}
}

func (w *windowsInspector) Inspect(ifaceName string) (*DHCPConfig, error) {
	cmd := exec.Command("ipconfig", "/all")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute ipconfig /all: %w", err)
	}

	cfg, err := ParseWindowsIPConfigDHCP(out.String(), ifaceName)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("interface %q not found in Windows IP configuration", ifaceName)
	}

	if ifaceName != "" && cfg.MACAddress == "" {
		if iface, err := net.InterfaceByName(ifaceName); err == nil {
			cfg.MACAddress = iface.HardwareAddr.String()
		}
	}

	return cfg, nil
}
