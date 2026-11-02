package dhcp

// Inspector retrieves the current DHCP and network configuration for an interface.
type Inspector interface {
	Inspect(ifaceName string) (*DHCPConfig, error)
}

// NewInspector creates an OS-specific inspector for the current platform.
func NewInspector() Inspector {
	return newPlatformInspector()
}
