package dhcp

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"
)

// ParseNMCLI parses output from 'nmcli -t -f IP4,DHCP4 device show <iface>'.
func ParseNMCLI(output string, ifaceName string) (*DHCPConfig, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	cfg := &DHCPConfig{
		InterfaceName: ifaceName,
		Assignment:    AssignmentStatic, // default until DHCP options observed
		Source:        "NetworkManager",
		ObservedAt:    time.Now(),
	}

	hasIP := false
	hasDHCP := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		if strings.HasPrefix(key, "IP4.ADDRESS") {
			// e.g. 192.0.2.100/24
			if ip, ipNet, err := net.ParseCIDR(val); err == nil && ip.To4() != nil {
				cfg.IPv4Address = ip.String()
				ones, _ := ipNet.Mask.Size()
				cfg.IPv4Prefix = ones
				hasIP = true
			}
		} else if key == "IP4.GATEWAY" {
			if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
				cfg.GatewayIP = ip.String()
			}
		} else if strings.HasPrefix(key, "IP4.DNS") {
			if ip := net.ParseIP(val); ip != nil {
				cfg.DNSServers = append(cfg.DNSServers, ip.String())
			}
		} else if strings.HasPrefix(key, "IP4.DOMAIN") {
			if cfg.DomainName == "" {
				cfg.DomainName = val
			}
		} else if strings.HasPrefix(key, "DHCP4.OPTION") {
			hasDHCP = true
			// e.g. dhcp_server_identifier = 192.0.2.1
			optParts := strings.SplitN(val, "=", 2)
			if len(optParts) == 2 {
				optName := strings.TrimSpace(optParts[0])
				optVal := strings.TrimSpace(optParts[1])
				switch optName {
				case "dhcp_server_identifier":
					if ip := net.ParseIP(optVal); ip != nil {
						cfg.DHCPServerIP = ip.String()
					}
				case "expiry":
					if sec, err := strconv.ParseInt(optVal, 10, 64); err == nil && sec > 0 {
						t := time.Unix(sec, 0)
						cfg.LeaseExpires = &t
					}
				case "domain_name":
					cfg.DomainName = optVal
				case "domain_search":
					for _, d := range strings.Fields(optVal) {
						cfg.DomainSearch = append(cfg.DomainSearch, d)
					}
				case "routers":
					if cfg.GatewayIP == "" {
						if ip := net.ParseIP(optVal); ip != nil {
							cfg.GatewayIP = ip.String()
						}
					}
				case "domain_name_servers":
					if len(cfg.DNSServers) == 0 {
						for _, s := range strings.Fields(optVal) {
							if ip := net.ParseIP(s); ip != nil {
								cfg.DNSServers = append(cfg.DNSServers, ip.String())
							}
						}
					}
				}
			}
		}
	}

	if hasDHCP {
		cfg.Assignment = AssignmentDHCP
	} else if !hasIP {
		cfg.Assignment = AssignmentUnknown
	}

	return cfg, nil
}
