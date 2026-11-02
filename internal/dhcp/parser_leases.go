package dhcp

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"
)

// ParseDHClientLease parses the latest lease block from a dhclient lease file.
func ParseDHClientLease(content string, ifaceName string) (*DHCPConfig, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var current *DHCPConfig
	var latest *DHCPConfig

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "lease {") {
			current = &DHCPConfig{
				Assignment: AssignmentDHCP,
				Source:     "dhclient lease",
				ObservedAt: time.Now(),
			}
			continue
		}

		if line == "}" && current != nil {
			if ifaceName == "" || current.InterfaceName == ifaceName {
				// Reject expired leases
				isExpired := current.LeaseExpires != nil && current.LeaseExpires.Before(time.Now())
				if !isExpired {
					latest = current
				}
			}
			current = nil
			continue
		}

		if current == nil {
			continue
		}

		line = strings.TrimSuffix(line, ";")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "interface":
			current.InterfaceName = strings.Trim(fields[1], `"`)
		case "fixed-address":
			if ip := net.ParseIP(fields[1]); ip != nil {
				current.IPv4Address = ip.String()
			}
		case "option":
			if len(fields) >= 3 {
				switch fields[1] {
				case "subnet-mask":
					if maskIP := net.ParseIP(fields[2]); maskIP != nil && maskIP.To4() != nil {
						mask := net.IPMask(maskIP.To4())
						ones, _ := mask.Size()
						current.IPv4Prefix = ones
					}
				case "routers":
					if ip := net.ParseIP(fields[2]); ip != nil {
						current.GatewayIP = ip.String()
					}
				case "dhcp-server-identifier":
					if ip := net.ParseIP(fields[2]); ip != nil {
						current.DHCPServerIP = ip.String()
					}
				case "domain-name-servers":
					rawServers := strings.Join(fields[2:], " ")
					for _, s := range strings.Split(rawServers, ",") {
						s = strings.TrimSpace(s)
						if ip := net.ParseIP(s); ip != nil {
							current.DNSServers = append(current.DNSServers, ip.String())
						}
					}
				case "domain-name":
					current.DomainName = strings.Trim(fields[2], `"`)
				}
			}
		case "expire":
			// expire <weekday> <YYYY/MM/DD> <HH:MM:SS>
			if len(fields) >= 4 {
				dtStr := fields[2] + " " + fields[3]
				if t, err := time.Parse("2006/01/02 15:04:05", dtStr); err == nil {
					current.LeaseExpires = &t
				}
			}
		case "renew":
			if len(fields) >= 4 {
				dtStr := fields[2] + " " + fields[3]
				if t, err := time.Parse("2006/01/02 15:04:05", dtStr); err == nil {
					current.LeaseObtained = &t
				}
			}
		}
	}

	return latest, nil
}

// ParseSystemdNetworkdLease parses systemd-networkd /run/systemd/netif/leases/* key-value files.
func ParseSystemdNetworkdLease(content string, ifaceName string) (*DHCPConfig, error) {
	return ParseSystemdNetworkdLeaseWithAcquisition(content, ifaceName, time.Time{})
}

// ParseSystemdNetworkdLeaseWithAcquisition parses a systemd-networkd lease, anchoring the lease lifetime
// to a trustworthy acquisition timestamp (such as file modification time or internal acquisition header)
// rather than advancing expiration on every parse.
func ParseSystemdNetworkdLeaseWithAcquisition(content string, ifaceName string, acquiredAt time.Time) (*DHCPConfig, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	cfg := &DHCPConfig{
		InterfaceName: ifaceName,
		Assignment:    AssignmentDHCP,
		Source:        "systemd-networkd",
		ObservedAt:    time.Now(),
	}

	var lifetimeSec int64
	var fileAcquired time.Time

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "ADDRESS":
			if ip := net.ParseIP(val); ip != nil {
				cfg.IPv4Address = ip.String()
			}
		case "NETMASK":
			if maskIP := net.ParseIP(val); maskIP != nil && maskIP.To4() != nil {
				mask := net.IPMask(maskIP.To4())
				ones, _ := mask.Size()
				cfg.IPv4Prefix = ones
			}
		case "ROUTER":
			if ip := net.ParseIP(val); ip != nil {
				cfg.GatewayIP = ip.String()
			}
		case "SERVER_ADDRESS":
			if ip := net.ParseIP(val); ip != nil {
				cfg.DHCPServerIP = ip.String()
			}
		case "DNS":
			for _, d := range strings.Fields(val) {
				if ip := net.ParseIP(d); ip != nil {
					cfg.DNSServers = append(cfg.DNSServers, ip.String())
				}
			}
		case "DOMAINNAME":
			cfg.DomainName = val
		case "LIFETIME":
			if sec, err := strconv.ParseInt(val, 10, 64); err == nil && sec > 0 {
				lifetimeSec = sec
			}
		case "_ACQUIRED", "USEC_ACQUIRED", "TIMESTAMP_REALTIME":
			if usec, err := strconv.ParseInt(val, 10, 64); err == nil && usec > 0 {
				if usec > 1_000_000_000_000_000 {
					fileAcquired = time.Unix(usec/1_000_000, (usec%1_000_000)*1000)
				} else if usec > 1_000_000_000 {
					fileAcquired = time.Unix(usec, 0)
				}
			}
		}
	}

	if cfg.IPv4Address == "" {
		return nil, nil
	}

	// Determine trustworthy acquisition timestamp
	var tAcq time.Time
	if !fileAcquired.IsZero() {
		tAcq = fileAcquired
	} else if !acquiredAt.IsZero() {
		tAcq = acquiredAt
	}

	if lifetimeSec > 0 {
		if !tAcq.IsZero() {
			cfg.LeaseObtained = &tAcq
			exp := tAcq.Add(time.Duration(lifetimeSec) * time.Second)
			cfg.LeaseExpires = &exp

			// Reject if already expired
			if exp.Before(time.Now()) {
				return nil, nil
			}
		} else {
			// Lease age cannot be determined reliably from file alone without acquisition evidence.
			// Explicitly qualify its validity and do NOT advance expiration relative to current time.
			cfg.LeaseExpires = nil
			cfg.Source = "systemd-networkd (unverified lease age)"
		}
	}

	return cfg, nil
}
