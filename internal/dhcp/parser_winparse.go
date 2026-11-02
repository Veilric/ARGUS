package dhcp

import (
	"bufio"
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	winAdapterHeaderRegex = regexp.MustCompile(`(?i)^(?:([a-z0-9 ]+?)\s+)?adapter\s+(.+?):\s*$`)
	winIPv4Regex          = regexp.MustCompile(`(?i)IPv4 Address[ .:]+:\s*([^\r\n]*)`)
	winMaskRegex          = regexp.MustCompile(`(?i)Subnet Mask[ .:]+:\s*([^\r\n]*)`)
	winGatewayRegex       = regexp.MustCompile(`(?i)Default Gateway[ .:]+:\s*([^\r\n]*)`)
	winDHCPEnabledRegex   = regexp.MustCompile(`(?i)DHCP Enabled[ .:]+:\s*([^\r\n]*)`)
	winDHCPServerRegex    = regexp.MustCompile(`(?i)DHCP Server[ .:]+:\s*([^\r\n]*)`)
	winDNSRegex           = regexp.MustCompile(`(?i)DNS Servers[ .:]+:\s*([^\r\n]*)`)
	winSuffixRegex        = regexp.MustCompile(`(?i)Connection-specific DNS Suffix[ .:]+:\s*([^\r\n]*)`)
	winKeyValRegex        = regexp.MustCompile(`^[ \t]+[A-Za-z0-9() -]+[ .]+:\s*`)
)

// ParseWindowsIPConfigDHCP extracts DHCP and network configuration from 'ipconfig /all' output.
func ParseWindowsIPConfigDHCP(output string, targetIface string) (*DHCPConfig, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var matched *DHCPConfig
	var current *DHCPConfig
	inDNSBlock := false

	for scanner.Scan() {
		rawLine := scanner.Text()
		trimmedLine := strings.TrimSpace(rawLine)

		if headerMatches := winAdapterHeaderRegex.FindStringSubmatch(trimmedLine); len(headerMatches) > 2 {
			if current != nil && isInterfaceMatch(current.InterfaceName, targetIface) {
				matched = current
				break
			}
			current = &DHCPConfig{
				InterfaceName: strings.TrimSpace(headerMatches[2]),
				Assignment:    AssignmentStatic,
				Source:        "Windows ipconfig",
				ObservedAt:    time.Now(),
			}
			inDNSBlock = false
			continue
		}

		if current == nil {
			continue
		}

		if dhcpMatches := winDHCPEnabledRegex.FindStringSubmatch(rawLine); len(dhcpMatches) > 1 {
			if strings.EqualFold(strings.TrimSpace(dhcpMatches[1]), "yes") {
				current.Assignment = AssignmentDHCP
			} else {
				current.Assignment = AssignmentStatic
			}
			continue
		}

		if ipv4Matches := winIPv4Regex.FindStringSubmatch(rawLine); len(ipv4Matches) > 1 {
			val := cleanWinValue(ipv4Matches[1])
			if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
				current.IPv4Address = ip.String()
			}
			continue
		}

		if maskMatches := winMaskRegex.FindStringSubmatch(rawLine); len(maskMatches) > 1 {
			val := cleanWinValue(maskMatches[1])
			if maskIP := net.ParseIP(val); maskIP != nil && maskIP.To4() != nil {
				mask := net.IPMask(maskIP.To4())
				ones, _ := mask.Size()
				current.IPv4Prefix = ones
			}
			continue
		}

		if gwMatches := winGatewayRegex.FindStringSubmatch(rawLine); len(gwMatches) > 1 {
			val := cleanWinValue(gwMatches[1])
			if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
				current.GatewayIP = ip.String()
			}
			continue
		}

		if dhcpSrvMatches := winDHCPServerRegex.FindStringSubmatch(rawLine); len(dhcpSrvMatches) > 1 {
			val := cleanWinValue(dhcpSrvMatches[1])
			if ip := net.ParseIP(val); ip != nil {
				current.DHCPServerIP = ip.String()
				current.Assignment = AssignmentDHCP
			}
			continue
		}

		if suffixMatches := winSuffixRegex.FindStringSubmatch(rawLine); len(suffixMatches) > 1 {
			current.DomainName = strings.TrimSpace(suffixMatches[1])
			continue
		}

		if dnsMatches := winDNSRegex.FindStringSubmatch(rawLine); len(dnsMatches) > 1 {
			inDNSBlock = true
			val := cleanWinValue(dnsMatches[1])
			if ip := net.ParseIP(val); ip != nil {
				current.DNSServers = append(current.DNSServers, ip.String())
			}
			continue
		}

		if inDNSBlock {
			if winKeyValRegex.MatchString(rawLine) || strings.HasSuffix(trimmedLine, ":") {
				inDNSBlock = false
			} else if trimmedLine != "" {
				val := cleanWinValue(trimmedLine)
				if ip := net.ParseIP(val); ip != nil {
					current.DNSServers = append(current.DNSServers, ip.String())
				}
				continue
			}
		}
	}

	if matched == nil && current != nil && isInterfaceMatch(current.InterfaceName, targetIface) {
		matched = current
	}

	// If no exact match and targetIface was empty, take first adapter with IPv4
	if matched == nil && targetIface == "" && current != nil && current.IPv4Address != "" {
		matched = current
	}

	if matched != nil {
		if matched.IPv4Address == "" {
			matched.Assignment = AssignmentUnknown
		}
		return matched, nil
	}

	return nil, nil
}

func isInterfaceMatch(adapterName, target string) bool {
	if target == "" {
		return true
	}
	return strings.EqualFold(adapterName, target) ||
		strings.Contains(strings.ToLower(adapterName), strings.ToLower(target)) ||
		strings.Contains(strings.ToLower(target), strings.ToLower(adapterName))
}

func cleanWinValue(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "("); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	if idx := strings.Index(s, "%"); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	return s
}
