package platform

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// WindowsAdapterSection holds parsed IP and DNS configuration for a single adapter.
type WindowsAdapterSection struct {
	AdapterType string
	AdapterName string
	Description string
	IPv4Addrs   []string
	IPv6Addrs   []string
	DNSServers  []string
	DHCPServer  string
	DHCPEnabled bool
}

var (
	adapterHeaderRegex = regexp.MustCompile(`(?i)^(?:([a-z0-9 ]+?)\s+)?adapter\s+(.+?):\s*$`)
	dnsServerLineRegex = regexp.MustCompile(`(?i)DNS Servers[ .:]+:\s*([^\r\n]*)`)
	ipv4LineRegex      = regexp.MustCompile(`(?i)IPv4 Address[ .:]+:\s*([^\r\n]*)`)
	ipv6LineRegex      = regexp.MustCompile(`(?i)(?:Link-local )?IPv6 Address[ .:]+:\s*([^\r\n]*)`)
	dhcpEnabledRegex   = regexp.MustCompile(`(?i)DHCP Enabled[ .:]+:\s*([^\r\n]*)`)
	dhcpServerRegex    = regexp.MustCompile(`(?i)DHCP Server[ .:]+:\s*([^\r\n]*)`)
	keyValueLineRegex  = regexp.MustCompile(`^[ \t]+[A-Za-z0-9() -]+[ .]+:\s*`)
)

// ParseWindowsIPConfigSections parses all adapter sections from 'ipconfig /all' output.
func ParseWindowsIPConfigSections(output string) ([]WindowsAdapterSection, error) {
	if strings.TrimSpace(output) == "" {
		return nil, fmt.Errorf("ipconfig output is empty")
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	var sections []WindowsAdapterSection
	var current *WindowsAdapterSection
	inDNSBlock := false

	for scanner.Scan() {
		rawLine := scanner.Text()
		trimmedLine := strings.TrimSpace(rawLine)

		// Check if this line starts a new adapter section
		if headerMatches := adapterHeaderRegex.FindStringSubmatch(trimmedLine); len(headerMatches) > 2 {
			if current != nil {
				sections = append(sections, *current)
			}
			current = &WindowsAdapterSection{
				AdapterType: strings.TrimSpace(headerMatches[1]),
				AdapterName: strings.TrimSpace(headerMatches[2]),
			}
			inDNSBlock = false
			continue
		}

		if current == nil {
			continue
		}

		// Check for DNS Servers line
		if dnsMatches := dnsServerLineRegex.FindStringSubmatch(rawLine); len(dnsMatches) > 1 {
			inDNSBlock = true
			val := cleanIPString(dnsMatches[1])
			if ip := net.ParseIP(val); ip != nil {
				current.DNSServers = append(current.DNSServers, ip.String())
			}
			continue
		}

		// If we are currently inside a multi-line DNS server block
		if inDNSBlock {
			// A key-value line or new section ends the DNS block
			if keyValueLineRegex.MatchString(rawLine) || strings.HasSuffix(trimmedLine, ":") {
				inDNSBlock = false
			} else if trimmedLine != "" {
				val := cleanIPString(trimmedLine)
				if ip := net.ParseIP(val); ip != nil {
					current.DNSServers = append(current.DNSServers, ip.String())
				}
				continue
			}
		}

		// Parse IPv4 address
		if ipv4Matches := ipv4LineRegex.FindStringSubmatch(rawLine); len(ipv4Matches) > 1 {
			val := cleanIPString(ipv4Matches[1])
			if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
				current.IPv4Addrs = append(current.IPv4Addrs, ip.String())
			}
			continue
		}

		// Parse IPv6 address
		if ipv6Matches := ipv6LineRegex.FindStringSubmatch(rawLine); len(ipv6Matches) > 1 {
			val := cleanIPString(ipv6Matches[1])
			if ip := net.ParseIP(val); ip != nil && ip.To4() == nil {
				current.IPv6Addrs = append(current.IPv6Addrs, ip.String())
			}
			continue
		}

		// Parse DHCP Enabled
		if dhcpMatches := dhcpEnabledRegex.FindStringSubmatch(rawLine); len(dhcpMatches) > 1 {
			if strings.EqualFold(strings.TrimSpace(dhcpMatches[1]), "yes") {
				current.DHCPEnabled = true
			}
			continue
		}

		// Parse DHCP Server
		if dhcpSrvMatches := dhcpServerRegex.FindStringSubmatch(rawLine); len(dhcpSrvMatches) > 1 {
			val := cleanIPString(dhcpSrvMatches[1])
			if ip := net.ParseIP(val); ip != nil {
				current.DHCPServer = ip.String()
			}
			continue
		}
	}

	if current != nil {
		sections = append(sections, *current)
	}

	if len(sections) == 0 {
		return nil, fmt.Errorf("no network adapter sections recognized in ipconfig output")
	}

	return sections, nil
}

// ParseWindowsIPConfigDNS extracts configured DNS servers from ipconfig /all output
// for the target interface name or IP addresses. Never returns fabricated fallback IPs.
func ParseWindowsIPConfigDNS(output string, targetIface string, targetIPs []string) ([]string, error) {
	sections, err := ParseWindowsIPConfigSections(output)
	if err != nil {
		return nil, err
	}

	targetIPMap := make(map[string]bool)
	for _, ip := range targetIPs {
		clean := cleanIPString(ip)
		if clean != "" {
			targetIPMap[clean] = true
		}
	}

	var matchedSection *WindowsAdapterSection

	if targetIface != "" {
		for i := range sections {
			sec := &sections[i]
			if strings.EqualFold(sec.AdapterName, targetIface) {
				matchedSection = sec
				break
			}
		}
	}

	// If not matched by exact name, match by target IP address
	if matchedSection == nil && len(targetIPMap) > 0 {
		for i := range sections {
			sec := &sections[i]
			for _, ip := range sec.IPv4Addrs {
				if targetIPMap[ip] {
					matchedSection = sec
					break
				}
			}
			if matchedSection != nil {
				break
			}
		}
	}

	// If still not matched and targetIface was specified, check case-insensitive contains
	if matchedSection == nil && targetIface != "" {
		targetLower := strings.ToLower(targetIface)
		for i := range sections {
			sec := &sections[i]
			if strings.Contains(strings.ToLower(sec.AdapterName), targetLower) ||
				strings.Contains(targetLower, strings.ToLower(sec.AdapterName)) {
				matchedSection = sec
				break
			}
		}
	}

	// If no interface was specified, use the first adapter with an IP and DNS configured
	if matchedSection == nil && targetIface == "" {
		for i := range sections {
			sec := &sections[i]
			if len(sec.IPv4Addrs) > 0 && len(sec.DNSServers) > 0 {
				matchedSection = sec
				break
			}
		}
	}

	if matchedSection == nil {
		if targetIface != "" {
			return nil, fmt.Errorf("interface %q not found in Windows IP configuration", targetIface)
		}
		return nil, fmt.Errorf("no active interface found in Windows IP configuration")
	}

	if len(matchedSection.DNSServers) == 0 {
		return nil, fmt.Errorf("no DNS servers configured on interface %q", matchedSection.AdapterName)
	}

	return matchedSection.DNSServers, nil
}

// ParseWindowsNetshDNS parses the output of 'netsh interface ip show dnsservers' and
// 'netsh interface ipv6 show dnsservers'. Never returns fabricated fallback IPs.
func ParseWindowsNetshDNS(ipv4Output string, ipv6Output string, targetIface string) ([]string, error) {
	var servers []string
	seen := make(map[string]bool)

	parseSingleNetsh := func(out string) {
		if strings.TrimSpace(out) == "" {
			return
		}
		scanner := bufio.NewScanner(strings.NewReader(out))
		inTargetIface := (targetIface == "")
		inDNSBlock := false

		ifaceHeaderRegex := regexp.MustCompile(`(?i)Configuration for interface "([^"]+)"`)
		dnsStartRegex := regexp.MustCompile(`(?i)(?:DNS servers configured through DHCP|Statically Configured DNS Servers):\s*(.*)`)

		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)

			if matches := ifaceHeaderRegex.FindStringSubmatch(line); len(matches) > 1 {
				name := matches[1]
				if targetIface == "" {
					inTargetIface = true
				} else {
					inTargetIface = strings.EqualFold(name, targetIface) ||
						strings.Contains(strings.ToLower(name), strings.ToLower(targetIface)) ||
						strings.Contains(strings.ToLower(targetIface), strings.ToLower(name))
				}
				inDNSBlock = false
				continue
			}

			if !inTargetIface {
				continue
			}

			if matches := dnsStartRegex.FindStringSubmatch(line); len(matches) > 1 {
				inDNSBlock = true
				val := cleanIPString(matches[1])
				if ip := net.ParseIP(val); ip != nil {
					s := ip.String()
					if !seen[s] {
						seen[s] = true
						servers = append(servers, s)
					}
				}
				continue
			}

			if inDNSBlock {
				if strings.Contains(line, ":") {
					// Another section property ends the DNS block
					inDNSBlock = false
				} else if trimmed != "" {
					val := cleanIPString(trimmed)
					if ip := net.ParseIP(val); ip != nil {
						s := ip.String()
						if !seen[s] {
							seen[s] = true
							servers = append(servers, s)
						}
					}
				}
			}
		}
	}

	parseSingleNetsh(ipv4Output)
	parseSingleNetsh(ipv6Output)

	if len(servers) == 0 {
		if targetIface != "" {
			return nil, fmt.Errorf("no DNS servers found in netsh configuration for interface %q", targetIface)
		}
		return nil, fmt.Errorf("no DNS servers found in netsh configuration")
	}

	return servers, nil
}

// cleanIPString strips parenthetical metadata like '(Preferred)', zone IDs like '%12', and whitespace.
func cleanIPString(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "("); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	if idx := strings.Index(s, "%"); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	return s
}
