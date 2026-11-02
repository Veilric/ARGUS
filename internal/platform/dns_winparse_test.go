package platform

import (
	"strings"
	"testing"
)

const sampleIPConfigSingleInterface = `
Windows IP Configuration

   Host Name . . . . . . . . . . . . : ARGUS-DESKTOP
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : corp.local
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection (7) I219-V
   Physical Address. . . . . . . . . : 00-15-5D-AA-BB-CC
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::1234:5678:9abc:def0%12(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.1.105(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       192.168.1.254
                                       2606:4700:4700::1111
   NetBIOS over Tcpip. . . . . . . . : Enabled
`

const sampleIPConfigMultiInterface = `
Windows IP Configuration

   Host Name . . . . . . . . . . . . : WORKSTATION-01

Ethernet adapter Ethernet 1:

   Connection-specific DNS Suffix  . : office.lan
   Description . . . . . . . . . . . : Realtek Gaming GbE Family Controller
   Physical Address. . . . . . . . . : 00-E0-4C-11-22-33
   DHCP Enabled. . . . . . . . . . . : No
   IPv4 Address. . . . . . . . . . . : 10.10.10.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.1
   DNS Servers . . . . . . . . . . . : 10.10.10.2
                                       10.10.10.3

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : home.net
   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX200 160MHz
   Physical Address. . . . . . . . . : 00-15-5D-44-55-66
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.50.25(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.1
   DHCP Server . . . . . . . . . . . : 192.168.50.1
   DNS Servers . . . . . . . . . . . : 192.168.50.1

Ethernet adapter vEthernet (WSL):

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter
   Physical Address. . . . . . . . . : 00-15-5D-77-88-99
   DHCP Enabled. . . . . . . . . . . : No
   IPv4 Address. . . . . . . . . . . : 172.28.16.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 
   DNS Servers . . . . . . . . . . . : 
`

func TestWindowsDNS_SuccessfulDiscovery_SingleInterface(t *testing.T) {
	servers, err := ParseWindowsIPConfigDNS(sampleIPConfigSingleInterface, "Ethernet", nil)
	if err != nil {
		t.Fatalf("expected successful DNS parse, got err: %v", err)
	}

	expected := []string{"192.168.1.1", "192.168.1.254", "2606:4700:4700::1111"}
	if len(servers) != len(expected) {
		t.Fatalf("expected %d DNS servers, got %d: %v", len(expected), len(servers), servers)
	}

	for i, exp := range expected {
		if servers[i] != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, servers[i])
		}
	}
}

func TestWindowsDNS_MultiInterface_TargetAssociation(t *testing.T) {
	// Query for Wi-Fi interface specifically
	wifiServers, err := ParseWindowsIPConfigDNS(sampleIPConfigMultiInterface, "Wi-Fi", nil)
	if err != nil {
		t.Fatalf("expected Wi-Fi DNS parse success, got: %v", err)
	}
	if len(wifiServers) != 1 || wifiServers[0] != "192.168.50.1" {
		t.Fatalf("expected Wi-Fi DNS [192.168.50.1], got %v", wifiServers)
	}

	// Query for Ethernet 1 specifically
	ethServers, err := ParseWindowsIPConfigDNS(sampleIPConfigMultiInterface, "Ethernet 1", nil)
	if err != nil {
		t.Fatalf("expected Ethernet 1 DNS parse success, got: %v", err)
	}
	if len(ethServers) != 2 || ethServers[0] != "10.10.10.2" || ethServers[1] != "10.10.10.3" {
		t.Fatalf("expected Ethernet 1 DNS [10.10.10.2 10.10.10.3], got %v", ethServers)
	}
}

func TestWindowsDNS_TargetIPAssociation(t *testing.T) {
	// Query by IP address instead of name
	servers, err := ParseWindowsIPConfigDNS(sampleIPConfigMultiInterface, "", []string{"192.168.50.25"})
	if err != nil {
		t.Fatalf("expected IP association parse success, got: %v", err)
	}
	if len(servers) != 1 || servers[0] != "192.168.50.1" {
		t.Fatalf("expected [192.168.50.1], got %v", servers)
	}
}

func TestWindowsDNS_EmptyDNS_ReturnsMeaningfulError(t *testing.T) {
	// vEthernet (WSL) has no DNS configured
	_, err := ParseWindowsIPConfigDNS(sampleIPConfigMultiInterface, "vEthernet (WSL)", nil)
	if err == nil {
		t.Fatal("expected error when interface has no DNS configured, got nil")
	}
	if !strings.Contains(err.Error(), "no DNS servers configured") {
		t.Errorf("expected 'no DNS servers configured' error, got %v", err)
	}
}

func TestWindowsDNS_MissingInterface_ReturnsError(t *testing.T) {
	_, err := ParseWindowsIPConfigDNS(sampleIPConfigMultiInterface, "NonExistentAdapter", nil)
	if err == nil {
		t.Fatal("expected error for non-existent interface, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got %v", err)
	}
}

func TestWindowsDNS_MalformedOutput_ReturnsError(t *testing.T) {
	_, err := ParseWindowsIPConfigDNS("Garbage text with no recognizable adapters", "", nil)
	if err == nil {
		t.Fatal("expected error on malformed ipconfig output, got nil")
	}

	_, err2 := ParseWindowsIPConfigDNS("", "", nil)
	if err2 == nil {
		t.Fatal("expected error on empty ipconfig output, got nil")
	}
}

func TestWindowsDNS_NeverFabricatesFallback(t *testing.T) {
	// Verify that under all failure conditions, neither 1.1.1.1 nor 8.8.8.8 are returned
	checkNoFallback := func(servers []string, err error) {
		for _, s := range servers {
			if s == "1.1.1.1" || s == "8.8.8.8" {
				t.Fatalf("detected fabricated fallback DNS server %s!", s)
			}
		}
	}

	s1, e1 := ParseWindowsIPConfigDNS(sampleIPConfigMultiInterface, "NonExistent", nil)
	checkNoFallback(s1, e1)

	s2, e2 := ParseWindowsIPConfigDNS(sampleIPConfigMultiInterface, "vEthernet (WSL)", nil)
	checkNoFallback(s2, e2)

	s3, e3 := ParseWindowsIPConfigDNS("Random string", "", nil)
	checkNoFallback(s3, e3)
}

func TestWindowsDNS_NetshParser(t *testing.T) {
	v4Out := `
Configuration for interface "Ethernet"
    DNS servers configured through DHCP:  192.168.1.1
                                          192.168.1.254
    Register with which suffix:           Primary only

Configuration for interface "Wi-Fi"
    Statically Configured DNS Servers:    10.0.0.1
    Register with which suffix:           Primary only
`
	v6Out := `
Configuration for interface "Ethernet"
    DNS servers configured through DHCP:  2001:4860:4860::8888
    Register with which suffix:           Primary only
`
	servers, err := ParseWindowsNetshDNS(v4Out, v6Out, "Ethernet")
	if err != nil {
		t.Fatalf("expected netsh parse success, got: %v", err)
	}

	expected := []string{"192.168.1.1", "192.168.1.254", "2001:4860:4860::8888"}
	if len(servers) != len(expected) {
		t.Fatalf("expected %d netsh servers, got %d: %v", len(expected), len(servers), servers)
	}

	for i, exp := range expected {
		if servers[i] != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, servers[i])
		}
	}
}
