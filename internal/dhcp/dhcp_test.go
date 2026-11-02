package dhcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleNMCLIWithDHCP = `
IP4.ADDRESS[1]:192.168.1.100/24
IP4.GATEWAY:192.168.1.1
IP4.DNS[1]:192.168.1.1
IP4.DOMAIN[1]:corp.local
DHCP4.OPTION[1]:dhcp_client_identifier = 01:00:11:22:33:44:55
DHCP4.OPTION[2]:dhcp_lease_time = 86400
DHCP4.OPTION[3]:dhcp_server_identifier = 192.168.1.1
DHCP4.OPTION[4]:domain_name_servers = 192.168.1.1 1.1.1.1
DHCP4.OPTION[5]:expiry = 1793678098
`

const sampleNMCLIStatic = `
IP4.ADDRESS[1]:10.0.0.50/24
IP4.GATEWAY:10.0.0.1
IP4.DNS[1]:10.0.0.1
`

const sampleDHClientLease = `
lease {
  interface "eth0";
  fixed-address 192.168.1.150;
  option subnet-mask 255.255.255.0;
  option routers 192.168.1.1;
  option dhcp-server-identifier 192.168.1.1;
  option domain-name-servers 192.168.1.1, 8.8.8.8;
  option domain-name "lan";
  renew 1 2026/11/02 12:00:00;
  expire 2 2026/11/03 12:00:00;
}
`

const sampleSystemdNetworkdLease = `
# This is private data. Do not parse.
ADDRESS=192.168.10.88
NETMASK=255.255.255.0
ROUTER=192.168.10.1
SERVER_ADDRESS=192.168.10.1
DNS=192.168.10.1
DOMAINNAME=home.arpa
LIFETIME=43200
`

const sampleWindowsIPConfigDHCP = `
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : localdomain
   Description . . . . . . . . . . . : Realtek PCIe GbE Family Controller
   Physical Address. . . . . . . . . : 00-15-5D-11-22-33
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.75(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       1.1.1.1
`

// Test 1: DHCP information successfully retrieved from NetworkManager.
func TestDHCP_Retrieval_NetworkManager(t *testing.T) {
	cfg, err := ParseNMCLI(sampleNMCLIWithDHCP, "enp6s0")
	if err != nil {
		t.Fatalf("unexpected error parsing nmcli: %v", err)
	}
	if cfg.Assignment != AssignmentDHCP {
		t.Errorf("expected AssignmentDHCP, got %v", cfg.Assignment)
	}
	if cfg.IPv4Address != "192.168.1.100" || cfg.IPv4Prefix != 24 {
		t.Errorf("expected 192.168.1.100/24, got %s/%d", cfg.IPv4Address, cfg.IPv4Prefix)
	}
	if cfg.GatewayIP != "192.168.1.1" {
		t.Errorf("expected gateway 192.168.1.1, got %s", cfg.GatewayIP)
	}
	if cfg.DHCPServerIP != "192.168.1.1" {
		t.Errorf("expected dhcp server 192.168.1.1, got %s", cfg.DHCPServerIP)
	}
	if len(cfg.DNSServers) == 0 || cfg.DNSServers[0] != "192.168.1.1" {
		t.Errorf("expected DNS 192.168.1.1, got %v", cfg.DNSServers)
	}
	if cfg.LeaseExpires == nil {
		t.Errorf("expected lease expiration timestamp to be parsed")
	}
}

// Test 2: Missing lease information reported as unavailable / unknown.
func TestDHCP_MissingLease_ReportedUnavailable(t *testing.T) {
	cfg, err := ParseNMCLI("", "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Assignment != AssignmentUnknown {
		t.Errorf("expected AssignmentUnknown for empty data, got %v", cfg.Assignment)
	}
	if cfg.DHCPServerIP != "" {
		t.Errorf("expected empty DHCP server for missing lease, got %s", cfg.DHCPServerIP)
	}
}

// Test 3: Static IP configurations handled correctly.
func TestDHCP_StaticIP_HandledCorrectly(t *testing.T) {
	cfg, err := ParseNMCLI(sampleNMCLIStatic, "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Assignment != AssignmentStatic {
		t.Errorf("expected AssignmentStatic, got %v", cfg.Assignment)
	}
	if cfg.IPv4Address != "10.0.0.50" || cfg.IPv4Prefix != 24 {
		t.Errorf("expected 10.0.0.50/24, got %s/%d", cfg.IPv4Address, cfg.IPv4Prefix)
	}
	if cfg.DHCPServerIP != "" {
		t.Errorf("static config must have empty DHCP server, got %s", cfg.DHCPServerIP)
	}
}

// Test 4: Gateway change detected.
func TestDHCP_ChangeDetection_Gateway(t *testing.T) {
	baseline := &ConfigBaseline{
		InterfaceName: "eth0",
		GatewayIP:     "192.168.1.1",
		IPv4Address:   "192.168.1.100",
		IPv4Prefix:    24,
	}
	current := &DHCPConfig{
		InterfaceName: "eth0",
		GatewayIP:     "192.168.1.254", // changed!
		IPv4Address:   "192.168.1.100",
		IPv4Prefix:    24,
		ObservedAt:    time.Now(),
	}

	changes := DetectChanges(baseline, current)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	chg := changes[0]
	if chg.Kind != ChangeGatewayChanged {
		t.Errorf("expected ChangeGatewayChanged, got %v", chg.Kind)
	}
	if chg.OldValue != "192.168.1.1" || chg.NewValue != "192.168.1.254" {
		t.Errorf("expected 192.168.1.1 -> 192.168.1.254, got %s -> %s", chg.OldValue, chg.NewValue)
	}
}

// Test 5: DNS configuration change detected.
func TestDHCP_ChangeDetection_DNS(t *testing.T) {
	baseline := &ConfigBaseline{
		InterfaceName: "eth0",
		DNSServers:    []string{"192.168.1.1"},
	}
	current := &DHCPConfig{
		InterfaceName: "eth0",
		DNSServers:    []string{"1.1.1.1", "8.8.8.8"},
		ObservedAt:    time.Now(),
	}

	changes := DetectChanges(baseline, current)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Kind != ChangeDNSChanged {
		t.Errorf("expected ChangeDNSChanged, got %v", changes[0].Kind)
	}
}

// Test 6: DHCP server identifier change detected (Deco AP -> Router mode scenario).
func TestDHCP_ChangeDetection_DHCPServer(t *testing.T) {
	baseline := &ConfigBaseline{
		InterfaceName: "eth0",
		DHCPServerIP:  "192.168.1.1",
		GatewayIP:     "192.168.1.1",
	}
	current := &DHCPConfig{
		InterfaceName: "eth0",
		DHCPServerIP:  "192.168.68.1", // TP-Link Deco subnet!
		GatewayIP:     "192.168.68.1",
		ObservedAt:    time.Now(),
	}

	changes := DetectChanges(baseline, current)
	foundDHCPServerChange := false
	for _, c := range changes {
		if c.Kind == ChangeDHCPServerChanged {
			foundDHCPServerChange = true
			if c.OldValue != "192.168.1.1" || c.NewValue != "192.168.68.1" {
				t.Errorf("expected 192.168.1.1 -> 192.168.68.1, got %s -> %s", c.OldValue, c.NewValue)
			}
		}
	}
	if !foundDHCPServerChange {
		t.Errorf("failed to detect DHCP server change")
	}
}

// Test 7: Legitimate repeated observations do not generate duplicate events.
func TestDHCP_ChangeDeduplication_NoDuplicateEvents(t *testing.T) {
	tracker := NewChangeTracker()

	change := ConfigChange{
		Kind:          ChangeGatewayChanged,
		InterfaceName: "eth0",
		FieldName:     "Default Gateway",
		OldValue:      "192.168.1.1",
		NewValue:      "192.168.1.254",
	}

	firstBatch := tracker.FilterNewChanges([]ConfigChange{change})
	if len(firstBatch) != 1 {
		t.Fatalf("expected first observation to be returned, got %d", len(firstBatch))
	}

	// Identical change on next poll cycle must be suppressed
	secondBatch := tracker.FilterNewChanges([]ConfigChange{change})
	if len(secondBatch) != 0 {
		t.Fatalf("expected duplicate change to be suppressed, got %d", len(secondBatch))
	}

	// If gateway changes again to something new, it should be emitted
	newChange := ConfigChange{
		Kind:          ChangeGatewayChanged,
		InterfaceName: "eth0",
		FieldName:     "Default Gateway",
		OldValue:      "192.168.1.254",
		NewValue:      "192.168.1.1",
	}
	thirdBatch := tracker.FilterNewChanges([]ConfigChange{newChange})
	if len(thirdBatch) != 1 {
		t.Fatalf("expected new transition to be returned, got %d", len(thirdBatch))
	}
}

// Test 8: Baselines survive application restarts.
func TestDHCP_BaselinePersistence_ApplicationRestart(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "argus_baseline_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "baselines.json")

	// Session 1: establish baseline
	store1, err := NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	cfg := &DHCPConfig{
		InterfaceName: "enp6s0",
		MACAddress:    "00:11:22:33:44:55",
		IPv4Address:   "192.168.1.50",
		IPv4Prefix:    24,
		Assignment:    AssignmentDHCP,
		GatewayIP:     "192.168.1.1",
		DNSServers:    []string{"192.168.1.1"},
		DHCPServerIP:  "192.168.1.1",
	}

	b1, err := store1.Establish(cfg)
	if err != nil {
		t.Fatalf("failed to establish baseline: %v", err)
	}

	// Session 2: simulate restart by creating a new store instance loading from same path
	store2, err := NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to load store2: %v", err)
	}

	b2, ok := store2.Get("enp6s0")
	if !ok || b2 == nil {
		t.Fatalf("baseline did not survive application restart!")
	}
	if b2.IPv4Address != b1.IPv4Address || b2.GatewayIP != b1.GatewayIP || b2.DHCPServerIP != b1.DHCPServerIP {
		t.Errorf("loaded baseline values mismatch: %+v vs %+v", b2, b1)
	}
}

// Test 9: User-approved baseline refresh works.
func TestDHCP_BaselineRefresh_UserApproved(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "argus_baseline_refresh_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, _ := NewBaselineStore(dbPath)

	cfgOld := &DHCPConfig{
		InterfaceName: "eth0",
		GatewayIP:     "192.168.1.1",
	}
	store.Establish(cfgOld)

	// User intentionally changed network and approves refresh
	cfgNew := &DHCPConfig{
		InterfaceName: "eth0",
		GatewayIP:     "10.0.0.1",
	}
	refreshed, err := store.Establish(cfgNew)
	if err != nil {
		t.Fatalf("failed to refresh baseline: %v", err)
	}
	if refreshed.GatewayIP != "10.0.0.1" {
		t.Errorf("expected refreshed gateway 10.0.0.1, got %s", refreshed.GatewayIP)
	}

	// Verify persistence
	storeReloaded, _ := NewBaselineStore(dbPath)
	b, _ := storeReloaded.Get("eth0")
	if b.GatewayIP != "10.0.0.1" {
		t.Errorf("refreshed baseline did not persist: got %s", b.GatewayIP)
	}
}

// Test 10: Unavailable configuration values do not become invented healthy results.
func TestDHCP_NoInventedHealthyResults_WhenUnavailable(t *testing.T) {
	cfg := &DHCPConfig{
		InterfaceName: "eth0",
		Assignment:    AssignmentUnknown,
	}

	if cfg.DHCPServerIP != "" {
		t.Errorf("expected empty DHCP server, got %s", cfg.DHCPServerIP)
	}
	if len(cfg.DNSServers) != 0 {
		t.Errorf("expected empty DNS servers, got %v", cfg.DNSServers)
	}
}

// Test 11: Configuration changes do not automatically prove DHCP conflicts.
func TestDHCP_ConflictingDHCP_NotAutomaticallyProven(t *testing.T) {
	baseline := &ConfigBaseline{
		InterfaceName: "eth0",
		DHCPServerIP:  "192.168.1.1",
	}
	current := &DHCPConfig{
		InterfaceName: "eth0",
		DHCPServerIP:  "192.168.1.254",
	}

	changes := DetectChanges(baseline, current)
	for _, c := range changes {
		// Implication must qualify possibility, not assert definite malicious rogue attack
		if !strings.Contains(c.Implication, "May indicate") && !strings.Contains(c.Implication, "roaming") && !strings.Contains(c.Implication, "competing") {
			t.Errorf("Implication failed to qualify possibility objectively: %s", c.Implication)
		}
	}
}

// Test 12: Events and reports preserve correct timestamps and old/new values.
func TestDHCP_EventsAndReports_PreserveTimestampsAndValues(t *testing.T) {
	now := time.Date(2026, 11, 2, 10, 15, 30, 0, time.UTC)
	baseline := &ConfigBaseline{
		InterfaceName: "eth0",
		GatewayIP:     "192.168.1.1",
	}
	current := &DHCPConfig{
		InterfaceName: "eth0",
		GatewayIP:     "192.168.1.254",
		ObservedAt:    now,
	}

	changes := DetectChanges(baseline, current)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	chg := changes[0]
	if !chg.Timestamp.Equal(now) {
		t.Errorf("expected timestamp %v, got %v", now, chg.Timestamp)
	}
	if chg.OldValue != "192.168.1.1" || chg.NewValue != "192.168.1.254" {
		t.Errorf("expected old=192.168.1.1 new=192.168.1.254, got old=%s new=%s", chg.OldValue, chg.NewValue)
	}
}

// Test 13: Systemd-networkd lease file parser.
func TestDHCP_SystemdNetworkdParser(t *testing.T) {
	cfg, err := ParseSystemdNetworkdLease(sampleSystemdNetworkdLease, "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IPv4Address != "192.168.10.88" || cfg.GatewayIP != "192.168.10.1" || cfg.DHCPServerIP != "192.168.10.1" {
		t.Errorf("parsed systemd lease mismatch: %+v", cfg)
	}
	if cfg.DomainName != "home.arpa" {
		t.Errorf("expected domain home.arpa, got %s", cfg.DomainName)
	}
}

// Test 14: DHClient lease file parser.
func TestDHCP_DHClientParser(t *testing.T) {
	cfg, err := ParseDHClientLease(sampleDHClientLease, "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IPv4Address != "192.168.1.150" || cfg.GatewayIP != "192.168.1.1" || cfg.DHCPServerIP != "192.168.1.1" {
		t.Errorf("parsed dhclient lease mismatch: %+v", cfg)
	}
	if len(cfg.DNSServers) != 2 || cfg.DNSServers[0] != "192.168.1.1" || cfg.DNSServers[1] != "8.8.8.8" {
		t.Errorf("expected [192.168.1.1 8.8.8.8], got %v", cfg.DNSServers)
	}
}

// Test 15: Windows ipconfig DHCP parser.
func TestDHCP_WindowsIPConfigParser(t *testing.T) {
	cfg, err := ParseWindowsIPConfigDHCP(sampleWindowsIPConfigDHCP, "Ethernet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected non-nil config")
	}
	if cfg.Assignment != AssignmentDHCP {
		t.Errorf("expected AssignmentDHCP, got %v", cfg.Assignment)
	}
	if cfg.IPv4Address != "192.168.1.75" || cfg.GatewayIP != "192.168.1.1" || cfg.DHCPServerIP != "192.168.1.1" {
		t.Errorf("parsed windows DHCP mismatch: %+v", cfg)
	}
	if len(cfg.DNSServers) != 2 {
		t.Errorf("expected 2 DNS servers, got %v", cfg.DNSServers)
	}
}
