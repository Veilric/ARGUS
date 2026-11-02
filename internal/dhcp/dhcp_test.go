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
	cfg, err := ParseNMCLI(sampleNMCLIWithDHCP, "eth0")
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
		InterfaceName: "eth0",
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

	b2, ok := store2.Get("eth0")
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

// Priority 2 Test A: Multi-interface dhclient lease file attributes correctly to the requested interface.
func TestDHCP_MultiInterfaceLease_Attribution(t *testing.T) {
	multiLease := `
lease {
  interface "eth0";
  fixed-address 192.168.1.10;
  option routers 192.168.1.1;
  option dhcp-server-identifier 192.168.1.1;
  expire 2 2030/01/01 00:00:00;
}
lease {
  interface "eth1";
  fixed-address 10.0.0.20;
  option routers 10.0.0.1;
  option dhcp-server-identifier 10.0.0.1;
  expire 2 2030/01/01 00:00:00;
}
`
	// Target eth0
	cfg0, err := ParseDHClientLease(multiLease, "eth0")
	if err != nil || cfg0 == nil {
		t.Fatalf("failed to parse eth0 lease: %v", err)
	}
	if cfg0.InterfaceName != "eth0" || cfg0.IPv4Address != "192.168.1.10" {
		t.Errorf("expected eth0 192.168.1.10, got %s %s", cfg0.InterfaceName, cfg0.IPv4Address)
	}

	// Target eth1
	cfg1, err := ParseDHClientLease(multiLease, "eth1")
	if err != nil || cfg1 == nil {
		t.Fatalf("failed to parse eth1 lease: %v", err)
	}
	if cfg1.InterfaceName != "eth1" || cfg1.IPv4Address != "10.0.0.20" {
		t.Errorf("expected eth1 10.0.0.20, got %s %s", cfg1.InterfaceName, cfg1.IPv4Address)
	}

	// Target non-existent wlan0
	cfgNone, err := ParseDHClientLease(multiLease, "wlan0")
	if err != nil {
		t.Fatalf("unexpected error for wlan0: %v", err)
	}
	if cfgNone != nil {
		t.Errorf("expected nil config for unmentioned interface wlan0, got: %+v", cfgNone)
	}
}

// Priority 2 Test B: Expired DHCP leases are rejected and never presented as active.
func TestDHCP_ExpiredLease_Rejected(t *testing.T) {
	expiredDHClient := `
lease {
  interface "eth0";
  fixed-address 192.168.1.150;
  option routers 192.168.1.1;
  option dhcp-server-identifier 192.168.1.1;
  expire 2 2020/01/01 00:00:00;
}
`
	cfg, err := ParseDHClientLease(expiredDHClient, "eth0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expired dhclient lease must be rejected, got: %+v", cfg)
	}
}

// Priority 3 Test A: Repeated unchanged observations do not rewrite baseline file on disk.
func TestDHCP_ReduceDiskWrites_NoChurnOnUnchangedObservations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, err := NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	cfg := &DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "192.168.1.100",
		Assignment:    AssignmentDHCP,
		GatewayIP:     "192.168.1.1",
	}

	_, err = store.EstablishInitial(cfg)
	if err != nil {
		t.Fatalf("failed to establish initial baseline: %v", err)
	}

	fiBefore, _ := os.Stat(dbPath)
	modBefore := fiBefore.ModTime()

	// Simulate 100 consecutive heartbeat checks (every 1.5s)
	for i := 0; i < 100; i++ {
		err := store.TouchLastSeen("eth0", time.Now())
		if err != nil {
			t.Fatalf("TouchLastSeen failed: %v", err)
		}
	}

	// File on disk must NOT have been rewritten!
	fiAfter, _ := os.Stat(dbPath)
	if !fiAfter.ModTime().Equal(modBefore) {
		t.Errorf("baseline file was rewritten during routine unchanged observations! ModTime changed from %v to %v", modBefore, fiAfter.ModTime())
	}
	if !store.IsDirty() {
		t.Errorf("expected store to be dirty in memory")
	}

	// Explicit Flush writes to disk
	err = store.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	fiFlushed, _ := os.Stat(dbPath)
	if fiFlushed.ModTime().Before(modBefore) {
		t.Errorf("Flush did not commit to disk")
	}
	if store.IsDirty() {
		t.Errorf("store should not be dirty after Flush")
	}
}

// Priority 3 Test B: Confirmed refresh persists immediately and creates a backup file.
func TestDHCP_ConfirmedRefresh_PersistsImmediatelyWithBackup(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, _ := NewBaselineStore(dbPath)

	initialCfg := &DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "192.168.1.100",
		GatewayIP:     "192.168.1.1",
	}
	_, _ = store.EstablishInitial(initialCfg)

	// User confirmed refresh with new network
	newCfg := &DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "10.0.0.50",
		GatewayIP:     "10.0.0.1",
	}
	b, err := store.EstablishConfirmed(newCfg)
	if err != nil {
		t.Fatalf("EstablishConfirmed failed: %v", err)
	}
	if b.Type != BaselineUserConfirmed {
		t.Errorf("expected type %s, got %s", BaselineUserConfirmed, b.Type)
	}

	// Backup file must exist and contain previous baseline
	bakPath := dbPath + ".bak"
	bakData, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("failed to read backup file %s: %v", bakPath, err)
	}
	if !strings.Contains(string(bakData), "192.168.1.1") {
		t.Errorf("backup file did not contain original baseline IP: %s", string(bakData))
	}

	// Active file must contain new baseline
	activeData, _ := os.ReadFile(dbPath)
	if !strings.Contains(string(activeData), "10.0.0.1") {
		t.Errorf("active file did not contain new baseline IP: %s", string(activeData))
	}
}

// Priority 3 Test C: Checkpoint timing enforces periodic persistence.
func TestDHCP_CheckpointFlush_IntervalEnforced(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, _ := NewBaselineStore(dbPath)
	store.SetCheckpointInterval(50 * time.Millisecond)

	cfg := &DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "192.168.1.100",
	}
	_, _ = store.EstablishInitial(cfg)

	fiBefore, _ := os.Stat(dbPath)
	modBefore := fiBefore.ModTime()

	// Wait past checkpoint interval
	time.Sleep(60 * time.Millisecond)

	_ = store.TouchLastSeen("eth0", time.Now())

	fiAfter, _ := os.Stat(dbPath)
	if fiAfter.ModTime().Equal(modBefore) {
		t.Errorf("checkpoint flush did not commit to disk after interval elapsed")
	}
}

// Priority 3 Test D: Legacy baselines without 'type' default to INITIAL_OBSERVED on load.
func TestDHCP_LegacyBaselineCompatibility_DefaultsToInitialObserved(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")

	// Write legacy JSON without "type" field
	legacyJSON := `{
  "eth0": {
    "interface_name": "eth0",
    "ipv4_address": "192.168.1.100",
    "gateway_ip": "192.168.1.1",
    "established_at": "2026-11-02T10:00:00Z",
    "last_seen_at": "2026-11-02T10:00:00Z"
  }
}`
	if err := os.WriteFile(dbPath, []byte(legacyJSON), 0644); err != nil {
		t.Fatalf("failed to write legacy JSON: %v", err)
	}

	store, err := NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to load legacy store: %v", err)
	}

	b, ok := store.Get("eth0")
	if !ok || b == nil {
		t.Fatalf("failed to retrieve loaded baseline")
	}
	if b.Type != BaselineInitialObserved {
		t.Errorf("expected legacy baseline to default to %s, got %s", BaselineInitialObserved, b.Type)
	}
	if b.IPv4Address != "192.168.1.100" || b.GatewayIP != "192.168.1.1" {
		t.Errorf("loaded data mismatch: %+v", b)
	}
}

// Priority 4 Test: Full state machine for recurring configuration changes:
// A -> B (drift alert), B -> B (suppress), B -> A (restoration event), subsequent A -> B (recurrence alert).
func TestDHCP_RecurringConfigurationChanges_FullStateMachine(t *testing.T) {
	tracker := NewChangeTracker()

	baseline := &ConfigBaseline{
		InterfaceName: "eth0",
		GatewayIP:     "192.168.1.1",
		IPv4Address:   "192.168.1.100",
		IPv4Prefix:    24,
	}

	// 1. Initial drift: Gateway changes from 192.168.1.1 -> 192.168.1.254 (A -> B)
	currentB := &DHCPConfig{
		InterfaceName: "eth0",
		GatewayIP:     "192.168.1.254",
		IPv4Address:   "192.168.1.100",
		IPv4Prefix:    24,
		ObservedAt:    time.Now(),
	}

	events1 := tracker.Track(baseline, currentB)
	if len(events1) != 1 {
		t.Fatalf("Cycle 1 (A -> B): expected 1 event, got %d", len(events1))
	}
	if events1[0].Kind != ChangeGatewayChanged || events1[0].NewValue != "192.168.1.254" {
		t.Errorf("Cycle 1: unexpected event: %+v", events1[0])
	}

	// 2. Duplicate observation: Gateway remains 192.168.1.254 (B -> B)
	events2 := tracker.Track(baseline, currentB)
	if len(events2) != 0 {
		t.Fatalf("Cycle 2 (B -> B): expected 0 events (duplicate suppressed), got %d", len(events2))
	}

	// 3. Temporarily unavailable observation: Gateway is empty ""
	currentEmpty := &DHCPConfig{
		InterfaceName: "eth0",
		GatewayIP:     "", // transient failure / unavailable
		IPv4Address:   "192.168.1.100",
		IPv4Prefix:    24,
		ObservedAt:    time.Now(),
	}
	events3 := tracker.Track(baseline, currentEmpty)
	if len(events3) != 0 {
		t.Fatalf("Cycle 3 (Unavailable data): must NOT emit events or invent restoration, got %d", len(events3))
	}

	// 4. Return to baseline: Gateway restored to 192.168.1.1 (B -> A)
	currentA := &DHCPConfig{
		InterfaceName: "eth0",
		GatewayIP:     "192.168.1.1",
		IPv4Address:   "192.168.1.100",
		IPv4Prefix:    24,
		ObservedAt:    time.Now(),
	}
	events4 := tracker.Track(baseline, currentA)
	if len(events4) != 1 {
		t.Fatalf("Cycle 4 (B -> A): expected 1 restoration event, got %d", len(events4))
	}
	if events4[0].Kind != ChangeRestored {
		t.Errorf("Cycle 4: expected ChangeRestored, got: %s", events4[0].Kind)
	}
	if !strings.Contains(events4[0].Summary, "restored to baseline value") {
		t.Errorf("Cycle 4: expected restoration summary, got: %s", events4[0].Summary)
	}

	// 5. Baseline remains stable: Gateway remains 192.168.1.1 (A -> A)
	events5 := tracker.Track(baseline, currentA)
	if len(events5) != 0 {
		t.Fatalf("Cycle 5 (A -> A): expected 0 events, got %d", len(events5))
	}

	// 6. Recurrence: Gateway drifts to 192.168.1.254 AGAIN! (A -> B recurrence)
	events6 := tracker.Track(baseline, currentB)
	if len(events6) != 1 {
		t.Fatalf("Cycle 6 (A -> B recurrence): expected 1 new drift event, got %d (was it suppressed by stale state?)", len(events6))
	}
	if events6[0].Kind != ChangeGatewayChanged || events6[0].NewValue != "192.168.1.254" {
		t.Errorf("Cycle 6: unexpected event: %+v", events6[0])
	}
}

// Data Integrity Test 1: Backup failure must block baseline overwrite and preserve previous baseline.
func TestDHCP_BackupFailure_BlocksBaselineOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, err := NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create baseline store: %v", err)
	}

	initialCfg := &DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "192.168.1.100",
		GatewayIP:     "192.168.1.1",
	}
	_, err = store.EstablishInitial(initialCfg)
	if err != nil {
		t.Fatalf("EstablishInitial failed: %v", err)
	}

	// Create an un-writable directory in place of the backup file path to force backup failure
	bakPath := dbPath + ".bak"
	if err := os.Mkdir(bakPath, 0000); err != nil {
		t.Fatalf("failed to create unwritable backup path: %v", err)
	}
	defer os.RemoveAll(bakPath)

	newCfg := &DHCPConfig{
		InterfaceName: "eth0",
		IPv4Address:   "10.0.0.99",
		GatewayIP:     "10.0.0.1",
	}

	// Attempt to overwrite baseline when backup is guaranteed to fail
	b, err := store.EstablishConfirmed(newCfg)
	if err == nil {
		t.Fatalf("EstablishConfirmed must fail when backup creation fails, but got success: %+v", b)
	}
	if !strings.Contains(err.Error(), "backup creation failed") {
		t.Errorf("expected 'backup creation failed' in error, got: %v", err)
	}

	// Verify in-memory baseline was preserved
	cur, ok := store.Get("eth0")
	if !ok || cur.GatewayIP != "192.168.1.1" {
		t.Errorf("in-memory baseline was corrupted or overwritten on backup failure: %+v", cur)
	}

	// Verify on-disk baseline was preserved
	data, _ := os.ReadFile(dbPath)
	if !strings.Contains(string(data), "192.168.1.1") || strings.Contains(string(data), "10.0.0.99") {
		t.Errorf("on-disk baseline was overwritten despite backup failure: %s", string(data))
	}
}

// Data Integrity Test 2: Repeated parsing of unchanged systemd-networkd lease does not advance expiration.
func TestDHCP_SystemdNetworkd_RepeatedParsingDoesNotRefreshExpiration(t *testing.T) {
	leaseContent := `
ADDRESS=192.168.10.88
NETMASK=255.255.255.0
ROUTER=192.168.10.1
SERVER_ADDRESS=192.168.10.1
LIFETIME=3600
`
	// Fixed acquisition time 30 minutes in the past
	acquiredAt := time.Now().Add(-1800 * time.Second)

	cfg1, err := ParseSystemdNetworkdLeaseWithAcquisition(leaseContent, "eth0", acquiredAt)
	if err != nil || cfg1 == nil {
		t.Fatalf("first parse failed: %v", err)
	}
	if cfg1.LeaseExpires == nil {
		t.Fatalf("expected LeaseExpires to be calculated from acquisition timestamp")
	}

	// Sleep slightly to simulate later inspection
	time.Sleep(30 * time.Millisecond)

	cfg2, err := ParseSystemdNetworkdLeaseWithAcquisition(leaseContent, "eth0", acquiredAt)
	if err != nil || cfg2 == nil {
		t.Fatalf("second parse failed: %v", err)
	}
	if cfg2.LeaseExpires == nil {
		t.Fatalf("second parse missing LeaseExpires")
	}

	// Expiration MUST be anchored to acquiredAt and identical across repeated reads
	if !cfg1.LeaseExpires.Equal(*cfg2.LeaseExpires) {
		t.Errorf("immortality bug: expiration advanced merely by rereading file! cfg1: %v, cfg2: %v",
			cfg1.LeaseExpires, cfg2.LeaseExpires)
	}
}

// Data Integrity Test 3: Systemd-networkd lease with past expiration is rejected as expired.
func TestDHCP_SystemdNetworkd_ExpiredLeaseRejected(t *testing.T) {
	leaseContent := `
ADDRESS=192.168.10.88
NETMASK=255.255.255.0
ROUTER=192.168.10.1
SERVER_ADDRESS=192.168.10.1
LIFETIME=1800
`
	// Acquired 2 hours ago with 30-min lifetime -> expired 1.5 hours ago
	acquiredAt := time.Now().Add(-7200 * time.Second)

	cfg, err := ParseSystemdNetworkdLeaseWithAcquisition(leaseContent, "eth0", acquiredAt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expired systemd-networkd lease must be rejected, got: %+v", cfg)
	}
}

// Data Integrity Test 4: Unverified lease age is explicitly qualified when acquisition time is unavailable.
func TestDHCP_SystemdNetworkd_UnverifiedLeaseAgeQualified(t *testing.T) {
	leaseContent := `
ADDRESS=192.168.10.88
NETMASK=255.255.255.0
ROUTER=192.168.10.1
SERVER_ADDRESS=192.168.10.1
LIFETIME=1800
`
	// Zero time (no acquisition timestamp known)
	cfg, err := ParseSystemdNetworkdLease(leaseContent, "eth0")
	if err != nil || cfg == nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Must NOT invent an expiration relative to now!
	if cfg.LeaseExpires != nil {
		t.Errorf("expected nil LeaseExpires for unverified lease age, got: %v", cfg.LeaseExpires)
	}
	if !strings.Contains(cfg.Source, "unverified lease age") {
		t.Errorf("expected source to qualify unverified lease age, got: %s", cfg.Source)
	}
}

// Data Integrity Test 5: Persistence rollback when backup succeeds but temporary baseline file creation fails.
// Existing baseline must remain unchanged in memory and on disk, and subsequent retry must work normally.
func TestDHCP_PersistenceRollback_BackupSucceeds_SaveFails(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, err := NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create baseline store: %v", err)
	}

	initialCfg := &DHCPConfig{
		InterfaceName: "eth0",
		MACAddress:    "00:11:22:33:44:01",
		IPv4Address:   "192.168.1.100",
		IPv4Prefix:    24,
		Assignment:    AssignmentDHCP,
		GatewayIP:     "192.168.1.1",
		DNSServers:    []string{"192.168.1.1"},
		DHCPServerIP:  "192.168.1.1",
	}

	origB, err := store.EstablishConfirmed(initialCfg)
	if err != nil {
		t.Fatalf("failed to establish initial confirmed baseline: %v", err)
	}

	// Block temporary file creation by creating baselines.json.tmp as a non-empty directory
	tmpPath := dbPath + ".tmp"
	if err := os.Mkdir(tmpPath, 0755); err != nil {
		t.Fatalf("failed to create blocking directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpPath, "blocker"), []byte("blocked"), 0644); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	newCfg := &DHCPConfig{
		InterfaceName: "eth0",
		MACAddress:    "00:11:22:33:44:01",
		IPv4Address:   "192.168.1.200",
		IPv4Prefix:    24,
		Assignment:    AssignmentDHCP,
		GatewayIP:     "192.168.1.254",
		DNSServers:    []string{"192.168.1.254"},
		DHCPServerIP:  "192.168.1.254",
	}

	// 1. Attempt to confirm new baseline: save must fail
	b, err := store.EstablishConfirmed(newCfg)
	if err == nil {
		t.Fatalf("EstablishConfirmed must fail when temporary baseline write fails, but succeeded: %+v", b)
	}
	if b != nil {
		t.Fatalf("EstablishConfirmed must return nil baseline on failure, got: %+v", b)
	}

	// 2. Backup must have succeeded
	bakPath := dbPath + ".bak"
	if _, err := os.Stat(bakPath); err != nil {
		t.Errorf("backup file %s should exist after successful backup: %v", bakPath, err)
	}

	// 3. In-memory baseline must remain unchanged (rolled back to original)
	memB, ok := store.Get("eth0")
	if !ok || memB == nil {
		t.Fatalf("baseline disappeared from memory after rollback")
	}
	if memB.IPv4Address != origB.IPv4Address || memB.GatewayIP != origB.GatewayIP {
		t.Errorf("in-memory baseline was corrupted: expected IP %s GW %s, got IP %s GW %s",
			origB.IPv4Address, origB.GatewayIP, memB.IPv4Address, memB.GatewayIP)
	}
	if store.IsDirty() {
		t.Errorf("store dirty flag was not restored on rollback")
	}

	// 4. On-disk baseline must remain unchanged
	diskBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("failed to read disk baseline: %v", err)
	}
	if !strings.Contains(string(diskBytes), "192.168.1.100") || strings.Contains(string(diskBytes), "192.168.1.200") {
		t.Errorf("on-disk baseline file was modified despite save failure: %s", string(diskBytes))
	}

	// 5. Subsequent retry after clearing obstruction must succeed
	if err := os.RemoveAll(tmpPath); err != nil {
		t.Fatalf("failed to remove blocking tmp directory: %v", err)
	}

	retryB, err := store.EstablishConfirmed(newCfg)
	if err != nil {
		t.Fatalf("retry EstablishConfirmed failed after unblocking: %v", err)
	}
	if retryB == nil || retryB.IPv4Address != "192.168.1.200" || retryB.GatewayIP != "192.168.1.254" {
		t.Errorf("retry baseline has wrong values: %+v", retryB)
	}

	// Verify in-memory and on-disk after successful retry
	memAfter, ok := store.Get("eth0")
	if !ok || memAfter.IPv4Address != "192.168.1.200" {
		t.Errorf("in-memory baseline not updated after retry: %+v", memAfter)
	}
	diskAfter, _ := os.ReadFile(dbPath)
	if !strings.Contains(string(diskAfter), "192.168.1.200") {
		t.Errorf("on-disk baseline not updated after retry: %s", string(diskAfter))
	}
}

// Data Integrity Test 6: A newly created baseline does not remain in memory when its first save fails.
func TestDHCP_PersistenceRollback_InitialSaveFails_NoMemoryLeak(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")

	// Pre-create blocking tmp directory with a file inside it
	tmpPath := dbPath + ".tmp"
	if err := os.Mkdir(tmpPath, 0755); err != nil {
		t.Fatalf("failed to create blocking directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpPath, "blocker"), []byte("blocked"), 0644); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	store, err := NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create baseline store: %v", err)
	}

	cfg := &DHCPConfig{
		InterfaceName: "eth0",
		MACAddress:    "00:11:22:33:44:02",
		IPv4Address:   "10.10.10.50",
		IPv4Prefix:    24,
		Assignment:    AssignmentDHCP,
		GatewayIP:     "10.10.10.1",
	}

	// 1. EstablishInitial fails because persistence fails
	b, err := store.EstablishInitial(cfg)
	if err == nil {
		t.Fatalf("expected EstablishInitial to fail when persistence fails")
	}
	if b != nil {
		t.Fatalf("expected nil baseline on failure, got: %+v", b)
	}

	// In-memory baseline MUST NOT exist!
	memB, ok := store.Get("eth0")
	if ok || memB != nil {
		t.Errorf("new baseline leaked into memory despite save failure: %+v", memB)
	}
	if store.IsDirty() {
		t.Errorf("store dirty flag was not restored to clean")
	}

	// On disk, baselines.json must NOT exist
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("baseline file should not exist on disk: %v", err)
	}

	// 2. Unblock and retry
	if err := os.RemoveAll(tmpPath); err != nil {
		t.Fatalf("failed to remove blocking tmp directory: %v", err)
	}

	retryB, err := store.EstablishInitial(cfg)
	if err != nil {
		t.Fatalf("EstablishInitial failed on retry: %v", err)
	}
	if retryB == nil || retryB.IPv4Address != "10.10.10.50" {
		t.Errorf("retry baseline mismatch: %+v", retryB)
	}

	// In memory and disk must now exist
	memAfter, ok := store.Get("eth0")
	if !ok || memAfter == nil || memAfter.IPv4Address != "10.10.10.50" {
		t.Errorf("baseline missing from memory after successful retry")
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("baseline file missing from disk after successful retry: %v", err)
	}
}

// Data Integrity Test 7: Establish() rolls back in-memory mutation if persistence fails.
func TestDHCP_PersistenceRollback_Establish_ExistingBaselineRollsBack(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "baselines.json")
	store, err := NewBaselineStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create baseline store: %v", err)
	}

	cfgOld := &DHCPConfig{
		InterfaceName: "eth0",
		MACAddress:    "00:11:22:33:44:03",
		IPv4Address:   "172.16.0.10",
		IPv4Prefix:    16,
		Assignment:    AssignmentDHCP,
		GatewayIP:     "172.16.0.1",
	}

	if _, err := store.Establish(cfgOld); err != nil {
		t.Fatalf("initial Establish failed: %v", err)
	}

	// Block temporary file write with a non-empty directory
	tmpPath := dbPath + ".tmp"
	if err := os.Mkdir(tmpPath, 0755); err != nil {
		t.Fatalf("failed to create blocking directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpPath, "blocker"), []byte("blocked"), 0644); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	cfgNew := &DHCPConfig{
		InterfaceName: "eth0",
		MACAddress:    "00:11:22:33:44:03",
		IPv4Address:   "172.16.0.99",
		IPv4Prefix:    16,
		Assignment:    AssignmentDHCP,
		GatewayIP:     "172.16.0.254",
	}

	b, err := store.Establish(cfgNew)
	if err == nil {
		t.Fatalf("expected Establish to fail when save fails")
	}
	if b != nil {
		t.Fatalf("expected nil baseline on failure, got: %+v", b)
	}

	// Memory must be rolled back to old config
	memB, ok := store.Get("eth0")
	if !ok || memB.IPv4Address != "172.16.0.10" {
		t.Errorf("in-memory baseline not rolled back: got %+v", memB)
	}

	// Unblock and retry
	if err := os.RemoveAll(tmpPath); err != nil {
		t.Fatalf("failed to remove blocking tmp directory: %v", err)
	}

	retryB, err := store.Establish(cfgNew)
	if err != nil {
		t.Fatalf("retry Establish failed: %v", err)
	}
	if retryB.IPv4Address != "172.16.0.99" {
		t.Errorf("retry baseline mismatch: %+v", retryB)
	}
}



