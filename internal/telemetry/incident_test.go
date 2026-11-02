package telemetry

import (
	"strings"
	"testing"
	"time"

	"argus/internal/dhcp"
)

func TestIncidentTrackerDebouncingAndRecovery(t *testing.T) {
	tracker := NewIncidentTracker()

	// Initial healthy status
	sHealthy := PipelineStatus{
		LinkOK:       true,
		GatewayOK:    true,
		GatewayState: "REACHABLE",
		GatewayIP:    "192.168.1.1",
		GatewayMAC:   "00:11:22:33:44:55",
		DNSOK:        true,
		InternetOK:   true,
		InternetRTT:  20 * time.Millisecond,
	}

	events := tracker.ProcessSample(sHealthy)
	if len(events) != 0 {
		t.Errorf("Expected 0 events on baseline sample, got: %v", events)
	}

	// First failure: should be debounced (no event yet because failureThreshold = 2)
	sFail1 := sHealthy
	sFail1.GatewayOK = false
	sFail1.GatewayState = "UNREACHABLE"
	events = tracker.ProcessSample(sFail1)
	if len(events) != 0 {
		t.Errorf("Expected 0 events on first failure due to debounce, got: %v", events)
	}

	// Second consecutive failure: outage declared
	events = tracker.ProcessSample(sFail1)
	if len(events) != 1 || !strings.Contains(events[0], "[CRIT] Default Gateway unreachable") {
		t.Errorf("Expected critical gateway outage event on 2nd consecutive failure, got: %v", events)
	}

	// Third consecutive failure: must NOT emit duplicate outage event
	events = tracker.ProcessSample(sFail1)
	if len(events) != 0 {
		t.Errorf("Expected 0 events on subsequent failure (no spam), got: %v", events)
	}

	// Recovery sample after outage
	time.Sleep(10 * time.Millisecond) // Ensure non-zero duration
	events = tracker.ProcessSample(sHealthy)
	if len(events) != 1 || !strings.Contains(events[0], "[RECOV] Default Gateway connectivity restored") {
		t.Errorf("Expected recovery event upon restoration, got: %v", events)
	}
}

func TestIncidentTrackerGatewayState_InconclusiveDoesNotIncrementOutage(t *testing.T) {
	tracker := NewIncidentTracker()

	sInconclusive := PipelineStatus{
		LinkOK:       true,
		GatewayOK:    false,
		GatewayState: "INCONCLUSIVE",
		GatewayIP:    "192.168.1.1",
		DNSOK:        true,
		InternetOK:   true,
	}

	// Send 5 consecutive INCONCLUSIVE samples.
	// Must NOT declare a gateway outage!
	for i := 0; i < 5; i++ {
		events := tracker.ProcessSample(sInconclusive)
		if len(events) > 0 {
			t.Fatalf("Inconclusive gateway state must NOT trigger outage event: %v", events)
		}
	}
}

func TestIncidentTrackerGatewayState_UnavailableDoesNotIncrementOutage(t *testing.T) {
	tracker := NewIncidentTracker()

	sUnavailable := PipelineStatus{
		LinkOK:       true,
		GatewayOK:    false,
		GatewayState: "UNAVAILABLE",
		DNSOK:        true,
		InternetOK:   true,
	}

	// Send 5 consecutive UNAVAILABLE samples.
	// Must NOT declare a gateway outage!
	for i := 0; i < 5; i++ {
		events := tracker.ProcessSample(sUnavailable)
		if len(events) > 0 {
			t.Fatalf("Unavailable gateway state must NOT trigger outage event: %v", events)
		}
	}
}

func TestIncidentTrackerGatewayState_InconclusiveDoesNotRecoverActiveOutage(t *testing.T) {
	tracker := NewIncidentTracker()

	sFail := PipelineStatus{
		GatewayOK:    false,
		GatewayState: "UNREACHABLE",
		GatewayIP:    "192.168.1.1",
		DNSOK:        true,
		InternetOK:   true,
	}

	// Trigger outage (2 consecutive UNREACHABLE samples)
	tracker.ProcessSample(sFail)
	events := tracker.ProcessSample(sFail)
	if len(events) != 1 || !strings.Contains(events[0], "[CRIT] Default Gateway unreachable") {
		t.Fatalf("Expected outage on 2nd failure, got: %v", events)
	}

	// Subsequent INCONCLUSIVE samples: must NOT mark recovered!
	sInconclusive := PipelineStatus{
		GatewayOK:    false,
		GatewayState: "INCONCLUSIVE",
		GatewayIP:    "192.168.1.1",
		DNSOK:        true,
		InternetOK:   true,
	}
	for i := 0; i < 3; i++ {
		evs := tracker.ProcessSample(sInconclusive)
		if len(evs) > 0 {
			t.Fatalf("INCONCLUSIVE state must not falsely recover active outage or emit events: %v", evs)
		}
	}

	// Finally, a verified REACHABLE sample arrives: should recover cleanly
	sReachable := PipelineStatus{
		GatewayOK:    true,
		GatewayState: "REACHABLE",
		GatewayIP:    "192.168.1.1",
		DNSOK:        true,
		InternetOK:   true,
	}
	recovEvents := tracker.ProcessSample(sReachable)
	if len(recovEvents) != 1 || !strings.Contains(recovEvents[0], "[RECOV]") {
		t.Fatalf("Expected [RECOV] event upon verified REACHABLE state, got: %v", recovEvents)
	}
}

func TestIncidentTrackerGatewayDrift(t *testing.T) {
	tracker := NewIncidentTracker()

	s1 := PipelineStatus{
		GatewayOK:    true,
		GatewayState: "REACHABLE",
		GatewayIP:    "192.168.1.1",
		GatewayMAC:   "00:11:22:33:44:55",
		DNSOK:        true,
		InternetOK:   true,
	}
	tracker.ProcessSample(s1)

	// MAC address changes (potential ARP spoofing or device swap)
	sDrift := s1
	sDrift.GatewayMAC = "AA:BB:CC:DD:EE:FF"
	events := tracker.ProcessSample(sDrift)

	foundDrift := false
	for _, ev := range events {
		if strings.Contains(ev, "[CRIT] Gateway MAC drifted") {
			foundDrift = true
			break
		}
	}
	if !foundDrift {
		t.Errorf("Expected gateway MAC drift alert, got: %v", events)
	}
}

func TestIncidentTrackerSustainedLatency(t *testing.T) {
	tracker := NewIncidentTracker()

	sHighLatency := PipelineStatus{
		GatewayOK:    true,
		GatewayState: "REACHABLE",
		DNSOK:        true,
		InternetOK:   true,
		InternetRTT:  250 * time.Millisecond,
	}

	// Streak 1
	events := tracker.ProcessSample(sHighLatency)
	if len(events) != 0 {
		t.Errorf("Did not expect alert on sample 1: %v", events)
	}

	// Streak 2
	events = tracker.ProcessSample(sHighLatency)
	if len(events) != 0 {
		t.Errorf("Did not expect alert on sample 2: %v", events)
	}

	// Streak 3: Alert triggered
	events = tracker.ProcessSample(sHighLatency)
	if len(events) != 1 || !strings.Contains(events[0], "Sustained high latency") {
		t.Errorf("Expected sustained high latency alert on 3rd sample, got: %v", events)
	}

	// Recovery back to low latency
	sNormal := sHighLatency
	sNormal.InternetRTT = 30 * time.Millisecond
	events = tracker.ProcessSample(sNormal)
	if len(events) != 1 || !strings.Contains(events[0], "[RECOV] External latency normalized") {
		t.Errorf("Expected latency normalized recovery event, got: %v", events)
	}
}

func TestIncidentTrackerConfigChange_TemporalCorrelationNotice(t *testing.T) {
	tracker := NewIncidentTracker()

	// Record a config change occurring now
	tracker.RecordConfigChange(dhcp.ConfigChange{
		Kind:          dhcp.ChangeDHCPServerChanged,
		InterfaceName: "eth0",
		FieldName:     "DHCPServerIP",
		OldValue:      "192.168.1.1",
		NewValue:      "192.168.68.1",
		Summary:       "DHCP server IP shifted from 192.168.1.1 to 192.168.68.1",
		Implication:   "Potential secondary router or subnet drift",
		Timestamp:     time.Now(),
	})

	recent := tracker.RecentConfigChanges()
	if len(recent) != 1 {
		t.Fatalf("expected 1 recent config change, got %d", len(recent))
	}

	// Trigger external internet outage while gateway is OK
	sOutage := PipelineStatus{
		GatewayOK:    true,
		GatewayState: "REACHABLE",
		GatewayIP:    "192.168.68.1",
		DNSOK:        true,
		InternetOK:   false,
	}

	tracker.ProcessSample(sOutage)
	events := tracker.ProcessSample(sOutage) // 2nd sample triggers threshold

	if len(events) != 1 {
		t.Fatalf("expected 1 outage event, got %v", events)
	}

	ev := events[0]
	if !strings.Contains(ev, "[CRIT] External internet connectivity lost") {
		t.Errorf("expected external internet connectivity lost in message: %s", ev)
	}
	if !strings.Contains(ev, "temporal correlation does not prove causation") {
		t.Errorf("expected temporal correlation notice in outage message: %s", ev)
	}
	if !strings.Contains(ev, "DHCP server IP shifted") {
		t.Errorf("expected config change summary mentioned in outage notice: %s", ev)
	}
}

