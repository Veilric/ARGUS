package telemetry

import (
	"fmt"
	"time"

	"argus/internal/dhcp"
)

// IncidentTracker manages debounced state transitions and recovery tracking.
type IncidentTracker struct {
	failureThreshold int // consecutive probe failures needed to declare outage

	// Gateway state
	gwConsecutiveFails int
	gwIsDown           bool
	gwDownSince        time.Time
	gwKnownIP          string
	gwKnownMAC         string

	// External WAN state
	extConsecutiveFails int
	extIsDown           bool
	extDownSince        time.Time

	// DNS state
	dnsConsecutiveFails int
	dnsIsDown           bool
	dnsDownSince        time.Time

	// Sustained high latency
	highLatencyStreak int

	// Configuration change tracking for temporal correlation
	recentConfigChanges []dhcp.ConfigChange
	lastConfigChangeAt  time.Time
}

func NewIncidentTracker() *IncidentTracker {
	return &IncidentTracker{
		failureThreshold: 2,
	}
}

// ProcessSample evaluates a new sample, returns newly generated transition events.
// It enforces debouncing to eliminate transient false alarms and repetitive logging.
func (t *IncidentTracker) ProcessSample(s PipelineStatus) []string {
	var events []string

	gwState := s.GatewayState
	if gwState == "" {
		if s.GatewayOK {
			gwState = "REACHABLE"
		} else {
			gwState = "UNREACHABLE"
		}
	}

	// 1. Gateway Connectivity Tracking (State-Aware)
	switch gwState {
	case "UNREACHABLE":
		t.gwConsecutiveFails++
		if t.gwConsecutiveFails == t.failureThreshold && !t.gwIsDown {
			t.gwIsDown = true
			t.gwDownSince = time.Now()
			events = append(events, fmt.Sprintf("[CRIT] Default Gateway unreachable (Target: %s, Method: %s)", s.GatewayIP, s.GatewayMethod))
		}
	case "REACHABLE":
		if t.gwIsDown {
			duration := time.Since(t.gwDownSince).Round(time.Second)
			events = append(events, fmt.Sprintf("[RECOV] Default Gateway connectivity restored after %s (RTT: %s via %s)", duration, formatDuration(s.GatewayRTT), s.GatewayMethod))
			t.gwIsDown = false
		}
		t.gwConsecutiveFails = 0
	case "INCONCLUSIVE", "UNAVAILABLE":
		// An inconclusive or unavailable gateway result must not increment a confirmed outage counter.
		// If a confirmed outage is already active, subsequent inconclusive observations must not falsely mark it recovered.
	}

	// 2. Gateway Configuration Drift
	if t.gwKnownIP == "" && s.GatewayIP != "" {
		t.gwKnownIP = s.GatewayIP
		t.gwKnownMAC = s.GatewayMAC
	} else if s.GatewayIP != "" && t.gwKnownIP != "" && s.GatewayIP != t.gwKnownIP {
		events = append(events, fmt.Sprintf("[WARN] Gateway IP changed from %s to %s", t.gwKnownIP, s.GatewayIP))
		t.gwKnownIP = s.GatewayIP
	}
	if s.GatewayMAC != "" && t.gwKnownMAC != "" && s.GatewayMAC != t.gwKnownMAC && s.GatewayMAC != "00:00:00:00:00:00" {
		events = append(events, fmt.Sprintf("[CRIT] Gateway MAC drifted from %s to %s for IP %s", t.gwKnownMAC, s.GatewayMAC, s.GatewayIP))
		t.gwKnownMAC = s.GatewayMAC
	}

	// 3. External Internet Connectivity Tracking
	if !s.InternetOK {
		t.extConsecutiveFails++
		if t.extConsecutiveFails == t.failureThreshold && !t.extIsDown {
			t.extIsDown = true
			t.extDownSince = time.Now()
			if s.GatewayOK {
				msg := "[CRIT] External internet connectivity lost (Default gateway remains responsive)"
				if !t.lastConfigChangeAt.IsZero() && time.Since(t.lastConfigChangeAt) < 60*time.Second && len(t.recentConfigChanges) > 0 {
					latest := t.recentConfigChanges[len(t.recentConfigChanges)-1]
					msg += fmt.Sprintf(" — Note: %s observed %s earlier; temporal correlation does not prove causation",
						latest.Summary,
						time.Since(latest.Timestamp).Round(time.Second),
					)
				}
				events = append(events, msg)
			} else {
				events = append(events, "[CRIT] External internet connectivity lost (Gateway also down)")
			}
		}
	} else {
		if t.extIsDown {
			duration := time.Since(t.extDownSince).Round(time.Second)
			events = append(events, fmt.Sprintf("[RECOV] External internet connectivity restored after %s (RTT: %s)", duration, formatDuration(s.InternetRTT)))
			t.extIsDown = false
		}
		t.extConsecutiveFails = 0
	}

	// 4. DNS Resolution Tracking
	if !s.DNSOK {
		t.dnsConsecutiveFails++
		if t.dnsConsecutiveFails == t.failureThreshold && !t.dnsIsDown {
			t.dnsIsDown = true
			t.dnsDownSince = time.Now()
			errMsg := s.DNSError
			if errMsg == "" {
				errMsg = "query timeout or no valid addresses"
			}
			events = append(events, fmt.Sprintf("[WARN] DNS resolution failed (Error: %s)", errMsg))
		}
	} else {
		if t.dnsIsDown {
			duration := time.Since(t.dnsDownSince).Round(time.Second)
			events = append(events, fmt.Sprintf("[RECOV] DNS resolution restored after %s (Query RTT: %s)", duration, formatDuration(s.DNSRTT)))
			t.dnsIsDown = false
		}
		t.dnsConsecutiveFails = 0
	}

	// 5. Sustained Latency Degradation
	if s.InternetOK && s.InternetRTT > 200*time.Millisecond {
		t.highLatencyStreak++
		if t.highLatencyStreak == 3 {
			events = append(events, fmt.Sprintf("[WARN] Sustained high latency observed (>200ms across 3 checks, current: %s)", formatDuration(s.InternetRTT)))
		}
	} else if s.InternetOK && s.InternetRTT < 100*time.Millisecond {
		if t.highLatencyStreak >= 3 {
			events = append(events, fmt.Sprintf("[RECOV] External latency normalized to %s", formatDuration(s.InternetRTT)))
		}
		t.highLatencyStreak = 0
	}

	return events
}

// RecordConfigChange registers a detected configuration transition for temporal incident correlation.
func (t *IncidentTracker) RecordConfigChange(chg dhcp.ConfigChange) {
	t.recentConfigChanges = append(t.recentConfigChanges, chg)
	t.lastConfigChangeAt = chg.Timestamp
	if len(t.recentConfigChanges) > 20 {
		t.recentConfigChanges = t.recentConfigChanges[1:]
	}
}

// RecentConfigChanges returns the recent configuration changes held by the tracker.
func (t *IncidentTracker) RecentConfigChanges() []dhcp.ConfigChange {
	return t.recentConfigChanges
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000.0)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
