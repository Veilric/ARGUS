package telemetry

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"argus/internal/config"
	"argus/internal/dhcp"
	"argus/internal/platform"
)

// PipelineStatus models the hop-by-hop reachability chain:
// [YOU] ───> [GATEWAY] ───> [DNS] ───> [INTERNET]
type PipelineStatus struct {
	LinkOK             bool          `json:"link_ok"`
	GatewayOK          bool          `json:"gateway_ok"`
	GatewayState       string        `json:"gateway_state"` // "REACHABLE", "UNREACHABLE", "INCONCLUSIVE"
	GatewayMethod      string        `json:"gateway_method"`
	GatewayIP          string        `json:"gateway_ip"`
	GatewayMAC         string        `json:"gateway_mac"`
	GatewayRTT         time.Duration `json:"gateway_rtt"`
	DNSOK              bool          `json:"dns_ok"`
	DNSRTT             time.Duration `json:"dns_rtt"`
	DNSServer          string        `json:"dns_server"`
	DNSServerReachable bool          `json:"dns_server_reachable"`
	DNSError           string        `json:"dns_error"`
	InternetOK         bool          `json:"internet_ok"`
	InternetRTT        time.Duration `json:"internet_rtt"`
	CaptiveState       string        `json:"captive_state"` // "CLEAN", "DETECTED", "UNKNOWN"
	PublicIP           string        `json:"public_ip"`
	ISPName            string        `json:"isp_name"`
	Attribution        string        `json:"attribution"`         // "SELECTED_INTERFACE", "SYSTEM_WIDE", "UNVERIFIED"
	AttributionDetails string        `json:"attribution_details"` // Evidence and routing priority details
	DHCPConfig         *dhcp.DHCPConfig     `json:"dhcp_config,omitempty"`
	Baseline           *dhcp.ConfigBaseline `json:"baseline,omitempty"`
	RecentChanges      []dhcp.ConfigChange  `json:"recent_changes,omitempty"`
}

// LogSink abstracts persistent file loggers to prevent circular package imports.
type LogSink interface {
	Log(msg string)
}

// Poller manages continuous live telemetry probes and incident transition tracking.
type Poller struct {
	cfg           *config.Config
	adapter       platform.NetworkAdapter
	mu            sync.RWMutex
	status        PipelineStatus
	gatewayBuf    *RingBuffer
	publicBuf     *RingBuffer
	tracker       *IncidentTracker
	logSink       LogSink
	startedLogged bool
	stopCh        chan struct{}
	eventLog      []string
	maxLogEvents  int

	baselineStore *dhcp.BaselineStore
	dhcpInspector dhcp.Inspector
	changeTracker *dhcp.ChangeTracker
}

func NewPoller(cfg *config.Config, adapter platform.NetworkAdapter) *Poller {
	return &Poller{
		cfg:          cfg,
		adapter:      adapter,
		gatewayBuf:   NewRingBuffer(30),
		publicBuf:    NewRingBuffer(30),
		tracker:      NewIncidentTracker(),
		stopCh:       make(chan struct{}),
		maxLogEvents: 100,
	}
}

// SetLogSink attaches a persistent logger (e.g. SessionLogger).
func (p *Poller) SetLogSink(sink LogSink) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logSink = sink
}

// SetDHCPComponents attaches persistent baseline storage and DHCP inspector to the poller.
func (p *Poller) SetDHCPComponents(store *dhcp.BaselineStore, inspector dhcp.Inspector) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.baselineStore = store
	p.dhcpInspector = inspector
	p.changeTracker = dhcp.NewChangeTracker()
}

// RefreshBaseline explicitly re-establishes the baseline from current observations.
func (p *Poller) RefreshBaseline(ifaceName string) (*dhcp.ConfigBaseline, error) {
	p.mu.RLock()
	store := p.baselineStore
	inspector := p.dhcpInspector
	cfg := p.status.DHCPConfig
	p.mu.RUnlock()

	if store == nil {
		return nil, fmt.Errorf("baseline store not initialized")
	}
	if cfg == nil && inspector != nil {
		var err error
		cfg, err = inspector.Inspect(ifaceName)
		if err != nil {
			return nil, err
		}
	}
	if cfg == nil {
		return nil, fmt.Errorf("no current configuration available to establish baseline")
	}
	b, err := store.Establish(cfg)
	if err == nil {
		p.mu.Lock()
		p.status.Baseline = b
		p.status.RecentChanges = nil
		p.mu.Unlock()
		p.LogEvent(fmt.Sprintf("[BASELINE] Network configuration baseline refreshed for %s", ifaceName))
	}
	return b, err
}

func (p *Poller) GatewayBuffer() *RingBuffer {
	return p.gatewayBuf
}

func (p *Poller) PublicBuffer() *RingBuffer {
	return p.publicBuf
}

func (p *Poller) Status() PipelineStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status
}

func (p *Poller) EventLogs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.eventLog))
	copy(copied, p.eventLog)
	return copied
}

func (p *Poller) LogEvent(msg string) {
	p.mu.Lock()
	ts := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s", ts, msg)
	p.eventLog = append(p.eventLog, entry)
	if len(p.eventLog) > p.maxLogEvents {
		p.eventLog = p.eventLog[1:]
	}
	sink := p.logSink
	p.mu.Unlock()

	if sink != nil {
		sink.Log(msg)
	}
}

// Stop logs the termination event and stops the poller.
func (p *Poller) Stop() {
	p.LogEvent("[INFO] Real-time telemetry monitoring stopped")
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
}

// ProbeOnce executes an instantaneous heartbeat check across all hops.
func (p *Poller) ProbeOnce(ctx context.Context) PipelineStatus {
	var status PipelineStatus

	if !p.startedLogged {
		p.startedLogged = true
		p.LogEvent("[INFO] Real-time telemetry monitoring started")
	}

	// 1. Interface link check
	iface, err := p.adapter.GetDefaultInterface()
	if err == nil && iface.IsUp {
		status.LinkOK = true
	} else {
		status.LinkOK = false
		status.GatewayOK = false
		status.GatewayState = "UNAVAILABLE"
		status.GatewayMethod = "Physical interface down or disconnected"
		p.gatewayBuf.Push(-1)
		p.publicBuf.Push(-1)
		p.updateAndTrack(status)
		return status
	}

	// 2. Gateway reachability (genuine response verification: TCP SYN/RST, ICMP ping, ARP fallback)
	gwIP, err := p.adapter.GetDefaultGateway()
	if err == nil && gwIP != nil {
		status.GatewayIP = gwIP.String()

		// Lookup gateway MAC in ARP table
		var gwMAC string
		if neighbors, err := p.adapter.GetARPTable(); err == nil {
			for _, n := range neighbors {
				if n.IP == gwIP.String() {
					gwMAC = n.MAC
					status.GatewayMAC = gwMAC
					break
				}
			}
		}

		gwProbe := platform.ProbeGatewayReachability(ctx, gwIP.String(), gwMAC, 800*time.Millisecond)
		status.GatewayMethod = gwProbe.Method

		switch gwProbe.State {
		case platform.ReachabilityConfirmed:
			status.GatewayOK = true
			status.GatewayState = "REACHABLE"
			status.GatewayRTT = gwProbe.RTT
			p.gatewayBuf.Push(float64(gwProbe.RTT.Microseconds()) / 1000.0)
		case platform.ReachabilityInconclusive:
			status.GatewayOK = false
			status.GatewayState = "INCONCLUSIVE"
			p.gatewayBuf.Push(-1)
		case platform.ReachabilityUnavailable:
			status.GatewayOK = false
			status.GatewayState = "UNAVAILABLE"
			p.gatewayBuf.Push(-1)
		default:
			status.GatewayOK = false
			status.GatewayState = "UNREACHABLE"
			p.gatewayBuf.Push(-1)
		}
	} else {
		status.GatewayOK = false
		status.GatewayState = "UNAVAILABLE"
		if err != nil {
			status.GatewayMethod = err.Error()
		} else {
			status.GatewayMethod = "No default gateway route configured"
		}
		p.gatewayBuf.Push(-1)
	}

	// 3. DNS server check (actual query resolution with response verification)
	dnsServers, err := p.adapter.GetDNSServers()
	dnsTarget := ""
	if err == nil && len(dnsServers) > 0 {
		dnsTarget = dnsServers[0]
	}
	status.DNSServer = dnsTarget

	dnsProbe := platform.ProbeDNSResolution(ctx, dnsTarget, "one.one.one.one", 1000*time.Millisecond)
	status.DNSOK = dnsProbe.Resolved
	status.DNSRTT = dnsProbe.RTT
	status.DNSServerReachable = dnsProbe.ServerPortReachable
	status.DNSError = dnsProbe.Error

	// Interface attribution evaluation
	routeStatus, rErr := p.adapter.GetRouteStatus()
	var localIP net.IP
	if iface != nil && len(iface.IPs) > 0 {
		for _, addr := range iface.IPs {
			if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
				localIP = addr.IP
				break
			}
		}
	}

	if rErr == nil {
		if routeStatus.HasDefaultRoute && routeStatus.IsPrimary {
			status.Attribution = "SELECTED_INTERFACE"
			status.AttributionDetails = routeStatus.Details
		} else if routeStatus.HasDefaultRoute && !routeStatus.IsPrimary {
			status.Attribution = "UNVERIFIED"
			status.AttributionDetails = routeStatus.Details
		} else if !routeStatus.HasDefaultRoute {
			status.Attribution = "UNVERIFIED"
			status.AttributionDetails = routeStatus.Details
		} else {
			status.Attribution = "SYSTEM_WIDE"
			status.AttributionDetails = routeStatus.Details
		}
	} else {
		status.Attribution = "SYSTEM_WIDE"
		status.AttributionDetails = "System-wide default route"
	}

	// 4. Public Internet reachability across independent external targets
	targets := p.cfg.PublicTargets
	if len(targets) == 0 {
		targets = []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	}
	if len(targets) > 3 {
		targets = targets[:3]
	}

	successCount := 0
	var minRTT time.Duration

	for _, target := range targets {
		rtt, ok := probeHostPort(target, 500*time.Millisecond, localIP)
		if ok {
			successCount++
			if minRTT == 0 || rtt < minRTT {
				minRTT = rtt
			}
		}
	}

	if successCount > 0 {
		status.InternetOK = true
		status.InternetRTT = minRTT
		p.publicBuf.Push(float64(minRTT.Microseconds()) / 1000.0)
	} else {
		status.InternetOK = false
		status.InternetRTT = 0
		p.publicBuf.Push(-1)
	}

	// 5. Captive Portal verification
	status.CaptiveState = p.checkCaptivePortal(ctx)

	// 6. DHCP & Configuration Baseline Inspection
	if p.dhcpInspector != nil && iface != nil {
		if cfg, dErr := p.dhcpInspector.Inspect(iface.Name); dErr == nil && cfg != nil {
			status.DHCPConfig = cfg
			if p.baselineStore != nil {
				if b, ok := p.baselineStore.Get(iface.Name); ok && b != nil {
					status.Baseline = b
					changes := dhcp.DetectChanges(b, cfg)
					if len(changes) > 0 {
						status.RecentChanges = changes
						if p.changeTracker != nil {
							newChanges := p.changeTracker.FilterNewChanges(changes)
							for _, chg := range newChanges {
								if p.tracker != nil {
									p.tracker.RecordConfigChange(chg)
								}
								p.LogEvent(fmt.Sprintf("[CONFIG] %s (%s)", chg.Summary, chg.Implication))
							}
						}
					}
					_ = p.baselineStore.UpdateLastSeen(iface.Name, time.Now())
				} else {
					// Automatically establish baseline if none exists
					if newB, err := p.baselineStore.Establish(cfg); err == nil {
						status.Baseline = newB
						p.LogEvent(fmt.Sprintf("[BASELINE] Initial baseline established for %s", iface.Name))
					}
				}
			}
		}
	}

	p.updateAndTrack(status)
	return status
}

func (p *Poller) updateAndTrack(s PipelineStatus) {
	p.mu.Lock()
	p.status = s
	p.mu.Unlock()

	// Debounced incident transition tracking
	if p.tracker != nil {
		events := p.tracker.ProcessSample(s)
		for _, ev := range events {
			p.LogEvent(ev)
		}
	}
}

func probeHostPort(target string, timeout time.Duration, localIP net.IP) (time.Duration, bool) {
	start := time.Now()
	var dialer net.Dialer
	dialer.Timeout = timeout
	if localIP != nil && localIP.To4() != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	conn, err := dialer.Dial("tcp", target)
	if err == nil {
		conn.Close()
		return time.Since(start), true
	}
	return 0, false
}

func (p *Poller) checkCaptivePortal(ctx context.Context) string {
	client := &http.Client{
		Timeout: 1200 * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.cfg.HTTPTarget, nil)
	if err != nil {
		return "UNKNOWN"
	}

	resp, err := client.Do(req)
	if err != nil {
		return "UNKNOWN"
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return "CLEAN" // Direct connection, HTTP 204 received
	} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return "DETECTED" // Redirected by captive portal splash
	} else if resp.StatusCode == http.StatusOK {
		// Some portals return 200 with HTML login page instead of 204
		return "DETECTED"
	}
	return "UNKNOWN"
}
