package telemetry

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"argus/internal/config"
	"argus/internal/platform"
)

// PipelineStatus models the hop-by-hop reachability chain:
// [YOU] ───> [GATEWAY] ───> [DNS] ───> [INTERNET]
type PipelineStatus struct {
	LinkOK       bool
	GatewayOK    bool
	DNSOK        bool
	InternetOK   bool
	GatewayRTT   time.Duration
	DNSRTT       time.Duration
	InternetRTT  time.Duration
	CaptiveState string // "CLEAN", "DETECTED", "UNKNOWN"
	PublicIP     string
	ISPName      string
}

// Poller manages continuous live telemetry probes.
type Poller struct {
	cfg          *config.Config
	adapter      platform.NetworkAdapter
	mu           sync.RWMutex
	status       PipelineStatus
	gatewayBuf   *RingBuffer
	publicBuf    *RingBuffer
	lastErr      error
	subscribers  []chan PipelineStatus
	stopCh       chan struct{}
	eventLog     []string
	maxLogEvents int
}

func NewPoller(cfg *config.Config, adapter platform.NetworkAdapter) *Poller {
	return &Poller{
		cfg:          cfg,
		adapter:      adapter,
		gatewayBuf:   NewRingBuffer(30),
		publicBuf:    NewRingBuffer(30),
		stopCh:       make(chan struct{}),
		maxLogEvents: 100,
	}
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
	defer p.mu.Unlock()
	ts := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("%s %s", ts, msg)
	p.eventLog = append(p.eventLog, entry)
	if len(p.eventLog) > p.maxLogEvents {
		p.eventLog = p.eventLog[1:]
	}
}

// ProbeOnce executes an instantaneous heartbeat check across all hops.
func (p *Poller) ProbeOnce(ctx context.Context) PipelineStatus {
	var status PipelineStatus

	// 1. Interface link check
	iface, err := p.adapter.GetDefaultInterface()
	if err == nil && iface.IsUp {
		status.LinkOK = true
	} else {
		status.LinkOK = false
		p.gatewayBuf.Push(-1)
		p.publicBuf.Push(-1)
		p.updateStatus(status)
		return status
	}

	// 2. Gateway reachability
	gwIP, err := p.adapter.GetDefaultGateway()
	if err == nil && gwIP != nil {
		gwRTT, ok := probeHost(gwIP.String(), 600*time.Millisecond)
		status.GatewayOK = ok
		status.GatewayRTT = gwRTT
		if ok {
			p.gatewayBuf.Push(float64(gwRTT.Microseconds()) / 1000.0)
		} else {
			p.gatewayBuf.Push(-1)
		}
	} else {
		p.gatewayBuf.Push(-1)
	}

	// 3. DNS server check
	dnsServers, err := p.adapter.GetDNSServers()
	dnsTarget := "1.1.1.1:53"
	if err == nil && len(dnsServers) > 0 {
		dnsTarget = net.JoinHostPort(dnsServers[0], "53")
	}
	dnsRTT, dnsOK := probeHostPort(dnsTarget, 800*time.Millisecond)
	status.DNSOK = dnsOK
	status.DNSRTT = dnsRTT

	// 4. Public Internet reachability
	publicTarget := "1.1.1.1:443"
	if len(p.cfg.PublicTargets) > 0 {
		publicTarget = p.cfg.PublicTargets[0]
	}
	pubRTT, pubOK := probeHostPort(publicTarget, 900*time.Millisecond)
	status.InternetOK = pubOK
	status.InternetRTT = pubRTT
	if pubOK {
		p.publicBuf.Push(float64(pubRTT.Microseconds()) / 1000.0)
	} else {
		p.publicBuf.Push(-1)
	}

	// 5. Captive Portal verification
	status.CaptiveState = p.checkCaptivePortal(ctx)

	p.updateStatus(status)
	return status
}

func (p *Poller) updateStatus(s PipelineStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = s
}

// probeHost tries unprivileged TCP ports (53, 80, 443) or ping
func probeHost(host string, timeout time.Duration) (time.Duration, bool) {
	ports := []string{"53", "80", "443"}
	for _, port := range ports {
		target := net.JoinHostPort(host, port)
		rtt, ok := probeHostPort(target, timeout)
		if ok {
			return rtt, true
		}
	}

	// UDP probe fallback
	start := time.Now()
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "12345"), timeout)
	if err == nil {
		defer conn.Close()
		return time.Since(start), true
	}

	return 0, false
}

func probeHostPort(target string, timeout time.Duration) (time.Duration, bool) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
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
