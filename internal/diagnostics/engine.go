package diagnostics

import (
	"context"
	"sync"
	"time"

	"argus/internal/dhcp"
	"argus/internal/platform"
)

// Engine orchestrates independent diagnostic modules.
type Engine struct {
	modules       []DiagnosticModule
	adapter       platform.NetworkAdapter
	baselineStore *dhcp.BaselineStore
	inspector     dhcp.Inspector
}

func NewEngine(adapter platform.NetworkAdapter, store *dhcp.BaselineStore, inspector dhcp.Inspector) *Engine {
	e := &Engine{
		adapter:       adapter,
		baselineStore: store,
		inspector:     inspector,
	}
	// Register default modular checks
	e.Register(&LinkCarrierCheck{})
	e.Register(&GatewayHealthCheck{})
	e.Register(&ConfigDriftCheck{})
	e.Register(&IPConflictCheck{})
	e.Register(&DoubleNATCheck{})
	e.Register(&DNSvsWANCheck{})
	e.Register(&CaptivePortalCheck{})
	e.Register(&MTUPathCheck{})
	e.Register(NewDHCPIntelligenceCheck(store, inspector))
	return e
}

func (e *Engine) Register(m DiagnosticModule) {
	e.modules = append(e.modules, m)
}

// RunDiagnostics gathers the network context and executes all modules concurrently.
func (e *Engine) RunDiagnostics(ctx context.Context) ([]DiagnosticResult, error) {
	netCtx := e.gatherContext()

	var wg sync.WaitGroup
	resultsChan := make(chan DiagnosticResult, len(e.modules))

	for _, module := range e.modules {
		wg.Add(1)
		go func(m DiagnosticModule) {
			defer wg.Done()
			timeoutCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()

			res, err := m.Run(timeoutCtx, netCtx)
			if err == nil && res != nil {
				resultsChan <- *res
			} else if err != nil {
				resultsChan <- DiagnosticResult{
					ID:        m.ID(),
					Title:     m.Name(),
					Category:  CategoryInconclusive,
					Severity:  SeverityInfo,
					Summary:   "Diagnostic check did not complete: " + err.Error(),
					Evidence:  []string{"Execution error: " + err.Error()},
					Timestamp: time.Now(),
				}
			}
		}(module)
	}

	wg.Wait()
	close(resultsChan)

	var results []DiagnosticResult
	for r := range resultsChan {
		results = append(results, r)
	}

	return results, nil
}

func (e *Engine) gatherContext() *NetworkContext {
	ctx := &NetworkContext{
		IsElevated: e.adapter.IsElevated(),
		ARPTable:   make(map[string]string),
	}

	iface, err := e.adapter.GetDefaultInterface()
	if err == nil && iface != nil {
		ctx.InterfaceName = iface.Name
		ctx.InterfaceUp = iface.IsUp
		ctx.MACAddress = iface.HardwareAddr.String()
		for _, ip := range iface.IPs {
			ctx.LocalIPs = append(ctx.LocalIPs, ip.String())
		}
	}

	gw, err := e.adapter.GetDefaultGateway()
	if err == nil && gw != nil {
		ctx.GatewayIP = gw.String()
	}

	dns, err := e.adapter.GetDNSServers()
	if err == nil {
		ctx.DNSServers = dns
	}

	neighbors, err := e.adapter.GetARPTable()
	if err == nil {
		for _, n := range neighbors {
			ctx.ARPTable[n.IP] = n.MAC
			if ctx.GatewayIP != "" && n.IP == ctx.GatewayIP {
				ctx.GatewayMAC = n.MAC
			}
		}
	}

	routeStatus, err := e.adapter.GetRouteStatus()
	if err == nil {
		if iface != nil && routeStatus.HasDefaultRoute && routeStatus.IsPrimary {
			ctx.Attribution = string(platform.AttributionSelectedInterface)
			ctx.AttributionDetails = routeStatus.Details
		} else if iface != nil && routeStatus.HasDefaultRoute && !routeStatus.IsPrimary {
			ctx.Attribution = string(platform.AttributionUnverified)
			ctx.AttributionDetails = routeStatus.Details
		} else if iface != nil && !routeStatus.HasDefaultRoute {
			ctx.Attribution = string(platform.AttributionUnverified)
			ctx.AttributionDetails = routeStatus.Details
		} else {
			ctx.Attribution = string(platform.AttributionSystemWide)
			ctx.AttributionDetails = routeStatus.Details
		}
	} else {
		ctx.Attribution = string(platform.AttributionSystemWide)
		ctx.AttributionDetails = "System-wide default routing"
	}

	// Gather DHCP and baseline configuration
	if iface != nil && iface.Name != "" {
		if e.inspector != nil {
			if cfg, dErr := e.inspector.Inspect(iface.Name); dErr == nil && cfg != nil {
				ctx.DHCPConfig = cfg
			}
		}
		if e.baselineStore != nil {
			if b, ok := e.baselineStore.Get(iface.Name); ok && b != nil {
				ctx.Baseline = b
				if ctx.DHCPConfig != nil {
					ctx.DetectedChanges = dhcp.DetectChanges(b, ctx.DHCPConfig)
				}
			}
		}
	}

	return ctx
}
