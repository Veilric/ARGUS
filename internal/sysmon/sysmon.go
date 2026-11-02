package sysmon

import (
	"fmt"
	"sync"
	"time"
)

// Stats holds snapshot host hardware and throughput telemetry.
type Stats struct {
	CPUPercent float64
	RAMUsedGB  float64
	RAMTotalGB float64
	RAMPercent float64
	RxBytesSec float64
	TxBytesSec float64
	Timestamp  time.Time
}

// Monitor tracks system performance with negligible overhead.
type Monitor struct {
	mu             sync.Mutex
	lastCPUTotal   uint64
	lastCPUIdle    uint64
	lastKernelTime uint64
	lastUserTime   uint64
	lastRxBytes    uint64
	lastTxBytes    uint64
	lastSample     time.Time
	currentStats   Stats
}

func NewMonitor() *Monitor {
	m := &Monitor{
		lastSample: time.Now(),
	}
	m.Sample()
	return m
}

func (m *Monitor) GetStats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentStats
}

// Sample computes instantaneous metrics.
func (m *Monitor) Sample() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(m.lastSample).Seconds()
	if elapsed <= 0 {
		elapsed = 1.0
	}

	stats := Stats{
		CPUPercent: -1, // Default to unavailable until verified
		RAMTotalGB: 0,
		Timestamp:  now,
	}

	m.sampleOS(&stats, elapsed)

	m.currentStats = stats
	m.lastSample = now
	return stats
}

// FormatRate formats bytes/sec into human-readable B/s, KB/s, MB/s.
func FormatRate(bytesPerSec float64) string {
	if bytesPerSec < 1024 {
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	} else if bytesPerSec < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/1024)
	}
	return fmt.Sprintf("%.2f MB/s", bytesPerSec/(1024*1024))
}
