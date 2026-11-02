package sysmon

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
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
	mu           sync.Mutex
	lastCPUTotal uint64
	lastCPUIdle  uint64
	lastRxBytes  uint64
	lastTxBytes  uint64
	lastSample   time.Time
	currentStats Stats
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

	stats := Stats{Timestamp: now}

	if runtime.GOOS == "linux" {
		m.sampleLinux(&stats, elapsed)
	} else {
		// Generic cross-platform fallback
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		stats.RAMUsedGB = float64(mem.Alloc) / (1024 * 1024 * 1024)
		stats.RAMTotalGB = stats.RAMUsedGB * 4 // estimate fallback
		if stats.RAMTotalGB > 0 {
			stats.RAMPercent = (stats.RAMUsedGB / stats.RAMTotalGB) * 100
		}
		stats.CPUPercent = 2.0 // lightweight placeholder for non-Linux until Windows perf counters
	}

	m.currentStats = stats
	m.lastSample = now
	return stats
}

func (m *Monitor) sampleLinux(stats *Stats, elapsed float64) {
	// 1. CPU utilization from /proc/stat
	if statFile, err := os.Open("/proc/stat"); err == nil {
		scanner := bufio.NewScanner(statFile)
		if scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 5 && fields[0] == "cpu" {
				var total uint64
				var idle uint64
				for i := 1; i < len(fields); i++ {
					v, _ := strconv.ParseUint(fields[i], 10, 64)
					total += v
					if i == 4 { // 4th field is idle
						idle = v
					}
				}

				if m.lastCPUTotal > 0 && total > m.lastCPUTotal {
					totalDelta := float64(total - m.lastCPUTotal)
					idleDelta := float64(idle - m.lastCPUIdle)
					stats.CPUPercent = (1.0 - (idleDelta / totalDelta)) * 100.0
					if stats.CPUPercent < 0 {
						stats.CPUPercent = 0
					} else if stats.CPUPercent > 100 {
						stats.CPUPercent = 100
					}
				}
				m.lastCPUTotal = total
				m.lastCPUIdle = idle
			}
		}
		statFile.Close()
	}

	// 2. RAM from /proc/meminfo
	if memFile, err := os.Open("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(memFile)
		var totalKB, availKB float64
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					totalKB, _ = strconv.ParseFloat(fields[1], 64)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					availKB, _ = strconv.ParseFloat(fields[1], 64)
				}
			}
		}
		memFile.Close()

		if totalKB > 0 {
			stats.RAMTotalGB = totalKB / (1024 * 1024)
			usedKB := totalKB - availKB
			stats.RAMUsedGB = usedKB / (1024 * 1024)
			stats.RAMPercent = (usedKB / totalKB) * 100.0
		}
	}

	// 3. Network throughput from /proc/net/dev
	if devFile, err := os.Open("/proc/net/dev"); err == nil {
		scanner := bufio.NewScanner(devFile)
		var curRxTotal, curTxTotal uint64
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, ":") || strings.Contains(line, "lo:") {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				fields := strings.Fields(parts[1])
				if len(fields) >= 9 {
					rx, _ := strconv.ParseUint(fields[0], 10, 64)
					tx, _ := strconv.ParseUint(fields[8], 10, 64)
					curRxTotal += rx
					curTxTotal += tx
				}
			}
		}
		devFile.Close()

		if m.lastRxBytes > 0 && curRxTotal >= m.lastRxBytes {
			stats.RxBytesSec = float64(curRxTotal-m.lastRxBytes) / elapsed
			stats.TxBytesSec = float64(curTxTotal-m.lastTxBytes) / elapsed
		}
		m.lastRxBytes = curRxTotal
		m.lastTxBytes = curTxTotal
	}
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
