//go:build linux

package sysmon

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func (m *Monitor) sampleOS(stats *Stats, elapsed float64) {
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
				} else {
					stats.CPUPercent = 0
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
