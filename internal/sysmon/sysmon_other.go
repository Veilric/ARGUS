//go:build !linux && !windows

package sysmon

func (m *Monitor) sampleOS(stats *Stats, elapsed float64) {
	stats.CPUPercent = -1
	stats.RAMTotalGB = 0
	stats.RAMUsedGB = 0
	stats.RAMPercent = 0
}
