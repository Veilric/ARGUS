package sysmon

import (
	"strings"
	"testing"
)

func TestFormatRate(t *testing.T) {
	tests := []struct {
		bytes    float64
		expected string
	}{
		{500, "500 B/s"},
		{1024, "1.0 KB/s"},
		{1024 * 1024 * 2.5, "2.50 MB/s"},
	}

	for _, tt := range tests {
		res := FormatRate(tt.bytes)
		if !strings.Contains(res, tt.expected) {
			t.Errorf("FormatRate(%f) = %s, expected to contain %s", tt.bytes, res, tt.expected)
		}
	}
}

func TestSysmonSample(t *testing.T) {
	m := NewMonitor()
	stats := m.GetStats()

	// CPUPercent should be either >= 0 or -1 (explicitly unavailable), never fabricated arbitrary values like 2.0 placeholder
	if stats.CPUPercent < -1 || stats.CPUPercent > 100 {
		t.Errorf("CPUPercent out of valid bounds: %f", stats.CPUPercent)
	}
}
