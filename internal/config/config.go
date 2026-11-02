package config

import (
	"time"
)

// Config represents runtime settings for ARGUS.
type Config struct {
	// General
	InterfaceName string        `json:"interface_name"`
	HeartbeatRate time.Duration `json:"heartbeat_rate"` // Default: 1.5s
	LogDir        string        `json:"log_dir"`
	ReportDir     string        `json:"report_dir"`
	LogEnabled    bool          `json:"log_enabled"`

	// Target IPs and domains for connectivity verification
	GatewayTarget string   `json:"gateway_target"` // Auto-detected if empty
	DNSTargets    []string `json:"dns_targets"`    // System DNS or fallbacks
	PublicTargets []string `json:"public_targets"` // 1.1.1.1, 8.8.8.8, 9.9.9.9
	HTTPTarget    string   `json:"http_target"`   // e.g. http://connectivitycheck.gstatic.com/generate_204

	// Subnet Discovery
	GentleProbeRate int           `json:"gentle_probe_rate"` // Max packets per sec (default: 15)
	ProbeTimeout    time.Duration `json:"probe_timeout"`

	// Retention limits for USB flash drive protection
	MaxLogSizeMB    int `json:"max_log_size_mb"`
	MaxLogRotations int `json:"max_log_rotations"`
}

// DefaultConfig returns safe, optimized defaults for portable USB usage.
func DefaultConfig() *Config {
	return &Config{
		HeartbeatRate: 1500 * time.Millisecond,
		LogDir:        "./logs",
		ReportDir:     "./reports",
		LogEnabled:    true,
		DNSTargets: []string{
			"1.1.1.1:53",
			"8.8.8.8:53",
		},
		PublicTargets: []string{
			"1.1.1.1:443",
			"8.8.8.8:443",
			"9.9.9.9:443",
		},
		HTTPTarget:      "http://connectivitycheck.gstatic.com/generate_204",
		GentleProbeRate: 15, // Safe rate to prevent IDS/switch alarms
		ProbeTimeout:    800 * time.Millisecond,
		MaxLogSizeMB:    5,
		MaxLogRotations: 3,
	}
}
