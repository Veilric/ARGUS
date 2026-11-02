//go:build !windows

package platform

import "os"

// IsElevated returns true if running as root (UID 0).
func IsElevated() bool {
	return os.Geteuid() == 0
}
