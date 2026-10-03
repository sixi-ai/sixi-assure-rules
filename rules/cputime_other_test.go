//go:build !linux

package rules

import "time"

// threadCPUTime has no per-thread CPU clock here: it runs f and reports ok=false, so the caller measures wall time.
func threadCPUTime(f func()) (time.Duration, bool) {
	f()
	return 0, false
}
