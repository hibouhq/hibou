//go:build unix

package server

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// processCPUSeconds returns the total user+system CPU time this process has
// consumed. The heartbeat sampler turns consecutive readings into a CPU%.
func processCPUSeconds() (float64, bool) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, false
	}
	seconds := float64(usage.Utime.Sec) + float64(usage.Utime.Usec)/1e6 +
		float64(usage.Stime.Sec) + float64(usage.Stime.Usec)/1e6

	return seconds, true
}

// processRSSBytes reads the resident set size from /proc/self/statm, so it
// only reports on Linux — the deployment target. Other platforms just omit
// the number.
func processRSSBytes() (int64, bool) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}

	return pages * int64(os.Getpagesize()), true
}
