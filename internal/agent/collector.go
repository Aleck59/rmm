package agent

import (
	"errors"
	"time"
)

// Volume is one fixed volume's capacity reading.
type Volume struct {
	Name  string // "C:"
	Total uint64
	Free  uint64
}

// Collector reads host metrics. The Windows implementation uses Win32 APIs
// (no localized performance-counter names, no WMI on the hot path); other
// platforms get a synthetic collector for development and tests.
type Collector interface {
	// CPUPercent returns total CPU utilization since the previous call.
	CPUPercent() (float64, error)
	// Memory returns used and total physical memory in bytes.
	Memory() (used, total uint64, err error)
	// Volumes lists fixed volumes.
	Volumes() ([]Volume, error)
	// BootTime returns when the OS last started.
	BootTime() (time.Time, error)
}

// errPriming is returned by a collector whose first CPU reading only
// initializes its counters; callers skip it silently.
var errPriming = errors.New("cpu: first reading primes the counters")

func clampPct(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 100:
		return 100
	}
	return v
}
