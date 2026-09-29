//go:build !windows

package agent

import (
	"math/rand/v2"
	"sync"
	"time"
)

// NewCollector returns a synthetic collector. The agent targets Windows; off
// Windows it produces plausible, clearly fake values so the full pipeline
// (enroll → collect → send → store) can be developed and tested anywhere.
func NewCollector() Collector {
	return &devCollector{cpu: 15, free: 120 << 30, boot: time.Now().Add(-time.Hour).Truncate(time.Second)}
}

type devCollector struct {
	mu   sync.Mutex
	cpu  float64
	free uint64
	boot time.Time
}

func (c *devCollector) CPUPercent() (float64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cpu = clampPct(c.cpu + rand.Float64()*10 - 5) // bounded random walk
	return c.cpu, nil
}

func (c *devCollector) Memory() (uint64, uint64, error) {
	const total = 8 << 30
	return total * 6 / 10, total, nil
}

func (c *devCollector) Volumes() ([]Volume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.free > 1<<30 {
		c.free -= 1 << 20 // the synthetic disk slowly fills up
	}
	return []Volume{{Name: "C:", Total: 256 << 30, Free: c.free}}, nil
}

func (c *devCollector) BootTime() (time.Time, error) { return c.boot, nil }
