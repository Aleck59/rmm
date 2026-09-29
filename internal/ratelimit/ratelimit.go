// Package ratelimit provides a small in-memory fixed-window rate limiter keyed
// by an arbitrary string (client IP, device ID). It is intentionally simple:
// a single server instance handles the MVP fleet, and limits exist to contain
// misbehaving agents and credential guessing, not to meter usage precisely.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows at most Limit events per key within each Window.
type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	start time.Time
	count int
}

// New returns a limiter allowing limit events per window per key.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:   limit,
		window:  window,
		now:     time.Now,
		buckets: make(map[string]*bucket),
	}
}

// Allow records an event for key. It reports whether the event is permitted
// and, if not, how long the caller should wait before retrying.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if len(l.buckets) > 4096 {
		l.purge(now)
	}
	b, ok := l.buckets[key]
	if !ok || now.Sub(b.start) >= l.window {
		l.buckets[key] = &bucket{start: now, count: 1}
		return true, 0
	}
	if b.count < l.limit {
		b.count++
		return true, 0
	}
	return false, b.start.Add(l.window).Sub(now)
}

func (l *Limiter) purge(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.start) >= l.window {
			delete(l.buckets, k)
		}
	}
}
