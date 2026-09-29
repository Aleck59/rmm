package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterWindow(t *testing.T) {
	l := New(2, time.Minute)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("event %d unexpectedly limited", i)
		}
	}
	ok, retry := l.Allow("a")
	if ok || retry <= 0 || retry > time.Minute {
		t.Fatalf("third event: ok=%v retry=%v, want limited with 0<retry<=1m", ok, retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("independent key must not be limited")
	}

	now = now.Add(time.Minute)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("new window must allow events again")
	}
}
