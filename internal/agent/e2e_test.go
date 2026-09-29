package agent

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Aleck59/rmm/internal/agentapi"
	"github.com/Aleck59/rmm/internal/store"
	"github.com/Aleck59/rmm/internal/store/storetest"
	"github.com/Aleck59/rmm/internal/tokens"
)

// fakeCollector returns fixed readings.
type fakeCollector struct{}

func (fakeCollector) CPUPercent() (float64, error)    { return 25, nil }
func (fakeCollector) Memory() (uint64, uint64, error) { return 3 << 30, 4 << 30, nil }
func (fakeCollector) Volumes() ([]Volume, error) {
	return []Volume{{Name: "C:", Total: 100 << 30, Free: 7 << 30}}, nil
}
func (fakeCollector) BootTime() (time.Time, error) { return time.Now().Add(-time.Hour).UTC(), nil }

type e2e struct {
	t          *testing.T
	st         *store.Store
	serverURL  string
	configPath string
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	st, _ := storetest.New(t)
	api := agentapi.New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	enroll, err := tokens.Generate(tokens.EnrollPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateEnrollmentToken(context.Background(), store.EnrollTokenSpec{
		Name: "e2e", AutoApprove: true, ExpiresAt: time.Now().Add(time.Hour),
	}, tokens.Hash(enroll), tokens.DisplayPrefix(enroll), "test"); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "agent.yaml")
	yaml := "# test agent\nserver_url: '" + srv.URL + "'\nenroll_token: '" + enroll + "'\nallow_insecure: true\nlog_level: debug\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return &e2e{t: t, st: st, serverURL: srv.URL, configPath: cfgPath}
}

// runAgent runs an agent until cond holds (or the deadline passes).
func (e *e2e) runAgent(cond func() bool) {
	e.t.Helper()
	cfg, err := LoadConfig(e.configPath)
	if err != nil {
		e.t.Fatal(err)
	}
	a := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
		ConfigPath:     e.configPath,
		Collector:      fakeCollector{},
		SendInterval:   40 * time.Millisecond,
		SampleInterval: 10 * time.Millisecond,
		DiskInterval:   40 * time.Millisecond,
		RetryDelay:     20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			cancel()
			e.t.Fatalf("condition not met within deadline (agent error: %v)", <-done)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		e.t.Fatalf("agent Run returned %v", err)
	}
}

func (e *e2e) count(sql string) int {
	e.t.Helper()
	var n int
	if err := e.st.Pool().QueryRow(context.Background(), sql).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestEndToEndEnrollAndDeliver(t *testing.T) {
	e := newE2E(t)

	// First run: enroll, then deliver host and disk samples.
	e.runAgent(func() bool {
		return e.count(`SELECT count(*) FROM metrics_host`) >= 2 && e.count(`SELECT count(*) FROM metrics_disk`) >= 1
	})

	if n := e.count(`SELECT count(*) FROM devices WHERE status = 'active'`); n != 1 {
		t.Fatalf("active devices = %d, want 1", n)
	}
	var cpu, memPct, minFree float64
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT cpu_pct, mem_used_pct, min_disk_free_pct FROM device_state`).Scan(&cpu, &memPct, &minFree); err != nil {
		t.Fatal(err)
	}
	if cpu != 25 || memPct != 75 || minFree != 7 {
		t.Fatalf("device_state cpu=%v mem=%v minFree=%v, want 25, 75, 7", cpu, memPct, minFree)
	}

	// The enrollment token was removed from agent.yaml; the identity is persisted.
	cfgText, _ := os.ReadFile(e.configPath)
	if strings.Contains(string(cfgText), "imenr_") {
		t.Fatalf("enroll_token still in config:\n%s", cfgText)
	}
	st, err := loadState(filepath.Dir(e.configPath))
	if err != nil || !st.Enrolled() {
		t.Fatalf("state after enrollment: %+v, %v", st, err)
	}

	// Second run (service restart): reuses the stored identity — no new
	// enrollment, no new device — and keeps delivering.
	before := e.count(`SELECT count(*) FROM metrics_host`)
	e.runAgent(func() bool { return e.count(`SELECT count(*) FROM metrics_host`) > before })
	if n := e.count(`SELECT count(*) FROM devices`); n != 1 {
		t.Fatalf("devices after restart = %d, want 1", n)
	}
	if n := e.count(`SELECT used_count FROM enrollment_tokens`); n != 1 {
		t.Fatalf("enrollment token used_count = %d, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'agent.enroll'`); n != 1 {
		t.Fatalf("enroll audit records = %d, want 1", n)
	}
}

func TestAgentStopsDeliveringWhenRevoked(t *testing.T) {
	e := newE2E(t)
	e.runAgent(func() bool { return e.count(`SELECT count(*) FROM metrics_host`) >= 1 })

	var id int64
	if err := e.st.Pool().QueryRow(context.Background(), `SELECT id FROM devices`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetDeviceStatus(context.Background(), id, "revoked", "test"); err != nil {
		t.Fatal(err)
	}

	cfg, _ := LoadConfig(e.configPath)
	a := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
		ConfigPath: e.configPath, Collector: fakeCollector{},
		SendInterval: time.Hour, SampleInterval: time.Hour, DiskInterval: time.Millisecond,
		RetryDelay: 20 * time.Millisecond,
	})
	client, err := NewClient(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	a.client = client
	if err := a.loadIdentity(); err != nil {
		t.Fatal(err)
	}
	a.sample()
	before := e.count(`SELECT count(*) FROM metrics_host`)
	a.flush(context.Background())
	if !a.revoked || len(a.host) != 0 || !a.pauseUntil.After(time.Now()) {
		t.Fatalf("after revocation: revoked=%v queued=%d pauseUntil=%v; want revoked, empty queue, long pause",
			a.revoked, len(a.host), a.pauseUntil)
	}
	if after := e.count(`SELECT count(*) FROM metrics_host`); after != before {
		t.Fatalf("revoked device still stored samples: %d → %d", before, after)
	}
}
