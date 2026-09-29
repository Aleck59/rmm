package store_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Aleck59/rmm/internal/store"
	"github.com/Aleck59/rmm/internal/store/storetest"
	"github.com/Aleck59/rmm/internal/tokens"
)

var ctx = context.Background()

func TestMigrationsEmbedded(t *testing.T) {
	ms, err := store.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 || ms[0].Version != "0001_core" {
		t.Fatalf("unexpected migrations: %+v", ms)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	_, dsn := storetest.New(t) // already migrated once
	applied, err := store.Migrate(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Fatalf("second run applied %v, want nothing", applied)
	}
}

func TestMaintainPartitions(t *testing.T) {
	st, _ := storetest.New(t)
	const retention = 14
	if err := st.MaintainPartitions(ctx, retention); err != nil {
		t.Fatal(err)
	}
	if err := st.MaintainPartitions(ctx, retention); err != nil { // idempotent
		t.Fatal(err)
	}
	var n int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM pg_inherits WHERE inhparent = 'metrics_host'::regclass`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if want := retention + store.PartitionLookaheadDays + 1; n != want {
		t.Fatalf("metrics_host partitions = %d, want %d", n, want)
	}
	// A partition older than the window is dropped by the next run.
	if _, err := st.Pool().Exec(ctx,
		`SELECT ensure_partitions('metrics_host', 'day', current_date - 40, 2)`); err != nil {
		t.Fatal(err)
	}
	if err := st.MaintainPartitions(ctx, retention); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM pg_inherits WHERE inhparent = 'metrics_host'::regclass`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if want := retention + store.PartitionLookaheadDays + 1; n != want {
		t.Fatalf("after drop: metrics_host partitions = %d, want %d", n, want)
	}
}

// newEnrollToken creates an enrollment token and returns its plain value.
func newEnrollToken(t *testing.T, st *store.Store, spec store.EnrollTokenSpec) string {
	t.Helper()
	tok, err := tokens.Generate(tokens.EnrollPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name == "" {
		spec.Name = "test wave"
	}
	if spec.ExpiresAt.IsZero() {
		spec.ExpiresAt = time.Now().Add(24 * time.Hour)
	}
	if _, err := st.CreateEnrollmentToken(ctx, spec, tokens.Hash(tok), tokens.DisplayPrefix(tok), "test"); err != nil {
		t.Fatal(err)
	}
	return tok
}

func enrollParams(enrollTok, deviceTok, uid string) store.EnrollParams {
	return store.EnrollParams{
		EnrollTokenHash: tokens.Hash(enrollTok),
		DeviceTokenHash: tokens.Hash(deviceTok),
		AgentUID:        uid,
		AgentVersion:    "1.0.0",
		Hostname:        "PC-ACC-012",
		Domain:          "CORP",
		OSName:          "Windows 10 Pro",
		OSVersion:       "10.0.19045.4894",
		OSArch:          "x64",
		RemoteIP:        netip.MustParseAddr("192.168.10.23"),
	}
}

func deviceToken(t *testing.T) string {
	t.Helper()
	tok, err := tokens.Generate(tokens.DevicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

const uid1 = "5b7c1c7e-2f3a-4c55-9a0e-3c1f9f0d2a11"

func TestEnrollHappyPathAndAudit(t *testing.T) {
	st, _ := storetest.New(t)
	maxUses := int32(1)
	et := newEnrollToken(t, st, store.EnrollTokenSpec{AutoApprove: true, MaxUses: &maxUses})
	dt := deviceToken(t)

	res, err := st.Enroll(ctx, enrollParams(et, dt, uid1))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "active" || res.Reenrolled || res.DeviceID == 0 {
		t.Fatalf("unexpected result %+v", res)
	}
	d, err := st.DeviceByToken(ctx, tokens.Hash(dt))
	if err != nil || d.ID != res.DeviceID || d.Status != "active" {
		t.Fatalf("DeviceByToken = %+v, %v", d, err)
	}

	var used int
	if err := st.Pool().QueryRow(ctx, `SELECT used_count FROM enrollment_tokens`).Scan(&used); err != nil || used != 1 {
		t.Fatalf("used_count = %d, %v; want 1", used, err)
	}
	var audits int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'agent.enroll' AND result = 'success'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("enroll audit rows = %d, %v; want 1", audits, err)
	}

	// max_uses = 1 is exhausted for a *new* agent...
	_, err = st.Enroll(ctx, enrollParams(et, deviceToken(t), "6c8d2d8f-3a4b-4d66-8b1f-4d2a0a1e3b22"))
	if !errors.Is(err, store.ErrInvalidEnrollToken) {
		t.Fatalf("second agent on exhausted token: err = %v, want ErrInvalidEnrollToken", err)
	}
	// ...but the same agent retrying after a lost response is allowed and
	// does not consume another use.
	dt2 := deviceToken(t)
	res2, err := st.Enroll(ctx, enrollParams(et, dt2, uid1))
	if err != nil || !res2.Reenrolled || res2.DeviceID != res.DeviceID {
		t.Fatalf("re-enroll = %+v, %v", res2, err)
	}
	if _, err := st.DeviceByToken(ctx, tokens.Hash(dt)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old device token still valid after re-enroll: %v", err)
	}
}

func TestEnrollRejectsBadTokens(t *testing.T) {
	st, _ := storetest.New(t)
	expired := newEnrollToken(t, st, store.EnrollTokenSpec{Name: "old", ExpiresAt: time.Now().Add(-time.Minute)})

	for name, tok := range map[string]string{"unknown": "imenr_doesnotexist", "expired": expired} {
		if _, err := st.Enroll(ctx, enrollParams(tok, deviceToken(t), uid1)); !errors.Is(err, store.ErrInvalidEnrollToken) {
			t.Errorf("%s token: err = %v, want ErrInvalidEnrollToken", name, err)
		}
	}
	revoked := newEnrollToken(t, st, store.EnrollTokenSpec{Name: "revoked"})
	if _, err := st.Pool().Exec(ctx,
		`UPDATE enrollment_tokens SET revoked_at = now() WHERE token_hash = $1`, tokens.Hash(revoked)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Enroll(ctx, enrollParams(revoked, deviceToken(t), uid1)); !errors.Is(err, store.ErrInvalidEnrollToken) {
		t.Errorf("revoked token: err = %v, want ErrInvalidEnrollToken", err)
	}
}

func TestEnrollPendingAndStateRules(t *testing.T) {
	st, _ := storetest.New(t)
	et := newEnrollToken(t, st, store.EnrollTokenSpec{AutoApprove: false})
	res, err := st.Enroll(ctx, enrollParams(et, deviceToken(t), uid1))
	if err != nil || res.Status != "pending" {
		t.Fatalf("pending enroll = %+v, %v", res, err)
	}

	// Once the device has reported data, re-enrollment of its agent_uid is refused.
	if _, err := st.IngestMetrics(ctx, store.IngestParams{DeviceID: res.DeviceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Enroll(ctx, enrollParams(et, deviceToken(t), uid1)); !errors.Is(err, store.ErrAlreadyEnrolled) {
		t.Fatalf("re-enroll after data: err = %v, want ErrAlreadyEnrolled", err)
	}

	// A revoked device cannot re-enroll under the same agent_uid.
	if err := st.SetDeviceStatus(ctx, res.DeviceID, "revoked", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Enroll(ctx, enrollParams(et, deviceToken(t), uid1)); !errors.Is(err, store.ErrDeviceRevoked) {
		t.Fatalf("re-enroll revoked: err = %v, want ErrDeviceRevoked", err)
	}
}

func TestIngestMetrics(t *testing.T) {
	st, _ := storetest.New(t)
	et := newEnrollToken(t, st, store.EnrollTokenSpec{AutoApprove: true})
	dt := deviceToken(t)
	res, err := st.Enroll(ctx, enrollParams(et, dt, uid1))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	batch := store.IngestParams{
		DeviceID: res.DeviceID,
		Host: []store.HostSample{
			{TS: now.Add(-time.Minute), CPU: 20, CPUMax: 40, MemUsed: 4 << 30, MemTotal: 8 << 30},
			{TS: now, CPU: 10, CPUMax: 30, MemUsed: 6 << 30, MemTotal: 8 << 30},
		},
		Disks: []store.DiskSample{
			{TS: now.Add(-5 * time.Minute), Volume: "C:", Total: 100 << 30, Free: 50 << 30},
			{TS: now, Volume: "C:", Total: 100 << 30, Free: 8 << 30}, // latest: 8 % free
			{TS: now, Volume: "D:", Total: 500 << 30, Free: 250 << 30},
		},
		RemoteIP:     netip.MustParseAddr("192.168.10.23"),
		AgentVersion: "1.0.1",
	}
	out, err := st.IngestMetrics(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	if out.ConfigVersion != 1 || out.RotateToken || out.InventoryRequested {
		t.Fatalf("unexpected ingest result %+v", out)
	}
	// Re-sending the same batch (lost response) must not duplicate rows.
	if _, err := st.IngestMetrics(ctx, batch); err != nil {
		t.Fatal(err)
	}

	var hostRows, diskRows int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM metrics_host`).Scan(&hostRows); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM metrics_disk`).Scan(&diskRows); err != nil {
		t.Fatal(err)
	}
	if hostRows != 2 || diskRows != 3 {
		t.Fatalf("rows host=%d disk=%d, want 2 and 3", hostRows, diskRows)
	}

	var cpu, memPct, minFree float64
	if err := st.Pool().QueryRow(ctx,
		`SELECT cpu_pct, mem_used_pct, min_disk_free_pct FROM device_state WHERE device_id = $1`,
		res.DeviceID).Scan(&cpu, &memPct, &minFree); err != nil {
		t.Fatal(err)
	}
	if cpu != 10 || memPct != 75 || minFree != 8 {
		t.Fatalf("device_state cpu=%v mem=%v minFree=%v, want 10, 75, 8", cpu, memPct, minFree)
	}
	var agentVersion string
	if err := st.Pool().QueryRow(ctx, `SELECT agent_version FROM devices WHERE id = $1`, res.DeviceID).Scan(&agentVersion); err != nil || agentVersion != "1.0.1" {
		t.Fatalf("agent_version = %q, %v", agentVersion, err)
	}

	// Older replayed volume data must not overwrite the newer state.
	if _, err := st.IngestMetrics(ctx, store.IngestParams{
		DeviceID: res.DeviceID,
		Disks:    []store.DiskSample{{TS: now.Add(-10 * time.Minute), Volume: "C:", Total: 100 << 30, Free: 90 << 30}},
	}); err != nil {
		t.Fatal(err)
	}
	var free int64
	if err := st.Pool().QueryRow(ctx,
		`SELECT free_bytes FROM device_volumes WHERE device_id = $1 AND volume = 'C:'`, res.DeviceID).Scan(&free); err != nil || free != 8<<30 {
		t.Fatalf("C: free after stale replay = %d, %v; want %d", free, err, int64(8<<30))
	}

	// Inventory flag is delivered once, then cleared.
	if _, err := st.Pool().Exec(ctx, `UPDATE devices SET inventory_requested = true WHERE id = $1`, res.DeviceID); err != nil {
		t.Fatal(err)
	}
	if out, _ := st.IngestMetrics(ctx, store.IngestParams{DeviceID: res.DeviceID}); !out.InventoryRequested {
		t.Fatal("inventory_requested not delivered")
	}
	if out, _ := st.IngestMetrics(ctx, store.IngestParams{DeviceID: res.DeviceID}); out.InventoryRequested {
		t.Fatal("inventory_requested delivered twice")
	}

	// An old token triggers the rotation hint.
	if _, err := st.Pool().Exec(ctx,
		`UPDATE devices SET token_issued_at = now() - interval '91 days' WHERE id = $1`, res.DeviceID); err != nil {
		t.Fatal(err)
	}
	if out, _ := st.IngestMetrics(ctx, store.IngestParams{DeviceID: res.DeviceID}); !out.RotateToken {
		t.Fatal("rotate_token not requested for a 91-day-old token")
	}
}

func TestRotateDeviceTokenOverlap(t *testing.T) {
	st, _ := storetest.New(t)
	et := newEnrollToken(t, st, store.EnrollTokenSpec{AutoApprove: true})
	oldTok := deviceToken(t)
	res, err := st.Enroll(ctx, enrollParams(et, oldTok, uid1))
	if err != nil {
		t.Fatal(err)
	}
	newTok := deviceToken(t)
	until, err := st.RotateDeviceToken(ctx, res.DeviceID, tokens.Hash(newTok), time.Hour, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(until) < 59*time.Minute {
		t.Fatalf("overlap ends too early: %v", until)
	}
	for name, tok := range map[string]string{"new": newTok, "previous (overlap)": oldTok} {
		if d, err := st.DeviceByToken(ctx, tokens.Hash(tok)); err != nil || d.ID != res.DeviceID {
			t.Errorf("%s token: %+v, %v", name, d, err)
		}
	}
	// After the overlap window the previous token stops working.
	if _, err := st.Pool().Exec(ctx,
		`UPDATE devices SET prev_token_expires_at = now() - interval '1 second' WHERE id = $1`, res.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeviceByToken(ctx, tokens.Hash(oldTok)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired previous token still accepted: %v", err)
	}
}
