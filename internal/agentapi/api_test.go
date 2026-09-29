package agentapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Aleck59/rmm/internal/protocol"
	"github.com/Aleck59/rmm/internal/store"
	"github.com/Aleck59/rmm/internal/store/storetest"
	"github.com/Aleck59/rmm/internal/tokens"
)

type fixture struct {
	t         *testing.T
	st        *store.Store
	api       *API
	srv       *httptest.Server
	enrollTok string // plain enrollment token
}

func newFixture(t *testing.T, autoApprove bool) *fixture {
	t.Helper()
	st, _ := storetest.New(t)
	api := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	tok, err := tokens.Generate(tokens.EnrollPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateEnrollmentToken(context.Background(), store.EnrollTokenSpec{
		Name: "test", AutoApprove: autoApprove, ExpiresAt: time.Now().Add(time.Hour),
	}, tokens.Hash(tok), tokens.DisplayPrefix(tok), "test"); err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, st: st, api: api, srv: srv, enrollTok: tok}
}

// result is the part of an HTTP response the tests inspect.
type result struct {
	StatusCode int
	Header     http.Header
}

func (f *fixture) do(method, path, token string, body any, gz bool, hdr map[string]string) (result, []byte) {
	f.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		if gz {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(raw)
			_ = zw.Close()
			raw = buf.Bytes()
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return result{StatusCode: resp.StatusCode, Header: resp.Header}, out
}

func enrollReq(uid string) protocol.EnrollRequest {
	return protocol.EnrollRequest{
		AgentUID: uid, AgentVersion: "1.0.0", Hostname: "PC-ACC-012", Domain: "CORP",
		OS:          protocol.OSInfo{Name: "Windows 10 Pro", Version: "10.0.19045.4894", Arch: "x64"},
		HardwareIDs: protocol.HardwareIDs{MachineGUID: "0f5e4a1c-9d3b-4c2e-8f7a-1b2c3d4e5f60", MACs: []string{"3C:52:82:11:22:33"}},
	}
}

const testUID = "5b7c1c7e-2f3a-4c55-9a0e-3c1f9f0d2a11"

func (f *fixture) enroll(uid string) protocol.EnrollResponse {
	f.t.Helper()
	resp, body := f.do("POST", "/api/agent/v1/enroll", f.enrollTok, enrollReq(uid), false, nil)
	if resp.StatusCode != http.StatusCreated {
		f.t.Fatalf("enroll status %d: %s", resp.StatusCode, body)
	}
	var er protocol.EnrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		f.t.Fatal(err)
	}
	return er
}

func problemCode(t *testing.T, body []byte) string {
	t.Helper()
	var p protocol.Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("not a problem document: %s", body)
	}
	return p.Code
}

func TestEnrollFlow(t *testing.T) {
	f := newFixture(t, true)
	resp, body := f.do("POST", "/api/agent/v1/enroll", f.enrollTok, enrollReq(testUID), false, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (response carries a secret)", cc)
	}
	var er protocol.EnrollResponse
	_ = json.Unmarshal(body, &er)
	if !tokens.Valid(er.DeviceToken, tokens.DevicePrefix) || er.Status != "active" || er.Config.MetricsSendIntervalS != 60 {
		t.Fatalf("unexpected enroll response %+v", er)
	}
}

func TestEnrollRejections(t *testing.T) {
	f := newFixture(t, true)

	// Wrong prefix never reaches the database.
	if resp, body := f.do("POST", "/api/agent/v1/enroll", "imagt_notanenrolltoken", enrollReq(testUID), false, nil); resp.StatusCode != 401 || problemCode(t, body) != protocol.CodeInvalidToken {
		t.Errorf("wrong-prefix token: %d %s", resp.StatusCode, body)
	}
	// Well-formed but unknown token → 401 and an audit record.
	unknown, _ := tokens.Generate(tokens.EnrollPrefix)
	if resp, body := f.do("POST", "/api/agent/v1/enroll", unknown, enrollReq(testUID), false, nil); resp.StatusCode != 401 {
		t.Errorf("unknown token: %d %s", resp.StatusCode, body)
	}
	var failures int
	if err := f.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = 'agent.enroll' AND result = 'failure'`).Scan(&failures); err != nil || failures != 1 {
		t.Errorf("failure audit rows = %d, %v; want 1", failures, err)
	}
	// Validation errors come back as field-level problems.
	bad := enrollReq("not-a-uuid")
	bad.OS.Arch = "mips"
	resp, body := f.do("POST", "/api/agent/v1/enroll", f.enrollTok, bad, false, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("invalid body: %d %s", resp.StatusCode, body)
	}
	var p protocol.Problem
	_ = json.Unmarshal(body, &p)
	if p.Code != protocol.CodeValidationFailed || len(p.Errors) != 2 {
		t.Errorf("validation problem = %+v, want 2 field errors", p)
	}
}

func TestEnrollRateLimit(t *testing.T) {
	f := newFixture(t, true)
	unknown, _ := tokens.Generate(tokens.EnrollPrefix)
	var last result
	for i := 0; i < 11; i++ {
		last, _ = f.do("POST", "/api/agent/v1/enroll", unknown, enrollReq(testUID), false, nil)
	}
	if last.StatusCode != http.StatusTooManyRequests || last.Header.Get("Retry-After") == "" {
		t.Fatalf("11th enrollment from one IP: status %d, Retry-After %q", last.StatusCode, last.Header.Get("Retry-After"))
	}
}

func metricsBatch(sentAt time.Time) protocol.MetricsBatch {
	return protocol.MetricsBatch{
		SentAt: sentAt,
		Host: []protocol.HostSample{
			{TS: sentAt.Add(-time.Minute), CPUPct: 12.4, CPUMaxPct: 38, MemUsedBytes: 6 << 30, MemTotalBytes: 8 << 30},
			{TS: sentAt, CPUPct: 9.8, CPUMaxPct: 21.5, MemUsedBytes: 6 << 30, MemTotalBytes: 8 << 30},
		},
		Disks: []protocol.DiskSample{{TS: sentAt, Volume: "C:", TotalBytes: 255 << 30, FreeBytes: 20 << 30}},
		Agent: &protocol.AgentHealth{Version: "1.0.0", UptimeS: 120},
	}
}

func TestMetricsIngestGzipAndIdempotency(t *testing.T) {
	f := newFixture(t, true)
	er := f.enroll(testUID)

	if resp, body := f.do("POST", "/api/agent/v1/metrics", "", metricsBatch(time.Now()), false, nil); resp.StatusCode != 401 {
		t.Fatalf("no token: %d %s", resp.StatusCode, body)
	}

	batch := metricsBatch(time.Now().UTC().Truncate(time.Second))
	for i := 0; i < 2; i++ { // second send simulates a retry after a lost response
		resp, body := f.do("POST", "/api/agent/v1/metrics", er.DeviceToken, batch, true, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("send %d: status %d: %s", i, resp.StatusCode, body)
		}
		var mr protocol.MetricsResponse
		_ = json.Unmarshal(body, &mr)
		if mr.Accepted.Host != 2 || mr.Accepted.Disks != 1 || mr.ConfigVersion != 1 {
			t.Fatalf("send %d: response %+v", i, mr)
		}
	}
	var rows int
	if err := f.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM metrics_host`).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("metrics_host rows = %d, %v; want 2 (no duplicates)", rows, err)
	}
}

func TestMetricsClockSkewAndWindow(t *testing.T) {
	f := newFixture(t, true)
	er := f.enroll(testUID)
	serverNow := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	f.api.now = func() time.Time { return serverNow }

	// Agent clock is one hour behind: samples are shifted forward by the skew.
	agentNow := serverNow.Add(-time.Hour)
	resp, body := f.do("POST", "/api/agent/v1/metrics", er.DeviceToken, metricsBatch(agentNow), false, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var newest time.Time
	var skew int
	ctx := context.Background()
	if err := f.st.Pool().QueryRow(ctx, `SELECT max(ts) FROM metrics_host`).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	if !newest.Equal(serverNow) {
		t.Errorf("corrected ts = %v, want %v", newest, serverNow)
	}
	if err := f.st.Pool().QueryRow(ctx, `SELECT clock_skew_s FROM device_state`).Scan(&skew); err != nil || skew != 3600 {
		t.Errorf("clock_skew_s = %d, %v; want 3600", skew, err)
	}

	// Samples far outside the retention window are dropped, not rejected.
	old := metricsBatch(serverNow)
	for i := range old.Host {
		old.Host[i].TS = serverNow.Add(-30 * 24 * time.Hour)
	}
	old.Disks = nil
	_, body = f.do("POST", "/api/agent/v1/metrics", er.DeviceToken, old, false, nil)
	var mr protocol.MetricsResponse
	_ = json.Unmarshal(body, &mr)
	if mr.Accepted.Host != 0 {
		t.Errorf("30-day-old samples accepted: %+v", mr)
	}
}

func TestMetricsRejectsInvalidAndOversized(t *testing.T) {
	f := newFixture(t, true)
	er := f.enroll(testUID)

	bad := metricsBatch(time.Now())
	bad.Host[0].CPUPct = 150
	bad.Disks[0].Volume = "C:\\"
	resp, body := f.do("POST", "/api/agent/v1/metrics", er.DeviceToken, bad, false, nil)
	if resp.StatusCode != 400 || problemCode(t, body) != protocol.CodeValidationFailed {
		t.Fatalf("invalid batch: %d %s", resp.StatusCode, body)
	}

	// 2 MiB of zeros compresses to a few KiB but exceeds the 1 MiB limit after decompression.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"sent_at":"2026-09-29T12:00:00Z","host":[],"pad":"` + strings.Repeat("0", 2<<20) + `"}`))
	_ = zw.Close()
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/agent/v1/metrics", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Authorization", "Bearer "+er.DeviceToken)
	req.Header.Set("Content-Encoding", "gzip")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(r2.Body)
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("gzip bomb (%d bytes compressed): status %d %s", buf.Len(), r2.StatusCode, b2)
	}
}

func TestDeviceLifecycleStatuses(t *testing.T) {
	f := newFixture(t, false) // manual approval
	er := f.enroll(testUID)
	if er.Status != "pending" {
		t.Fatalf("status = %q, want pending", er.Status)
	}
	resp, body := f.do("POST", "/api/agent/v1/metrics", er.DeviceToken, metricsBatch(time.Now()), false, nil)
	if resp.StatusCode != 403 || problemCode(t, body) != protocol.CodePendingApproval {
		t.Fatalf("pending device: %d %s", resp.StatusCode, body)
	}

	ctx := context.Background()
	if err := f.st.SetDeviceStatus(ctx, er.DeviceID, "active", "test"); err != nil {
		t.Fatal(err)
	}
	if resp, _ := f.do("POST", "/api/agent/v1/metrics", er.DeviceToken, metricsBatch(time.Now()), false, nil); resp.StatusCode != 200 {
		t.Fatalf("approved device: status %d", resp.StatusCode)
	}

	if err := f.st.SetDeviceStatus(ctx, er.DeviceID, "revoked", "test"); err != nil {
		t.Fatal(err)
	}
	resp, body = f.do("POST", "/api/agent/v1/metrics", er.DeviceToken, metricsBatch(time.Now()), false, nil)
	if resp.StatusCode != 403 || problemCode(t, body) != protocol.CodeDeviceRevoked {
		t.Fatalf("revoked device: %d %s", resp.StatusCode, body)
	}
}

func TestConfigETagAndRotation(t *testing.T) {
	f := newFixture(t, true)
	er := f.enroll(testUID)

	resp, body := f.do("GET", "/api/agent/v1/config", er.DeviceToken, nil, false, nil)
	etag := resp.Header.Get("ETag")
	if resp.StatusCode != 200 || etag != `"1"` {
		t.Fatalf("config: %d etag=%q %s", resp.StatusCode, etag, body)
	}
	if resp, _ := f.do("GET", "/api/agent/v1/config", er.DeviceToken, nil, false, map[string]string{"If-None-Match": etag}); resp.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional config: status %d, want 304", resp.StatusCode)
	}

	resp, body = f.do("POST", "/api/agent/v1/token/rotate", er.DeviceToken, nil, false, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("rotate: %d %s", resp.StatusCode, body)
	}
	var rr protocol.TokenRotateResponse
	_ = json.Unmarshal(body, &rr)
	for name, tok := range map[string]string{"new": rr.DeviceToken, "old (overlap)": er.DeviceToken} {
		if resp, _ := f.do("GET", "/api/agent/v1/config", tok, nil, false, nil); resp.StatusCode != 200 {
			t.Errorf("%s token after rotation: status %d", name, resp.StatusCode)
		}
	}
}

func TestRoutingErrors(t *testing.T) {
	f := newFixture(t, true)
	if resp, body := f.do("GET", "/api/agent/v1/nope", "", nil, false, nil); resp.StatusCode != 404 || problemCode(t, body) != protocol.CodeNotFound {
		t.Errorf("unknown path: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do("GET", "/api/agent/v1/enroll", "", nil, false, nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET on enroll: status %d, want 405", resp.StatusCode)
	}
}
