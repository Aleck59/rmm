package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthz(t *testing.T) {
	s, err := New(DefaultConfig(), discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if body := rr.Body.String(); body != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("missing security header, X-Content-Type-Options = %q", got)
	}
}

func TestVersion(t *testing.T) {
	s, err := New(DefaultConfig(), discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/version", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["version"]; !ok {
		t.Errorf("version field missing: %v", body)
	}
}

func TestReadyz(t *testing.T) {
	s, err := New(DefaultConfig(), discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestAPIStubNotImplemented(t *testing.T) {
	s, err := New(DefaultConfig(), discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rr.Code)
	}
}

func TestSPAFallback(t *testing.T) {
	s, err := New(DefaultConfig(), discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// An unknown client-side route must fall back to index.html.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/devices/42", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if !strings.Contains(rr.Body.String(), "InvMon") {
		t.Errorf("index body does not mention InvMon")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
