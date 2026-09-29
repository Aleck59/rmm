package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := loadState(dir)
	if err != nil || st.Enrolled() || st.AgentUID != "" {
		t.Fatalf("missing state file: %+v, %v; want empty", st, err)
	}
	want := State{AgentUID: "5b7c1c7e-2f3a-4c55-9a0e-3c1f9f0d2a11", DeviceID: 42, DeviceToken: "imagt_x"}
	if err := saveState(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(dir)
	if err != nil || got != want {
		t.Fatalf("loadState = %+v, %v; want %+v", got, err, want)
	}
	info, err := os.Stat(filepath.Join(dir, stateFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
}

func TestNewUUID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	a, _ := newUUID()
	b, _ := newUUID()
	if !re.MatchString(a) || a == b {
		t.Fatalf("newUUID produced %q and %q", a, b)
	}
}

func TestScrubEnrollToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	orig := "# InvMon agent\r\nserver_url: 'https://x:8443'\r\nenroll_token: 'imenr_secret'\r\nlog_level: info\r\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scrubEnrollToken(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	if strings.Contains(s, "imenr_secret") {
		t.Fatalf("token still present:\n%s", s)
	}
	for _, keep := range []string{"# InvMon agent\r\n", "server_url: 'https://x:8443'\r\n", "log_level: info\r\n"} {
		if !strings.Contains(s, keep) {
			t.Errorf("lost line %q", keep)
		}
	}
	cfg, err := LoadConfig(path)
	if err != nil || cfg.EnrollToken != "" || cfg.ServerURL != "https://x:8443" {
		t.Fatalf("scrubbed file does not parse cleanly: %+v, %v", cfg, err)
	}
	if err := scrubEnrollToken(filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatalf("missing file: %v", err)
	}
}

func TestNewClientRejectsUnsafeConfig(t *testing.T) {
	cases := map[string]Config{
		"plain http without allow_insecure": {ServerURL: "http://srv:8443"},
		"bad scheme":                        {ServerURL: "ftp://srv"},
		"no host":                           {ServerURL: "https://"},
		"missing CA file":                   {ServerURL: "https://srv:8443", CAFile: filepath.Join(t.TempDir(), "none.pem")},
		"malformed pin":                     {ServerURL: "https://srv:8443", PinSHA256: []string{"not-base64!"}},
	}
	for name, cfg := range cases {
		if _, err := NewClient(cfg, "test"); err == nil {
			t.Errorf("%s: NewClient succeeded, want error", name)
		}
	}
	if _, err := NewClient(Config{ServerURL: "http://srv:8443", AllowInsecure: true}, "test"); err != nil {
		t.Errorf("explicit allow_insecure: %v", err)
	}
}

func TestIntervalClamping(t *testing.T) {
	if got := pick(0, 1, 30, 60); got != 30*time.Second {
		t.Errorf("server value below minimum: %v, want 30s", got)
	}
	if got := pick(0, 0, 30, 60); got != 60*time.Second {
		t.Errorf("missing server value: %v, want default 60s", got)
	}
	if got := pick(50*time.Millisecond, 60, 30, 60); got != 50*time.Millisecond {
		t.Errorf("override: %v, want 50ms", got)
	}
}
