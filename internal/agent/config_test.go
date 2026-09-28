package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigMissingReturnsDefaults(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want default %q", cfg.LogLevel, "info")
	}
}

func TestLoadConfigParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	const sample = `server_url: 'https://invmon.corp.local:8443'
ca_file: 'C:\ProgramData\InvMon\Agent\ca.pem'
enroll_token: 'imenr_test'
pin_sha256:
  - 'abc123'
log_level: debug
`
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ServerURL != "https://invmon.corp.local:8443" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.EnrollToken != "imenr_test" {
		t.Errorf("EnrollToken = %q", cfg.EnrollToken)
	}
	if len(cfg.PinSHA256) != 1 || cfg.PinSHA256[0] != "abc123" {
		t.Errorf("PinSHA256 = %v", cfg.PinSHA256)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
}
