package agent

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config mirrors agent.yaml. Collection intervals are intentionally absent:
// the server owns them and hands them to the agent at runtime.
type Config struct {
	// ServerURL is the agent API base URL, e.g. https://invmon.corp.local:8443.
	ServerURL string `yaml:"server_url"`
	// CAFile is the PEM certificate authority used to verify the server. When
	// empty, the system trust store is used (not recommended on Windows 7).
	CAFile string `yaml:"ca_file"`
	// PinSHA256 optionally pins the server public key (base64 SHA-256 of SPKI).
	PinSHA256 []string `yaml:"pin_sha256"`
	// EnrollToken is used once on first launch, then removed from the file.
	EnrollToken string `yaml:"enroll_token"`
	// Proxy is "" (direct) or "system" (proxy from the environment).
	Proxy string `yaml:"proxy"`
	// LogLevel is debug|info|warn|error.
	LogLevel string `yaml:"log_level"`
	// DataDir holds state.bin (device identity and token). Defaults to
	// C:\ProgramData\InvMon\Agent on Windows.
	DataDir string `yaml:"data_dir"`
	// AllowInsecure permits an http:// server URL. Development and tests only.
	AllowInsecure bool `yaml:"allow_insecure"`
}

// DefaultConfig returns development defaults.
func DefaultConfig() Config {
	return Config{LogLevel: "info"}
}

// LoadConfig reads YAML from path, layering it over DefaultConfig.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}
