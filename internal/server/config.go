package server

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the Stage 0 server configuration. It intentionally covers only
// what the skeleton needs (listeners, TLS, logging); database, SMTP and
// security settings arrive with the ingest and web modules in later stages.
type Config struct {
	// PublicURL is the externally reachable base URL (used in links/logs).
	PublicURL string `yaml:"public_url"`
	// WebAddr is the listen address for the admin UI and web API (":443").
	WebAddr string `yaml:"web_addr"`
	// AgentAddr is the listen address for the agent API (":8443"). In Stage 0
	// the agent API is not yet implemented; the field is reserved so config
	// files are forward-compatible.
	AgentAddr string `yaml:"agent_addr"`
	// TLSCert and TLSKey point to the PEM certificate/key. When empty the
	// server falls back to plain HTTP (development only) and logs a warning.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// LogLevel is debug|info|warn|error.
	LogLevel string `yaml:"log_level"`
}

// DefaultConfig returns safe development defaults.
func DefaultConfig() Config {
	return Config{
		WebAddr:  ":8080",
		LogLevel: "info",
	}
}

// LoadConfig reads YAML from path, layering it over DefaultConfig. A missing
// path returns the defaults so the server can run out of the box.
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
