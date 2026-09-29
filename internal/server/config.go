package server

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// EnvDatabaseURL overrides database.url when set (convenient for development
// and CI; production keeps the value in the ACL-protected config file).
const EnvDatabaseURL = "INVMON_DATABASE_URL"

// Config is the server configuration.
type Config struct {
	// PublicURL is the externally reachable base URL (used in links/logs).
	PublicURL string `yaml:"public_url"`
	// WebAddr is the listen address for the admin UI and web API.
	WebAddr string `yaml:"web_addr"`
	// AgentAddr is the listen address for the agent API.
	AgentAddr string `yaml:"agent_addr"`
	// TLSCert and TLSKey point to the PEM certificate/key used by both
	// listeners. When empty the server falls back to plain HTTP (development
	// only) and logs a warning.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// LogLevel is debug|info|warn|error.
	LogLevel string `yaml:"log_level"`
	// Database connection settings.
	Database DatabaseConfig `yaml:"database"`
}

// DatabaseConfig holds PostgreSQL connection URLs.
type DatabaseConfig struct {
	// URL is used by the running server (least-privileged role, e.g. invmon_app).
	URL string `yaml:"url"`
	// MigrateURL is used to apply schema migrations (schema-owner role,
	// e.g. invmon_owner). Defaults to URL when empty.
	MigrateURL string `yaml:"migrate_url"`
}

// MigrationURL returns the URL used for migrations.
func (d DatabaseConfig) MigrationURL() string {
	if d.MigrateURL != "" {
		return d.MigrateURL
	}
	return d.URL
}

// DefaultConfig returns safe development defaults.
func DefaultConfig() Config {
	return Config{
		WebAddr:   ":8080",
		AgentAddr: ":8443",
		LogLevel:  "info",
	}
}

// LoadConfig reads YAML from path, layered over DefaultConfig, then applies
// environment overrides. A missing path yields the defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return cfg, fmt.Errorf("parse config %q: %w", path, err)
			}
		case os.IsNotExist(err):
			// fall through with defaults
		default:
			return cfg, fmt.Errorf("read config %q: %w", path, err)
		}
	}
	if v := os.Getenv(EnvDatabaseURL); v != "" {
		cfg.Database.URL = v
	}
	return cfg, nil
}
