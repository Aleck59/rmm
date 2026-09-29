// Command invmon-server is the InvMon server: the admin web UI and the agent
// API. Subcommands: run, migrate, token, device, version, service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"time"

	"github.com/Aleck59/rmm/internal/cliutil"
	"github.com/Aleck59/rmm/internal/server"
	"github.com/Aleck59/rmm/internal/store"
	"github.com/Aleck59/rmm/internal/tokens"
	"github.com/Aleck59/rmm/internal/winservice"
)

const (
	serviceName        = "InvMonServer"
	serviceDisplayName = "InvMon Server"
	serviceDescription = "InvMon — сбор метрик и инвентаризации парка Windows-ПК (сервер)."
	defaultConfigPath  = `C:\ProgramData\InvMon\Server\server.yaml`
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "migrate":
		return cmdMigrate(args[1:])
	case "token":
		return cmdToken(args[1:])
	case "device":
		return cmdDevice(args[1:])
	case "version", "--version", "-v":
		return cliutil.PrintVersion(os.Stdout, hasFlag(args[1:], "--json"))
	case "service":
		return cliutil.HandleServiceCommand(args[1:], winservice.Config{
			Name:        serviceName,
			DisplayName: serviceDisplayName,
			Description: serviceDescription,
			Arguments:   []string{"run", "--config", defaultConfigPath},
		})
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to server.yaml")
	addr := fs.String("addr", "", "override web listen address (e.g. :8080)")
	agentAddr := fs.String("agent-addr", "", "override agent listen address (e.g. :8443)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *addr != "" {
		cfg.WebAddr = *addr
	}
	if *agentAddr != "" {
		cfg.AgentAddr = *agentAddr
	}
	log := cliutil.NewLogger(cfg.LogLevel)

	var st *store.Store
	if cfg.Database.URL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		st, err = openAndMigrate(ctx, cfg, log)
		cancel()
		if err != nil {
			return err
		}
		defer st.Close()
	}

	srv, err := server.New(cfg, log, st)
	if err != nil {
		return err
	}
	return cliutil.RunSupervised(serviceName, func(ctx context.Context) error {
		return srv.Run(ctx)
	})
}

func openAndMigrate(ctx context.Context, cfg server.Config, log *slog.Logger) (*store.Store, error) {
	applied, err := store.Migrate(ctx, cfg.Database.MigrationURL())
	if err != nil {
		return nil, err
	}
	if len(applied) > 0 {
		log.Info("database migrations applied", "versions", applied)
	}
	return store.Open(ctx, cfg.Database.URL)
}

func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to server.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadDBConfig(*configPath)
	if err != nil {
		return err
	}
	applied, err := store.Migrate(context.Background(), cfg.Database.MigrationURL())
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("database schema is up to date")
		return nil
	}
	fmt.Printf("applied migrations: %v\n", applied)
	return nil
}

// cmdToken implements `token create`, which mints an enrollment token. The
// plain token is printed once; only its hash is stored.
func cmdToken(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: token create --name NAME [--days 30] [--max-uses N] [--manual-approve] [--group-id ID] [--config PATH]")
	}
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to server.yaml")
	name := fs.String("name", "", "human-readable name, e.g. \"Бухгалтерия, волна 1\" (required)")
	days := fs.Int("days", 30, "validity in days (1-365)")
	maxUses := fs.Int("max-uses", 0, "maximum number of agents (0 = unlimited)")
	manual := fs.Bool("manual-approve", false, "new devices wait for approval (status pending)")
	groupID := fs.Int64("group-id", 0, "device group for new devices (0 = none)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	if *days < 1 || *days > 365 {
		return errors.New("--days must be between 1 and 365")
	}

	cfg, err := loadDBConfig(*configPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database.URL)
	if err != nil {
		return err
	}
	defer st.Close()

	tok, err := tokens.Generate(tokens.EnrollPrefix)
	if err != nil {
		return err
	}
	spec := store.EnrollTokenSpec{
		Name:        *name,
		AutoApprove: !*manual,
		ExpiresAt:   time.Now().Add(time.Duration(*days) * 24 * time.Hour),
	}
	if *maxUses > 0 {
		m := int32(*maxUses)
		spec.MaxUses = &m
	}
	if *groupID > 0 {
		spec.GroupID = groupID
	}
	id, err := st.CreateEnrollmentToken(ctx, spec, tokens.Hash(tok), tokens.DisplayPrefix(tok), cliActor())
	if err != nil {
		return err
	}
	fmt.Printf("Enrollment token #%d created (expires %s). It is shown only once:\n\n  %s\n\n",
		id, spec.ExpiresAt.Format(time.RFC3339), tok)
	fmt.Printf("Install the agent (PowerShell, as administrator):\n\n  .\\install.ps1 -ServerUrl https://<server>:8443 -EnrollToken %s -CaFile .\\ca.pem -Start\n", tok)
	return nil
}

// cmdDevice implements `device set-status` (approve / revoke / retire).
func cmdDevice(args []string) error {
	if len(args) == 0 || args[0] != "set-status" {
		return errors.New("usage: device set-status --id ID --status active|revoked|retired [--config PATH]")
	}
	fs := flag.NewFlagSet("device set-status", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to server.yaml")
	id := fs.Int64("id", 0, "device id (required)")
	status := fs.String("status", "", "active | revoked | retired (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch *status {
	case "active", "revoked", "retired":
	default:
		return errors.New("--status must be active, revoked or retired")
	}
	if *id <= 0 {
		return errors.New("--id is required")
	}
	cfg, err := loadDBConfig(*configPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database.URL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.SetDeviceStatus(ctx, *id, *status, cliActor()); err != nil {
		return err
	}
	fmt.Printf("device %d: status set to %s\n", *id, *status)
	return nil
}

func loadDBConfig(path string) (server.Config, error) {
	cfg, err := server.LoadConfig(path)
	if err != nil {
		return cfg, err
	}
	if cfg.Database.URL == "" {
		return cfg, fmt.Errorf("database.url is not configured (set it in the config file or %s)", server.EnvDatabaseURL)
	}
	return cfg, nil
}

// cliActor names the operator in audit records for CLI actions.
func cliActor() string {
	if u, err := user.Current(); err == nil {
		return "cli:" + u.Username
	}
	return "cli"
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprintf(os.Stderr, `invmon-server — сервер InvMon

Usage:
  invmon-server run [--config PATH] [--addr :8080] [--agent-addr :8443]
  invmon-server migrate [--config PATH]
  invmon-server token create --name NAME [--days 30] [--max-uses N] [--manual-approve] [--group-id ID]
  invmon-server device set-status --id ID --status active|revoked|retired
  invmon-server version [--json]
  invmon-server service <install|uninstall|start|stop>

Database URL: database.url in the config file or the %s environment variable.

`, server.EnvDatabaseURL)
}
