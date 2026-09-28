// Command invmon-server is the InvMon server: it serves the admin web UI and
// (in later stages) the agent and web APIs. Subcommands: run, version, service.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Aleck59/rmm/internal/cliutil"
	"github.com/Aleck59/rmm/internal/server"
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

	log := cliutil.NewLogger(cfg.LogLevel)
	srv, err := server.New(cfg, log)
	if err != nil {
		return err
	}
	return cliutil.RunSupervised(serviceName, func(ctx context.Context) error {
		return srv.Run(ctx)
	})
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
  invmon-server run [--config PATH] [--addr :8080]
  invmon-server version [--json]
  invmon-server service <install|uninstall|start|stop>

`)
}
