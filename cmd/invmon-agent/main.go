// Command invmon-agent is the InvMon Windows agent. Subcommands: run, version,
// service. Metric collection and enrollment arrive in Stage 1; Stage 0 wires up
// the process, configuration and service lifecycle.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Aleck59/rmm/internal/agent"
	"github.com/Aleck59/rmm/internal/cliutil"
	"github.com/Aleck59/rmm/internal/winservice"
)

const (
	serviceName        = "InvMonAgent"
	serviceDisplayName = "InvMon Agent"
	serviceDescription = "InvMon — сбор метрик и инвентаризации данного ПК (агент)."
	defaultConfigPath  = `C:\ProgramData\InvMon\Agent\agent.yaml`
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
	configPath := fs.String("config", "", "path to agent.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	log := cliutil.NewLogger(cfg.LogLevel)
	a := agent.New(cfg, log, agent.Options{ConfigPath: *configPath})
	return cliutil.RunSupervised(serviceName, func(ctx context.Context) error {
		return a.Run(ctx)
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
	fmt.Fprintf(os.Stderr, `invmon-agent — агент InvMon

Usage:
  invmon-agent run [--config PATH]
  invmon-agent version [--json]
  invmon-agent service <install|uninstall|start|stop>

`)
}
