// Package cliutil holds helpers shared by the invmon-server and invmon-agent
// command-line entry points: logging, version output, and service dispatch.
package cliutil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Aleck59/rmm/internal/buildinfo"
	"github.com/Aleck59/rmm/internal/winservice"
)

// NewLogger returns a JSON slog.Logger writing to stderr at the given level
// (debug|info|warn|error; anything else falls back to info).
func NewLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// PrintVersion writes build metadata to w, as JSON when jsonOut is set.
func PrintVersion(w io.Writer, jsonOut bool) error {
	info := buildinfo.Get()
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	_, err := fmt.Fprintf(w, "%s %s (commit %s, built %s, %s, %s)\n",
		os.Args[0], info.Version, info.Commit, info.Date, info.Go, info.Platform)
	return err
}

// RunSupervised runs a payload either under the Windows SCM (when started as a
// service) or directly with Ctrl+C / SIGTERM cancellation (console/dev).
func RunSupervised(serviceName string, run winservice.RunFunc) error {
	isSvc, err := winservice.IsService()
	if err != nil {
		return fmt.Errorf("determine service context: %w", err)
	}
	if isSvc {
		return winservice.RunAsService(serviceName, run)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}

// HandleServiceCommand dispatches `service <install|uninstall|start|stop|status>`.
// On install it registers the current executable with the supplied arguments.
func HandleServiceCommand(args []string, cfg winservice.Config) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: service <install|uninstall|start|stop>")
	}
	switch args[0] {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate executable: %w", err)
		}
		if err := winservice.Install(cfg, exe); err != nil {
			return err
		}
		fmt.Printf("service %q installed\n", cfg.Name)
		return nil
	case "uninstall", "remove":
		if err := winservice.Remove(cfg.Name); err != nil {
			return err
		}
		fmt.Printf("service %q removed\n", cfg.Name)
		return nil
	case "start":
		if err := winservice.Start(cfg.Name); err != nil {
			return err
		}
		fmt.Printf("service %q started\n", cfg.Name)
		return nil
	case "stop":
		if err := winservice.Stop(cfg.Name); err != nil {
			return err
		}
		fmt.Printf("service %q stopped\n", cfg.Name)
		return nil
	default:
		return fmt.Errorf("unknown service command %q", args[0])
	}
}
