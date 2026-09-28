// Package agent implements the InvMon Windows agent. Stage 0 provides the
// process skeleton — configuration, logging, and a supervised run loop — so it
// can be installed and run as a service on every target OS. Metric collection,
// inventory and server communication arrive in Stage 1.
package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/Aleck59/rmm/internal/buildinfo"
)

// Agent is the running agent instance.
type Agent struct {
	cfg Config
	log *slog.Logger
}

// New constructs an Agent.
func New(cfg Config, log *slog.Logger) *Agent {
	return &Agent{cfg: cfg, log: log}
}

// Run executes the agent loop until ctx is canceled. In Stage 0 the loop only
// emits a heartbeat log line on each tick; collectors replace the placeholder
// in Stage 1.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("agent starting",
		"version", buildinfo.Version,
		"server_url", a.cfg.ServerURL,
		"has_enroll_token", a.cfg.EnrollToken != "",
	)
	if a.cfg.ServerURL == "" {
		a.log.Warn("server_url is not configured; running in idle mode")
	}

	const tick = 60 * time.Second
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("agent stopping")
			return nil
		case <-ticker.C:
			// Placeholder for the collect → buffer → send pipeline (Stage 1).
			a.log.Debug("collection tick")
		}
	}
}
