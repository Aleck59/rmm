// Package agent implements the InvMon Windows agent: enrollment, host-metric
// collection and delivery to the server. The agent only initiates outbound
// HTTPS requests; it opens no ports and executes nothing on the server's
// behalf in this stage.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Aleck59/rmm/internal/buildinfo"
	"github.com/Aleck59/rmm/internal/protocol"
)

// Queue and batch bounds.
const (
	maxQueuedHost = 1440     // 24 h of one-minute samples
	maxQueuedDisk = 26 * 288 // 24 h of five-minute samples for 26 volumes
	maxBatch      = 1000     // server-side per-array limit
	maxErrors     = 50
)

// Options tune the agent; zero values mean production defaults.
type Options struct {
	// ConfigPath is agent.yaml; used to scrub the enrollment token.
	ConfigPath string
	// Collector overrides the platform collector (tests).
	Collector Collector
	// Now overrides the clock (tests).
	Now func() time.Time
	// Interval overrides; zero uses the server-provided configuration.
	SendInterval, SampleInterval, DiskInterval time.Duration
	// RetryDelay is the base retry delay (default 30 s). Longer pauses are
	// multiples: invalid token 120× (1 h), pending approval 10× (5 min),
	// revoked 2880× (24 h).
	RetryDelay time.Duration
}

// Agent is the running agent instance.
type Agent struct {
	cfg       Config
	log       *slog.Logger
	opts      Options
	collector Collector
	client    *Client
	dataDir   string
	started   time.Time

	state  State
	remote protocol.AgentConfig

	host        []protocol.HostSample
	disks       []protocol.DiskSample
	cpuSum      float64
	cpuMax      float64
	cpuN        int
	lastDisk    time.Time
	collectErrs []protocol.CollectorError
	pauseUntil  time.Time
	revoked     bool
}

// New constructs an Agent.
func New(cfg Config, log *slog.Logger, opts Options) *Agent {
	if opts.Collector == nil {
		opts.Collector = NewCollector()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.RetryDelay <= 0 {
		opts.RetryDelay = 30 * time.Second
	}
	dataDir := cfg.DataDir
	if dataDir == "" {
		if opts.ConfigPath != "" {
			dataDir = filepath.Dir(opts.ConfigPath)
		} else {
			dataDir = defaultDataDir()
		}
	}
	return &Agent{
		cfg: cfg, log: log, opts: opts, collector: opts.Collector,
		dataDir: dataDir, remote: protocol.DefaultAgentConfig(),
	}
}

func userAgent() string {
	si := collectSysInfo()
	return fmt.Sprintf("InvMonAgent/%s (%s %s; %s)", buildinfo.Version, runtime.GOOS, si.OSVersion, si.Arch)
}

// Run executes the agent until ctx is canceled.
func (a *Agent) Run(ctx context.Context) error {
	a.started = a.opts.Now()
	a.log.Info("agent starting", "version", buildinfo.Version, "server_url", a.cfg.ServerURL, "data_dir", a.dataDir)
	if a.cfg.ServerURL == "" {
		a.log.Warn("server_url is not configured; running in idle mode")
		<-ctx.Done()
		return nil
	}
	client, err := NewClient(a.cfg, userAgent())
	if err != nil {
		return err
	}
	a.client = client

	if err := a.loadIdentity(); err != nil {
		return err
	}
	if err := a.ensureEnrolled(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	a.refreshConfig(ctx)

	sample := time.NewTicker(a.sampleInterval())
	send := time.NewTicker(a.sendInterval())
	defer sample.Stop()
	defer send.Stop()
	a.sample() // prime CPU counters

	for {
		select {
		case <-ctx.Done():
			a.log.Info("agent stopping")
			return nil
		case <-sample.C:
			a.sample()
		case <-send.C:
			if a.flush(ctx) {
				sample.Reset(a.sampleInterval())
				send.Reset(a.sendInterval())
			}
		}
	}
}

// loadIdentity reads state.bin and creates the agent_uid on first start.
func (a *Agent) loadIdentity() error {
	st, err := loadState(a.dataDir)
	if err != nil {
		return err
	}
	if st.AgentUID == "" {
		if st.AgentUID, err = newUUID(); err != nil {
			return err
		}
		if err := saveState(a.dataDir, st); err != nil {
			return err
		}
	}
	a.state = st
	return nil
}

func (a *Agent) ensureEnrolled(ctx context.Context) error {
	for !a.state.Enrolled() {
		if a.cfg.EnrollToken == "" {
			return errors.New("agent is not enrolled and enroll_token is not configured")
		}
		err := a.enroll(ctx)
		if err == nil {
			return nil
		}
		delay := a.opts.RetryDelay
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			switch {
			case apiErr.Status == 409:
				return fmt.Errorf("enrollment refused: %w (this agent_uid already reported data; reinstall the agent)", err)
			case apiErr.Status == 401, apiErr.Status == 403:
				delay = 120 * a.opts.RetryDelay
			case apiErr.Status == 429 && apiErr.RetryAfter > 0:
				delay = apiErr.RetryAfter
			}
		}
		a.log.Warn("enrollment failed; will retry", "err", err, "retry_in", delay.String())
		if !sleepCtx(ctx, delay) {
			return ctx.Err()
		}
	}
	return nil
}

func (a *Agent) enroll(ctx context.Context) error {
	si := collectSysInfo()
	req := protocol.EnrollRequest{
		AgentUID:     a.state.AgentUID,
		AgentVersion: truncateRunes(buildinfo.Version, 32),
		Hostname:     si.Hostname,
		Domain:       si.Domain,
		OS: protocol.OSInfo{
			Name: si.OSName, Version: si.OSVersion, Build: si.Build, UBR: si.UBR,
			DisplayVersion: si.OSDisplayVersion, Arch: si.Arch,
		},
		HardwareIDs: protocol.HardwareIDs{MachineGUID: si.MachineGUID},
	}
	resp, err := a.client.Enroll(ctx, a.cfg.EnrollToken, req)
	if err != nil {
		return err
	}
	st := a.state
	st.DeviceID, st.DeviceToken = resp.DeviceID, resp.DeviceToken
	// Persist before sending any data: a device that reported data can no
	// longer re-enroll, so losing the token afterwards would orphan it.
	if err := saveState(a.dataDir, st); err != nil {
		return fmt.Errorf("persist device token: %w", err)
	}
	a.state = st
	a.remote = resp.Config
	if err := scrubEnrollToken(a.opts.ConfigPath); err != nil {
		a.log.Warn("could not remove enroll_token from config file", "err", err)
	}
	a.cfg.EnrollToken = ""
	a.log.Info("enrolled", "device_id", resp.DeviceID, "status", resp.Status)
	if resp.Status == "pending" {
		a.log.Warn("device is pending approval by an administrator")
	}
	return nil
}

func (a *Agent) refreshConfig(ctx context.Context) {
	cfg, err := a.client.GetConfig(ctx, a.state.DeviceToken)
	if err != nil {
		a.log.Warn("could not fetch configuration; keeping current", "err", err)
		return
	}
	a.remote = cfg
}

// sample adds one CPU reading to the current averaging window.
func (a *Agent) sample() {
	cpu, err := a.collector.CPUPercent()
	if errors.Is(err, errPriming) {
		return
	}
	if err != nil {
		a.noteErr("cpu", err)
		return
	}
	a.cpuSum += cpu
	a.cpuN++
	if cpu > a.cpuMax {
		a.cpuMax = cpu
	}
}

// flush closes the averaging window, collects volumes when due, and sends
// the queue. It reports whether the server configuration changed.
func (a *Agent) flush(ctx context.Context) bool {
	now := a.opts.Now().UTC()
	if a.cpuN > 0 {
		used, total, err := a.collector.Memory()
		switch {
		case err != nil:
			a.noteErr("memory", err)
		case total > 0:
			a.host = append(a.host, protocol.HostSample{
				TS:            now.Truncate(time.Second),
				CPUPct:        round1(a.cpuSum / float64(a.cpuN)),
				CPUMaxPct:     round1(a.cpuMax),
				MemUsedBytes:  int64(used),
				MemTotalBytes: int64(total),
			})
		}
		a.cpuSum, a.cpuMax, a.cpuN = 0, 0, 0
	}
	if now.Sub(a.lastDisk) >= a.diskInterval() {
		vols, err := a.collector.Volumes()
		if err != nil {
			a.noteErr("disk", err)
		} else {
			for _, v := range vols {
				a.disks = append(a.disks, protocol.DiskSample{
					TS: now.Truncate(time.Second), Volume: v.Name, TotalBytes: int64(v.Total), FreeBytes: int64(v.Free),
				})
			}
			a.lastDisk = now
		}
	}
	a.host = keepNewest(a.host, maxQueuedHost)
	a.disks = keepNewest(a.disks, maxQueuedDisk)

	if now.Before(a.pauseUntil) {
		return false
	}
	return a.send(ctx, now)
}

func (a *Agent) send(ctx context.Context, now time.Time) bool {
	nh, nd := min(len(a.host), maxBatch), min(len(a.disks), maxBatch)
	batch := protocol.MetricsBatch{
		SentAt: now,
		Host:   a.host[:nh],
		Disks:  a.disks[:nd],
		Agent:  a.health(now),
	}
	if boot, err := a.collector.BootTime(); err == nil {
		batch.BootTime = &boot
	}
	resp, err := a.client.PostMetrics(ctx, a.state.DeviceToken, batch)
	if err != nil {
		a.handleSendError(err, nh, nd, now)
		return false
	}
	a.revoked = false
	a.host, a.disks, a.collectErrs = a.host[nh:], a.disks[nd:], nil

	if resp.RotateToken {
		a.rotateToken(ctx)
	}
	if resp.InventoryRequested {
		a.log.Info("server requested an inventory refresh (inventory collection arrives in a later stage)")
	}
	if resp.ConfigVersion != a.remote.ConfigVersion {
		a.refreshConfig(ctx)
		return true
	}
	return false
}

func (a *Agent) handleSendError(err error, nh, nd int, now time.Time) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		a.log.Warn("metrics delivery failed; data kept for retry", "err", err, "queued", len(a.host))
		a.pauseUntil = now.Add(a.opts.RetryDelay)
		return
	}
	switch {
	case apiErr.Status == 400 || apiErr.Status == 413:
		// A poison batch would block the queue forever: drop it.
		a.log.Error("server rejected metrics batch; dropping it", "err", err, "host", nh, "disks", nd)
		a.host, a.disks = a.host[nh:], a.disks[nd:]
	case apiErr.Status == 401:
		a.log.Error("device token rejected; pausing", "err", err)
		a.pauseUntil = now.Add(120 * a.opts.RetryDelay)
	case apiErr.Code == protocol.CodePendingApproval:
		a.log.Info("device is pending approval; will retry")
		a.pauseUntil = now.Add(10 * a.opts.RetryDelay)
	case apiErr.Status == 403:
		if !a.revoked {
			a.log.Warn("device has been revoked by an administrator; stopping data delivery")
		}
		a.revoked = true
		a.host, a.disks = nil, nil
		a.pauseUntil = now.Add(2880 * a.opts.RetryDelay)
	case apiErr.Status == 429:
		delay := apiErr.RetryAfter
		if delay <= 0 {
			delay = a.opts.RetryDelay
		}
		a.pauseUntil = now.Add(delay)
	default:
		a.log.Warn("server error; data kept for retry", "err", err)
		a.pauseUntil = now.Add(a.opts.RetryDelay)
	}
}

func (a *Agent) rotateToken(ctx context.Context) {
	resp, err := a.client.RotateToken(ctx, a.state.DeviceToken)
	if err != nil {
		a.log.Warn("token rotation failed; will retry on a later request", "err", err)
		return
	}
	st := a.state
	st.DeviceToken = resp.DeviceToken
	if err := saveState(a.dataDir, st); err != nil {
		// The old token stays valid until PreviousValidUntil; keep using the
		// new one in memory and let the next rotation persist it.
		a.log.Error("could not persist rotated token", "err", err)
	}
	a.state = st
	a.log.Info("device token rotated")
}

func (a *Agent) health(now time.Time) *protocol.AgentHealth {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	h := &protocol.AgentHealth{
		Version:    truncateRunes(buildinfo.Version, 32),
		SpoolItems: len(a.host),
		RSSBytes:   int64(ms.Sys),
		Errors:     a.collectErrs,
	}
	if !a.started.IsZero() {
		h.UptimeS = int64(now.Sub(a.started).Seconds())
	}
	return h
}

func (a *Agent) noteErr(collector string, err error) {
	now := a.opts.Now().UTC()
	a.collectErrs = append(a.collectErrs, protocol.CollectorError{
		Collector: collector, Message: truncateRunes(err.Error(), 500), At: &now,
	})
	a.collectErrs = keepNewest(a.collectErrs, maxErrors)
	a.log.Warn("collector error", "collector", collector, "err", err)
}

// Interval resolution: explicit overrides win; server values are clamped to
// sane minimums so a bad setting cannot turn agents into a flood.
func (a *Agent) sendInterval() time.Duration {
	return pick(a.opts.SendInterval, a.remote.MetricsSendIntervalS, 30, 60)
}
func (a *Agent) sampleInterval() time.Duration {
	return pick(a.opts.SampleInterval, a.remote.CPUSampleIntervalS, 5, 15)
}
func (a *Agent) diskInterval() time.Duration {
	return pick(a.opts.DiskInterval, a.remote.DiskIntervalS, 60, 300)
}

func pick(override time.Duration, serverSecs, minSecs, defSecs int) time.Duration {
	if override > 0 {
		return override
	}
	switch {
	case serverSecs <= 0:
		serverSecs = defSecs
	case serverSecs < minSecs:
		serverSecs = minSecs
	}
	return time.Duration(serverSecs) * time.Second
}

func keepNewest[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
