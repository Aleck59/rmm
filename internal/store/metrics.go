package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// HostSample is a validated host metrics sample (server clock).
type HostSample struct {
	TS       time.Time
	CPU      float32
	CPUMax   float32
	MemUsed  int64
	MemTotal int64
}

// DiskSample is a validated volume sample (server clock).
type DiskSample struct {
	TS     time.Time
	Volume string
	Total  int64
	Free   int64
}

// IngestParams is one validated metrics batch.
type IngestParams struct {
	DeviceID      int64
	Host          []HostSample
	Disks         []DiskSample
	RemoteIP      netip.Addr
	BootTime      *time.Time
	LoggedOnUser  *string
	ClockSkewS    int
	AgentVersion  string
	AgentUptimeS  *int64
	AgentRSSBytes *int64
	AgentErrors   []byte // JSON array; nil means "[]"
}

// IngestResult tells the handler what to report back to the agent.
type IngestResult struct {
	InventoryRequested bool
	RotateToken        bool
	ConfigVersion      int
}

// TokenRotationAge is how old a device token may get before the server asks
// the agent to rotate it.
const TokenRotationAge = 90 * 24 * time.Hour

// IngestMetrics stores a batch in one transaction: raw samples (idempotent on
// the primary key, so a re-sent batch is harmless), the latest volume state,
// and the per-device "hot" state row.
func (s *Store) IngestMetrics(ctx context.Context, p IngestParams) (IngestResult, error) {
	var res IngestResult
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if n := len(p.Host); n > 0 {
		ts := make([]time.Time, n)
		cpu := make([]float32, n)
		cpuMax := make([]float32, n)
		used := make([]int64, n)
		total := make([]int64, n)
		for i, h := range p.Host {
			ts[i], cpu[i], cpuMax[i], used[i], total[i] = h.TS, h.CPU, h.CPUMax, h.MemUsed, h.MemTotal
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO metrics_host (device_id, ts, cpu_pct, cpu_max_pct, mem_used_bytes, mem_total_bytes)
			SELECT $1, t.ts, t.cpu, t.cpu_max, t.mem_used, t.mem_total
			FROM unnest($2::timestamptz[], $3::real[], $4::real[], $5::bigint[], $6::bigint[])
			     AS t(ts, cpu, cpu_max, mem_used, mem_total)
			ON CONFLICT (device_id, ts) DO NOTHING`,
			p.DeviceID, ts, cpu, cpuMax, used, total); err != nil {
			return res, fmt.Errorf("insert host metrics: %w", err)
		}
	}

	if n := len(p.Disks); n > 0 {
		ts := make([]time.Time, n)
		vol := make([]string, n)
		total := make([]int64, n)
		free := make([]int64, n)
		for i, d := range p.Disks {
			ts[i], vol[i], total[i], free[i] = d.TS, d.Volume, d.Total, d.Free
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO metrics_disk (device_id, ts, volume, total_bytes, free_bytes)
			SELECT $1, t.ts, t.volume, t.total, t.free
			FROM unnest($2::timestamptz[], $3::text[], $4::bigint[], $5::bigint[])
			     AS t(ts, volume, total, free)
			ON CONFLICT (device_id, volume, ts) DO NOTHING`,
			p.DeviceID, ts, vol, total, free); err != nil {
			return res, fmt.Errorf("insert disk metrics: %w", err)
		}

		// Latest sample per volume → device_volumes. One row per volume per
		// statement (ON CONFLICT cannot touch a row twice), and older replayed
		// samples never overwrite newer state.
		latest := latestPerVolume(p.Disks)
		lv := make([]string, 0, len(latest))
		lt := make([]int64, 0, len(latest))
		lf := make([]int64, 0, len(latest))
		lts := make([]time.Time, 0, len(latest))
		for _, d := range latest {
			lv, lt, lf, lts = append(lv, d.Volume), append(lt, d.Total), append(lf, d.Free), append(lts, d.TS)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_volumes (device_id, volume, total_bytes, free_bytes, updated_at)
			SELECT $1, t.volume, t.total, t.free, t.ts
			FROM unnest($2::text[], $3::bigint[], $4::bigint[], $5::timestamptz[]) AS t(volume, total, free, ts)
			ON CONFLICT (device_id, volume) DO UPDATE
			SET total_bytes = EXCLUDED.total_bytes,
			    free_bytes  = EXCLUDED.free_bytes,
			    updated_at  = EXCLUDED.updated_at
			WHERE device_volumes.updated_at <= EXCLUDED.updated_at`,
			p.DeviceID, lv, lt, lf, lts); err != nil {
			return res, fmt.Errorf("update volumes: %w", err)
		}
	}

	var cpu, memPct *float32
	var memTotal *int64
	if h, ok := latestHost(p.Host); ok {
		c := h.CPU
		m := float32(float64(h.MemUsed) * 100 / float64(h.MemTotal))
		t := h.MemTotal
		cpu, memPct, memTotal = &c, &m, &t
	}
	agentErrors := p.AgentErrors
	if agentErrors == nil {
		agentErrors = []byte("[]")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_state (device_id, last_seen_at, last_ip, boot_time, logged_on_user,
		                          cpu_pct, mem_used_pct, mem_total_bytes, min_disk_free_pct,
		                          clock_skew_s, agent_uptime_s, agent_rss_bytes, agent_errors)
		VALUES ($1, now(), $2, $3, $4, $5, $6, $7,
		        (SELECT min(free_pct) FROM device_volumes WHERE device_id = $1),
		        $8, $9, $10, $11::jsonb)
		ON CONFLICT (device_id) DO UPDATE SET
			last_seen_at      = EXCLUDED.last_seen_at,
			last_ip           = EXCLUDED.last_ip,
			boot_time         = COALESCE(EXCLUDED.boot_time, device_state.boot_time),
			logged_on_user    = EXCLUDED.logged_on_user,
			cpu_pct           = COALESCE(EXCLUDED.cpu_pct, device_state.cpu_pct),
			mem_used_pct      = COALESCE(EXCLUDED.mem_used_pct, device_state.mem_used_pct),
			mem_total_bytes   = COALESCE(EXCLUDED.mem_total_bytes, device_state.mem_total_bytes),
			min_disk_free_pct = EXCLUDED.min_disk_free_pct,
			clock_skew_s      = EXCLUDED.clock_skew_s,
			agent_uptime_s    = EXCLUDED.agent_uptime_s,
			agent_rss_bytes   = EXCLUDED.agent_rss_bytes,
			agent_errors      = EXCLUDED.agent_errors`,
		p.DeviceID, inetOrNil(p.RemoteIP), p.BootTime, p.LoggedOnUser,
		cpu, memPct, memTotal, p.ClockSkewS, p.AgentUptimeS, p.AgentRSSBytes, string(agentErrors)); err != nil {
		return res, fmt.Errorf("update device state: %w", err)
	}

	// Cold-table writes only when something actually changed: devices is not
	// rewritten on every heartbeat.
	if p.AgentVersion != "" {
		if _, err := tx.Exec(ctx,
			`UPDATE devices SET agent_version = $2 WHERE id = $1 AND agent_version IS DISTINCT FROM $2`,
			p.DeviceID, p.AgentVersion); err != nil {
			return res, fmt.Errorf("update agent version: %w", err)
		}
	}
	err = tx.QueryRow(ctx,
		`UPDATE devices SET inventory_requested = false WHERE id = $1 AND inventory_requested RETURNING true`,
		p.DeviceID).Scan(&res.InventoryRequested)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return res, fmt.Errorf("read inventory flag: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(token_issued_at < now() - make_interval(secs => $2::double precision), false)
		FROM devices WHERE id = $1`, p.DeviceID, TokenRotationAge.Seconds()).Scan(&res.RotateToken); err != nil {
		return res, fmt.Errorf("check token age: %w", err)
	}
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE((SELECT (value->>'config_version')::int FROM settings WHERE key = 'agent'), 0)`).
		Scan(&res.ConfigVersion); err != nil {
		return res, fmt.Errorf("read config version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("commit metrics: %w", err)
	}
	return res, nil
}

func latestHost(h []HostSample) (HostSample, bool) {
	if len(h) == 0 {
		return HostSample{}, false
	}
	best := h[0]
	for _, s := range h[1:] {
		if s.TS.After(best.TS) {
			best = s
		}
	}
	return best, true
}

func latestPerVolume(d []DiskSample) []DiskSample {
	idx := map[string]int{}
	var out []DiskSample
	for _, s := range d {
		if i, ok := idx[s.Volume]; ok {
			if s.TS.After(out[i].TS) {
				out[i] = s
			}
			continue
		}
		idx[s.Volume] = len(out)
		out = append(out, s)
	}
	return out
}
