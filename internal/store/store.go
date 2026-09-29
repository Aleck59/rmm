// Package store is the PostgreSQL data layer of the InvMon server. The schema
// is created by the embedded, versioned migrations in migrations/ (0001_core
// is byte-identical to docs/db/schema.sql; CI enforces this).
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors returned by store operations. Callers map them to API responses.
var (
	ErrNotFound           = errors.New("not found")
	ErrInvalidEnrollToken = errors.New("enrollment token is invalid, expired, revoked or exhausted")
	ErrAlreadyEnrolled    = errors.New("agent is already enrolled")
	ErrDeviceRevoked      = errors.New("device is revoked or retired")
)

// Store wraps a pgx connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL and verifies the connection. Sessions run in
// UTC so date arithmetic (partition boundaries) is deterministic.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	cfg.ConnConfig.RuntimeParams["application_name"] = "invmon-server"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases all connections.
func (s *Store) Close() { s.pool.Close() }

// Ping checks database connectivity (used by /readyz).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Pool exposes the underlying pool (tests and ad-hoc queries).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// querier is satisfied by both *pgxpool.Pool and pgx.Tx.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// auditEntry is one append-only audit_log record.
type auditEntry struct {
	ActorType  string // user | agent | system
	ActorID    *int64
	ActorName  string
	Action     string
	ObjectType string
	ObjectID   string
	Result     string // success | failure
	IP         netip.Addr
	Details    map[string]any
}

func insertAudit(ctx context.Context, q querier, e auditEntry) error {
	details := []byte("{}")
	if e.Details != nil {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			return fmt.Errorf("encode audit details: %w", err)
		}
	}
	if e.Result == "" {
		e.Result = "success"
	}
	_, err := q.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_id, actor_name, action, object_type, object_id, result, ip, details)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9::jsonb)`,
		e.ActorType, e.ActorID, e.ActorName, e.Action, e.ObjectType, e.ObjectID, e.Result,
		inetOrNil(e.IP), string(details))
	if err != nil {
		return fmt.Errorf("insert audit record: %w", err)
	}
	return nil
}

// inetOrNil maps an invalid address to SQL NULL.
func inetOrNil(a netip.Addr) any {
	if !a.IsValid() {
		return nil
	}
	return a
}
