package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Aleck59/rmm/internal/protocol"
)

// EnrollTokenSpec describes a new enrollment token.
type EnrollTokenSpec struct {
	Name        string
	GroupID     *int64
	AutoApprove bool
	MaxUses     *int32
	ExpiresAt   time.Time
}

// CreateEnrollmentToken stores the hash of a new enrollment token. The plain
// token is shown to the operator once and never persisted.
func (s *Store) CreateEnrollmentToken(ctx context.Context, spec EnrollTokenSpec, tokenHash []byte, displayPrefix, actor string) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var id int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO enrollment_tokens (name, token_hash, token_prefix, group_id, auto_approve, max_uses, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`,
		spec.Name, tokenHash, displayPrefix, spec.GroupID, spec.AutoApprove, spec.MaxUses, spec.ExpiresAt).
		Scan(&id); err != nil {
		return 0, fmt.Errorf("create enrollment token: %w", err)
	}
	if err := insertAudit(ctx, tx, auditEntry{
		ActorType: "system", ActorName: actor,
		Action: "enrollment_token.create", ObjectType: "enrollment_token", ObjectID: fmt.Sprint(id),
		Details: map[string]any{
			"name": spec.Name, "token_prefix": displayPrefix, "auto_approve": spec.AutoApprove,
			"max_uses": spec.MaxUses, "expires_at": spec.ExpiresAt,
		},
	}); err != nil {
		return 0, err
	}
	return id, tx.Commit(ctx)
}

// SetDeviceStatus changes a device's lifecycle status (approve, revoke,
// retire). Revoked devices keep their token hash so the agent receives an
// explicit 403 device_revoked and stops, rather than retrying on 401.
func (s *Store) SetDeviceStatus(ctx context.Context, deviceID int64, status, actor string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var prev string
	err = tx.QueryRow(ctx, `
		UPDATE devices d SET status = $2::device_status
		FROM (SELECT id, status::text AS prev FROM devices WHERE id = $1 FOR UPDATE) o
		WHERE d.id = o.id
		RETURNING o.prev`, deviceID, status).Scan(&prev)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("set device status: %w", err)
	}
	if err := insertAudit(ctx, tx, auditEntry{
		ActorType: "system", ActorName: actor,
		Action: "device.status", ObjectType: "device", ObjectID: fmt.Sprint(deviceID),
		Details: map[string]any{"before": prev, "after": status},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AgentConfig returns the collection configuration handed to agents
// (settings key "agent"), falling back to defaults for missing fields.
func (s *Store) AgentConfig(ctx context.Context) (protocol.AgentConfig, error) {
	cfg := protocol.DefaultAgentConfig()
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'agent'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read agent settings: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decode agent settings: %w", err)
	}
	return cfg, nil
}
