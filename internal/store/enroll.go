package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// EnrollParams carries a validated enrollment request.
type EnrollParams struct {
	EnrollTokenHash  []byte
	DeviceTokenHash  []byte
	AgentUID         string // canonical UUID string
	AgentVersion     string
	Hostname         string
	Domain           string
	OSName           string
	OSVersion        string
	OSDisplayVersion string
	OSArch           string // x86 | x64 | arm64
	MachineGUID      string
	SMBIOSUUID       string // canonical UUID or "" when unknown
	SerialNumber     string
	RemoteIP         netip.Addr
}

// EnrollResult describes the enrolled device.
type EnrollResult struct {
	DeviceID   int64
	Status     string // active | pending
	Reenrolled bool   // true when an existing, never-seen agent re-enrolled
}

// Enroll validates the enrollment token and creates (or, for a lost
// response, re-issues the token of) the device identified by AgentUID.
//
// Idempotency rule: an existing agent_uid may re-enroll only while the device
// has never reported data (no device_state row). That covers the "response
// lost in transit" case without letting a leaked enrollment token be used to
// take over an established device's identity.
func (s *Store) Enroll(ctx context.Context, p EnrollParams) (EnrollResult, error) {
	var res EnrollResult
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var (
		tokenID     int64
		groupID     *int64
		autoApprove bool
		maxUses     *int32
		usedCount   int32
		expiresAt   time.Time
		revokedAt   *time.Time
		tokenPrefix string
	)
	err = tx.QueryRow(ctx, `
		SELECT id, group_id, auto_approve, max_uses, used_count, expires_at, revoked_at, token_prefix
		FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE`, p.EnrollTokenHash).
		Scan(&tokenID, &groupID, &autoApprove, &maxUses, &usedCount, &expiresAt, &revokedAt, &tokenPrefix)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, ErrInvalidEnrollToken
	}
	if err != nil {
		return res, fmt.Errorf("look up enrollment token: %w", err)
	}
	if revokedAt != nil || !expiresAt.After(time.Now()) {
		return res, ErrInvalidEnrollToken
	}

	var (
		existingID     int64
		existingStatus string
		hasState       bool
	)
	err = tx.QueryRow(ctx, `
		SELECT d.id, d.status::text,
		       EXISTS (SELECT 1 FROM device_state s WHERE s.device_id = d.id)
		FROM devices d WHERE d.agent_uid = $1::uuid FOR UPDATE OF d`, p.AgentUID).
		Scan(&existingID, &existingStatus, &hasState)
	switch {
	case err == nil:
		if existingStatus == "revoked" || existingStatus == "retired" {
			return res, ErrDeviceRevoked
		}
		if hasState {
			return res, ErrAlreadyEnrolled
		}
		err = tx.QueryRow(ctx, `
			UPDATE devices SET
				token_hash = $2, token_issued_at = now(),
				prev_token_hash = NULL, prev_token_expires_at = NULL,
				hostname = $3, domain = NULLIF($4, ''),
				os_name = $5, os_version = $6, os_display_version = NULLIF($7, ''),
				os_arch = NULLIF($8, ''), agent_version = $9
			WHERE id = $1
			RETURNING status::text`,
			existingID, p.DeviceTokenHash, p.Hostname, p.Domain,
			p.OSName, p.OSVersion, p.OSDisplayVersion, p.OSArch, p.AgentVersion).Scan(&res.Status)
		if err != nil {
			return res, fmt.Errorf("re-issue device token: %w", err)
		}
		res.DeviceID, res.Reenrolled = existingID, true

	case errors.Is(err, pgx.ErrNoRows):
		if maxUses != nil && usedCount >= *maxUses {
			return res, ErrInvalidEnrollToken
		}
		status := "active"
		if !autoApprove {
			status = "pending"
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO devices (agent_uid, status, hostname, domain, group_id,
			                     machine_guid, smbios_uuid, serial_number,
			                     os_name, os_version, os_display_version, os_arch, agent_version,
			                     token_hash, token_issued_at, enrolled_via)
			VALUES ($1::uuid, $2::device_status, $3, NULLIF($4, ''), $5,
			        NULLIF($6, ''), $7::uuid, NULLIF($8, ''),
			        $9, $10, NULLIF($11, ''), NULLIF($12, ''), $13,
			        $14, now(), $15)
			RETURNING id, status::text`,
			p.AgentUID, status, p.Hostname, p.Domain, groupID,
			p.MachineGUID, uuidOrNil(p.SMBIOSUUID), p.SerialNumber,
			p.OSName, p.OSVersion, p.OSDisplayVersion, p.OSArch, p.AgentVersion,
			p.DeviceTokenHash, tokenID).Scan(&res.DeviceID, &res.Status)
		if err != nil {
			return res, fmt.Errorf("create device: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE enrollment_tokens SET used_count = used_count + 1 WHERE id = $1`, tokenID); err != nil {
			return res, fmt.Errorf("count enrollment token use: %w", err)
		}

	default:
		return res, fmt.Errorf("look up device: %w", err)
	}

	id := res.DeviceID
	if err := insertAudit(ctx, tx, auditEntry{
		ActorType: "agent", ActorID: &id, ActorName: p.Hostname,
		Action: "agent.enroll", ObjectType: "device", ObjectID: fmt.Sprint(id),
		IP: p.RemoteIP,
		Details: map[string]any{
			"token_prefix": tokenPrefix,
			"status":       res.Status,
			"reenrolled":   res.Reenrolled,
			"agent_uid":    p.AgentUID,
		},
	}); err != nil {
		return res, err
	}
	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("commit enrollment: %w", err)
	}
	return res, nil
}

// AuditEnrollFailure records a rejected enrollment attempt. The HTTP layer
// rate-limits enrollment per IP, which bounds how fast this table can grow.
func (s *Store) AuditEnrollFailure(ctx context.Context, hostname string, ip netip.Addr, reason string) error {
	return insertAudit(ctx, s.pool, auditEntry{
		ActorType: "agent", ActorName: truncate(hostname, 255),
		Action: "agent.enroll", ObjectType: "device", Result: "failure", IP: ip,
		Details: map[string]any{"reason": reason},
	})
}

// Device is the authenticated identity behind a device token.
type Device struct {
	ID       int64
	Status   string
	Hostname string
}

// DeviceByToken resolves a device from the SHA-256 of its bearer token,
// accepting the previous token until its overlap window expires.
func (s *Store) DeviceByToken(ctx context.Context, tokenHash []byte) (Device, error) {
	var d Device
	err := s.pool.QueryRow(ctx, `
		SELECT id, status::text, hostname FROM devices
		WHERE token_hash = $1
		   OR (prev_token_hash = $1 AND prev_token_expires_at > now())`, tokenHash).
		Scan(&d.ID, &d.Status, &d.Hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, fmt.Errorf("look up device token: %w", err)
	}
	return d, nil
}

// RotateDeviceToken installs a new token and keeps the current one valid for
// the overlap period, so a lost response does not lock the agent out.
func (s *Store) RotateDeviceToken(ctx context.Context, deviceID int64, newHash []byte, overlap time.Duration, ip netip.Addr) (time.Time, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var (
		validUntil time.Time
		hostname   string
	)
	err = tx.QueryRow(ctx, `
		UPDATE devices SET
			prev_token_hash = token_hash,
			prev_token_expires_at = now() + make_interval(secs => $3::double precision),
			token_hash = $2,
			token_issued_at = now()
		WHERE id = $1
		RETURNING prev_token_expires_at, hostname`,
		deviceID, newHash, overlap.Seconds()).Scan(&validUntil, &hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("rotate device token: %w", err)
	}
	id := deviceID
	if err := insertAudit(ctx, tx, auditEntry{
		ActorType: "agent", ActorID: &id, ActorName: hostname,
		Action: "agent.token_rotate", ObjectType: "device", ObjectID: fmt.Sprint(id), IP: ip,
	}); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	return validUntil, nil
}

func uuidOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
