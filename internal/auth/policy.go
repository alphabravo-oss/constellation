package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ---- A1: admin-configurable password policy + session/idle timeout ----
//
// SecurityPolicy is the per-org, runtime-mutable security policy that supersedes the
// hardcoded DefaultPasswordProfile (12ch/3-class/90d/5-history) and the deploy-time-only
// session/idle env knobs. It is stored as a single JSONB blob in the auth_policy table
// (migration 124) and surfaced through the auth/security-policy REST CRUD. It models the
// same knobs as NeuVector's CLUSPwdProfile (MinLen/expiration/history + SessionTimeout),
// adapted to Constellation's existing PasswordProfile shape (MinClasses rather than
// per-class minimum counts, which is what ValidatePassword already enforces).
//
// The hardcoded values remain the FALLBACK: DefaultSecurityPolicy() reproduces the legacy
// behaviour, and Load() returns it when an org has no row, so login/validation never
// hard-fails on a missing policy. Durations are carried on the wire as integer minutes/days
// (JSON has no duration type) and converted at the accessor boundary.
type SecurityPolicy struct {
	// Password strength / lifecycle knobs (map onto PasswordProfile).
	MinLength    int `json:"min_length"`
	MinClasses   int `json:"min_classes"`
	MaxAgeDays   int `json:"max_age_days"`  // 0 disables expiration (EnablePwdExpiration=false)
	HistoryDepth int `json:"history_depth"` // 0 disables reuse checking

	// Session lifetime knobs. SessionTimeoutMinutes is the absolute JWT TTL; IdleTimeoutMinutes
	// is the inactivity window (A7). Zero on either means "use the deploy-time default" so an
	// org that only cares about the password policy doesn't have to pin session timings.
	SessionTimeoutMinutes int `json:"session_timeout_minutes"`
	IdleTimeoutMinutes    int `json:"idle_timeout_minutes"`
}

// Policy bounds, mirroring NeuVector's UserIdleTimeoutMin/Max intent. These keep an admin
// from locking everyone out (idle 0) or pinning an effectively-infinite session.
const (
	minLengthFloor    = 1
	minLengthCeil     = 256
	maxClasses        = 4
	sessionMinutesMin = 5            // 5 minutes
	sessionMinutesMax = 30 * 24 * 60 // 30 days
	idleMinutesMin    = 1            // 1 minute
	idleMinutesMax    = 12 * 60      // 12 hours
	historyDepthCeil  = 32           // matches NeuVector _maxPwdHistoryCount
)

// DefaultSecurityPolicy is the built-in fallback: exactly the legacy hardcoded behaviour.
// Password knobs come from DefaultPasswordProfile (12ch/3-class/90d/5-history); the session
// knobs are zero, meaning "defer to the deploy-time JWT TTL + SESSION_IDLE_TIMEOUT env".
func DefaultSecurityPolicy() SecurityPolicy {
	p := DefaultPasswordProfile()
	return SecurityPolicy{
		MinLength:    p.MinLength,
		MinClasses:   p.MinClasses,
		MaxAgeDays:   int(p.MaxAge / (24 * time.Hour)),
		HistoryDepth: p.HistoryDepth,
		// Session/idle default to 0 => "use the env/JWT deploy-time value" (see SessionTTL/IdleTimeout).
	}
}

// PasswordProfile projects the policy onto the existing PasswordProfile the login/validation
// path already consumes, so callers can keep using ValidatePassword unchanged.
func (p SecurityPolicy) PasswordProfile() PasswordProfile {
	return PasswordProfile{
		MinLength:    p.MinLength,
		MinClasses:   p.MinClasses,
		MaxAge:       time.Duration(p.MaxAgeDays) * 24 * time.Hour,
		HistoryDepth: p.HistoryDepth,
	}
}

// SessionTTL returns the configured absolute session lifetime, or fallback when the policy
// leaves it unset (0). Callers pass the deploy-time default (JWT TTL) as fallback.
func (p SecurityPolicy) SessionTTL(fallback time.Duration) time.Duration {
	if p.SessionTimeoutMinutes <= 0 {
		return fallback
	}
	return time.Duration(p.SessionTimeoutMinutes) * time.Minute
}

// IdleTimeout returns the configured idle/inactivity window, or fallback when unset (0).
func (p SecurityPolicy) IdleTimeout(fallback time.Duration) time.Duration {
	if p.IdleTimeoutMinutes <= 0 {
		return fallback
	}
	return time.Duration(p.IdleTimeoutMinutes) * time.Minute
}

// ErrInvalidPolicy is returned by Validate for an out-of-range policy.
var ErrInvalidPolicy = errors.New("auth: invalid security policy")

// Validate enforces the field invariants. Called on every PUT (before persist) and on every
// load from the DB so a malformed row can never become the live policy (it falls back instead).
func (p SecurityPolicy) Validate() error {
	if p.MinLength < minLengthFloor || p.MinLength > minLengthCeil {
		return fmt.Errorf("%w: min_length must be between %d and %d", ErrInvalidPolicy, minLengthFloor, minLengthCeil)
	}
	if p.MinClasses < 0 || p.MinClasses > maxClasses {
		return fmt.Errorf("%w: min_classes must be between 0 and %d", ErrInvalidPolicy, maxClasses)
	}
	if p.MaxAgeDays < 0 {
		return fmt.Errorf("%w: max_age_days must be >= 0", ErrInvalidPolicy)
	}
	if p.HistoryDepth < 0 || p.HistoryDepth > historyDepthCeil {
		return fmt.Errorf("%w: history_depth must be between 0 and %d", ErrInvalidPolicy, historyDepthCeil)
	}
	// Session/idle are optional (0 => deploy-time default). When set they must be in range.
	if p.SessionTimeoutMinutes != 0 && (p.SessionTimeoutMinutes < sessionMinutesMin || p.SessionTimeoutMinutes > sessionMinutesMax) {
		return fmt.Errorf("%w: session_timeout_minutes must be 0 or between %d and %d", ErrInvalidPolicy, sessionMinutesMin, sessionMinutesMax)
	}
	if p.IdleTimeoutMinutes != 0 && (p.IdleTimeoutMinutes < idleMinutesMin || p.IdleTimeoutMinutes > idleMinutesMax) {
		return fmt.Errorf("%w: idle_timeout_minutes must be 0 or between %d and %d", ErrInvalidPolicy, idleMinutesMin, idleMinutesMax)
	}
	return nil
}

// --------------------------------- store ------------------------------------

// PolicyStore is the minimal pgx surface the policy store needs; *pgxpool.Pool satisfies it.
type PolicyStore interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// LoadSecurityPolicy returns the org's policy + its revision. When no row exists it returns
// DefaultSecurityPolicy() at revision 0 (the fallback), so callers at login/validation time
// can substitute LoadSecurityPolicy for the DefaultPasswordProfile constant with no other
// change. A stored-but-invalid row also degrades to the default rather than failing the login.
func LoadSecurityPolicy(ctx context.Context, s PolicyStore, orgID uuid.UUID) (SecurityPolicy, int64, error) {
	var raw json.RawMessage
	var rev int64
	err := s.QueryRow(ctx, `SELECT policy, revision FROM auth_policy WHERE org_id = $1`, orgID).Scan(&raw, &rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultSecurityPolicy(), 0, nil
	}
	if err != nil {
		return SecurityPolicy{}, 0, fmt.Errorf("auth: load policy: %w", err)
	}
	// Start from the default so an unset field in the stored blob inherits the legacy value.
	pol := DefaultSecurityPolicy()
	if err := json.Unmarshal(raw, &pol); err != nil {
		return DefaultSecurityPolicy(), rev, nil
	}
	if err := pol.Validate(); err != nil {
		// A malformed persisted row must never brick logins: fall back to the default.
		return DefaultSecurityPolicy(), rev, nil
	}
	return pol, rev, nil
}

// LoadPasswordProfile is the convenience the login/validation path uses in place of the
// DefaultPasswordProfile() constant: it loads the org's policy (falling back to the default)
// and projects it onto a PasswordProfile.
func LoadPasswordProfile(ctx context.Context, s PolicyStore, orgID uuid.UUID) PasswordProfile {
	pol, _, err := LoadSecurityPolicy(ctx, s, orgID)
	if err != nil {
		return DefaultPasswordProfile()
	}
	return pol.PasswordProfile()
}

// ErrPolicyRevisionConflict is returned by SaveSecurityPolicy when the row's current revision
// no longer matches the expectedRev the caller read (a concurrent PUT won the race). The caller
// re-loads, re-applies, and retries (HTTP 409).
var ErrPolicyRevisionConflict = errors.New("auth: policy revision conflict")

// SaveSecurityPolicy persists pol for org and bumps the revision. expectedRev is the revision
// the caller based its edit on (0 means "no row existed yet"); Save enforces it as an
// optimistic-concurrency precondition, mirroring syscfg.Save.
func SaveSecurityPolicy(ctx context.Context, s PolicyStore, orgID uuid.UUID, pol SecurityPolicy, expectedRev int64, updatedBy *uuid.UUID) (int64, error) {
	if err := pol.Validate(); err != nil {
		return 0, err
	}
	blob, err := json.Marshal(pol)
	if err != nil {
		return 0, err
	}
	var rev int64
	err = s.QueryRow(ctx, `
INSERT INTO auth_policy (org_id, policy, revision, updated_by, updated_at)
VALUES ($1, $2::jsonb, 1, $3, now())
ON CONFLICT (org_id) DO UPDATE
   SET policy = EXCLUDED.policy,
       revision = auth_policy.revision + 1,
       updated_by = EXCLUDED.updated_by,
       updated_at = now()
   WHERE auth_policy.revision = $4
RETURNING revision`, orgID, blob, updatedBy, expectedRev).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrPolicyRevisionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("auth: save policy: %w", err)
	}
	return rev, nil
}
