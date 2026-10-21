package handler

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func bumpSessionEpoch(ctx context.Context, pool sessionEpochExecer, userID uuid.UUID) error {
	_, err := pool.Exec(ctx, `UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1`, userID)
	return err
}

// sessionEpochExecer is the minimal Exec surface shared by *pgxpool.Pool and pgx.Tx so
// the epoch bump + cascade can run either standalone or inside a caller's transaction.
type sessionEpochExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// RevokeUserSessions bumps the user's session epoch and cascades credential revocation
// (A1 step 5/6): it revokes every API token attached to the user and removes the user's
// role_assignments. Call inside the same transaction that disables or deletes the user so
// the JWT invalidation, PAT revocation, and role teardown are atomic. Exported so the
// user-management handlers (disable / delete / password-change / role-change) can reuse it.
func RevokeUserSessions(ctx context.Context, tx sessionEpochExecer, userID uuid.UUID) error {
	if err := bumpSessionEpoch(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = now(), status = 'revoked'
		  WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM role_assignments WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM identity_sessions WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func SafeFilter(f string) string { return strings.ReplaceAll(f, "\n", "") }

func actorIPFromRequest(r *http.Request) net.IP {
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	return actorIP
}

// auditLoginFailure emits an auth.login.failed audit row (RSP-AUDIT-05) with the source IP,
// the attempted username, and a machine-readable reason so brute-force is visible to
// /audit/events and the SIEM. orgID/userID are nil for an unknown/unlinked identity. This
