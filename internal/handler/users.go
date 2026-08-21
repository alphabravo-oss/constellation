package handler

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Users is the RBAC-gated user-management handler (A1/A4): disable, delete, and force a
// password reset on a user. Every mutation that revokes access runs the revocation cascade
// (RevokeUserSessions) inside the SAME transaction as the state change, so the session-epoch
// bump, PAT revocation, role_assignments teardown, and user_sessions purge are atomic with
// the disable/delete/reset — closing the gap where those primitives were implemented but
// never wired to an actual operation.
type Users struct {
	db    *db.DB
	audit *audit.Logger
}

// NewUsers builds the user-management handler.
func NewUsers(database *db.DB, auditLog *audit.Logger) *Users {
	return &Users{db: database, audit: auditLog}
}

// targetUserID parses the {id} path param.
func targetUserID(r *http.Request) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, "id"))
}

// Disable sets users.disabled = TRUE for a user in the caller's org and cascade-revokes all
// of the user's credentials in one transaction (A1 step 4/5): bumps session_epoch (live JWTs
// rejected on next request), revokes the user's PATs, removes role_assignments, and purges
// user_sessions. Idempotent — disabling an already-disabled user still re-runs the cascade.
func (h *Users) Disable(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "db unavailable"})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}
	targetID, err := targetUserID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	if targetID == subj.UserID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot disable yourself"})
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "begin"})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Scope to the caller's org so an admin cannot disable users in another tenant.
	tag, err := tx.Exec(r.Context(),
		`UPDATE users SET disabled = TRUE, updated_at = now() WHERE id = $1 AND org_id = $2`,
		targetID, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "disable user"})
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err := RevokeUserSessions(r.Context(), tx, targetID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revoke sessions"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit"})
		return
	}
	h.logUserAction(r.Context(), subj.OrgID, subj.UserID, "user.disable", targetID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// Delete removes a user in the caller's org. The revocation cascade runs in the same
// transaction before the DELETE so PATs are tombstoned (revoked_at/status) and the epoch is
// bumped even though the FK cascades would drop the rows anyway — this keeps the audit trail
// consistent and ensures any in-flight JWT is rejected the instant the tx commits.
func (h *Users) Delete(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "db unavailable"})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}
	targetID, err := targetUserID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	if targetID == subj.UserID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete yourself"})
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "begin"})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Verify the target is in the caller's org before touching anything.
	var exists bool
	if err := tx.QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND org_id = $2)`,
		targetID, subj.OrgID).Scan(&exists); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup user"})
		return
	}
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err := RevokeUserSessions(r.Context(), tx, targetID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revoke sessions"})
		return
	}
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM users WHERE id = $1 AND org_id = $2`, targetID, subj.OrgID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete user"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit"})
		return
	}
	h.logUserAction(r.Context(), subj.OrgID, subj.UserID, "user.delete", targetID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ForcePasswordReset sets users.must_change_password = TRUE for a user in the caller's org and
// bumps session_epoch + revokes the user's PATs in the same transaction (A4). After this the
// user's live JWTs are rejected, the user is forced through change-password on next login, and
// the PAT path (also gated on must_change_password) cannot be used to sidestep the reset.
func (h *Users) ForcePasswordReset(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "db unavailable"})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}
	targetID, err := targetUserID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "begin"})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	tag, err := tx.Exec(r.Context(), `
UPDATE users
   SET must_change_password = TRUE,
       session_epoch = session_epoch + 1,
       updated_at = now()
 WHERE id = $1 AND org_id = $2 AND password_hash IS NOT NULL`,
		targetID, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reset password"})
		return
	}
	if tag.RowsAffected() == 0 {
		// Either no such user in the org, or the user has no local password (SSO-only); a
		// forced local-password reset does not apply to an SSO-only account.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no local-password user"})
		return
	}
	// Revoke the target's PATs too so the reset cannot be sidestepped by an existing token.
	if _, err := tx.Exec(r.Context(),
		`UPDATE api_tokens SET revoked_at = now(), status = 'revoked'
		  WHERE user_id = $1 AND revoked_at IS NULL`, targetID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revoke tokens"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit"})
		return
	}
	h.logUserAction(r.Context(), subj.OrgID, subj.UserID, "user.force_password_reset", targetID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset_required"})
}

// Unlock clears a user's brute-force lockout (AUTH-LOCKOUT-17): it zeroes failed_login_count
// and NULLs block_login_since for a user in the caller's org, so an account locked by repeated
// failed logins can be restored without waiting out the lockout window. Scoped to the caller's
// org so an admin cannot unlock users in another tenant. Idempotent — unlocking a non-locked
// user is a no-op that still returns 200. Gated by rbac.VerbManageUsers in the router.
//
// ROUTE (add to internal/server/server.go alongside the other /users/{id}/... routes, e.g. after
// the force-password-reset line ~942):
//
//	r.Post("/users/{id}/unlock", s.requireVerb(rbac.VerbManageUsers, users.Unlock))
func (h *Users) Unlock(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "db unavailable"})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}
	targetID, err := targetUserID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE users
   SET failed_login_count = 0,
       block_login_since = NULL,
       updated_at = now()
 WHERE id = $1 AND org_id = $2`, targetID, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unlock user"})
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	h.logUserAction(r.Context(), subj.OrgID, subj.UserID, "user.unlock", targetID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

func (h *Users) logUserAction(ctx context.Context, orgID, actorID uuid.UUID, action string, targetID uuid.UUID) {
	if h.audit == nil {
		return
	}
	oid, aid := orgID, actorID
	_, _, _ = h.audit.Log(ctx, audit.Event{
		OrgID: &oid, ActorID: &aid, Action: action,
		TargetKind: "user", TargetID: targetID.String(),
	})
}
