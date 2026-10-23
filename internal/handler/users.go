package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
		apiutil.WriteStatus(r.Context(), w, http.StatusServiceUnavailable, "db unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		apiutil.WriteStatus(r.Context(), w, http.StatusUnauthorized, "no subject")
		return
	}
	targetID, err := targetUserID(r)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad id")
		return
	}
	if targetID == subj.UserID {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "cannot disable yourself")
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "begin")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Scope to the caller's org so an admin cannot disable users in another tenant.
	tag, err := tx.Exec(r.Context(),
		`UPDATE users SET disabled = TRUE, updated_at = now() WHERE id = $1 AND org_id = $2`,
		targetID, subj.OrgID)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "disable user")
		return
	}
	if tag.RowsAffected() == 0 {
		apiutil.WriteStatus(r.Context(), w, http.StatusNotFound, "not found")
		return
	}
	if err := RevokeUserSessions(r.Context(), tx, targetID); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "revoke sessions")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "commit")
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
		apiutil.WriteStatus(r.Context(), w, http.StatusServiceUnavailable, "db unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		apiutil.WriteStatus(r.Context(), w, http.StatusUnauthorized, "no subject")
		return
	}
	targetID, err := targetUserID(r)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "bad id")
		return
	}
	if targetID == subj.UserID {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, "cannot delete yourself")
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "begin")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// Verify the target is in the caller's org before touching anything.
	var lockedID uuid.UUID
	err = tx.QueryRow(r.Context(),
		`SELECT id FROM users WHERE id = $1 AND org_id = $2 FOR UPDATE`,
		targetID, subj.OrgID).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		apiutil.WriteStatus(r.Context(), w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "lookup user")
		return
	}
	if err := RevokeUserSessions(r.Context(), tx, targetID); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "revoke sessions")
		return
	}
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM users WHERE id = $1 AND org_id = $2`, targetID, subj.OrgID); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "delete user")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "commit")
		return
	}
	h.logUserAction(r.Context(), subj.OrgID, subj.UserID, "user.delete", targetID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Users) auditUserActionTx(ctx context.Context, tx pgx.Tx, orgID, actorID uuid.UUID, action string, targetID uuid.UUID) error {
	if h.audit == nil {
		return errors.New("audit unavailable")
	}
	_, _, err := h.audit.LogInTx(ctx, tx, audit.Event{
		OrgID: &orgID, ActorID: &actorID, Action: action,
		TargetKind: "user", TargetID: targetID.String(),
	})
	return err
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
