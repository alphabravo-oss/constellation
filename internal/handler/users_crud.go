package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// AUTH-USERCRUD-20 — local-user admin CRUD. The Users handler already carries the
// lifecycle verbs (Disable / Delete / ForcePasswordReset / Unlock); this file adds the
// two operations it was missing: Create (invite a local, password-authenticated user with
// an initial org-scoped role + a forced temporary password) and Update (change an existing
// user's role / email / active state). Both are org-scoped, audited, and honor the same
// privilege-escalation guard the SSO JIT / CreateLocalUser paths use — a caller may never
// mint or promote a user to a role more privileged than their own effective privilege.
//
// ROUTES (add to internal/server/server.go alongside the other /users/{id}/... routes,
// e.g. after the unlock line):
//
//	r.Post("/users", s.requireVerb(rbac.VerbManageUsers, users.Create))
//	r.Put("/users/{id}", s.requireVerb(rbac.VerbManageUsers, users.Update))

// createUserBody is the POST /users request.
type createUserBody struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

// updateUserBody is the PUT /users/{id} request. Fields are pointers so an omitted field
// is left unchanged (partial update); a present field is applied.
type updateUserBody struct {
	Email  *string `json:"email"`
	Role   *string `json:"role"`
	Active *bool   `json:"active"`
}

// orgCustomRoleVerbs loads the org's custom role name→verbs map for AuthorizeWithCustom.
// Best-effort: on any error it returns an empty map, which is fail-safe for the privilege
// check (it can only deny, never over-grant).
func orgCustomRoleVerbs(ctx context.Context, pool interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID uuid.UUID) map[string][]rbac.Verb {
	out := map[string][]rbac.Verb{}
	rows, err := pool.Query(ctx, `SELECT name, verbs FROM custom_roles WHERE org_id = $1`, orgID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var verbs []string
		if err := rows.Scan(&name, &verbs); err != nil {
			return out
		}
		vs := make([]rbac.Verb, 0, len(verbs))
		for _, v := range verbs {
			vs = append(vs, rbac.Verb(v))
		}
		out[name] = vs
	}
	return out
}

// callerCanGrantRole enforces the privilege-escalation guard: the caller must already hold
// every verb the requested role grants (honoring the caller's own custom roles). Returns
// false when granting role would hand out privilege the caller does not itself possess.
func callerCanGrantRole(subj Subject, custom map[string][]rbac.Verb, role string) bool {
	res := rbac.Resource{OrgID: subj.OrgID}
	for _, v := range rbac.VerbsForRole(role) {
		if rbac.AuthorizeWithCustom(subj.Assignments, v, res, custom) != nil {
			return false
		}
	}
	return true
}

// Create provisions a password-authenticated local user in the caller's org with a single
// org-scoped role and a forced temporary password (must_change_password = TRUE — the admin
// sets an initial secret and the user is forced through change-password on first login).
// Org-scoped, privilege-guarded, audited (user.create). POST /users.
func (h *Users) Create(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "db unavailable"})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}
	var body createUserBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	body.DisplayName = strings.TrimSpace(body.DisplayName)
	body.Role = strings.TrimSpace(body.Role)
	if body.Email == "" || !strings.Contains(body.Email, "@") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a valid email is required"})
		return
	}
	if body.DisplayName == "" {
		body.DisplayName = body.Email
	}
	if !rbac.IsRole(body.Role) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
		return
	}
	custom := orgCustomRoleVerbs(r.Context(), h.db.Pool(), subj.OrgID)
	if !callerCanGrantRole(subj, custom, body.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot grant a role more privileged than your own"})
		return
	}
	// Enforce the org's password policy at creation, same profile the change-password path uses.
	profile := auth.LoadPasswordProfile(r.Context(), h.db.Pool(), subj.OrgID)
	if err := auth.ValidatePassword(profile, body.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash password"})
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "begin"})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var id uuid.UUID
	err = tx.QueryRow(r.Context(), `
INSERT INTO users (org_id, email, display_name, password_hash, must_change_password)
VALUES ($1, $2, $3, $4, TRUE)
ON CONFLICT (org_id, email) DO NOTHING
RETURNING id`, subj.OrgID, body.Email, body.DisplayName, hash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a user with that email already exists"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create user"})
		return
	}
	if _, err := tx.Exec(r.Context(), `
INSERT INTO role_assignments (user_id, role, scope_org_id)
VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id, body.Role, subj.OrgID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "grant role"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit"})
		return
	}
	if h.audit != nil {
		oid, aid := subj.OrgID, subj.UserID
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &aid, Action: "user.create",
			TargetKind: "user", TargetID: id.String(),
			After: map[string]any{"email": body.Email, "role": body.Role},
		})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id.String(), "email": body.Email, "role": body.Role})
}

// Update changes an existing user's email, org-scoped role, and/or active state in the
// caller's org. A role change replaces the user's org-scoped assignments and bumps
// session_epoch (stale role set in live JWTs is rejected on next request); deactivating a
// user runs the same revocation cascade Disable uses. A caller cannot change their own role
// or active state (self-lockout guard). Org-scoped, privilege-guarded, audited (user.update).
// PUT /users/{id}.
func (h *Users) Update(w http.ResponseWriter, r *http.Request) {
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
	var body updateUserBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.Email == nil && body.Role == nil && body.Active == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing to update"})
		return
	}
	self := targetID == subj.UserID
	if self && body.Role != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot change your own role"})
		return
	}
	if self && body.Active != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot change your own active state"})
		return
	}

	var newEmail string
	if body.Email != nil {
		newEmail = strings.ToLower(strings.TrimSpace(*body.Email))
		if newEmail == "" || !strings.Contains(newEmail, "@") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a valid email is required"})
			return
		}
	}
	if body.Role != nil {
		if !rbac.IsRole(strings.TrimSpace(*body.Role)) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
			return
		}
		custom := orgCustomRoleVerbs(r.Context(), h.db.Pool(), subj.OrgID)
		if !callerCanGrantRole(subj, custom, strings.TrimSpace(*body.Role)) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot grant a role more privileged than your own"})
			return
		}
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

	// Email and/or active state, plus an epoch bump whenever access-affecting state changes.
	bumpEpoch := body.Role != nil || (body.Active != nil && !*body.Active)
	if body.Email != nil || body.Active != nil {
		tag, err := tx.Exec(r.Context(), `
UPDATE users
   SET email = COALESCE($3, email),
       disabled = COALESCE($4, disabled),
       session_epoch = session_epoch + CASE WHEN $5 THEN 1 ELSE 0 END,
       updated_at = now()
 WHERE id = $1 AND org_id = $2`,
			targetID, subj.OrgID, body.Email, negBool(body.Active), bumpEpoch)
		if err != nil {
			// A duplicate email (org_id, email unique) surfaces here.
			writeJSON(w, http.StatusConflict, map[string]string{"error": "update user (email may already exist)"})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
	} else if bumpEpoch {
		// Role-only change still needs the epoch bump.
		if _, err := tx.Exec(r.Context(),
			`UPDATE users SET session_epoch = session_epoch + 1, updated_at = now() WHERE id = $1 AND org_id = $2`,
			targetID, subj.OrgID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "bump epoch"})
			return
		}
	}

	if body.Role != nil {
		// Replace the user's org-scoped assignments with the single requested role. Cluster /
		// project-scoped grants are left untouched (managed via the access-control bindings path).
		if _, err := tx.Exec(r.Context(),
			`DELETE FROM role_assignments
			  WHERE user_id = $1 AND scope_org_id = $2
			    AND scope_cluster_id IS NULL AND scope_project_id IS NULL`,
			targetID, subj.OrgID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "clear roles"})
			return
		}
		if _, err := tx.Exec(r.Context(),
			`INSERT INTO role_assignments (user_id, role, scope_org_id)
			 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			targetID, strings.TrimSpace(*body.Role), subj.OrgID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "grant role"})
			return
		}
	}

	// Deactivating a user tears down its live credentials in the same transaction.
	if body.Active != nil && !*body.Active {
		if err := RevokeUserSessions(r.Context(), tx, targetID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revoke sessions"})
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit"})
		return
	}

	after := map[string]any{}
	if body.Email != nil {
		after["email"] = newEmail
	}
	if body.Role != nil {
		after["role"] = strings.TrimSpace(*body.Role)
	}
	if body.Active != nil {
		after["active"] = *body.Active
	}
	if h.audit != nil {
		oid, aid := subj.OrgID, subj.UserID
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &aid, Action: "user.update",
			TargetKind: "user", TargetID: targetID.String(), After: after,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

// negBool maps the request's Active flag to the users.disabled column: disabled = !active.
// Returns nil (leave unchanged) when the caller omitted active.
func negBool(active *bool) *bool {
	if active == nil {
		return nil
	}
	d := !*active
	return &d
}
