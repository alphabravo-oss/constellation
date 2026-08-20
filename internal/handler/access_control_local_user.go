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

// loadCustomRoleVerbs returns the org's custom role name→verbs map for AuthorizeWithCustom.
// Best-effort: on any error it returns an empty map (canonical-role authorization still
// applies), which is fail-safe for the privilege check (it can only deny, never over-grant).
func (h *AccessControl) loadCustomRoleVerbs(ctx context.Context, orgID uuid.UUID) map[string][]rbac.Verb {
	out := map[string][]rbac.Verb{}
	if h.db == nil {
		return out
	}
	rows, err := h.db.Pool().Query(ctx, `SELECT name, verbs FROM custom_roles WHERE org_id = $1`, orgID)
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

// CreateLocalUser provisions a password-authenticated local user with a single org-scoped
// role — the "create user outside SSO JIT" capability NeuVector ships and Constellation
// lacked (users could only appear via OIDC/SAML first login). Gated by VerbManageUsers.
// POST /api/v1/access-control/local-users
func (h *AccessControl) CreateLocalUser(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "db unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var body struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	body.DisplayName = strings.TrimSpace(body.DisplayName)
	body.Role = strings.TrimSpace(body.Role)
	if body.Email == "" || !strings.Contains(body.Email, "@") {
		jsonError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	if body.DisplayName == "" {
		body.DisplayName = body.Email
	}
	if !rbac.IsRole(body.Role) {
		jsonError(w, http.StatusBadRequest, "invalid role")
		return
	}
	// Privilege-escalation guard: a caller may only mint a user with a role no more
	// privileged than their own. Without this, anyone holding VerbManageUsers (e.g. via a
	// delegated custom role) could create a GlobalAdmin and set its password. Require the
	// caller to already hold every verb the requested role grants — honoring the caller's
	// own custom roles when computing their effective privilege.
	custom := h.loadCustomRoleVerbs(r.Context(), subj.OrgID)
	res := rbac.Resource{OrgID: subj.OrgID}
	for _, v := range rbac.VerbsForRole(body.Role) {
		if rbac.AuthorizeWithCustom(subj.Assignments, v, res, custom) != nil {
			jsonError(w, http.StatusForbidden, "cannot grant a role more privileged than your own")
			return
		}
	}
	// Enforce the org's password policy (length / character classes) at creation, the same
	// profile the change-password path uses.
	profile := auth.LoadPasswordProfile(r.Context(), h.db.Pool(), subj.OrgID)
	if err := auth.ValidatePassword(profile, body.Password); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "hash password")
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var id uuid.UUID
	err = tx.QueryRow(r.Context(), `
INSERT INTO users (org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, $4)
ON CONFLICT (org_id, email) DO NOTHING
RETURNING id`, subj.OrgID, body.Email, body.DisplayName, hash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// No row returned ⇒ the email already exists in this org (ON CONFLICT DO NOTHING).
		jsonError(w, http.StatusConflict, "a user with that email already exists")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "create user: "+err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `
INSERT INTO role_assignments (user_id, role, scope_org_id)
VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id, body.Role, subj.OrgID); err != nil {
		jsonError(w, http.StatusInternalServerError, "grant role: "+err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit")
		return
	}

	if h.audit != nil {
		uid, oid := subj.UserID, subj.OrgID
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "user.create",
			TargetKind: "user", TargetID: id.String(),
			After: map[string]any{"email": body.Email, "role": body.Role},
		})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id.String(), "email": body.Email, "role": body.Role})
}
