package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

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
	if err != nil {
		// No row returned ⇒ the email already exists in this org.
		jsonError(w, http.StatusConflict, "a user with that email already exists")
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
