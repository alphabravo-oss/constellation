package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// AuthServers serves the B4 DB-backed auth-provider (IdP) CRUD:
//
//	GET    /api/v1/auth-servers        — list the org's providers (secrets REDACTED)
//	GET    /api/v1/auth-servers/{id}   — one provider (secrets REDACTED)
//	POST   /api/v1/auth-servers        — create a provider
//	PUT    /api/v1/auth-servers/{id}   — replace a provider's mutable fields
//	DELETE /api/v1/auth-servers/{id}   — delete a provider
//
// All routes are gated by rbac.VerbManageAuthServers in the router. A mutation bumps the row's
// revision; the in-process ProviderSet poller (wired in internal/server) detects the bump and
// rebuilds the live verifier set WITHOUT a restart. The handler also kicks an immediate reload on
// the writing replica so its own subsequent logins see the change without waiting for a tick.
type AuthServers struct {
	db        *db.DB
	audit     *audit.Logger
	providers *auth.ProviderSet
	// sealer (H2) seals the IdP secret fields at rest before they are persisted to
	// auth_servers.config. Same install-KEK cipher used for registry creds + the fed-CA key.
	sealer auth.Sealer
}

// NewAuthServers constructs the handler. providers is the same ProviderSet the login handler
// reads through, so a mutation here can immediately reload the live set in-process. sealer seals
// the IdP secret fields at rest (nil = no install KEK, plaintext fallback).
func NewAuthServers(d *db.DB, a *audit.Logger, providers *auth.ProviderSet, sealer auth.Sealer) *AuthServers {
	return &AuthServers{db: d, audit: a, providers: providers, sealer: sealer}
}

// authServerBody is the create/update request + list/get response shape. Config and RoleMapping
// are passed through to the typed model; secrets in the response are redacted.
type authServerBody struct {
	ID          string              `json:"id,omitempty"`
	Type        string              `json:"type,omitempty"`
	Name        string              `json:"name"`
	Enabled     bool                `json:"enabled"`
	AuthOrder   int                 `json:"auth_order"`
	Config      auth.ServerConfig   `json:"config"`
	RoleMapping authRoleMappingBody `json:"role_mapping"`
	Revision    int64               `json:"revision,omitempty"`
}

// authRoleMappingBody is the wire form of auth.RoleMapping (whose fields are unexported-JSON-less).
// Keeping a DTO here means the engine type stays free of JSON tags it doesn't otherwise need.
type authRoleMappingBody struct {
	Rules   map[string]string `json:"rules"`
	Default string            `json:"default"`
}

func (b authRoleMappingBody) toModel() auth.RoleMapping {
	return auth.RoleMapping{Rules: b.Rules, Default: b.Default}
}

func fromRoleMapping(m auth.RoleMapping) authRoleMappingBody {
	return authRoleMappingBody{Rules: m.Rules, Default: m.Default}
}

func toBody(s auth.AuthServer) authServerBody {
	r := s.Redacted()
	return authServerBody{
		ID:          r.ID.String(),
		Type:        r.Type,
		Name:        r.Name,
		Enabled:     r.Enabled,
		AuthOrder:   r.AuthOrder,
		Config:      r.Config,
		RoleMapping: fromRoleMapping(r.RoleMapping),
		Revision:    r.Revision,
	}
}

func (h *AuthServers) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	srvs, err := auth.ListAuthServers(r.Context(), h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]authServerBody, 0, len(srvs))
	for _, s := range srvs {
		out = append(out, toBody(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_servers": out})
}

func (h *AuthServers) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	srv, err := auth.GetAuthServer(r.Context(), h.db.Pool(), subj.OrgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "auth server not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toBody(srv))
}

func (h *AuthServers) Create(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var body authServerBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	srv := auth.AuthServer{
		OrgID:       subj.OrgID,
		Type:        body.Type,
		Name:        body.Name,
		Enabled:     body.Enabled,
		AuthOrder:   body.AuthOrder,
		Config:      body.Config,
		RoleMapping: body.RoleMapping.toModel(),
	}
	created, err := auth.CreateAuthServer(r.Context(), h.db.Pool(), srv, h.sealer, h.actor(r))
	if errors.Is(err, auth.ErrNameConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		// Validation failures (bad type / missing fields) are caller errors.
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.reloadAndAudit(r, "auth.server.create", auth.AuthServer{}, created)
	writeJSON(w, http.StatusCreated, toBody(created))
}

func (h *AuthServers) Update(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	prev, err := auth.GetAuthServer(r.Context(), h.db.Pool(), subj.OrgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "auth server not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var body authServerBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	srv := auth.AuthServer{
		ID:          id,
		OrgID:       subj.OrgID,
		Name:        body.Name,
		Enabled:     body.Enabled,
		AuthOrder:   body.AuthOrder,
		Config:      body.Config,
		RoleMapping: body.RoleMapping.toModel(),
	}
	updated, err := auth.UpdateAuthServer(r.Context(), h.db.Pool(), srv, h.sealer, h.actor(r))
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "auth server not found")
		return
	}
	if errors.Is(err, auth.ErrNameConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.reloadAndAudit(r, "auth.server.update", prev, updated)
	writeJSON(w, http.StatusOK, toBody(updated))
}

func (h *AuthServers) Delete(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	prev, err := auth.GetAuthServer(r.Context(), h.db.Pool(), subj.OrgID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "auth server not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := auth.DeleteAuthServer(r.Context(), h.db.Pool(), subj.OrgID, id); errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "auth server not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.reloadAndAudit(r, "auth.server.delete", prev, auth.AuthServer{})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// scopedMappingBody is the create-request + list-response shape for a sso_role_mappings row (P0-10):
// a group->role grant scoped to an optional cluster and namespace. cluster_id "" means all clusters
// (org scope); a set namespace narrows to that namespace and REQUIRES a cluster to anchor against.
type scopedMappingBody struct {
	ID        string `json:"id,omitempty"`
	Group     string `json:"group"`
	Role      string `json:"role"`
	ClusterID string `json:"cluster_id,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

func toScopedMappingBody(m auth.ScopedRoleMapping) scopedMappingBody {
	b := scopedMappingBody{ID: m.ID.String(), Group: m.Group, Role: m.Role, Namespace: m.Namespace}
	if m.ClusterID != nil {
		b.ClusterID = m.ClusterID.String()
	}
	return b
}

// buildScopedMapping validates a create body and turns it into the auth store model. Kept as a
// pure function (no DB/HTTP) so the invariants are unit-testable: group required, role must be a
// known RBAC role, cluster_id (when present) must parse, and a namespace grant must carry a cluster
// to anchor against (a namespace with no cluster can never be materialised into role_assignments).
func buildScopedMapping(orgID, authServerID uuid.UUID, body scopedMappingBody, createdBy *uuid.UUID) (auth.ScopedRoleMapping, error) {
	group := strings.TrimSpace(body.Group)
	if group == "" {
		return auth.ScopedRoleMapping{}, errors.New("group required")
	}
	if !rbac.IsRole(body.Role) {
		return auth.ScopedRoleMapping{}, fmt.Errorf("unknown role %q", body.Role)
	}
	m := auth.ScopedRoleMapping{
		OrgID:        orgID,
		AuthServerID: authServerID,
		Group:        group,
		Role:         body.Role,
		Namespace:    strings.TrimSpace(body.Namespace),
		CreatedBy:    createdBy,
	}
	if cid := strings.TrimSpace(body.ClusterID); cid != "" {
		u, err := uuid.Parse(cid)
		if err != nil {
			return auth.ScopedRoleMapping{}, errors.New("invalid cluster_id")
		}
		m.ClusterID = &u
	}
	if m.Namespace != "" && m.ClusterID == nil {
		return auth.ScopedRoleMapping{}, errors.New("namespace requires a cluster_id")
	}
	return m, nil
}

// ListScopedMappings serves GET /auth-servers/{id}/scoped-mappings — the auth server's scoped grants.
func (h *AuthServers) ListScopedMappings(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	serverID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := auth.GetAuthServer(r.Context(), h.db.Pool(), subj.OrgID, serverID); errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "auth server not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows, err := auth.ListScopedRoleMappings(r.Context(), h.db.Pool(), subj.OrgID, serverID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]scopedMappingBody, 0, len(rows))
	for _, m := range rows {
		out = append(out, toScopedMappingBody(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"scoped_mappings": out})
}

// CreateScopedMapping serves POST /auth-servers/{id}/scoped-mappings — add one scoped grant.
func (h *AuthServers) CreateScopedMapping(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	serverID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := auth.GetAuthServer(r.Context(), h.db.Pool(), subj.OrgID, serverID); errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "auth server not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var body scopedMappingBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	model, err := buildScopedMapping(subj.OrgID, serverID, body, h.actor(r))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := auth.CreateScopedRoleMapping(r.Context(), h.db.Pool(), model)
	if errors.Is(err, auth.ErrScopedMappingExists) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.reloadAndAuditScoped(r, "auth.scoped_mapping.create", serverID, created.ID)
	writeJSON(w, http.StatusCreated, toScopedMappingBody(created))
}

// DeleteScopedMapping serves DELETE /auth-servers/{id}/scoped-mappings/{mid} — remove one grant.
func (h *AuthServers) DeleteScopedMapping(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	serverID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	mappingID, err := uuid.Parse(chi.URLParam(r, "mid"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid mapping id")
		return
	}
	if err := auth.DeleteScopedRoleMapping(r.Context(), h.db.Pool(), subj.OrgID, serverID, mappingID); errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "scoped mapping not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.reloadAndAuditScoped(r, "auth.scoped_mapping.delete", serverID, mappingID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// reloadAndAuditScoped hot-reloads the writing replica's provider set (so its own next login sees
// the new scoped rules) and records an audit event. Cross-replica pickup rides the auth_server
// revision bump the store already performed.
func (h *AuthServers) reloadAndAuditScoped(r *http.Request, action string, serverID, mappingID uuid.UUID) {
	subj, _ := SubjectFrom(r.Context())
	if h.providers != nil {
		_ = h.providers.Reload(r.Context(), h.db.Pool(), subj.OrgID)
	}
	if h.audit != nil {
		oid := subj.OrgID
		uid := subj.UserID
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: action,
			TargetKind: "auth_server", TargetID: serverID.String(),
			After: map[string]string{"mapping_id": mappingID.String()},
		})
	}
}

// actor returns the calling user's id when it maps to a real users row, for the updated_by column
// + audit ActorID. A service-account/PAT caller without a user row yields nil.
func (h *AuthServers) actor(r *http.Request) *uuid.UUID {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		return nil
	}
	var exists bool
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, subj.UserID).Scan(&exists); err == nil && exists {
		uid := subj.UserID
		return &uid
	}
	return nil
}

// reloadAndAudit hot-reloads the writing replica's provider set so its own next login reflects the
// change immediately (other replicas pick it up on the next poll tick), then records an audit event
// with secrets redacted in both Before and After.
func (h *AuthServers) reloadAndAudit(r *http.Request, action string, before, after auth.AuthServer) {
	subj, _ := SubjectFrom(r.Context())
	if h.providers != nil {
		_ = h.providers.Reload(r.Context(), h.db.Pool(), subj.OrgID)
	}
	if h.audit != nil {
		oid := subj.OrgID
		uid := subj.UserID
		target := after.ID
		if target == uuid.Nil {
			target = before.ID
		}
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: action,
			TargetKind: "auth_server", TargetID: target.String(),
			Before: before.Redacted(), After: after.Redacted(),
		})
	}
}
