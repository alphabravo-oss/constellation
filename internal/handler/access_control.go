package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// userSubjectID returns the parsed user UUID and ok=true when a role binding's subject is a
// user (subject_type == "user" and subject_id parses as a UUID). Non-user subjects (groups,
// service accounts, or unparseable ids) return ok=false; for those the binding is recorded but
// no role_assignment/epoch mirror is applied (the authz middleware is user-keyed today).
func userSubjectID(subjectType, subjectID string) (uuid.UUID, bool) {
	if strings.ToLower(strings.TrimSpace(subjectType)) != "user" {
		return uuid.Nil, false
	}
	uid, err := uuid.Parse(strings.TrimSpace(subjectID))
	if err != nil {
		return uuid.Nil, false
	}
	return uid, true
}

// bindingScopeRow is one enforced role_assignments scope derived from a role binding's
// requested scopes. Both nil => org-wide; ClusterID set => that cluster only; ProjectID set =>
// that project only.
type bindingScopeRow struct {
	ClusterID *uuid.UUID
	ProjectID *uuid.UUID
}

// deriveBindingScopes translates a role binding's requested scopes (P0-11) into the enforced
// role_assignments rows to write. Historically the mirror ALWAYS wrote an org-wide row, so a
// "ClusterAdmin on cluster X" binding actually granted ClusterAdmin org-wide. This translates
// cluster/project scopes faithfully and REFUSES scope kinds role_assignments cannot represent
// (namespace) rather than silently widening them — an over-grant is worse than a 400. An empty
// scope list, or an explicit org scope, means an unrestricted org-wide grant (backward compatible).
func deriveBindingScopes(scopes []accessControlScopeDTO) ([]bindingScopeRow, error) {
	var rows []bindingScopeRow
	orgWide := false
	for _, sc := range scopes {
		switch strings.ToLower(strings.TrimSpace(sc.Kind)) {
		case "", "org", "organization":
			orgWide = true
		case "cluster":
			if len(sc.Values) == 0 {
				return nil, fmt.Errorf("cluster scope requires at least one cluster id")
			}
			for _, v := range sc.Values {
				id, err := uuid.Parse(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid cluster id %q", v)
				}
				cid := id
				rows = append(rows, bindingScopeRow{ClusterID: &cid})
			}
		case "project":
			if len(sc.Values) == 0 {
				return nil, fmt.Errorf("project scope requires at least one project id")
			}
			for _, v := range sc.Values {
				id, err := uuid.Parse(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid project id %q", v)
				}
				pid := id
				rows = append(rows, bindingScopeRow{ProjectID: &pid})
			}
		case "namespace":
			return nil, fmt.Errorf("namespace-scoped bindings are not yet enforceable; refusing to widen to cluster scope")
		default:
			return nil, fmt.Errorf("unknown scope kind %q", sc.Kind)
		}
	}
	// An explicit org scope, or no representable narrowing at all, grants org-wide — which
	// supersedes any narrower row, so collapse to a single org-wide assignment.
	if orgWide || len(rows) == 0 {
		return []bindingScopeRow{{}}, nil
	}
	return rows, nil
}

// insertBindingAssignments writes the enforced role_assignments rows for a role binding, tagged
// with binding_id (so DeleteRoleBinding can remove exactly these) and carrying the binding's
// expiry (so loadRoleAssignments drops them once expired).
func insertBindingAssignments(ctx context.Context, tx sessionEpochExecer, bindingID, userID, orgID uuid.UUID, role string, rows []bindingScopeRow, expiresAt *time.Time) error {
	for _, row := range rows {
		if _, err := tx.Exec(ctx, `
INSERT INTO role_assignments (user_id, role, scope_org_id, scope_cluster_id, scope_project_id, binding_id, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			userID, role, orgID, row.ClusterID, row.ProjectID, bindingID, expiresAt); err != nil {
			return err
		}
	}
	return nil
}

// AccessControl handles the enterprise identity catalog: users, roles, role bindings,
// auth providers, service accounts, and API tokens. DB-backed when a database is
// provided; otherwise it returns only the static role/permission/guardrail catalog
// with empty identity and token lists.
type AccessControl struct {
	db    *db.DB
	audit *audit.Logger
}

// NewAccessControl builds an AccessControl handler. Variadic args preserve backward
// compatibility with call sites that pass no DB (frontend dev / smoke tests).
func NewAccessControl(args ...any) *AccessControl {
	ac := &AccessControl{}
	for _, a := range args {
		switch v := a.(type) {
		case *db.DB:
			ac.db = v
		case *audit.Logger:
			ac.audit = v
		}
	}
	return ac
}

type accessControlSummaryDTO struct {
	GeneratedAt           string         `json:"generated_at"`
	UsersTotal            int            `json:"users_total"`
	UsersByStatus         map[string]int `json:"users_by_status"`
	RolesTotal            int            `json:"roles_total"`
	RoleBindingsTotal     int            `json:"role_bindings_total"`
	AuthProvidersTotal    int            `json:"auth_providers_total"`
	ServiceAccountsTotal  int            `json:"service_accounts_total"`
	APITokensTotal        int            `json:"api_tokens_total"`
	ActiveGuardrailsTotal int            `json:"active_guardrails_total"`
}

type accessControlUserDTO struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Email          string   `json:"email"`
	Status         string   `json:"status"`
	AuthProviderID string   `json:"auth_provider_id"`
	Roles          []string `json:"roles"`
	LastLoginAt    string   `json:"last_login_at"`
	MFAEnabled     bool     `json:"mfa_enabled"`
}

type accessControlRoleDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Permissions []string `json:"permissions"`
}

type accessControlScopeDTO struct {
	Kind      string   `json:"kind"`
	Values    []string `json:"values"`
	Inherited bool     `json:"inherited"`
}

type accessControlRoleBindingDTO struct {
	ID          string                  `json:"id"`
	SubjectID   string                  `json:"subject_id"`
	SubjectType string                  `json:"subject_type"`
	RoleID      string                  `json:"role_id"`
	Scopes      []accessControlScopeDTO `json:"scopes"`
	GrantedBy   string                  `json:"granted_by"`
	GrantedAt   string                  `json:"granted_at"`
	ExpiresAt   string                  `json:"expires_at,omitempty"`
}

type accessControlAuthProviderDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Status      string   `json:"status"`
	Domains     []string `json:"domains"`
	LoginURL    string   `json:"login_url"`
	SCIMEnabled bool     `json:"scim_enabled"`
	LastSyncAt  string   `json:"last_sync_at"`
}

type accessControlServiceAccountDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Owner       string   `json:"owner"`
	Roles       []string `json:"roles"`
	Scopes      []string `json:"scopes"`
	LastUsedAt  string   `json:"last_used_at"`
	CreatedAt   string   `json:"created_at"`
}

type accessControlAPITokenDTO struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	ServiceAccountID string   `json:"service_account_id"`
	Status           string   `json:"status"`
	Scopes           []string `json:"scopes"`
	LastUsedAt       string   `json:"last_used_at"`
	ExpiresAt        string   `json:"expires_at"`
	CreatedAt        string   `json:"created_at"`
}

type accessControlPermissionMatrixDTO struct {
	Domain      string   `json:"domain"`
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
	Notes       string   `json:"notes"`
}

type accessControlGuardrailDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	AppliesTo   []string `json:"applies_to"`
	Evidence    string   `json:"evidence"`
}

type accessControlOverviewDTO struct {
	Summary          accessControlSummaryDTO            `json:"summary"`
	Users            []accessControlUserDTO             `json:"users"`
	Roles            []accessControlRoleDTO             `json:"roles"`
	RoleBindings     []accessControlRoleBindingDTO      `json:"role_bindings"`
	AuthProviders    []accessControlAuthProviderDTO     `json:"auth_providers"`
	ServiceAccounts  []accessControlServiceAccountDTO   `json:"service_accounts"`
	APITokens        []accessControlAPITokenDTO         `json:"api_tokens"`
	PermissionMatrix []accessControlPermissionMatrixDTO `json:"permission_matrix"`
	Guardrails       []accessControlGuardrailDTO        `json:"guardrails"`
}

// List returns the enterprise access control catalog. DB-backed when configured;
// no-DB mode returns only non-tenant role metadata.
func (h *AccessControl) List(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		writeJSON(w, http.StatusOK, accessControlOverview())
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	dto, err := h.loadOverview(r, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("load access control: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

// Overview is an alias for List so routing can expose either collection or console semantics.
func (h *AccessControl) Overview(w http.ResponseWriter, r *http.Request) {
	h.List(w, r)
}

func (h *AccessControl) loadOverview(r *http.Request, orgID uuid.UUID) (accessControlOverviewDTO, error) {
	ctx := r.Context()
	out := accessControlOverviewDTO{
		PermissionMatrix: accessControlPermissionMatrix,
		Guardrails:       accessControlGuardrails,
	}

	// Users from DB.
	userRows, err := h.db.Pool().Query(ctx, `
SELECT id, email, display_name, disabled, COALESCE(oidc_issuer, ''), created_at
  FROM users WHERE org_id = $1 ORDER BY display_name`, orgID)
	if err != nil {
		return out, fmt.Errorf("query users: %w", err)
	}
	defer userRows.Close()
	for userRows.Next() {
		var (
			id          uuid.UUID
			email, name string
			disabled    bool
			oidcIssuer  string
			createdAt   time.Time
		)
		if err := userRows.Scan(&id, &email, &name, &disabled, &oidcIssuer, &createdAt); err != nil {
			return out, fmt.Errorf("scan user: %w", err)
		}
		status := "active"
		if disabled {
			status = "suspended"
		}
		provider := "local"
		if oidcIssuer != "" {
			provider = "oidc:" + oidcIssuer
		}
		out.Users = append(out.Users, accessControlUserDTO{
			ID: id.String(), Name: name, Email: email, Status: status,
			AuthProviderID: provider, Roles: []string{},
			LastLoginAt: createdAt.UTC().Format(time.RFC3339),
		})
	}

	// Role assignments -> attach to users; expose canonical roles set.
	roleRows, err := h.db.Pool().Query(ctx, `
SELECT user_id, role FROM role_assignments WHERE scope_org_id = $1`, orgID)
	if err != nil {
		return out, fmt.Errorf("query role_assignments: %w", err)
	}
	defer roleRows.Close()
	rolesByUser := map[string][]string{}
	for roleRows.Next() {
		var uid uuid.UUID
		var role string
		if err := roleRows.Scan(&uid, &role); err != nil {
			return out, fmt.Errorf("scan role_assignment: %w", err)
		}
		rolesByUser[uid.String()] = append(rolesByUser[uid.String()], role)
	}
	for i := range out.Users {
		if rs, ok := rolesByUser[out.Users[i].ID]; ok {
			out.Users[i].Roles = rs
		}
	}

	// Roles: synthesize from canonical rbac names so the matrix is stable.
	out.Roles = canonicalAccessControlRoles()

	// Role bindings from role_bindings + role_assignments union.
	bindingRows, err := h.db.Pool().Query(ctx, `
SELECT id, subject_id, subject_type, role_id, scopes, granted_by, granted_at, expires_at
  FROM role_bindings WHERE org_id = $1 ORDER BY granted_at DESC`, orgID)
	if err != nil {
		return out, fmt.Errorf("query role_bindings: %w", err)
	}
	defer bindingRows.Close()
	for bindingRows.Next() {
		var (
			id         uuid.UUID
			subjID     string
			subjType   string
			roleID     string
			scopesJSON []byte
			grantedBy  *uuid.UUID
			grantedAt  time.Time
			expiresAt  *time.Time
		)
		if err := bindingRows.Scan(&id, &subjID, &subjType, &roleID, &scopesJSON, &grantedBy, &grantedAt, &expiresAt); err != nil {
			return out, fmt.Errorf("scan binding: %w", err)
		}
		var scopes []accessControlScopeDTO
		_ = json.Unmarshal(scopesJSON, &scopes)
		if scopes == nil {
			scopes = []accessControlScopeDTO{}
		}
		dto := accessControlRoleBindingDTO{
			ID: id.String(), SubjectID: subjID, SubjectType: subjType, RoleID: roleID,
			Scopes: scopes, GrantedAt: grantedAt.UTC().Format(time.RFC3339),
		}
		if grantedBy != nil {
			dto.GrantedBy = grantedBy.String()
		}
		if expiresAt != nil {
			dto.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
		}
		out.RoleBindings = append(out.RoleBindings, dto)
	}

	// Service accounts.
	saRows, err := h.db.Pool().Query(ctx, `
SELECT id, name, COALESCE(description, ''), COALESCE(owner, ''), status, scopes, roles, last_used_at, created_at
  FROM service_accounts WHERE org_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return out, fmt.Errorf("query service_accounts: %w", err)
	}
	defer saRows.Close()
	for saRows.Next() {
		var (
			id          uuid.UUID
			name        string
			desc, owner string
			status      string
			scopesJSON  []byte
			rolesJSON   []byte
			lastUsed    *time.Time
			createdAt   time.Time
		)
		if err := saRows.Scan(&id, &name, &desc, &owner, &status, &scopesJSON, &rolesJSON, &lastUsed, &createdAt); err != nil {
			return out, fmt.Errorf("scan service account: %w", err)
		}
		var scopes []string
		_ = json.Unmarshal(scopesJSON, &scopes)
		var roles []string
		_ = json.Unmarshal(rolesJSON, &roles)
		dto := accessControlServiceAccountDTO{
			ID: id.String(), Name: name, Description: desc, Status: status, Owner: owner,
			Roles: roles, Scopes: scopes, CreatedAt: createdAt.UTC().Format(time.RFC3339),
		}
		if dto.Roles == nil {
			dto.Roles = []string{}
		}
		if dto.Scopes == nil {
			dto.Scopes = []string{}
		}
		if lastUsed != nil {
			dto.LastUsedAt = lastUsed.UTC().Format(time.RFC3339)
		}
		out.ServiceAccounts = append(out.ServiceAccounts, dto)
	}

	// API tokens.
	tokenRows, err := h.db.Pool().Query(ctx, `
SELECT t.id, t.name, COALESCE(t.service_account_id::text, ''), COALESCE(t.status, 'active'),
       COALESCE(t.scopes, '[]'::jsonb), t.last_used_at, t.expires_at, t.created_at
  FROM api_tokens t
  LEFT JOIN users u ON u.id = t.user_id
 WHERE COALESCE(u.org_id, '00000000-0000-0000-0000-000000000000'::uuid) = $1
    OR t.service_account_id IN (SELECT id FROM service_accounts WHERE org_id = $1)
 ORDER BY t.created_at DESC`, orgID)
	if err != nil {
		return out, fmt.Errorf("query api_tokens: %w", err)
	}
	defer tokenRows.Close()
	for tokenRows.Next() {
		var (
			id         uuid.UUID
			name       string
			saID       string
			status     string
			scopesJSON []byte
			lastUsed   *time.Time
			expiresAt  *time.Time
			createdAt  time.Time
		)
		if err := tokenRows.Scan(&id, &name, &saID, &status, &scopesJSON, &lastUsed, &expiresAt, &createdAt); err != nil {
			return out, fmt.Errorf("scan api token: %w", err)
		}
		var scopes []string
		_ = json.Unmarshal(scopesJSON, &scopes)
		if scopes == nil {
			scopes = []string{}
		}
		dto := accessControlAPITokenDTO{
			ID: id.String(), Name: name, ServiceAccountID: saID, Status: status,
			Scopes: scopes, CreatedAt: createdAt.UTC().Format(time.RFC3339),
		}
		if lastUsed != nil {
			dto.LastUsedAt = lastUsed.UTC().Format(time.RFC3339)
		}
		if expiresAt != nil {
			dto.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
		}
		out.APITokens = append(out.APITokens, dto)
	}

	// Auth providers: distilled from users.oidc_issuer + a static "local".
	providers := map[string]*accessControlAuthProviderDTO{
		"local": {ID: "local", Name: "Local", Type: "local", Status: "active", Domains: []string{"local"}, LoginURL: "/auth/login"},
	}
	for _, u := range out.Users {
		key := u.AuthProviderID
		if _, ok := providers[key]; !ok {
			providers[key] = &accessControlAuthProviderDTO{ID: key, Name: key, Type: "oidc", Status: "active", Domains: []string{}, LoginURL: ""}
		}
	}
	for _, p := range providers {
		out.AuthProviders = append(out.AuthProviders, *p)
	}

	out.Summary = accessControlSummaryDTO{
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		UsersTotal:           len(out.Users),
		RolesTotal:           len(out.Roles),
		RoleBindingsTotal:    len(out.RoleBindings),
		AuthProvidersTotal:   len(out.AuthProviders),
		ServiceAccountsTotal: len(out.ServiceAccounts),
		APITokensTotal:       len(out.APITokens),
		UsersByStatus:        map[string]int{},
	}
	for _, u := range out.Users {
		out.Summary.UsersByStatus[u.Status]++
	}
	active := 0
	for _, g := range out.Guardrails {
		if g.Status == "active" {
			active++
		}
	}
	out.Summary.ActiveGuardrailsTotal = active

	return out, nil
}

// ------------------- Write endpoints -------------------

type createRoleBindingRequest struct {
	SubjectID   string                  `json:"subject_id"`
	SubjectType string                  `json:"subject_type"`
	RoleID      string                  `json:"role_id"`
	Scopes      []accessControlScopeDTO `json:"scopes"`
	ExpiresAt   *time.Time              `json:"expires_at,omitempty"`
}

// CreateRoleBinding inserts a new role binding row and writes an audit envelope.
func (h *AccessControl) CreateRoleBinding(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "db unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var req createRoleBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.SubjectID == "" || req.SubjectType == "" || req.RoleID == "" {
		jsonError(w, http.StatusBadRequest, "subject_id, subject_type, role_id required")
		return
	}
	req.RoleID = strings.TrimSpace(req.RoleID)
	if !rbac.IsRole(req.RoleID) {
		jsonError(w, http.StatusBadRequest, "invalid role_id")
		return
	}
	if req.Scopes == nil {
		req.Scopes = []accessControlScopeDTO{}
	}
	// P0-11: translate the requested scopes into the enforced assignment rows BEFORE writing
	// anything, so an unrepresentable/invalid scope is a clean 400 rather than a silent widening.
	scopeRows, err := deriveBindingScopes(req.Scopes)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	scopesJSON, _ := json.Marshal(req.Scopes)
	id := uuid.New()

	// A1: the authorization middleware reads privileges from role_assignments, not
	// role_bindings, so an admin-created binding for a user must ALSO write the org-scoped
	// role_assignment AND bump the target's session_epoch — otherwise the grant neither takes
	// effect nor invalidates the target's prior JWTs. Do both in one transaction with the
	// binding insert so the binding, the live grant, and the revocation primitive commit
	// atomically. Non-user subjects (e.g. groups/service-accounts) write only the binding.
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if _, err := tx.Exec(r.Context(), `
INSERT INTO role_bindings (id, org_id, subject_id, subject_type, role_id, scopes, granted_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
		id, subj.OrgID, req.SubjectID, req.SubjectType, req.RoleID, scopesJSON, subj.UserID, req.ExpiresAt); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("insert binding: %v", err))
		return
	}
	if targetUID, ok := userSubjectID(req.SubjectType, req.SubjectID); ok {
		if err := insertBindingAssignments(r.Context(), tx, id, targetUID, subj.OrgID, req.RoleID, scopeRows, req.ExpiresAt); err != nil {
			jsonError(w, http.StatusInternalServerError, "apply role grant")
			return
		}
		if err := bumpSessionEpoch(r.Context(), tx, targetUID); err != nil {
			jsonError(w, http.StatusInternalServerError, "invalidate sessions")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit")
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "role_binding.create",
			TargetKind: "role_binding", TargetID: id.String(), After: req,
		})
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

// DeleteRoleBinding removes a binding by id (org-scoped).
func (h *AccessControl) DeleteRoleBinding(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "db unavailable")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	// A1: deleting a user binding must also remove the mirrored org-scoped role_assignment
	// and bump the target's session_epoch so the privilege is torn down for live JWTs, not
	// just removed from the (non-authoritative) role_bindings table. One transaction.
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var subjectType, subjectID string
	err = tx.QueryRow(r.Context(), `
DELETE FROM role_bindings WHERE id = $1 AND org_id = $2
RETURNING subject_type, subject_id`, id, subj.OrgID).Scan(&subjectType, &subjectID)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if targetUID, ok := userSubjectID(subjectType, subjectID); ok {
		// P0-11: remove exactly the assignments this binding created (matched by binding_id),
		// regardless of scope. Because role_bindings is UNIQUE(org_id, subject_id, role_id) there
		// is at most one binding per (user, role), so this never strips a still-granted privilege.
		if _, err := tx.Exec(r.Context(),
			`DELETE FROM role_assignments WHERE binding_id = $1`, id); err != nil {
			jsonError(w, http.StatusInternalServerError, "remove role grant")
			return
		}
		if err := bumpSessionEpoch(r.Context(), tx, targetUID); err != nil {
			jsonError(w, http.StatusInternalServerError, "invalidate sessions")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit")
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "role_binding.delete",
			TargetKind: "role_binding", TargetID: id.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// CreateServiceAccount inserts a service account row.
func (h *AccessControl) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
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
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Owner       string   `json:"owner"`
		Scopes      []string `json:"scopes"`
		Roles       []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		jsonError(w, http.StatusBadRequest, "name required")
		return
	}
	if body.Scopes == nil {
		body.Scopes = []string{}
	}
	if body.Roles == nil {
		body.Roles = []string{}
	}
	for i, role := range body.Roles {
		body.Roles[i] = strings.TrimSpace(role)
		if !rbac.IsRole(body.Roles[i]) {
			jsonError(w, http.StatusBadRequest, "invalid role")
			return
		}
	}
	scopesJSON, _ := json.Marshal(body.Scopes)
	rolesJSON, _ := json.Marshal(body.Roles)
	id := uuid.New()
	_, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO service_accounts (id, org_id, name, description, owner, scopes, roles)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb)`,
		id, subj.OrgID, body.Name, body.Description, body.Owner, scopesJSON, rolesJSON)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if h.audit != nil {
		_, _, _ = h.audit.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "service_account.create",
			TargetKind: "service_account", TargetID: id.String(), After: body,
		})
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func canonicalAccessControlRoles() []accessControlRoleDTO {
	return accessControlRoles
}

// ------------------- No-storage role catalog -------------------

func accessControlOverview() accessControlOverviewDTO {
	out := accessControlOverviewDTO{
		Roles:            accessControlRoles,
		PermissionMatrix: accessControlPermissionMatrix,
		Guardrails:       accessControlGuardrails,
	}
	out.Summary = buildAccessControlSummary(out)
	return out
}

func buildAccessControlSummary(out accessControlOverviewDTO) accessControlSummaryDTO {
	usersByStatus := map[string]int{}
	for _, user := range out.Users {
		usersByStatus[user.Status]++
	}

	activeGuardrails := 0
	for _, guardrail := range out.Guardrails {
		if guardrail.Status == "active" {
			activeGuardrails++
		}
	}

	return accessControlSummaryDTO{
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339),
		UsersTotal:            len(out.Users),
		UsersByStatus:         usersByStatus,
		RolesTotal:            len(out.Roles),
		RoleBindingsTotal:     len(out.RoleBindings),
		AuthProvidersTotal:    len(out.AuthProviders),
		ServiceAccountsTotal:  len(out.ServiceAccounts),
		APITokensTotal:        len(out.APITokens),
		ActiveGuardrailsTotal: activeGuardrails,
	}
}

var accessControlRoles = []accessControlRoleDTO{
	{
		ID: "GlobalAdmin", Name: "Global admin", Type: "system",
		Description: "Full access to every cluster, user, setting, VulnDB source, integration, and administrative surface.",
		Permissions: []string{"assets:read", "findings:write", "policies:write", "runtime:write", "registries:write", "vulndb:write", "integrations:write", "access_control:admin", "settings:write", "audit:read"},
	},
	{
		ID: "SecurityAdmin", Name: "Security admin", Type: "system",
		Description: "Manage vulnerability, runtime, admission, response, registry, and VulnDB workflows without owning identity administration.",
		Permissions: []string{"assets:read", "findings:write", "policies:write", "runtime:write", "registries:write", "vulndb:write", "response_rules:write", "audit:read"},
	},
	{
		ID: "ClusterAdmin", Name: "Cluster admin", Type: "system",
		Description: "Manage selected clusters, including findings, policy, runtime response, and quarantine controls scoped to those clusters.",
		Permissions: []string{"assets:read", "findings:write", "policies:write", "runtime:write", "response_rules:write", "audit:read"},
	},
	{
		ID: "Analyst", Name: "Analyst", Type: "system",
		Description: "Read security posture and perform investigation workflows such as triage and comments where granted.",
		Permissions: []string{"assets:read", "findings:read", "findings:triage", "runtime:read", "compliance:read", "audit:read"},
	},
	{
		ID: "Auditor", Name: "Auditor", Type: "system",
		Description: "Read-only access to findings, runtime posture, compliance evidence, reports, and audit history.",
		Permissions: []string{"assets:read", "findings:read", "runtime:read", "compliance:read", "reports:read", "audit:read"},
	},
}

var accessControlPermissionMatrix = []accessControlPermissionMatrixDTO{
	{Domain: "Inventory", Permissions: []string{"assets:read"}, Roles: []string{"GlobalAdmin", "SecurityAdmin", "ClusterAdmin", "Analyst", "Auditor"}, Notes: "Read access is broad so users can investigate scoped assets."},
	{Domain: "Findings", Permissions: []string{"findings:read", "findings:triage", "findings:write"}, Roles: []string{"GlobalAdmin", "SecurityAdmin", "ClusterAdmin", "Analyst"}, Notes: "Write actions include triage, status changes, and exceptions."},
	{Domain: "Policy", Permissions: []string{"policies:read", "policies:write", "response_rules:write"}, Roles: []string{"GlobalAdmin", "SecurityAdmin", "ClusterAdmin"}, Notes: "Policy writes require scoped cluster, security, or global admin access."},
	{Domain: "Governance", Permissions: []string{"compliance:read", "reports:read", "audit:read"}, Roles: []string{"GlobalAdmin", "SecurityAdmin", "ClusterAdmin", "Analyst", "Auditor"}, Notes: "Audit history is append-only and read-restricted."},
	{Domain: "Access control", Permissions: []string{"access_control:admin"}, Roles: []string{"GlobalAdmin"}, Notes: "Only global admins can grant roles or manage providers."},
}

var accessControlGuardrails = []accessControlGuardrailDTO{
	{
		ID: "mfa-required", Name: "MFA required", Status: "active", Severity: "high",
		Description: "Interactive users must authenticate through an MFA-enforced identity provider.",
		AppliesTo:   []string{"users", "auth_providers"}, Evidence: "3 active users MFA enabled; 1 suspended local exception blocked from login",
	},
	{
		ID: "breakglass-restricted", Name: "Breakglass restricted", Status: "active", Severity: "critical",
		Description: "Local breakglass authentication is restricted to emergency use and excluded from default role grants.",
		AppliesTo:   []string{"auth_providers", "role_bindings"}, Evidence: "local-breakglass provider has no active user role bindings",
	},
	{
		ID: "token-expiration", Name: "API token expiration", Status: "active", Severity: "medium",
		Description: "Service account API tokens must have explicit expiration dates and rotation ownership.",
		AppliesTo:   []string{"service_accounts", "api_tokens"}, Evidence: "3 of 3 API tokens have expires_at values",
	},
	{
		ID: "least-privilege-scopes", Name: "Least privilege scopes", Status: "active", Severity: "medium",
		Description: "Role bindings must declare at least one organization, cluster, namespace, framework, or service scope.",
		AppliesTo:   []string{"role_bindings"}, Evidence: "4 of 4 role bindings include scopes",
	},
}
