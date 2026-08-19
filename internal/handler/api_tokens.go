// API token (Personal Access Token / PAT) management.
//
//	POST   /api/v1/api-tokens            — mint a new token (raw shown once)
//	GET    /api/v1/api-tokens            — list tokens for the caller's org
//	GET    /api/v1/api-tokens/{id}       — token detail
//	POST   /api/v1/api-tokens/{id}/rotate — invalidate + mint replacement (same scopes/expiry)
//	DELETE /api/v1/api-tokens/{id}       — revoke (sets revoked_at)
//	GET    /api/v1/rbac/verbs            — catalog of available scopes (for the UI picker)
//
// Raw token shape: "cst_" + base64url(32 random bytes). Store sha256(raw) in api_tokens.token_hash.
// The raw token is shown only on create/rotate; thereafter only the hash and DB metadata exist.
//
// RBAC envelope: a request authenticated with a PAT carries Subject.TokenScopes; the server's
// requireVerb middleware short-circuits with 403 if the verb isn't in that set, even when the
// underlying role would otherwise allow it. See subject.go and server.go authMiddleware.
package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// APIToken (PAT) raw-value prefix. Chosen to be distinct from scanner/runtime-agent
// token prefixes so the auth middleware can route on the prefix alone.
const apiTokenPrefix = "cst_"

// APITokens handler bundles the mint/list/rotate/revoke CRUD over api_tokens.
type APITokens struct {
	db    *db.DB
	audit *audit.Logger
	// maxLifetime caps how far in the future a minted PAT's expires_at may be (A7).
	// A PAT with no expires_at, or one beyond now()+maxLifetime, is rejected. Zero
	// disables the cap (back-compat: any expiry, including none, is accepted).
	maxLifetime time.Duration
}

// NewAPITokens constructs the handler.
func NewAPITokens(d *db.DB, a *audit.Logger) *APITokens {
	return &APITokens{db: d, audit: a}
}

// WithMaxLifetime sets the A7 PAT lifetime cap and returns the handler for chaining.
func (h *APITokens) WithMaxLifetime(d time.Duration) *APITokens {
	h.maxLifetime = d
	return h
}

// apiTokenDTO is the wire-shape used by list/detail responses. Raw token values
// are NEVER included here — only on the create/rotate response (apiTokenCreateResponse).
type apiTokenDTO struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Scopes          []string `json:"scopes"`
	AttachedToKind  string   `json:"attached_to_kind"`            // "user" | "service-account"
	AttachedToID    string   `json:"attached_to_id"`              // user_id or service_account_id
	AttachedToLabel string   `json:"attached_to_label,omitempty"` // email or service-account name
	Status          string   `json:"status"`                      // "active" | "expired" | "revoked"
	CreatedAt       string   `json:"created_at"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	LastUsedAt      string   `json:"last_used_at,omitempty"`
	RevokedAt       string   `json:"revoked_at,omitempty"`
}

// apiTokenCreateRequest is the POST /api-tokens body.
type apiTokenCreateRequest struct {
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes"`
	ExpiresAt  string   `json:"expires_at,omitempty"`  // RFC3339; empty = never
	AttachedTo string   `json:"attached_to,omitempty"` // "user" or "service-account-<uuid>"; default "user"
}

// apiTokenCreateResponse is the one-time response that includes the raw token.
type apiTokenCreateResponse struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Scopes   []string `json:"scopes"`
	RawToken string   `json:"raw_token"`
	Hint     string   `json:"hint"`
}

// Create mints a new API token. Returns the raw token exactly once in the response.
func (h *APITokens) Create(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if subj.TokenScopes != nil {
		// A PAT cannot mint another PAT — that would let a stolen token bootstrap a
		// fresh credential. Mint is a user-only action.
		jsonError(w, http.StatusForbidden, "api tokens cannot mint other api tokens")
		return
	}
	var req apiTokenCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "name required")
		return
	}
	scopes, err := validateScopes(req.Scopes)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "expires_at: "+err.Error())
			return
		}
		if t.Before(time.Now()) {
			jsonError(w, http.StatusBadRequest, "expires_at is in the past")
			return
		}
		expiresAt = &t
	}
	// A7: PAT lifetime cap. When a max is configured, every PAT must carry an
	// expires_at (no unbounded/never-expiring tokens) and it must fall within
	// now()+maxLifetime. This bounds the blast radius of a leaked PAT.
	if err := h.checkPATLifetime(expiresAt); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, serviceAccountID, err := resolveAttachment(r.Context(), h.db.Pool(), subj, req.AttachedTo)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	raw, id, err := h.mint(r.Context(), userID, serviceAccountID, req.Name, scopes, expiresAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "mint: "+err.Error())
		return
	}

	h.auditEvent(r.Context(), subj, "api_token.create", id.String(), map[string]any{
		"name":               req.Name,
		"scopes":             scopes,
		"attached_to":        req.AttachedTo,
		"expires_at":         req.ExpiresAt,
		"service_account_id": serviceAccountIDPtrString(serviceAccountID),
	})

	writeJSON(w, http.StatusCreated, apiTokenCreateResponse{
		ID:       id.String(),
		Name:     req.Name,
		Scopes:   stringsFromScopes(scopes),
		RawToken: raw,
		Hint:     "Store this token now — it will not be shown again. Use it as Bearer in the Authorization header.",
	})
}

// List returns all org tokens (no raw values).
func (h *APITokens) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	tokens, err := loadAPITokensForOrg(r.Context(), h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "load tokens: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

// Get returns one token's detail.
func (h *APITokens) Get(w http.ResponseWriter, r *http.Request) {
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
	dto, err := loadAPITokenByID(r.Context(), h.db.Pool(), subj.OrgID, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "token not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

// Rotate revokes the current token and mints a fresh one with the same scopes / expiry.
// The new raw value is shown only in this response.
func (h *APITokens) Rotate(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	if subj.TokenScopes != nil {
		jsonError(w, http.StatusForbidden, "api tokens cannot rotate other api tokens")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad id")
		return
	}
	var (
		name       string
		userID     *uuid.UUID
		saID       *uuid.UUID
		scopesJSON []byte
		expiresAt  *time.Time
		revokedAt  *time.Time
	)
	row := h.db.Pool().QueryRow(r.Context(), `
SELECT t.name, t.user_id, t.service_account_id, COALESCE(t.scopes, '[]'::jsonb),
       t.expires_at, t.revoked_at
  FROM api_tokens t
  LEFT JOIN users u ON u.id = t.user_id
  LEFT JOIN service_accounts sa ON sa.id = t.service_account_id
 WHERE t.id = $1
   AND (u.org_id = $2 OR sa.org_id = $2)`, id, subj.OrgID)
	if err := row.Scan(&name, &userID, &saID, &scopesJSON, &expiresAt, &revokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "token not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if revokedAt != nil {
		jsonError(w, http.StatusConflict, "token already revoked; create a new one")
		return
	}
	var scopeStrs []string
	_ = json.Unmarshal(scopesJSON, &scopeStrs)
	scopes, err := validateScopes(scopeStrs)
	if err != nil {
		// Existing token referenced a scope we no longer recognize. Reject the rotate
		// so the operator must explicitly re-issue with valid scopes.
		jsonError(w, http.StatusUnprocessableEntity, "stored token scopes invalid: "+err.Error())
		return
	}
	// A7: a rotate must not re-mint a token that violates the current lifetime cap
	// (e.g. an older unbounded token, or one whose stored expiry now exceeds the max).
	// The operator must re-create with a compliant expires_at instead.
	if err := h.checkPATLifetime(expiresAt); err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "stored token "+err.Error())
		return
	}

	// Revoke + mint in a transaction so we never have two active tokens for the same id.
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if _, err := tx.Exec(r.Context(),
		`UPDATE api_tokens SET revoked_at = NOW(), status = 'revoked' WHERE id = $1`, id); err != nil {
		jsonError(w, http.StatusInternalServerError, "revoke: "+err.Error())
		return
	}
	raw, newID, err := h.mintTx(r.Context(), tx, userID, saID, name, scopes, expiresAt)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "mint: "+err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}

	h.auditEvent(r.Context(), subj, "api_token.rotate", newID.String(), map[string]any{
		"old_id": id.String(),
		"name":   name,
		"scopes": scopes,
	})

	writeJSON(w, http.StatusOK, apiTokenCreateResponse{
		ID:       newID.String(),
		Name:     name,
		Scopes:   stringsFromScopes(scopes),
		RawToken: raw,
		Hint:     "Rotated. The previous token is now revoked. Store this new value — it will not be shown again.",
	})
}

// Revoke sets revoked_at + status. Idempotent.
func (h *APITokens) Revoke(w http.ResponseWriter, r *http.Request) {
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
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE api_tokens t
   SET revoked_at = NOW(), status = 'revoked'
  FROM (SELECT t2.id FROM api_tokens t2
         LEFT JOIN users u ON u.id = t2.user_id
         LEFT JOIN service_accounts sa ON sa.id = t2.service_account_id
        WHERE t2.id = $1 AND (u.org_id = $2 OR sa.org_id = $2)) scoped
 WHERE t.id = scoped.id`, id, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, http.StatusNotFound, "token not found")
		return
	}
	h.auditEvent(r.Context(), subj, "api_token.revoke", id.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// VerbCatalogResponse is what GET /api/v1/rbac/verbs returns to power the UI scope picker.
type VerbCatalogResponse struct {
	Verbs []rbac.VerbInfo `json:"verbs"`
}

// VerbCatalog returns the registry of every verb the RBAC engine knows about. The UI
// uses this to populate the scope-picker checkboxes grouped by category.
func (h *APITokens) VerbCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, VerbCatalogResponse{Verbs: rbac.VerbCatalog()})
}

// ---------- internals ----------

// checkPATLifetime enforces the A7 PAT lifetime cap. With a max configured, a PAT
// must carry an expires_at (unbounded tokens rejected) within now()+maxLifetime.
// With no max (zero), any expiry — including none — is accepted (back-compat).
func (h *APITokens) checkPATLifetime(expiresAt *time.Time) error {
	if h.maxLifetime <= 0 {
		return nil
	}
	if expiresAt == nil {
		return fmt.Errorf("expires_at is required: unbounded api tokens are not allowed (max lifetime %s)", h.maxLifetime)
	}
	max := time.Now().Add(h.maxLifetime)
	if expiresAt.After(max) {
		return fmt.Errorf("expires_at exceeds the maximum token lifetime of %s", h.maxLifetime)
	}
	return nil
}

func (h *APITokens) mint(ctx context.Context, userID, saID *uuid.UUID, name string, scopes []rbac.Verb, expiresAt *time.Time) (string, uuid.UUID, error) {
	raw, hash, err := generateAPITokenRaw()
	if err != nil {
		return "", uuid.Nil, err
	}
	id := uuid.New()
	scopesJSON, _ := json.Marshal(stringsFromScopes(scopes))
	if _, err := h.db.Pool().Exec(ctx, `
INSERT INTO api_tokens (id, user_id, service_account_id, name, token_hash, scopes, status, expires_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'active', $7)`,
		id, userID, saID, name, hash, scopesJSON, expiresAt); err != nil {
		return "", uuid.Nil, fmt.Errorf("insert api_token: %w", err)
	}
	return raw, id, nil
}

func (h *APITokens) mintTx(ctx context.Context, tx pgx.Tx, userID, saID *uuid.UUID, name string, scopes []rbac.Verb, expiresAt *time.Time) (string, uuid.UUID, error) {
	raw, hash, err := generateAPITokenRaw()
	if err != nil {
		return "", uuid.Nil, err
	}
	id := uuid.New()
	scopesJSON, _ := json.Marshal(stringsFromScopes(scopes))
	if _, err := tx.Exec(ctx, `
INSERT INTO api_tokens (id, user_id, service_account_id, name, token_hash, scopes, status, expires_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'active', $7)`,
		id, userID, saID, name, hash, scopesJSON, expiresAt); err != nil {
		return "", uuid.Nil, fmt.Errorf("insert api_token tx: %w", err)
	}
	return raw, id, nil
}

func (h *APITokens) auditEvent(ctx context.Context, subj Subject, action, targetID string, after map[string]any) {
	if h.audit == nil {
		return
	}
	uid, oid := subj.UserID, subj.OrgID
	if _, _, err := h.audit.Log(ctx, audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: action, TargetKind: "api_token", TargetID: targetID,
		After: after,
	}); err != nil {
		slog.WarnContext(ctx, "audit log failed", slog.String("action", action), slog.String("err", err.Error()))
	}
}

// serviceAccountAssignments turns a service account's stored roles JSON into RBAC
// assignments at the org scope (A7 least-privilege). Unknown role names are dropped.
// When no valid role remains, the SA falls back to a read-only role (RoleAuditor) so a
// service-account-attached PAT can never inherit GlobalAdmin via a missing/garbled grant.
func serviceAccountAssignments(orgID uuid.UUID, rolesJSON []byte) []rbac.RoleAssignment {
	var names []string
	_ = json.Unmarshal(rolesJSON, &names)
	out := make([]rbac.RoleAssignment, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if !rbac.IsRole(n) {
			continue
		}
		out = append(out, rbac.RoleAssignment{Role: n, Scope: rbac.Scope{OrgID: orgID}})
	}
	if len(out) == 0 {
		out = append(out, rbac.RoleAssignment{Role: rbac.RoleAuditor, Scope: rbac.Scope{OrgID: orgID}})
	}
	return out
}

// generateAPITokenRaw returns (raw, sha256hex(raw), err).
func generateAPITokenRaw() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("rand: %w", err)
	}
	raw := apiTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

// validateScopes parses + de-duplicates scope strings, rejecting any that aren't known
// or aren't user-grantable. Empty input is rejected — a token with no scopes is useless
// and almost always a UI bug.
func validateScopes(in []string) ([]rbac.Verb, error) {
	if len(in) == 0 {
		return nil, errors.New("at least one scope required")
	}
	seen := make(map[rbac.Verb]struct{}, len(in))
	out := make([]rbac.Verb, 0, len(in))
	for _, s := range in {
		v := rbac.Verb(strings.TrimSpace(s))
		if v == "" {
			continue
		}
		if !rbac.IsKnownVerb(v) {
			return nil, fmt.Errorf("unknown scope: %s", v)
		}
		if !rbac.IsUserGrantableVerb(v) {
			return nil, fmt.Errorf("scope not grantable to api tokens: %s", v)
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one scope required")
	}
	return out, nil
}

func stringsFromScopes(in []rbac.Verb) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, string(v))
	}
	return out
}

// resolveAttachment maps the request's "attached_to" string into either a user_id or a
// service_account_id. Accepted shapes:
//   - ""            => current user (default)
//   - "user"        => current user
//   - "user-<uuid>" => specific user in same org (admin path; minter must == subject.UserID)
//   - "service-account-<uuid>" => service account owned by same org
//
// Returns (userID, serviceAccountID, err). Exactly one of the two non-nil values is set.
func resolveAttachment(ctx context.Context, pool *pgxpool.Pool, subj Subject, attached string) (*uuid.UUID, *uuid.UUID, error) {
	attached = strings.TrimSpace(attached)
	if attached == "" || attached == "user" {
		uid := subj.UserID
		return &uid, nil, nil
	}
	if strings.HasPrefix(attached, "service-account-") {
		idStr := strings.TrimPrefix(attached, "service-account-")
		sid, err := uuid.Parse(idStr)
		if err != nil {
			return nil, nil, fmt.Errorf("bad service-account id: %w", err)
		}
		var orgID uuid.UUID
		if err := pool.QueryRow(ctx,
			`SELECT org_id FROM service_accounts WHERE id = $1`, sid).Scan(&orgID); err != nil {
			return nil, nil, fmt.Errorf("service account not found: %w", err)
		}
		if orgID != subj.OrgID {
			return nil, nil, errors.New("service account not in caller's org")
		}
		return nil, &sid, nil
	}
	return nil, nil, fmt.Errorf("unsupported attached_to: %s", attached)
}

func serviceAccountIDPtrString(p *uuid.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// loadAPITokensForOrg fetches all tokens belonging to users / service-accounts in orgID.
func loadAPITokensForOrg(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) ([]apiTokenDTO, error) {
	rows, err := pool.Query(ctx, `
SELECT t.id, t.name, COALESCE(t.scopes, '[]'::jsonb), COALESCE(t.status, 'active'),
       t.user_id, t.service_account_id,
       u.email, sa.name,
       t.created_at, t.expires_at, t.last_used_at, t.revoked_at
  FROM api_tokens t
  LEFT JOIN users u ON u.id = t.user_id
  LEFT JOIN service_accounts sa ON sa.id = t.service_account_id
 WHERE u.org_id = $1 OR sa.org_id = $1
 ORDER BY t.created_at DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("query api_tokens: %w", err)
	}
	defer rows.Close()
	out := []apiTokenDTO{}
	for rows.Next() {
		dto, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dto)
	}
	return out, rows.Err()
}

func loadAPITokenByID(ctx context.Context, pool *pgxpool.Pool, orgID, tokenID uuid.UUID) (apiTokenDTO, error) {
	row := pool.QueryRow(ctx, `
SELECT t.id, t.name, COALESCE(t.scopes, '[]'::jsonb), COALESCE(t.status, 'active'),
       t.user_id, t.service_account_id,
       u.email, sa.name,
       t.created_at, t.expires_at, t.last_used_at, t.revoked_at
  FROM api_tokens t
  LEFT JOIN users u ON u.id = t.user_id
  LEFT JOIN service_accounts sa ON sa.id = t.service_account_id
 WHERE t.id = $1 AND (u.org_id = $2 OR sa.org_id = $2)`, tokenID, orgID)
	return scanAPIToken(row)
}

// rowScanner is the common subset of pgx.Row / pgx.Rows we use in scanAPIToken so a
// single helper handles both code paths.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAPIToken(r rowScanner) (apiTokenDTO, error) {
	var (
		id            uuid.UUID
		name          string
		scopesJSON    []byte
		status        string
		userID, saID  *uuid.UUID
		email, saName *string
		createdAt     time.Time
		expiresAt     *time.Time
		lastUsedAt    *time.Time
		revokedAt     *time.Time
	)
	if err := r.Scan(&id, &name, &scopesJSON, &status, &userID, &saID, &email, &saName, &createdAt, &expiresAt, &lastUsedAt, &revokedAt); err != nil {
		return apiTokenDTO{}, err
	}
	var scopes []string
	_ = json.Unmarshal(scopesJSON, &scopes)
	if scopes == nil {
		scopes = []string{}
	}
	dto := apiTokenDTO{
		ID:        id.String(),
		Name:      name,
		Scopes:    scopes,
		Status:    deriveStatus(status, expiresAt, revokedAt),
		CreatedAt: createdAt.UTC().Format(time.RFC3339),
	}
	switch {
	case saID != nil:
		dto.AttachedToKind = "service-account"
		dto.AttachedToID = saID.String()
		if saName != nil {
			dto.AttachedToLabel = *saName
		}
	case userID != nil:
		dto.AttachedToKind = "user"
		dto.AttachedToID = userID.String()
		if email != nil {
			dto.AttachedToLabel = *email
		}
	}
	if expiresAt != nil {
		dto.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	}
	if lastUsedAt != nil {
		dto.LastUsedAt = lastUsedAt.UTC().Format(time.RFC3339)
	}
	if revokedAt != nil {
		dto.RevokedAt = revokedAt.UTC().Format(time.RFC3339)
	}
	return dto, nil
}

// deriveStatus computes the visible status pill regardless of how the DB column reads.
// We prefer "revoked" > "expired" > stored status > "active".
func deriveStatus(stored string, expiresAt, revokedAt *time.Time) string {
	if revokedAt != nil {
		return "revoked"
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return "expired"
	}
	if stored == "" {
		return "active"
	}
	return stored
}

// AuthenticateAPIToken validates a `cst_` bearer token against api_tokens, loads role
// assignments for the underlying user (or none, for a service-account-attached token),
// and returns the synthesized Subject. The caller is server.authMiddleware. Returns
// (subject, true) on success; (zero, false) on any failure.
//
// last_used_at is updated best-effort in a separate UPDATE — failures here do NOT block
// the request, matching the documented behaviour of the runtime-agent middleware.
//
// maxLifetime (A7) is the configured PAT lifetime cap. When > 0, a token with NO
// expires_at (an unbounded token minted before the cap existed, or while the cap was
// unset) is rejected once its age exceeds the cap — so the grandfathered population of
// never-expiring PATs cannot outlive the cap. A zero maxLifetime disables this check
// (back-compat). Tokens that DO carry an expires_at are bounded by it as before.
func AuthenticateAPIToken(ctx context.Context, pool *pgxpool.Pool, raw string, maxLifetime time.Duration, loadAssignments func(context.Context, uuid.UUID) ([]rbac.RoleAssignment, error)) (Subject, bool) {
	if !strings.HasPrefix(raw, apiTokenPrefix) {
		return Subject{}, false
	}
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])

	var (
		tokenID     uuid.UUID
		userID      *uuid.UUID
		saID        *uuid.UUID
		scopesJSON  []byte
		orgID       uuid.UUID
		email       *string
		saRolesJSON []byte
		saStatus    *string
	)
	// A7: bound grandfathered unbounded tokens. $2 is the cap in seconds; 0 means
	// "no cap" and the clause becomes a no-op (a NULL-expiry token still authenticates).
	capSeconds := int64(0)
	if maxLifetime > 0 {
		capSeconds = int64(maxLifetime / time.Second)
	}
	err := pool.QueryRow(ctx, `
SELECT t.id, t.user_id, t.service_account_id, COALESCE(t.scopes, '[]'::jsonb),
       COALESCE(u.org_id, sa.org_id) AS org_id,
       u.email,
       COALESCE(sa.roles, '[]'::jsonb), sa.status
  FROM api_tokens t
  LEFT JOIN users u            ON u.id = t.user_id
  LEFT JOIN service_accounts sa ON sa.id = t.service_account_id
 WHERE t.token_hash = $1
   AND t.revoked_at IS NULL
   AND (t.expires_at IS NULL OR t.expires_at > NOW())
   -- A7: a configured lifetime cap also bounds tokens that never got an expires_at:
   -- once such a token is older than the cap it is rejected. No cap ($2 = 0) => no-op.
   AND ($2 = 0 OR t.expires_at IS NOT NULL OR t.created_at > NOW() - make_interval(secs => $2))
   AND COALESCE(t.status, 'active') = 'active'
   -- A1: a disabled user's PATs must stop working immediately. Service-account-
   -- attached tokens (u.id IS NULL) are unaffected by this clause.
   AND (u.id IS NULL OR u.disabled = FALSE)
   -- A4: a user under forced password reset (must_change_password) must not be able to
   -- sidestep the reset gate via a PAT — the JWT path 403s such users, so the PAT path
   -- must reject them too. Service-account-attached tokens are exempt by design.
   AND (u.id IS NULL OR u.must_change_password = FALSE)
   -- A7: a disabled service account's tokens stop working too.
   AND (sa.id IS NULL OR COALESCE(sa.status, 'active') = 'active')`,
		hash, capSeconds).Scan(&tokenID, &userID, &saID, &scopesJSON, &orgID, &email, &saRolesJSON, &saStatus)
	if err != nil {
		return Subject{}, false
	}

	var scopeStrs []string
	_ = json.Unmarshal(scopesJSON, &scopeStrs)
	scopes := make([]rbac.Verb, 0, len(scopeStrs))
	for _, s := range scopeStrs {
		v := rbac.Verb(s)
		if rbac.IsKnownVerb(v) {
			scopes = append(scopes, v)
		}
	}
	// Tokens with zero valid scopes are useless; reject auth rather than silently
	// minting a privilege-less session (which would 403 every request opaquely).
	if len(scopes) == 0 {
		return Subject{}, false
	}

	subj := Subject{OrgID: orgID, TokenScopes: scopes, TokenID: tokenID.String()}

	// Load role assignments for whichever principal the token is attached to.
	switch {
	case userID != nil:
		subj.UserID = *userID
		if email != nil {
			subj.Email = *email
		}
		if loadAssignments != nil {
			as, err := loadAssignments(ctx, *userID)
			if err == nil {
				subj.Assignments = as
			}
		}
	case saID != nil:
		// A7 least-privilege: a service-account-attached token is bound to the SA's
		// EXPLICIT role grants (service_accounts.roles), not a synthetic GlobalAdmin.
		// The effective verbs are still the intersection of these role grants ∩ the
		// token's declared scopes (Subject.HasTokenScope), but the base grant is now
		// the operator-chosen least-privilege role rather than an org-wide superuser.
		// A SA with no roles configured gets a read-only floor (RoleAuditor) so an
		// over-scoped token can never silently inherit admin verbs.
		subj.Email = "service-account:" + saID.String()
		subj.Assignments = serviceAccountAssignments(orgID, saRolesJSON)
	}

	// Best-effort last_used_at update. We deliberately don't wait on this — the spec
	// calls out "update async, don't block the request." Failures are logged at debug
	// and swallowed.
	go func(id uuid.UUID) {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(bgCtx,
			`UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`, id); err != nil {
			slog.Debug("update api_token last_used_at", slog.String("err", err.Error()))
		}
	}(tokenID)

	return subj, true
}
