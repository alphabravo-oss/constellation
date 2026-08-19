package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// ---- pure (no-DB) unit tests for the A7 helpers ----

// A7: with a max lifetime configured, an unbounded (nil expiry) PAT and one beyond the
// cap are rejected, while one inside the window passes. With no cap, anything passes.
func TestCheckPATLifetime(t *testing.T) {
	capped := &APITokens{maxLifetime: 24 * time.Hour}
	if err := capped.checkPATLifetime(nil); err == nil {
		t.Fatalf("unbounded PAT must be rejected when a max lifetime is set")
	}
	tooFar := time.Now().Add(48 * time.Hour)
	if err := capped.checkPATLifetime(&tooFar); err == nil {
		t.Fatalf("PAT beyond max lifetime must be rejected")
	}
	ok := time.Now().Add(1 * time.Hour)
	if err := capped.checkPATLifetime(&ok); err != nil {
		t.Fatalf("PAT within max lifetime must be accepted: %v", err)
	}

	uncapped := &APITokens{maxLifetime: 0}
	if err := uncapped.checkPATLifetime(nil); err != nil {
		t.Fatalf("with no cap, unbounded PAT must be accepted: %v", err)
	}
}

// A7: a service account is bound to its EXPLICIT roles, never a synthetic GlobalAdmin.
// An SA with no roles falls back to a read-only floor (Auditor), and unknown role names
// are dropped (also falling back to Auditor rather than silently escalating).
func TestServiceAccountAssignments_NeverGlobalAdmin(t *testing.T) {
	org := uuid.New()

	// Explicit least-privilege role is honored, and GlobalAdmin is never synthesized.
	as := serviceAccountAssignments(org, []byte(`["Analyst"]`))
	if len(as) != 1 || as[0].Role != rbac.RoleAnalyst || as[0].Scope.OrgID != org {
		t.Fatalf("explicit role not honored: %+v", as)
	}
	for _, a := range as {
		if a.Role == rbac.RoleGlobalAdmin {
			t.Fatalf("service account must not be granted GlobalAdmin")
		}
	}

	// Empty roles -> read-only Auditor floor, NOT GlobalAdmin.
	floor := serviceAccountAssignments(org, []byte(`[]`))
	if len(floor) != 1 || floor[0].Role != rbac.RoleAuditor {
		t.Fatalf("empty-roles SA must default to Auditor floor, got %+v", floor)
	}

	// Unknown/garbled role names are dropped; the floor still is not GlobalAdmin.
	junk := serviceAccountAssignments(org, []byte(`["NotARole","alsoBogus"]`))
	if len(junk) != 1 || junk[0].Role == rbac.RoleGlobalAdmin {
		t.Fatalf("unknown roles must drop to a non-admin floor, got %+v", junk)
	}
}

// ---- DB-backed integration tests ----

// ensureA7Schema idempotently applies the A7 DDL (migration 101) so the DB-backed tests
// run even before goose is pointed at the test database. Mirrors the A5 sessionkeys_test
// approach. Relaxing api_tokens.user_id is what makes the service-account token path mint.
func ensureA7Schema(t *testing.T, d *db.DB) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`ALTER TABLE api_tokens ALTER COLUMN user_id DROP NOT NULL`,
		`ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()`,
	}
	for _, s := range stmts {
		if _, err := d.Pool().Exec(ctx, s); err != nil {
			t.Fatalf("ensure A7 schema (%s): %v", s, err)
		}
	}
}

// A7: minting an unbounded (no expires_at) PAT is rejected once a max lifetime is set.
func TestAPITokens_Create_RejectsUnboundedPAT(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ensureA7Schema(t, d)
	ctx := context.Background()

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := d.Pool().Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'A7 PAT Test')`,
		orgID, "a7-pat-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := d.Pool().Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'A7 Admin')`,
		userID, orgID, "a7-pat-"+userID.String()+"@example.test"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM api_tokens WHERE user_id = $1`, userID)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	h := NewAPITokens(d, nil).WithMaxLifetime(24 * time.Hour)
	subj := authctx.Subject{UserID: userID, OrgID: orgID, Email: "a7@example.test"}

	mkReq := func(body map[string]any) *http.Request {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/api-tokens", bytes.NewReader(b))
		return req.WithContext(authctx.WithSubject(context.Background(), subj))
	}

	// Unbounded (no expires_at) -> 400.
	w := httptest.NewRecorder()
	h.Create(w, mkReq(map[string]any{"name": "unbounded", "scopes": []string{string(rbac.VerbReadFindings)}}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unbounded PAT create = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}

	// Beyond the cap -> 400.
	w = httptest.NewRecorder()
	h.Create(w, mkReq(map[string]any{
		"name":       "too-long",
		"scopes":     []string{string(rbac.VerbReadFindings)},
		"expires_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339),
	}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("over-cap PAT create = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}

	// Within the cap -> 201.
	w = httptest.NewRecorder()
	h.Create(w, mkReq(map[string]any{
		"name":       "ok",
		"scopes":     []string{string(rbac.VerbReadFindings)},
		"expires_at": time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("within-cap PAT create = %d, want 201 (body=%s)", w.Code, w.Body.String())
	}
}

// A7: a service-account-attached PAT resolves to the SA's explicit roles, NOT a synthetic
// GlobalAdmin. We mint a SA-attached token (Analyst role) and assert the authenticated
// subject carries Analyst at the org scope and no GlobalAdmin assignment.
func TestAuthenticateAPIToken_ServiceAccountNotGlobalAdmin(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ensureA7Schema(t, d)
	ctx := context.Background()

	orgID := uuid.New()
	saID := uuid.New()
	if _, err := d.Pool().Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'A7 SA Test')`,
		orgID, "a7-sa-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := d.Pool().Exec(ctx, `
INSERT INTO service_accounts (id, org_id, name, roles)
VALUES ($1, $2, $3, '["Analyst"]'::jsonb)`,
		saID, orgID, "a7-sa-"+saID.String()); err != nil {
		t.Fatalf("insert service account: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM api_tokens WHERE service_account_id = $1`, saID)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM service_accounts WHERE id = $1`, saID)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	// Mint a SA-attached PAT directly via the handler's mint helper.
	h := NewAPITokens(d, nil)
	raw, _, err := h.mint(ctx, nil, &saID, "sa-token", []rbac.Verb{rbac.VerbReadFindings, rbac.VerbManageOrg}, nil)
	if err != nil {
		t.Fatalf("mint SA token: %v", err)
	}

	// loadAssignments must NOT be consulted for a SA-attached token; pass a sentinel that
	// would fail the test if called.
	loadAssignments := func(context.Context, uuid.UUID) ([]rbac.RoleAssignment, error) {
		t.Fatalf("loadAssignments should not be called for a service-account token")
		return nil, nil
	}
	subj, ok := AuthenticateAPIToken(ctx, d.Pool(), raw, 0, loadAssignments)
	if !ok {
		t.Fatalf("AuthenticateAPIToken failed for SA token")
	}

	sawAnalyst := false
	for _, a := range subj.Assignments {
		if a.Role == rbac.RoleGlobalAdmin {
			t.Fatalf("service-account token must NOT synthesize GlobalAdmin, got assignments %+v", subj.Assignments)
		}
		if a.Role == rbac.RoleAnalyst && a.Scope.OrgID == orgID {
			sawAnalyst = true
		}
	}
	if !sawAnalyst {
		t.Fatalf("expected Analyst assignment at org scope, got %+v", subj.Assignments)
	}

	// And the verb envelope reflects least-privilege: Analyst lacks VerbManageOrg even
	// though the token's scopes requested it, so the intersection denies the admin verb.
	res := rbac.Resource{OrgID: orgID}
	if err := rbac.Authorize(subj.Assignments, rbac.VerbManageOrg, res); err == nil {
		t.Fatalf("SA base grant must not authorize VerbManageOrg (would mean GlobalAdmin leaked)")
	}
	if err := rbac.Authorize(subj.Assignments, rbac.VerbReadFindings, res); err != nil {
		t.Fatalf("SA Analyst should authorize VerbReadFindings: %v", err)
	}
}
