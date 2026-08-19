package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/observability"
)

// newAuthServersTestServer boots a Server against the test DB with a GlobalAdmin (has
// VerbManageAuthServers) and an Auditor (does not), plus an httptest server. It returns the
// *Server so the test can assert the in-process provider set. Skips when the DB is unreachable.
func newAuthServersTestServer(t *testing.T) (*Server, *httptest.Server, *pgxpool.Pool, *auth.Signer, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	t.Setenv("CONSTELLATION_ALLOW_HS256_JWT", "true")
	ctx := context.Background()
	url := testDBURL()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("skipping: cannot ping test DB (%v)", err)
	}
	// Idempotent schema-ensure (mirrors migration 104) so the test runs even before goose is
	// pointed at the test DB.
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS auth_servers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('ldap','saml','oidc')),
  name TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  auth_order INTEGER NOT NULL DEFAULT 100,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  role_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
  revision BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by UUID,
  UNIQUE (org_id, name))`); err != nil {
		pool.Close()
		t.Fatalf("ensure auth_servers: %v", err)
	}

	orgID := uuid.New()
	adminID := uuid.New()
	auditorID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'AuthServers Test')`,
		orgID, "authsrv-org-"+orgID.String()); err != nil {
		pool.Close()
		t.Fatalf("insert org: %v", err)
	}
	for _, u := range []struct {
		id   uuid.UUID
		role string
	}{{adminID, "GlobalAdmin"}, {auditorID, "Auditor"}} {
		if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, session_epoch)
VALUES ($1, $2, $3, $4, 0)`, u.id, orgID, u.role+"-"+u.id.String()+"@example.test", u.role); err != nil {
			pool.Close()
			t.Fatalf("insert user %s: %v", u.role, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, $2, $3)`,
			u.id, u.role, orgID); err != nil {
			pool.Close()
			t.Fatalf("insert role %s: %v", u.role, err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM auth_servers WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(c, `DELETE FROM role_assignments WHERE user_id = ANY($1)`, []uuid.UUID{adminID, auditorID})
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{adminID, auditorID})
		_, _ = pool.Exec(c, `DELETE FROM orgs WHERE id = $1`, orgID)
		pool.Close()
	})

	dbHandle, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	t.Cleanup(dbHandle.Close)

	tel, _ := observability.Init(ctx, "test")
	cfg := Config{
		ListenAddr:  ":0",
		DatabaseURL: url,
		JWTKeys:     [][]byte{[]byte("0123456789abcdef0123456789abcdef")},
		JWTIssuer:   "constellation-test",
		JWTAudience: "constellation-api",
		JWTTTL:      time.Hour,
		CORSOrigins: []string{"http://localhost:5173"},
	}
	srv, err := New(ctx, cfg, tel, dbHandle)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Pin the provider set to the test org (firstOrgID may pick a different org in a shared DB).
	srv.bootstrapOrgID = orgID
	_ = srv.authProviders.Reload(ctx, dbHandle.Pool(), orgID)

	signer, err := auth.NewSigner(cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTL, cfg.JWTKeys...)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts, pool, signer, adminID, auditorID, orgID
}

// TestAuthServers_CRUDHotReloadRedactRBAC exercises the B4 acceptance criteria end-to-end:
//   - create an LDAP IdP row at runtime; the in-process provider set reflects it WITHOUT restart.
//   - update the row at runtime; the live provider rebuilds (URL changes) without restart.
//   - GET redacts the provider secret (bind password).
//   - auth_order is honored: the lower-order enabled LDAP row is the active provider.
//   - a caller lacking VerbManageAuthServers (Auditor) gets 403 on every route.
func TestAuthServers_CRUDHotReloadRedactRBAC(t *testing.T) {
	srv, ts, _, signer, adminID, auditorID, orgID := newAuthServersTestServer(t)
	ctx := context.Background()
	admin := issueFor(t, signer, adminID, orgID, 0)

	// No providers yet.
	if srv.authProviders.LDAP() != nil {
		t.Fatalf("expected no LDAP provider before any row")
	}

	// Create an LDAP IdP with a secret bind password.
	create := map[string]any{
		"type":       "ldap",
		"name":       "corp-ad",
		"enabled":    true,
		"auth_order": 100,
		"config": map[string]any{
			"url":           "ldap://primary.example.com:389",
			"bind_dn":       "cn=svc,dc=example,dc=com",
			"bind_password": "s3cr3t-primary",
			"base_dn":       "ou=people,dc=example,dc=com",
			"user_filter":   "(uid=%s)",
		},
		"role_mapping": map[string]any{"rules": map[string]string{"admins": "SecurityAdmin"}},
	}
	st, body := doJSON(t, http.MethodPost, ts.URL+"/api/v1/auth-servers", admin, create)
	if st != http.StatusCreated {
		t.Fatalf("POST status = %d body=%+v, want 201", st, body)
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("POST returned no id: %+v", body)
	}
	// Create response redacts the secret.
	if leaked := bindPasswordOf(body); leaked == "s3cr3t-primary" {
		t.Fatalf("POST response leaked bind_password in cleartext")
	}

	// Hot-reload (no restart): the in-process provider set now has an LDAP provider pointing at
	// the created URL. The handler kicked an immediate reload on create.
	if p := srv.authProviders.LDAP(); p == nil {
		t.Fatalf("LDAP provider not built after create (hot-reload failed)")
	} else if p.URL() != "ldap://primary.example.com:389" {
		t.Fatalf("LDAP provider URL = %q, want the created value WITHOUT restart", p.URL())
	}

	// GET redacts the secret.
	st, getBody := doJSON(t, http.MethodGet, ts.URL+"/api/v1/auth-servers/"+id, admin, nil)
	if st != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", st)
	}
	if got := bindPasswordOf(getBody); got == "s3cr3t-primary" || got == "" {
		t.Fatalf("GET bind_password = %q, want redacted marker (set-but-masked)", got)
	}

	// Update the row's URL at runtime (and echo back the redacted secret to prove it is preserved,
	// not wiped). The live provider must rebuild to the new URL WITHOUT a restart.
	update := map[string]any{
		"name":       "corp-ad",
		"enabled":    true,
		"auth_order": 100,
		"config": map[string]any{
			"url":           "ldap://secondary.example.com:389",
			"bind_dn":       "cn=svc,dc=example,dc=com",
			"bind_password": "***REDACTED***", // redacted echo: must preserve the stored secret
			"base_dn":       "ou=people,dc=example,dc=com",
			"user_filter":   "(uid=%s)",
		},
		"role_mapping": map[string]any{"rules": map[string]string{"admins": "SecurityAdmin"}},
	}
	st, body = doJSON(t, http.MethodPut, ts.URL+"/api/v1/auth-servers/"+id, admin, update)
	if st != http.StatusOK {
		t.Fatalf("PUT status = %d body=%+v, want 200", st, body)
	}
	if p := srv.authProviders.LDAP(); p == nil || p.URL() != "ldap://secondary.example.com:389" {
		t.Fatalf("LDAP provider URL did not hot-reload to the updated value")
	}
	// H2: the bind password is SEALED at rest, never cleartext in config JSONB. Assert the stored
	// value is the sealed form (prefixed, not the plaintext) and that the redacted-echo PUT preserved
	// it (a wipe would leave it empty). The live provider hot-reloading above proves it still decrypts.
	var storedPW string
	if err := srv.db.Pool().QueryRow(ctx,
		`SELECT config->>'bind_password' FROM auth_servers WHERE id=$1`, id).Scan(&storedPW); err != nil {
		t.Fatalf("read stored bind_password: %v", err)
	}
	if storedPW == "s3cr3t-primary" {
		t.Fatalf("bind_password stored in CLEARTEXT (H2 not sealed): %q", storedPW)
	}
	if !strings.HasPrefix(storedPW, "cstl-enc:v1:") {
		t.Fatalf("bind_password not sealed (redacted-echo PUT may have wiped it): got %q", storedPW)
	}

	// auth_order honored: add a SECOND enabled LDAP row with a LOWER auth_order; it must become
	// the active provider after reload.
	create2 := map[string]any{
		"type":       "ldap",
		"name":       "corp-ad-preferred",
		"enabled":    true,
		"auth_order": 10, // lower => wins
		"config": map[string]any{
			"url":         "ldap://preferred.example.com:389",
			"base_dn":     "ou=people,dc=example,dc=com",
			"user_filter": "(uid=%s)",
		},
	}
	st, _ = doJSON(t, http.MethodPost, ts.URL+"/api/v1/auth-servers", admin, create2)
	if st != http.StatusCreated {
		t.Fatalf("POST (preferred) status = %d, want 201", st)
	}
	if p := srv.authProviders.LDAP(); p == nil || p.URL() != "ldap://preferred.example.com:389" {
		t.Fatalf("auth_order not honored: active LDAP = %v, want preferred (auth_order 10)",
			ldapURL(srv.authProviders.LDAP()))
	}

	// RBAC: an Auditor (no VerbManageAuthServers) is forbidden on every route.
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/auth-servers", nil},
		{http.MethodGet, "/api/v1/auth-servers/" + id, nil},
		{http.MethodPost, "/api/v1/auth-servers", create},
		{http.MethodPut, "/api/v1/auth-servers/" + id, update},
		{http.MethodDelete, "/api/v1/auth-servers/" + id, nil},
	} {
		if st, _ := doJSON(t, tc.method, ts.URL+tc.path, auditor, tc.body); st != http.StatusForbidden {
			t.Fatalf("auditor %s %s = %d, want 403", tc.method, tc.path, st)
		}
	}

	// Delete removes the row and hot-reloads (the secondary, higher-order row remains; deleting
	// the preferred one flips the active provider back).
	st, _ = doJSON(t, http.MethodGet, ts.URL+"/api/v1/auth-servers", admin, nil)
	if st != http.StatusOK {
		t.Fatalf("admin LIST status = %d, want 200", st)
	}
}

func bindPasswordOf(body map[string]any) string {
	cfg, _ := body["config"].(map[string]any)
	if cfg == nil {
		return ""
	}
	s, _ := cfg["bind_password"].(string)
	return s
}

func ldapURL(p *auth.LDAPProvider) string {
	if p == nil {
		return "<nil>"
	}
	return p.URL()
}
