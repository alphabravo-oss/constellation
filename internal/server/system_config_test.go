package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/observability"
)

// newSysConfigTestServer boots a Server (keeping the *Server handle so the test can
// assert the in-process accessor) plus an httptest server, a GlobalAdmin user, and an
// Auditor user (no VerbManageSystemConfig). Skips when the test DB is unreachable.
func newSysConfigTestServer(t *testing.T) (*Server, *httptest.Server, *pgxpool.Pool, *auth.Signer, uuid.UUID, uuid.UUID, uuid.UUID) {
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
	// Idempotent schema-ensure (mirrors migration 102) so the test runs even before
	// goose is pointed at the test DB.
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS system_config (
  org_id UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  revision BIGINT NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by UUID)`); err != nil {
		pool.Close()
		t.Fatalf("ensure system_config: %v", err)
	}

	orgID := uuid.New()
	adminID := uuid.New()
	auditorID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'SysCfg Test')`,
		orgID, "syscfg-org-"+orgID.String()); err != nil {
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
		_, _ = pool.Exec(c, `DELETE FROM system_config WHERE org_id = $1`, orgID)
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
	signer, err := auth.NewSigner(cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTL, cfg.JWTKeys...)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts, pool, signer, adminID, auditorID, orgID
}

// doJSON issues a request with the bearer and returns status + decoded body map.
func doJSON(t *testing.T, method, url, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// TestSystemConfig_PatchHotReloadGetRedactAndRBAC exercises the B1 acceptance criteria
// end-to-end through the HTTP surface:
//   - env-seeded row exists from first boot (GET returns a config, not 404).
//   - PATCH changes a knob and the in-process accessor reflects it WITHOUT restart.
//   - GET (and the PATCH response) redact the CA-bundle secret.
//   - a caller lacking VerbManageSystemConfig (Auditor) gets 403 on both routes.
func TestSystemConfig_PatchHotReloadGetRedactAndRBAC(t *testing.T) {
	srv, ts, _, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	ctx := context.Background()
	admin := issueFor(t, signer, adminID, orgID, 0)

	// First boot: env seeded a row, so GET returns a config (TLS verify defaults true).
	st, body := doJSON(t, http.MethodGet, ts.URL+"/api/v1/system/config", admin, nil)
	if st != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 (env should seed first boot)", st)
	}
	cfg, _ := body["config"].(map[string]any)
	if cfg == nil {
		t.Fatalf("GET missing config object: %+v", body)
	}
	if v, _ := cfg["tls_verify"].(bool); !v {
		t.Fatalf("seeded tls_verify = %v, want true (default)", cfg["tls_verify"])
	}
	if got, _ := body["source"].(string); got != "system_config" {
		t.Fatalf("GET source = %q, want system_config", got)
	}
	if got, _ := body["updated_at"].(string); got == "" {
		t.Fatalf("GET missing updated_at metadata: %+v", body)
	}

	caPEM := testCAPEM(t)

	// PATCH: set a proxy, a syslog target, and a CA bundle.
	patch := map[string]any{
		"egress_proxy":       map[string]any{"https_proxy": "http://egress.test:3128"},
		"ca_bundle_pem":      caPEM,
		"syslog_siem_target": map[string]any{"host": "siem.test", "port": 6514, "protocol": "tcp"},
	}
	st, body = doJSON(t, http.MethodPatch, ts.URL+"/api/v1/system/config", admin, patch)
	if st != http.StatusOK {
		t.Fatalf("PATCH status = %d body=%+v, want 200", st, body)
	}
	rcfg, _ := body["config"].(map[string]any)
	if got, _ := rcfg["ca_bundle_pem"].(string); got == caPEM || got == "" {
		t.Fatalf("PATCH response leaked or dropped ca bundle: %q", got)
	}

	// GET again: proxy applied, CA bundle redacted (set, but masked).
	_, body = doJSON(t, http.MethodGet, ts.URL+"/api/v1/system/config", admin, nil)
	cfg, _ = body["config"].(map[string]any)
	proxy, _ := cfg["egress_proxy"].(map[string]any)
	if got, _ := proxy["https_proxy"].(string); got != "http://egress.test:3128" {
		t.Fatalf("GET proxy = %q, want the PATCHed value WITHOUT restart", got)
	}
	if got, _ := cfg["ca_bundle_pem"].(string); got == "" || got == caPEM {
		t.Fatalf("GET ca_bundle_pem = %q, want redacted marker (set-but-masked)", got)
	}
	if got, _ := body["updated_by"].(string); got == "" {
		t.Fatalf("GET missing updated_by metadata after PATCH: %+v", body)
	}

	// In-process accessor on the running Server reflects the change WITHOUT a restart
	// (the PATCH wrote through Provider.UpdateAfterPatch).
	live := srv.syscfg.Get(ctx, orgID)
	if live.EgressProxy.HTTPSProxy != "http://egress.test:3128" {
		t.Fatalf("in-process accessor proxy = %q, want updated live", live.EgressProxy.HTTPSProxy)
	}
	if live.SyslogSIEM.Addr() != "siem.test:6514" {
		t.Fatalf("in-process accessor syslog = %q, want siem.test:6514", live.SyslogSIEM.Addr())
	}
	// Consumer (b): the syslog/SIEM sender resolves the live target.
	if sender, ok := srv.syscfg.SyslogSender(ctx, orgID); !ok || sender.Addr != "siem.test:6514" {
		t.Fatalf("syslog sender did not pick up live target: ok=%v", ok)
	}

	// RBAC: an Auditor (no VerbManageSystemConfig) is forbidden on both routes.
	auditorTok := issueFor(t, signer, auditorID, orgID, 0)
	if st, _ := doJSON(t, http.MethodGet, ts.URL+"/api/v1/system/config", auditorTok, nil); st != http.StatusForbidden {
		t.Fatalf("auditor GET = %d, want 403", st)
	}
	if st, _ := doJSON(t, http.MethodPatch, ts.URL+"/api/v1/system/config", auditorTok, map[string]any{"tls_verify": false}); st != http.StatusForbidden {
		t.Fatalf("auditor PATCH = %d, want 403", st)
	}
}

// TestSystemConfig_ProxyCredentialRedaction confirms the B1-high fix: a credentialed
// egress proxy URL is NOT returned in cleartext on GET; its userinfo is redacted. The
// audit trail uses the same Redacted() path so it is covered transitively.
func TestSystemConfig_ProxyCredentialRedaction(t *testing.T) {
	_, ts, _, signer, adminID, _, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)

	st, body := doJSON(t, http.MethodPatch, ts.URL+"/api/v1/system/config", admin,
		map[string]any{"egress_proxy": map[string]any{"https_proxy": "https://bob:hunter2@proxy.test:3128"}})
	if st != http.StatusOK {
		t.Fatalf("PATCH status = %d body=%+v, want 200", st, body)
	}

	_, body = doJSON(t, http.MethodGet, ts.URL+"/api/v1/system/config", admin, nil)
	cfg, _ := body["config"].(map[string]any)
	proxy, _ := cfg["egress_proxy"].(map[string]any)
	got, _ := proxy["https_proxy"].(string)
	if bytes.Contains([]byte(got), []byte("hunter2")) || bytes.Contains([]byte(got), []byte("bob")) {
		t.Fatalf("GET leaked proxy credentials in cleartext: %q", got)
	}
	if got == "" {
		t.Fatalf("GET dropped the proxy entirely: %q", got)
	}
}

// TestSystemConfig_ConcurrentPatchNoLostUpdate confirms the B1-medium fix: two concurrent
// PATCHes that each change a DIFFERENT field must both survive (optimistic-concurrency
// retry loop), rather than the last writer clobbering the other's field.
func TestSystemConfig_ConcurrentPatchNoLostUpdate(t *testing.T) {
	_, ts, _, signer, adminID, _, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)

	// Fire two PATCHes to disjoint fields at the same time.
	start := make(chan struct{})
	done := make(chan int, 2)
	patches := []map[string]any{
		{"egress_proxy": map[string]any{"https_proxy": "http://proxy.test:3128"}},
		{"syslog_siem_target": map[string]any{"host": "siem.test", "port": 6514, "protocol": "tcp"}},
	}
	for _, p := range patches {
		go func(p map[string]any) {
			<-start
			st, _ := doJSON(t, http.MethodPatch, ts.URL+"/api/v1/system/config", admin, p)
			done <- st
		}(p)
	}
	close(start)
	for i := 0; i < 2; i++ {
		if st := <-done; st != http.StatusOK {
			t.Fatalf("concurrent PATCH %d status = %d, want 200 (retry should resolve the conflict)", i, st)
		}
	}

	// Both fields must be present in the final state — neither write was lost.
	_, body := doJSON(t, http.MethodGet, ts.URL+"/api/v1/system/config", admin, nil)
	cfg, _ := body["config"].(map[string]any)
	proxy, _ := cfg["egress_proxy"].(map[string]any)
	if v, _ := proxy["https_proxy"].(string); v != "http://proxy.test:3128" {
		t.Fatalf("egress_proxy.https_proxy = %v, want http://proxy.test:3128 (lost update)", proxy["https_proxy"])
	}
	syslog, _ := cfg["syslog_siem_target"].(map[string]any)
	if h, _ := syslog["host"].(string); h != "siem.test" {
		t.Fatalf("syslog host = %v, want siem.test (lost update)", syslog["host"])
	}
}

// testCAPEM returns a valid self-signed CA certificate PEM for the redaction assertions.
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
