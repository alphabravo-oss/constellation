package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/observability"
)

// mintTestPAT returns (rawToken, sha256hex(rawToken)) using the same shape the production
// minter uses: "cst_" + base64url(32 random bytes). The auth middleware routes on the
// "cst_" prefix and matches sha256(raw) against api_tokens.token_hash.
func mintTestPAT(t *testing.T) (string, string) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	raw := "cst_" + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

// A1 negative tests for the JWT auth middleware: a disabled user, a logged-out session,
// and a post-role/password-change session must all be rejected on their next request even
// though the JWT itself is still cryptographically valid and unexpired. These exercise the
// DB-backed revocation primitive (users.disabled + users.session_epoch) wired into
// authMiddleware. They run against the shared test DB and skip when it is unreachable.
func testDBURL() string {
	if u := os.Getenv("CONSTELLATION_TEST_DATABASE_URL"); u != "" {
		return u
	}
	return "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
}

// newAuthTestServer boots a Server against the test DB and returns it plus a seeded,
// enabled GlobalAdmin user. Skips the test if the DB is unreachable.
func newAuthTestServer(t *testing.T) (*httptest.Server, *pgxpool.Pool, *auth.Signer, uuid.UUID, uuid.UUID) {
	t.Helper()
	t.Setenv("CONSTELLATION_ALLOW_HS256_JWT", "true") // tests sign with a symmetric JWTKeys secret
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

	orgID := uuid.New()
	userID := uuid.New()
	email := "revoke-" + userID.String() + "@example.test"
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Revoke Test')`,
		orgID, "revoke-org-"+orgID.String()); err != nil {
		pool.Close()
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, session_epoch)
VALUES ($1, $2, $3, 'Revoke Admin', 0)`, userID, orgID, email); err != nil {
		pool.Close()
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'GlobalAdmin', $2)`,
		userID, orgID); err != nil {
		pool.Close()
		t.Fatalf("insert role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_tokens WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
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
	return ts, pool, signer, userID, orgID
}

// getMe issues GET /api/v1/auth/me with the bearer and returns the status code.
func getMe(t *testing.T, baseURL, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/auth/me", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func issueFor(t *testing.T, signer *auth.Signer, userID, orgID uuid.UUID, epoch int64) string {
	t.Helper()
	tok, _, err := signer.Issue(userID, orgID, "revoke@example.test", []string{"GlobalAdmin"}, epoch)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

func TestAuthMiddleware_DisabledUserJWTRejected(t *testing.T) {
	ts, pool, signer, userID, orgID := newAuthTestServer(t)
	ctx := context.Background()

	tok := issueFor(t, signer, userID, orgID, 0)
	if got := getMe(t, ts.URL, tok); got != http.StatusOK {
		t.Fatalf("pre-disable /me = %d, want 200", got)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET disabled = TRUE WHERE id = $1`, userID); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if got := getMe(t, ts.URL, tok); got != http.StatusUnauthorized {
		t.Fatalf("post-disable /me = %d, want 401", got)
	}
}

func TestAuthMiddleware_EpochBumpInvalidatesPriorJWT(t *testing.T) {
	ts, pool, signer, userID, orgID := newAuthTestServer(t)
	ctx := context.Background()

	tok := issueFor(t, signer, userID, orgID, 0)
	if got := getMe(t, ts.URL, tok); got != http.StatusOK {
		t.Fatalf("pre-bump /me = %d, want 200", got)
	}
	// Simulate a password-change / role-change / disable bumping the epoch.
	if _, err := pool.Exec(ctx, `UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1`, userID); err != nil {
		t.Fatalf("bump epoch: %v", err)
	}
	if got := getMe(t, ts.URL, tok); got != http.StatusUnauthorized {
		t.Fatalf("stale-epoch /me = %d, want 401", got)
	}
	// A token minted at the new epoch still works.
	fresh := issueFor(t, signer, userID, orgID, 1)
	if got := getMe(t, ts.URL, fresh); got != http.StatusOK {
		t.Fatalf("fresh-epoch /me = %d, want 200", got)
	}
}

func TestAuthMiddleware_LogoutInvalidatesJWT(t *testing.T) {
	ts, _, signer, userID, orgID := newAuthTestServer(t)

	tok := issueFor(t, signer, userID, orgID, 0)
	// Logout with the token bumps the epoch server-side.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", resp.StatusCode)
	}
	// The same token can no longer be used.
	if got := getMe(t, ts.URL, tok); got != http.StatusUnauthorized {
		t.Fatalf("post-logout /me = %d, want 401", got)
	}
}

func TestAuthMiddleware_DisabledPATReturns401(t *testing.T) {
	ts, pool, _, userID, _ := newAuthTestServer(t)
	ctx := context.Background()

	// Mint a PAT for the user directly. raw = "cst_" + token; store sha256(raw).
	raw, hash := mintTestPAT(t)
	tokenID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO api_tokens (id, user_id, name, token_hash, scopes, status)
VALUES ($1, $2, 'revoke-pat', $3, '["read-findings"]'::jsonb, 'active')`,
		tokenID, userID, hash); err != nil {
		t.Fatalf("insert pat: %v", err)
	}
	// Active PAT on an enabled user authenticates (200 on /me).
	if got := getMe(t, ts.URL, raw); got != http.StatusOK {
		t.Fatalf("enabled-user PAT /me = %d, want 200", got)
	}
	// Disable the user; the PAT must now be rejected.
	if _, err := pool.Exec(ctx, `UPDATE users SET disabled = TRUE WHERE id = $1`, userID); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if got := getMe(t, ts.URL, raw); got != http.StatusUnauthorized {
		t.Fatalf("disabled-user PAT /me = %d, want 401", got)
	}
}
