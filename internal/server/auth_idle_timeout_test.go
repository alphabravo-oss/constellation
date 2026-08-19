package server

import (
	"context"
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

// newIdleTimeoutTestServer boots a Server with a configurable A7 SessionIdleTimeout and
// returns it plus a seeded GlobalAdmin user. Mirrors newAuthTestServer but lets the test
// dial in a short idle window. Skips when the test DB is unreachable.
func newIdleTimeoutTestServer(t *testing.T, idle time.Duration) (*httptest.Server, *pgxpool.Pool, *auth.Signer, uuid.UUID, uuid.UUID) {
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
	// A7 idempotent schema-ensure (mirrors migration 101) so the idle-timeout test runs
	// even before goose is pointed at the test DB.
	if _, err := pool.Exec(ctx,
		`ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()`); err != nil {
		pool.Close()
		t.Fatalf("ensure last_seen_at column: %v", err)
	}

	orgID := uuid.New()
	userID := uuid.New()
	email := "idle-" + userID.String() + "@example.test"
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Idle Test')`,
		orgID, "idle-org-"+orgID.String()); err != nil {
		pool.Close()
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, session_epoch)
VALUES ($1, $2, $3, 'Idle Admin', 0)`, userID, orgID, email); err != nil {
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
		_, _ = pool.Exec(context.Background(), `DELETE FROM user_sessions WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = $1`, userID)
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
		ListenAddr:         ":0",
		DatabaseURL:        url,
		JWTKeys:            [][]byte{[]byte("0123456789abcdef0123456789abcdef")},
		JWTIssuer:          "constellation-test",
		JWTAudience:        "constellation-api",
		JWTTTL:             time.Hour,
		SessionIdleTimeout: idle,
		CORSOrigins:        []string{"http://localhost:5173"},
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

// A7: a JWT session that has been idle longer than SessionIdleTimeout is rejected on its
// next request, even though the JWT itself is well inside its absolute TTL. An active
// session (recent last_seen_at) keeps working and slides its last-activity forward.
func TestAuthMiddleware_IdleTimeoutExpiresSession(t *testing.T) {
	idle := 30 * time.Minute
	ts, pool, signer, userID, orgID := newIdleTimeoutTestServer(t, idle)
	ctx := context.Background()

	tok := issueFor(t, signer, userID, orgID, 0)
	sid := mustSessionID(t, signer, tok)

	// Record a tracked session whose last activity is "now": the token works.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_sessions (session_id, user_id, last_seen_at) VALUES ($1, $2, now())`,
		sid, userID); err != nil {
		t.Fatalf("record session: %v", err)
	}
	if got := getMe(t, ts.URL, tok); got != http.StatusOK {
		t.Fatalf("active-session /me = %d, want 200", got)
	}

	// The successful request above slid last_seen_at to ~now. Back-date it beyond the idle
	// window to simulate inactivity, then the next request must be rejected.
	if _, err := pool.Exec(ctx,
		`UPDATE user_sessions SET last_seen_at = now() - ($2::interval) WHERE session_id = $1`,
		sid, (idle + time.Minute).String()); err != nil {
		t.Fatalf("backdate last_seen: %v", err)
	}
	if got := getMe(t, ts.URL, tok); got != http.StatusUnauthorized {
		t.Fatalf("idle /me = %d, want 401", got)
	}

	// The idle session was hard-stopped (row deleted) so it cannot be revived.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_sessions WHERE session_id = $1`, sid).Scan(&n); err != nil {
		t.Fatalf("count session: %v", err)
	}
	if n != 0 {
		t.Fatalf("idle session row count = %d, want 0 (expired sessions are purged)", n)
	}

	// A7 bypass guard: replaying the SAME still-within-TTL JWT after the idle 401 must
	// also be rejected. Deleting the row alone left a hole (anySession=false => the token
	// looked untracked and slipped through); the idle branch now bumps session_epoch so
	// the epoch check rejects every later replay. Without that bump this would 200.
	if got := getMe(t, ts.URL, tok); got != http.StatusUnauthorized {
		t.Fatalf("replayed idle token /me = %d, want 401 (epoch must be bumped on idle expiry)", got)
	}
	var epoch int64
	if err := pool.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id = $1`, userID).Scan(&epoch); err != nil {
		t.Fatalf("read session_epoch: %v", err)
	}
	if epoch < 1 {
		t.Fatalf("session_epoch = %d, want >= 1 (idle expiry must bump epoch)", epoch)
	}
}

// A7: a recent session whose last activity is within the idle window keeps working, and
// each successful request slides last_seen_at forward so an actively-used session never
// times out.
func TestAuthMiddleware_IdleTimeoutSlidesOnActivity(t *testing.T) {
	idle := 30 * time.Minute
	ts, pool, signer, userID, orgID := newIdleTimeoutTestServer(t, idle)
	ctx := context.Background()

	tok := issueFor(t, signer, userID, orgID, 0)
	sid := mustSessionID(t, signer, tok)

	// Last activity 10 minutes ago: still within the 30m window.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_sessions (session_id, user_id, last_seen_at) VALUES ($1, $2, now() - interval '10 minutes')`,
		sid, userID); err != nil {
		t.Fatalf("record session: %v", err)
	}
	if got := getMe(t, ts.URL, tok); got != http.StatusOK {
		t.Fatalf("within-window /me = %d, want 200", got)
	}

	// That request must have slid last_seen_at to ~now (well under 1 minute old).
	var ageSeconds float64
	if err := pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (now() - last_seen_at)) FROM user_sessions WHERE session_id = $1`,
		sid).Scan(&ageSeconds); err != nil {
		t.Fatalf("read last_seen age: %v", err)
	}
	if ageSeconds > 60 {
		t.Fatalf("last_seen_at not slid forward: age=%.1fs, want < 60s", ageSeconds)
	}
}
