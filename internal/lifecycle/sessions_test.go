//go:build integration

package lifecycle

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func sessionPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable integration database")
	}
	base, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(base.Close)
	pool := pgfixture.Schema(t, base)
	execSessionSQL(t, pool, `CREATE TABLE user_sessions (LIKE public.user_sessions INCLUDING ALL);
 CREATE TABLE browser_refresh_tokens (LIKE public.browser_refresh_tokens INCLUDING ALL);
 ALTER TABLE browser_refresh_tokens ADD FOREIGN KEY(session_id) REFERENCES user_sessions(session_id) ON DELETE CASCADE;
 CREATE TABLE network_sessions (LIKE public.network_sessions INCLUDING ALL);
 CREATE TABLE network_session_kills (LIKE public.network_session_kills INCLUDING ALL);`)
	return pool
}

func execSessionSQL(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func seedSession(t *testing.T, pool *pgxpool.Pool, expiry *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	execSessionSQL(t, pool, `INSERT INTO user_sessions(session_id,user_id,created_at,last_seen_at,expires_at)
 VALUES ($1,$2,now()-interval '30 days',now()-interval '30 days',$3)`, id, uuid.New(), expiry)
	return id
}

func seedRefresh(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, expiry time.Time, consumed bool) string {
	t.Helper()
	hash := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	execSessionSQL(t, pool, `INSERT INTO browser_refresh_tokens(token_hash,session_id,session_epoch,expires_at,consumed_at)
 VALUES ($1,$2,0,$3,CASE WHEN $4 THEN now()-interval '1 minute' END)`, hash, id, expiry, consumed)
	return hash
}

func TestSessionReaperPreservesActiveLegacyAndReuseEvidence(t *testing.T) {
	pool := sessionPool(t)
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	expired := seedSession(t, pool, &past)
	active := seedSession(t, pool, &future)
	legacy := seedSession(t, pool, nil)
	guarded := seedSession(t, pool, &past)
	seedRefresh(t, pool, expired, past, true)
	seedRefresh(t, pool, active, future, true)
	seedRefresh(t, pool, active, future, false)
	seedRefresh(t, pool, guarded, future, false)
	result, err := ReapSessions(t.Context(), pool, 100)
	if err != nil || result.RefreshTokens != 1 || result.UserSessions != 1 {
		t.Fatalf("cleanup=%+v err=%v", result, err)
	}
	for _, id := range []uuid.UUID{active, legacy, guarded} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM user_sessions WHERE session_id=$1)`, id).Scan(&exists); err != nil || !exists {
			t.Fatalf("protected session removed: %s %v", id, err)
		}
	}
	var tokens int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM browser_refresh_tokens`).Scan(&tokens); err != nil || tokens != 3 {
		t.Fatalf("reuse evidence lost: %d %v", tokens, err)
	}
	result, err = ReapSessions(t.Context(), pool, 100)
	if err != nil || result != (SessionCleanup{}) {
		t.Fatalf("non-idempotent cleanup: %+v %v", result, err)
	}
}

func TestSessionReaperBoundsCascadeAndSkipsLocks(t *testing.T) {
	pool := sessionPool(t)
	past := time.Now().Add(-time.Hour)
	id := seedSession(t, pool, &past)
	for range 3 {
		seedRefresh(t, pool, id, past, true)
	}
	result, err := ReapSessions(t.Context(), pool, 2)
	if err != nil || result.RefreshTokens != 2 || result.UserSessions != 0 {
		t.Fatalf("unbounded cascade: %+v %v", result, err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `SELECT session_id FROM user_sessions WHERE session_id=$1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result, err = ReapSessions(ctx, pool, 2)
	if err != nil || result.RefreshTokens != 1 || result.UserSessions != 0 {
		t.Fatalf("locked session not skipped: %+v %v", result, err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err = ReapSessions(t.Context(), pool, 2)
	if err != nil || result.UserSessions != 1 {
		t.Fatalf("unlocked session not reaped: %+v %v", result, err)
	}
}

func TestNetworkReaperKeepsFreshRowsAndScopesCompositeKeys(t *testing.T) {
	pool := sessionPool(t)
	org, cluster, other := uuid.New(), uuid.New(), uuid.New()
	execSessionSQL(t, pool, `INSERT INTO network_sessions(org_id,cluster_id,node,id,updated_at)
 VALUES ($1,$2,'old-node',42,now()-interval '6 minutes'),($1,$2,'live-node',42,now()),($1,$3,'old-node',42,now());`, org, cluster, other)
	execSessionSQL(t, pool, `INSERT INTO network_session_kills(org_id,cluster_id,node,session_id,requested_at)
 VALUES ($1,$2,'old-node',42,now()-interval '6 minutes'),($1,$2,'live-node',42,now()),($1,$3,'old-node',42,now());`, org, cluster, other)
	result, err := ReapSessions(t.Context(), pool, 1)
	if err != nil || result.NetworkSessions != 1 || result.KillRequests != 1 {
		t.Fatalf("cleanup=%+v err=%v", result, err)
	}
	var sessions, kills int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM network_sessions),(SELECT count(*) FROM network_session_kills)`).Scan(&sessions, &kills); err != nil || sessions != 2 || kills != 2 {
		t.Fatalf("fresh/scoped rows lost: %d %d %v", sessions, kills, err)
	}
}

func TestSessionReaperRejectsInvalidBatchAndCancellation(t *testing.T) {
	pool := sessionPool(t)
	for _, n := range []int{0, -1, 5001} {
		if _, err := ReapSessions(t.Context(), pool, n); err == nil {
			t.Fatalf("invalid batch %d accepted", n)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ReapSessions(ctx, pool, 1); err == nil {
		t.Fatal("cancellation ignored")
	}
}
