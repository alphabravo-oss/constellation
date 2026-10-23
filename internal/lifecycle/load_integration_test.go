//go:build integration

package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// This opt-in fixture measures local SQL work, not the one-minute production
// cadence, an application-login SLO, or a sustainable fleet arrival rate.
func TestSessionCleanupLocalLoad(t *testing.T) {
	if os.Getenv("CONSTELLATION_TEST_LIFECYCLE_LOAD") != "true" {
		t.Skip("set CONSTELLATION_TEST_LIFECYCLE_LOAD=true for isolated 400000-row maintenance qualification")
	}
	t.Parallel()
	pool := pgtest.Pool(t)
	seedCleanupLoad(t, pool)
	if _, _, err := audit.New(pool).Log(t.Context(), audit.Event{Action: "cleanup.load.fixture"}); err != nil {
		t.Fatal(err)
	}
	var lsn string
	if err := pool.QueryRow(t.Context(), `SELECT pg_current_wal_insert_lsn()::text`).Scan(&lsn); err != nil {
		t.Fatal(err)
	}
	scope := liveSessionScope{}
	if err := pool.QueryRow(t.Context(), `SELECT org_id::text,id::text FROM clusters WHERE name='prod-east'`).Scan(&scope.org, &scope.cluster); err != nil {
		t.Fatal(err)
	}
	baseline := make([]time.Duration, 0, 100)
	for range 100 {
		duration, err := foregroundSessionRequest(t.Context(), pool, scope)
		if err != nil {
			t.Fatal(err)
		}
		baseline = append(baseline, duration)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	foreground := make(chan foregroundSamples, 1)
	go func() { foreground <- sampleForeground(ctx, pool, scope) }()
	passes := make([]time.Duration, 0, 100)
	started := time.Now()
	for range 100 {
		passStart := time.Now()
		got, err := ReapSessions(t.Context(), pool, 1000)
		passes = append(passes, time.Since(passStart))
		want := SessionCleanup{LoginAttempts: 1000, IdentitySessions: 1000, NetworkSessions: 1000, KillRequests: 1000}
		if err != nil || got != want {
			t.Fatalf("load cleanup got=%+v want=%+v err=%v", got, want, err)
		}
	}
	elapsed := time.Since(started)
	cancel()
	requests := <-foreground
	if requests.err != nil || len(requests.durations) == 0 {
		t.Fatalf("foreground requests failed or did not run: %v", requests.err)
	}
	assertCleanupLoadSurvivors(t, pool)
	var wal float64
	if err := pool.QueryRow(t.Context(), `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::float8`, lsn).Scan(&wal); err != nil {
		t.Fatal(err)
	}
	result := map[string]any{
		"expired_rows": 400000, "passes": len(passes), "elapsed_seconds": elapsed.Seconds(),
		"pass_p95_ms": percentileMS(passes, 95), "pass_p99_ms": percentileMS(passes, 99),
		"foreground_requests": len(requests.durations), "foreground_p95_ms": percentileMS(requests.durations, 95), "foreground_p99_ms": percentileMS(requests.durations, 99),
		"baseline_p95_ms": percentileMS(baseline, 95), "baseline_p99_ms": percentileMS(baseline, 99), "combined_wal_bytes": wal,
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(raw))
}

func seedCleanupLoad(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	execSessionSQL(t, pool, `
INSERT INTO oidc_login_attempts(state_hash,binding_hash,verifier,nonce,expires_at)
 SELECT 'load-'||n,'binding','verifier','nonce',now()-interval '1 hour' FROM generate_series(1,100000) n;
INSERT INTO oidc_login_attempts(state_hash,binding_hash,verifier,nonce,expires_at)
 VALUES('load-live','binding','verifier','nonce',now()+interval '1 hour');
INSERT INTO identity_sessions(token_hash,user_id,roles,session_epoch,kind,expires_at)
 SELECT 'load-'||n,u.id,'[]',u.session_epoch,'oidc',now()-interval '1 hour' FROM users u CROSS JOIN generate_series(1,100000) n WHERE u.email='admin@demo.test';
INSERT INTO identity_sessions(token_hash,user_id,roles,session_epoch,kind,expires_at)
 SELECT 'load-live',id,'[]',session_epoch,'oidc',now()+interval '1 hour' FROM users WHERE email='admin@demo.test';
INSERT INTO network_sessions(org_id,cluster_id,node,id,updated_at)
 SELECT org_id,id,'load-expired',n,now()-interval '1 hour' FROM clusters CROSS JOIN generate_series(1,100000) n WHERE name='prod-east';
INSERT INTO network_sessions(org_id,cluster_id,node,id,updated_at)
 SELECT org_id,id,'load-live',0,now() FROM clusters WHERE name='prod-east';
INSERT INTO network_session_kills(org_id,cluster_id,node,session_id,requested_at)
 SELECT org_id,cluster_id,node,id,updated_at FROM network_sessions WHERE node LIKE 'load-%';
ANALYZE oidc_login_attempts; ANALYZE identity_sessions; ANALYZE network_sessions; ANALYZE network_session_kills;`)
}

type liveSessionScope struct{ org, cluster string }

type foregroundSamples struct {
	durations []time.Duration
	err       error
}

func sampleForeground(ctx context.Context, pool *pgxpool.Pool, scope liveSessionScope) foregroundSamples {
	var out foregroundSamples
	for range 10000 {
		if ctx.Err() != nil {
			break
		}
		duration, err := foregroundSessionRequest(ctx, pool, scope)
		if err != nil {
			if ctx.Err() == nil {
				out.err = err
			}
			break
		}
		out.durations = append(out.durations, duration)
		time.Sleep(time.Millisecond)
	}
	return out
}

func foregroundSessionRequest(ctx context.Context, pool *pgxpool.Pool, scope liveSessionScope) (time.Duration, error) {
	started := time.Now()
	var current bool
	if err := pool.QueryRow(ctx, `SELECT expires_at>clock_timestamp() FROM identity_sessions WHERE token_hash='load-live'`).Scan(&current); err != nil {
		return 0, err
	}
	if !current {
		return 0, fmt.Errorf("active identity session expired")
	}
	tag, err := pool.Exec(ctx, `UPDATE network_sessions SET updated_at=clock_timestamp() WHERE org_id=$1 AND cluster_id=$2 AND node='load-live' AND id=0`, scope.org, scope.cluster)
	if err == nil && tag.RowsAffected() != 1 {
		err = fmt.Errorf("active network session lost")
	}
	return time.Since(started), err
}

func assertCleanupLoadSurvivors(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if got, err := ReapSessions(t.Context(), pool, 1000); err != nil || got != (SessionCleanup{}) {
		t.Fatalf("expired backlog did not drain: %+v %v", got, err)
	}
	var attempts, identities, sessions, kills, receipts int
	err := pool.QueryRow(t.Context(), `SELECT
 (SELECT count(*) FROM oidc_login_attempts WHERE state_hash LIKE 'load-%'),
 (SELECT count(*) FROM identity_sessions WHERE token_hash LIKE 'load-%'),
 (SELECT count(*) FROM network_sessions WHERE node LIKE 'load-%'),
 (SELECT count(*) FROM network_session_kills WHERE node LIKE 'load-%'),
 (SELECT count(*) FROM audit_events)`).Scan(&attempts, &identities, &sessions, &kills, &receipts)
	if err != nil || attempts != 1 || identities != 1 || sessions != 1 || kills != 1 || receipts != 1 {
		t.Fatalf("live state/evidence changed: %d/%d/%d/%d/%d err=%v", attempts, identities, sessions, kills, receipts, err)
	}
	if broken, err := audit.VerifyChain(t.Context(), pool); err != nil || broken != nil {
		t.Fatalf("audit integrity changed: %v %v", broken, err)
	}
}

func percentileMS(values []time.Duration, percentile int) float64 {
	ordered := slices.Clone(values)
	slices.Sort(ordered)
	return ordered[(len(ordered)*percentile+99)/100-1].Seconds() * 1000
}
