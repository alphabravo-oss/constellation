//go:build integration

package lifecycle

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func seedSessionCleanup(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := pgtest.Pool(t)
	execSessionSQL(t, pool, `
INSERT INTO oidc_login_attempts(state_hash,binding_hash,verifier,nonce,expires_at)
SELECT name,'binding','verifier','nonce',now()+age FROM
 (VALUES ('locked',interval '-3 hours'),('expired-a',interval '-2 hours'),
         ('expired-b',interval '-1 hour'),('fresh',interval '1 hour')) x(name,age);
INSERT INTO identity_sessions(token_hash,user_id,roles,session_epoch,kind,expires_at)
SELECT x.name,u.id,'[]',u.session_epoch,'oidc',now()+x.age FROM users u CROSS JOIN
 (VALUES ('locked',interval '-3 hours'),('expired-a',interval '-2 hours'),
         ('expired-b',interval '-1 hour'),('fresh',interval '1 hour')) x(name,age)
WHERE u.email='admin@demo.test';
INSERT INTO orgs(name,display_name) VALUES('cleanup-other','Cleanup other');
INSERT INTO clusters(org_id,name) SELECT id,'cleanup-other' FROM orgs;
INSERT INTO network_sessions(org_id,cluster_id,node,id,updated_at)
SELECT c.org_id,c.id,'original',x.id,now()+x.age FROM clusters c CROSS JOIN
 (VALUES (7,interval '-3 hours'),(8,interval '-2 hours'),
         (9,interval '-1 hour'),(10,interval '0 hours')) x(id,age)
WHERE c.name='prod-east';
INSERT INTO network_sessions(org_id,cluster_id,node,id,updated_at)
SELECT c.org_id,c.id,'original',7,now() FROM clusters c WHERE c.name='cleanup-other';
INSERT INTO network_sessions(org_id,cluster_id,node,id,updated_at)
SELECT c.org_id,c.id,'other-node',7,now() FROM clusters c WHERE c.name='prod-east';
INSERT INTO network_session_kills(org_id,cluster_id,node,session_id,requested_at)
SELECT org_id,cluster_id,node,id,updated_at FROM network_sessions;
`)
	if _, _, err := audit.New(pool).Log(t.Context(), audit.Event{Action: "cleanup.fixture"}); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestSessionCleanupCurrentIdentityTablesAndCompositeKeys(t *testing.T) {
	t.Parallel()
	pool := seedSessionCleanup(t)
	ctx := t.Context()
	locked, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = locked.Rollback(ctx) }()
	for _, query := range []string{
		`SELECT state_hash FROM oidc_login_attempts WHERE state_hash='locked' FOR UPDATE`,
		`SELECT token_hash FROM identity_sessions WHERE token_hash='locked' FOR UPDATE`,
		`SELECT id FROM network_sessions WHERE id=7 AND updated_at<now()-interval '5 minutes' FOR UPDATE`,
		`SELECT session_id FROM network_session_kills WHERE session_id=7 AND requested_at<now()-interval '5 minutes' FOR UPDATE`,
	} {
		if _, err := locked.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	want := SessionCleanup{LoginAttempts: 1, IdentitySessions: 1, NetworkSessions: 1, KillRequests: 1}
	for pass := range 3 {
		got, err := ReapSessions(ctx, pool, 1)
		expected := want
		if pass == 2 {
			expected = SessionCleanup{}
		}
		if err != nil || got != expected {
			t.Fatalf("bounded lock-skipping pass %d: got=%+v want=%+v err=%v", pass, got, expected, err)
		}
	}
	if err := locked.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := ReapSessions(ctx, pool, 1)
	if err != nil || got != want {
		t.Fatalf("released expired rows: got=%+v err=%v", got, err)
	}
	var attempts, sessions, flows, kills, receipts int
	err = pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM oidc_login_attempts WHERE state_hash='fresh'),
 (SELECT count(*) FROM identity_sessions WHERE token_hash='fresh'),
 (SELECT count(*) FROM network_sessions WHERE updated_at>=now()-interval '5 minutes'),
 (SELECT count(*) FROM network_session_kills WHERE requested_at>=now()-interval '5 minutes'),
 (SELECT count(*) FROM audit_events)`).Scan(&attempts, &sessions, &flows, &kills, &receipts)
	if err != nil || attempts != 1 || sessions != 1 || flows != 4 || kills != 4 || receipts != 1 {
		t.Fatalf("live rows or audit receipt lost: %d/%d/%d/%d/%d err=%v", attempts, sessions, flows, kills, receipts, err)
	}
	if next, err := ReapSessions(ctx, pool, 1); err != nil || next != (SessionCleanup{}) {
		t.Fatalf("cleanup not exhausted: %+v err=%v", next, err)
	}
	if broken, err := audit.VerifyChain(ctx, pool); err != nil || broken != nil {
		t.Fatalf("audit evidence changed: %v err=%v", broken, err)
	}
	metrics, err := NewMetrics(prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	metrics.Record(got, time.Second, nil)
	for _, family := range []string{"oidc_login_attempts", "identity_sessions", "network_sessions", "kill_requests"} {
		if n := testutil.ToFloat64(metrics.deleted.WithLabelValues(family)); n != 1 {
			t.Fatalf("cleanup metric for current family %s = %v, want 1", family, n)
		}
	}
}

func TestSessionCleanupFailurePreservesPartialProgress(t *testing.T) {
	t.Parallel()
	pool := seedSessionCleanup(t)
	execSessionSQL(t, pool, `ALTER TABLE network_session_kills RENAME TO unavailable_kills`)
	got, err := ReapSessions(t.Context(), pool, 1)
	if err == nil || got != (SessionCleanup{LoginAttempts: 1, IdentitySessions: 1, NetworkSessions: 1}) {
		t.Fatalf("partial cleanup: got=%+v err=%v", got, err)
	}
	for _, batch := range []int{0, -1, 5001} {
		if got, err := ReapSessions(t.Context(), nil, batch); err == nil || got != (SessionCleanup{}) {
			t.Fatalf("invalid batch %d reached database: %+v err=%v", batch, got, err)
		}
	}
}
