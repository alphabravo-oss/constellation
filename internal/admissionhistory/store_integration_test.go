//go:build integration

package admissionhistory

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func seedScope(t *testing.T, pool *pgxpool.Pool, count int) ClearRequest {
	t.Helper()
	req := ClearRequest{OrgID: uuid.New(), ActorID: uuid.New()}
	cluster := uuid.New()
	req.ClusterID = &cluster
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'history fixture')`, req.OrgID, req.OrgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,org_id,email,display_name) VALUES($1,$2,$3,'fixture actor')`, req.ActorID, req.OrgID, req.ActorID.String()+"@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'history fixture')`, cluster, req.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO admission_dry_run_history(org_id,cluster_id,actor_id,image,decision,assessed_at)
 SELECT $1,$2,$3,'fixture/image','allow',now()-n*interval '1 second' FROM generate_series(1,$4::int) n`, req.OrgID, cluster, req.ActorID, count); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestClearBoundedScopedAndLockSkipping(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	req := seedScope(t, pool, 1005)
	other := seedScope(t, pool, 1)
	if _, err := pool.Exec(t.Context(), `INSERT INTO admission_dry_run_history(org_id,image,decision) VALUES($1,'unscoped/image','allow')`, req.OrgID); err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(t.Context()) }()
	if _, err = lock.Exec(t.Context(), `SELECT id FROM admission_dry_run_history WHERE cluster_id=$1 ORDER BY assessed_at DESC LIMIT 1 FOR UPDATE`, req.ClusterID); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int64{1000, 4, 0} {
		got, err := Clear(t.Context(), pool, req)
		if err != nil || got != want {
			t.Fatalf("clear got=%d want=%d err=%v", got, want, err)
		}
	}
	if err = lock.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := Clear(t.Context(), pool, req); err != nil || got != 1 {
		t.Fatalf("unlocked clear: %d %v", got, err)
	}
	var foreign, unscoped, receipts int
	if err = pool.QueryRow(t.Context(), `SELECT
 (SELECT count(*) FROM admission_dry_run_history WHERE org_id=$1),
 (SELECT count(*) FROM admission_dry_run_history WHERE org_id=$2 AND cluster_id IS NULL),
 (SELECT count(*) FROM audit_events WHERE org_id=$2 AND action='admission.dry-run.clear')`, other.OrgID, req.OrgID).Scan(&foreign, &unscoped, &receipts); err != nil {
		t.Fatal(err)
	}
	if foreign != 1 || unscoped != 1 || receipts != 4 {
		t.Fatalf("scope or audit broken: %d %d %d", foreign, unscoped, receipts)
	}
	req.ClusterID = nil
	if got, err := Clear(t.Context(), pool, req); err != nil || got != 1 {
		t.Fatalf("org scope: %d %v", got, err)
	}
	result, err := audit.VerifyChain(t.Context(), pool)
	if err != nil || result != nil {
		t.Fatalf("audit chain invalid: %+v %v", result, err)
	}
}

func TestClearRollsBackWithoutAudit(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	req := seedScope(t, pool, 3)
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_history_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$;
 CREATE CONSTRAINT TRIGGER reject_history_receipt AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_history_receipt()`); err != nil {
		t.Fatal(err)
	}
	if got, err := Clear(t.Context(), pool, req); err == nil || got != 0 {
		t.Fatalf("clear committed without receipt: %d %v", got, err)
	}
	var history, receipts int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM admission_dry_run_history WHERE org_id=$1),(SELECT count(*) FROM audit_events WHERE org_id=$1)`, req.OrgID).Scan(&history, &receipts); err != nil {
		t.Fatal(err)
	}
	if history != 3 || receipts != 0 {
		t.Fatalf("partial commit: %d %d", history, receipts)
	}
}
