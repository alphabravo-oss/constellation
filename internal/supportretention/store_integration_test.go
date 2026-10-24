//go:build integration

package supportretention

import (
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestExpiryHoldsUnauditedJobsAndBoundsPasses(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	org := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'support retention fixture')`, org, org.String()); err != nil {
		t.Fatal(err)
	}
	receipt, _, err := audit.New(pool).Log(t.Context(), audit.Event{OrgID: &org, Action: "support.bundle.job.ready"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO support_bundle_jobs(org_id,status,bundle_id,payload,expires_at,audit_event_id)
 SELECT $1,'ready',gen_random_uuid(),'{"private":"payload"}',now()-interval '1 day',$2 FROM generate_series(1,205)`, org, receipt); err != nil {
		t.Fatal(err)
	}
	var pending, missing uuid.UUID
	if err = pool.QueryRow(t.Context(), `INSERT INTO support_bundle_jobs(org_id,status,bundle_id,payload,expires_at,audit_pending) VALUES($1,'ready',gen_random_uuid(),'{"private":"pending"}',now()-interval '1 day','ready') RETURNING id`, org).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(t.Context(), `INSERT INTO support_bundle_jobs(org_id,status,error,expires_at) VALUES($1,'failed','missing audit',now()-interval '1 day') RETURNING id`, org).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(t.Context()) }()
	if _, err = lock.Exec(t.Context(), `SELECT id FROM support_bundle_jobs WHERE audit_event_id IS NOT NULL ORDER BY id LIMIT 1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int64{100, 100, 4, 0} {
		got, err := ExpirePayloads(t.Context(), pool)
		if err != nil || got != want {
			t.Fatalf("expiry: %d want %d %v", got, want, err)
		}
	}
	var held bool
	var jobs, expired, receipts int
	if err = pool.QueryRow(t.Context(), `SELECT
 (SELECT status='ready' AND payload IS NOT NULL AND audit_pending='ready' FROM support_bundle_jobs WHERE id=$1),
 (SELECT count(*) FROM support_bundle_jobs),(SELECT count(*) FROM support_bundle_jobs WHERE status='expired'),(SELECT count(*) FROM audit_events)`, pending).Scan(&held, &jobs, &expired, &receipts); err != nil || !held || jobs != 207 || expired != 204 || receipts != 1 {
		t.Fatalf("hold/receipt lost: %v %d %d %d %v", held, jobs, expired, receipts, err)
	}
	if err = lock.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := ExpirePayloads(t.Context(), pool); err != nil || got != 1 {
		t.Fatalf("locked expiry retry: %d %v", got, err)
	}
	if _, err = pool.Exec(t.Context(), `UPDATE support_bundle_jobs SET audit_pending=NULL,audit_event_id=$2 WHERE id=$1`, pending, receipt); err != nil {
		t.Fatal(err)
	}
	if got, err := ExpirePayloads(t.Context(), pool); err != nil || got != 1 {
		t.Fatalf("audited expiry retry: %d %v", got, err)
	}
	var status string
	if err = pool.QueryRow(t.Context(), `SELECT status FROM support_bundle_jobs WHERE id=$1`, missing).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("missing-receipt job removed: %s %v", status, err)
	}
}
