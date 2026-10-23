//go:build integration

package scanretention

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

func seedTarget(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	org, target := uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'Retention')`, org)
	exec(t, pool, `INSERT INTO scan_targets(id,org_id,type,ref,source_type) VALUES($1,$2,'image','sha256:test','manual')`, target, org)
	return org, target
}
func exec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
func seedJob(t *testing.T, pool *pgxpool.Pool, org, target uuid.UUID, age time.Duration) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, pool, `INSERT INTO scan_jobs(id,org_id,target_id,status,requested_at,finished_at) VALUES($1,$2,$3,'completed',$4,$4)`, id, org, target, time.Now().Add(-age))
	return id
}
func seedResult(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, target, job *uuid.UUID, digest string, age time.Duration) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, pool, `INSERT INTO image_scan_results(id,org_id,scan_target_id,last_scan_job_id,image_ref,image_ref_normalized,image_repository,image_digest,last_scanned_at,vulndb_bundle_version)
 VALUES($1::uuid,$2,$3,$4,$5,$5,'',$5,$6,$1::text)`, id, org, target, job, "sha256:"+digest, time.Now().Add(-age))
	return id
}
func attest(t *testing.T, pool *pgxpool.Pool, org, target uuid.UUID, job, result *uuid.UUID) {
	t.Helper()
	exec(t, pool, `INSERT INTO scan_result_attestations(org_id,scan_target_id,scan_job_id,image_scan_result_id,target_type,target_ref,source_type,subject_kind,subject_ref,subject_digest,predicate_type,format,payload,payload_sha256,verification_status)
 VALUES($1,$2,$3,$4,'image','fixture','manual','image','fixture','sha256:fixture','fixture','fixture','{}',$5,'untrusted')`, org, target, job, result, "sha256:"+uuid.NewString())
}
func exists(t *testing.T, pool *pgxpool.Pool, table string, id uuid.UUID) bool {
	t.Helper()
	var found bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, id).Scan(&found); err != nil {
		t.Fatal(err)
	}
	return found
}
func TestJobsRetainReferencesLatestAndLocks(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	org, target := seedTarget(t, pool)
	old := seedJob(t, pool, org, target, 96*time.Hour)
	attested := seedJob(t, pool, org, target, 72*time.Hour)
	linked := seedJob(t, pool, org, target, 48*time.Hour)
	newest := seedJob(t, pool, org, target, 36*time.Hour)
	attest(t, pool, org, target, &attested, nil)
	seedResult(t, pool, org, &target, &linked, "job-ref", 48*time.Hour)
	lock, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	if _, err := lock.Exec(t.Context(), `SELECT id FROM scan_jobs WHERE id=$1 FOR UPDATE`, old); err != nil {
		t.Fatal(err)
	}
	if n, err := PruneJobs(t.Context(), pool, 24*time.Hour, 1); err != nil || n != 0 {
		t.Fatalf("locked/ref prune: %d %v", n, err)
	}
	if err := lock.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n, err := PruneJobs(t.Context(), pool, 24*time.Hour, 1); err != nil || n != 1 {
		t.Fatalf("expired prune: %d %v", n, err)
	}
	if exists(t, pool, "scan_jobs", old) {
		t.Fatal("unreferenced expired job remains")
	}
	for _, id := range []uuid.UUID{attested, linked, newest} {
		if !exists(t, pool, "scan_jobs", id) {
			t.Fatalf("protected job lost: %s", id)
		}
	}
	if n, err := PruneJobs(t.Context(), pool, 0, 1); err != nil || n != 0 {
		t.Fatal("hold ignored")
	}
}
func TestOrphanResultsRetainEvidenceAndBoundEachPass(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	org, target := seedTarget(t, pool)
	keep := seedResult(t, pool, org, nil, nil, "attested", 72*time.Hour)
	attest(t, pool, org, target, nil, &keep)
	seedResult(t, pool, org, nil, nil, "attested", 24*time.Hour)
	finding := seedResult(t, pool, org, nil, nil, "finding", 72*time.Hour)
	exec(t, pool, `INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,title,severity) VALUES($1,$2,'CVE','finding','high')`, org, finding)
	seedResult(t, pool, org, nil, nil, "finding", 24*time.Hour)
	latest := seedResult(t, pool, org, &target, nil, "current", 72*time.Hour)
	a := seedResult(t, pool, org, nil, nil, "current", 96*time.Hour)
	b := seedResult(t, pool, org, nil, nil, "current", 96*time.Hour)
	fresh := seedResult(t, pool, org, nil, nil, "recent", time.Hour)
	for i := 0; i < 2; i++ {
		if n, err := PruneOrphanResults(t.Context(), pool, 1); err != nil || n != 1 {
			t.Fatalf("bounded prune: %d %v", n, err)
		}
	}
	for _, id := range []uuid.UUID{a, b} {
		if exists(t, pool, "image_scan_results", id) {
			t.Fatal("disposable result remains")
		}
	}
	for _, id := range []uuid.UUID{keep, finding, latest, fresh} {
		if !exists(t, pool, "image_scan_results", id) {
			t.Fatalf("protected result lost: %s", id)
		}
	}
}

func TestReferenceCommittedAfterCandidateSnapshotSurvives(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	org, target := seedTarget(t, pool)
	old := seedJob(t, pool, org, target, 72*time.Hour)
	seedJob(t, pool, org, target, 48*time.Hour)
	gate, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if _, err := gate.Exec(t.Context(), `SELECT pg_advisory_xact_lock(987654321)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		n, err := pruneLocked(t.Context(), pool, `SELECT j.id FROM scan_jobs j CROSS JOIN (SELECT pg_advisory_xact_lock(987654321)) gate
 WHERE j.id='`+old.String()+`' AND j.finished_at<$1 AND `+jobReferences+` LIMIT $2 FOR UPDATE OF j SKIP LOCKED`,
			`DELETE FROM scan_jobs j WHERE j.id=ANY($1::uuid[]) AND `+jobReferences, time.Now().Add(-24*time.Hour), 1)
		if err == nil && n != 0 {
			err = fmt.Errorf("concurrent reference lost: deleted %d", n)
		}
		done <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=987654321 AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("candidate statement did not reach gate")
		}
		time.Sleep(10 * time.Millisecond)
	}
	attest(t, pool, org, target, &old, nil)
	if err := gate.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !exists(t, pool, "scan_jobs", old) {
		t.Fatal("referenced job was removed")
	}
}
