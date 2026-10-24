//go:build integration

package k8sauditarchive

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func seedScope(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'archive fixture')`, org, org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'archive fixture')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	return org, cluster
}

func TestPagedExportAndIndependentRestore(t *testing.T) {
	t.Parallel()
	source := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, _ := archiveFixture()
	w.OrgID, w.ClusterID = seedScope(t, source)
	otherOrg, otherCluster := seedScope(t, source)
	if _, err := source.Exec(t.Context(), `INSERT INTO k8s_audit_events(org_id,cluster_id,verb,raw,at)
 SELECT $1,$2,'get','{"private":"retained-event"}',$3 FROM generate_series(1,1005)`, w.OrgID, w.ClusterID, w.From.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(t.Context(), `INSERT INTO k8s_audit_events(org_id,cluster_id,verb,at) VALUES
 ($1,$2,'outside-window',$3),($1,$2,'outside-window',$4),($5,$6,'foreign',$3),($1,$6,'other-cluster',$7)`, w.OrgID, w.ClusterID, w.From.Add(-time.Second), w.Through, otherOrg, otherCluster, w.From); err != nil {
		t.Fatal(err)
	}
	pages := [][]byte{}
	reports := []Report{}
	for _, want := range []int{1000, 5} {
		data, report, err := Export(t.Context(), source, w, 1000, private, public)
		if err != nil {
			t.Fatal(err)
		}
		if report.Manifest.Count != want || report.Manifest.More != (want == 1000) {
			t.Fatalf("page metadata: %+v", report.Manifest)
		}
		pages = append(pages, data)
		reports = append(reports, report)
		w.After = report.Manifest.Last
	}
	if _, _, err := Export(t.Context(), source, w, 1000, private, public); err == nil {
		t.Fatal("empty page reported archive success")
	}
	var unchanged int
	if err := source.QueryRow(t.Context(), `SELECT count(*) FROM k8s_audit_events`).Scan(&unchanged); err != nil || unchanged != 1009 {
		t.Fatalf("source changed: %d %v", unchanged, err)
	}
	source.Close()
	dest, err := pgxpool.New(t.Context(), pgtest.FreshURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dest.Close)
	if _, err = database.MigratePool(t.Context(), dest, slog.Default()); err != nil {
		t.Fatal(err)
	}
	org, cluster := seedScope(t, dest)
	if _, err = Restore(t.Context(), dest, bytes.NewReader(pages[0]), public, uuid.New(), cluster); err == nil {
		t.Fatal("foreign cluster accepted")
	}
	for run := 0; run < 2; run++ {
		for i, page := range pages {
			got, err := Restore(t.Context(), dest, bytes.NewReader(page), public, org, cluster)
			if err != nil {
				t.Fatal(err)
			}
			want := reports[i].Manifest.Count
			if run == 0 && (got.Inserted != want || got.Existing != 0) || run == 1 && (got.Inserted != 0 || got.Existing != want) {
				t.Fatalf("replay counts: %+v", got)
			}
		}
	}
	var count, receipts int
	var intact bool
	if err = dest.QueryRow(t.Context(), `SELECT count(*),bool_and(org_id=$1 AND cluster_id=$2 AND raw='{"private":"retained-event"}'::jsonb AND reported_at IS NULL) FROM k8s_audit_events`, org, cluster).Scan(&count, &intact); err != nil || count != 1005 || !intact {
		t.Fatalf("recovered evidence: %d %v %v", count, intact, err)
	}
	if err = dest.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='k8s.audit.restore' AND org_id=$1`, org).Scan(&receipts); err != nil || receipts != 2 {
		t.Fatalf("audit receipts: %d %v", receipts, err)
	}
	if broken, err := audit.VerifyChain(t.Context(), dest); err != nil || broken != nil {
		t.Fatalf("audit chain: %+v %v", broken, err)
	}
}

func TestRestoreConflictRollsBackWholePage(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, rows := archiveFixture()
	org, cluster := seedScope(t, pool)
	rows = append(rows, rows[0])
	rows[1].ID = uuid.New()
	rows[1].At = rows[0].At.Add(time.Second)
	data, _, err := encode(t.Context(), w, rows, false, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO k8s_audit_events(id,org_id,cluster_id,verb,at) VALUES($1,$2,$3,'conflict',$4)`, rows[1].ID, org, cluster, rows[1].At); err != nil {
		t.Fatal(err)
	}
	if _, err = Restore(t.Context(), pool, bytes.NewReader(data), public, org, cluster); err == nil {
		t.Fatal("conflict overwritten")
	}
	assertFailedRestore(t, pool, 1)
}

func TestRestoreAuditCommitFailureRollsBack(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, rows := archiveFixture()
	org, cluster := seedScope(t, pool)
	data, _, err := encode(t.Context(), w, rows, false, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `CREATE FUNCTION reject_k8s_archive_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit fixture unavailable'; END $$;
 CREATE CONSTRAINT TRIGGER reject_k8s_archive_receipt AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_k8s_archive_receipt()`); err != nil {
		t.Fatal(err)
	}
	if _, err = Restore(t.Context(), pool, bytes.NewReader(data), public, org, cluster); err == nil {
		t.Fatal("restored without committed audit receipt")
	}
	assertFailedRestore(t, pool, 0)
}

func assertFailedRestore(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var count, receipts int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM k8s_audit_events),(SELECT count(*) FROM audit_events WHERE action='k8s.audit.restore')`).Scan(&count, &receipts); err != nil || count != want || receipts != 0 {
		t.Fatalf("partial restore: %d %d %v", count, receipts, err)
	}
}

func TestExportOversizedRecordHeld(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, _ := archiveFixture()
	w.OrgID, w.ClusterID = seedScope(t, pool)
	if _, err := pool.Exec(t.Context(), `INSERT INTO k8s_audit_events(org_id,cluster_id,verb,raw,at) VALUES($1,$2,'get',jsonb_build_object('large',repeat('x',$4)),$3)`, w.OrgID, w.ClusterID, w.From, MaxRecordBytes); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Export(t.Context(), pool, w, 1, private, public); err == nil {
		t.Fatal("oversized record exported")
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM k8s_audit_events`).Scan(&count); err != nil || count != 1 {
		t.Fatal("oversized source was changed")
	}
}

func TestArchivePreservesReportedTimestampAndNulls(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, rows := archiveFixture()
	org, cluster := seedScope(t, pool)
	reported := w.From.Add(-time.Hour)
	rows[0].ReportedAt = &reported
	rows[0].Raw = json.RawMessage(`null`)
	data, _, err := encode(t.Context(), w, rows, false, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Restore(t.Context(), pool, bytes.NewReader(data), public, org, cluster); err != nil {
		t.Fatal(err)
	}
	var got time.Time
	var unknown bool
	if err = pool.QueryRow(t.Context(), `SELECT reported_at,resource IS NULL AND "user" IS NULL AND raw IS NULL FROM k8s_audit_events WHERE id=$1`, rows[0].ID).Scan(&got, &unknown); err != nil || !got.Equal(reported) || !unknown {
		t.Fatalf("null/timestamp changed: %v %v %v", got, unknown, err)
	}
}
