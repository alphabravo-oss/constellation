//go:build integration

package threatarchive

import (
	"bytes"
	"context"
	"errors"
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
	if _, err := source.Exec(t.Context(), `INSERT INTO runtime_threats(org_id,cluster_id,threat_id,severity,packet,pkt_len,cap_len,reported_at,at)
 SELECT $1,$2,4294967295,9,decode('00ff805c','hex'),4,9000,$3::timestamptz-interval '1 day',$3 FROM generate_series(1,1005)`, w.OrgID, w.ClusterID, w.From.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(t.Context(), `INSERT INTO runtime_threats(org_id,cluster_id,threat_id,severity,reported_at,at) VALUES
 ($1,$2,1,9,$3,$3),($1,$2,1,9,$4,$4),($5,$6,1,9,$3,$3),($1,$6,1,9,$7,$7)`, w.OrgID, w.ClusterID, w.From.Add(-time.Second), w.Through, otherOrg, otherCluster, w.From); err != nil {
		t.Fatal(err)
	}
	// A non-default bytea output must not alter the archive encoding.
	config := source.Config().Copy()
	config.ConnConfig.RuntimeParams["bytea_output"] = "escape"
	exportPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(exportPool.Close)
	pages := [][]byte{}
	reports := []Report{}
	for _, want := range []int{1000, 5} {
		data, report, err := Export(t.Context(), exportPool, w, 1000, private, public)
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
	if _, _, err := Export(t.Context(), exportPool, w, 1000, private, public); err == nil {
		t.Fatal("empty page reported archive success")
	}
	var unchanged int
	if err := source.QueryRow(t.Context(), `SELECT count(*) FROM runtime_threats`).Scan(&unchanged); err != nil || unchanged != 1009 {
		t.Fatalf("source changed: %d %v", unchanged, err)
	}
	exportPool.Close()
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
	if err = dest.QueryRow(t.Context(), `SELECT count(*),bool_and(org_id=$1 AND cluster_id=$2 AND packet=decode('00ff805c','hex') AND threat_id=4294967295 AND pkt_len=4 AND cap_len=9000 AND reported_at=at-interval '1 day' AND workload_id IS NULL) FROM runtime_threats`, org, cluster).Scan(&count, &intact); err != nil || count != 1005 || !intact {
		t.Fatalf("recovered evidence: %d %v %v", count, intact, err)
	}
	if err = dest.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='runtime.threat.restore' AND org_id=$1`, org).Scan(&receipts); err != nil || receipts != 2 {
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
	if _, err = pool.Exec(t.Context(), `INSERT INTO runtime_threats(id,org_id,cluster_id,threat_id,severity,reported_at,at) VALUES($1,$2,$3,1,9,$4,$4)`, rows[1].ID, org, cluster, rows[1].At); err != nil {
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
	if _, err = pool.Exec(t.Context(), `CREATE FUNCTION reject_threat_archive_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit fixture unavailable'; END $$;
 CREATE CONSTRAINT TRIGGER reject_threat_archive_receipt AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_threat_archive_receipt()`); err != nil {
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
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM runtime_threats),(SELECT count(*) FROM audit_events WHERE action='runtime.threat.restore')`).Scan(&count, &receipts); err != nil || count != want || receipts != 0 {
		t.Fatalf("partial restore: %d %d %v", count, receipts, err)
	}
}

func TestExportOversizedRecordHeld(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, _ := archiveFixture()
	w.OrgID, w.ClusterID = seedScope(t, pool)
	if _, err := pool.Exec(t.Context(), `INSERT INTO runtime_threats(org_id,cluster_id,threat_id,severity,msg,reported_at,at) VALUES($1,$2,1,9,repeat('x',$4),$3,$3)`, w.OrgID, w.ClusterID, w.From, MaxRecordBytes); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Export(t.Context(), pool, w, 1, private, public); err == nil {
		t.Fatal("oversized record exported")
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM runtime_threats`).Scan(&count); err != nil || count != 1 {
		t.Fatal("oversized source was changed")
	}
}

func TestArchivePreservesPacketNullEmptyAndMetadata(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, _ := archiveFixture()
	w.OrgID, w.ClusterID = seedScope(t, pool)
	if _, err := pool.Exec(t.Context(), `INSERT INTO runtime_threats(org_id,cluster_id,threat_id,severity,reported_at,at,packet,msg,workload_id,application,dlp_name_hash,pkt_len,cap_len)
 VALUES($1,$2,4294967295,9,$3,$3,NULL,'private message','workload',2147483647,9223372036854775807,0,99),($1,$2,2147483648,9,$3,$3,decode('','hex'),NULL,NULL,NULL,NULL,NULL,NULL)`, w.OrgID, w.ClusterID, w.From); err != nil {
		t.Fatal(err)
	}
	data, _, err := Export(t.Context(), pool, w, 1000, private, public)
	if err != nil {
		t.Fatal(err)
	}
	org, cluster := seedScope(t, pool)
	// Restore in place is a conflict: identities cannot be silently remapped twice.
	if _, err = Restore(t.Context(), pool, bytes.NewReader(data), public, org, cluster); err == nil {
		t.Fatal("foreign existing identity accepted")
	}
	// Replaying to the original scope preserves SQL null vs zero-length bytea.
	got, err := Restore(t.Context(), pool, bytes.NewReader(data), public, w.OrgID, w.ClusterID)
	if err != nil || got.Existing != 2 || got.Inserted != 0 {
		t.Fatalf("metadata replay: %+v %v", got, err)
	}
	records, _, err := verify(t.Context(), bytes.NewReader(data), public)
	if err != nil {
		t.Fatal(err)
	}
	nulls, empty := 0, 0
	for _, r := range records {
		if r.Packet == nil {
			nulls++
			if r.DLPNameHash == nil || *r.DLPNameHash != 9223372036854775807 || r.Msg == nil || *r.Msg != "private message" {
				t.Fatal("metadata lost")
			}
		} else if *r.Packet == `\x` {
			empty++
		}
	}
	if nulls != 1 || empty != 1 {
		t.Fatal("null/empty packet collapsed")
	}
}

func TestRestoreCancellationAndLockedDestination(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, rows := archiveFixture()
	org, cluster := seedScope(t, pool)
	data, _, err := encode(t.Context(), w, rows, false, private, public)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(t.Context(), `SELECT id FROM clusters WHERE id=$1 FOR UPDATE`, cluster); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err = Restore(ctx, pool, bytes.NewReader(data), public, org, cluster); err == nil {
		t.Fatal("restore ignored destination lock")
	}
	assertFailedRestore(t, pool, 0)
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, _, err = Export(canceled, pool, w, 1000, private, public); !errors.Is(err, context.Canceled) {
		t.Fatalf("export cancellation: %v", err)
	}
}

func TestByteBudgetPagesPreserveSourceAndQuarantine(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, _ := archiveFixture()
	w.OrgID, w.ClusterID = seedScope(t, pool)
	if _, err := pool.Exec(t.Context(), `INSERT INTO runtime_threats(org_id,cluster_id,threat_id,severity,msg,reported_at,at)
 SELECT $1,$2,1,9,repeat('x',3*1024*1024),$3,$3 FROM generate_series(1,12)`, w.OrgID, w.ClusterID, w.From); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO quarantine_entries(org_id,cluster_id,scope,match_key,reason,origin,source_kind,source_id)
 SELECT org_id,cluster_id,'workload','ns/app','case evidence','auto','runtime_threat',id FROM runtime_threats LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{10, 2} {
		data, report, err := Export(t.Context(), pool, w, 1000, private, public)
		if err != nil {
			t.Fatal(err)
		}
		if report.Manifest.Count != want || report.Manifest.More != (want == 10) || report.Manifest.RecordBytes > MaxBatchBytes {
			t.Fatalf("byte page: %+v", report)
		}
		if _, err = Verify(t.Context(), bytes.NewReader(data), public); err != nil {
			t.Fatal(err)
		}
		w.After = report.Manifest.Last
	}
	var count, refs int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM runtime_threats),(SELECT count(*) FROM quarantine_entries q JOIN runtime_threats t ON q.source_id=t.id WHERE q.lifted_at IS NULL)`).Scan(&count, &refs); err != nil || count != 12 || refs != 1 {
		t.Fatalf("source/case altered: %d %d %v", count, refs, err)
	}
}

func TestConcurrentReplayHasOneReceipt(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := archiveKeys(t)
	w, rows := archiveFixture()
	org, cluster := seedScope(t, pool)
	data, _, err := encode(t.Context(), w, rows, false, private, public)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan RestoreResult, 2)
	failures := make(chan error, 2)
	for range 2 {
		go func() {
			result, err := Restore(t.Context(), pool, bytes.NewReader(data), public, org, cluster)
			results <- result
			failures <- err
		}()
	}
	inserted, existing := 0, 0
	for range 2 {
		result := <-results
		if err := <-failures; err != nil {
			t.Fatal(err)
		}
		inserted += result.Inserted
		existing += result.Existing
	}
	if inserted != 1 || existing != 1 {
		t.Fatalf("concurrent replay counts: %d %d", inserted, existing)
	}
	var receipts, quarantines int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM audit_events WHERE action='runtime.threat.restore'),(SELECT count(*) FROM quarantine_entries)`).Scan(&receipts, &quarantines); err != nil || receipts != 1 || quarantines != 0 {
		t.Fatalf("replay side effects: %d %d %v", receipts, quarantines, err)
	}
}
