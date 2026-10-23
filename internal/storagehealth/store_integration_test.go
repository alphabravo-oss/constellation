//go:build integration

package storagehealth

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/alphabravocompany/constellation/internal/auditarchive"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestMain(m *testing.M) { pgtest.Main(m) }
func execSQL(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
func read(t *testing.T, pool *pgxpool.Pool, stream string) snapshot {
	t.Helper()
	s, err := readSnapshot(t.Context(), pool, stream)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPhysicalLeavesAndDefaultAncestryAreCountedOnce(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	execSQL(t, pool, `TRUNCATE findings;
 ALTER TABLE findings_p_default RENAME TO findings_catchall_without_suffix;
 CREATE TABLE findings_future PARTITION OF findings FOR VALUES FROM ('2050-01-01') TO ('2051-01-01') PARTITION BY RANGE(first_seen_at);
 CREATE TABLE findings_nested PARTITION OF findings_future DEFAULT;
 INSERT INTO findings(org_id,asset_id,kind,title,severity,first_seen_at)
 SELECT gen_random_uuid(),gen_random_uuid(),'vulnerability','fixture','high',at FROM (VALUES ('2020-01-01'::timestamptz),('2020-01-02'),('2050-03-01')) x(at);
 ANALYZE findings_catchall_without_suffix; ANALYZE findings_nested; ANALYZE findings;
 SELECT pg_stat_force_next_flush()`)
	s := read(t, pool, "")
	var got relation
	for _, r := range s.Relations {
		if r.Name == "findings" {
			got = r
		}
	}
	var bytes, indexes float64
	if err := pool.QueryRow(t.Context(), `SELECT (pg_total_relation_size('findings_catchall_without_suffix')+pg_total_relation_size('findings_nested'))::float8,
 (pg_indexes_size('findings_catchall_without_suffix')+pg_indexes_size('findings_nested'))::float8`).Scan(&bytes, &indexes); err != nil {
		t.Fatal(err)
	}
	if got.TotalBytes != bytes || got.IndexBytes != indexes || got.TableBytes+got.IndexBytes != got.TotalBytes {
		t.Fatalf("physical byte accounting: %+v expected bytes=%v indexes=%v", got, bytes, indexes)
	}
	if got.LiveRows != 3 || got.DefaultRows != 3 || got.DefaultBytes != bytes {
		t.Fatalf("default ancestry or parent double-count: %+v", got)
	}
	if s.DatabaseBytes < got.TotalBytes || s.WALBytes < 0 {
		t.Fatalf("database/WAL metrics: %+v", s)
	}
	// Destructive expiry is not an observability side effect.
	var n int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM findings`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("collector changed source rows: %d %v", n, err)
	}
}

func TestDeadTupleEstimatesUsePostgresStatistics(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	execSQL(t, pool, `ALTER TABLE cve_records SET (autovacuum_enabled=false);
 INSERT INTO cve_records(cve_id,title) SELECT 'TEST-'||n,'before' FROM generate_series(1,100) n;
 UPDATE cve_records SET title='after' WHERE cve_id LIKE 'TEST-%';
 ANALYZE cve_records; SELECT pg_stat_force_next_flush()`)
	s := read(t, pool, "")
	var wantLive, wantDead float64
	if err := pool.QueryRow(t.Context(), `SELECT n_live_tup::float8,n_dead_tup::float8 FROM pg_stat_all_tables WHERE relid='cve_records'::regclass`).Scan(&wantLive, &wantDead); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Relations {
		if r.Name == "cve_records" {
			if r.LiveRows != wantLive || r.DeadRows != wantDead || r.LiveRows < 100 || wantDead <= 0 {
				t.Fatalf("tuple estimates=%+v expected live=%v dead=%v", r, wantLive, wantDead)
			}
			return
		}
	}
	t.Fatal("CVE root missing")
}

func TestArchiveDestinationAndRollupProgress(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	active := auditarchive.DestinationID("https://objects.example", "evidence", "/audit/")
	old := auditarchive.DestinationID("https://old.example", "evidence", "audit")
	logger := audit.New(pool)
	ids := []int64{}
	for range 3 {
		id, _, err := logger.Log(t.Context(), audit.Event{Action: "storage.fixture"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	execSQL(t, pool, `UPDATE network_flow_rollup_state SET watermark=now()-interval '2 hours'`)
	execSQL(t, pool, `INSERT INTO audit_archive_progress(stream,last_id,last_hash,last_manifest,updated_at)
 SELECT $1,id,chain_hash,'active',now()-interval '1 hour' FROM audit_events WHERE id=$2`, active, ids[1])
	execSQL(t, pool, `INSERT INTO audit_archive_progress(stream) VALUES($1)`, old)
	s := read(t, pool, active)
	if s.ArchiveHead != ids[2] || s.ArchiveLast != ids[1] || s.ArchivePresent != 1 {
		t.Fatalf("active archive selection: %+v", s)
	}
	now := float64(time.Now().Unix())
	if now-s.RollupWatermark < 7190 || now-s.ArchiveUpdated < 3590 {
		t.Fatal("stale progress hidden")
	}
	missing := read(t, pool, "not-yet-published")
	if missing.ArchivePresent != 0 || missing.ArchiveLast != 0 || missing.ArchiveUpdated != 0 || missing.ArchiveHead != s.ArchiveHead {
		t.Fatal("missing archive falsely healthy")
	}
	disabled := read(t, pool, "")
	if disabled.ArchiveHead != 0 {
		t.Fatal("disabled archive queried")
	}
	execSQL(t, pool, `UPDATE audit_archive_progress SET last_id=999999 WHERE stream=$1`, active)
	if _, err := readSnapshot(t.Context(), pool, active); err == nil {
		t.Fatal("accepted progress ahead of source")
	}
}

func TestBackupSchedulesKeepMissingAndFailedTenantsVisible(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	execSQL(t, pool, `INSERT INTO orgs(name,display_name) VALUES ('fresh','Fresh'),('missing','Missing'),('disabled','Disabled'),('old','Old');
 INSERT INTO backup_schedules(org_id,enabled,last_status,next_run_at)
 SELECT id,name!='disabled',CASE WHEN name='old' THEN 'failed' ELSE 'succeeded' END,
 CASE WHEN name='old' THEN now()-interval '2 hours' ELSE now()+interval '1 day' END FROM orgs WHERE name IN ('fresh','missing','disabled','old');
 INSERT INTO backups(org_id,status,mode,finished_at)
 SELECT id,'succeeded','org-backup',CASE WHEN name='old' THEN now()-interval '3 days' ELSE now()-interval '1 hour' END FROM orgs WHERE name IN ('fresh','disabled','old');
 INSERT INTO backups(org_id,status,mode,finished_at) SELECT id,'succeeded','pg-dump',now() FROM orgs WHERE name='missing';
 INSERT INTO backups(org_id,status,mode,finished_at) SELECT id,'failed','org-backup',now() FROM orgs WHERE name='missing'`)
	s := read(t, pool, "")
	if s.BackupSchedules != 3 || s.BackupMissing != 1 || s.BackupFailed != 1 {
		t.Fatalf("backup scope: %+v", s)
	}
	now := float64(time.Now().Unix())
	if now-s.BackupOldestSuccess < 3*86400-10 || now-s.BackupOldestDue < 7190 {
		t.Fatal("fresh tenant masked older or overdue tenant")
	}
	// Never-initialized schedules must become overdue even with NULL next_run_at.
	execSQL(t, pool, `UPDATE backup_schedules SET next_run_at=NULL,created_at=now()-interval '4 hours' WHERE org_id=(SELECT id FROM orgs WHERE name='missing')`)
	uninitialized := read(t, pool, "")
	if now-uninitialized.BackupOldestDue < 4*3600-10 {
		t.Fatal("uninitialized schedule was hidden")
	}

	execSQL(t, pool, `UPDATE backup_schedules SET enabled=false`)
	s = read(t, pool, "")
	if s.BackupSchedules != 0 || s.BackupMissing != 0 || s.BackupFailed != 0 || s.BackupOldestDue != 0 || s.BackupOldestSuccess != 0 {
		t.Fatal("disabled schedules retained stale data")
	}
	execSQL(t, pool, `INSERT INTO backups(org_id,status,mode,finished_at)
 SELECT o.id,'failed','org-backup',now() FROM orgs o CROSS JOIN generate_series(1,2000) WHERE o.name='fresh'; ANALYZE backups`)
	rows, err := pool.Query(t.Context(), `EXPLAIN SELECT finished_at FROM backups
 WHERE org_id=(SELECT id FROM orgs WHERE name='fresh') AND mode='org-backup' AND status='succeeded' AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1`)
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err = rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "idx_backups_org_latest_success") {
		t.Fatalf("latest-success lookup lost its bounded index plan: %s", plan.String())
	}

	var valid bool
	if err := pool.QueryRow(t.Context(), `SELECT indisvalid FROM pg_index WHERE indexrelid='idx_backups_org_latest_success'::regclass`).Scan(&valid); err != nil || !valid {
		t.Fatalf("latest-success index invalid: %v", err)
	}
}

func gather(t *testing.T, reg *prometheus.Registry) map[string][]*dto.Metric {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]*dto.Metric{}
	for _, f := range families {
		out[strings.TrimPrefix(f.GetName(), "constellation_storage_")] = f.Metric
	}
	return out
}
func gauge(m map[string][]*dto.Metric, name string) float64 {
	if len(m[name]) == 0 {
		return -1
	}
	return m[name][0].GetGauge().GetValue()
}
func counter(m map[string][]*dto.Metric, name string) float64 {
	if len(m[name]) == 0 {
		return -1
	}
	return m[name][0].GetCounter().GetValue()
}

func TestCollectorCacheFailureRecoveryAndBoundedLabels(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	c := New(pool, Config{TTL: time.Hour}, nil)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	first := gather(t, reg)
	if gauge(first, "collector_up") != 1 || gauge(first, "database_bytes") <= 0 || counter(first, "collector_queries_total") != 1 {
		t.Fatal("initial metrics unavailable")
	}
	for name, metrics := range first {
		for _, m := range metrics {
			for _, l := range m.Label {
				if l.GetName() != "table" && l.GetName() != "kind" {
					t.Fatalf("unbounded label %s in %s", l.GetName(), name)
				}
			}
		}
	}
	// Many concurrent gathers share one cached database snapshot.
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = reg.Gather() }()
	}
	wg.Wait()
	if got := counter(gather(t, reg), "collector_queries_total"); got != 1 {
		t.Fatalf("cache stampede: %v", got)
	}
	execSQL(t, pool, `ALTER TABLE network_flow_rollup_state RENAME TO unavailable_rollup`)
	c.mu.Lock()
	c.attempted = time.Time{}
	c.mu.Unlock()
	failed := gather(t, reg)
	if gauge(failed, "collector_up") != 0 || counter(failed, "collector_errors_total") != 1 || len(failed["relation_bytes"]) != 0 {
		t.Fatal("failed snapshot retained stale or partial storage values")
	}
	if gauge(failed, "collector_last_success_timestamp_seconds") != gauge(first, "collector_last_success_timestamp_seconds") {
		t.Fatal("failure advanced success time")
	}
	if counter(gather(t, reg), "collector_queries_total") != 2 {
		t.Fatal("failure bypassed cache backoff")
	}
	execSQL(t, pool, `ALTER TABLE unavailable_rollup RENAME TO network_flow_rollup_state`)
	c.mu.Lock()
	c.attempted = time.Time{}
	c.mu.Unlock()
	if gauge(gather(t, reg), "collector_up") != 1 {
		t.Fatal("collector did not recover")
	}
}

func TestCollectorLockTimeoutAndMissingRelationFailClosed(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err = tx.Exec(t.Context(), `LOCK TABLE network_flow_rollup_state IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err = readSnapshot(t.Context(), pool, ""); err == nil {
		t.Fatal("locked source accepted")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("lock timeout exceeded: %v", elapsed)
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	execSQL(t, pool, `ALTER TABLE scan_evidence RENAME TO unavailable_evidence`)
	if _, err = readSnapshot(t.Context(), pool, ""); err == nil {
		t.Fatal("missing monitored relation treated as empty")
	}
}

func TestStorageReaderDoesNotRequireSuperuserOrWriteGrants(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	role := "storage_reader_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ident := pgx.Identifier{role}.Sanitize()
	execSQL(t, pool, "CREATE ROLE "+ident)
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), "DROP OWNED BY "+ident+"; DROP ROLE "+ident)
		if err != nil {
			t.Error(err)
		}
	})
	execSQL(t, pool, "GRANT USAGE ON SCHEMA public TO "+ident+"; GRANT SELECT ON orgs,system_config,network_flow_rollup_state,audit_archive_progress,audit_events,backups,backup_schedules TO "+ident)
	cfg := pool.Config()
	cfg.ConnConfig.RuntimeParams["role"] = role
	reader, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	s := read(t, reader, "configured")
	if len(s.Relations) != len(monitoredTables) {
		t.Fatal("read-only role missing stats")
	}
	if s.WALKnown != 0 {
		t.Fatal("unprivileged WAL occupancy claimed known")
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(New(reader, Config{}, nil))
	metrics := gather(t, reg)
	if gauge(metrics, "postgres_wal_occupancy_known") != 0 || len(metrics["postgres_wal_retained_bytes"]) != 0 {
		t.Fatal("unknown WAL emitted as a measured zero")
	}

	if _, err = reader.Exec(t.Context(), `DELETE FROM audit_archive_progress`); err == nil {
		t.Fatal("reader unexpectedly has write access")
	}
}

func TestArchiveIDDistancePreservesBigintPrecision(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	execSQL(t, pool, `SELECT setval('audit_events_id_seq',9007199254740992,false)`)
	logger := audit.New(pool)
	first, hash, err := logger.Log(t.Context(), audit.Event{Action: "large-id.first"})
	if err != nil {
		t.Fatal(err)
	}
	last, _, err := logger.Log(t.Context(), audit.Event{Action: "large-id.last"})
	if err != nil {
		t.Fatal(err)
	}
	if last-first != 1 {
		t.Fatal("invalid sequence fixture")
	}
	execSQL(t, pool, `INSERT INTO audit_archive_progress(stream,last_id,last_hash,last_manifest) VALUES('large-id',$1,$2,'fixture')`, first, hash)
	c := New(pool, Config{ArchiveStream: "large-id"}, nil)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	if got := gauge(gather(t, reg), "archive_pending_id_distance"); got != 1 {
		t.Fatalf("pending evidence vanished through float rounding: %v", got)
	}
}

func TestRetentionSignalsUseActualBoundsAndHoldPolicy(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	execSQL(t, pool, `INSERT INTO orgs(name,display_name) VALUES('retention-signals','Retention signals');
 INSERT INTO system_config(org_id,config) SELECT id,'{"events_retention_days":7,"network_flow_retention_days":7,"scan_job_retention_days":7}'::jsonb FROM orgs WHERE name='retention-signals';
 CREATE TABLE events_20990101 PARTITION OF events FOR VALUES FROM ('2001-01-01') TO ('2001-01-02');
 CREATE TABLE events_19990101 PARTITION OF events FOR VALUES FROM ('2099-01-01') TO ('2099-01-02');
 CREATE TABLE flow_old_observation PARTITION OF network_flows FOR VALUES FROM ('2001-01-01') TO ('2001-01-02')`)
	s := read(t, pool, "")
	for _, signal := range s.Retention {
		if signal.Enabled != 1 {
			t.Fatalf("retention unexpectedly held: %+v", signal)
		}
		if signal.Table == "events" && (signal.ExpiredPartitions != 1 || signal.OldestExpiredUpper != 978393600) {
			t.Fatalf("actual bounds not counted: %+v", signal)
		}
		if signal.Table == "network_flows" && signal.ExpiredPartitions != 0 {
			t.Fatal("unfolded flow partition treated as eligible")
		}
	}
	execSQL(t, pool, `UPDATE network_flow_rollup_state SET watermark=now(),raw_pruned_before=now()-interval '7 days'`)
	s = read(t, pool, "")
	for _, signal := range s.Retention {
		if signal.Table == "network_flows" && signal.ExpiredPartitions != 1 {
			t.Fatalf("folded old partition omitted: %+v", signal)
		}
	}
	if s.RawPrunedBefore <= 0 || s.WALKnown != 1 || s.WALRetained <= 0 {
		t.Fatalf("progress/WAL missing: %+v", s)
	}
	execSQL(t, pool, `INSERT INTO orgs(name,display_name) VALUES('retention-hold','Retention hold');
 INSERT INTO system_config(org_id,config) SELECT id,'{"events_retention_days":0,"network_flow_retention_days":0,"scan_job_retention_days":0}'::jsonb FROM orgs WHERE name='retention-hold'`)
	for _, signal := range read(t, pool, "").Retention {
		if signal.Enabled != 0 || signal.Cutoff != 0 || signal.ExpiredPartitions != 0 {
			t.Fatalf("tenant hold bypassed: %+v", signal)
		}
	}
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('events_20990101') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatal("observation removed a partition")
	}
}

func TestRetentionSignalRejectsInvalidPolicy(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	execSQL(t, pool, `INSERT INTO orgs(name,display_name) VALUES('bad-policy','Bad policy');
 INSERT INTO system_config(org_id,config) SELECT id,'{"events_retention_days":-1}'::jsonb FROM orgs WHERE name='bad-policy'`)
	if _, err := readSnapshot(t.Context(), pool, ""); err == nil {
		t.Fatal("invalid policy claimed healthy expiry")
	}
}
