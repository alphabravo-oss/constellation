// Package storagehealth reads bounded operational storage signals. It never
// changes retention, repairs evidence, or scans high-volume tables for counts.
package storagehealth

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/syscfg"
)

var monitoredTables = []string{"events", "network_flows", "findings", "audit_events", "cve_records", "network_flow_rollups", "k8s_audit_events", "runtime_threats", "runtime_pcap_captures", "forensics_snapshots", "scan_jobs", "image_scan_results", "scan_evidence", "backups"}

type relation struct {
	Name                                                                              string
	TableBytes, IndexBytes, TotalBytes, LiveRows, DeadRows, DefaultBytes, DefaultRows float64
}
type retentionSignal struct {
	Table                                                  string
	Enabled, Cutoff, ExpiredPartitions, OldestExpiredUpper float64
}
type snapshot struct {
	Retention                                                                          []retentionSignal
	WALRetained, WALKnown, RawPrunedBefore                                             float64
	ArchiveHead, ArchiveLast                                                           int64
	Relations                                                                          []relation
	DatabaseBytes, WALBytes, WALReset, RollupWatermark                                 float64
	ArchiveUpdated, ArchivePresent                                                     float64
	BackupSchedules, BackupMissing, BackupFailed, BackupOldestSuccess, BackupOldestDue float64
}

// All leaf sizes are counted once under their fixed root. Parent statistics are
// excluded because they can describe the same tuples as their child statistics.
// DEFAULT ancestry is catalog-derived, never inferred from a naming convention.
const relationSQL = `WITH RECURSIVE roots AS (
 SELECT name,to_regclass('public.'||name) AS oid FROM unnest($1::text[]) name
), tree AS (
 SELECT name,oid,false AS in_default FROM roots WHERE oid IS NOT NULL
 UNION ALL
 SELECT t.name,i.inhrelid,t.in_default OR pg_get_expr(c.relpartbound,c.oid)='DEFAULT'
 FROM tree t JOIN pg_inherits i ON i.inhparent=t.oid JOIN pg_class c ON c.oid=i.inhrelid
)
SELECT t.name,
 COALESCE(sum(pg_table_size(c.oid)) FILTER(WHERE c.relkind IN ('r','m')),0)::float8,
 COALESCE(sum(pg_indexes_size(c.oid)) FILTER(WHERE c.relkind IN ('r','m')),0)::float8,
 COALESCE(sum(pg_total_relation_size(c.oid)) FILTER(WHERE c.relkind IN ('r','m')),0)::float8,
 COALESCE(sum(s.n_live_tup) FILTER(WHERE c.relkind IN ('r','m')),0)::float8,
 COALESCE(sum(s.n_dead_tup) FILTER(WHERE c.relkind IN ('r','m')),0)::float8,
 COALESCE(sum(pg_total_relation_size(c.oid)) FILTER(WHERE t.in_default AND c.relkind IN ('r','m')),0)::float8,
 COALESCE(sum(s.n_live_tup) FILTER(WHERE t.in_default AND c.relkind IN ('r','m')),0)::float8
 FROM tree t JOIN pg_class c ON c.oid=t.oid
 LEFT JOIN pg_stat_all_tables s ON s.relid=c.oid GROUP BY t.name ORDER BY t.name`

func readSnapshot(ctx context.Context, pool *pgxpool.Pool, stream string) (snapshot, error) {
	var out snapshot
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='2500ms'; SET LOCAL lock_timeout='250ms'`); err != nil {
		return out, err
	}
	out.Relations, err = readRelations(ctx, tx)
	if err != nil {
		return out, err
	}
	err = tx.QueryRow(ctx, `SELECT pg_database_size(current_database())::float8,
 wal_bytes::float8,COALESCE(extract(epoch FROM stats_reset),0)::float8 FROM pg_stat_wal`).Scan(&out.DatabaseBytes, &out.WALBytes, &out.WALReset)
	if err != nil {
		return out, err
	}
	err = tx.QueryRow(ctx, `SELECT extract(epoch FROM watermark)::float8,extract(epoch FROM raw_pruned_before)::float8 FROM network_flow_rollup_state WHERE id=true`).Scan(&out.RollupWatermark, &out.RawPrunedBefore)
	if err != nil {
		return out, err
	}
	if err = readWALOccupancy(ctx, tx, &out); err != nil {
		return out, err
	}
	if err = readRetentionProgress(ctx, tx, &out); err != nil {
		return out, err
	}
	if stream != "" {
		if err = readArchive(ctx, tx, stream, &out); err != nil {
			return out, err
		}
	}
	if err = readBackups(ctx, tx, &out); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func readRelations(ctx context.Context, tx pgx.Tx) ([]relation, error) {
	rows, err := tx.Query(ctx, relationSQL, monitoredTables)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]relation, 0, len(monitoredTables))
	for rows.Next() {
		var r relation
		if err = rows.Scan(&r.Name, &r.TableBytes, &r.IndexBytes, &r.TotalBytes, &r.LiveRows, &r.DeadRows, &r.DefaultBytes, &r.DefaultRows); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(monitoredTables) {
		return nil, fmt.Errorf("storage health requires all %d monitored relations; found %d", len(monitoredTables), len(out))
	}
	return out, nil
}
func readArchive(ctx context.Context, tx pgx.Tx, stream string, out *snapshot) error {
	err := tx.QueryRow(ctx, `SELECT
 COALESCE((SELECT id FROM audit_events ORDER BY id DESC LIMIT 1),0),
 COALESCE(p.last_id,0),COALESCE(extract(epoch FROM p.updated_at),0)::float8,
 CASE WHEN p.stream IS NULL THEN 0::float8 ELSE 1::float8 END
 FROM (SELECT $1::text AS stream) wanted LEFT JOIN audit_archive_progress p USING(stream)`, stream).Scan(&out.ArchiveHead, &out.ArchiveLast, &out.ArchiveUpdated, &out.ArchivePresent)
	if err != nil {
		return err
	}
	if out.ArchiveLast > out.ArchiveHead {
		return fmt.Errorf("archive progress is ahead of retained source chain")
	}
	return nil
}

// The partial index added with this reader keeps each enabled organization's
// latest-success lookup bounded. Disabled schedules never hide or add failures.
func readBackups(ctx context.Context, tx pgx.Tx, out *snapshot) error {
	return tx.QueryRow(ctx, `SELECT count(*)::float8,
 count(*) FILTER(WHERE b.finished_at IS NULL)::float8,
 count(*) FILTER(WHERE s.last_status='failed')::float8,
 COALESCE(extract(epoch FROM min(b.finished_at)),0)::float8,
 COALESCE(extract(epoch FROM min(COALESCE(s.next_run_at,s.created_at)) FILTER(WHERE COALESCE(s.next_run_at,s.created_at)<=now())),0)::float8
 FROM backup_schedules s LEFT JOIN LATERAL (
 SELECT finished_at FROM backups WHERE org_id=s.org_id AND mode='org-backup' AND status='succeeded' AND finished_at IS NOT NULL
 ORDER BY finished_at DESC LIMIT 1) b ON true WHERE s.enabled`).Scan(&out.BackupSchedules, &out.BackupMissing, &out.BackupFailed, &out.BackupOldestSuccess, &out.BackupOldestDue)
}

func epoch(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixNano()) / 1e9
}

// The application does not need a filesystem privilege merely to collect other
// health signals. Unknown WAL occupancy is explicit and never emitted as zero.
func readWALOccupancy(ctx context.Context, tx pgx.Tx, out *snapshot) error {
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT has_function_privilege(current_user,'pg_catalog.pg_ls_waldir()','EXECUTE')`).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return nil
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(size),0)::float8 FROM pg_catalog.pg_ls_waldir()`).Scan(&out.WALRetained); err != nil {
		return err
	}
	out.WALKnown = 1
	return nil
}

func readRetentionProgress(ctx context.Context, tx pgx.Tx, out *snapshot) error {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		return err
	}
	for _, family := range []struct {
		table string
		pick  func(syscfg.Config) int
	}{
		{"events", func(c syscfg.Config) int { return c.EventsRetentionDays }},
		{"network_flows", func(c syscfg.Config) int { return c.NetworkFlowRetentionDays }},
	} {
		days, err := syscfg.EffectiveRetentionDays(ctx, tx, family.pick)
		if err != nil {
			return err
		}
		signal := retentionSignal{Table: family.table}
		if days == 0 {
			out.Retention = append(out.Retention, signal)
			continue
		}
		cutoff := now.Add(-time.Duration(days) * 24 * time.Hour).UTC()
		if family.table == "network_flows" {
			cutoff = cutoff.Truncate(time.Hour)
			folded := time.Unix(int64(out.RollupWatermark), 0).UTC().Add(-time.Hour).Truncate(time.Hour)
			if folded.Before(cutoff) {
				cutoff = folded
			}
		}
		signal.Enabled = 1
		signal.Cutoff = epoch(cutoff)
		// Inspect actual range bounds, not date-shaped relation names. Unexpected
		// non-default bounds fail the snapshot instead of claiming no expiry backlog.
		var unknownBounds int
		err = tx.QueryRow(ctx, `WITH bounds AS (
    SELECT pg_get_expr(c.relpartbound,c.oid) AS expression FROM pg_inherits i
    JOIN pg_class c ON c.oid=i.inhrelid WHERE i.inhparent=to_regclass('public.'||$1)
   ), ranges AS (
    SELECT substring(expression FROM 'TO \(''([^'']+)''\)')::timestamptz AS upper_bound
    FROM bounds WHERE expression<>'DEFAULT'
   ) SELECT count(*) FILTER(WHERE upper_bound<=$2)::float8,
    COALESCE(extract(epoch FROM min(upper_bound) FILTER(WHERE upper_bound<=$2)),0)::float8,
    count(*) FILTER(WHERE upper_bound IS NULL) FROM ranges`, family.table, cutoff).Scan(&signal.ExpiredPartitions, &signal.OldestExpiredUpper, &unknownBounds)
		if err != nil {
			return err
		}
		if unknownBounds != 0 {
			return fmt.Errorf("storage health cannot interpret %s partition bounds", family.table)
		}
		out.Retention = append(out.Retention, signal)
	}
	return nil
}
