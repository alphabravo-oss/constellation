package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/alphabravocompany/constellation/internal/flowrollup"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PartitionManager keeps the big time-series tables (events, network_flows) healthy
// by managing daily RANGE partitions on their `at` column:
//
//   - PRE-CREATE upcoming daily partitions (a few days ahead) so new rows route into a
//     dated partition instead of piling into the catch-all DEFAULT partition. Creating
//     tomorrow's partition today is always safe — the default holds no future rows.
//   - DROP whole partitions once every row in them is older than the retention horizon.
//     A partition DROP is instant and returns the disk to the OS immediately — unlike a
//     batched DELETE, which leaves dead tuples the file never shrinks past (this is why
//     the tables ballooned to tens of GB after prior row-level pruning).
//
// This is the NeuVector-style bound: raw records are cheap to shed because the durable
// signal lives in the aggregates (network_flow_rollups) and findings, not the raw rows.
//
// The pre-created partitions capture data going FORWARD. Rows already sitting in the
// DEFAULT partition (history + the current day, before its partition existed) are left
// to the age-based retention DELETE loops (rollup.go / events_retention.go). Once a
// default partition is empty, the manager reclaims its delete bloat with TRUNCATE.
type PartitionedTable struct {
	Parent        string                        // "events" | "network_flows"
	RetentionDays func(ctx context.Context) int // live retention horizon (0 = keep forever → never drop)
}

// partitionNameRe matches a managed daily partition: <parent>_YYYYMMDD.
var partitionNameRe = regexp.MustCompile(`_(\d{8})$`)
var partitionParentRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

const defaultPartitionReclaimMinBytes int64 = 256 << 20

// RunPartitionManager runs the manager until ctx is cancelled. Leader-gated by the
// caller. Ticks hourly (cheap; the work is idempotent) plus once immediately on start.
func RunPartitionManager(ctx context.Context, pool *pgxpool.Pool, tables []PartitionedTable, logger *slog.Logger) {
	if pool == nil || len(tables) == 0 {
		return
	}
	const aheadDays = 3 // keep this many future daily partitions pre-created
	run := func() {
		for _, t := range tables {
			if err := ensureDailyPartitions(ctx, pool, t.Parent, aheadDays); err != nil && logger != nil {
				logger.Warn("partition manager: ensure", slog.String("table", t.Parent), slog.String("err", err.Error()))
			}
			days := t.RetentionDays(ctx)
			dropped, err := dropExpiredPartitions(ctx, pool, t.Parent, days)
			if err != nil && logger != nil {
				logger.Warn("partition manager: drop", slog.String("table", t.Parent), slog.String("err", err.Error()))
			}
			if dropped > 0 && logger != nil {
				logger.Info("partition manager: dropped expired partitions",
					slog.String("table", t.Parent), slog.Int("count", dropped), slog.Int("retention_days", days))
			}
			reclaimed, err := reclaimEmptyDefaultPartition(ctx, pool, t.Parent, defaultPartitionReclaimMinBytes)
			if err != nil && logger != nil {
				logger.Warn("partition manager: reclaim default", slog.String("table", t.Parent), slog.String("err", err.Error()))
			}
			if reclaimed && logger != nil {
				logger.Info("partition manager: reclaimed empty default partition", slog.String("table", t.Parent))
			}
		}
	}
	run()
	tk := time.NewTicker(time.Hour)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			run()
		}
	}
}

func reclaimEmptyDefaultPartition(ctx context.Context, pool *pgxpool.Pool, parent string, minBytes int64) (bool, error) {
	if !partitionParentRe.MatchString(parent) {
		return false, fmt.Errorf("invalid partition parent %q", parent)
	}
	child := parent + "_p_default"
	identifier := pgx.Identifier{child}.Sanitize()
	var size int64
	err := pool.QueryRow(ctx, `
SELECT pg_total_relation_size(c.oid)
  FROM pg_inherits i
  JOIN pg_class c ON c.oid = i.inhrelid
 WHERE i.inhparent = to_regclass($1)
   AND i.inhrelid = to_regclass($2)
   AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'`, parent, child).Scan(&size)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if size < minBytes {
		return false, nil
	}
	var occupied bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ONLY `+identifier+` LIMIT 1)`).Scan(&occupied); err != nil {
		return false, err
	}
	if occupied {
		return false, nil
	}

	lockCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := pool.Begin(lockCtx)
	if err != nil {
		if reclaimLockUnavailable(err) {
			return false, nil
		}
		return false, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(lockCtx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
		return false, err
	}
	if _, err := tx.Exec(lockCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return false, err
	}
	if _, err := tx.Exec(lockCtx, `SET LOCAL enable_seqscan = off`); err != nil {
		return false, err
	}
	if _, err := tx.Exec(lockCtx, `LOCK TABLE `+identifier+` IN ACCESS EXCLUSIVE MODE NOWAIT`); err != nil {
		if reclaimLockUnavailable(err) {
			return false, nil
		}
		return false, err
	}
	var isDefault bool
	if err := tx.QueryRow(lockCtx, `
SELECT EXISTS (
    SELECT 1 FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    WHERE i.inhparent = to_regclass($1)
      AND i.inhrelid = to_regclass($2)
      AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'
)`, parent, child).Scan(&isDefault); err != nil {
		if reclaimLockUnavailable(err) {
			return false, nil
		}
		return false, err
	}
	if !isDefault {
		return false, nil
	}
	var marker int
	err = tx.QueryRow(lockCtx, `SELECT 1 FROM ONLY `+identifier+` ORDER BY id, at LIMIT 1`).Scan(&marker)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		if reclaimLockUnavailable(err) {
			return false, nil
		}
		return false, err
	}
	if _, err := tx.Exec(lockCtx, `TRUNCATE TABLE ONLY `+identifier); err != nil {
		if reclaimLockUnavailable(err) {
			return false, nil
		}
		return false, err
	}
	if err := tx.Commit(lockCtx); err != nil {
		return false, err
	}
	return true, nil
}

func reclaimLockUnavailable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &pgErr) && (pgErr.Code == "55P03" || pgErr.Code == "57014"))
}

// ensureDailyPartitions creates a daily partition for each of the next `aheadDays` days
// (starting tomorrow) if it does not already exist. Tomorrow's partition is created
// today so that when the clock rolls over, that day's inserts route into it rather than
// the default. Idempotent via IF NOT EXISTS.
func ensureDailyPartitions(ctx context.Context, pool *pgxpool.Pool, parent string, aheadDays int) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for i := 1; i <= aheadDays; i++ {
		d := today.AddDate(0, 0, i)
		name := partitionName(parent, d)
		lo := d.Format("2006-01-02")
		hi := d.AddDate(0, 0, 1).Format("2006-01-02")
		// Identifiers are derived from a fixed parent constant + a formatted date, so
		// string-building the DDL is safe (no user input, no injection surface).
		sql := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
			name, parent, lo, hi)
		if _, err := pool.Exec(ctx, sql); err != nil {
			return fmt.Errorf("create partition %s: %w", name, err)
		}
	}
	return nil
}

// dropExpiredPartitions drops every managed daily partition of `parent` whose day is
// entirely older than the retention horizon (its whole [day, day+1) range is < cutoff).
// The DEFAULT partition and any non-daily child are never touched. Returns the count
// dropped. retentionDays <= 0 means "keep forever" — nothing is dropped.
func dropExpiredPartitions(ctx context.Context, pool *pgxpool.Pool, parent string, retentionDays int) (int, error) {
	if !partitionParentRe.MatchString(parent) {
		return 0, fmt.Errorf("invalid partition parent %q", parent)
	}
	if retentionDays <= 0 {
		return 0, nil
	}
	// A partition for day D covers [D, D+1). It is fully expired once D+1 <= cutoff,
	// i.e. D < cutoff-1day. cutoff = midnight(today) - retentionDays.
	cutoff := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -retentionDays)

	rows, err := pool.Query(ctx,
		`SELECT inhrelid::regclass::text FROM pg_inherits WHERE inhparent = $1::regclass`, parent)
	if err != nil {
		return 0, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return 0, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	dropped := 0
	for _, n := range names {
		day, ok := partitionDay(n)
		if !ok {
			continue // default / non-daily partition
		}
		// Fully expired when the partition's upper bound (day+1) is at or before cutoff.
		if !day.AddDate(0, 0, 1).After(cutoff) {
			removed, err := dropExpiredPartition(ctx, pool, parent, n, day.AddDate(0, 0, 1), cutoff)
			if err != nil {
				return dropped, err
			}
			if removed {
				dropped++
			}
		}
	}
	return dropped, nil
}

// A flow partition is expired only behind the successfully folded watermark.
// Hold the same state lock as ingest/refold while checking and dropping it.
func dropExpiredPartition(ctx context.Context, pool *pgxpool.Pool, parent, child string, upper, cutoff time.Time) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '500ms'"); err != nil {
		return false, err
	}
	if parent == "network_flows" {
		watermark, _, err := flowrollup.Lock(ctx, tx, true)
		if err != nil {
			return false, err
		}
		foldedCutoff := watermark.UTC().Add(-time.Hour).Truncate(time.Hour)
		if foldedCutoff.Before(cutoff) {
			cutoff = foldedCutoff
		}
		if upper.After(cutoff) {
			return false, nil
		}
	}
	// Catalog-derived regclass text is quoted by PostgreSQL. Verify attachment
	// under the lock so an independently detached table is never removed.
	if _, err := tx.Exec(ctx, "LOCK TABLE "+child+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return false, err
	}
	var attached, hasCurrent bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_inherits WHERE inhparent=to_regclass($1) AND inhrelid=to_regclass($2))`, parent, child).Scan(&attached); err != nil {
		return false, err
	}
	if !attached {
		return false, nil
	}
	// A date-shaped name alone is not proof of its actual partition bounds.
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+child+" WHERE at >= $1)", cutoff).Scan(&hasCurrent); err != nil {
		return false, err
	}
	if hasCurrent {
		return false, nil
	}
	if _, err := tx.Exec(ctx, "DROP TABLE "+child); err != nil {
		return false, err
	}
	if parent == "network_flows" {
		if _, err := tx.Exec(ctx, `UPDATE network_flow_rollup_state SET raw_pruned_before=GREATEST(raw_pruned_before,$1) WHERE id=true`, cutoff); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func partitionName(parent string, day time.Time) string {
	return parent + "_" + day.Format("20060102")
}

// partitionDay extracts the YYYYMMDD day a managed daily partition covers from its name.
// Returns ok=false for the default partition or any child not named <parent>_YYYYMMDD.
func partitionDay(name string) (time.Time, bool) {
	m := partitionNameRe.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	d, err := time.Parse("20060102", m[1])
	if err != nil {
		return time.Time{}, false
	}
	return d.UTC(), true
}
