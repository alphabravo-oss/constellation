package handler

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"time"

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
// to the age-based retention DELETE loops (rollup.go / events_retention.go) and a
// one-time VACUUM FULL to reclaim; the default stops growing once the forward partitions
// exist, so it only ever drains.
type PartitionedTable struct {
	Parent        string                              // "events" | "network_flows"
	RetentionDays func(ctx context.Context) int       // live retention horizon (0 = keep forever → never drop)
}

// partitionNameRe matches a managed daily partition: <parent>_YYYYMMDD.
var partitionNameRe = regexp.MustCompile(`_(\d{8})$`)

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
	if retentionDays <= 0 {
		return 0, nil
	}
	// A partition for day D covers [D, D+1). It is fully expired once D+1 <= cutoff,
	// i.e. D < cutoff-1day. cutoff = midnight(today) - retentionDays.
	cutoff := time.Now().UTC().Truncate(24 * time.Hour).AddDate(0, 0, -retentionDays)

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
			if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, n)); err != nil {
				return dropped, fmt.Errorf("drop partition %s: %w", n, err)
			}
			dropped++
		}
	}
	return dropped, nil
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
