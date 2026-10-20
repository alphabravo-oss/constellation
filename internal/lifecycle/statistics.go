package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Transaction-scoped coordination also protects installations without API leases.
const partitionStatisticsLock int64 = 0x435354415453

type StatisticsRefresh struct {
	LastAnalyze map[string]time.Time
	Analyzed    string
}

// RefreshPartitionStatistics analyzes at most one stale partitioned parent in
// the application's schema. PostgreSQL autovacuum does not analyze parents.
// Fixed SQL targets, short lock waits, a 25-second statement budget and a 2 MiB
// buffer ring keep this separate from unbounded or database-wide maintenance.
func RefreshPartitionStatistics(ctx context.Context, pool *pgxpool.Pool) (StatisticsRefresh, error) {
	result := StatisticsRefresh{LastAnalyze: make(map[string]time.Time)}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout='25s'; SET LOCAL lock_timeout='1s'"); err != nil {
		return result, err
	}
	var locked bool
	if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", partitionStatisticsLock).Scan(&locked); err != nil || !locked {
		return result, err
	}
	target, allowed, err := readPartitionStatistics(ctx, tx, result.LastAnalyze)
	if err != nil || target == "" {
		return result, err
	}
	if !allowed {
		return result, errors.New("partition statistics maintenance requires table or database ownership")
	}
	lockSQL, analyzeSQL, err := partitionStatisticsSQL(target)
	if err != nil {
		return result, err
	}
	// ANALYZE SKIP_LOCKED alone reports success when it skips a locked parent.
	// Acquire the parent lock explicitly so a skipped parent cannot count as fresh.
	if _, err := tx.Exec(ctx, lockSQL); err != nil {
		return result, fmt.Errorf("lock statistics parent %s: %w", target, err)
	}
	if _, err := tx.Exec(ctx, analyzeSQL); err != nil {
		return result, fmt.Errorf("analyze parent %s: %w", target, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	result.Analyzed = target
	result.LastAnalyze[target] = time.Now()
	return result, nil
}

func partitionStatisticsSQL(table string) (string, string, error) {
	switch table {
	case "network_flows":
		return "LOCK TABLE ONLY network_flows IN SHARE UPDATE EXCLUSIVE MODE NOWAIT", "ANALYZE (SKIP_LOCKED, BUFFER_USAGE_LIMIT '2MB') network_flows", nil
	case "events":
		return "LOCK TABLE ONLY events IN SHARE UPDATE EXCLUSIVE MODE NOWAIT", "ANALYZE (SKIP_LOCKED, BUFFER_USAGE_LIMIT '2MB') events", nil
	case "findings":
		return "LOCK TABLE ONLY findings IN SHARE UPDATE EXCLUSIVE MODE NOWAIT", "ANALYZE (SKIP_LOCKED, BUFFER_USAGE_LIMIT '2MB') findings", nil
	default:
		return "", "", errors.New("unknown statistics maintenance target")
	}
}

// RunPartitionStatistics refreshes at most one stale parent every five minutes;
// each parent is due only after one hour. The API leader owns this loop.
func RunPartitionStatistics(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, metrics *StatisticsMetrics) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		started := time.Now()
		result, err := RefreshPartitionStatistics(ctx, pool)
		metrics.Record(result, time.Since(started), err)
		if logger != nil {
			if err != nil {
				logger.Warn("partition statistics maintenance failed", "error", err)
			} else if result.Analyzed != "" {
				logger.Info("partition statistics refreshed", "table", result.Analyzed, "duration", time.Since(started))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func readPartitionStatistics(ctx context.Context, tx pgx.Tx, lastAnalyze map[string]time.Time) (string, bool, error) {
	rows, err := tx.Query(ctx, `SELECT c.relname, s.last_analyze,
 COALESCE(s.last_analyze < clock_timestamp() - interval '1 hour', true),
 pg_has_role(c.relowner, 'USAGE') OR EXISTS (
   SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND pg_has_role(d.datdba, 'USAGE'))
 FROM pg_class c
 LEFT JOIN pg_stat_all_tables s ON s.relid=c.oid
 WHERE c.relkind='p'
 AND c.oid IN (to_regclass('network_flows'),to_regclass('events'),to_regclass('findings'))
 ORDER BY s.last_analyze NULLS FIRST, c.relname`)
	if err != nil {
		return "", false, err
	}
	var target string
	var allowed bool
	for rows.Next() {
		var table string
		var last pgtype.Timestamptz
		var due, owner bool
		if err := rows.Scan(&table, &last, &due, &owner); err != nil {
			rows.Close()
			return "", false, err
		}
		lastAnalyze[table] = last.Time
		if target == "" && due {
			target, allowed = table, owner
		}
	}
	rows.Close()
	return target, allowed, rows.Err()
}
