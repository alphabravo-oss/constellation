package flowrollup

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/syscfg"
)

// Prune expires a bounded batch only behind the known raw-history boundary.
// The same exclusive state lock is shared with forward/late folding and rebuilds.
func Prune(ctx context.Context, pool *pgxpool.Pool, batch int) (int64, error) {
	if batch < 1 || batch > 50000 {
		return 0, fmt.Errorf("rollup retention batch must be between 1 and 50000")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelCleanup()
		_ = tx.Rollback(cleanup)
	}()
	days, err := syscfg.EffectiveRetentionDays(ctx, tx, func(c syscfg.Config) int { return c.NetworkRollupRetentionDays })
	if err != nil || days == 0 {
		return 0, err
	}
	_, rawBoundary, err := Lock(ctx, tx, true)
	if err != nil {
		return 0, err
	}
	// Legacy fixtures/installations may explicitly mark no raw expiry at epoch.
	if !rawBoundary.After(time.Unix(0, 0)) {
		return 0, nil
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		return 0, err
	}
	cutoff := now.UTC().Add(-time.Duration(days) * 24 * time.Hour).Truncate(time.Hour)
	if rawBoundary.Before(cutoff) {
		cutoff = rawBoundary.UTC().Truncate(time.Hour)
	}
	// The boundary reports partial batches as unavailable too. It never rolls
	// backward when an operator increases the retention period after deletion.
	if _, err := tx.Exec(ctx, `UPDATE network_flow_rollup_state SET rollups_pruned_before=GREATEST(rollups_pruned_before,$1) WHERE id=true`, cutoff); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `WITH expired AS (SELECT tableoid,ctid FROM network_flow_rollups
 WHERE bucket<$1 ORDER BY bucket LIMIT $2 FOR UPDATE SKIP LOCKED)
 DELETE FROM network_flow_rollups r USING expired e WHERE r.tableoid=e.tableoid AND r.ctid=e.ctid`, cutoff, batch)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// AvailableFrom must be read after historical queries and before sending their
// results. If pruning committed during the read, the caller rejects partial data.
func AvailableFrom(ctx context.Context, pool *pgxpool.Pool) (time.Time, error) {
	var boundary time.Time
	err := pool.QueryRow(ctx, `SELECT rollups_pruned_before FROM network_flow_rollup_state WHERE id=true`).Scan(&boundary)
	return boundary, err
}

func RunRetention(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := Prune(ctx, pool, 5000)
		if err != nil {
			logger.Warn("rollup retention failed", "error", err)
		} else if n > 0 {
			logger.Info("rollup retention", "deleted", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
