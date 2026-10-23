package handler

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/scanretention"
)

// RunEventsRetentionMonitor prunes rows from the (partitioned) events table older
// than the runtime-configured horizon. The horizon is read LIVE each pass from
// system config via `retention` (0 = disabled), so an admin can set it from the UI
// without a restart. Deletes are batched so a large backlog is worked off across
// cycles instead of one long lock.
//
// The batched DELETE uses the partitioned table's (id, at) primary key. A ctid
// alone is only unique inside one child partition and can delete unrelated rows.
func RunEventsRetentionMonitor(ctx context.Context, pool *pgxpool.Pool, retention func(ctx context.Context) time.Duration, logger *slog.Logger) {
	if pool == nil || retention == nil {
		return
	}
	const (
		// Batches are frequent + sizeable so a large historical backlog (tens of
		// millions of rows in the legacy default partition) drains in hours, not days.
		// Steady-state passes after the backlog clears are near-empty and cheap.
		interval  = 2 * time.Minute
		batchSize = 100000
	)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			horizon := retention(ctx)
			if horizon <= 0 {
				continue // disabled
			}
			deleted, err := pruneEventsOnce(ctx, pool, horizon, batchSize)
			if err != nil {
				if logger != nil {
					logger.Warn("events retention prune", slog.String("err", err.Error()))
				}
				continue
			}
			if deleted > 0 && logger != nil {
				logger.Info("events retention prune",
					slog.Int64("deleted", deleted), slog.String("horizon", horizon.String()))
			}
		}
	}
}

// RunScanJobsRetentionMonitor prunes TERMINAL scan_jobs (completed / failed / canceled)
// older than the configured horizon. Mirrors NeuVector's stale-scan-job cleanup: the
// queue accumulates hundreds of thousands of finished jobs, but only recent history is
// useful. Live, latest and referenced jobs survive. scan_jobs is not
// partitioned, so this is a batched DELETE; autovacuum reclaims the (small) space.
func RunScanJobsRetentionMonitor(ctx context.Context, pool *pgxpool.Pool, retention func(ctx context.Context) time.Duration, logger *slog.Logger) {
	if pool == nil || retention == nil {
		return
	}
	const (
		interval  = 30 * time.Minute
		batchSize = 20000
	)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			horizon := retention(ctx)
			if horizon <= 0 {
				continue
			}
			n, err := scanretention.PruneJobs(ctx, pool, horizon, batchSize)
			if err != nil {
				if logger != nil {
					logger.Warn("scan_jobs retention prune", slog.String("err", err.Error()))
				}
				continue
			}
			if n > 0 && logger != nil {
				logger.Info("scan_jobs retention prune", slog.Int64("deleted", n), slog.String("horizon", horizon.String()))
			}
		}
	}
}

func pruneEventsOnce(ctx context.Context, pool *pgxpool.Pool, retention time.Duration, batch int64) (int64, error) {
	if retention <= 0 || batch <= 0 {
		return 0, nil
	}
	secs := strconv.FormatInt(int64(retention/time.Second), 10)
	tag, err := pool.Exec(ctx, `
DELETE FROM events
 WHERE (id, at) IN (
     SELECT id, at FROM events
      WHERE at < now() - ($1::text || ' seconds')::interval
      ORDER BY at, id
      LIMIT $2
      FOR UPDATE SKIP LOCKED
 )`, secs, batch)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RunOrphanImageScanResultMonitor prunes node-local evidence scan results that are
// digest-only (no resolved repo:tag), have a newer result for the same image,
// and no longer back any running workload (absent
// from image_workload_links). The evidence path scans each RUNNING container by its
// image digest and writes one image_scan_result per container; when the container is
// gone the result orphans, keyed by an unnamed sha256. Left unchecked these pile up
// and inflate the CVE affected-images list far past what is actually running —
// NeuVector does not retain scan data for dead containers. Named registry scans keep
// a repository and are never touched. Referenced results and findings survive.
//
// The first pass runs immediately on start so a deploy cleans the backlog without
// waiting a full interval. A short grace window spares a just-scanned image whose
// discovery link hasn't landed yet.
func RunOrphanImageScanResultMonitor(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	if pool == nil {
		return
	}
	const (
		interval  = 30 * time.Minute
		batchSize = 5000
	)
	prune := func() {
		n, err := scanretention.PruneOrphanResults(ctx, pool, batchSize)
		if err != nil && logger != nil {
			logger.Warn("orphan image_scan_results prune", slog.String("err", err.Error()))
		} else if n > 0 && logger != nil {
			logger.Info("orphan image_scan_results prune", slog.Int64("deleted", n))
		}
	}
	prune() // immediate first pass on start
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}
