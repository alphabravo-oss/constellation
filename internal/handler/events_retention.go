package handler

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunEventsRetentionMonitor prunes rows from the (partitioned) events table older
// than the runtime-configured horizon. The horizon is read LIVE each pass from
// system config via `retention` (0 = disabled), so an admin can set it from the UI
// without a restart. Deletes are batched so a large backlog is worked off across
// cycles instead of one long lock.
//
// ponytail: batched ctid DELETE, matching the network_flows pruner. events is
// partitioned by time, so DROP-partition is the eventual cheap upgrade once the
// ingest side rotates partitions.
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
// useful (live jobs and image_scan_results are never touched). scan_jobs is not
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
			secs := strconv.FormatInt(int64(horizon/time.Second), 10)
			tag, err := pool.Exec(ctx, `
DELETE FROM scan_jobs
 WHERE ctid IN (
     SELECT ctid FROM scan_jobs
      WHERE status IN ('completed','failed','canceled')
        AND finished_at IS NOT NULL
        AND finished_at < now() - ($1::text || ' seconds')::interval
      LIMIT $2
 )`, secs, batchSize)
			if err != nil {
				if logger != nil {
					logger.Warn("scan_jobs retention prune", slog.String("err", err.Error()))
				}
				continue
			}
			if n := tag.RowsAffected(); n > 0 && logger != nil {
				logger.Info("scan_jobs retention prune", slog.Int64("deleted", n), slog.String("horizon", horizon.String()))
			}
		}
	}
}

func pruneEventsOnce(ctx context.Context, pool *pgxpool.Pool, retention time.Duration, batch int64) (int64, error) {
	secs := strconv.FormatInt(int64(retention/time.Second), 10)
	tag, err := pool.Exec(ctx, `
DELETE FROM events
 WHERE ctid IN (
     SELECT ctid FROM events
      WHERE at < now() - ($1::text || ' seconds')::interval
      LIMIT $2
 )`, secs, batch)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RunOrphanImageScanResultMonitor prunes node-local evidence scan results that are
// digest-only (no resolved repo:tag) AND no longer back any running workload (absent
// from image_workload_links). The evidence path scans each RUNNING container by its
// image digest and writes one image_scan_result per container; when the container is
// gone the result orphans, keyed by an unnamed sha256. Left unchecked these pile up
// and inflate the CVE affected-images list far past what is actually running —
// NeuVector does not retain scan data for dead containers. Named registry scans keep
// a repository and are never touched. image_scan_findings cascade-delete with the row.
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
		for {
			tag, err := pool.Exec(ctx, `
DELETE FROM image_scan_results r
 WHERE r.ctid IN (
     SELECT r2.ctid FROM image_scan_results r2
      WHERE (COALESCE(r2.image_repository,'') = '' OR r2.image_ref ~ '^sha256:')
        AND r2.last_scanned_at < now() - interval '6 hours'
        AND (
            -- (a) orphaned: no longer backing any running workload
            NOT EXISTS (
                SELECT 1 FROM image_workload_links l
                 WHERE l.org_id = r2.org_id
                   AND (l.image_digest = r2.image_digest OR l.image_digest = r2.image_ref))
            -- (b) superseded: a NAMED result already covers the same image digest, so the
            -- nameless row is a stale duplicate (older scan under a different platform/
            -- profile the ingest upsert key didn't collapse). Drops the leftover sha rows
            -- that would otherwise sit next to the named image on its CVE page.
            OR EXISTS (
                SELECT 1 FROM image_scan_results n
                 WHERE n.org_id = r2.org_id AND n.id <> r2.id
                   AND COALESCE(n.image_repository,'') <> '' AND n.image_ref !~ '^sha256:'
                   AND n.image_digest = COALESCE(NULLIF(r2.image_digest,''), r2.image_ref))
        )
      LIMIT $1
 )`, batchSize)
			if err != nil {
				if logger != nil {
					logger.Warn("orphan image_scan_results prune", slog.String("err", err.Error()))
				}
				return
			}
			n := tag.RowsAffected()
			if n > 0 && logger != nil {
				logger.Info("orphan image_scan_results prune", slog.Int64("deleted", n))
			}
			if n < batchSize {
				return
			}
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
