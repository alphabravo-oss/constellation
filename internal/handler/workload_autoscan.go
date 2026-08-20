package handler

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnqueueClusterImageScans queues a scan job for each distinct image of the cluster's
// currently-running workloads (the discoverer's live inventory), skipping images that
// already have a pending/running job or were scanned within `rescanWithin`. It is the
// shared core of the manual cross-scan (POST /clusters/{id}/cross-scan) and the
// auto-scan loop below. requestedBy may be nil (system-initiated). Returns
// (imagesSeen, enqueued).
func EnqueueClusterImageScans(ctx context.Context, pool *pgxpool.Pool, orgID, clusterID uuid.UUID, requestedBy *uuid.UUID, rescanWithin time.Duration) (int, int, error) {
	rows, err := pool.Query(ctx, `
SELECT img.ref, COALESCE(MAX(l.image_digest), '') AS image_digest
  FROM deployments d
 CROSS JOIN LATERAL unnest(d.image_refs) AS img(ref)
  LEFT JOIN image_workload_links l
    ON l.org_id = d.org_id AND l.cluster_id = d.cluster_id
   AND l.image_ref = img.ref AND l.image_digest IS NOT NULL
 WHERE d.org_id = $1 AND d.cluster_id = $2 AND img.ref <> ''
 GROUP BY img.ref
 ORDER BY img.ref`, orgID, clusterID)
	if err != nil {
		return 0, 0, err
	}
	type img struct{ ref, digest string }
	var images []img
	for rows.Next() {
		var i img
		if err := rows.Scan(&i.ref, &i.digest); err != nil {
			rows.Close()
			return 0, 0, err
		}
		images = append(images, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	enqueued := 0
	for _, i := range images {
		target, err := upsertScanTarget(ctx, pool, nil, orgID, scanTargetUpsert{
			TargetType:      "image",
			TargetRef:       i.ref,
			TargetClusterID: &clusterID,
			SourceType:      "discoverer",
			SourceRef:       clusterID.String(),
			ImageRef:        i.ref,
			ImageDigest:     i.digest,
		})
		if err != nil {
			return len(images), enqueued, err
		}
		// Skip if a job for this target is already in flight, or was attempted within
		// the rescan window (success OR failure — don't hammer an image that can't scan).
		var skip bool
		if err := pool.QueryRow(ctx, `
SELECT EXISTS(
  SELECT 1 FROM scan_jobs
   WHERE org_id = $1 AND target_id = $2
     AND (status IN ('pending','running','paused')
          OR requested_at > now() - $3::interval))`,
			orgID, target.ID, rescanWithin.String()).Scan(&skip); err != nil {
			return len(images), enqueued, err
		}
		if skip {
			continue
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, requested_by, enqueue_reason)
VALUES (gen_random_uuid(), $1, $2, 'pending', $3, 'auto-scan')`,
			orgID, target.ID, requestedBy); err != nil {
			return len(images), enqueued, err
		}
		enqueued++
	}
	return len(images), enqueued, nil
}

// RunWorkloadAutoScan periodically scans the images of running workloads across all
// clusters — NeuVector's `enable_auto_scan_workload`. It closes the "discovery ≠
// scanning" gap: the discoverer inventories running workloads, and this loop makes sure
// each running image gets (re)scanned by the live Trivy/Grype pipeline without a manual
// trigger. Leader-gated. `enabled` and `rescanHours` are read live from system config so
// the toggle + cadence are UI-adjustable.
func RunWorkloadAutoScan(ctx context.Context, pool *pgxpool.Pool, enabled func(ctx context.Context) bool, rescanHours func(ctx context.Context) int, logger *slog.Logger) {
	if pool == nil {
		return
	}
	const interval = 30 * time.Minute
	run := func() {
		if !enabled(ctx) {
			return
		}
		hrs := rescanHours(ctx)
		if hrs <= 0 {
			hrs = 24
		}
		within := time.Duration(hrs) * time.Hour
		rows, err := pool.Query(ctx, `SELECT id, org_id FROM clusters WHERE state = 'connected'`)
		if err != nil {
			if logger != nil {
				logger.Warn("auto-scan: list clusters", slog.String("err", err.Error()))
			}
			return
		}
		type cl struct{ id, org uuid.UUID }
		var clusters []cl
		for rows.Next() {
			var c cl
			if err := rows.Scan(&c.id, &c.org); err == nil {
				clusters = append(clusters, c)
			}
		}
		rows.Close()
		total := 0
		for _, c := range clusters {
			_, enq, err := EnqueueClusterImageScans(ctx, pool, c.org, c.id, nil, within)
			if err != nil {
				if logger != nil {
					logger.Warn("auto-scan: enqueue", slog.String("cluster", c.id.String()), slog.String("err", err.Error()))
				}
				continue
			}
			total += enq
		}
		if total > 0 && logger != nil {
			logger.Info("auto-scan: enqueued workload image scans", slog.Int("jobs", total), slog.Int("clusters", len(clusters)))
		}
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
