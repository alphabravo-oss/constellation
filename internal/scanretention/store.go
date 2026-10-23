// Package scanretention expires replaceable scan history while preserving evidence references.
package scanretention

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const jobReferences = `
 NOT EXISTS (SELECT 1 FROM scan_result_attestations a WHERE a.scan_job_id=j.id)
 AND NOT EXISTS (SELECT 1 FROM image_scan_results r WHERE r.last_scan_job_id=j.id)
 AND EXISTS (SELECT 1 FROM scan_jobs newer WHERE newer.org_id=j.org_id AND newer.target_id=j.target_id
  AND newer.status IN ('completed','failed','canceled')
  AND newer.finished_at IS NOT NULL AND (newer.finished_at,newer.id)>(j.finished_at,j.id))`

// PruneJobs preserves current and referenced jobs regardless of age. The newest
// completed history per target remains available even when the target is idle.
func PruneJobs(ctx context.Context, pool *pgxpool.Pool, horizon time.Duration, batch int) (int64, error) {
	if horizon <= 0 {
		return 0, nil
	}
	return pruneLocked(ctx, pool, `SELECT j.id FROM scan_jobs j WHERE j.status IN ('completed','failed','canceled')
 AND j.finished_at<$1 AND `+jobReferences+` ORDER BY j.finished_at,j.id LIMIT $2 FOR UPDATE OF j SKIP LOCKED`,
		`DELETE FROM scan_jobs j WHERE j.id=ANY($1::uuid[]) AND `+jobReferences, time.Now().Add(-horizon), batch)
}

const resultReferences = `
 EXISTS (SELECT 1 FROM image_scan_results newer WHERE newer.org_id=r.org_id
  AND newer.image_digest=r.image_digest AND newer.platform=r.platform AND newer.scanner_profile=r.scanner_profile
  AND (newer.last_scanned_at,newer.id)>(r.last_scanned_at,r.id)) AND
 NOT EXISTS (SELECT 1 FROM scan_result_attestations a WHERE a.image_scan_result_id=r.id)
 AND NOT EXISTS (SELECT 1 FROM image_scan_findings f WHERE f.image_scan_result_id=r.id)
 AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.scan_target_id=r.scan_target_id)
 AND NOT EXISTS (SELECT 1 FROM image_workload_links l WHERE l.org_id=r.org_id
  AND (l.image_digest=r.image_digest OR l.image_digest=r.image_ref))
 AND (r.scan_target_id IS NULL OR EXISTS (SELECT 1 FROM image_scan_results newer
  WHERE newer.org_id=r.org_id AND newer.scan_target_id=r.scan_target_id
  AND newer.platform=r.platform AND newer.scanner_profile=r.scanner_profile
  AND (newer.last_scanned_at,newer.id)>(r.last_scanned_at,r.id)))`

// PruneOrphanResults removes one bounded batch of old unnamed cache records.
// Named results, current target results, findings and all attestations survive.
func PruneOrphanResults(ctx context.Context, pool *pgxpool.Pool, batch int) (int64, error) {
	return pruneLocked(ctx, pool, `SELECT r.id FROM image_scan_results r
 WHERE (COALESCE(r.image_repository,'')='' OR r.image_ref ~ '^sha256:')
 AND r.last_scanned_at<$1 AND `+resultReferences+`
 ORDER BY r.last_scanned_at,r.id LIMIT $2 FOR UPDATE OF r SKIP LOCKED`,
		`DELETE FROM image_scan_results r WHERE r.id=ANY($1::uuid[]) AND `+resultReferences, time.Now().Add(-6*time.Hour), batch)
}

// Separate statements are deliberate: after locking parent rows, READ COMMITTED
// takes a fresh snapshot for the reference check. A reference that committed
// while the initial candidate query ran must not be lost to ON DELETE SET NULL.
// FK key-share locks prevent new references while the locked deletion commits.
func pruneLocked(ctx context.Context, pool *pgxpool.Pool, selectSQL, deleteSQL string, cutoff time.Time, batch int) (int64, error) {
	if batch < 1 || batch > 20000 {
		return 0, fmt.Errorf("scan retention batch must be between 1 and 20000")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, err
	}
	defer func() {
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelCleanup()
		_ = tx.Rollback(cleanup)
	}()
	rows, err := tx.Query(ctx, selectSQL, cutoff, batch)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, deleteSQL, ids)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
