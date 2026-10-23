package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const retentionBatch = 100

// applyRetention preserves remote/failed receipts and the configured local copy
// floor. It holds deletion if a protected artifact is missing, empty or unsafe.
// File availability is not cryptographic verification or a restore rehearsal.
func applyRetention(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, keepLast, maxAgeDays int, now time.Time, logger *slog.Logger) int {
	count, err := pruneLocalBackups(ctx, pool, orgID, keepLast, maxAgeDays, now, logger)
	if err != nil && logger != nil {
		logger.Warn("backup executor: retention held", slog.String("err", err.Error()))
	}
	return count
}

func pruneLocalBackups(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, keepLast, maxAgeDays int, now time.Time, logger *slog.Logger) (int, error) {
	if keepLast <= 0 && maxAgeDays <= 0 {
		return 0, nil
	}
	if keepLast < 0 || keepLast > 10000 || maxAgeDays < 0 || maxAgeDays > 36500 {
		return 0, errors.New("backup retention policy exceeds bounded maintenance limits")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var acquired bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "backup-retention:"+orgID.String()).Scan(&acquired); err != nil || !acquired {
		return 0, err
	}
	protected, err := protectedBackups(ctx, tx, orgID, max(1, keepLast))
	if err != nil || len(protected) < max(1, keepLast) {
		return 0, err
	}
	if err = requireAvailableCopies(ctx, protected); err != nil {
		return 0, err
	}
	floor := protected[len(protected)-1]
	rows, err := tx.Query(ctx, `SELECT id,started_at,COALESCE(local_path,'') FROM backups
 WHERE org_id=$1 AND mode='org-backup' AND status='succeeded' AND COALESCE(s3_uri,'')=''
 AND (started_at,id)<($2,$3)
 ORDER BY started_at,id LIMIT $4 FOR UPDATE SKIP LOCKED`, orgID, floor.StartedAt, floor.ID, retentionBatch)
	if err != nil {
		return 0, err
	}
	candidates, err := pgx.CollectRows(rows, pgx.RowToStructByPos[backupRecord])
	if err != nil {
		return 0, err
	}
	victims := retentionVictims(append(protected, candidates...), keepLast, maxAgeDays, now)
	count, err := removeRetainedArtifacts(ctx, tx, orgID, victims, logger)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

func protectedBackups(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, count int) ([]backupRecord, error) {
	rows, err := tx.Query(ctx, `SELECT id,started_at,COALESCE(local_path,'') FROM backups
 WHERE org_id=$1 AND mode='org-backup' AND status='succeeded' AND COALESCE(s3_uri,'')=''
 ORDER BY started_at DESC,id DESC LIMIT $2 FOR UPDATE SKIP LOCKED`, orgID, count)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[backupRecord])
}

func requireAvailableCopies(ctx context.Context, records []backupRecord) error {
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.LocalPath == "" {
			return errors.New("protected local backup has no artifact path")
		}
		file, err := OpenArtifact(r.LocalPath)
		if err != nil {
			return errors.New("protected local backup artifact is unavailable")
		}
		info, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || info.Size() <= 0 {
			return errors.New("protected local backup artifact is unreadable or empty")
		}
	}
	return nil
}

// Row locks prevent catalog path/status changes during cleanup; application
// exports use unique paths. This does not serialize arbitrary external filesystem
// writers or make filesystem deletion and database commit atomic. A failed commit
// retains receipts for retry, and never removes the protected artifact floor.
func removeRetainedArtifacts(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, victims []backupRecord, logger *slog.Logger) (int, error) {
	count := 0
	for _, v := range victims {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if err := removeUnsharedArtifact(ctx, tx, v); err != nil {
			if logger != nil {
				logger.Warn("backup executor: artifact cleanup failed", slog.String("backup", v.ID.String()))
			}
			continue
		}
		tag, err := tx.Exec(ctx, `DELETE FROM backups WHERE id=$1 AND org_id=$2 AND status='succeeded' AND mode='org-backup' AND COALESCE(s3_uri,'')=''`, v.ID, orgID)
		if err != nil {
			return count, fmt.Errorf("delete retained backup receipt: %w", err)
		}
		count += int(tag.RowsAffected())
	}
	return count, nil
}

func removeUnsharedArtifact(ctx context.Context, tx pgx.Tx, v backupRecord) error {
	if v.LocalPath == "" {
		return nil
	}
	var shared bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM backups WHERE local_path=$1 AND id<>$2)`, v.LocalPath, v.ID).Scan(&shared); err != nil {
		return err
	}
	if shared {
		return nil
	}
	return RemoveArtifact(v.LocalPath)
}
