package scanretention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RepositoryScanRetentionConfig struct {
	Enabled   bool
	MaxAge    time.Duration
	Interval  time.Duration
	BatchSize int
	DryRun    bool
}

type RepositoryScanRetentionResult struct {
	Enabled         bool      `json:"enabled"`
	DryRun          bool      `json:"dry_run"`
	LockAcquired    bool      `json:"lock_acquired"`
	Cutoff          time.Time `json:"cutoff"`
	Candidates      int       `json:"candidates"`
	PrunedTargets   int       `json:"pruned_targets"`
	DeletedFindings int       `json:"deleted_findings"`
	DeletedAssets   int       `json:"deleted_assets"`
}

func NormalizeRepositoryScanRetentionConfig(cfg RepositoryScanRetentionConfig) RepositoryScanRetentionConfig {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.Interval < 0 {
		cfg.Interval = 0
	}
	return cfg
}

func PruneRepositoryScansOnce(ctx context.Context, pool *pgxpool.Pool, cfg RepositoryScanRetentionConfig, now time.Time) (RepositoryScanRetentionResult, error) {
	cfg = NormalizeRepositoryScanRetentionConfig(cfg)
	out := RepositoryScanRetentionResult{
		Enabled: cfg.Enabled,
		DryRun:  cfg.DryRun,
	}
	if pool == nil {
		return out, fmt.Errorf("database pool required")
	}
	if cfg.BatchSize > 5000 {
		return out, fmt.Errorf("repository retention batch must not exceed 5000")
	}
	if !cfg.Enabled || cfg.MaxAge <= 0 {
		return out, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	out.Cutoff = now.Add(-cfg.MaxAge)

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('repository-scan-retention', 0))`).Scan(&out.LockAcquired); err != nil {
		return out, err
	}
	if !out.LockAcquired {
		return out, tx.Commit(ctx)
	}

	if cfg.DryRun {
		if err := tx.QueryRow(ctx, repositoryRetentionCandidateCountSQL, out.Cutoff, cfg.BatchSize, now).Scan(&out.Candidates); err != nil {
			return out, err
		}
		return out, tx.Commit(ctx)
	}

	// Lock targets first, then recheck all references using a fresh statement
	// snapshot. FK key-share locks serialize new findings/evidence against expiry.
	rows, err := tx.Query(ctx, repositoryRetentionEligibleSQL+` FOR UPDATE OF st SKIP LOCKED`, out.Cutoff, cfg.BatchSize, now)
	if err != nil {
		return out, err
	}
	ids, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (uuid.UUID, error) {
		var id, org uuid.UUID
		err := row.Scan(&id, &org)
		return id, err
	})
	if err != nil {
		return out, err
	}
	if err := lockRepositoryCascade(ctx, tx, ids); err != nil {
		return out, err
	}
	if err := tx.QueryRow(ctx, repositoryRetentionDeleteSQL, out.Cutoff, cfg.BatchSize, now, ids).Scan(&out.Candidates, &out.DeletedFindings, &out.DeletedAssets, &out.PrunedTargets); err != nil {
		return out, err
	}

	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

func lockRepositoryCascade(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) error {
	// Jobs can be referenced independently of the target by an attestation or
	// image result. Lock the cascade parents too before the final reference check.
	jobRows, err := tx.Query(ctx, `SELECT id FROM scan_jobs WHERE target_id=ANY($1::uuid[]) LIMIT 20001 FOR UPDATE`, ids)
	if err != nil {
		return err
	}
	jobs, err := pgx.CollectRows(jobRows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	if len(jobs) > 20000 {
		return fmt.Errorf("repository retention cascade exceeds job budget")
	}
	// Assets have their own finding FK. Lock them before the next snapshot so
	// a concurrent finding cannot be cascade-deleted by asset cleanup.
	assetRows, err := tx.Query(ctx, `SELECT a.id FROM assets a JOIN scan_targets st ON a.org_id=st.org_id
 AND a.digest='scan-target:'||st.id::text WHERE st.id=ANY($1::uuid[]) AND a.kind='repository' LIMIT 20001 FOR UPDATE OF a`, ids)
	if err != nil {
		return err
	}
	assets, err := pgx.CollectRows(assetRows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	if len(assets) > 20000 {
		return fmt.Errorf("repository retention cascade exceeds asset budget")
	}
	return nil
}

func RunRepositoryScanRetentionMonitor(ctx context.Context, pool *pgxpool.Pool, cfg RepositoryScanRetentionConfig, logger *slog.Logger) {
	cfg = NormalizeRepositoryScanRetentionConfig(cfg)
	if pool == nil || !cfg.Enabled || cfg.Interval <= 0 || cfg.MaxAge <= 0 {
		return
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			out, err := PruneRepositoryScansOnce(ctx, pool, cfg, time.Now())
			if err != nil {
				if logger != nil {
					logger.Warn("repository scan retention failed", slog.String("err", err.Error()))
				}
				continue
			}
			if logger != nil && out.LockAcquired && (out.PrunedTargets > 0 || out.Candidates > 0) {
				logger.Info("repository scan retention completed",
					slog.Bool("dry_run", out.DryRun),
					slog.Int("candidates", out.Candidates),
					slog.Int("pruned_targets", out.PrunedTargets),
					slog.Int("deleted_findings", out.DeletedFindings),
					slog.Int("deleted_assets", out.DeletedAssets),
				)
			}
		}
	}
}

const repositoryRetentionEligibleSQL = `
    SELECT st.id, st.org_id
      FROM scan_targets st
     WHERE st.type = 'repository'
       AND st.last_seen_at < $1
       AND NOT EXISTS (
            SELECT 1
              FROM scan_jobs active
             WHERE active.org_id = st.org_id
               AND active.target_id = st.id
               AND active.status IN ('pending', 'running', 'paused')
       )
       AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.scan_target_id=st.id)
       AND NOT EXISTS (SELECT 1 FROM scan_evidence e WHERE e.scan_target_id=st.id)
       AND NOT EXISTS (SELECT 1 FROM scan_result_attestations a WHERE a.scan_target_id=st.id)
       AND NOT EXISTS (SELECT 1 FROM image_scan_results r WHERE r.scan_target_id=st.id)
       AND NOT EXISTS (SELECT 1 FROM scan_jobs j JOIN image_scan_results r ON r.last_scan_job_id=j.id WHERE j.target_id=st.id)
       AND NOT EXISTS (SELECT 1 FROM scan_jobs j JOIN scan_result_attestations a ON a.scan_job_id=j.id WHERE j.target_id=st.id)
       AND st.last_seen_at <= $3
     ORDER BY st.last_seen_at ASC, st.id ASC
     LIMIT $2`

const repositoryRetentionCandidateCountSQL = `
WITH candidate AS (` + repositoryRetentionEligibleSQL + `)
SELECT COUNT(*)::int FROM candidate`

const repositoryRetentionDeleteSQL = `
WITH eligible AS (` + repositoryRetentionEligibleSQL + `),
candidate AS MATERIALIZED (SELECT * FROM eligible WHERE id=ANY($4::uuid[])),
deleted_assets AS (
    DELETE FROM assets a
     USING candidate c
     WHERE a.org_id = c.org_id
       AND a.kind = 'repository'
       AND a.digest = 'scan-target:' || c.id::text
       AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.asset_id=a.id)
 RETURNING a.id
),
deleted_targets AS (
    DELETE FROM scan_targets st
     USING candidate c
     WHERE st.id = c.id
 RETURNING st.id
)
SELECT (SELECT COUNT(*)::int FROM candidate),
       0::int,
       (SELECT COUNT(*)::int FROM deleted_assets),
       (SELECT COUNT(*)::int FROM deleted_targets)`
