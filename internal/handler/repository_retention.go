package handler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

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
	if !cfg.Enabled || cfg.MaxAge <= 0 {
		return out, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	out.Cutoff = now.Add(-cfg.MaxAge)

	tx, err := pool.Begin(ctx)
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

	if err := tx.QueryRow(ctx, repositoryRetentionDeleteSQL, out.Cutoff, cfg.BatchSize, now).Scan(
		&out.Candidates,
		&out.DeletedFindings,
		&out.DeletedAssets,
		&out.PrunedTargets,
	); err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
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
       AND NOT EXISTS (
            SELECT 1
              FROM scan_result_attestations sra
              JOIN scan_attestation_verifications sav
                ON sav.attestation_id = sra.id
               AND sav.org_id = sra.org_id
             WHERE sra.org_id = st.org_id
               AND sra.scan_target_id = st.id
       )
       AND NOT EXISTS (
            SELECT 1
              FROM scan_result_attestations trusted
             WHERE trusted.org_id = st.org_id
               AND trusted.scan_target_id = st.id
               AND trusted.trusted
               AND (trusted.expires_at IS NULL OR trusted.expires_at > $3)
       )
     ORDER BY st.last_seen_at ASC, st.id ASC
     LIMIT $2`

const repositoryRetentionCandidateCountSQL = `
WITH candidate AS (` + repositoryRetentionEligibleSQL + `)
SELECT COUNT(*)::int FROM candidate`

const repositoryRetentionDeleteSQL = `
WITH candidate AS MATERIALIZED (` + repositoryRetentionEligibleSQL + ` FOR UPDATE SKIP LOCKED),
deleted_findings AS (
    DELETE FROM findings f
     USING candidate c
     WHERE f.org_id = c.org_id
       AND f.scan_target_id = c.id
 RETURNING f.id
),
deleted_assets AS (
    DELETE FROM assets a
     USING candidate c
     WHERE a.org_id = c.org_id
       AND a.kind = 'repository'
       AND a.digest = 'scan-target:' || c.id::text
 RETURNING a.id
),
deleted_targets AS (
    DELETE FROM scan_targets st
     USING candidate c
     WHERE st.id = c.id
 RETURNING st.id
)
SELECT (SELECT COUNT(*)::int FROM candidate),
       (SELECT COUNT(*)::int FROM deleted_findings),
       (SELECT COUNT(*)::int FROM deleted_assets),
       (SELECT COUNT(*)::int FROM deleted_targets)`
