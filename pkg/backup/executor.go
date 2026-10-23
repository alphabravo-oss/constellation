package backup

// Scheduled-backup executor + retention (roadmap A9).
//
// The backup schedule schema/API (migration 037, internal/handler/backup.go) let an
// operator persist a per-org cron + S3 destination, but nothing ever RAN those schedules.
// This file is the missing cron runner: a leader-gated background loop (wired into
// internal/server/leaderelection.go's startSingletonLoops) that periodically:
//
//  1. reads enabled backup_schedules,
//  2. runs a fresh org-backup for any schedule whose next_run_at is due,
//  3. applies retention (prunes old succeeded backups + their local artifacts),
//  4. records the outcome back onto the schedule row (last_run_at/last_status/next_run_at).
//
// SAFETY / no-op default: the loop only ever touches schedules an operator explicitly
// created (PutSchedule inserts the row). With no schedules the loop is a pure no-op. It
// never enables, deletes, or enforces anything on live workloads — it only reads org data
// into a tarball and prunes its OWN historical backup artifacts.
//
// The due-calculation and retention-victim selection are pure functions (isDue,
// retentionVictims) so they can be unit-tested without a database.

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"
)

// ScheduleExecutorConfig configures the background schedule runner. Zero values are
// replaced with safe defaults by normalize().
type ScheduleExecutorConfig struct {
	// Interval is how often the loop wakes to check for due schedules. Default 1m.
	Interval time.Duration
	// BackupDir is where artifacts are written (mirrors the HTTP handler's dir).
	BackupDir string
	// SignKeyPath is the PEM ed25519 key used when a schedule's sign_mode=static-key.
	SignKeyPath string
	// DefaultKeepLast is a fallback protected-copy count used only when a schedule leaves
	// retention_keep_last NULL/0 AND CONSTELLATION_BACKUP_DEFAULT_KEEP_LAST is set. Left
	// 0 (the default) retention is fully opt-in per schedule.
	DefaultKeepLast int
	// Clock override for tests. Defaults to time.Now.
	now func() time.Time
}

func (c *ScheduleExecutorConfig) normalize() {
	if c.Interval <= 0 {
		c.Interval = time.Minute
	}
	if c.BackupDir == "" {
		c.BackupDir = "/var/lib/constellation/backups"
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// schedule is the in-memory view of a backup_schedules row the executor cares about.
type schedule struct {
	OrgID           uuid.UUID
	OrgName         string
	CronExpr        string
	Enabled         bool
	S3Bucket        string
	S3Prefix        string
	S3Endpoint      string
	SignMode        string
	NextRunAt       *time.Time
	RetentionKeep   int // 0 = disabled
	RetentionMaxAge int // days, 0 = disabled
}

// isDue reports whether a schedule should fire at now. A schedule with no computed
// next_run_at is NOT fired immediately — it is bootstrapped (next_run_at initialized)
// on the first pass so creating a schedule never triggers a surprise backup mid-request.
func isDue(s schedule, now time.Time) bool {
	if !s.Enabled {
		return false
	}
	if s.NextRunAt == nil {
		return false
	}
	return !now.Before(*s.NextRunAt)
}

// backupRecord is the minimal view of a backups row used for retention selection.
type backupRecord struct {
	ID        uuid.UUID
	StartedAt time.Time
	LocalPath string
}

// retentionVictims keeps at least the newest successful backup, and never lets
// max age override an explicit keep-last floor. Zero rules retain everything.
func retentionVictims(recs []backupRecord, keepLast, maxAgeDays int, now time.Time) []backupRecord {
	if keepLast <= 0 && maxAgeDays <= 0 {
		return nil
	}
	// Copy + sort newest-first so "keep last N" is deterministic.
	sorted := make([]backupRecord, len(recs))
	copy(sorted, recs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].StartedAt.Equal(sorted[j].StartedAt) {
			return sorted[i].ID.String() > sorted[j].ID.String()
		}
		return sorted[i].StartedAt.After(sorted[j].StartedAt)
	})
	var cutoff time.Time
	if maxAgeDays > 0 {
		cutoff = now.Add(-time.Duration(maxAgeDays) * 24 * time.Hour)
	}
	var victims []backupRecord
	for i, r := range sorted {
		if i < max(1, keepLast) {
			continue
		}
		overCount := keepLast > 0 && i >= keepLast
		tooOld := maxAgeDays > 0 && r.StartedAt.Before(cutoff)
		if overCount || tooOld {
			victims = append(victims, r)
		}
	}
	return victims
}

// RunScheduleExecutor blocks until ctx is done, periodically running due backup
// schedules and applying retention. It is safe to run under leader election (all state
// lives in Postgres; a single leader owns the loop). With no schedule rows it is a no-op.
func RunScheduleExecutor(ctx context.Context, pool *pgxpool.Pool, cfg ScheduleExecutorConfig, logger *slog.Logger) {
	configuredDir := cfg.BackupDir
	cfg.normalize()
	if pool == nil {
		return
	}
	dir, err := ManagedArtifactDir(configuredDir)
	if err != nil {
		if logger != nil {
			logger.Error("backup executor: artifact directory unavailable", slog.String("err", err.Error()))
		}
		return
	}
	cfg.BackupDir = dir
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickSchedules(ctx, pool, cfg, logger)
		}
	}
}

// tickSchedules processes one pass over the schedule table.
func tickSchedules(ctx context.Context, pool *pgxpool.Pool, cfg ScheduleExecutorConfig, logger *slog.Logger) {
	now := cfg.now().UTC()
	scheds, err := loadSchedules(ctx, pool)
	if err != nil {
		if logger != nil {
			logger.Warn("backup executor: load schedules failed", slog.String("err", err.Error()))
		}
		return
	}
	for _, s := range scheds {
		if !s.Enabled {
			continue
		}
		// Bootstrap: a schedule with no next_run_at gets one computed but does NOT fire
		// this pass (avoids an immediate backup the instant a schedule is created).
		if s.NextRunAt == nil {
			next, nerr := NextBackupRun(s.CronExpr, now)
			if nerr != nil {
				recordScheduleError(ctx, pool, s.OrgID, "invalid cron: "+nerr.Error())
				continue
			}
			_, _ = pool.Exec(ctx, `UPDATE backup_schedules SET next_run_at=$2, updated_at=NOW() WHERE org_id=$1`, s.OrgID, next)
			continue
		}
		if !isDue(s, now) {
			continue
		}
		runScheduledBackup(ctx, pool, cfg, s, now, logger)
	}
}

// runScheduledBackup performs one org-backup for a due schedule, then applies retention
// and advances next_run_at. Failures are recorded on the schedule row, not fatal.
func runScheduledBackup(ctx context.Context, pool *pgxpool.Pool, cfg ScheduleExecutorConfig, s schedule, now time.Time, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	id := uuid.New()
	mode, signingErr := ResolveSignMode(s.SignMode, SignModeStaticKey)
	signed := signingErr == nil && mode != SignModeNone
	if _, err := pool.Exec(ctx, `
INSERT INTO backups (id, org_id, mode, status, started_at, signed, format_version)
VALUES ($1, $2, 'org-backup', 'running', NOW(), $3, $4)`, id, s.OrgID, signed, FormatVersion); err != nil {
		if logger != nil {
			logger.Warn("backup executor: insert row failed", slog.String("org", s.OrgID.String()), slog.String("err", err.Error()))
		}
		return
	}

	if signingErr != nil {
		_, _ = pool.Exec(ctx, `UPDATE backups SET status='failed',error=$2,finished_at=NOW() WHERE id=$1`, id, signingErr.Error())
		recordScheduleRun(ctx, pool, s, now, "failed", signingErr.Error())
		return
	}

	fname := ArtifactName(s.OrgName, id, now)
	path := filepath.Join(cfg.BackupDir, fname)

	destination, destinationErr := scheduleDestination(s, fname)
	if destinationErr != nil {
		_, _ = pool.Exec(ctx, `UPDATE backups SET status='failed',error=$2,finished_at=NOW() WHERE id=$1`, id, destinationErr.Error())
		recordScheduleRun(ctx, pool, s, now, "failed", destinationErr.Error())
		return
	}
	opts := ExportOptions{
		OrgID:          s.OrgID.String(),
		OrgName:        s.OrgName,
		GeneratedBy:    "backup-scheduler",
		SourceInstance: "constellation-api",
	}
	opts.Sign.Mode = mode
	if mode == SignModeStaticKey {
		opts.Sign.KeyPath = cfg.SignKeyPath
	}

	res, err := ExportManaged(ctx, pool, cfg.BackupDir, fname, opts)
	if err != nil {
		recordScheduledFailure(ctx, pool, s, id, now, "export: "+err.Error(), "", 0)
		if logger != nil {
			logger.Warn("backup executor: export failed", slog.String("org", s.OrgID.String()), slog.String("err", err.Error()))
		}
		return
	}

	checksum := ""
	if destination != "" {
		checksum, err = uploadScheduledArtifact(ctx, destination, s.S3Endpoint, path, res.Bytes)
		if err != nil {
			recordScheduledFailure(ctx, pool, s, id, now, err.Error(), path, res.Bytes)
			return
		}
	}
	tables := make([]string, 0, len(res.Manifest.Tables))
	for _, t := range res.Manifest.Tables {
		tables = append(tables, t.Name)
	}
	if _, err := pool.Exec(ctx, `
UPDATE backups
   SET status='succeeded', finished_at=NOW(), size_bytes=$2, signer_identity=$3,
       signed=$4, tables_included=$5, local_path=$6, format_version=$7, s3_uri=NULLIF($8,''), sha256=NULLIF($9,'')
 WHERE id=$1`, id, res.Bytes, res.SignerIdentity, res.SignMode != SignModeNone && res.SignMode != "",
		tables, path, FormatVersion, destination, checksum); err != nil {
		recordScheduleRun(ctx, pool, s, now, "failed", "update: "+err.Error())
		return
	}

	// Retention: prune old succeeded backups + their artifacts.
	keep := s.RetentionKeep
	if keep <= 0 {
		keep = cfg.DefaultKeepLast
	}
	pruned := applyRetention(ctx, pool, s.OrgID, keep, s.RetentionMaxAge, now, logger)

	recordScheduleRun(ctx, pool, s, now, "succeeded", "")
	if logger != nil {
		logger.Info("backup executor: scheduled backup complete",
			slog.String("org", s.OrgID.String()),
			slog.Int64("bytes", res.Bytes),
			slog.Int("tables", len(tables)),
			slog.Int("pruned", pruned))
	}
}

// Persist failure after a canceled upload/export without extending the operation
// itself. A bounded independent context prevents stranded running receipts.
func recordScheduledFailure(ctx context.Context, pool *pgxpool.Pool, s schedule, id uuid.UUID, now time.Time, message, path string, size int64) {
	finalize, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = pool.Exec(finalize, `UPDATE backups SET status='failed',error=$2,finished_at=NOW(),local_path=NULLIF($3,''),size_bytes=$4 WHERE id=$1 AND status='running'`, id, message, path, size)
	recordScheduleRun(finalize, pool, s, now, "failed", message)
}

// recordScheduleRun advances next_run_at and stamps last_* on the schedule row.
func recordScheduleRun(ctx context.Context, pool *pgxpool.Pool, s schedule, now time.Time, status, errMsg string) {
	next, err := NextBackupRun(s.CronExpr, now)
	var nextPtr *time.Time
	if err == nil {
		nextPtr = &next
	}
	_, _ = pool.Exec(ctx, `
UPDATE backup_schedules
   SET last_run_at=$2, last_status=$3, last_error=NULLIF($4,''), next_run_at=$5, updated_at=NOW()
 WHERE org_id=$1`, s.OrgID, now, status, errMsg, nextPtr)
}

func recordScheduleError(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, errMsg string) {
	_, _ = pool.Exec(ctx, `
UPDATE backup_schedules SET last_status='failed', last_error=$2, updated_at=NOW() WHERE org_id=$1`, orgID, errMsg)
}

// loadSchedules reads the enabled backup schedules joined with the org name.
func loadSchedules(ctx context.Context, pool *pgxpool.Pool) ([]schedule, error) {
	rows, err := pool.Query(ctx, `
SELECT bs.org_id, o.name, bs.cron_expr, bs.enabled, bs.sign_mode, bs.next_run_at,
       COALESCE(bs.retention_keep_last,0), COALESCE(bs.retention_max_age_days,0),
 COALESCE(bs.s3_bucket,''),COALESCE(bs.s3_prefix,''),COALESCE(bs.s3_endpoint,'')
  FROM backup_schedules bs
  JOIN orgs o ON o.id = bs.org_id
 WHERE bs.enabled = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []schedule
	for rows.Next() {
		var s schedule
		if err := rows.Scan(&s.OrgID, &s.OrgName, &s.CronExpr, &s.Enabled, &s.SignMode,
			&s.NextRunAt, &s.RetentionKeep, &s.RetentionMaxAge, &s.S3Bucket, &s.S3Prefix, &s.S3Endpoint); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// NextBackupRun computes the next fire time for a standard 5-field cron expression,
// evaluated in UTC. Mirrors compliance's NextRunFromCron; returns an error for a
// parseable-but-never-occurring spec so callers never persist a zero next_run_at.
func NextBackupRun(expr string, from time.Time) (time.Time, error) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := parser.Parse(expr)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse cron %q: %w", expr, err)
	}
	from = from.UTC()
	next := sched.Next(from)
	if next.IsZero() || !next.After(from) {
		return time.Time{}, fmt.Errorf("cron %q has no future occurrences", expr)
	}
	return next.UTC(), nil
}
