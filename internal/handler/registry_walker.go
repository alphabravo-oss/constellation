package handler

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/registry"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// DefaultRegistryWalkerInterval is the global tick cadence used when no explicit
// interval is configured. It bounds how often auto-cadence registries re-sync and
// how finely periodic cadences are checked.
const DefaultRegistryWalkerInterval = 60 * time.Second

// DefaultRegistryWalkerConcurrency caps the number of registries synced in
// parallel within a single tick.
const DefaultRegistryWalkerConcurrency = 4

// RunRegistryWalker runs the periodic registry-rescan loop until ctx is canceled.
// It runs one tick immediately, then re-ticks every interval. This is the always-on
// scheduler that makes non-manual scan cadences (auto/hourly/6h/daily/weekly) actually
// fire; without it only the manual sync-now path ever runs. It is safe to run as a
// leader-gated singleton — each tick takes a pg_advisory_xact_lock per registry (via
// SyncOnce) so overlapping ticks or replicas never double-walk a registry.
func RunRegistryWalker(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, auditor *audit.Logger, concurrency int, interval time.Duration) {
	if concurrency < 1 {
		concurrency = DefaultRegistryWalkerConcurrency
	}
	if interval <= 0 {
		interval = DefaultRegistryWalkerInterval
	}
	logger.Info("registry walker starting",
		slog.Duration("interval", interval),
		slog.Int("concurrency", concurrency))

	if err := RegistryWalkerTick(ctx, pool, logger, auditor, concurrency, interval); err != nil {
		logger.Warn("registry walker first tick error", slog.String("err", err.Error()))
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("registry walker shutting down")
			return
		case <-t.C:
			if err := RegistryWalkerTick(ctx, pool, logger, auditor, concurrency, interval); err != nil {
				logger.Warn("registry walker tick error", slog.String("err", err.Error()))
			}
		}
	}
}

// walkerDueRow is one registry awaiting sync.
type walkerDueRow struct {
	id    uuid.UUID
	orgID uuid.UUID
	name  string
}

// RegistryWalkerTick selects rows whose per-registry schedule (manual/auto/periodic)
// is due relative to the global interval, then runs SyncOnce on each up to concurrency
// in parallel. Exported so the one-shot binary path and integration tests can drive a
// single tick.
func RegistryWalkerTick(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, auditor *audit.Logger, concurrency int, globalInterval time.Duration) error {
	due, err := listDueRegistries(ctx, pool, globalInterval)
	if err != nil {
		return fmt.Errorf("list due: %w", err)
	}
	if len(due) == 0 {
		return nil
	}
	logger.Info("registry walker tick", slog.Int("due", len(due)))

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, row := range due {
		row := row
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			walkerSyncOne(ctx, pool, logger, auditor, row)
		}()
	}
	wg.Wait()
	return nil
}

func walkerSyncOne(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, auditor *audit.Logger, row walkerDueRow) {
	res, err := SyncOnce(ctx, pool, logger, row.orgID, row.id)
	after := map[string]any{"registry_name": row.name}
	if res != nil {
		after["status"] = res.Status
		after["images_seen"] = res.ImagesSeen
		after["scan_jobs_enqueued"] = res.JobsEnqueued
		if res.Error != "" {
			after["error"] = res.Error
		}
	}
	if err != nil {
		after["fatal_error"] = err.Error()
		logger.Error("registry sync failed",
			slog.String("registry_id", row.id.String()),
			slog.String("err", err.Error()))
	}
	org := row.orgID
	_, _, _ = auditor.Log(ctx, audit.Event{
		OrgID:      &org,
		Action:     "registry.sync.walker",
		TargetKind: "registry",
		TargetID:   row.id.String(),
		After:      after,
	})
}

// listDueRegistries returns the registries whose per-registry schedule is due. The
// schedule mode (manual/auto/periodic) is derived from scan_cadence via
// registry.ResolveSchedule:
//   - manual:   skipped.
//   - auto:     due once globalInterval has elapsed since last_sync (every tick re-checks).
//   - periodic: due on the registry's own fixed interval.
func listDueRegistries(ctx context.Context, pool *pgxpool.Pool, globalInterval time.Duration) ([]walkerDueRow, error) {
	rows, err := pool.Query(ctx, `
SELECT id, org_id, name, scan_cadence, last_sync_at
  FROM registries
 WHERE scan_cadence <> 'manual'
 ORDER BY COALESCE(last_sync_at, '1970-01-01'::timestamptz) ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now()
	out := []walkerDueRow{}
	for rows.Next() {
		var (
			id      uuid.UUID
			orgID   uuid.UUID
			name    string
			cadence string
			last    *time.Time
		)
		if err := rows.Scan(&id, &orgID, &name, &cadence, &last); err != nil {
			return nil, err
		}
		if registry.ResolveSchedule(cadence).IsDue(last, now, globalInterval) {
			out = append(out, walkerDueRow{id: id, orgID: orgID, name: name})
		}
	}
	return out, rows.Err()
}
