package network

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/flowrollup"
)

// RollupRefresher incrementally folds raw network_flows into the per-hour
// network_flow_rollups pre-aggregate (migration 115) that /network/map and
// /network/conversations read from. It advances a watermark (the max flow `at`
// already folded in) so each pass only processes newly-ingested rows — the same
// continuous-aggregation idea NeuVector uses to keep its conversation graph hot,
// but durable in Postgres.
//
// It optionally prunes raw flows past a retention horizon (Tier 3). Retention is
// OFF unless CONSTELLATION_NETWORK_FLOW_RETENTION_DAYS is set, so it never
// deletes flow history without an operator opting in.
type RollupRefresher struct {
	db         *db.DB
	interval   time.Duration
	lag        time.Duration // don't fold flows newer than now()-lag, to tolerate clock skew / late arrivals
	retention  time.Duration // env-derived default; 0 = disabled
	pruneBatch int64
	// liveRetention, when set, returns the runtime-configured horizon (from system
	// config) each pass and overrides the env default, including an explicit zero
	// (retention disabled).
	liveRetention func(ctx context.Context) time.Duration
}

// SetRetentionResolver wires a live retention-horizon source (system config). Called
// once at startup. See RollupRefresher.liveRetention.
func (rr *RollupRefresher) SetRetentionResolver(fn func(ctx context.Context) time.Duration) {
	rr.liveRetention = fn
}

func NewRollupRefresher(d *db.DB) *RollupRefresher {
	rr := &RollupRefresher{db: d, interval: time.Minute, lag: 30 * time.Second, pruneBatch: 50000}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_NETWORK_FLOW_ROLLUP_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			rr.interval = d
		}
	}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_NETWORK_FLOW_RETENTION_DAYS")); v != "" {
		if days, err := strconv.Atoi(v); err == nil && days > 0 {
			rr.retention = time.Duration(days) * 24 * time.Hour
		}
	}
	return rr
}

// Start launches the refresh loop. It runs one pass immediately (which
// backfills the whole table on first boot, off the request path) then ticks.
func (rr *RollupRefresher) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(rr.interval)
		defer t.Stop()
		rr.runOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rr.runOnce(ctx)
			}
		}
	}()
}

func (rr *RollupRefresher) runOnce(ctx context.Context) {
	start := time.Now()
	if err := rr.refresh(ctx); err != nil {
		slog.Warn("network flow rollup refresh; retention skipped", slog.String("err", err.Error()))
		return
	} else if d := time.Since(start); d > 2*time.Second {
		// Only noisy on the first-boot backfill; steady-state incremental passes are sub-second.
		slog.Info("network flow rollup refresh", slog.Duration("took", d))
	}
	horizon := rr.retention
	if rr.liveRetention != nil {
		horizon = rr.liveRetention(ctx)
	}
	if horizon > 0 {
		if deleted, err := rr.prune(ctx, horizon); err != nil {
			slog.Warn("network flow retention prune", slog.String("err", err.Error()))
		} else if deleted > 0 {
			slog.Info("network flow retention prune", slog.Int64("deleted", deleted), slog.String("horizon", horizon.String()))
		}
	}
}

// refresh folds every flow in (watermark, now()-lag] into hourly buckets and
// advances the watermark to that upper bound. Runs in one transaction that locks
// the singleton state row FOR UPDATE, so concurrent passes serialize (never
// double-count) and, crucially, the lower bound is a bound parameter — not a
// correlated subquery — so the planner can use the BRIN index on at for a tight
// range scan of just the new flows instead of scanning the whole table.
func (rr *RollupRefresher) refresh(ctx context.Context) error {
	tx, err := rr.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	lagSecs := strconv.FormatInt(int64(rr.lag/time.Second), 10)
	var lo, hi time.Time
	if err := tx.QueryRow(ctx,
		`SELECT watermark, now() - ($1::text || ' seconds')::interval
           FROM network_flow_rollup_state FOR UPDATE`, lagSecs).Scan(&lo, &hi); err != nil {
		return err
	}
	if !hi.After(lo) {
		return tx.Commit(ctx) // nothing new to fold
	}

	if err := rr.foldRange(ctx, tx, lo, hi); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `UPDATE network_flow_rollup_state SET watermark = $1`, hi); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// foldRange folds every raw flow in (lo, hi] into its hourly bucket, additively
// (INSERT .. ON CONFLICT DO UPDATE SET col = col + EXCLUDED.col). It is the one
// place the aggregation shape lives, shared by the incremental refresh() (whose
// lo is the watermark) and RefoldWindow() (whose lo is an hour boundary), so the
// two can never drift apart. The (lo, hi] bound is exclusive-low so a flow is
// never folded twice across successive incremental passes.
func (rr *RollupRefresher) foldRange(ctx context.Context, tx pgx.Tx, lo, hi time.Time) error {
	return flowrollup.FoldRange(ctx, tx, lo, hi)
}

// RefoldWindow rebuilds the hourly rollup buckets covering [from, to] from raw
// network_flows. The flow backfiller relabels raw "cluster/<ip>" rows in place
// after ingest, which leaves the pre-aggregate holding counts under the OLD
// labels; this recomputes the affected buckets so /network/map and
// /network/conversations reflect the freshly-resolved workloads.
//
// It DELETEs the rollup rows whose bucket falls in [date_trunc('hour', from), to]
// then re-folds that same window from raw with foldRange (the identical
// aggregation refresh() uses). The upper bound is clamped to the fold watermark:
// the incremental refresh() owns (watermark, now-lag] and folds it exactly once,
// so re-folding past the watermark here would double-count it on the next pass
// (the fold is additive). Both paths take the state row FOR UPDATE, so a refold
// and an incremental fold never touch the same buckets concurrently.
func (rr *RollupRefresher) RefoldWindow(ctx context.Context, from, to time.Time) error {
	tx, err := rr.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := flowrollup.Rebuild(ctx, tx, from, to); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// prune deletes a bounded batch of raw flows older than the retention horizon.
// Bounded so a backlog is worked off across cycles instead of one long lock.
// Address rows by the partitioned table's (id, at) primary key, never by ctid
// alone: two children can have the same physical tuple address.
func (rr *RollupRefresher) prune(ctx context.Context, retention time.Duration) (int64, error) {
	if retention <= 0 || rr.pruneBatch <= 0 {
		return 0, nil
	}
	tx, err := rr.db.Pool().Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	watermark, _, err := flowrollup.Lock(ctx, tx, true)
	if err != nil {
		return 0, err
	}
	// Keep at least an hour of replay grace and prune only completely folded hours.
	cutoff := time.Now().UTC().Add(-retention).Truncate(time.Hour)
	foldCutoff := watermark.UTC().Add(-time.Hour).Truncate(time.Hour)
	if foldCutoff.Before(cutoff) {
		cutoff = foldCutoff
	}
	var deleted int64
	var through *time.Time
	err = tx.QueryRow(ctx, `
WITH removed AS (
 DELETE FROM network_flows
 WHERE (id, at) IN (
   SELECT id, at FROM network_flows WHERE at < $1
   ORDER BY at, id LIMIT $2 FOR UPDATE SKIP LOCKED
 ) RETURNING at
)
SELECT count(*), date_trunc('hour', max(at) AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' + interval '1 hour' FROM removed`, cutoff, rr.pruneBatch).Scan(&deleted, &through)
	if err != nil {
		return 0, err
	}
	if through != nil {
		if _, err := tx.Exec(ctx, `UPDATE network_flow_rollup_state SET raw_pruned_before = GREATEST(raw_pruned_before, $1) WHERE id=true`, *through); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return deleted, nil
}
