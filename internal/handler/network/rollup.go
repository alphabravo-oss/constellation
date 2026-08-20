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
	db        *db.DB
	interval  time.Duration
	lag       time.Duration // don't fold flows newer than now()-lag, to tolerate clock skew / late arrivals
	retention time.Duration // env-derived default; 0 = disabled
	pruneBatch int64
	// liveRetention, when set, returns the runtime-configured horizon (from system
	// config) each pass; a value > 0 overrides the env default so an admin can set
	// retention from the UI without a restart. 0 falls back to the env default.
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
		slog.Warn("network flow rollup refresh", slog.String("err", err.Error()))
	} else if d := time.Since(start); d > 2*time.Second {
		// Only noisy on the first-boot backfill; steady-state incremental passes are sub-second.
		slog.Info("network flow rollup refresh", slog.Duration("took", d))
	}
	horizon := rr.retention
	if rr.liveRetention != nil {
		if live := rr.liveRetention(ctx); live > 0 {
			horizon = live
		}
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
	_, err := tx.Exec(ctx, `
INSERT INTO network_flow_rollups (
    org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bucket,
    sum_bytes, sum_packets, flow_count, max_at, min_src_addr, min_dst_addr, min_src_port,
    has_dp, has_hubble, has_bpf, min_source, sum_client_bytes, sum_server_bytes, sum_sessions,
    max_threat_id, max_severity, max_application, fqdn)
SELECT f.org_id, f.cluster_id, f.src_workload, f.dst_workload, f.protocol,
       COALESCE(f.l7_protocol, ''), COALESCE(f.dst_port, 0), COALESCE(f.verdict, ''),
       date_trunc('hour', f.at),
       SUM(COALESCE(f.bytes, 0))::bigint, SUM(COALESCE(f.packets, 0))::bigint, COUNT(*)::bigint, MAX(f.at),
       COALESCE(MIN(f.src_addr), ''), COALESCE(MIN(f.dst_addr), ''), COALESCE(MIN(f.src_port), 0),
       bool_or(f.source = 'dp'), bool_or(f.source = 'hubble'), bool_or(f.source = 'bpf'), COALESCE(MIN(f.source), ''),
       SUM(COALESCE(f.client_bytes, 0))::bigint, SUM(COALESCE(f.server_bytes, 0))::bigint, SUM(COALESCE(f.sessions, 0))::bigint,
       MAX(f.threat_id), MAX(f.severity), MAX(f.application), COALESCE(MIN(NULLIF(f.fqdn, '')), '')
  FROM network_flows f
 WHERE f.cluster_id IS NOT NULL
   AND f.at > $1 AND f.at <= $2
 GROUP BY f.org_id, f.cluster_id, f.src_workload, f.dst_workload, f.protocol,
          COALESCE(f.l7_protocol, ''), COALESCE(f.dst_port, 0), COALESCE(f.verdict, ''),
          date_trunc('hour', f.at)
ON CONFLICT (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bucket)
DO UPDATE SET
    sum_bytes        = network_flow_rollups.sum_bytes + EXCLUDED.sum_bytes,
    sum_packets      = network_flow_rollups.sum_packets + EXCLUDED.sum_packets,
    flow_count       = network_flow_rollups.flow_count + EXCLUDED.flow_count,
    max_at           = GREATEST(network_flow_rollups.max_at, EXCLUDED.max_at),
    min_src_addr     = LEAST(network_flow_rollups.min_src_addr, EXCLUDED.min_src_addr),
    min_dst_addr     = LEAST(network_flow_rollups.min_dst_addr, EXCLUDED.min_dst_addr),
    min_src_port     = LEAST(network_flow_rollups.min_src_port, EXCLUDED.min_src_port),
    has_dp           = network_flow_rollups.has_dp OR EXCLUDED.has_dp,
    has_hubble       = network_flow_rollups.has_hubble OR EXCLUDED.has_hubble,
    has_bpf          = network_flow_rollups.has_bpf OR EXCLUDED.has_bpf,
    min_source       = LEAST(network_flow_rollups.min_source, EXCLUDED.min_source),
    sum_client_bytes = network_flow_rollups.sum_client_bytes + EXCLUDED.sum_client_bytes,
    sum_server_bytes = network_flow_rollups.sum_server_bytes + EXCLUDED.sum_server_bytes,
    sum_sessions     = network_flow_rollups.sum_sessions + EXCLUDED.sum_sessions,
    max_threat_id    = GREATEST(network_flow_rollups.max_threat_id, EXCLUDED.max_threat_id),
    max_severity     = GREATEST(network_flow_rollups.max_severity, EXCLUDED.max_severity),
    max_application  = GREATEST(network_flow_rollups.max_application, EXCLUDED.max_application),
    fqdn             = COALESCE(NULLIF(network_flow_rollups.fqdn, ''), EXCLUDED.fqdn)`,
		lo, hi)
	return err
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

	var watermark time.Time
	if err := tx.QueryRow(ctx,
		`SELECT watermark FROM network_flow_rollup_state FOR UPDATE`).Scan(&watermark); err != nil {
		return err
	}
	hi := to
	if watermark.Before(hi) {
		hi = watermark // never re-fold ahead of the incremental watermark
	}
	// date_trunc('hour', from): buckets are hourly, so the whole hour must be rebuilt.
	lo := from.UTC().Truncate(time.Hour)
	if !hi.After(lo) {
		return tx.Commit(ctx) // window is entirely ahead of the watermark; nothing settled to refold
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM network_flow_rollups WHERE bucket >= $1 AND bucket <= $2`, lo, hi); err != nil {
		return err
	}
	// foldRange's lower bound is exclusive (at > lo); step back 1µs so a flow landing
	// exactly on the hour boundary is included in its rebuilt bucket.
	if err := rr.foldRange(ctx, tx, lo.Add(-time.Microsecond), hi); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// prune deletes a bounded batch of raw flows older than the retention horizon.
// Bounded so a backlog is worked off across cycles instead of one long lock.
// ponytail: batched DELETE, not partition-drop. network_flows is a partitioned
// table but everything currently lands in the default partition, so there are no
// time partitions to DROP cheaply; a per-day partitioning + DROP is the upgrade
// path once the ingest side rotates partitions.
func (rr *RollupRefresher) prune(ctx context.Context, retention time.Duration) (int64, error) {
	horizon := strconv.FormatInt(int64(retention/time.Second), 10)
	tag, err := rr.db.Pool().Exec(ctx, `
DELETE FROM network_flows
 WHERE ctid IN (
     SELECT ctid FROM network_flows
      WHERE at < now() - ($1::text || ' seconds')::interval
      LIMIT $2
 )`, horizon, rr.pruneBatch)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
