package network

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
)

// FlowBackfiller is the automatic, retroactive counterpart to the manual
// `constellationctl network-flows backfill` command. Rows whose src_workload or
// dst_workload was stamped "cluster/<ip>" at ingest (the pod raced the
// discoverer, or was already gone) stay raw forever. Now that pod_ips retains
// history (migration 117) and the IP resolver is time-aware, a periodic pass can
// re-resolve them: it re-runs the SAME resolver the ingest path uses over a
// trailing window of recent flows and rewrites the rows whose labels moved off
// "cluster/<ip>". After rewriting raw rows it refolds the affected rollup
// buckets so the pre-aggregate agrees with the raw table.
//
// It reuses the CLI backfill's approach (scan cluster/<ip> rows, batch-resolve
// per org, UPDATE the movers) but lives server-side so it can share the handler
// IP resolver instead of the CLI's parallel reimplementation, and stays
// leader-gated so replicas don't race each other or the rollup watermark.
type FlowBackfiller struct {
	db       *db.DB
	rollup   *RollupRefresher
	interval time.Duration
	window   time.Duration // trailing scan window
	limit    int           // max candidate rows scanned per pass (bounded work)
	batch    int           // rows per UPDATE batch
}

// NewFlowBackfiller builds a backfiller. The rollup refresher is shared so the
// backfill can refold the buckets it disturbs. Tunables are env-overridable so
// operators can dial the DB load without a rebuild:
//
//	CONSTELLATION_NETWORK_FLOW_BACKFILL_INTERVAL  (duration, default 60s; <=0 disables)
//	CONSTELLATION_NETWORK_FLOW_BACKFILL_WINDOW    (duration, default 30m)
//	CONSTELLATION_NETWORK_FLOW_BACKFILL_LIMIT     (int, default 5000 candidate rows/pass)
func NewFlowBackfiller(d *db.DB, rr *RollupRefresher) *FlowBackfiller {
	b := &FlowBackfiller{db: d, rollup: rr, interval: time.Minute, window: 30 * time.Minute, limit: 5000, batch: 500}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_NETWORK_FLOW_BACKFILL_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			b.interval = d
		}
	}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_NETWORK_FLOW_BACKFILL_WINDOW")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			b.window = d
		}
	}
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_NETWORK_FLOW_BACKFILL_LIMIT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			b.limit = n
		}
	}
	return b
}

// Start launches the reconcile loop. It runs one pass immediately then ticks.
// A non-positive interval disables it entirely (loop never starts), matching the
// opt-out contract of the other env-tuned loops. The loop exits when ctx is
// canceled (leader-election lease loss), like every other singleton loop.
func (b *FlowBackfiller) Start(ctx context.Context) {
	if b.interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(b.interval)
		defer t.Stop()
		b.runOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				b.runOnce(ctx)
			}
		}
	}()
}

func (b *FlowBackfiller) runOnce(ctx context.Context) {
	start := time.Now()
	rewritten, from, to, err := b.backfill(ctx)
	if err != nil {
		slog.Warn("network flow backfill", slog.String("err", err.Error()))
		return
	}
	if rewritten == 0 {
		return
	}
	// Raw rows moved off "cluster/<ip>"; the rollup pre-aggregate still holds
	// their counts under the old labels. Refold the disturbed window so the two
	// agree again.
	if err := b.rollup.RefoldWindow(ctx, from, to); err != nil {
		slog.Warn("network flow backfill refold", slog.String("err", err.Error()))
	}
	slog.Info("network flow backfill",
		slog.Int("rewritten", rewritten),
		slog.Duration("took", time.Since(start)))
}

// candidate is one raw flow row that still carries a "cluster/<ip>" label.
type candidate struct {
	id      uuid.UUID
	orgID   uuid.UUID
	src     string
	dst     string
	srcAddr string
	dstAddr string
	at      time.Time
}

// backfill runs one pass: scan recent cluster/<ip> rows, re-resolve them per org
// via the handler IP resolver, and UPDATE the movers. Returns the number of rows
// rewritten and the [from, to] `at` span they covered (for the caller's refold).
func (b *FlowBackfiller) backfill(ctx context.Context) (rewritten int, from, to time.Time, err error) {
	// Only scan rows a resolve could actually MOVE: at least one "cluster/<ip>"
	// side's IP must currently exist in pod_ips or cluster_services. This keeps
	// the bounded per-pass budget from being burned on permanently-unresolvable
	// labels (the CNI gateway / host IPs, which dominate the raw cluster/<ip>
	// volume) and never reaching the resolvable stragglers. Newest-first so the
	// most recently-observed misses heal first.
	rows, err := b.db.Pool().Query(ctx, `
SELECT f.id, f.org_id, f.src_workload, f.dst_workload,
       COALESCE(f.src_addr, ''), COALESCE(f.dst_addr, ''), f.at
  FROM network_flows f
 WHERE f.at >= now() - ($1::text || ' seconds')::interval
   AND (f.src_workload LIKE 'cluster/%' OR f.dst_workload LIKE 'cluster/%')
   AND (
     EXISTS (SELECT 1 FROM pod_ips p
              WHERE p.org_id = f.org_id
                AND host(p.ip) IN (substring(f.src_workload from 9), substring(f.dst_workload from 9)))
     OR EXISTS (SELECT 1 FROM cluster_services s
                 WHERE s.org_id = f.org_id
                   AND host(s.cluster_ip) IN (substring(f.src_workload from 9), substring(f.dst_workload from 9)))
   )
 ORDER BY f.at DESC
 LIMIT $2`,
		strconv.FormatInt(int64(b.window/time.Second), 10), b.limit)
	if err != nil {
		return 0, time.Time{}, time.Time{}, err
	}
	var all []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.orgID, &c.src, &c.dst, &c.srcAddr, &c.dstAddr, &c.at); err != nil {
			rows.Close()
			return 0, time.Time{}, time.Time{}, err
		}
		all = append(all, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, time.Time{}, time.Time{}, err
	}
	if len(all) == 0 {
		return 0, time.Time{}, time.Time{}, nil
	}

	// Group by org so the resolver's batched pod_ips/cluster_services lookup runs
	// once per org (usually one org in single-tenant deployments).
	byOrg := map[uuid.UUID][]int{}
	for i := range all {
		byOrg[all[i].orgID] = append(byOrg[all[i].orgID], i)
	}

	updates := make([]flowRelabel, 0, b.batch)
	flush := func() error {
		if len(updates) == 0 {
			return nil
		}
		if err := applyRelabels(ctx, b.db.Pool(), updates); err != nil {
			return err
		}
		rewritten += len(updates)
		updates = updates[:0]
		return nil
	}

	for _, idxs := range byOrg {
		// Feed the org's rows to the resolver as synthetic ingest rows; it collects
		// their distinct addresses (and IPs embedded in cluster/<ip> labels) and
		// resolves them in two batched SELECTs.
		req := make(handler.FlowIngestRequest, len(idxs))
		for j, i := range idxs {
			c := all[i]
			req[j] = handler.FlowIngestRow{
				SrcWorkload: c.src,
				DstWorkload: c.dst,
				SrcAddr:     c.srcAddr,
				DstAddr:     c.dstAddr,
				At:          c.at,
			}
		}
		resolver := handler.NewIPResolver(ctx, b.db, all[idxs[0]].orgID, req)
		for _, i := range idxs {
			c := all[i]
			newSrc, newDst, changed := relabelFlow(resolver.Resolve, c.src, c.dst, c.srcAddr, c.dstAddr, c.at)
			if !changed {
				continue
			}
			updates = append(updates, flowRelabel{id: c.id, at: c.at, src: newSrc, dst: newDst})
			if from.IsZero() || c.at.Before(from) {
				from = c.at
			}
			if c.at.After(to) {
				to = c.at
			}
			if len(updates) >= b.batch {
				if err := flush(); err != nil {
					return rewritten, from, to, err
				}
			}
		}
	}
	if err := flush(); err != nil {
		return rewritten, from, to, err
	}
	return rewritten, from, to, nil
}

// resolveFunc is the time-aware resolver seam. It matches
// (*handler.IPResolver).Resolve so relabelFlow can be unit-tested against a fake
// without a DB.
type resolveFunc func(workload, addr, nodeHint string, at time.Time) (string, bool)

// relabelFlow decides a row's new (src, dst) labels. It mirrors the ingest path
// (network_flows_ingest.go): the source workload is the node hint for both ends,
// and the flow's `at` time-brackets the pod_ips history lookup. changed reports
// whether either label actually moved.
func relabelFlow(rf resolveFunc, src, dst, srcAddr, dstAddr string, at time.Time) (newSrc, newDst string, changed bool) {
	newSrc, _ = rf(src, srcAddr, src, at)
	newDst, _ = rf(dst, dstAddr, src, at)
	return newSrc, newDst, newSrc != src || newDst != dst
}

// flowRelabel is one row's rewrite, addressed by its (id, at) primary key.
type flowRelabel struct {
	id  uuid.UUID
	at  time.Time
	src string
	dst string
}

// applyRelabels writes the batch as one pgx.Batch round-trip. Rows are keyed on
// the (id, at) primary key rather than ctid, so an UPDATE is stable even if the
// row moved partitions or the table was vacuumed between scan and write.
func applyRelabels(ctx context.Context, pool *pgxpool.Pool, ops []flowRelabel) error {
	b := &pgx.Batch{}
	for _, op := range ops {
		b.Queue(`UPDATE network_flows
		            SET src_workload = $1, dst_workload = $2
		          WHERE id = $3 AND at = $4`,
			op.src, op.dst, op.id, op.at)
	}
	br := pool.SendBatch(ctx, b)
	defer br.Close()
	for range ops {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}
