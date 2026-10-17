// Package flowrollup owns the aggregate shape shared by refresh and late ingest.
package flowrollup

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Lock serializes aggregation, refolding and expiry. Ingest holds a shared lock
// until its inserts and late aggregates commit, so expiry cannot overtake it.
func Lock(ctx context.Context, tx pgx.Tx, exclusive bool) (watermark, rawPrunedBefore time.Time, err error) {
	clause := " FOR SHARE"
	if exclusive {
		clause = " FOR UPDATE"
	}
	err = tx.QueryRow(ctx, "SELECT watermark, raw_pruned_before FROM network_flow_rollup_state WHERE id = true"+clause).Scan(&watermark, &rawPrunedBefore)
	return
}

func FoldRange(ctx context.Context, tx pgx.Tx, lo, hi time.Time) error {
	_, err := tx.Exec(ctx, strings.Replace(foldSQL, "/*predicate*/", "f.at > $1 AND f.at <= $2", 1), lo, hi)
	return err
}

// FoldLate adds only the newly inserted IDs at/below the locked watermark.
// Those rows will never be seen by the forward-only incremental refresher.
func FoldLate(ctx context.Context, tx pgx.Tx, ids []uuid.UUID, watermark time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, strings.Replace(foldSQL, "/*predicate*/", "f.id = ANY($1::uuid[]) AND f.at <= $2", 1), ids, watermark)
	return err
}

const foldSQL = `
INSERT INTO network_flow_rollups (
    org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bucket,
    sum_bytes, sum_packets, flow_count, max_at, min_src_addr, min_dst_addr, min_src_port,
    has_dp, has_hubble, has_bpf, min_source, sum_client_bytes, sum_server_bytes, sum_sessions,
    max_threat_id, max_severity, max_application, fqdn, threat_id_complete)
SELECT f.org_id, f.cluster_id, f.src_workload, f.dst_workload, f.protocol,
       COALESCE(f.l7_protocol, ''), COALESCE(f.dst_port, 0), COALESCE(f.verdict, ''),
       date_trunc('hour', f.at),
       SUM(COALESCE(f.bytes, 0))::bigint, SUM(COALESCE(f.packets, 0))::bigint, COUNT(*)::bigint, MAX(f.at),
       COALESCE(MIN(f.src_addr), ''), COALESCE(MIN(f.dst_addr), ''), COALESCE(MIN(f.src_port), 0),
       bool_or(f.source = 'dp'), bool_or(f.source = 'hubble'), bool_or(f.source = 'bpf'), COALESCE(MIN(f.source), ''),
       SUM(COALESCE(f.client_bytes, 0))::bigint, SUM(COALESCE(f.server_bytes, 0))::bigint, SUM(COALESCE(f.sessions, 0))::bigint,
       MAX(f.threat_id), MAX(f.severity), MAX(f.application), COALESCE(MIN(NULLIF(f.fqdn, '')), ''), true
  FROM network_flows f
 WHERE f.cluster_id IS NOT NULL
   AND /*predicate*/
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
    threat_id_complete = network_flow_rollups.threat_id_complete AND EXCLUDED.threat_id_complete,
    max_threat_id    = GREATEST(network_flow_rollups.max_threat_id, EXCLUDED.max_threat_id),
    max_severity     = GREATEST(network_flow_rollups.max_severity, EXCLUDED.max_severity),
    max_application  = GREATEST(network_flow_rollups.max_application, EXCLUDED.max_application),
    fqdn             = COALESCE(NULLIF(network_flow_rollups.fqdn, ''), EXCLUDED.fqdn)`

// Rebuild replaces only complete raw hours and must run in the relabel transaction.
func Rebuild(ctx context.Context, tx pgx.Tx, from, to time.Time) error {
	watermark, prunedBefore, err := Lock(ctx, tx, true)
	if err != nil {
		return err
	}
	// Rebuild complete hours, including the tail of the last requested hour.
	hi := to.UTC().Truncate(time.Hour).Add(time.Hour).Add(-time.Microsecond)
	if watermark.Before(hi) {
		hi = watermark
	}
	// date_trunc('hour', from): buckets are hourly, so the whole hour must be rebuilt.
	lo := from.UTC().Truncate(time.Hour)
	if lo.Before(prunedBefore) {
		lo = prunedBefore
	}
	if !hi.After(lo) {
		return nil // window is entirely ahead of the watermark; nothing settled to refold
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM network_flow_rollups WHERE bucket >= $1 AND bucket <= $2`, lo, hi); err != nil {
		return err
	}
	// foldRange's lower bound is exclusive (at > lo); step back 1µs so a flow landing
	// exactly on the hour boundary is included in its rebuilt bucket.
	if err := FoldRange(ctx, tx, lo.Add(-time.Microsecond), hi); err != nil {
		return err
	}
	return nil
}
