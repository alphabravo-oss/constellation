//go:build integration

package network

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/flowrollup"
)

// This opt-in SQL qualification uses migrated partitioned tables and the real
// refresh/prune/late-fold paths. It is not an HTTP, fleet or production-cadence SLA.
func TestFlowLifecycleLocalLoad(t *testing.T) {
	if os.Getenv("CONSTELLATION_TEST_FLOW_LOAD") != "true" {
		t.Skip("set CONSTELLATION_TEST_FLOW_LOAD=true for isolated 110000-flow qualification")
	}
	t.Parallel()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	org, cluster := seedFlowLoad(t, pool)
	old := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Hour)
	recent := time.Now().UTC().Add(-2 * time.Minute)
	createFlowLoadPartitions(t, pool, old, recent)
	if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol,at,bytes)
 SELECT $1,$2,'app/'||(n%1000)::text,'app/destination','tcp',$3::timestamptz+(n%3600)*interval '1 second',10 FROM generate_series(1,100000) n`, org, cluster, old); err != nil {
		t.Fatal(err)
	}
	rr := NewRollupRefresher(database)
	rr.lag = 0
	rr.pruneBatch = 5000
	var lsn string
	if err := pool.QueryRow(ctx, `SELECT pg_current_wal_insert_lsn()::text`).Scan(&lsn); err != nil {
		t.Fatal(err)
	}
	initialStart := time.Now()
	if err := rr.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	initialFold := time.Since(initialStart)
	if err := rr.RefoldWindow(ctx, old, old.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	incoming := make(chan flowLoadSamples, 1)
	start := make(chan struct{})
	go func() { <-start; incoming <- ingestFlowLoad(ctx, pool, org, cluster, old, recent) }()
	maintenance := make([]time.Duration, 0, 40)
	started := time.Now()
	close(start)
	var removed int64
	for range 40 {
		passStart := time.Now()
		if err := rr.refresh(ctx); err != nil {
			t.Fatal(err)
		}
		n, err := rr.prune(ctx, 24*time.Hour)
		if err != nil || n > rr.pruneBatch {
			t.Fatalf("bounded prune: %d %v", n, err)
		}
		removed += n
		// Rebuilding a partially pruned hour must not erase its surviving aggregate.
		if err := rr.RefoldWindow(ctx, old, old.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		maintenance = append(maintenance, time.Since(passStart))
	}
	maintenanceEnd := time.Now()
	samples := <-incoming
	if !samples.started.Before(maintenanceEnd) || !samples.finished.After(started) {
		t.Fatal("ingestion did not overlap maintenance")
	}
	if samples.err != nil {
		t.Fatal(samples.err)
	}
	if err := rr.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// Drain any old late arrivals committed after the forty measured passes.
	for range 30 {
		n, err := rr.prune(ctx, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		removed += n
		if n == 0 {
			break
		}
	}
	if removed != 105000 {
		t.Fatalf("removed=%d want 105000", removed)
	}
	assertFlowLoadTotals(t, pool, org)
	var wal float64
	if err := pool.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::double precision`, lsn).Scan(&wal); err != nil {
		t.Fatal(err)
	}
	t.Logf("flows=110000 initial_fold=%s concurrent_elapsed=%s ingest_batches=%d ingest_p95=%s ingest_p99=%s maintenance_p95=%s maintenance_p99=%s removed=%d combined_wal_bytes=%.0f",
		initialFold, time.Since(started), len(samples.latency), flowPercentile(samples.latency, 95), flowPercentile(samples.latency, 99), flowPercentile(maintenance, 95), flowPercentile(maintenance, 99), removed, wal)
}

func seedFlowLoad(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'flow load fixture')`, org, org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'flow load fixture')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	return org, cluster
}

type flowLoadSamples struct {
	latency           []time.Duration
	started, finished time.Time
	err               error
}

func ingestFlowLoad(ctx context.Context, pool *pgxpool.Pool, org, cluster uuid.UUID, old, recent time.Time) flowLoadSamples {
	result := flowLoadSamples{latency: make([]time.Duration, 0, 100), started: time.Now()}
	for batch := 0; batch < 100; batch++ {
		started := time.Now()
		if err := insertFlowLoadBatch(ctx, pool, org, cluster, old, recent, batch); err != nil {
			result.err = err
			return result
		}
		result.latency = append(result.latency, time.Since(started))
	}
	result.finished = time.Now()
	return result
}

func insertFlowLoadBatch(ctx context.Context, pool *pgxpool.Pool, org, cluster uuid.UUID, old, recent time.Time, batch int) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	watermark, _, err := flowrollup.Lock(ctx, tx, false)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	err = tx.QueryRow(ctx, `WITH inserted AS (
 INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol,at,bytes)
 SELECT $1,$2,'app/'||((n+$5::int*100)%1000)::text,'app/destination','tcp',CASE WHEN n%2=0 THEN $3::timestamptz ELSE $4::timestamptz END,10
 FROM generate_series(1,100) n RETURNING id) SELECT array_agg(id) FROM inserted`, org, cluster, old.Add(30*time.Minute), recent, batch).Scan(&ids)
	if err != nil {
		return err
	}
	if err = flowrollup.FoldLate(ctx, tx, ids, watermark); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func assertFlowLoadTotals(t *testing.T, pool *pgxpool.Pool, org uuid.UUID) {
	t.Helper()
	var raw, total, bytes int64
	var stale int64
	err := pool.QueryRow(t.Context(), `SELECT
 (SELECT count(*) FROM network_flows WHERE org_id=$1),
 (SELECT count(*) FROM network_flows WHERE org_id=$1 AND at<now()-interval '1 day'),
 (SELECT coalesce(sum(flow_count),0) FROM network_flow_rollups WHERE org_id=$1),
 (SELECT coalesce(sum(sum_bytes),0) FROM network_flow_rollups WHERE org_id=$1)`, org).Scan(&raw, &stale, &total, &bytes)
	if err != nil || raw != 5000 || stale != 0 || total != 110000 || bytes != 1100000 {
		t.Fatalf("flow conservation raw=%d stale=%d folded=%d bytes=%d err=%v", raw, stale, total, bytes, err)
	}
}

func flowPercentile(values []time.Duration, p int) time.Duration {
	ordered := slices.Clone(values)
	slices.Sort(ordered)
	return ordered[(len(ordered)-1)*p/100]
}

func createFlowLoadPartitions(t *testing.T, pool *pgxpool.Pool, old, recent time.Time) {
	t.Helper()
	for _, entry := range []struct {
		name string
		at   time.Time
	}{{"load_old", old}, {"load_recent", recent}} {
		day := entry.at.UTC().Truncate(24 * time.Hour)
		// All DDL identifiers and timestamp literals come from this fixture.
		query := fmt.Sprintf("CREATE TABLE network_flows_%s PARTITION OF network_flows FOR VALUES FROM ('%s') TO ('%s')", entry.name, day.Format(time.RFC3339), day.Add(24*time.Hour).Format(time.RFC3339))
		if _, err := pool.Exec(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
}
