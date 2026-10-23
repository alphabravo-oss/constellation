//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/flowrollup"
	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func TestCLIBackfillCommitsLabelsAndTotalsTogether(t *testing.T) {
	ctx := context.Background()
	database := db.NewFromPool(pgtest.Pool(t))
	pool := pgfixture.Schema(t, database.Pool())
	_, err := pool.Exec(ctx, `CREATE TABLE network_flows (LIKE public.network_flows INCLUDING ALL);
 CREATE TABLE network_flow_rollups (LIKE public.network_flow_rollups INCLUDING ALL);
 CREATE TABLE network_flow_rollup_state (id boolean PRIMARY KEY, watermark timestamptz, raw_pruned_before timestamptz, rollups_pruned_before timestamptz NOT NULL DEFAULT '0001-01-01');
 INSERT INTO network_flow_rollup_state VALUES (true, now(), '1970-01-01');`)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Hour)
	var id string
	err = pool.QueryRow(ctx, `INSERT INTO network_flows (org_id,cluster_id,src_workload,dst_workload,protocol,at,bytes)
 VALUES ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','cluster/10.0.0.1','app/b','tcp',$1,10) RETURNING id::text`, at).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := flowrollup.FoldRange(ctx, tx, at.Add(-time.Hour), at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	ops := []batchUpdate{{id: id, at: at, src: "app/a", dst: "app/b"}}
	if err := applyUpdates(ctx, pool, ops); err != nil {
		t.Fatal(err)
	}
	var label string
	var count int64
	if err := pool.QueryRow(ctx, `SELECT src_workload,flow_count FROM network_flow_rollups`).Scan(&label, &count); err != nil {
		t.Fatal(err)
	}
	if label != "app/a" || count != 1 {
		t.Fatalf("label=%s count=%d", label, count)
	}
	// Missing raw history is a refusal, never a partially applied relabel.
	if _, err := pool.Exec(ctx, `UPDATE network_flow_rollup_state SET raw_pruned_before=$1`, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ops[0].src = "app/changed"
	if err := applyUpdates(ctx, pool, ops); err == nil {
		t.Fatal("expected incomplete history refusal")
	}
	if err := pool.QueryRow(ctx, `SELECT src_workload FROM network_flows`).Scan(&label); err != nil {
		t.Fatal(err)
	}
	if label != "app/a" {
		t.Fatalf("refused relabel committed: %s", label)
	}
}
