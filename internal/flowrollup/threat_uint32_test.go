//go:build integration

package flowrollup

import (
	"context"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

func TestThreatUint32LateFoldPreservesUnknownAndRebuildRepairs(t *testing.T) {
	t.Parallel()
	d := db.NewFromPool(pgtest.Pool(t))
	p := d.Pool()
	ctx := t.Context()
	org, cluster := uuid.New(), uuid.New()
	t.Cleanup(func() {
		cleanup := context.WithoutCancel(ctx)
		_, _ = p.Exec(cleanup, `DELETE FROM network_flows WHERE org_id=$1`, org)
		_, _ = p.Exec(cleanup, `DELETE FROM network_flow_rollups WHERE org_id=$1`, org)
		_, _ = p.Exec(cleanup, `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := p.Exec(ctx, `INSERT INTO orgs(id,name,display_name)VALUES($1::uuid,$1::text,'fold unsigned')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'fold unsigned')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(ctx)) })
	// Hold the singleton lock and roll back its fixture watermark at the end.
	if _, _, err = Lock(ctx, tx, true); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Hour).Add(10 * time.Minute)
	if _, err = tx.Exec(ctx, `UPDATE network_flow_rollup_state SET raw_pruned_before=$1,watermark=$2 WHERE id=true`, at.Truncate(time.Hour), at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO network_flows(id,org_id,cluster_id,src_workload,dst_workload,protocol,source,at,threat_id)VALUES($1,$2,$3,'prod/api','prod/db','tcp','dp',$4,4294967295)`, id, org, cluster, at); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,verdict,bucket,max_at,flow_count,max_threat_id,threat_id_complete)VALUES($1,$2,'prod/api','prod/db','tcp','allow',date_trunc('hour',$3::timestamptz),$3,1,0,false)`, org, cluster, at); err != nil {
		t.Fatal(err)
	}
	if err = FoldLate(ctx, tx, []uuid.UUID{id}, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var complete bool
	var max, n int64
	if err = tx.QueryRow(ctx, `SELECT max_threat_id,threat_id_complete,flow_count FROM network_flow_rollups WHERE org_id=$1`, org).Scan(&max, &complete, &n); err != nil || complete || max != 4294967295 || n != 2 {
		t.Fatalf("late max=%d complete=%v count=%d err=%v", max, complete, n, err)
	}
	if err = Rebuild(ctx, tx, at, at); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(ctx, `SELECT max_threat_id,threat_id_complete,flow_count FROM network_flow_rollups WHERE org_id=$1`, org).Scan(&max, &complete, &n); err != nil || !complete || max != 4294967295 || n != 1 {
		t.Fatalf("rebuild max=%d complete=%v count=%d err=%v", max, complete, n, err)
	}
}
