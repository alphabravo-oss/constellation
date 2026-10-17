package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestDeploymentThreatUint32PivotsAndFlowsPreserveHighIDs(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := t.Context()
	org, cluster := uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM runtime_threats WHERE org_id=$1;`, org)
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM network_flows WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'unsigned')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'unsigned')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO runtime_threats(org_id,cluster_id,workload_id,threat_id,severity,reported_at) VALUES($1,$2,'prod/api',4294967295,7,now());`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol,threat_id,source) VALUES($1,$2,'prod/api','prod/db','tcp',4294967295,'dp')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewDeployments(d, nil)
	r := httptest.NewRequestWithContext(ctx, "GET", "/", nil)
	pivots, err := h.deploymentRuntimeThreatPivots(r, org, &cluster, []string{"prod/api"})
	if err != nil || len(pivots) != 1 {
		t.Fatalf("pivots=%+v err=%v", pivots, err)
	}
	flows, err := h.deploymentNetworkFlows(r, org, &cluster, []string{"prod/api"})
	if err != nil || len(flows) != 1 || flows[0].ThreatID != 4294967295 {
		t.Fatalf("flows=%+v err=%v", flows, err)
	}
}
