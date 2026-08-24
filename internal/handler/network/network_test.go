package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/google/uuid"
)

func TestNetwork_MapAggregatesFlows(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	clusterID := uuid.New()
	otherClusterID := uuid.New()
	userID := uuid.New()
	_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, orgID)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Test')
`, orgID, "network-test-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'test-cluster', 'connected')
`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'other-cluster', 'connected')
`, otherClusterID, orgID); err != nil {
		t.Fatalf("other cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, risk_score, finding_count)
VALUES ($1, $2, 'default', 'api', 'Deployment', 80, 4),
       ($1, $2, 'data', 'postgres', 'StatefulSet', 55, 2)
`, orgID, clusterID); err != nil {
		t.Fatalf("deployments: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO groups (org_id, cluster_id, name, kind, criteria, members, policy_mode, profile_mode)
VALUES ($1, $2, 'payments-tier', 'ground', '[]'::jsonb, '["default/api"]'::jsonb, 'monitor', 'monitor')
`, orgID, clusterID); err != nil {
		t.Fatalf("group: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, src_addr, dst_addr, src_port, protocol, l7_protocol, dst_port, verdict, bytes, packets, at)
VALUES ($1, $2, 'default/api', 'data/postgres', '10.42.0.8', '10.42.1.15', 41002, 'tcp', 'postgres', 5432, 'allow', 1000, 10, NOW()),
       ($1, $2, 'default/api', 'data/postgres', '10.42.0.8', '10.42.1.15', 41002, 'tcp', 'postgres', 5432, 'allow', 500, 5, NOW() - INTERVAL '5 minutes')
`, orgID, clusterID); err != nil {
		t.Fatalf("flows: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, src_addr, dst_addr, src_port, protocol, l7_protocol, dst_port, verdict, bytes, packets, at)
VALUES ($1, $2, 'default/api', 'data/postgres', '10.99.0.8', '10.99.1.15', 41002, 'tcp', 'postgres', 5432, 'allow', 9000, 90, NOW())
`, orgID, otherClusterID); err != nil {
		t.Fatalf("other cluster flow: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	// Map now reads the aggregated `flows` from the network_flow_rollups
	// pre-aggregate, so fold the just-inserted raw flows into it. Reset the
	// singleton watermark to epoch and fold with zero lag so the NOW() rows are
	// included deterministically. (recentFlows/workloads still read raw flows.)
	if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollup_state (id) VALUES (true) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("rollup state seed: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE network_flow_rollup_state SET watermark = '1970-01-01T00:00:00Z'`); err != nil {
		t.Fatalf("rollup watermark reset: %v", err)
	}
	if err := (&RollupRefresher{db: d, lag: 0}).refresh(ctx); err != nil {
		t.Fatalf("rollup fold: %v", err)
	}

	r := httptest.NewRequest("GET", "/api/v1/network/map?hours=1&cluster_id="+clusterID.String(), nil)
	r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewNetwork(d).Map(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}

	var got struct {
		Summary struct {
			RecentFlows          int    `json:"recent_flows"`
			TotalBytes           int64  `json:"total_bytes"`
			TotalPackets         int64  `json:"total_packets"`
			Allowed              int    `json:"allowed"`
			Selected             string `json:"selected_cluster_id"`
			SelectedGroup        string `json:"selected_group"`
			SelectedGroupMembers int    `json:"selected_group_members"`
			Clusters             []struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"clusters"`
		} `json:"summary"`
		Workloads   []map[string]any `json:"workloads"`
		RecentFlows []struct {
			FlowID     string `json:"flow_id"`
			Src        string `json:"src"`
			Dst        string `json:"dst"`
			SrcAddr    string `json:"src_addr"`
			DstAddr    string `json:"dst_addr"`
			SrcPort    int    `json:"src_port"`
			Scope      string `json:"traffic_scope"`
			State      string `json:"state"`
			ObservedAt string `json:"observed_at"`
		} `json:"recent_flows"`
		Flows []struct {
			Src     string `json:"src"`
			Dst     string `json:"dst"`
			SrcAddr string `json:"src_addr"`
			DstAddr string `json:"dst_addr"`
			SrcPort int    `json:"src_port"`
			Scope   string `json:"traffic_scope"`
			State   string `json:"state"`
			Bytes   int64  `json:"bytes"`
			Packets int64  `json:"packets"`
			Samples int64  `json:"samples"`
		} `json:"flows"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Workloads) != 2 {
		t.Fatalf("workloads: %+v", got.Workloads)
	}
	if len(got.Flows) != 1 {
		t.Fatalf("flows: %+v", got.Flows)
	}
	flow := got.Flows[0]
	if flow.Src != "default/api" || flow.Dst != "data/postgres" || flow.State != "ok" {
		t.Fatalf("unexpected flow: %+v", flow)
	}
	if flow.Bytes != 1500 || flow.Packets != 15 || flow.Samples != 2 {
		t.Fatalf("unexpected aggregate: %+v", flow)
	}
	if flow.SrcAddr != "10.42.0.8" || flow.DstAddr != "10.42.1.15" || flow.SrcPort != 41002 || flow.Scope != "cross-namespace" {
		t.Fatalf("missing edge metadata: %+v", flow)
	}
	if got.Summary.RecentFlows != 2 || got.Summary.TotalBytes != 1500 || got.Summary.TotalPackets != 15 || got.Summary.Allowed != 1 {
		t.Fatalf("unexpected summary: %+v", got.Summary)
	}
	if got.Summary.Selected != clusterID.String() || len(got.Summary.Clusters) != 2 {
		t.Fatalf("missing cluster scope summary: %+v", got.Summary)
	}
	if len(got.RecentFlows) != 2 || got.RecentFlows[0].FlowID == "" || got.RecentFlows[0].ObservedAt == "" {
		t.Fatalf("missing recent flow stream: %+v", got.RecentFlows)
	}
	if got.RecentFlows[0].SrcAddr != "10.42.0.8" || got.RecentFlows[0].DstAddr != "10.42.1.15" || got.RecentFlows[0].SrcPort != 41002 || got.RecentFlows[0].Scope != "cross-namespace" {
		t.Fatalf("missing recent flow metadata: %+v", got.RecentFlows[0])
	}

	groupReq := httptest.NewRequest("GET", "/api/v1/network/map?hours=1&cluster_id="+clusterID.String()+"&group=payments-tier", nil)
	groupReq = groupReq.WithContext(authctx.WithSubject(groupReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	groupRec := httptest.NewRecorder()
	NewNetwork(d).Map(groupRec, groupReq)
	if groupRec.Code != http.StatusOK {
		t.Fatalf("group status: %d body: %s", groupRec.Code, groupRec.Body.String())
	}
	var grouped struct {
		Summary struct {
			SelectedGroup        string `json:"selected_group"`
			SelectedGroupMembers int    `json:"selected_group_members"`
		} `json:"summary"`
		Flows []struct {
			Src string `json:"src"`
			Dst string `json:"dst"`
		} `json:"flows"`
	}
	if err := json.NewDecoder(groupRec.Body).Decode(&grouped); err != nil {
		t.Fatalf("decode grouped: %v", err)
	}
	if grouped.Summary.SelectedGroup != "payments-tier" || grouped.Summary.SelectedGroupMembers != 1 {
		t.Fatalf("missing selected group metadata: %+v", grouped.Summary)
	}
	if len(grouped.Flows) != 1 || grouped.Flows[0].Src != "default/api" {
		t.Fatalf("group filter should keep only member conversations, got %+v", grouped.Flows)
	}
}
