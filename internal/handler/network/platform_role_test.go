package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestNetworkMapPlatformRole(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := context.Background()
	orgID, clusterID := uuid.New(), uuid.New()
	pool := database.Pool()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Platform Role Test')`, orgID, "network-platform-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'network-platform-cluster')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels) VALUES
		($1, $2, 'operations', 'houston', 'Deployment', '{"app.kubernetes.io/part-of":"astronomer"}'::jsonb),
		($1, $2, 'payments', 'api', 'Deployment', '{}'::jsonb)`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/network/map?cluster_id="+clusterID.String(), nil)
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
	response := httptest.NewRecorder()
	NewNetwork(database).Map(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("map status %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Workloads []map[string]any `json:"workloads"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Workloads) != 2 {
		t.Fatalf("workloads: %#v", body.Workloads)
	}
	for _, workload := range body.Workloads {
		switch workload["namespace"] {
		case "operations":
			if workload["platform_role"] != "core" {
				t.Fatalf("custom install not classified: %#v", workload)
			}
		case "payments":
			if workload["platform_role"] != "" {
				t.Fatalf("customer workload must remain explicitly unclassified: %#v", workload)
			}
		default:
			t.Fatalf("unexpected workload: %#v", workload)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, src_addr, dst_addr, protocol, dst_port, sessions) VALUES
		($1, $2, 'external', 'operations/houston', '8.8.8.8', '10.0.0.10', 'tcp', 443, 1)`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/network/exposure?cluster_id="+clusterID.String(), nil)
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
	response = httptest.NewRecorder()
	NewNetwork(database).Exposure(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("exposure status %d: %s", response.Code, response.Body.String())
	}
	var exposure struct {
		Ingress []map[string]any `json:"ingress"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &exposure); err != nil {
		t.Fatal(err)
	}
	if len(exposure.Ingress) != 1 || exposure.Ingress[0]["platform_role"] != "core" {
		t.Fatalf("exposure role: %#v", exposure.Ingress)
	}
}

func TestNetworkFlowPlatformRolesRetainExactCluster(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := context.Background()
	org, foreignOrg := uuid.New(), uuid.New()
	cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "flow-role-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM network_flow_rollups WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM network_flows WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'a'),($3,$2,'b'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,'operations','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($1,$3,'operations','api','Deployment','{}'),
 ($4,$5,'operations','api','Deployment','{"helm.sh/chart":"constellation-1"}')`, org, cluster, sibling, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []struct{ org, cluster uuid.UUID }{{org, cluster}, {org, sibling}, {foreignOrg, foreign}} {
		if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bytes) VALUES($1,$2,'operations/api','external/8.8.8.8','tcp',443,'allow',50)`, identity.org, identity.cluster); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,sum_bytes,flow_count) VALUES($1,$2,'operations/api','external/8.8.8.8','tcp',443,'allow',date_trunc('hour',NOW()),NOW(),50,1)`, identity.org, identity.cluster); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []string{"?cluster_id=" + cluster.String(), "?cluster_id=" + sibling.String()} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/network/map"+scope, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		response := httptest.NewRecorder()
		NewNetwork(database).Map(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("map %d: %s", response.Code, response.Body.String())
		}
		var body struct {
			Flows  []map[string]any `json:"flows"`
			Recent []map[string]any `json:"recent_flows"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		for _, rows := range [][]map[string]any{body.Flows, body.Recent} {
			want := 1
			if len(rows) != want {
				t.Fatalf("row count %d expected %d", len(rows), want)
			}
			for _, row := range rows {
				if row["cluster_id"] == cluster.String() {
					if row["src_platform_role"] != "core" {
						t.Fatalf("missing role: %#v", row)
					}
				} else if row["src_platform_role"] != "" {
					t.Fatalf("wrong cluster inherited role: %#v", row)
				}
				if row["dst_platform_role"] != "" {
					t.Fatalf("external classified: %#v", row)
				}
			}
		}
	}
}
