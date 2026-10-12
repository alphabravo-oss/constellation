package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNetworkMapAndExposureExactEndpointRoles(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx, pool := context.Background(), database.Pool()
	org, foreignOrg, cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, tenant := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, tenant, "map-exposure-role-"+tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	owner, unlabelled, ambiguousOwner, siblingOwner, foreignOwner := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($4,$2,$3,'custom-install','neighbor','Deployment','{}'),
 ($5,$2,$3,'ambiguous','api','Deployment','{"helm.sh/chart":"constellation-1"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','StatefulSet','{}'),
 (gen_random_uuid(),$2,$3,'generic','api','Deployment','{"app.kubernetes.io/managed-by":"Helm"}'),
 (gen_random_uuid(),$2,$3,'custom-install','unobserved','Deployment','{"app.kubernetes.io/part-of":"constellation"}'),
 ($6,$2,$7,'custom-install','api','Deployment','{}'),
 ($8,$9,$10,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}')`, owner, org, cluster, unlabelled, ambiguousOwner, siblingOwner, sibling, foreignOwner, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES
 ($1,$2,'custom-install','api-pod','pod-a','custom-install/pod/api-pod','Deployment','api','custom-install/api',$3),
 ($1,$2,'custom-install','api-pod','pod-a-again','custom-install/pod/api-pod','Deployment','api','custom-install/api',$3),
 ($1,$2,'ambiguous','api-pod','pod-b','ambiguous/pod/api-pod','Deployment','api','ambiguous/api',$4),
 ($1,$2,'custom-install','multiple','pod-c','custom-install/pod/multiple','Deployment','api','custom-install/api',$3),
 ($1,$2,'custom-install','multiple','pod-d','custom-install/pod/multiple','Deployment','neighbor','custom-install/neighbor',$5),
 ($1,$2,'custom-install','sibling-owner','pod-e','custom-install/pod/sibling-owner','Deployment','api','custom-install/api',$6),
 ($1,$2,'custom-install','foreign-owner','pod-f','custom-install/pod/foreign-owner','Deployment','api','custom-install/api',$7),
 ($1,$8,'custom-install','api-pod','pod-g','custom-install/pod/api-pod','Deployment','api','custom-install/api',$6)`, org, cluster, owner, ambiguousOwner, unlabelled, siblingOwner, foreignOwner, sibling); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ workload, role string }{
		{"custom-install/api", "core"}, {"custom-install/pod/api-pod", "core"},
		{"ambiguous/api", ""}, {"ambiguous/pod/api-pod", "core"},
		{"custom-install/pod/multiple", ""}, {"custom-install/pod/sibling-owner", ""},
		{"custom-install/pod/foreign-owner", ""}, {"custom-install/missing", ""},
		{"generic/api", ""}, {"kube-system/10.42.0.2", ""}, {"kube-system/coredns", "core"},
	}
	seedFlow := func(tenant, scope uuid.UUID, src, dst string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,src_addr,dst_addr,protocol,dst_port,verdict,bytes,packets,sessions) VALUES($1,$2,$3,$4,'8.8.8.8','10.0.0.10','tcp',443,'allow',50,2,1)`, tenant, scope, src, dst); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,sum_bytes,sum_packets,sum_sessions,flow_count) VALUES($1,$2,$3,$4,'tcp',443,'allow',date_trunc('hour',NOW()),NOW(),50,2,1,1)`, tenant, scope, src, dst); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range cases {
		seedFlow(org, cluster, "external", item.workload)
		seedFlow(org, cluster, item.workload, "external")
	}
	for _, item := range []struct{ tenant, scope uuid.UUID }{{org, sibling}, {foreignOrg, foreign}} {
		seedFlow(item.tenant, item.scope, "external", "custom-install/api")
		seedFlow(item.tenant, item.scope, "external", "custom-install/pod/api-pod")
	}
	if _, err := pool.Exec(ctx, `UPDATE deployments SET critical_count=CASE WHEN kind='Deployment' THEN 2 ELSE 5 END,high_count=CASE WHEN kind='Deployment' THEN 9 ELSE 3 END,risk_score=CASE WHEN kind='Deployment' THEN 30 ELSE 70 END WHERE org_id=$1 AND cluster_id=$2 AND namespace='ambiguous' AND name='api'`, org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewNetwork(database)
	call := func(scope uuid.UUID, endpoint string, handle http.HandlerFunc) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, endpoint+"?cluster_id="+scope.String(), nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		res := httptest.NewRecorder()
		handle(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", endpoint, res.Code, res.Body.String())
		}
		return res.Body.Bytes()
	}
	var inventory struct {
		Summary   map[string]any   `json:"summary"`
		Workloads []map[string]any `json:"workloads"`
		Flows     []map[string]any `json:"flows"`
		Recent    []map[string]any `json:"recent_flows"`
	}
	if err := json.Unmarshal(call(cluster, "/network/map", h.Map), &inventory); err != nil {
		t.Fatal(err)
	}
	// Existing map inventory includes both kind rows for an ambiguous logical
	// graph ID, two deployments with no flows, and one synthetic external node.
	if len(inventory.Workloads) != len(cases)+4 || inventory.Summary["workloads"] != float64(len(cases)+4) || len(inventory.Flows) != 2*len(cases) || inventory.Summary["flows_total"] != float64(2*len(cases)) || len(inventory.Recent) != 2*len(cases) || inventory.Summary["recent_flows_total"] != float64(2*len(cases)) {
		t.Fatalf("changed map counts: %+v", inventory.Summary)
	}
	expected := map[string]string{"external": "", "custom-install/neighbor": "", "custom-install/unobserved": "core"}
	for _, item := range cases {
		expected[item.workload] = item.role
	}
	ambiguousRows := 0
	for _, row := range inventory.Workloads {
		id := row["id"].(string)
		want, ok := expected[id]
		if !ok || row["platform_role"] != want {
			t.Fatalf("map node %s role=%#v want=%q", id, row["platform_role"], want)
		}
		if id == "ambiguous/api" {
			ambiguousRows++
		}
	}
	if ambiguousRows != 2 {
		t.Fatalf("graph identity rows changed: %d", ambiguousRows)
	}
	for _, rows := range [][]map[string]any{inventory.Flows, inventory.Recent} {
		for _, row := range rows {
			for _, side := range []string{"src", "dst"} {
				id := row[side].(string)
				if row[side+"_platform_role"] != expected[id] {
					t.Fatalf("flow disagrees with node: %+v", row)
				}
			}
		}
	}
	var exposure struct{ Ingress, Egress []map[string]any }
	if err := json.Unmarshal(call(cluster, "/network/exposure", h.Exposure), &exposure); err != nil {
		t.Fatal(err)
	}
	for _, rows := range [][]map[string]any{exposure.Ingress, exposure.Egress} {
		if len(rows) != len(cases) {
			t.Fatalf("changed exposure rows: %d", len(rows))
		}
		for _, row := range rows {
			if row["sessions"] != float64(1) || row["external_peers"] != float64(1) {
				t.Fatalf("source sessions multiplied: %+v", row)
			}
			if row["workload"] == "ambiguous/api" && (row["critical"] != float64(5) || row["high"] != float64(9) || row["risk_score"] != float64(70)) {
				t.Fatalf("MAX vulnerability semantics changed: %+v", row)
			}
			if row["platform_role"] != expected[row["workload"].(string)] {
				t.Fatalf("exposure role mismatch %+v", row)
			}
		}
	}
	var siblingMap struct {
		Workloads []map[string]any `json:"workloads"`
		Flows     []map[string]any `json:"flows"`
	}
	if err := json.Unmarshal(call(sibling, "/network/map", h.Map), &siblingMap); err != nil {
		t.Fatal(err)
	}
	if len(siblingMap.Workloads) != 3 || len(siblingMap.Flows) != 2 {
		t.Fatalf("sibling counts %+v", siblingMap)
	}
	for _, row := range siblingMap.Workloads {
		if row["platform_role"] != "" {
			t.Fatalf("sibling borrowed labels %+v", row)
		}
	}
	exposure.Ingress = nil
	exposure.Egress = nil
	if err := json.Unmarshal(call(sibling, "/network/exposure", h.Exposure), &exposure); err != nil {
		t.Fatal(err)
	}
	if len(exposure.Ingress) != 2 || len(exposure.Egress) != 0 {
		t.Fatalf("sibling exposure %+v", exposure)
	}
	for _, row := range exposure.Ingress {
		if row["platform_role"] != "" {
			t.Fatalf("sibling exposure borrowed role %+v", row)
		}
	}
	for _, endpoint := range []struct {
		path   string
		handle http.HandlerFunc
	}{{"/network/map", h.Map}, {"/network/exposure", h.Exposure}} {
		req := httptest.NewRequest(http.MethodGet, endpoint.path+"?cluster_id="+foreign.String(), nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		res := httptest.NewRecorder()
		endpoint.handle(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("foreign scope %s: %d %s", endpoint.path, res.Code, res.Body.String())
		}
	}
}

func TestNetworkMapAndExposureRoleLookupFailure(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx, pool := context.Background(), database.Pool()
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "map-role-failure-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,src_addr,dst_addr,protocol,sessions) VALUES($1,$2,'external','custom-install/api','8.8.8.8','10.0.0.1','tcp',1)`, org, cluster); err != nil {
		t.Fatal(err)
	}
	role := pgx.Identifier{"map_role_test_" + uuid.New().String()}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP OWNED BY `+role); _, _ = pool.Exec(ctx, `DROP ROLE `+role) })
	// Existing source reads are permitted; only exact pod ownership lookup fails.
	for _, sql := range []string{`GRANT USAGE ON SCHEMA public TO ` + role, `GRANT SELECT ON clusters, deployments, groups, network_flows, network_flow_rollups TO ` + role} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg := pool.Config().Copy()
	cfg.MinConns = 0
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["role"] = role[1 : len(role)-1]
	restricted, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restricted.Close)
	h := NewNetwork(db.NewFromPool(restricted))
	for _, item := range []struct {
		path   string
		handle http.HandlerFunc
	}{{"/network/map", h.Map}, {"/network/exposure", h.Exposure}} {
		req := httptest.NewRequest(http.MethodGet, item.path+"?cluster_id="+cluster.String(), nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		res := httptest.NewRecorder()
		item.handle(res, req)
		if res.Code != http.StatusInternalServerError {
			t.Fatalf("metadata failure %s: %d %s", item.path, res.Code, res.Body.String())
		}
		var fields map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &fields); err != nil || fields["error"] == nil || fields["workloads"] != nil || fields["ingress"] != nil {
			t.Fatalf("partial success %s", res.Body.String())
		}
	}
}

func TestNetworkMapLegacyMultiClusterGraphRolesAreAmbiguous(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx, pool := context.Background(), database.Pool()
	org, clusterOrg, first, second, owner := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, tenant := range []uuid.UUID{org, clusterOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, tenant, "legacy-map-"+tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, clusterOrg) })
	// Earlier schemas allowed evidence and deployment rows whose cluster was not
	// in their organization's owned cluster registry. Preserve those source rows
	// while refusing to infer a single installation for their merged graph ID.
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'first'),($3,$2,'second')`, first, clusterOrg, second); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,$3,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}')`, owner, org, first); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,'custom-install','api-pod','legacy-pod','custom-install/pod/api-pod','Deployment','api','custom-install/api',$3)`, org, first, owner); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []uuid.UUID{first, second} {
		for _, workload := range []string{"custom-install/api", "custom-install/pod/api-pod"} {
			if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,sum_bytes,flow_count) VALUES($1,$2,$3,'external','tcp',date_trunc('hour',NOW()),NOW(),10,1)`, org, scope, workload); err != nil {
				t.Fatal(err)
			}
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/network/map", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
	res := httptest.NewRecorder()
	NewNetwork(database).Map(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("legacy source %d %s", res.Code, res.Body.String())
	}
	var data struct {
		Workloads []map[string]any `json:"workloads"`
		Flows     []map[string]any `json:"flows"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Workloads) != 3 || len(data.Flows) != 4 {
		t.Fatalf("legacy counts changed %+v", data)
	}
	for _, node := range data.Workloads {
		if node["platform_role"] != "" {
			t.Fatalf("graph node borrowed a cluster role %+v", node)
		}
	}
	for _, flow := range data.Flows {
		want := ""
		if flow["cluster_id"] == first.String() {
			want = "core"
		}
		if flow["src_platform_role"] != want {
			t.Fatalf("exact endpoint role lost %+v", flow)
		}
	}
}
