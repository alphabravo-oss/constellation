//go:build integration

package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

type peersRoleResponse struct {
	WorkloadRole string     `json:"workload_platform_role"`
	ClusterID    *uuid.UUID `json:"cluster_id"`
	Hide         bool       `json:"hide_platform"`
	Total        int        `json:"total"`
	HasMore      bool       `json:"has_more"`
	SourceLimit  int        `json:"source_limit"`
	Peers        []peerDTO  `json:"peers"`
}

func TestPeersRolesExactSourceIdentityAndVisibility(t *testing.T) {
	t.Parallel()
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := context.Background(), d.Pool()
	org, foreignOrg, cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, tenant := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, tenant, "peer-role-"+tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM network_flows WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name,state) VALUES($1,$2,'main','connected'),($3,$2,'sibling','disconnected'),($4,$5,'foreign','connected')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	core, foreignOwner := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'orbit','api','Deployment','{"helm.sh/chart":"constellation-1"}'),
 (gen_random_uuid(),$2,$3,'app','client','Deployment','{}'),
 (gen_random_uuid(),$2,$3,'generic','api','Deployment','{"app.kubernetes.io/part-of":"constellation-near-match"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','Deployment','{"helm.sh/chart":"constellation-1"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','StatefulSet','{}'),
 (gen_random_uuid(),$2,$4,'orbit','api','Deployment','{}'),
 ($5,$6,$7,'foreign-only','api','Deployment','{"helm.sh/chart":"constellation-1"}')`, core, org, cluster, sibling, foreignOwner, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,'orbit','api-pod','peer-pod','orbit/pod/api-pod','Deployment','api','orbit/api',$3),($1,$2,'foreign-only','api-pod','foreign-pod','foreign-only/pod/api-pod','Deployment','api','foreign-only/api',$4)`, org, cluster, core, foreignOwner); err != nil {
		t.Fatal(err)
	}
	add := func(tenant, cl uuid.UUID, src, dst, ip string, bytes int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,src_addr,dst_addr,dst_port,protocol,bytes,sessions) VALUES($1,$2,$3,$4,$5,'10.9.0.1',443,'tcp',$6,1)`, tenant, cl, src, dst, ip, bytes); err != nil {
			t.Fatal(err)
		}
	}
	for i, workload := range []string{"orbit/api", "orbit/pod/api-pod", "generic/api", "ambiguous/api", "foreign-only/api", "foreign-only/pod/api-pod", "10.42.0.90", "external"} {
		add(org, cluster, workload, "app/client", fmt.Sprintf("10.42.0.%d", i+1), 10)
	}
	add(org, cluster, "orbit/api", "app/client", "10.42.0.50", 20)
	add(org, cluster, "generic/api", "app/client", "10.42.0.50", 30)
	add(org, sibling, "orbit/api", "app/client", "10.42.0.1", 500)
	add(foreignOrg, foreign, "orbit/api", "app/client", "10.42.0.99", 1000)
	// Even an inconsistent foreign cluster reference cannot leak or classify its labels.
	add(org, foreign, "orbit/api", "app/client", "10.42.0.98", 1000)
	request := func(path string, handle http.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), "GET", path, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		res := httptest.NewRecorder()
		handle(res, req)
		return res
	}
	read := func(extra string) peersRoleResponse {
		t.Helper()
		res := request("/network/peers?workload=app/client&cluster_id="+cluster.String()+extra, NewNetwork(d).Peers)
		if res.Code != 200 {
			t.Fatalf("%d %s", res.Code, res.Body.String())
		}
		var body peersRoleResponse
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	all := read("")
	if all.Total != 9 || len(all.Peers) != 9 || all.HasMore || all.SourceLimit != 500 || all.ClusterID == nil || *all.ClusterID != cluster || all.WorkloadRole != "" {
		t.Fatalf("scope/count %+v", all)
	}
	for _, row := range all.Peers {
		want := ""
		if row.PeerIP == "10.42.0.1" || row.PeerIP == "10.42.0.2" {
			want = "core"
		}
		if row.PeerPlatformRole != want {
			t.Fatalf("role %+v want %q", row, want)
		}
		if row.PeerIP == "10.42.0.50" && (row.Peer != "" || row.PeerClusterID != nil || row.Bytes != 50 || row.Sessions != 2) {
			t.Fatalf("mixed identity %+v", row)
		}
		if (row.PeerIP == "10.42.0.7" || row.PeerIP == "10.42.0.8") && row.PeerClusterID != nil {
			t.Fatalf("IP/external cluster %+v", row)
		}
	}
	hidden := read("&hide_platform=true")
	if hidden.Total != 7 || !hidden.Hide {
		t.Fatalf("hide %+v", hidden)
	}
	for _, row := range hidden.Peers {
		if row.PeerPlatformRole != "" {
			t.Fatalf("hidden platform %+v", row)
		}
		if row.PeerIP == "10.42.0.50" && (row.Peer != "generic/api" || row.Bytes != 30 || row.Sessions != 1) {
			t.Fatalf("filter must precede fold %+v", row)
		}
	}
	// A positively classified inspected workload is excluded too.
	res := request("/network/peers?workload=orbit/api&cluster_id="+cluster.String()+"&hide_platform=true", NewNetwork(d).Peers)
	var coreResponse peersRoleResponse
	_ = json.Unmarshal(res.Body.Bytes(), &coreResponse)
	if res.Code != 200 || coreResponse.WorkloadRole != "core" || coreResponse.Total != 0 {
		t.Fatalf("self role %d %s", res.Code, res.Body.String())
	}
	res = request("/network/peers?workload=app/client&cluster_id="+sibling.String(), NewNetwork(d).Peers)
	var siblingResponse peersRoleResponse
	_ = json.Unmarshal(res.Body.Bytes(), &siblingResponse)
	if res.Code != 200 || siblingResponse.Total != 1 || siblingResponse.Peers[0].PeerPlatformRole != "" {
		t.Fatalf("sibling borrow %s", res.Body.String())
	}
	res = request("/network/peers?workload=app/client", NewNetwork(d).Peers)
	var defaultResponse peersRoleResponse
	_ = json.Unmarshal(res.Body.Bytes(), &defaultResponse)
	if res.Code != 200 || defaultResponse.ClusterID == nil || *defaultResponse.ClusterID != cluster || defaultResponse.Total != 9 {
		t.Fatalf("legacy selected-cluster default %s", res.Body.String())
	}
	// Retained diagnostic cap is explicit and counts the complete matching peer cohort.
	if _, err := pool.Exec(ctx, `INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,src_addr,dst_addr,protocol,bytes) SELECT $1,$2,'external','app/capped','10.0.'||(i/256)::text||'.'||(i%256)::text,'10.9.0.2','tcp',1 FROM generate_series(1,501)i`, org, cluster); err != nil {
		t.Fatal(err)
	}
	res = request("/network/peers?workload=app/capped&cluster_id="+cluster.String(), NewNetwork(d).Peers)
	var capped peersRoleResponse
	_ = json.Unmarshal(res.Body.Bytes(), &capped)
	if res.Code != 200 || capped.Total != 501 || len(capped.Peers) != 500 || !capped.HasMore {
		t.Fatalf("cap %d %+v", res.Code, capped)
	}
	// Query failure must not be a successful empty/partial response.
	role := pgx.Identifier{"peer_test_" + uuid.New().String()}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP OWNED BY `+role); _, _ = pool.Exec(ctx, `DROP ROLE `+role) })
	for _, sql := range []string{`GRANT USAGE ON SCHEMA public TO ` + role, `GRANT SELECT ON clusters,network_flows TO ` + role} {
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
	res = request("/network/peers?workload=app/client&cluster_id="+cluster.String(), NewNetwork(db.NewFromPool(restricted)).Peers)
	if res.Code != 500 {
		t.Fatalf("read failure %d %s", res.Code, res.Body.String())
	}
	var failure map[string]any
	_ = json.Unmarshal(res.Body.Bytes(), &failure)
	if failure["peers"] != nil || failure["error"] == nil {
		t.Fatalf("partial success %s", res.Body.String())
	}
}

func TestPeersRejectsMalformedVisibilityAndDuplicateQuery(t *testing.T) {
	t.Parallel()
	h := NewNetwork(nil)
	for _, path := range []string{"/network/peers?workload=a/b&hide_platform=yes", "/network/peers?workload=a/b&workload=c/d", "/network/peers?workload=a/b;hide_platform=true"} {
		res := httptest.NewRecorder()
		h.Peers(res, httptest.NewRequestWithContext(t.Context(), "GET", path, nil))
		if res.Code != 400 {
			t.Fatalf("%s: %d", path, res.Code)
		}
	}
}
