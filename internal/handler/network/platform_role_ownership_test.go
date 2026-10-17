package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/livegraph"
)

func TestNetworkEvidenceRolesPodOwnershipAndKindAmbiguity(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx, pool := context.Background(), database.Pool()
	org, foreignOrg, cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, tenant := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, tenant, "network-owner-"+tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreignOrg) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	owner, otherOwner, foreignOwner, ambiguousOwner := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($4,$2,$3,'custom-install','other','Deployment','{}'),
 ($5,$6,$7,'custom-install','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 (gen_random_uuid(),$2,$8,'custom-install','api','Deployment','{}'),
 ($9,$2,$3,'ambiguous','api','Deployment','{"helm.sh/chart":"constellation-1"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','StatefulSet','{}'),
 (gen_random_uuid(),$2,$3,'generic','api','Deployment','{"app.kubernetes.io/managed-by":"Helm"}')`, owner, org, cluster, otherOwner, foreignOwner, foreignOrg, foreign, sibling, ambiguousOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES
 ($1,$2,'custom-install','api-pod','pod-1','custom-install/pod/api-pod','Deployment','api','custom-install/api',$3),
 ($1,$4,'custom-install','api-pod','pod-2','custom-install/pod/api-pod','Deployment','api','custom-install/api',$3),
 ($1,$2,'custom-install','foreign-pod','pod-3','custom-install/pod/foreign-pod','Deployment','api','custom-install/api',$5),
 ($1,$2,'custom-install','ambiguous-pod','pod-4','custom-install/pod/ambiguous-pod','Deployment','api','custom-install/api',$3),
 ($1,$2,'custom-install','ambiguous-pod','pod-5','custom-install/pod/ambiguous-pod','Deployment','other','custom-install/other',$6),
 ($1,$2,'ambiguous','api-pod','pod-6','ambiguous/pod/api-pod','Deployment','api','ambiguous/api',$7)`, org, cluster, owner, sibling, foreignOwner, otherOwner, ambiguousOwner); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ workload, role string }{
		{"custom-install/api", "core"}, {"custom-install/pod/api-pod", "core"},
		{"ambiguous/api", ""}, {"ambiguous/pod/api-pod", "core"}, {"custom-install/pod/ambiguous-pod", ""},
		{"custom-install/pod/foreign-pod", ""}, {"custom-install/pod/missing", ""},
		{"generic/api", ""}, {"kube-system/10.42.0.2", ""},
	}
	live := livegraph.New(livegraph.Config{})
	for i, item := range cases {
		if _, err := pool.Exec(ctx, `INSERT INTO network_sessions(org_id,cluster_id,node,id,workload_id,client_bytes,updated_at) VALUES($1,$2,'node',$3,$4,$5,NOW())`, org, cluster, i+1, item.workload, 100-i); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,sum_bytes) VALUES($1,$2,$3,'payments/api','tcp',date_trunc('hour',NOW()),NOW(),$4)`, org, cluster, item.workload, 100-i); err != nil {
			t.Fatal(err)
		}
		live.Publish(livegraph.Flow{OrgID: org, ClusterID: cluster, SrcWorkload: item.workload, DstWorkload: "payments/api", Protocol: "tcp", Bytes: int64(100 - i), At: time.Now()})
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_sessions(org_id,cluster_id,node,id,workload_id,updated_at) VALUES($1,$2,'node',99,'custom-install/pod/api-pod',NOW()),($3,$4,'node',100,'custom-install/api',NOW())`, org, sibling, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	request := func(path string, handle http.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		res := httptest.NewRecorder()
		handle(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, res.Code, res.Body.String())
		}
		return res
	}
	var sessions struct {
		Sessions []sessionDTO `json:"sessions"`
		Total    int          `json:"total"`
		HasMore  bool         `json:"has_more"`
	}
	if err := json.Unmarshal(request("/network/sessions?limit=20&cluster_id="+cluster.String(), NewNetwork(database).Sessions).Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	if sessions.Total != len(cases) || len(sessions.Sessions) != len(cases) || sessions.HasMore {
		t.Fatalf("session counts %+v", sessions)
	}
	for _, row := range sessions.Sessions {
		if row.ID < 1 || row.ID > int64(len(cases)) || row.PlatformRole != cases[row.ID-1].role {
			t.Fatalf("session classification %+v", row)
		}
	}
	var siblingSessions struct {
		Sessions []sessionDTO `json:"sessions"`
		Total    int          `json:"total"`
	}
	if err := json.Unmarshal(request("/network/sessions?cluster_id="+sibling.String(), NewNetwork(database).Sessions).Body.Bytes(), &siblingSessions); err != nil {
		t.Fatal(err)
	}
	if siblingSessions.Total != 1 || len(siblingSessions.Sessions) != 1 || siblingSessions.Sessions[0].ID != 99 || siblingSessions.Sessions[0].PlatformRole != "" {
		t.Fatalf("sibling owner borrowed: %+v", siblingSessions)
	}
	for _, hot := range []bool{false, true} {
		h := NewNetworkConversations(database)
		if hot {
			h.WithLiveGraph(live)
		}
		var list struct {
			Conversations []platformConversation `json:"conversations"`
			Total         int                    `json:"total"`
			HasMore       bool                   `json:"has_more"`
		}
		if err := json.Unmarshal(request("/network/conversations?cluster_id="+cluster.String(), h.List).Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if list.Total != len(cases) || len(list.Conversations) != len(cases) || list.HasMore {
			t.Fatalf("hot=%t counts %+v", hot, list)
		}
		for _, item := range cases {
			found := false
			for _, row := range list.Conversations {
				if row.From == item.workload {
					found = true
					if row.FromPlatformRole != item.role {
						t.Fatalf("hot=%t %s role=%q want=%q", hot, item.workload, row.FromPlatformRole, item.role)
					}
				}
			}
			if !found {
				t.Fatalf("missing %s", item.workload)
			}
		}
	}
	for _, item := range cases {
		var detail struct {
			FromPlatformRole string                 `json:"from_platform_role"`
			Entries          []conversationEntryDTO `json:"entries"`
			Totals           struct {
				Bytes int64 `json:"bytes"`
			} `json:"totals"`
		}
		if err := json.Unmarshal(request(fmt.Sprintf("/network/conversations/entries?cluster_id=%s&from=%s&to=payments/api", cluster, item.workload), NewNetworkConversations(database).Detail).Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		if detail.FromPlatformRole != item.role || len(detail.Entries) != 1 || detail.Totals.Bytes <= 0 {
			t.Fatalf("detail %s: %+v", item.workload, detail)
		}
	}
	// Folding an organization with several clusters retains unknown label roles.
	var all struct {
		Conversations []platformConversation `json:"conversations"`
	}
	if err := json.Unmarshal(request("/network/conversations", NewNetworkConversations(database).List).Body.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	for _, row := range all.Conversations {
		if row.FromPlatformRole != "" {
			t.Fatalf("org ambiguity borrowed role: %+v", row)
		}
	}
	// An organization with one cluster still supports its exact installation.
	if _, err := pool.Exec(ctx, `DELETE FROM clusters WHERE id=$1`, sibling); err != nil {
		t.Fatal(err)
	}
	all.Conversations = nil
	if err := json.Unmarshal(request("/network/conversations", NewNetworkConversations(database).List).Body.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	for _, row := range all.Conversations {
		for _, item := range cases {
			if row.From == item.workload && row.FromPlatformRole != item.role {
				t.Fatalf("single-cluster organization: %+v", row)
			}
		}
	}

}

func TestNetworkRoleLookupFailureIsVisible(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx, pool := context.Background(), database.Pool()
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "network-role-failure-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_sessions(org_id,cluster_id,node,id,workload_id,updated_at) VALUES($1,$2,'node',1,'custom-install/api',NOW())`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,sum_bytes) VALUES($1,$2,'custom-install/api','payments/api','tcp',date_trunc('hour',NOW()),NOW(),10)`, org, cluster); err != nil {
		t.Fatal(err)
	}
	role := pgx.Identifier{"network_role_test_" + uuid.New().String()}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP OWNED BY `+role); _, _ = pool.Exec(ctx, `DROP ROLE `+role) })
	for _, sql := range []string{`GRANT USAGE ON SCHEMA public TO ` + role, `GRANT SELECT ON clusters, network_sessions, network_flow_rollups TO ` + role} {
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
	scoped := db.NewFromPool(restricted)
	live := livegraph.New(livegraph.Config{})
	live.Publish(livegraph.Flow{OrgID: org, ClusterID: cluster, SrcWorkload: "custom-install/api", DstWorkload: "payments/api", Protocol: "tcp", Bytes: 10, At: time.Now()})
	for _, item := range []struct {
		path   string
		handle http.HandlerFunc
	}{
		{"/network/sessions?cluster_id=" + cluster.String(), NewNetwork(scoped).Sessions},
		{"/network/conversations?cluster_id=" + cluster.String(), NewNetworkConversations(scoped).List},
		{"/network/conversations?cluster_id=" + cluster.String(), NewNetworkConversations(scoped).WithLiveGraph(live).List},
		{"/network/conversations/entries?cluster_id=" + cluster.String() + "&from=custom-install/api&to=payments/api", NewNetworkConversations(scoped).Detail},
	} {
		req := httptest.NewRequest(http.MethodGet, item.path, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		res := httptest.NewRecorder()
		item.handle(res, req)
		if res.Code != http.StatusInternalServerError {
			t.Fatalf("lookup failure %s: %d %s", item.path, res.Code, res.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil || body["error"] == nil || body["sessions"] != nil || body["conversations"] != nil || body["entries"] != nil {
			t.Fatalf("partial success %s", res.Body.String())
		}
	}
}
