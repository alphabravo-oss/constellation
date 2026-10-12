package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/google/uuid"
)

func TestEvidencePlatformRolesExactScopeAndInventories(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	org, foreignOrg := uuid.New(), uuid.New()
	cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "role-evidence-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM runtime_threats WHERE org_id IN ($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreignOrg)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'a'),($3,$2,'b'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	deployment := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'operations','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 (gen_random_uuid(),$2,$4,'operations','api','Deployment','{}'),
 (gen_random_uuid(),$5,$6,'operations','api','Deployment','{"helm.sh/chart":"constellation-1.0"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','Deployment','{"helm.sh/chart":"constellation-1.0"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','api','StatefulSet','{}'),
 (gen_random_uuid(),$2,$3,'malformed','api','Deployment','{"app.kubernetes.io/part-of":"astronomer","bad":12}')`, deployment, org, cluster, sibling, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,'operations','api-pod','unique-pod','operations/pod/api-pod','Deployment','api','operations/api',$3)`, org, cluster, deployment); err != nil {
		t.Fatal(err)
	}
	identities := []handler.PlatformWorkloadIdentity{
		{ClusterID: cluster, Workload: "operations/api"}, {ClusterID: sibling, Workload: "operations/api"},
		{ClusterID: foreign, Workload: "operations/api"}, {ClusterID: cluster, Workload: "operations/pod/api-pod"},
		{ClusterID: cluster, Workload: "kube-system/coredns"}, {ClusterID: cluster, Workload: "host/operations"},
		{ClusterID: cluster, Workload: "ambiguous/api"}, {ClusterID: cluster, Workload: "malformed/api"},
		{Workload: "operations/api"}, {ClusterID: cluster, Workload: "operations/api", Namespace: "kube-system"},
		{ClusterID: cluster, Workload: "api", Namespace: "operations"},
		{ClusterID: cluster, Workload: "api"},
		{ClusterID: cluster, Workload: "10.0.0.1", Namespace: "operations"},
		{ClusterID: cluster, Workload: "kube-system/10.42.0.2"},
		{ClusterID: cluster, Workload: "10.42.0.2", Namespace: "kube-system"},
	}
	roles, err := handler.EvidencePlatformRoles(ctx, pool, org, identities)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"core", "", "", "core", "core", "", "", "", "", "core", "core", "", "", "", ""}
	for i, want := range expected {
		if roles[i] != want {
			t.Fatalf("identity %d role=%q want=%q", i, roles[i], want)
		}
	}

	// The inventory predicate must classify before paging exactly as the batch path.
	for i, identity := range identities {
		var role string
		sql := "SELECT " + handler.EvidencePlatformRoleSQL("$1::uuid", "$2::uuid", "$3::text", "$4::text")
		if err := pool.QueryRow(ctx, sql, org, identity.ClusterID, identity.Workload, identity.Namespace).Scan(&role); err != nil {
			t.Fatal(err)
		}
		if role != roles[i] {
			t.Fatalf("SQL role %d=%q Go=%q", i, role, roles[i])
		}
	}
	type record struct {
		id       uuid.UUID
		identity handler.PlatformWorkloadIdentity
		role     string
	}
	records := []record{}
	for i := 0; i < 5; i++ {
		identity := identities[i]
		id := uuid.New()
		tenant := org
		if identity.ClusterID == foreign {
			tenant = foreignOrg
		}
		if _, err := pool.Exec(ctx, `INSERT INTO runtime_threats(id,org_id,cluster_id,workload_id,namespace,threat_id,severity,reported_at) VALUES($1,$2,$3,$4,'operations',2022,2,NOW())`, id, tenant, identity.ClusterID, identity.Workload); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO runtime_pcap_captures(id,org_id,cluster_id,workload,namespace,requested_by) VALUES($1,$2,$3,$4,'operations',$5)`, id, tenant, identity.ClusterID, identity.Workload, uuid.New()); err != nil {
			t.Fatal(err)
		}
		records = append(records, record{id, identity, expected[i]})
	}
	request := func(path string, handle http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		result := httptest.NewRecorder()
		handle(result, req)
		return result
	}
	threats, pcap := NewRuntimeThreats(database), NewPcapHTTP(database)
	for _, inventory := range []struct {
		path, key string
		list, get http.HandlerFunc
	}{
		{"/api/v1/runtime-threats", "threats", threats.List, threats.Get},
		{"/api/v1/runtime-pcap", "captures", pcap.List, pcap.Get},
	} {
		t.Run(inventory.key, func(t *testing.T) {
			result := request(inventory.path, inventory.list)
			if result.Code != http.StatusOK {
				t.Fatalf("list %d: %s", result.Code, result.Body.String())
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			var rows []map[string]any
			if err := json.Unmarshal(body[inventory.key], &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 4 {
				t.Fatalf("tenant list returned %d rows", len(rows))
			}
			byID := map[string]map[string]any{}
			for _, row := range rows {
				byID[row["id"].(string)] = row
			}
			for _, record := range records {
				detail := request(inventory.path+"/"+record.id.String(), inventory.get)
				if record.identity.ClusterID == foreign {
					if detail.Code != http.StatusNotFound {
						t.Fatalf("foreign detail=%d", detail.Code)
					}
					continue
				}
				if detail.Code != http.StatusOK {
					t.Fatalf("get %d: %s", detail.Code, detail.Body.String())
				}
				var row map[string]any
				if err := json.Unmarshal(detail.Body.Bytes(), &row); err != nil {
					t.Fatal(err)
				}
				for _, got := range []map[string]any{row, byID[record.id.String()]} {
					role, classified := got["platform_role"].(string)
					if !classified {
						t.Fatalf("modern evidence must include an explicit evaluated role: %#v", got)
					}
					if role != record.role {
						t.Fatalf("role %v expected %q: %#v", role, record.role, got)
					}
				}
			}
			result = request(inventory.path+"?cluster_id="+sibling.String(), inventory.list)
			if result.Code != http.StatusOK {
				t.Fatalf("sibling list %d", result.Code)
			}
			if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			rows = nil // JSON unmarshalling reuses existing maps without removing omitted fields.
			if err := json.Unmarshal(body[inventory.key], &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0]["platform_role"] != "" {
				t.Fatalf("sibling inherited role: %#v", rows)
			}
		})
	}
}
