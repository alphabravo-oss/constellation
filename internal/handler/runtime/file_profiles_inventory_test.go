//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestFileProfileFullInventoryAndConditionalDelete(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := t.Context()
	org, user, cluster, otherOrg, otherCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=ANY($1::uuid[])`, []uuid.UUID{org, otherOrg})
	})
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'File inventory'),($3,$4,'Other inventory')`, org, "file-inv-"+org.String(), otherOrg, "file-other-"+otherOrg.String())
	exec(`INSERT INTO users(id,org_id,email,display_name,password_hash) VALUES($1,$2,$3,'Reviewer','x')`, user, org, user.String()+"@example.test")
	exec(`INSERT INTO clusters(id,org_id,name,distro,state) VALUES($1,$2,'File inventory','k3s','connected'),($3,$4,'Other inventory','k3s','connected')`, cluster, org, otherCluster, otherOrg)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) SELECT $1,$2,'prod','workload-'||lpad(n::text,3,'0'),'Deployment','{}'::jsonb FROM generate_series(0,204) n`, org, cluster)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'operations','scanner','Deployment','{"app.kubernetes.io/part-of":"constellation"}'),($1,$2,'prod','shared','Deployment','{"app.kubernetes.io/part-of":"constellation"}'),($1,$2,'prod','shared','DaemonSet','{}'),($3,$4,'prod','foreign','Deployment','{}'),($1,$4,'prod','inconsistent-cluster','Deployment','{}')`, org, cluster, otherOrg, otherCluster)
	// Real retained evidence beyond the old 1000-event cap, including a linked pod.
	exec(`INSERT INTO events(org_id,cluster_id,node_id,kind,source,severity,verdict,workload_id,payload,at) SELECT $1,$2,'node','file_open','runtime-agent','high','block','prod/workload-204',jsonb_build_object('path','/etc/shadow','comm','cat'),now()-interval '1 hour' FROM generate_series(1,1205)`, org, cluster)
	var owner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM deployments WHERE org_id=$1 AND cluster_id=$2 AND name='workload-204'`, org, cluster).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,'prod','owned','owned','prod/pod/owned','Deployment','workload-204','prod/workload-204',$3)`, org, cluster, owner)
	exec(`INSERT INTO events(org_id,cluster_id,node_id,kind,source,severity,verdict,workload_id,payload,at) VALUES($1,$2,'node','file_open','runtime-agent','medium','alert','prod/pod/owned','{"path":"/tmp/owned","comm":"cat"}',now()),($1,$2,'node','file_open','runtime-agent','medium','allow','prod/shared','{"path":"/tmp/shared","comm":"cat"}',now()),($3,$2,'node','file_open','runtime-agent','high','block','prod/workload-204','{"path":"/foreign","comm":"cat"}',now()),($1,$4,'node','file_open','runtime-agent','high','block','prod/workload-204','{"path":"/other-cluster","comm":"cat"}',now())`, org, cluster, otherOrg, otherCluster)
	var shared uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM deployments WHERE org_id=$1 AND cluster_id=$2 AND name='shared' AND kind='Deployment'`, org, cluster).Scan(&shared); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,'prod','ambiguous','ambiguous','prod/pod/ambiguous','Deployment','shared','prod/shared',$3)`, org, cluster, shared)
	exec(`INSERT INTO events(org_id,cluster_id,node_id,kind,source,severity,verdict,workload_id,payload) VALUES($1,$2,'node','file_open','runtime-agent','high','block','prod/pod/ambiguous','{"path":"/not-owned","comm":"cat"}')`, org, cluster)
	h := NewFileProfiles(d, audit.New(pool))
	type response struct {
		Profiles   []fileProfileInventoryRow `json:"profiles"`
		Total      int                       `json:"total"`
		Limit      int                       `json:"limit"`
		Offset     int                       `json:"offset"`
		HasMore    bool                      `json:"has_more"`
		Summary    map[string]int            `json:"summary"`
		Namespaces []string                  `json:"namespaces"`
		Filters    map[string]any            `json:"filters"`
	}
	get := func(query string, export bool) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := baselineRequest(ctx, http.MethodGet, "/api/v1/runtime/file-profiles/inventory?cluster_id="+cluster.String()+query, "", nil, org, user)
		if export {
			h.InventoryCSV(rec, req)
		} else {
			h.Inventory(rec, req)
		}
		return rec
	}
	read := func(query string) response {
		t.Helper()
		rec := get(query, false)
		if rec.Code != 200 {
			t.Fatalf("%s: status=%d %s", query, rec.Code, rec.Body.String())
		}
		var data response
		if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Run("full summary traversal and read only", func(t *testing.T) {
		ctx := t.Context()
		ids := map[string]bool{}
		for offset := 0; offset < 208; offset += 100 {
			data := read(fmt.Sprintf("&sort=workload&order=asc&offset=%d", offset))
			if data.Total != 207 || data.Summary["alerts"] != 1206 || data.Summary["blocks"] != 1205 || data.Summary["retained_events"] != 1207 || data.Summary["ambiguous"] != 1 {
				t.Fatalf("metadata %+v", data)
			}
			for _, row := range data.Profiles {
				if ids[row.RowID] {
					t.Fatal("duplicate identity")
				}
				ids[row.RowID] = true
			}
		}
		if len(ids) != 207 {
			t.Fatalf("traversed %d", len(ids))
		}
		var states int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM file_profile_states WHERE org_id=$1`, org).Scan(&states); err != nil || states != 0 {
			t.Fatalf("GET created states=%d err=%v", states, err)
		}
	})
	t.Run("tail search and full retained pod evidence", func(t *testing.T) {
		data := read("&q=workload-204")
		if data.Total != 1 || data.Profiles[0].RetainedEvents != 1206 || data.Profiles[0].MonitoredAlerts24h != 1206 || data.Profiles[0].EnforcedBlocks24h != 1205 || data.Profiles[0].LearnedPathsCount != 2 || data.Profiles[0].SensitivePathCount != 1 {
			t.Fatalf("tail %+v", data)
		}
		if strings.Join(data.Namespaces, ",") != "operations,prod" {
			t.Fatalf("scope facets %v", data.Namespaces)
		}
		if read("&q=%25").Total != 0 {
			t.Fatal("literal percent broadened")
		}
	})
	t.Run("deduplicated ambiguous owner never borrows pod role or evidence", func(t *testing.T) {
		data := read("&q=shared")
		row := data.Profiles[0]
		if data.Total != 1 || row.OwnerCount != 2 || !row.OwnerAmbiguous || row.PlatformRole != "" || row.RetainedEvents != 1 || row.EnforcedBlocks24h != 0 {
			t.Fatalf("ambiguous %+v", row)
		}
	})
	t.Run("platform filter and matching CSV before paging", func(t *testing.T) {
		data := read("&hide_platform=true&sort=workload&order=asc")
		if data.Total != 206 {
			t.Fatalf("hide count %d", data.Total)
		}
		if read("&platform_role=core").Total != 1 {
			t.Fatal("role classification")
		}
		rec := get("&q=workload-&sort=workload&order=desc&offset=2000000&limit=1", true)
		if rec.Code != 200 {
			t.Fatalf("CSV %d %s", rec.Code, rec.Body.String())
		}
		records, err := csv.NewReader(rec.Body).ReadAll()
		if err != nil || len(records) != 206 || records[1][2] != "prod/workload-204" || records[205][2] != "prod/workload-000" || rec.Header().Get("X-Export-Total") != "205" || rec.Header().Get("X-Export-Limit") != "100000" || rec.Header().Get("X-Export-Truncated") != "false" {
			t.Fatalf("CSV rows=%d err=%v headers=%v", len(records), err, rec.Header())
		}
	})
	t.Run("deep empty continuation and strict query scope", func(t *testing.T) {
		ctx := t.Context()
		if data := read("&offset=2000000"); data.Total != 207 || len(data.Profiles) != 0 || data.HasMore {
			t.Fatalf("deep %+v", data)
		}
		for _, query := range []string{"&limit=2001", "&limit=no", "&limit=", "&offset=-1", "&offset=2147483648", "&offset=NaN", "&sort=unsupported", "&sort=image;DROP", "&order=sideways", "&mode=invalid", "&hide_platform=unknown", "&q=a&q=b"} {
			rec := get(query, false)
			if rec.Code != 400 {
				t.Errorf("%s got %d %s", query, rec.Code, rec.Body.String())
			}
		}
		for _, id := range []uuid.UUID{otherCluster, uuid.New()} {
			rec := httptest.NewRecorder()
			h.Inventory(rec, baselineRequest(ctx, http.MethodGet, "/?cluster_id="+id.String(), "", nil, org, user))
			if rec.Code != 404 {
				t.Fatalf("foreign/missing cluster=%d", rec.Code)
			}
		}
	})
	t.Run("persisted and rule-only profiles and canonical metadata without list side effects", func(t *testing.T) {
		ctx := t.Context()
		exec(`INSERT INTO file_profile_states(org_id,cluster_id,workload_id,namespace,name,mode) VALUES($1,$2,'prod/workload-000','aaa-stale','wrong','monitor'),($1,$2,'retired/saved','wrong','wrong','enforce')`, org, cluster)
		rule := uuid.New()
		exec(`INSERT INTO file_profile_rules(id,org_id,cluster_id,workload_id,filter,path,behavior) VALUES($1,$2,$3,'retired/rule-only','/rule-only','/rule-only','monitor_change')`, rule, org, cluster)
		row := read("&q=workload-000").Profiles[0]
		if row.Namespace != "prod" || row.Name != "workload-000" || row.Mode != "monitor" {
			t.Fatalf("stale metadata %+v", row)
		}
		saved := read("&namespace=retired")
		if saved.Total != 2 {
			t.Fatalf("retained profiles %+v", saved)
		}
		for _, p := range saved.Profiles {
			if p.OwnerCount != 0 || p.OwnerAmbiguous || p.Namespace != "retired" {
				t.Fatalf("orphan metadata %+v", p)
			}
		}
		rec := httptest.NewRecorder()
		h.Get(rec, baselineRequest(ctx, http.MethodGet, "/?cluster_id="+cluster.String(), "prod/shared", nil, org, user))
		if rec.Code != 409 {
			t.Fatalf("ambiguous detail %d %s", rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		_, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, org, "file-readonly-bundle-"+uuid.NewString(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO cluster_init_bundles(org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted) VALUES($1,$2,$3,now()+interval '1 hour',$4,'test','\x00'::bytea)`, org, cluster, "file-inventory-"+tokenID.String(), tokenID)
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/?cluster_id="+cluster.String(), nil)
		req = req.WithContext(handler.WithRuntimeAgentToken(ctx, &handler.RuntimeAgentToken{ID: tokenID, OrgID: org}))
		h.AgentRulesBundle(rec, req)
		if rec.Code != 200 {
			t.Fatalf("agent bundle %d %s", rec.Code, rec.Body.String())
		}
		var bundle fileProfileRuleBundleDTO
		if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
			t.Fatal(err)
		}
		if len(bundle.Rules) != 1 || bundle.Rules[0].Mode != "learn" || bundle.Rules[0].WorkloadID != "retired/rule-only" {
			t.Fatalf("default learn bundle %+v", bundle)
		}
	})
	t.Run("reviewed update preserves exact microsecond revision and rejects stale writer", func(t *testing.T) {
		ctx := t.Context()
		rule := uuid.New()
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		exec(`INSERT INTO file_profile_rules(id,org_id,cluster_id,workload_id,filter,path,behavior,updated_at) VALUES($1,$2,$3,'prod/workload-000','/update-reviewed','/update-reviewed','monitor_change',$4)`, rule, org, cluster, stamp)
		call := func(expected string) *httptest.ResponseRecorder {
			body, _ := json.Marshal(map[string]string{"reason": "reviewed edit", "description": "reviewed new description", "expected_updated_at": expected})
			rec := httptest.NewRecorder()
			h.UpdateRule(rec, fileProfileRuleRequest(ctx, http.MethodPut, "/?cluster_id="+cluster.String(), "prod/workload-000", rule.String(), bytes.NewReader(body), org, user))
			return rec
		}
		if rec := call(stamp.Add(-time.Second).Format(time.RFC3339Nano)); rec.Code != 409 {
			t.Fatalf("stale edit %d %s", rec.Code, rec.Body.String())
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='file_profile.rule.update'`, org).Scan(&count); err != nil || count != 0 {
			t.Fatalf("conflict audit count %d err %v", count, err)
		}
		rec := call(stamp.Format(time.RFC3339Nano))
		if rec.Code != 200 {
			t.Fatalf("reviewed edit %d %s", rec.Code, rec.Body.String())
		}
		var dto fileProfileRuleDTO
		if err := json.Unmarshal(rec.Body.Bytes(), &dto); err != nil {
			t.Fatal(err)
		}
		var actual time.Time
		if err := pool.QueryRow(ctx, `SELECT updated_at FROM file_profile_rules WHERE id=$1`, rule).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		got, err := time.Parse(time.RFC3339Nano, dto.UpdatedAt)
		if err != nil || !got.Equal(actual) {
			t.Fatalf("revision precision dto %s db %s", dto.UpdatedAt, actual)
		}
	})
	t.Run("reviewed delete atomic conflict no audit and competing writers", func(t *testing.T) {
		ctx := t.Context()
		rule := uuid.New()
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		exec(`INSERT INTO file_profile_rules(id,org_id,cluster_id,workload_id,filter,path,behavior,updated_at) VALUES($1,$2,$3,'prod/workload-204','/reviewed','/reviewed','monitor_change',$4)`, rule, org, cluster, stamp)
		call := func(expected string) *httptest.ResponseRecorder {
			body, _ := json.Marshal(map[string]string{"reason": "reviewed removal", "expected_updated_at": expected})
			rec := httptest.NewRecorder()
			h.DeleteRule(rec, fileProfileRuleRequest(ctx, http.MethodDelete, "/?cluster_id="+cluster.String(), "prod/workload-204", rule.String(), bytes.NewReader(body), org, user))
			return rec
		}
		if rec := call(stamp.Add(-time.Second).Format(time.RFC3339Nano)); rec.Code != 409 {
			t.Fatalf("stale delete %d %s", rec.Code, rec.Body.String())
		}
		var count int
		pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='file_profile.rule.delete'`, org).Scan(&count)
		if count != 0 {
			t.Fatalf("conflict audited %d", count)
		}
		var wg sync.WaitGroup
		codes := make(chan int, 2)
		for range 2 {
			wg.Add(1)
			go func() { defer wg.Done(); codes <- call(stamp.Format(time.RFC3339Nano)).Code }()
		}
		wg.Wait()
		close(codes)
		success := 0
		for code := range codes {
			if code == 200 {
				success++
			} else if code != 404 && code != 409 {
				t.Fatalf("race code %d", code)
			}
		}
		if success != 1 {
			t.Fatalf("winners %d", success)
		}
		pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='file_profile.rule.delete'`, org).Scan(&count)
		if count != 1 {
			t.Fatalf("audit winners %d", count)
		}
	})
}
