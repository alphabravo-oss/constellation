package runtime

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
	"github.com/google/uuid"
)

func TestBaselineInventoryReadOnlyFullCohortAndBundle(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := t.Context()
	org, foreign, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []uuid.UUID{org, foreign} {
		exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "baseline-inventory-"+id.String())
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign) })
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreignCluster, foreign)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) SELECT $1,$2,'apps','app-'||lpad(seq::text,4,'0'),'Deployment','{}'::jsonb FROM generate_series(1,601)seq`, org, cluster)
	owner, duplicate, core := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'apps','shared','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($4,$2,$3,'apps','shared','StatefulSet','{}'),
 ($5,$2,$3,'custom-install','agent','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 (gen_random_uuid(),$2,$3,'literal%_','needle%_','Deployment','{}'),
 (gen_random_uuid(),$2,$6,'apps','app-0001','Deployment','{}'),
 (gen_random_uuid(),$7,$8,'apps','foreign','Deployment','{}')`, owner, org, cluster, duplicate, core, sibling, foreign, foreignCluster)
	exec(`INSERT INTO process_baseline_states(org_id,cluster_id,workload_id,namespace,name,mode,learn_started_at) VALUES
 ($1,$2,'apps/app-0001','apps','app-0001','monitor',NOW()-INTERVAL '30 days'),
 ($1,$2,'apps/shared','apps','shared','enforce',NOW()-INTERVAL '30 days'),
 ($1,$2,'custom-install/agent','custom-install','agent','enforce',NOW()-INTERVAL '30 days')`, org, cluster)
	exec(`INSERT INTO process_profile_rules(org_id,cluster_id,workload_id,name,path,action,enabled) SELECT $1,$2,'apps/app-0001','rule-'||seq,'/bin/rule-'||seq,'allow',TRUE FROM generate_series(1,1201)seq`, org, cluster)
	exec(`INSERT INTO process_profile_rules(org_id,cluster_id,workload_id,name,path,action) VALUES($1,$2,'orphan/config','orphan-rule','/bin/orphan','deny')`, org, cluster)
	var mainOwner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM deployments WHERE org_id=$1 AND cluster_id=$2 AND namespace='apps' AND name='app-0001'`, org, cluster).Scan(&mainOwner); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES
 ($1,$2,'apps','owned','p1','apps/pod/owned','Deployment','app-0001','apps/app-0001',$3),
 ($1,$2,'apps','shared','p2','apps/pod/shared','Deployment','shared','apps/shared',$4),
 ($1,$5,'apps','sibling','p3','apps/pod/sibling','Deployment','app-0001','apps/app-0001',$3)`, org, cluster, mainOwner, owner, sibling)
	exec(`INSERT INTO events(org_id,cluster_id,node_id,workload_id,kind,source,severity,verdict,payload,at)
 SELECT $1,$2,'node','apps/app-0001','process_exec','test','high','alert',jsonb_build_object('comm','proc-'||seq,'filename','/bin/proc-'||seq),NOW()-seq*INTERVAL '1 second' FROM generate_series(1,1501)seq`, org, cluster)
	exec(`INSERT INTO events(org_id,cluster_id,node_id,workload_id,kind,source,severity,verdict,payload,at) VALUES
 ($1,$2,'node','apps/app-0001','process_exec','test','info','observed','{"comm":"older-safe","filename":"/bin/older-safe","exe_sha256":"\u00a0old-hash\t","parent_name":"\u2003old-parent\r"}',NOW()-INTERVAL '2 days'),
 ($1,$2,'node','apps/app-0001','process_exec','test','info','observed','{"comm":"retired-safe","filename":"/bin/retired-safe"}',NOW()-INTERVAL '3 days'),
 ($1,$2,'node','apps/app-0001','process_exec','test','info','observed','{"comm":"older-safe","filename":"/bin/older-safe"}',NOW()),
 ($1,$2,'node','apps/pod/owned','process_exec','test','info','block','{"comm":"pod-owned","filename":"/bin/pod-owned"}',NOW()),
 ($1,$2,'node','apps/shared','process_exec','test','info','observed','{"comm":"canonical"}',NOW()),
 ($1,$2,'node','apps/pod/shared','process_exec','test','high','alert','{"comm":"ambiguous-pod"}',NOW()),
 ($1,$3,'node','apps/app-0001','process_exec','test','high','alert','{"comm":"sibling-event"}',NOW()),
 ($4,$2,'node','apps/app-0001','process_exec','test','high','alert','{"comm":"foreign-event"}',NOW())`, org, cluster, sibling, foreign)
	h := NewBaselines(d, nil)
	request := func(query string, export bool, status int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}), http.MethodGet, "/runtime/baselines/inventory?"+query, nil)
		w := httptest.NewRecorder()
		if export {
			h.InventoryCSV(w, r)
		} else {
			h.Inventory(w, r)
		}
		if w.Code != status {
			t.Fatalf("%s export=%t status%d %s", query, export, w.Code, w.Body.String())
		}
		return w
	}
	type response struct {
		Profiles       []baselineInventoryRow
		Total          int
		HasMore        bool `json:"has_more"`
		Summary        map[string]int64
		Namespaces     []string
		SourceComplete bool   `json:"source_complete"`
		SummaryScope   string `json:"summary_scope"`
	}
	read := func(query string) response {
		t.Helper()
		var data response
		if err := json.Unmarshal(request("cluster_id="+cluster.String()+"&"+query, false, 200).Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	const total = 605
	before := 0
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_baseline_states WHERE org_id=$1`, org).Scan(&before); err != nil {
		t.Fatal(err)
	}
	first := read("limit=100&sort=processes&order=desc")
	if first.Total != total || len(first.Profiles) != 100 || !first.HasMore || first.Summary["total"] != total || first.Summary["monitor"] != 1 || first.Summary["enforce"] != 2 || first.Summary["learn"] != 602 || first.Summary["processes"] != 1505 || first.Summary["alerts_24h"] != 1501 || first.Summary["blocks_24h"] != 1 || first.Summary["rules"] != 1202 || first.Summary["ambiguous_owners"] != 1 || !first.SourceComplete || first.SummaryScope != "matching_retained_process_events" {
		t.Fatalf("full summary %+v", first)
	}
	top := first.Profiles[0]
	if top.WorkloadID != "apps/app-0001" || top.LearnedProcessesCount != 1504 || top.RuleCount != 1201 || top.OwnerCount != 1 || top.LastNewProcessAt == "" {
		t.Fatalf("top %+v", top)
	}
	shared := read("q=shared")
	if shared.Total != 1 || shared.Profiles[0].OwnerCount != 2 || !shared.Profiles[0].OwnerAmbiguous || shared.Profiles[0].PlatformRole != "" || shared.Profiles[0].LearnedProcessesCount != 1 {
		t.Fatalf("dedupe/ambiguity %+v", shared)
	}
	hidden := read("hide_platform=true&limit=1")
	if hidden.Total != 604 || hidden.Summary["enforce"] != 1 {
		t.Fatalf("pre-page role %+v", hidden)
	}
	needle := read("q=" + url.QueryEscape("needle%_") + "&namespace=" + url.QueryEscape("literal%_"))
	if needle.Total != 1 || needle.Profiles[0].WorkloadID != "literal%_/needle%_" || len(needle.Namespaces) < 4 {
		t.Fatalf("literal/facets %+v", needle)
	}
	tail := read("offset=600&limit=100")
	if len(tail.Profiles) != 5 || tail.HasMore || tail.Summary["rules"] != 1202 {
		t.Fatalf("tail %+v", tail)
	}
	empty := read("offset=" + strconv.Itoa(inventorylist.MaxOffset))
	if len(empty.Profiles) != 0 || empty.Total != total || empty.Summary["processes"] != 1505 {
		t.Fatalf("high offset %+v", empty)
	}
	records, err := csv.NewReader(request("cluster_id="+cluster.String()+"&offset="+strconv.Itoa(inventorylist.MaxOffset)+"&limit=1&sort=processes&order=desc", true, 200).Body).ReadAll()
	if err != nil || len(records) != total+1 || records[1][2] != "apps/app-0001" || records[1][10] != "1504" {
		t.Fatalf("CSV rows%d err%v", len(records), err)
	}
	after := 0
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_baseline_states WHERE org_id=$1`, org).Scan(&after); err != nil || before != after {
		t.Fatalf("inventory mutated state before%d after%d %v", before, after, err)
	}
	for _, query := range []string{"", "cluster_id=bad", "cluster_id=" + foreignCluster.String(), "cluster_id=" + uuid.New().String()} {
		status := 400
		if strings.HasPrefix(query, "cluster_id=") && !strings.HasSuffix(query, "bad") {
			status = 404
		}
		for _, export := range []bool{false, true} {
			request(query, export, status)
		}
	}
	for _, query := range []string{"limit=0", "limit=501", "offset=-1", "offset=" + strconv.Itoa(inventorylist.MaxOffset+1), "sort=bad", "order=bad", "mode=bad", "hide_platform=maybe", "q=a&q=b"} {
		for _, export := range []bool{false, true} {
			request("cluster_id="+cluster.String()+"&"+query, export, 400)
		}
	}
	// Agent source remains uncapped and read-only even though Inventory never lazily
	// creates learn states. Older retained identities and authored pins remain intact.
	r := httptest.NewRequestWithContext(handler.WithRuntimeAgentToken(ctx, &handler.RuntimeAgentToken{OrgID: org}), http.MethodGet, "/runtime/process-baselines:bundle?cluster_id="+cluster.String(), nil)
	w := httptest.NewRecorder()
	h.AgentBaselineBundle(w, r)
	if w.Code != 200 {
		t.Fatalf("bundle %d %s", w.Code, w.Body.String())
	}
	var bundle processBaselineBundleDTO
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if len(bundle.Rows) != total {
		t.Fatalf("bundle capped/missing %d", len(bundle.Rows))
	}
	found := false
	for _, row := range bundle.Rows {
		if row.WorkloadID == "apps/app-0001" {
			if len(row.Processes) != 1504 || len(row.Entries) != 2705 {
				t.Fatalf("complete bundle processes%d entries%d", len(row.Processes), len(row.Entries))
			}
			for _, entry := range row.Entries {
				if entry.Basename == "older-safe" {
					found = true
					if entry.Sha256 != "old-hash" || entry.ParentName != "old-parent" {
						t.Fatalf("weakened established pins %+v", entry)
					}
				}
			}
		}
		if row.WorkloadID == "apps/shared" && (len(row.PodWorkloadIDs) != 0 || len(row.Processes) != 1) {
			t.Fatalf("ambiguous bundle attribution %+v", row)
		}
	}
	if !found {
		t.Fatal("older allowed identity was dropped")
	}
	fresh := NewBaselines(d, nil)
	if err := fresh.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	mode, allowed, ok := fresh.BaselineModeForCluster(org, cluster, "apps/app-0001")
	if !ok || mode != baseline.ModeMonitor {
		t.Fatalf("mode %s %t", mode, ok)
	}
	if _, ok := allowed["retired-safe"]; !ok {
		t.Fatal("restart cache lost retained older allowed identity")
	}
	// Exact authoring never resolves an arbitrary owner of a shared name.
	for _, endpoint := range []struct{ method, path, body string }{
		{"GET", "/runtime/baselines/apps%2Fshared", ""},
		{"POST", "/runtime/baselines/apps%2Fshared/mode", `{"mode":"monitor","expected_mode":"enforce","reason":"reviewed"}`},
		{"POST", "/runtime/baselines/apps%2Fshared/rules", `{"name":"reviewed","path":"/bin/reviewed","action":"allow"}`},
		{"PUT", "/runtime/baselines/apps%2Fshared/rules/missing", `{"name":"reviewed","path":"/bin/reviewed","action":"deny"}`},
	} {
		request := baselineRequest(endpoint.method, endpoint.path+"?cluster_id="+cluster.String(), "apps/shared", bytes.NewReader([]byte(endpoint.body)), org, uuid.New())
		response := httptest.NewRecorder()
		switch {
		case endpoint.method == "GET":
			h.Get(response, request)
		case strings.HasSuffix(endpoint.path, "/mode"):
			h.SetMode(response, request)
		case endpoint.method == "POST":
			h.CreateRule(response, request)
		default:
			h.UpdateRule(response, request)
		}
		if response.Code != 409 {
			t.Fatalf("ambiguous %s %s status%d %s", endpoint.method, endpoint.path, response.Code, response.Body.String())
		}
	}
	// A detail read keeps its sample DTO but refreshes the full cached allowed set.
	detailResponse := httptest.NewRecorder()
	h.Get(detailResponse, baselineRequest("GET", "/runtime/baselines/apps%2Fapp-0001?cluster_id="+cluster.String(), "apps/app-0001", nil, org, uuid.New()))
	if detailResponse.Code != 200 {
		t.Fatalf("detail %d %s", detailResponse.Code, detailResponse.Body.String())
	}
	var detail baselineDetailDTO
	if err := json.Unmarshal(detailResponse.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	for _, process := range detail.Processes {
		if process.Name == "retired-safe" {
			t.Fatal("detail unexpectedly changed its sampled contract")
		}
	}
	_, currentAllowed, _ := h.BaselineModeForCluster(org, cluster, "apps/app-0001")
	if _, ok := currentAllowed["retired-safe"]; !ok {
		t.Fatal("detail refresh replaced full allowed cache with the UI sample")
	}

	actor := uuid.New()
	exec(`INSERT INTO users(id,org_id,email,display_name,password_hash) VALUES($1,$2,$3,'reviewer','x')`, actor, org, actor.String()+"@baseline.test")
	modeResponse := httptest.NewRecorder()
	h.SetMode(modeResponse, baselineRequest("POST", "/runtime/baselines/apps%2Fapp-0001/mode?cluster_id="+cluster.String(), "apps/app-0001", bytes.NewReader([]byte(`{"mode":"enforce","expected_mode":"monitor","reason":"reviewed full retained identities"}`)), org, actor))
	if modeResponse.Code != 200 {
		t.Fatalf("mode %d %s", modeResponse.Code, modeResponse.Body.String())
	}
	currentMode, currentAllowed, ok := h.BaselineModeForCluster(org, cluster, "apps/app-0001")
	if !ok || currentMode != baseline.ModeEnforce {
		t.Fatalf("cached mode lost %s %t", currentMode, ok)
	}
	if _, ok := currentAllowed["retired-safe"]; !ok {
		t.Fatal("mode transition replaced full allowed cache with the UI sample")
	}

}
