//go:build integration

package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestContainersServerInventoryBeyondCapFiltersCountsAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreign, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "containers-inventory-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$4,'main'),($2,$4,'sibling'),($3,$5,'foreign')`, cluster, sibling, foreignCluster, org, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,risk_factors,critical_count,high_count,labels) VALUES
 ($1,$2,'prod','app','Deployment','{"privileged":0,"run_as_root":null}',2,0,'{}'),
 ($1,$2,'custom-install','agent','Deployment','{}',5,0,'{"helm.sh/chart":"Constellation-1.2.3"}'),
 ($1,$2,'prod','big-high','Deployment','{}',0,5000,'{}'),
 ($1,$3,'prod','app','Deployment','{"privileged":1}',99,99,'{}'),
 ($4,$5,'prod','app','Deployment','{"privileged":1}',99,99,'{}')`, org, cluster, sibling, foreign, foreignCluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO host_containers(org_id,cluster_id,node,container_count,observed_at,payload) SELECT $1,$2,'node-main',3105,'2026-10-12',jsonb_build_object('items',jsonb_agg(jsonb_build_object('id','container-'||n,'name',CASE WHEN n=3105 THEN 'tail%_needle' ELSE 'app' END,'pod_namespace','prod','pod_name','app-'||lpad(n::text,4,'0'),'image','sha256:app','state','CONTAINER_RUNNING'))) FROM generate_series(1,3105)n`, org, cluster); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		o, c          uuid.UUID
		node, payload string
	}{
		{org, cluster, "node-platform", `{"items":[{"id":"platform","name":"platform","pod_namespace":"custom-install","pod_name":"agent-abc","state":"running","image":"agent"}]}`},
		{org, cluster, "node-empty", `{"items":[{"id":"","name":"same","pod_namespace":"prod","state":"running"},{"id":"","name":"same","pod_namespace":"prod","state":"running"},{"id":"big-high","name":"high-count","pod_namespace":"prod","pod_name":"big-high-abc","state":"running"},{"id":"stopped","name":"tail-stopped","pod_namespace":"prod","state":"CONTAINER_EXITED"}]}`},
		{org, sibling, "node-main", `{"items":[{"id":"sibling","name":"tail-sibling","pod_namespace":"prod","pod_name":"app-abc","state":"running"}]}`},
		{foreign, foreignCluster, "node-main", `{"items":[{"id":"foreign","name":"tail-foreign","pod_namespace":"prod","pod_name":"app-abc","state":"running"}]}`},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO host_containers(org_id,cluster_id,node,container_count,payload,observed_at) VALUES($1,$2,$3,4,$4::jsonb,'2026-10-12')`, item.o, item.c, item.node, item.payload); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) SELECT $1,$2,'custom-install','agent-abc','platform-pod','custom-install/pod/agent-abc','Deployment','agent','custom-install/agent',id FROM deployments WHERE org_id=$1 AND cluster_id=$2 AND namespace='custom-install' AND name='agent'`, org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewNodes(d)
	request := func(clusterID uuid.UUID, values url.Values, export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, "/containers?"+values.Encode(), nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", clusterID.String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		if export {
			h.ContainersCSV(w, r)
		} else {
			h.Containers(w, r)
		}
		return w
	}
	type page struct {
		Rows    []containerRow `json:"items"`
		Total   int
		HasMore bool `json:"has_more"`
		Summary map[string]int
	}
	read := func(values url.Values) page {
		t.Helper()
		w := request(cluster, values, false)
		if w.Code != 200 {
			t.Fatalf("list%d %s", w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	values := url.Values{"hide_platform": {"true"}, "limit": {"100"}, "sort": {"risk"}, "order": {"desc"}}
	first := read(values)
	if first.Total != 3108 || len(first.Rows) != 100 || !first.HasMore || first.Summary["privileged"] != 3105 || first.Summary["run_as_root"] != 3105 || first.Summary["platform_count"] != 1 || first.Rows[0].Critical != 2 {
		t.Fatalf("first %+v", first)
	}
	values.Set("offset", "3100")
	last := read(values)
	if last.Total != 3108 || len(last.Rows) != 8 || last.HasMore {
		t.Fatalf("last %+v", last)
	}
	seen := map[string]bool{}
	for _, row := range last.Rows {
		if seen[row.RowID] {
			t.Fatal("duplicate stable row identity")
		}
		seen[row.RowID] = true
	}
	values.Set("offset", "9999")
	end := read(values)
	if end.Total != 3108 || len(end.Rows) != 0 || end.HasMore || end.Summary["privileged"] != 3105 {
		t.Fatalf("empty %+v", end)
	}
	values.Del("offset")
	values.Set("q", "%_")
	deep := read(values)
	if deep.Total != 1 || deep.Rows[0].Name != "tail%_needle" || !deep.Rows[0].Privileged || !deep.Rows[0].RunAsRoot || deep.Rows[0].Critical != 2 {
		t.Fatalf("tail predicate/enrichment %+v", deep)
	}
	values.Set("namespace", "prod")
	values.Set("node", "node-main")
	w := request(cluster, values, true)
	csvRows, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || w.Code != 200 || len(csvRows) != 2 || w.Header().Get("X-Export-Total") != "1" || csvRows[1][3] != "tail%_needle" || csvRows[1][11] != "true" || csvRows[1][12] != "true" {
		t.Fatalf("filtered CSV%d rows%d err%v", w.Code, len(csvRows), err)
	}
	values = url.Values{"platform_role": {"core"}, "hide_platform": {"false"}}
	platform := read(values)
	if platform.Total != 1 || platform.Rows[0].PlatformRole != "core" || platform.Rows[0].Namespace != "custom-install" {
		t.Fatalf("custom platform %+v", platform)
	}
	w = request(cluster, values, true)
	csvRows, err = csv.NewReader(w.Body).ReadAll()
	if err != nil || len(csvRows) != 2 || csvRows[1][5] != "core" {
		t.Fatal("CSV role missing")
	}
	values = url.Values{"hide_platform": {"true"}, "sort": {"risk"}, "order": {"desc"}, "limit": {"1"}, "offset": {"9999"}}
	w = request(cluster, values, true)
	csvRows, err = csv.NewReader(w.Body).ReadAll()
	if err != nil || len(csvRows) != 3109 || w.Header().Get("X-Export-Total") != "3108" || csvRows[1][14] != "2" {
		t.Fatalf("full matching export rows%d err%v", len(csvRows), err)
	}
	values = url.Values{"node": {"node-empty"}, "hide_platform": {"false"}}
	duplicates := read(values)
	if duplicates.Total != 3 || duplicates.Rows[1].RowID == duplicates.Rows[2].RowID {
		t.Fatal("empty IDs collapsed")
	}
	repeat := read(values)
	for i, row := range duplicates.Rows {
		if row.RowID != repeat.Rows[i].RowID {
			t.Fatal("tie order unstable")
		}
	}
	for _, export := range []bool{false, true} {
		for _, query := range []url.Values{{"sort": {"bad"}}, {"order": {"bad"}}, {"platform_role": {"bad"}}, {"hide_platform": {"bad"}}} {
			if w := request(cluster, query, export); w.Code != 400 {
				t.Fatalf("invalid filters status%d", w.Code)
			}
		}
		if w := request(foreignCluster, nil, export); w.Code != 404 {
			t.Fatalf("foreign scope%d", w.Code)
		}
		if w := request(uuid.New(), nil, export); w.Code != 404 {
			t.Fatalf("missing scope%d", w.Code)
		}
	}
}

func TestContainersPlatformRoleUsesExactUnambiguousPodOwner(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreignOrg, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	platform, customer, siblingOwner, foreignOwner := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "containers-roles-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreignCluster, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels,critical_count) VALUES
 ($1,$2,$3,'custom-install','agent','Deployment','{"helm.sh/chart":"constellation-1"}',7),
 ($4,$2,$3,'custom-install','customer','Deployment','{}',0),
 ($5,$2,$6,'custom-install','agent','Deployment','{"helm.sh/chart":"constellation-1"}',99),
 ($7,$8,$9,'custom-install','agent','Deployment','{"helm.sh/chart":"constellation-1"}',99)`, platform, org, cluster, customer, siblingOwner, sibling, foreignOwner, foreignOrg, foreignCluster); err != nil {
		t.Fatal(err)
	}
	type fixture struct {
		pod, namespace, role string
		owners               []uuid.UUID
	}
	fixtures := []fixture{
		{"agent-owned", "custom-install", "core", []uuid.UUID{platform, platform}},
		{"agent-prefix-only", "custom-install", "", nil},
		{"agent-safe", "custom-install", "", []uuid.UUID{customer}},
		{"agent-ambiguous", "custom-install", "", []uuid.UUID{platform, customer}},
		{"agent-foreign", "custom-install", "", []uuid.UUID{foreignOwner}},
		{"agent-sibling", "custom-install", "", []uuid.UUID{siblingOwner}},
		{"10.42.0.2", "kube-system", "", nil},
		{"system", "kube-system", "core", nil},
	}
	items := []map[string]string{}
	for _, f := range fixtures {
		items = append(items, map[string]string{"id": f.pod, "name": f.pod, "pod_name": f.pod, "pod_namespace": f.namespace, "state": "running"})
		for _, owner := range f.owners {
			if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,$3,$4,$5,$3||'/pod/'||$4,'Deployment','agent',$3||'/agent',$6)`, org, cluster, f.namespace, f.pod, uuid.New().String(), owner); err != nil {
				t.Fatal(err)
			}
		}
	}
	payload, _ := json.Marshal(map[string]any{"items": items})
	if _, err := pool.Exec(ctx, `INSERT INTO host_containers(org_id,cluster_id,node,container_count,payload,observed_at) VALUES($1,$2,'node',8,$3::jsonb,NOW())`, org, cluster, string(payload)); err != nil {
		t.Fatal(err)
	}
	h := NewNodes(d)
	request := func(values url.Values, export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, "/containers?"+values.Encode(), nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", cluster.String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		if export {
			h.ContainersCSV(w, r)
		} else {
			h.Containers(w, r)
		}
		return w
	}
	type page struct {
		Items   []containerRow
		Total   int
		Summary map[string]int
	}
	read := func(values url.Values) page {
		t.Helper()
		w := request(values, false)
		if w.Code != 200 {
			t.Fatalf("list %d %s", w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	all := read(nil)
	if all.Total != 8 || all.Summary["platform_count"] != 2 {
		t.Fatalf("all %+v", all)
	}
	roles := map[string]string{}
	for _, row := range all.Items {
		roles[row.PodName] = row.PlatformRole
		if row.PodName == "agent-prefix-only" && row.Critical != 7 {
			t.Fatal("advisory risk attribution changed")
		}
	}
	for _, f := range fixtures {
		if role, ok := roles[f.pod]; !ok || role != f.role {
			t.Fatalf("pod %s role %q, want %q", f.pod, role, f.role)
		}
	}
	hidden := read(url.Values{"hide_platform": {"true"}})
	if hidden.Total != 6 || len(hidden.Items) != 6 || hidden.Summary["platform_count"] != 2 {
		t.Fatalf("hidden %+v", hidden)
	}
	for _, row := range hidden.Items {
		if row.PlatformRole != "" {
			t.Fatal("platform row leaked hide filter")
		}
	}
	core := read(url.Values{"platform_role": {"core"}})
	if core.Total != 2 || len(core.Items) != 2 {
		t.Fatalf("core %+v", core)
	}
	// List/count/CSV must share exact ownership filtering before the page cutoff.
	for _, values := range []url.Values{{"hide_platform": {"true"}}, {"platform_role": {"core"}}, {"q": {"agent-ambiguous"}, "platform_role": {"core"}}, {"q": {"agent-"}, "platform_role": {"none"}}} {
		p := read(values)
		w := request(values, true)
		rows, err := csv.NewReader(w.Body).ReadAll()
		if err != nil || w.Code != 200 || len(rows) != p.Total+1 || w.Header().Get("X-Export-Total") != strconv.Itoa(p.Total) {
			t.Fatalf("CSV scope list%d CSV%d rows%d err%v", p.Total, w.Code, len(rows), err)
		}
		for _, row := range rows[1:] {
			if row[5] != roles[row[6]] {
				t.Fatal("CSV role differs from exact ownership classification")
			}
		}
	}
}
