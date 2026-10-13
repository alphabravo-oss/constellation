package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestDeploymentFindingOptionsStrictContract(t *testing.T) {
	cluster := uuid.New().String()
	base := "cluster_id=" + cluster
	o, err := parseDeploymentFindingOptions(url.Values{"cluster_id": {cluster}})
	if err != nil || o.Lifecycle != "open" || o.Limit != 100 || o.Sort != "risk" || o.Order != "desc" || o.Offset != 0 {
		t.Fatalf("default options %+v %v", o, err)
	}
	values, _ := url.ParseQuery(base + "&q=%20Needle%25_%20&lifecycle=%20all%20&severity=all&fixable=all&offset=" + strconv.Itoa(inventorylist.MaxOffset))
	o, err = parseDeploymentFindingOptions(values)
	if err != nil || o.Query != "needle%_" || o.Lifecycle != "all" || o.Severity != "" || o.Fixable != "" || o.Offset != inventorylist.MaxOffset {
		t.Fatalf("normalized options %+v %v", o, err)
	}
	for _, query := range []string{"", "cluster_id=", "cluster_id=bad", base + "&cluster_id=" + cluster,
		base + "&q=a&q=b", base + "&limit=", base + "&limit=-1", base + "&limit=0", base + "&limit=501", base + "&limit=1.5",
		base + "&offset=", base + "&offset=-1", base + "&offset=2147483648", base + "&offset=9999999999999999999999", base + "&offset=no",
		base + "&sort=evil", base + "&order=evil", base + "&severity=severe", base + "&lifecycle=gone", base + "&fixable=1"} {
		values, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = parseDeploymentFindingOptions(values); err == nil {
			t.Fatalf("accepted invalid query %q", query)
		}
	}
}

func TestDeploymentFindingsInventoryFullSourceOwnershipAndExport(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreign, cluster, sibling, foreignCluster, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	main, other, sharedA, sharedB, solo, siblingDep, foreignDep := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'inventory'),($2::uuid,$2::text,'foreign')`, org, foreign)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id IN($1,$2)`, org, foreign)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$4,'main'),($2,$4,'sibling'),($3,$5,'foreign')`, cluster, sibling, foreignCluster, org, foreign)
	exec(`INSERT INTO assets(id,org_id,cluster_id,kind,name) VALUES($1,$2,$3,'workload','api')`, asset, org, cluster)
	exec(`INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$8,$9,'prod','api','Deployment','{}'),($2,$8,$9,'prod','other','Deployment','{}'),
 ($3,$8,$9,'custom-install','agent','Deployment','{"helm.sh/chart":"constellation-1.0"}'),
 ($4,$8,$9,'custom-install','agent','StatefulSet','{}'),
 ($5,$8,$9,'custom-install','solo','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($6,$8,$10,'prod','api','Deployment','{}'),($7,$11,$12,'prod','api','Deployment','{}')`,
		main, other, sharedA, sharedB, solo, siblingDep, foreignDep, org, cluster, sibling, foreign, foreignCluster)
	exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,external_id,title,severity,risk_score,lifecycle,target_type,target_ref,detail_json,last_seen_at)
 SELECT $1,$2,$3,'vulnerability','CVE-2099-'||n,CASE WHEN n=1305 THEN 'needle%_literal' ELSE 'Finding '||n END,
 CASE WHEN n%3=0 THEN 'critical' ELSE 'high' END,n%101,'open','workload','prod/api',
 jsonb_build_object('package',jsonb_build_object('name','lib-'||n,'version','1.0'),'fixed',CASE WHEN n%4=0 THEN '2.0' ELSE '' END),'2026-10-12'
 FROM generate_series(1,1305)n`, org, cluster, asset)
	duplicate := uuid.New()
	exec(`INSERT INTO findings(id,first_seen_at,org_id,cluster_id,asset_id,kind,title,severity,risk_score,lifecycle,target_type,target_ref,last_seen_at)
 VALUES($1,'2026-09-01',$2,$3,$4,'runtime','Repeated physical UUID','medium',10,'open','workload','prod/api','2026-10-12'),
 ($1,'2026-10-01',$2,$3,$4,'runtime','Repeated physical UUID','medium',10,'open','workload','prod/api','2026-10-12')`, duplicate, org, cluster, asset)
	pod := func(orgID, clusterID, deployment uuid.UUID, namespace, name, owner, uid string) {
		t.Helper()
		exec(`INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id)
 VALUES($1,$2,$3,$4,$5,$3||'/pod/'||$4,'Deployment',$6,$3||'/'||$6,$7)`, orgID, clusterID, namespace, name, uid, owner, deployment)
	}
	pod(org, cluster, main, "prod", "api-unique", "api", "unique-1")
	pod(org, cluster, main, "prod", "api-unique", "api", "unique-2") // repeated same owner is not ambiguous
	pod(org, cluster, main, "prod", "api-ambiguous", "api", "ambiguous-main")
	pod(org, cluster, other, "prod", "api-ambiguous", "other", "ambiguous-other")
	pod(org, cluster, other, "prod", "api-prefix", "other", "owned-other")
	pod(org, sibling, siblingDep, "prod", "api-unique", "api", "sibling-pod")
	pod(foreign, foreignCluster, foreignDep, "prod", "api-unique", "api", "foreign-pod")
	pod(org, cluster, siblingDep, "prod", "api-unique", "api", "malformed-sibling-owner")
	pod(org, cluster, foreignDep, "prod", "api-unique", "api", "malformed-foreign-owner")
	// Malformed link references must not be accepted merely because deployment ID
	// matches; the canonical owner, namespace and cluster must all agree.
	pod(org, cluster, main, "prod", "api-bad-owner", "other", "bad-owner")
	pod(org, cluster, main, "wrong-ns", "api-wrong-ns", "api", "wrong-namespace")
	pod(org, cluster, main, "prod", "10.1.2.3", "api", "ip-pseudo-pod")
	pod(org, cluster, sharedA, "custom-install", "agent-unique", "agent", "shared-kind-a")
	pod(org, cluster, sharedA, "custom-install", "agent-ambiguous", "agent", "shared-ambiguous-a")
	pod(org, cluster, sharedB, "custom-install", "agent-ambiguous", "agent", "shared-ambiguous-b")

	insert := func(reporting, target *uuid.UUID, ref, title, severity, lifecycle, kind, targetType string) {
		t.Helper()
		exec(`INSERT INTO findings(org_id,cluster_id,target_cluster_id,asset_id,kind,title,severity,risk_score,lifecycle,target_type,target_ref,last_seen_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,5,$8,$9,$10,'2026-10-12')`, org, reporting, target, asset, kind, title, severity, lifecycle, targetType, ref)
	}
	insert(&cluster, nil, "prod/pod/api-unique", "exact pod", "info", "open", "runtime", "workload")
	insert(&sibling, &cluster, "prod/api", "effective target wins", "low", "open", "runtime", "workload")
	insert(nil, &cluster, "prod/api", "null reporting cluster", "low", "open", "runtime", "workload")
	insert(&cluster, nil, "prod/api", "resolved record", "high", "resolved", "runtime", "workload")
	insert(&cluster, nil, "prod/api", "accepted record", "medium", "accepted", "runtime", "workload")
	insert(&cluster, nil, "prod/api", "retained legacy lifecycle", "medium", "legacy_hold", "runtime", "workload")
	for _, ref := range []string{"prod/pod/api-ambiguous", "prod/pod/api-prefix", "prod/pod/api-guessed", "prod/pod/api-bad-owner", "wrong-ns/pod/api-wrong-ns", "prod/pod/10.1.2.3", "prod/not-api"} {
		insert(&cluster, nil, ref, "excluded "+ref, "critical", "open", "runtime", "workload")
	}
	insert(&cluster, &sibling, "prod/api", "target override to sibling", "critical", "open", "runtime", "workload")
	insert(&sibling, nil, "prod/api", "sibling cluster", "critical", "open", "runtime", "workload")
	insert(nil, nil, "prod/api", "null effective cluster", "critical", "open", "runtime", "workload")
	insert(&cluster, nil, "prod/api", "different target type", "critical", "open", "vulnerability", "image-workload")
	exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,title,severity,lifecycle,target_type,target_ref) VALUES($1,$2,$3,'runtime','foreign tenant','critical','open','workload','prod/api')`, foreign, cluster, asset)
	insert(&cluster, nil, "custom-install/agent", "shared canonical", "high", "open", "runtime", "workload")
	insert(&cluster, nil, "custom-install/pod/agent-unique", "shared name uniquely owned pod", "high", "open", "runtime", "workload")
	insert(&cluster, nil, "custom-install/pod/agent-ambiguous", "shared ambiguous pod", "critical", "open", "runtime", "workload")
	insert(&cluster, nil, "custom-install/solo", "classified canonical", "high", "open", "runtime", "workload")
	insert(&sibling, &cluster, "custom-install/solo", "unknown cross-cluster role", "high", "open", "runtime", "workload")
	insert(nil, &cluster, "custom-install/solo", "unknown missing-source role", "high", "open", "runtime", "workload")
	exec(`UPDATE findings SET detail_json='{"package_name":"root-package-needle","package_version":"root-version-needle","fixed_version":"root-fixed-needle"}' WHERE org_id=$1 AND title='resolved record'`, org)
	exec(`UPDATE findings SET detail_json='{"package":{"Name":"upper-package-needle","Version":"upper-version-needle"},"affected_range":{"fixed_version":"upper-fixed-needle"}}' WHERE org_id=$1 AND title='accepted record'`, org)
	exec(`UPDATE findings SET detail_json='{"affected_range":{"package_name":"range-package-needle","fixed_version":"range-fixed-needle"}}' WHERE org_id=$1 AND title='shared canonical'`, org)

	h := NewDeployments(d, nil)
	request := func(id uuid.UUID, query string, export, auth bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", "/deployments/"+id.String()+"/findings?"+query, nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", id.String())
		r = r.WithContext(context.WithValue(ctx, chi.RouteCtxKey, route))
		if auth {
			r = r.WithContext(WithSubject(r.Context(), Subject{OrgID: org}))
		}
		w := httptest.NewRecorder()
		if export {
			h.FindingsCSV(w, r)
		} else {
			h.FindingsInventory(w, r)
		}
		return w
	}
	type page struct {
		Items []DeploymentFindingInstance `json:"items"`
		inventorylist.Metadata
		DeploymentID   uuid.UUID                `json:"deployment_id"`
		ClusterID      uuid.UUID                `json:"cluster_id"`
		WorkloadID     string                   `json:"workload_id"`
		OwnerCount     int                      `json:"owner_count"`
		OwnerAmbiguous bool                     `json:"owner_ambiguous"`
		Filters        deploymentFindingFilters `json:"filters"`
		SourceComplete bool                     `json:"source_complete"`
		SummaryScope   string                   `json:"summary_scope"`
	}
	base := "cluster_id=" + cluster.String()
	read := func(id uuid.UUID, query string) page {
		t.Helper()
		w := request(id, base+query, false, true)
		if w.Code != 200 {
			t.Fatalf("read %d: %s", w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := read(main, "")
	if p.Total != 1310 || len(p.Items) != 100 || !p.HasMore || p.Summary["critical"] != 435 || p.Summary["high"] != 870 || p.Summary["fixable"] != 326 || p.Summary["canonical"] != 1309 || p.Summary["pod"] != 1 || p.Summary["open"] != 1310 || p.Summary["other_lifecycle"] != 0 {
		t.Fatalf("metadata %+v", p.Metadata)
	}
	if p.ClusterID != cluster || p.DeploymentID != main || p.WorkloadID != "prod/api" || p.OwnerCount != 1 || p.OwnerAmbiguous || !p.SourceComplete || p.SummaryScope != "matching_direct_workload_findings" || p.Filters.Lifecycle != "open" {
		t.Fatalf("scope %+v", p)
	}
	seen := map[string]bool{}
	for offset := 0; offset < 1400; offset += 100 {
		p = read(main, "&offset="+strconv.Itoa(offset))
		for _, item := range p.Items {
			if seen[item.RowID] || item.EffectiveTargetClusterID != cluster || item.TargetType != "workload" || item.OwnerCount != 1 || item.OwnerAmbiguous {
				t.Fatalf("wrong instance or scope %+v", item)
			}
			seen[item.RowID] = true
		}
	}
	if len(seen) != 1310 {
		t.Fatalf("continuation got %d instances", len(seen))
	}
	p = read(main, "&offset="+strconv.Itoa(inventorylist.MaxOffset))
	if p.Total != 1310 || len(p.Items) != 0 || p.HasMore || p.Summary["fixable"] != 326 || p.OwnerCount != 1 {
		t.Fatal("empty deep page lost full cohort or ownership")
	}
	p = read(main, "&q=%20NEEDLE%25_%20")
	if p.Total != 1 || p.Items[0].Title != "needle%_literal" || p.Filters.Query != "needle%_" {
		t.Fatal("tail search is not literal, normalized and complete")
	}
	p = read(main, "&severity=critical&fixable=true&sort=package&order=asc")
	if p.Total != 108 || p.Summary["critical"] != 108 || p.Summary["fixable"] != 108 {
		t.Fatalf("filters %+v", p.Metadata)
	}
	p = read(main, "&lifecycle=all&severity=all&fixable=all")
	if p.Total != 1313 || p.Summary["resolved"] != 1 || p.Summary["accepted"] != 1 || p.Summary["other_lifecycle"] != 1 || p.Filters.Lifecycle != "all" || p.Filters.Severity != "" || p.Filters.Fixable != "" {
		t.Fatalf("all lifecycle %+v", p.Metadata)
	}
	p = read(main, "&lifecycle=all&q=retained%20legacy")
	if p.Total != 1 || p.Items[0].Lifecycle != "legacy_hold" || p.Summary["other_lifecycle"] != 1 {
		t.Fatal("all lifecycle inventory lost a retained legacy lifecycle value")
	}
	if p := read(main, "&q=retained%20legacy"); p.Total != 0 || p.Summary["other_lifecycle"] != 0 {
		t.Fatal("default open cohort included a legacy lifecycle value")
	}
	p = read(main, "&lifecycle=resolved")
	if p.Total != 1 || p.Items[0].Title != "resolved record" {
		t.Fatal("lifecycle filter differs")
	}
	for _, term := range []string{"root-package-needle", "root-version-needle", "root-fixed-needle", "upper-package-needle", "upper-version-needle", "upper-fixed-needle"} {
		p = read(main, "&lifecycle=all&q="+term+"&fixable=true")
		if p.Total != 1 || !p.Items[0].Fixable || p.Items[0].PackageName == "" || p.Items[0].PackageVersion == "" {
			t.Fatalf("legacy package metadata search %s %+v", term, p.Items)
		}
	}
	p = read(sharedA, "&q=range-package-needle&fixable=true")
	if p.Total != 1 || p.Items[0].PackageName != "range-package-needle" || p.Items[0].FixedVersion != "range-fixed-needle" {
		t.Fatal("affected-range package metadata search differs")
	}
	p = read(main, "&q=repeated&sort=first_seen&order=asc")
	if p.Total != 2 || p.Items[0].ID != duplicate || p.Items[1].ID != duplicate || p.Items[0].RowID == p.Items[1].RowID || !p.Items[0].FirstSeenAt.Before(p.Items[1].FirstSeenAt) {
		t.Fatal("partition identity lost or first-seen order wrong")
	}
	for _, order := range []string{"asc", "desc"} {
		p = read(main, "&sort=risk&order="+order)
		for i := 1; i < len(p.Items); i++ {
			left, right := p.Items[i-1], p.Items[i]
			if order == "asc" && left.RiskScore > right.RiskScore || order == "desc" && left.RiskScore < right.RiskScore || left.RiskScore == right.RiskScore && left.ID.String() > right.ID.String() {
				t.Fatal("risk order/tie is not deterministic")
			}
		}
	}
	p = read(main, "&q=effective%20target")
	if p.Total != 1 || p.Items[0].SourceClusterID == nil || *p.Items[0].SourceClusterID != sibling || p.Items[0].TargetClusterID == nil || *p.Items[0].TargetClusterID != cluster || p.Items[0].PlatformRole != "" {
		t.Fatal("effective target precedence/source attribution differs")
	}
	p = read(sharedA, "")
	if p.Total != 2 || p.OwnerCount != 2 || !p.OwnerAmbiguous || p.Summary["ambiguous_owners"] != 1 || p.Summary["pod"] != 1 {
		t.Fatalf("shared ownership %+v", p)
	}
	for _, item := range p.Items {
		if item.Attribution == "canonical" && (item.OwnerCount != 2 || !item.OwnerAmbiguous || item.PlatformRole != "") || item.Attribution == "pod" && (item.OwnerCount != 1 || item.OwnerAmbiguous || item.PlatformRole != "core") {
			t.Fatalf("arbitrary owner classification %+v", item)
		}
	}
	p = read(sharedB, "")
	if p.Total != 1 || p.Items[0].Attribution != "canonical" || !p.OwnerAmbiguous {
		t.Fatal("pod belonging to another kind substituted for shared canonical owner")
	}
	p = read(solo, "")
	if p.Total != 3 {
		t.Fatal("source/effective cluster cohort changed")
	}
	for _, item := range p.Items {
		if item.Title == "classified canonical" && item.PlatformRole != "core" || item.Title != "classified canonical" && item.PlatformRole != "" {
			t.Fatalf("source/target role borrowed %+v", item)
		}
	}
	w := request(main, base+"&offset="+strconv.Itoa(inventorylist.MaxOffset)+"&limit=1&sort=first_seen&order=asc", true, true)
	if w.Code != 200 || w.Header().Get("X-Export-Total") != "1310" || w.Header().Get("X-Export-Limit") != "100000" || w.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("CSV %d %s", w.Code, w.Body.String())
	}
	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(records) != 1311 || records[0][0] != "Instance row ID" || records[0][9] != "Source cluster ID" || records[0][11] != "Effective target cluster ID" || records[0][24] != "Platform role" {
		t.Fatalf("CSV rows %d err %v", len(records), err)
	}
	seen = map[string]bool{}
	var last time.Time
	for _, record := range records[1:] {
		first, err := time.Parse(time.RFC3339Nano, record[22])
		if err != nil || seen[record[0]] || record[2] != main.String() || record[3] != cluster.String() || record[11] != cluster.String() || first.Before(last) {
			t.Fatal("CSV ordering, identity or exact scope differs")
		}
		last = first
		seen[record[0]] = true
	}
	w = request(main, base+"&q=needle%25_&severity=critical&fixable=false", true, true)
	records, err = csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(records) != 2 || records[1][14] != "needle%_literal" || w.Header().Get("X-Export-Total") != "1" {
		t.Fatal("matching filtered CSV differs from page cohort")
	}
	w = request(main, base+"&lifecycle=all&q=retained%20legacy", true, true)
	records, err = csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(records) != 2 || records[1][17] != "legacy_hold" || w.Header().Get("X-Export-Total") != "1" {
		t.Fatal("matching all lifecycle CSV lost the retained legacy value")
	}
	for _, export := range []bool{false, true} {
		for _, test := range []struct {
			id    uuid.UUID
			query string
			auth  bool
			code  int
		}{{main, base, false, 401}, {foreignDep, "cluster_id=" + foreignCluster.String(), true, 404}, {main, "cluster_id=" + sibling.String(), true, 404},
			{main, "cluster_id=" + foreignCluster.String(), true, 404}, {uuid.New(), base, true, 404}, {main, "", true, 400},
			{main, base + "&offset=2147483648", true, 400}, {main, base + "&limit=", true, 400}, {main, base + "&q=a&q=b", true, 400},
			{main, base + "&sort=evil", true, 400}, {main, base + "&severity=evil", true, 400}, {main, base + "&lifecycle=evil", true, 400}} {
			w = request(test.id, test.query, export, test.auth)
			if w.Code != test.code {
				t.Fatalf("scope validation export=%t want=%d got=%d: %s", export, test.code, w.Code, w.Body.String())
			}
		}
	}
}

func TestDeploymentFindingsCSVCapRetainsCompleteSummary(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, cluster, deployment, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'export cap')`, org)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	})
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main')`, cluster, org)
	exec(`INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind) VALUES($1,$2,$3,'prod','cap','Deployment')`, deployment, org, cluster)
	exec(`INSERT INTO assets(id,org_id,cluster_id,kind,name) VALUES($1,$2,$3,'workload','cap')`, asset, org, cluster)
	exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,title,severity,lifecycle,target_type,target_ref,first_seen_at,last_seen_at)
 SELECT $1,$2,$3,'runtime','Retained '||n,'high','open','workload','prod/cap','2026-10-01','2026-10-12' FROM generate_series(1,100005)n`, org, cluster, asset)
	h := NewDeployments(d, nil)
	request := func(export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/deployments/"+deployment.String()+"/findings?cluster_id="+cluster.String()+"&limit=1&offset=2147483647&sort=finding&order=asc", nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", deployment.String())
		r = r.WithContext(context.WithValue(WithSubject(ctx, Subject{OrgID: org}), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		if export {
			h.FindingsCSV(w, r)
		} else {
			h.FindingsInventory(w, r)
		}
		return w
	}
	w := request(false)
	var page struct {
		Items []DeploymentFindingInstance `json:"items"`
		inventorylist.Metadata
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || page.Total != 100005 || len(page.Items) != 0 || page.HasMore || page.Summary["high"] != 100005 {
		t.Fatalf("full source summary status=%d err=%v %+v", w.Code, err, page.Metadata)
	}
	w = request(true)
	if w.Code != 200 || w.Header().Get("X-Export-Total") != "100005" || w.Header().Get("X-Export-Limit") != "100000" || w.Header().Get("X-Export-Truncated") != "true" {
		t.Fatalf("cap metadata status=%d total=%s truncated=%s", w.Code, w.Header().Get("X-Export-Total"), w.Header().Get("X-Export-Truncated"))
	}
	reader := csv.NewReader(strings.NewReader(w.Body.String()))
	header, err := reader.Read()
	if err != nil || len(header) != len(deploymentFindingCSVHeaders) {
		t.Fatal("invalid CSV header")
	}
	count := 0
	last := ""
	for count < inventorylist.ExportLimit {
		record, err := reader.Read()
		if err != nil || record[2] != deployment.String() || record[11] != cluster.String() || strings.ToLower(record[14]) < last {
			t.Fatalf("CSV row %d scope/order err=%v", count, err)
		}
		last = strings.ToLower(record[14])
		count++
	}
	if _, err := reader.Read(); err != io.EOF {
		t.Fatalf("CSV did not end at disclosed export cap: %v", err)
	}
}
