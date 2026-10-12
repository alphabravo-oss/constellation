package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/findings"
	"github.com/google/uuid"
)

func TestDashboardStrongestGroupModeDestinations(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreign, cluster, sibling, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "mode-cohort-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id IN($1,$2)`, org, foreign)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$3,'main'),($2,$3,'sibling')`, cluster, sibling, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,kind,name) VALUES($1,$2,'image','fixture')`, asset, org); err != nil {
		t.Fatal(err)
	}
	// Main: alpha belongs to discover AND protect, beta monitor, gamma discover;
	// unmatched has exposure but no group. Sibling alpha is discover only.
	for _, item := range []struct {
		org, cluster        uuid.UUID
		name, mode, members string
	}{
		{org, cluster, "learn", "discover", `["ns/alpha","ns/gamma"]`}, {org, cluster, "strong", "protect", `["ns/alpha"]`},
		{org, cluster, "watch", "monitor", `["ns/beta"]`}, {org, sibling, "sibling", "discover", `["ns/alpha"]`},
		{foreign, cluster, "foreign", "protect", `["ns/gamma","ns/beta"]`},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO groups(org_id,cluster_id,name,kind,policy_mode,members) VALUES($1,$2,$3,'ground',$4,$5::jsonb)`, item.org, item.cluster, item.name, item.mode, item.members); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		org, cluster  uuid.UUID
		name, factors string
	}{
		{org, cluster, "alpha", `{"net_exposure":0}`}, {org, cluster, "beta", `{"net_exposure":null}`}, {org, cluster, "gamma", `{"net_exposure":false}`},
		{org, cluster, "unmatched", `{"net_exposure":1}`}, {org, cluster, "no-exposure", `{}`}, {org, sibling, "alpha", `{"net_exposure":1}`}, {foreign, cluster, "alpha", `{"net_exposure":1}`}, {foreign, cluster, "gamma", `{"net_exposure":1}`},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,risk_factors) VALUES($1,$2,'ns',$3,'Deployment',$4::jsonb)`, item.org, item.cluster, item.name, item.factors); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		org, cluster     uuid.UUID
		workload, digest string
	}{
		{org, cluster, "ns/alpha", "sha256:shared"}, {org, cluster, "ns/beta", "sha256:shared"}, {org, cluster, "ns/gamma", "sha256:discover"},
		{org, cluster, "ns/unmatched", "sha256:unmatched"}, {org, sibling, "ns/alpha", "sha256:sibling"}, {foreign, cluster, "ns/gamma", "sha256:discover"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_digest) SELECT $1,$2,id,$3,namespace,name,'Deployment',$4,$4,$4 FROM deployments WHERE org_id=$1 AND cluster_id=$2 AND namespace||'/'||name=$3`, item.org, item.cluster, item.workload, item.digest); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(o, c uuid.UUID, external any, target, ref, state, kind string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,cluster_id,asset_id,external_id,target_type,target_ref,lifecycle,kind,title,severity,detail_json) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,'mode fixture','high','{"fixed":"1"}')`, o, c, asset, external, target, ref, state, kind); err != nil {
			t.Fatal(err)
		}
	}
	insert(org, cluster, "CVE-SHARED", "image-workload", "sha256:shared", "open", "vulnerability")
	insert(org, cluster, "CVE-SHARED", "image-workload", "sha256:shared", "open", "vulnerability") // instances dedup once per ID, not multiplied by two links
	insert(org, cluster, "GHSA-advisory", "image-workload", "sha256:shared", "open", "vulnerability")
	insert(org, cluster, nil, "image-workload", "sha256:shared", "open", "vulnerability") // NULL IDs not in distinct-ID source
	insert(org, cluster, "CVE-DISCOVER", "image-workload", "sha256:discover", "open", "vulnerability")
	insert(org, sibling, "CVE-SIBLING", "image-workload", "sha256:sibling", "open", "vulnerability")
	insert(foreign, cluster, "CVE-FOREIGN", "image-workload", "sha256:discover", "open", "vulnerability")
	insert(org, cluster, "CVE-UNMATCHED", "image-workload", "sha256:unmatched", "open", "vulnerability")
	insert(org, cluster, "CVE-NULL-TARGET", "image-workload", "", "open", "vulnerability")
	insert(org, cluster, "CVE-ACCEPTED", "image-workload", "sha256:shared", "accepted", "vulnerability")
	insert(org, cluster, "CVE-DUPLICATE", "workload", "sha256:shared", "open", "vulnerability")
	insert(org, cluster, "CVE-LICENSE", "image-workload", "sha256:shared", "open", "license")
	insert(org, cluster, "HOST-advisory", "host", "", "open", "vulnerability")
	insert(org, cluster, "CVE-HOST", "host", "", "open", "vulnerability")
	request := func(path string, handle http.HandlerFunc) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handle(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, value any) {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("status %d %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), value); err != nil {
			t.Fatal(err)
		}
	}
	var source dashboardSummaryDTO
	decode(request("/dashboard?cluster_id="+cluster.String(), NewDashboard(d).Summary), &source)
	f, dep := findings.NewFindings(d, nil, nil), NewDeployments(d, nil)
	for mode, want := range map[string]int{"discover": 1, "monitor": 2, "protect": 2} {
		if source.Posture.CvesByMode[mode] != want || source.Posture.ExposedByMode[mode] != 1 {
			t.Fatalf("source mode %s CVEs=%d exposure=%d", mode, source.Posture.CvesByMode[mode], source.Posture.ExposedByMode[mode])
		}
		values := url.Values{"cluster_id": {cluster.String()}, "kind": {"vulnerability"}, "lifecycle": {"open"}, "target_type": {"image-workload"}, "group_mode": {mode}, "id_scope": {"all"}, "limit": {"1"}}
		var rollup struct {
			Total int
			CVEs  []struct {
				CVE       string
				Instances int
			} `json:"cves"`
		}
		decode(request("/findings/by-cve?"+values.Encode(), f.ByCVE), &rollup)
		if rollup.Total != want || len(rollup.CVEs) != 1 {
			t.Fatalf("mode %s rollup %+v", mode, rollup)
		}
		values.Set("offset", "1")
		decode(request("/findings/by-cve?"+values.Encode(), f.ByCVE), &rollup)
		if rollup.Total != want || len(rollup.CVEs) != want-1 {
			t.Fatalf("mode %s page2 %+v", mode, rollup)
		}
		values.Del("offset")
		values.Set("limit", "100000")
		var list struct {
			Total    int
			Findings []struct{ ID string }
			Counts   map[string]int `json:"lifecycle_counts"`
		}
		decode(request("/findings?"+values.Encode(), f.List), &list)
		instances := 1
		if mode != "discover" {
			instances = 3
		}
		if list.Total != instances || len(list.Findings) != instances || list.Counts["open"] != instances {
			t.Fatalf("mode %s instances %+v", mode, list)
		}
		if mode != "discover" && list.Counts["accepted"] != 1 {
			t.Fatalf("mode lifecycle lost predicate: %+v", list)
		}
		exported := request("/findings.csv?"+values.Encode(), findings.NewFindingsCSV(d).Stream)
		records, err := csv.NewReader(exported.Body).ReadAll()
		if err != nil || exported.Code != 200 || len(records) != instances+1 {
			t.Fatalf("mode %s CSV count=%d err=%v status=%d", mode, len(records), err, exported.Code)
		}
		values = url.Values{"cluster_id": {cluster.String()}, "hide_platform": {"false"}, "risk_fact": {"net_exposure"}, "group_mode": {mode}, "limit": {"1"}}
		var deployments struct {
			Total       int
			Deployments []deploymentListRow
			Summary     deploymentListSummary
		}
		decode(request("/deployments?"+values.Encode(), dep.List), &deployments)
		if deployments.Total != 1 || len(deployments.Deployments) != 1 || deployments.Summary.Total != 1 {
			t.Fatalf("mode %s deployment %+v", mode, deployments)
		}
		exported = request("/deployments.csv?"+values.Encode(), dep.ExportCSV)
		records, err = csv.NewReader(exported.Body).ReadAll()
		if err != nil || len(records) != 2 || records[1][2] != deployments.Deployments[0].Name {
			t.Fatalf("mode %s exposure CSV wrong", mode)
		}
	}
	// Organization scope must not upgrade sibling alpha to main alpha's protect.
	decode(request("/dashboard", NewDashboard(d).Summary), &source)
	if source.Posture.CvesByMode["discover"] != 2 || source.Posture.CvesByMode["protect"] != 2 || source.Posture.ExposedByMode["discover"] != 2 || source.Posture.ExposedByMode["protect"] != 1 {
		t.Fatalf("org source crossed clusters %+v", source.Posture)
	}
	var cohort struct{ Total int }
	decode(request("/findings/by-cve?group_mode=discover&id_scope=all&lifecycle=open", f.ByCVE), &cohort)
	if cohort.Total != 2 {
		t.Fatalf("org mode destination %d", cohort.Total)
	}
	// Distinct host ID cohort includes non-CVE IDs and NULL target refs safely.
	decode(request("/findings/by-cve?cluster_id="+cluster.String()+"&target_type=host&id_scope=all&lifecycle=open", f.ByCVE), &cohort)
	if cohort.Total != 2 {
		t.Fatalf("host ID total=%d", cohort.Total)
	}
	decode(request("/findings/by-cve?cluster_id="+cluster.String()+"&target_type=host&lifecycle=open", f.ByCVE), &cohort)
	if cohort.Total != 1 {
		t.Fatalf("default CVE behavior changed=%d", cohort.Total)
	}
	for _, handle := range []http.HandlerFunc{f.List, f.ByCVE, findings.NewFindingsCSV(d).Stream, dep.List, dep.ExportCSV} {
		if w := request("/inventory?group_mode=unknown", handle); w.Code != 400 {
			t.Fatalf("invalid mode accepted %d", w.Code)
		}
	}
	for _, handle := range []http.HandlerFunc{f.List, f.ByCVE, findings.NewFindingsCSV(d).Stream} {
		if w := request("/inventory?id_scope=unknown", handle); w.Code != 400 {
			t.Fatalf("invalid ID scope accepted %d", w.Code)
		}
	}
}
