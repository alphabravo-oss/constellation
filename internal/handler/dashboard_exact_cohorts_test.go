package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/findings"
	"github.com/google/uuid"
)

// Exercise actual tile source, destination pages/counts, rollups and CSV. A
// substring target filter, truthy-only fact filter, hidden platform rows or
// filtering after LIMIT would each change this fixture's expected cohorts.
func TestDashboardExactLocationAndRiskFactDestinations(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx, pool := t.Context(), d.Pool()
	org, foreign, cluster, sibling, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "dashboard-cohort-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id IN ($1,$2)`, org, foreign)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreign)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$3,'selected'),($2,$3,'sibling')`, cluster, sibling, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,kind,name) VALUES($1,$2,'image','fixture')`, asset, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,asset_id,cluster_id,kind,external_id,title,severity,lifecycle,target_type,target_ref)
 SELECT $1,$2,$3,'vulnerability','CVE-2099-EXACT','image record '||n,'high','open','image-workload','image:'||n FROM generate_series(1,505)n`, org, asset, cluster); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		org, cluster        uuid.UUID
		kind, state, target string
	}{
		{org, cluster, "vulnerability", "open", "host"}, {org, cluster, "vulnerability", "open", "host"}, // unnamed host refs still count
		{org, cluster, "vulnerability", "open", "platform"}, {org, cluster, "vulnerability", "open", "image-workload-extra"},
		{org, cluster, "vulnerability", "open", "workload"}, {org, cluster, "vulnerability", "accepted", "image-workload"},
		{org, cluster, "license", "open", "image-workload"}, {org, sibling, "vulnerability", "open", "image-workload"}, {foreign, cluster, "vulnerability", "open", "image-workload"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,asset_id,cluster_id,kind,external_id,title,severity,lifecycle,target_type) VALUES($1,$2,$3,$4,'CVE-2099-EXACT','other record','high',$5,$6)`, item.org, asset, item.cluster, item.kind, item.state, item.target); err != nil {
			t.Fatal(err)
		}
	}
	for i, raw := range []string{`{"privileged":1,"run_as_root":1,"net_exposure":1}`, `{"privileged":0,"run_as_root":0,"net_exposure":0}`, `{"privileged":null,"run_as_root":null,"net_exposure":null}`, `{"privileged":false,"run_as_root":false,"net_exposure":false}`, `{}`} {
		ns := "customer"
		if i == 2 {
			ns = "constellation"
		}
		if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,risk_factors) VALUES($1,$2,$3,$4,'Deployment',$5::jsonb)`, org, cluster, ns, "fact-"+string(rune('a'+i)), raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,risk_factors) VALUES($1,$2,'customer','sibling','Deployment','{"privileged":1}'),($3,$4,'customer','foreign','Deployment','{"privileged":1}')`, org, sibling, foreign, cluster); err != nil {
		t.Fatal(err)
	}
	request := func(path string, handle http.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: org}))
		w := httptest.NewRecorder()
		handle(w, req)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, value any) {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), value); err != nil {
			t.Fatal(err)
		}
	}
	var source dashboardSummaryDTO
	decode(request("/dashboard/summary?cluster_id="+cluster.String(), NewDashboard(d).Summary), &source)
	f := findings.NewFindings(d, nil, nil)
	for target, count := range map[string]int{"image-workload": 505, "host": 2, "platform": 1} {
		location := target
		if target == "image-workload" {
			location = "image"
		}
		if source.Posture.VulnsByLocation[location] != count {
			t.Fatalf("source %s=%d want %d", location, source.Posture.VulnsByLocation[location], count)
		}
		values := url.Values{"cluster_id": {cluster.String()}, "kind": {"vulnerability"}, "lifecycle": {"open"}, "target_type": {target}, "limit": {"1"}, "offset": {"1"}}
		var destination struct {
			Total    int
			Findings []struct{ ID string }
			Counts   map[string]int `json:"lifecycle_counts"`
		}
		decode(request("/findings?"+values.Encode(), f.List), &destination)
		if destination.Total != count || destination.Counts["open"] != count || len(destination.Findings) != min(1, count-1) {
			t.Fatalf("%s destination %+v", target, destination)
		}
		if target == "image-workload" && destination.Counts["accepted"] != 1 {
			t.Fatalf("lifecycle counts lost location predicate: %+v", destination.Counts)
		}
		values.Del("offset")
		values.Set("limit", "100000")
		exported := request("/findings.csv?"+values.Encode(), findings.NewFindingsCSV(d).Stream)
		records, err := csv.NewReader(strings.NewReader(exported.Body.String())).ReadAll()
		if err != nil || exported.Code != 200 || len(records) != count+1 {
			t.Fatalf("%s CSV status=%d rows=%d err=%v", target, exported.Code, len(records), err)
		}
		var rollup struct {
			Total int
			CVEs  []struct{ Instances int } `json:"cves"`
		}
		decode(request("/findings/by-cve?"+values.Encode(), f.ByCVE), &rollup)
		if rollup.Total != 1 || len(rollup.CVEs) != 1 || rollup.CVEs[0].Instances != count {
			t.Fatalf("%s rollup %+v", target, rollup)
		}
	}
	dep := NewDeployments(d, nil)
	for fact, sourceKey := range map[string]string{"privileged": "privileged", "run_as_root": "run_as_root", "net_exposure": "exposed"} {
		count := source.Posture.Hardening[sourceKey]
		if count != 4 {
			t.Fatalf("fact source %s=%d", fact, count)
		}
		values := url.Values{"cluster_id": {cluster.String()}, "hide_platform": {"false"}, "risk_fact": {fact}, "limit": {"1"}, "offset": {"3"}}
		var destination struct {
			Total       int
			Deployments []deploymentListRow
			Summary     deploymentListSummary
		}
		decode(request("/deployments?"+values.Encode(), dep.List), &destination)
		if destination.Total != count || destination.Summary.Total != int64(count) || len(destination.Deployments) != 1 {
			t.Fatalf("fact %s destination %+v", fact, destination)
		}
		exported := request("/deployments.csv?"+values.Encode(), dep.ExportCSV)
		records, err := csv.NewReader(strings.NewReader(exported.Body.String())).ReadAll()
		if err != nil || exported.Code != 200 || len(records) != count+1 {
			t.Fatalf("fact %s CSV rows=%d status=%d err=%v", fact, len(records), exported.Code, err)
		}
		if !strings.Contains(exported.Body.String(), "fact-c") || strings.Contains(exported.Body.String(), "fact-e") || strings.Contains(exported.Body.String(), "sibling") || strings.Contains(exported.Body.String(), "foreign") {
			t.Fatalf("fact %s wrong CSV cohort: %s", fact, exported.Body.String())
		}
	}
	for _, handle := range []http.HandlerFunc{f.List, f.ByCVE, findings.NewFindingsCSV(d).Stream} {
		if w := request("/findings?target_type=image-workload-extra", handle); w.Code != 400 {
			t.Fatalf("invalid target status=%d", w.Code)
		}
	}
	for _, handle := range []http.HandlerFunc{dep.List, dep.ExportCSV} {
		if w := request("/deployments?risk_fact=privileged%27%20OR%20true", handle); w.Code != 400 {
			t.Fatalf("invalid fact status=%d", w.Code)
		}
	}
}
