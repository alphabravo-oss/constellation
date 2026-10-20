//go:build integration

package findings

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

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestCVEAffectedInventoryBeyondCapsDedupScopeAndExports(t *testing.T) {
	t.Parallel()
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreignOrg, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	cveID := "CVE-2026-91919"
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "cve-inventory-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg) })
	must := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'Main'),($3,$2,'Sibling'),($4,$5,'Foreign')`, cluster, org, sibling, foreignCluster, foreignOrg)
	must(`INSERT INTO image_scan_results(org_id,image_ref,image_ref_normalized,image_repository,image_tag,image_digest,platform,scanner_profile,last_scanned_at) SELECT $1,'team/image-'||lpad(n::text,4,'0')||':v1','team/image-'||lpad(n::text,4,'0')||':v1',CASE WHEN n=610 THEN 'team/tail%_image' ELSE 'team/image-'||lpad(n::text,4,'0') END,'v1','sha256:image-'||n,'linux/amd64','default','2026-10-12' FROM generate_series(1,610)n`, org)
	must(`INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,external_id,title,severity,risk_score,package_name,package_version,fixed_version) SELECT $1,id,'first',$2,'fixture',CASE WHEN right(image_digest,1) IN('0','2','4','6','8') THEN 'critical' ELSE 'high' END,CASE WHEN right(image_digest,1) IN('0','2','4','6','8') THEN 95 ELSE 80 END,CASE WHEN image_digest='sha256:image-610' THEN 'tail%_package' ELSE 'package' END,'1.0','1.1' FROM image_scan_results WHERE org_id=$1`, org, cveID)
	must(`INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,external_id,title,severity,risk_score,package_name) SELECT $1,id,'second',$2,'second package','high',70,'second-package' FROM image_scan_results WHERE org_id=$1 AND image_digest='sha256:image-1'`, org, cveID)
	must(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind) SELECT $1,$2,'prod',CASE WHEN n=1205 THEN 'tail%_workload' ELSE 'app'||lpad(n::text,4,'0') END,'Deployment' FROM generate_series(1,1205)n`, org, cluster)
	must(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_tag,image_digest) SELECT $1,$2,d.id,'prod/'||d.name,'prod',d.name,'Deployment',r.image_ref,r.image_ref_normalized,r.image_repository,'v1',r.image_digest FROM deployments d JOIN image_scan_results r ON r.org_id=$1 AND r.image_digest='sha256:image-'||CASE WHEN d.name='tail%_workload' THEN 595 ELSE ((substring(d.name from 4)::int-1)%610)+1 END WHERE d.org_id=$1 AND d.cluster_id=$2`, org, cluster)
	// Same association through two refs must count canonical finding IDs once.
	must(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_tag,image_digest) SELECT org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,'alias/ref','alias/ref',image_repository,image_tag,image_digest FROM image_workload_links WHERE org_id=$1 AND cluster_id=$2 AND name='app0001'`, org, cluster)
	must(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_tag,image_digest) SELECT org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,'zzz/other:a','zzz/other:a','zzz/other','a',image_digest FROM image_workload_links WHERE org_id=$1 AND cluster_id=$2 AND name='app0001' LIMIT 1`, org, cluster)
	// A different full association identity sharing the deployment remains a row.
	must(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_tag,image_digest) SELECT org_id,cluster_id,deployment_id,'prod/alias-one',namespace,name,kind,'alias/one','alias/one',image_repository,image_tag,image_digest FROM image_workload_links WHERE org_id=$1 AND cluster_id=$2 AND name='app0001' LIMIT 1`, org, cluster)
	must(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind) VALUES($1,$2,'prod','sibling','Deployment'),($3,$4,'prod','foreign','Deployment')`, org, sibling, foreignOrg, foreignCluster)
	must(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_tag,image_digest) SELECT d.org_id,d.cluster_id,d.id,'prod/'||d.name,'prod',d.name,'Deployment','sibling/ref','sibling/ref','team/image-0001','v1','sha256:image-1' FROM deployments d WHERE (d.org_id=$1 AND d.cluster_id=$2) OR (d.org_id=$3 AND d.cluster_id=$4)`, org, sibling, foreignOrg, foreignCluster)
	// Malformed cross-tenant relationships must not contribute canonical evidence.
	must(`INSERT INTO image_scan_results(org_id,image_ref,image_ref_normalized,image_repository,image_digest) VALUES($1,'foreign/ref','foreign/ref','foreign/repository','sha256:foreign')`, foreignOrg)
	must(`INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,external_id,title,severity,risk_score) SELECT $1,id,'poison',$2,'foreign poison','critical',100 FROM image_scan_results WHERE org_id=$3`, org, cveID, foreignOrg)
	h := NewCVE(d, "")
	request := func(view string, values url.Values, export, auth bool) *httptest.ResponseRecorder {
		requestCtx := ctx
		if auth {
			requestCtx = authctx.WithSubject(ctx, authctx.Subject{OrgID: org})
		}
		r := httptest.NewRequestWithContext(requestCtx, http.MethodGet, "/affected/"+view+"?"+values.Encode(), nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", cveID)
		route.URLParams.Add("view", view)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		if view == "legacy" {
			h.Affected(w, r)
		} else if export {
			h.AffectedInventoryCSV(w, r)
		} else {
			h.AffectedInventory(w, r)
		}
		return w
	}
	type page struct {
		Items   []map[string]any
		Total   int
		Summary map[string]int
		HasMore bool `json:"has_more"`
	}
	read := func(view string, values url.Values) page {
		t.Helper()
		w := request(view, values, false, true)
		if w.Code != 200 {
			t.Fatalf("%s status%d %s", view, w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	images := read("images", nil)
	if images.Total != 610 || len(images.Items) != 100 || images.Summary["finding_count"] != 611 || !images.HasMore {
		t.Fatalf("full image summary %+v", images)
	}
	packages := read("packages", nil)
	if packages.Total != 611 || packages.Summary["image_count"] != 610 {
		t.Fatalf("full package summary %+v", packages)
	}
	main := url.Values{"cluster_id": {cluster.String()}}
	workloads := read("workloads", main)
	if workloads.Total != 1206 || workloads.Summary["finding_count"] != 1209 || workloads.Summary["deployment_count"] != 1205 || workloads.Summary["cluster_count"] != 1 {
		t.Fatalf("full workload summary %+v", workloads)
	}
	orgWorkloads := read("workloads", nil)
	if orgWorkloads.Total != 1207 || orgWorkloads.Summary["finding_count"] != 1211 || orgWorkloads.Summary["cluster_count"] != 2 {
		t.Fatalf("organization workload summary %+v", orgWorkloads)
	}
	clusters := read("clusters", nil)
	if clusters.Total != 2 || clusters.Summary["workload_count"] != 1207 || clusters.Summary["finding_count"] != 1211 {
		t.Fatalf("full cluster rollups %+v", clusters)
	}
	deep := read("images", url.Values{"sort": {"image"}, "order": {"asc"}, "offset": {"600"}})
	if len(deep.Items) != 10 || deep.HasMore || deep.Total != 610 {
		t.Fatal("image continuation failed")
	}
	deep = read("workloads", url.Values{"cluster_id": {cluster.String()}, "offset": {"1200"}})
	if len(deep.Items) != 6 || deep.Total != 1206 || deep.HasMore {
		t.Fatal("workload continuation failed")
	}
	empty := read("workloads", url.Values{"offset": {"9999"}})
	if len(empty.Items) != 0 || empty.Total != 1207 || empty.HasMore {
		t.Fatal("empty page lost source totals")
	}
	duplicate := read("workloads", url.Values{"cluster_id": {cluster.String()}, "q": {"app0001"}})
	if duplicate.Total != 2 || duplicate.Items[0]["row_id"] == duplicate.Items[1]["row_id"] {
		t.Fatal("association identities collapsed")
	}
	for _, item := range duplicate.Items {
		evidence := item["image_evidence"].([]any)
		for _, raw := range evidence {
			tuple := raw.(map[string]any)
			if tuple["image_repository"] == "zzz/other" && tuple["image_tag"] != "a" {
				t.Fatal("synthesized image evidence tuple")
			}
		}
	}
	csvResult := request("workloads", url.Values{"cluster_id": {cluster.String()}, "q": {"app0001"}}, true, true)
	csvRows, csvErr := csv.NewReader(csvResult.Body).ReadAll()
	if csvErr != nil || len(csvRows) != 3 {
		t.Fatal("association CSV failed")
	}
	for _, row := range csvRows[1:] {
		var evidence []affectedImageEvidence
		if err := json.Unmarshal([]byte(row[8]), &evidence); err != nil {
			t.Fatal("CSV did not preserve structured tuples")
		}
		for _, tuple := range evidence {
			if tuple.ImageRepository == "zzz/other" && tuple.ImageTag != "a" {
				t.Fatal("CSV synthesized a tuple")
			}
		}
	}
	for _, item := range duplicate.Items {
		if item["finding_count"] != float64(2) {
			t.Fatal("duplicate image links multiplied canonical findings")
		}
	}
	for _, test := range []struct {
		view  string
		query url.Values
		total int
	}{
		{"images", url.Values{"q": {"%_"}}, 1}, {"workloads", url.Values{"q": {"%_"}}, 2}, {"packages", url.Values{"q": {"%_"}}, 1}, {"clusters", url.Values{"q": {"Main"}}, 1},
		{"images", url.Values{"severity": {"critical"}}, 305}, {"packages", url.Values{"severity": {"high"}}, 306}, {"workloads", url.Values{"cluster_id": {sibling.String()}}, 1}, {"images", url.Values{"cluster_id": {sibling.String()}}, 1},
		{"workloads", url.Values{"namespace": {"missing"}}, 0}, {"images", url.Values{"namespace": {"missing"}}, 0},
		{"images", url.Values{"offset": {"9999"}}, 610}, {"workloads", url.Values{"cluster_id": {cluster.String()}, "offset": {"9999"}}, 1206}, {"packages", url.Values{"offset": {"9999"}}, 611}, {"clusters", url.Values{"offset": {"9999"}}, 2},
	} {
		p := read(test.view, test.query)
		if p.Total != test.total {
			t.Fatalf("filter%s %v total%d want%d", test.view, test.query, p.Total, test.total)
		}
		w := request(test.view, test.query, true, true)
		csvRows, err := csv.NewReader(w.Body).ReadAll()
		if err != nil || w.Code != 200 || len(csvRows) != test.total+1 || w.Header().Get("X-Export-Total") != strconv.Itoa(test.total) || w.Header().Get("X-Export-Limit") != "100000" {
			t.Fatalf("matching CSV%s status%d rows%d err%v", test.view, w.Code, len(csvRows), err)
		}
	}
	for _, view := range []string{"images", "workloads", "clusters", "packages"} {
		first := read(view, nil)
		repeat := read(view, nil)
		for i, item := range first.Items {
			if item["row_id"] != repeat.Items[i]["row_id"] {
				t.Fatal("unstable tie order")
			}
		}
		for _, export := range []bool{false, true} {
			for _, test := range []struct {
				query  url.Values
				auth   bool
				status int
			}{{nil, false, 401}, {url.Values{"cluster_id": {"bad"}}, true, 400}, {url.Values{"cluster_id": {foreignCluster.String()}}, true, 404}, {url.Values{"cluster_id": {uuid.New().String()}}, true, 404}, {url.Values{"sort": {"bad"}}, true, 400}, {url.Values{"severity": {"bad"}}, true, 400}, {url.Values{"order": {"bad"}}, true, 400}, {url.Values{"limit": {"0"}}, true, 400}, {url.Values{"limit": {"501"}}, true, 400}, {url.Values{"limit": {"bad"}}, true, 400}, {url.Values{"offset": {"-1"}}, true, 400}, {url.Values{"offset": {"bad"}}, true, 400}} {
				if w := request(view, test.query, export, test.auth); w.Code != test.status {
					t.Fatalf("boundary%s %d want%d", view, w.Code, test.status)
				}
			}
		}
	}
	if w := request("invalid", nil, false, true); w.Code != 400 {
		t.Fatal("invalid view accepted")
	}
	// Ref, normalized-ref and repository/tag fallback matching remain independent
	// of digest equality and still deduplicate finding IDs.
	for _, match := range []string{"ref-only", "normalized-only", "repository-only"} {
		imageRef, normalized, repository, tag := "unknown-"+match, "unknown-"+match, "", ""
		if match == "ref-only" {
			imageRef = "team/image-0001:v1"
		}
		if match == "normalized-only" {
			normalized = "team/image-0001:v1"
		}
		if match == "repository-only" {
			repository = "team/image-0001"
			tag = "v1"
		}
		must(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_tag,image_digest) SELECT $1,$2,id,'prod/'||$3,'prod',$3,'Deployment',$4,$5,$6,$7,NULL FROM deployments WHERE org_id=$1 AND cluster_id=$2 AND name='app0001'`, org, cluster, match, imageRef, normalized, repository, tag)
		p := read("workloads", url.Values{"q": {match}, "cluster_id": {cluster.String()}})
		if p.Total != 1 || p.Items[0]["finding_count"] != float64(2) {
			t.Fatalf("%s match %+v", match, p)
		}
	}
	// A newer scan B for the same mutable tag must not be attributed to a link
	// recording digest A. The sibling contains only that exact known-digest link.
	must(`INSERT INTO image_scan_results(org_id,image_ref,image_ref_normalized,image_repository,image_tag,image_digest) VALUES($1,'team/image-0001:v1','team/image-0001:v1','team/image-0001','v1','sha256:replacement-B')`, org)
	must(`INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,external_id,title,severity,risk_score,package_name) SELECT $1,id,'replacement',$2,'replacement','critical',100,'replacement-package' FROM image_scan_results WHERE org_id=$1 AND image_digest='sha256:replacement-B'`, org, cveID)
	scoped := url.Values{"cluster_id": {sibling.String()}}
	for _, view := range []string{"images", "workloads", "clusters", "packages"} {
		page := read(view, scoped)
		want := 1
		if view == "packages" {
			want = 2
		}
		if page.Total != want || page.Summary["finding_count"] != 2 {
			t.Fatalf("%s borrowed replacement digest: %+v", view, page)
		}
		for _, item := range page.Items {
			if item["image_digest"] == "sha256:replacement-B" {
				t.Fatal("foreign digest attributed through tag")
			}
		}
		exported := request(view, scoped, true, true)
		rows, err := csv.NewReader(exported.Body).ReadAll()
		if err != nil || len(rows) != want+1 {
			t.Fatal("exact-digest CSV scope mismatch")
		}
	}
	legacy := request("legacy", scoped, false, true)
	var legacyPage struct {
		Images    []cveAffectedImageDTO
		Workloads []cveAffectedWorkloadDTO
		Summary   cveAffectedSummaryDTO
	}
	if legacy.Code != 200 {
		t.Fatalf("legacy%d %s", legacy.Code, legacy.Body.String())
	}
	if err := json.Unmarshal(legacy.Body.Bytes(), &legacyPage); err != nil {
		t.Fatal(err)
	}
	if len(legacyPage.Images) != 1 || len(legacyPage.Workloads) != 1 || legacyPage.Summary.FindingCount != 2 || legacyPage.Workloads[0].FindingCount != 2 {
		t.Fatal("legacy affected borrowed a different digest through a mutable tag")
	}

}
