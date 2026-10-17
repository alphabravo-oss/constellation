package compliance

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	evidence "github.com/alphabravocompany/constellation/internal/complianceevidence"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestComplianceEvidenceInventoryFullScopeAndExport(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := t.Context()
	org, siblingOrg, cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$3,'evidence inventory'),($2,$4,'foreign')`, org, siblingOrg, "inventory-"+org.String(), "foreign-"+siblingOrg.String())
	t.Cleanup(func() {
		_, _ = pool.Exec(t.Context(), `DELETE FROM findings WHERE org_id IN($1,$2)`, org, siblingOrg)
		_, _ = pool.Exec(t.Context(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, siblingOrg)
	})
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'current'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreign, siblingOrg)
	// Identical projected rows still have distinct source IDs. They exceed the old
	// source/page cap before any node, workload or cloud evidence is appended.
	exec(`INSERT INTO compliance_checks(org_id,cluster_id,framework,control_id,title,status,severity,evidence,evaluated_at) SELECT $1,$2,'cis-k8s-1.9','duplicate','Repeated evidence','fail','high','literal %_ evidence','2026-10-12T00:00:00Z'::timestamptz FROM generate_series(1,1105)`, org, cluster)
	exec(`INSERT INTO compliance_checks(org_id,cluster_id,framework,control_id,title,status,severity,evidence) VALUES($1,$2,'cis-k8s-1.9','duplicate','sibling','fail','high','never current'),($3,$4,'cis-k8s-1.9','duplicate','foreign','fail','high','never current')`, org, sibling, siblingOrg, foreign)
	exec(`INSERT INTO host_cis(org_id,cluster_id,node,profile,passed,failed,warned,skipped,payload,observed_at) SELECT $1,$2,'node-a','fixture',0,501,0,0,jsonb_build_object('checks',jsonb_agg(jsonb_build_object('id','unknown-control','title','Repeated node evidence','result','fail','detail','host check'))),'2026-10-12T00:00:00Z'::timestamptz FROM generate_series(1,501)`, org, cluster)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels,risk_factors,risk_score,finding_count,critical_count,high_count,image_refs,last_seen_at) SELECT $1,$2,'apps','service-'||lpad(i::text,4,'0'),'Deployment','{}','{}',0,0,0,0,'{}','2026-10-12T00:00:00Z'::timestamptz FROM generate_series(1,501) i`, org, cluster)
	exec(`INSERT INTO assets(org_id,cluster_id,kind,name,labels) SELECT $1,$2,'cloud-resource','cloud-'||i,'{}' FROM generate_series(1,501) i`, org, cluster)
	exec(`INSERT INTO findings(org_id,asset_id,kind,title,severity,lifecycle,target_type,description,last_seen_at) SELECT $1,id,'cloud-config','Cloud configuration','high','open','cloud-resource','configuration evidence','2026-10-12T00:00:00Z'::timestamptz FROM assets WHERE org_id=$1`, org)
	exec(`INSERT INTO compliance_exemptions(org_id,cluster_id,framework,control_id,reason,expires_at) VALUES($1,NULL,'cis-k8s-1.9','duplicate','Organization inherited',NOW()+INTERVAL '1 day'),($1,$2,'cis-k8s-1.9','duplicate','Cluster preferred',NOW()+INTERVAL '1 day')`, org, cluster)
	// A partitioned finding's physical identity includes first_seen_at, even
	// when a producer reuses its UUID and every displayed value is identical.
	var cloudID, cloudAsset uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id,asset_id FROM findings WHERE org_id=$1 LIMIT 1`, org).Scan(&cloudID, &cloudAsset); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO findings(id,org_id,asset_id,kind,title,severity,lifecycle,target_type,description,first_seen_at,last_seen_at) VALUES($1,$2,$3,'cloud-config','Cloud configuration','high','open','cloud-resource','configuration evidence',NOW()-INTERVAL '1 hour','2026-10-12T00:00:00Z'::timestamptz)`, cloudID, org, cloudAsset)
	// Image evidence accepts the exact recorded pod workload ID independently
	// from the link's namespace/name projection.
	exec(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized) SELECT $1,$2,id,'apps/pod/exact-pod','apps','service-0501','Deployment','registry.test/missing:latest','registry.test/missing:latest' FROM deployments WHERE org_id=$1 AND name='service-0501'`, org, cluster)
	handler := NewCompliance(database, nil)
	read := func(path string, export bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		r = r.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		if export {
			handler.EvidenceCSV(w, r)
		} else {
			handler.Evidence(w, r)
		}
		return w
	}
	decode := func(w *httptest.ResponseRecorder) evidence.Result {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var result evidence.Result
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	base := "/api/v1/compliance/evidence?cluster_id=" + cluster.String()
	full := decode(read(base+"&limit=100000&sort=scope&order=asc", false))
	if full.Total <= 3000 || len(full.Items) != full.Total || full.HasMore || full.Total != full.Summary.Total {
		t.Fatalf("incomplete normalized inventory total=%d rows=%d summary=%+v", full.Total, len(full.Items), full.Summary)
	}
	if full.Summary.ByScope["kubernetes"].Total != 1105 || full.Summary.ByScope["node"].Total != 501 || full.Summary.ByScope["workload"].Total < 1002 || full.Summary.ByScope["cloud"].Total < 502 {
		t.Fatalf("scope starvation: %+v", full.Summary.ByScope)
	}
	ids := map[string]bool{}
	for _, item := range full.Items {
		if ids[item.ID] {
			t.Fatalf("duplicate row identity %s", item.ID)
		}
		ids[item.ID] = true
		if item.ClusterID != nil && *item.ClusterID != cluster {
			t.Fatalf("foreign scope %v", item.ClusterID)
		}
		if item.Scope == "kubernetes" && (item.EffectiveStatus != "exempted" || item.Exemption == nil || item.Exemption.Reason != "Cluster preferred") {
			t.Fatalf("exemption changed %+v", item)
		}
	}
	page := decode(read(base+"&limit=37&offset=1200&sort=scope&order=asc", false))
	if len(page.Items) != 37 || page.Total != full.Total || !page.HasMore || !slices.EqualFunc(page.Items, full.Items[1200:1237], func(a, b evidence.Item) bool { return a.ID == b.ID }) {
		t.Fatal("page/count/order mismatch")
	}
	second := decode(read(base+"&limit=37&offset=1200&sort=scope&order=asc", false))
	if !slices.EqualFunc(second.Items, page.Items, func(a, b evidence.Item) bool { return a.ID == b.ID }) {
		t.Fatal("ties are unstable")
	}
	late := decode(read(base+"&scope=workload&target=apps%2Fservice-0501&limit=1", false))
	if len(late.Items) != 1 || late.Total < 2 || late.Items[0].Target != "apps/service-0501" {
		t.Fatalf("filter after cap: %+v", late)
	}
	exec(`INSERT INTO compliance_checks(org_id,cluster_id,framework,control_id,title,status,severity) VALUES($1,$2,'cis-k8s-1.9','unknown-status','Unknown collector status','warning','medium')`, org, cluster)
	manual := decode(read(base+"&scope=kubernetes&status=manual", false))
	if manual.Total != 1 || manual.Summary.Manual != 1 || manual.Items[0].Status != "warning" {
		t.Fatalf("raw status/category filter mismatch: %+v", manual)
	}
	// Remove this supplementary category row so the all-scope CSV comparison
	// continues to use the same source snapshot as the earlier full read.
	exec(`DELETE FROM compliance_checks WHERE org_id=$1 AND control_id='unknown-status'`, org)
	filtered := decode(read(base+"&scope=kubernetes&status=exempted&q="+url.QueryEscape("%_")+"&limit=17", false))
	if filtered.Total != 1105 || filtered.Summary.Exempted != 1105 || filtered.Summary.Fail != 0 {
		t.Fatalf("literal search or effective status mismatch %+v", filtered.Summary)
	}
	absent := decode(read(base+"&scope=kubernetes&q="+url.QueryEscape("%_ absent")+"&offset=100", false))
	if absent.Total != 0 || len(absent.Items) != 0 || absent.HasMore {
		t.Fatal("literal search expanded or empty page missing metadata")
	}
	csvResponse := read(base+"&sort=scope&order=asc&limit=1&offset=1200", true)
	if csvResponse.Code != 200 || csvResponse.Header().Get("X-Export-Total") != strconv.Itoa(full.Total) || csvResponse.Header().Get("X-Export-Limit") != "100000" || csvResponse.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("CSV metadata status=%d headers=%v body=%s", csvResponse.Code, csvResponse.Header(), csvResponse.Body.String())
	}
	records, err := csv.NewReader(strings.NewReader(csvResponse.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != full.Total+1 {
		t.Fatalf("CSV rows %d total %d", len(records)-1, full.Total)
	}
	for i, item := range full.Items {
		if records[i+1][0] != item.ID {
			t.Fatalf("CSV order mismatch %d", i)
		}
	}
	q := evidence.Query{OrgID: org, ClusterID: &cluster, Scope: evidence.ScopeWorkload, Limit: 1, Targets: []string{"apps/service-0501"}}
	narrow, err := (evidence.Collector{Pool: pool}).Collect(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if narrow.Total <= late.Total || len(narrow.Items) != 1 || !strings.HasPrefix(narrow.Items[0].Target, "apps/service-0501") {
		t.Fatal("internal targets were filtered after page")
	}
	q.Targets = []string{"apps/pod/exact-pod"}
	pod, err := (evidence.Collector{Pool: pool}).Collect(ctx, q)
	if err != nil || pod.Total < 2 || len(pod.Items) != 1 || pod.Items[0].Source != "image_scan_artifacts" {
		t.Fatalf("exact workload-ID filter: total=%d items=%+v err=%v", pod.Total, pod.Items, err)
	}
	q.Targets = []string{}
	empty, err := (evidence.Collector{Pool: pool}).Collect(ctx, q)
	if err != nil || empty.Total != 0 || len(empty.Items) != 0 {
		t.Fatalf("empty targets must fail closed: total=%d err=%v", empty.Total, err)
	}
	for _, suffix := range []string{"&scope=bad", "&sort=title", "&order=bad", "&offset=-1", "&offset=1000001", "&limit=0", "&limit=100001", "&status=graded", "&q=%zz"} {
		for _, export := range []bool{false, true} {
			w := read(base+suffix, export)
			if w.Code != 400 {
				t.Errorf("invalid %q export=%v status=%d", suffix, export, w.Code)
			}
		}
	}
	for _, scopeID := range []uuid.UUID{sibling, foreign, uuid.New()} {
		w := read("/api/v1/compliance/evidence?cluster_id="+scopeID.String(), false)
		if scopeID == sibling {
			result := decode(w)
			if result.Summary.ByScope["kubernetes"].Total != 1 {
				t.Fatalf("sibling leaked %d", result.Total)
			}
		} else if w.Code != 404 {
			t.Errorf("foreign cluster status=%d", w.Code)
		}
	}
	// A known immutable digest must not borrow a newer clean result under
	// the same mutable reference, and foreign results must never supply evidence.
	digestA, digestB, scanA, scanB, foreignScan := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), uuid.New(), uuid.New(), uuid.New()
	for _, entry := range []struct {
		id, org uuid.UUID
		digest  string
		age     int
	}{{scanA, org, digestA, 2}, {scanB, org, digestB, 1}, {foreignScan, siblingOrg, digestA, 0}} {
		exec(`INSERT INTO image_scan_results(id,org_id,image_ref,image_ref_normalized,image_digest,image_repository,platform,scanner_profile,vulndb_bundle_version,package_count,finding_count,last_scanned_at) VALUES($1,$2,'registry.test/mutable:latest','registry.test/mutable:latest',$3,'registry.test/mutable','linux/amd64','default','fixture',0,0,NOW()-($4*INTERVAL '1 hour'))`, entry.id, entry.org, entry.digest, entry.age)
		count := 0
		if entry.id == scanA {
			count = 1
		}
		exec(`INSERT INTO image_scan_artifacts(org_id,image_scan_result_id,artifact_type,format,sha256,package_count,payload) VALUES($1,$2,'secret-scan','constellation-image-secrets-v1','fixture-sha',$3,jsonb_build_object('status','observed','secret_count',$3::int))`, entry.org, entry.id, count)
	}
	exec(`UPDATE image_workload_links SET image_ref='registry.test/mutable:latest',image_ref_normalized='registry.test/mutable:latest',image_digest=$2 WHERE org_id=$1 AND workload_id='apps/pod/exact-pod'`, org, digestA)
	q.Targets = []string{"apps/pod/exact-pod"}
	q.Limit = 100000
	exact, err := (evidence.Collector{Pool: pool}).Collect(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	secrets := 0
	for _, item := range exact.Items {
		if item.InternalID == "container.image-secrets-absent" {
			secrets++
			if item.Status != "fail" || !strings.Contains(item.Evidence, scanA.String()) || strings.Contains(item.Evidence, scanB.String()) {
				t.Fatalf("borrowed mutable/foreign scan: %+v", item)
			}
		}
	}
	if secrets == 0 {
		t.Fatal("missing exact secret mappings")
	}
	exec(`UPDATE image_workload_links SET image_digest=NULL WHERE org_id=$1 AND workload_id='apps/pod/exact-pod'`, org)
	fallback, err := (evidence.Collector{Pool: pool}).Collect(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range fallback.Items {
		if item.InternalID == "container.image-secrets-absent" && (item.Status != "pass" || !strings.Contains(item.Evidence, scanB.String())) {
			t.Fatalf("missing reference fallback: %+v", item)
		}
	}
	// A failed read must not return an empty-success inventory or CSV.
	database.Close()
	for _, export := range []bool{false, true} {
		w := read(base, export)
		if w.Code != 500 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("closed DB export=%v status=%d type=%s", export, w.Code, w.Header().Get("Content-Type"))
		}
	}
}
