package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestAssetFindingsFullInventoryAndExport(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreign, cluster, sibling, asset, sharedAsset, result, oldResult, foreignResult := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
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
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$3,'main'),($2,$3,'sibling')`, cluster, sibling, org)
	exec(`INSERT INTO assets(id,org_id,cluster_id,kind,name,digest) VALUES($1,$3,$4,'image','api','sha256:inventory'),($2,$3,$5,'image','shared','sha256:inventory')`, asset, sharedAsset, org, cluster, sibling)
	exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,external_id,title,severity,risk_score,lifecycle,last_seen_at) SELECT $1,$2,$3,'vulnerability','CVE-'||n,CASE WHEN n=1205 THEN 'needle%_literal' ELSE 'Finding '||n END,'high',70,'open','2026-10-12' FROM generate_series(1,1205)n`, org, cluster, asset)
	duplicateID := uuid.New()
	exec(`INSERT INTO findings(id,first_seen_at,org_id,cluster_id,asset_id,kind,external_id,title,severity,risk_score,lifecycle,last_seen_at) VALUES($1,'2026-10-10',$2,$3,$4,'vulnerability','CVE-repeated','Repeated UUID','high',70,'open','2026-10-12'),($1,'2026-10-11',$2,$3,$4,'vulnerability','CVE-repeated','Repeated UUID','high',70,'open','2026-10-12')`, duplicateID, org, cluster, asset)

	exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,title,severity) VALUES($1,$2,$3,'runtime','wrong cluster','critical'),($4,$5,$3,'runtime','foreign','critical')`, org, sibling, asset, foreign, cluster)
	exec(`INSERT INTO image_scan_results(id,org_id,asset_id,image_ref,image_ref_normalized,image_repository,image_digest,platform,scanner_profile,last_scanned_at) VALUES($1,$4,$5,'api:v1','api:v1','api','sha256:inventory','linux/amd64','default','2026-10-12'),($2,$4,$6,'api:v0','api:v0','api','sha256:inventory','linux/amd64','old','2026-10-11'),($3,$7,NULL,'api:foreign','api:foreign','api','sha256:inventory','linux/amd64','default','2026-10-13')`, result, oldResult, foreignResult, org, sharedAsset, asset, foreign)
	exec(`INSERT INTO image_scan_results(org_id,asset_id,image_ref,image_ref_normalized,image_repository,image_digest,platform,scanner_profile,last_scanned_at) VALUES($1,$2,'api:v1','api:v1','api','sha256:different-reused-tag','linux/amd64','default','2026-10-14')`, org, asset)

	exec(`INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,external_id,title,severity,risk_score) SELECT $1,$2,'key:'||n,'CVE-'||n,'Canonical '||n,'critical',90 FROM generate_series(1,205)n`, org, result)
	exec(`INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,title,severity,risk_score) VALUES($1,$2,'old','Old scan','critical',100),($3,$4,'foreign','Foreign scan','critical',100),($3,$5,'malformed','Wrong tenant child','critical',100)`, org, oldResult, foreign, foreignResult, result)
	h := NewAssets(d)
	request := func(id uuid.UUID, query string, export bool, auth bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", "/assets/"+id.String()+"/findings?"+query, nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", id.String())
		r = r.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rc))
		if auth {
			r = r.WithContext(WithSubject(r.Context(), Subject{OrgID: org}))
		}
		w := httptest.NewRecorder()
		if export {
			h.FindingsCSV(w, r)
		} else {
			h.Findings(w, r)
		}
		return w
	}
	legacyRequest := httptest.NewRequest("GET", "/assets/"+asset.String(), nil)
	legacyRoute := chi.NewRouteContext()
	legacyRoute.URLParams.Add("id", asset.String())
	legacyRequest = legacyRequest.WithContext(context.WithValue(WithSubject(ctx, Subject{OrgID: org}), chi.RouteCtxKey, legacyRoute))
	legacyResponse := httptest.NewRecorder()
	h.Get(legacyResponse, legacyRequest)
	if legacyResponse.Code != 200 {
		t.Fatalf("legacy asset read: %d %s", legacyResponse.Code, legacyResponse.Body.String())
	}
	var legacy struct {
		ImageScanResult imageScanResultDTO `json:"image_scan_result"`
	}
	if err := json.Unmarshal(legacyResponse.Body.Bytes(), &legacy); err != nil || legacy.ImageScanResult.ID != result {
		t.Fatalf("known digest used another image scan: %v %+v", err, legacy.ImageScanResult)
	}

	type page struct {
		Items []assetFindingRow `json:"items"`
		inventorylist.Metadata
		AssetID   uuid.UUID `json:"asset_id"`
		ClusterID uuid.UUID `json:"cluster_id"`
	}
	read := func(query string) page {
		t.Helper()
		w := request(asset, query, false, true)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := read("limit=100&cluster_id=" + cluster.String())
	if p.Total != 1412 || len(p.Items) != 100 || !p.HasMore || p.Summary["critical"] != 205 || p.Summary["high"] != 1207 || p.Summary["asset_findings"] != 1207 || p.Summary["image_scan_findings"] != 205 {
		t.Fatalf("metadata %+v", p.Metadata)
	}
	seen := map[string]bool{}
	for offset := 0; offset < 1500; offset += 100 {
		p = read("limit=100&offset=" + strconv.Itoa(offset))
		for _, f := range p.Items {
			if seen[f.RowID] {
				t.Fatalf("duplicate %s", f.RowID)
			}
			seen[f.RowID] = true
		}
	}
	if len(seen) != 1412 {
		t.Fatalf("got %d identities", len(seen))
	}
	p = read("offset=2000")
	if p.Total != 1412 || len(p.Items) != 0 || p.HasMore {
		t.Fatal("empty continuation lost total")
	}
	p = read("q=%25_")
	if p.Total != 1 || p.Items[0].Title != "needle%_literal" {
		t.Fatal("search must be literal")
	}
	p = read("source=image_scan&severity=critical&lifecycle=open&sort=finding&order=asc")
	if p.Total != 205 || p.Items[0].ImageScanResultID == nil || *p.Items[0].ImageScanResultID != result {
		t.Fatal("shared latest digest cohort missing")
	}
	w := request(asset, "offset=1400&limit=1", true, true)
	if w.Code != 200 || w.Header().Get("X-Export-Total") != "1412" || w.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("export %d %s", w.Code, w.Body.String())
	}
	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(records) != 1413 {
		t.Fatalf("CSV %d %v", len(records), err)
	}
	if records[0][len(records[0])-1] != "platform_role" {
		t.Fatal("role export column missing")
	}
	for _, row := range records[1:] {
		if row[len(row)-1] != "" {
			t.Fatal("image evidence must not inherit a workload role")
		}
	}
	w = request(asset, "q=%25_", true, true)
	records, err = csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(records) != 2 {
		t.Fatal("filtered export")
	}
	for _, query := range []string{"severity=bogus", "source=bogus", "lifecycle=bogus", "limit=0", "offset=-1", "sort=bogus", "order=no", "cluster_id=bad"} {
		if w = request(asset, query, false, true); w.Code != 400 {
			t.Fatalf("query %s: %d", query, w.Code)
		}
	}
	if w = request(asset, "cluster_id="+sibling.String(), false, true); w.Code != 404 {
		t.Fatal("sibling scope accepted")
	}
	if w = request(uuid.New(), "", false, true); w.Code != 404 {
		t.Fatal("missing asset accepted")
	}
	if w = request(asset, "", false, false); w.Code != 401 {
		t.Fatal("subject required")
	}
}

func TestAssetsGetReadFailureIsNotMissingOrEmpty(t *testing.T) {
	d := openTestDB(t)
	d.Close()
	r := httptest.NewRequest("GET", "/assets/test", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", uuid.NewString())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
	r = r.WithContext(WithSubject(r.Context(), Subject{OrgID: uuid.New()}))
	w := httptest.NewRecorder()
	NewAssets(d).Get(w, r)
	if w.Code != 500 || strings.Contains(w.Body.String(), "findings") {
		t.Fatalf("read failure must not become missing or empty evidence: %d %s", w.Code, w.Body.String())
	}
}
