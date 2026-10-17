package findings

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestFindingsServerFilterParity(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	org, foreign, cluster, sibling, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	// Findings are partitioned and do not cascade from orgs; always remove fixtures.
	defer func() {
		_, _ = d.Pool().Exec(ctx, `DELETE FROM findings WHERE org_id=ANY($1)`, []uuid.UUID{org, foreign})
	}()
	base := `INSERT INTO findings (org_id,cluster_id,asset_id,kind,external_id,title,severity,risk_score,lifecycle,target_type,target_ref,canonical_engine,detail_json)
 VALUES ($1,$2,$3,$4,'CVE-2099-1000',$5,'high',70,$6,$7,'image:fixture','trivy',$8::jsonb)`
	detail := `{"package_name":"openssl","package_version":"1.0","fixed_version":"2.0","kev":"true","cvss_base":"8.7"}`
	if _, err := d.Pool().Exec(ctx, `INSERT INTO findings (org_id,cluster_id,asset_id,kind,external_id,title,severity,risk_score,lifecycle,target_type,target_ref,canonical_engine,detail_json)
 SELECT $1,$2,$3,'vulnerability','CVE-2099-1000',CASE WHEN n=605 THEN 'deepneedle' ELSE 'ordinary issue' END,'high',70,'open','image-workload','image:'||n,'trivy',$4::jsonb FROM generate_series(1,605) n`, org, cluster, asset, detail); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		org, cluster                uuid.UUID
		kind, state, target, detail string
	}{
		{org, cluster, "vulnerability", "accepted", "image-workload", detail},
		{org, cluster, "vulnerability", "suppressed", "image-workload", detail},
		{org, cluster, "vulnerability", "open", "image-workload", `{"package":{"name":"openssl","version":"1.0"},"kev":true}`},
		{org, cluster, "vulnerability", "open", "workload", detail},
		{org, sibling, "vulnerability", "open", "image-workload", detail},
		{foreign, cluster, "vulnerability", "open", "image-workload", detail},
		{org, cluster, "license", "open", "image-workload", detail},
		{org, cluster, "vulnerability", "open", "image-workload", `{"package_name":"other","fixed":"2.0","kev":true}`},
	} {
		if _, err := d.Pool().Exec(ctx, base, item.org, item.cluster, asset, item.kind, "fixture", item.state, item.target, item.detail); err != nil {
			t.Fatal(err)
		}
	}
	values := url.Values{"cluster_id": {cluster.String()}, "kind": {"vulnerability"}, "lifecycle": {"open"}, "fixable": {"true"}, "q": {"openssl !status:suppressed kev:true canonical:trivy"}}
	request := func(handler http.HandlerFunc, values url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/?"+values.Encode(), nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}
	type page struct {
		Findings []findingDTO   `json:"findings"`
		Total    int            `json:"total"`
		HasMore  bool           `json:"has_more"`
		Counts   map[string]int `json:"lifecycle_counts"`
	}
	get := func(values url.Values) page {
		t.Helper()
		w := request(NewFindings(d, nil, nil).List, values)
		if w.Code != 200 {
			t.Fatalf("list status%d: %s", w.Code, w.Body.String())
		}
		var result page
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := get(values)
	if len(first.Findings) != 100 || first.Total != 605 || !first.HasMore || first.Counts["open"] != 605 || first.Counts["accepted"] != 1 || first.Counts["suppressed"] != 0 {
		t.Fatalf("first page len=%d total=%d counts=%v", len(first.Findings), first.Total, first.Counts)
	}
	if first.Findings[0].PackageName != "openssl" || first.Findings[0].FixedVersion != "2.0" || !first.Findings[0].KEV {
		t.Fatalf("flat package hydration missing: %+v", first.Findings[0])
	}
	values.Set("offset", "600")
	last := get(values)
	if len(last.Findings) != 5 || last.Total != 605 || last.HasMore {
		t.Fatalf("last page len=%d total=%d hasmore=%v", len(last.Findings), last.Total, last.HasMore)
	}
	repeated := get(values)
	for i := range last.Findings {
		if last.Findings[i].ID != repeated.Findings[i].ID {
			t.Fatal("unstable tie pagination")
		}
	}
	w := request(NewFindingsCSV(d).Stream, values)
	if w.Code != 200 {
		t.Fatalf("CSV status%d %s", w.Code, w.Body.String())
	}
	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 6 {
		t.Fatalf("CSV count%d", len(records))
	}
	for i, item := range last.Findings {
		if records[i+1][0] != item.ID.String() {
			t.Fatal("CSV and list predicates/order disagree")
		}
	}
	values.Del("offset")
	for _, literal := range []string{"deep_eedle", "%"} {
		values.Set("q", literal)
		if got := get(values); got.Total != 0 {
			t.Fatalf("literal %q broadened to %d findings", literal, got.Total)
		}
	}
	values.Set("q", "deepneedle")
	if got := get(values); got.Total != 1 || len(got.Findings) != 1 {
		t.Fatal("server search failed past first500")
	}
	values.Set("q", "package:openssl@1.0 !status:suppressed asset:"+asset.String())
	if got := get(values); got.Total != 605 {
		t.Fatalf("aliases/package version total%d", got.Total)
	}
	values.Set("q", "openssl !status:suppressed kev:true canonical:trivy")
	w = request(NewFindings(d, nil, nil).ByCVE, values)
	if w.Code != 200 {
		t.Fatalf("rollup status%d %s", w.Code, w.Body.String())
	}
	var rollup struct {
		Total int `json:"total"`
		CVEs  []struct {
			Instances int    `json:"instances"`
			Package   string `json:"package"`
			HasFix    bool   `json:"has_fix"`
		} `json:"cves"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rollup); err != nil {
		t.Fatal(err)
	}
	if rollup.Total != 1 || len(rollup.CVEs) != 1 || rollup.CVEs[0].Instances != 606 || rollup.CVEs[0].Package != "openssl" || !rollup.CVEs[0].HasFix {
		t.Fatalf("rollup %+v", rollup)
	}
	for _, bad := range []string{"typo:value", "status:", "kev:garbage"} {
		values.Set("q", bad)
		for _, handler := range []http.HandlerFunc{NewFindings(d, nil, nil).List, NewFindingsCSV(d).Stream, NewFindings(d, nil, nil).ByCVE} {
			if w := request(handler, values); w.Code != 400 {
				t.Fatalf("invalid query status%d", w.Code)
			}
		}
	}
	values.Set("q", "")
	values.Set("cluster_id", "bad")
	if w := request(NewFindingsCSV(d).Stream, values); w.Code != 400 {
		t.Fatal("CSV accepted bad cluster")
	}
	values.Set("cluster_id", cluster.String())
	values.Set("sort", "risk; DROP TABLE findings")
	if w := request(NewFindings(d, nil, nil).List, values); w.Code != 400 {
		t.Fatal("accepted unlisted sort")
	}
	values.Set("sort", "cvss")
	values.Set("order", "desc")
	if got := get(values); got.Total != 606 || len(got.Findings) == 0 || got.Findings[0].CVSSBase != 8.7 {
		t.Fatalf("sorted filter total%d", got.Total)
	}
}
