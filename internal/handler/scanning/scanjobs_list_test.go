package scanning

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

func TestScanJobsInventoryContinuationAndExport(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	org, foreign := uuid.New(), uuid.New()
	target, foreignTarget := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Job inventory')`, id, "job-inventory-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=ANY($1)`, []uuid.UUID{org, foreign}) })
	for _, pair := range [][2]uuid.UUID{{target, org}, {foreignTarget, foreign}} {
		if _, err := pool.Exec(ctx, `INSERT INTO scan_targets(id,org_id,type,ref,source_type) VALUES($1,$2,'image','registry.test/app_%:latest','manual')`, pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs(id,org_id,target_id,status,requested_at,finding_count) SELECT gen_random_uuid(),$1,$2,CASE WHEN i%2=0 THEN 'completed' ELSE 'failed' END,'2026-10-01'::timestamptz,i FROM generate_series(1,650)i`, org, target); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs(id,org_id,target_id,status) VALUES(gen_random_uuid(),$1,$2,'pending')`, foreign, foreignTarget); err != nil {
		t.Fatal(err)
	}

	cluster, siblingCluster, foreignCluster, registry, foreignRegistry := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, pair := range [][2]uuid.UUID{{cluster, org}, {siblingCluster, org}, {foreignCluster, foreign}} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,$3)`, pair[0], pair[1], pair[0].String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]uuid.UUID{{registry, org}, {foreignRegistry, foreign}} {
		if _, err := pool.Exec(ctx, `INSERT INTO registries(id,org_id,name,kind,endpoint,auth_kind) VALUES($1,$2,$3,'generic-v2','https://registry.test','none')`, pair[0], pair[1], pair[0].String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE scan_targets SET cluster_id=$1,registry_id=$2 WHERE id=$3`, cluster, registry, target); err != nil {
		t.Fatal(err)
	}
	h := NewScanJobs(d, nil)
	request := func(query string, export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scan-jobs?"+query, nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		w := httptest.NewRecorder()
		if export {
			h.ExportCSV(w, r)
		} else {
			h.List(w, r)
		}
		return w
	}
	type response struct {
		Jobs    []JobView      `json:"jobs"`
		Total   int            `json:"total"`
		HasMore bool           `json:"has_more"`
		Summary map[string]int `json:"summary"`
		Limit   int            `json:"limit"`
		Offset  int            `json:"offset"`
	}
	get := func(q string) response {
		t.Helper()
		w := request(q, false)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body.String())
		}
		var got response
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	if got := get("cluster_id=" + cluster.String() + "&registry_id=" + registry.String()); got.Total != 650 {
		t.Fatal("exact scope missing")
	}
	if got := get("cluster_id=" + siblingCluster.String()); got.Total != 0 {
		t.Fatal("sibling cluster leak")
	}
	for _, q := range []string{"cluster_id=" + foreignCluster.String(), "registry_id=" + foreignRegistry.String()} {
		if w := request(q, false); w.Code != 404 {
			t.Fatalf("foreignscope%s: %d", q, w.Code)
		}
	}
	a := get("sort=findings&order=asc&limit=100")
	b := get("sort=findings&order=asc&limit=100&offset=600")
	if a.Total != 650 || len(a.Jobs) != 100 || !a.HasMore || a.Summary["failed"] != 325 || a.Jobs[0].FindingCount != 1 || b.Jobs[0].FindingCount != 601 || len(b.Jobs) != 50 || b.HasMore {
		t.Fatalf("continuation a=%+v b=%+v", a, b)
	}
	// Equal timestamps retain exact identity order, stable across requests.
	first, second := get("limit=100"), get("limit=100&offset=100")
	seen := map[uuid.UUID]bool{}
	for _, j := range first.Jobs {
		seen[j.ID] = true
	}
	for _, j := range second.Jobs {
		if seen[j.ID] {
			t.Fatal("overlapping tie pages")
		}
	}
	if got := get(""); got.Limit != 200 || len(got.Jobs) != 200 || got.Total != 650 {
		t.Fatalf("legacy default %+v", got)
	}
	literal := url.QueryEscape("app_%")
	filtered := get("q=" + literal + "&status=failed&offset=300&limit=100&sort=findings&order=desc")
	if filtered.Total != 325 || len(filtered.Jobs) != 25 || filtered.Summary["completed"] != 0 {
		t.Fatalf("filtered %+v", filtered)
	}
	if got := get("q=" + url.QueryEscape("missing%")); got.Total != 0 {
		t.Fatal("wildcard query")
	}
	if got := get("offset=9999"); got.Total != 650 || len(got.Jobs) != 0 || got.HasMore {
		t.Fatal("empty continuation metadata")
	}
	w := request("q="+literal+"&status=failed&sort=findings&order=desc&offset=9999&limit=1", true)
	if w.Code != 200 {
		t.Fatalf("CSV %s", w.Body.String())
	}
	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 326 || w.Header().Get("X-Export-Total") != "325" || w.Header().Get("X-Export-Truncated") != "false" || records[1][10] != "649" {
		t.Fatalf("CSV rows %d metadata%v", len(records), w.Header())
	}
	for _, q := range []string{"status=unknown", "target_type=unknown", "sort=unknown", "order=wat", "cluster_id=bad", "registry_id=bad"} {
		if got := request(q, false); got.Code != 400 {
			t.Fatalf("invalid%s status%d", q, got.Code)
		}
	}
	for _, q := range []string{"cluster_id=" + uuid.NewString(), "registry_id=" + uuid.NewString()} {
		if got := request(q, false); got.Code != 404 {
			t.Fatalf("missing scope%s status%d", q, got.Code)
		}
	}
}
