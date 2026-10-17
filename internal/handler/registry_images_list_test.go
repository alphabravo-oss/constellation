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

func TestRegistryImageInventoryLiteralFiltersStableScansAndMatchingCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreignOrg, registry, sibling, foreignRegistry := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "registry-inventory-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg) })
	if _, err := pool.Exec(ctx, `INSERT INTO registries(id,org_id,name,kind,endpoint,auth_kind) VALUES($1,$2,'main','generic-v2','https://example.test','none'),($3,$2,'sibling','generic-v2','https://sibling.test','none'),($4,$5,'foreign','generic-v2','https://foreign.test','none')`, registry, org, sibling, foreignRegistry, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO registry_images(org_id,registry_id,repository,tags,digests,last_seen_at) SELECT $1,$2,CASE WHEN n=610 THEN 'team/tail%_needle' ELSE 'team/app'||lpad(n::text,4,'0') END,ARRAY['latest','release'],jsonb_build_object('latest','sha256:'||repeat('a',64)),'2026-10-12' FROM generate_series(1,610)n`, org, registry); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO registry_images(org_id,registry_id,repository) VALUES($1,$2,'team/tail%_sibling'),($3,$4,'team/tail%_foreign')`, org, sibling, foreignOrg, foreignRegistry); err != nil {
		t.Fatal(err)
	}
	old, newest := uuid.MustParse("00000000-0000-0000-0000-000000003001"), uuid.MustParse("00000000-0000-0000-0000-000000003002")
	if _, err := pool.Exec(ctx, `INSERT INTO image_scan_results(id,org_id,image_ref,image_ref_normalized,image_repository,image_digest,finding_count,last_scanned_at) VALUES
 ($1,$3,'team/app0001:old','team/app0001:old','team/app0001','sha256:old',9,'2026-10-12'),
 ($2,$3,'team/app0001:new','team/app0001:new','team/app0001','sha256:new',2,'2026-10-12'),
 (gen_random_uuid(),$3,'team/app0002:latest','team/app0002:latest','team/app0002','sha256:second',0,'2026-10-11'),
 (gen_random_uuid(),$4,'team/app0001:foreign','team/app0001:foreign','team/app0001','sha256:foreign',999,'2027-01-01')`, old, newest, org, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,title,severity) VALUES($1,$2,'critical','critical','critical'),($1,$2,'high','high','high'),($1,$3,'old','old','critical'),($4,$2,'foreign-poison','foreign','critical')`, org, newest, old, foreignOrg); err != nil {
		t.Fatal(err)
	}
	h := NewRegistries(d, nil)
	request := func(id string, values url.Values, export bool, authenticated bool) *httptest.ResponseRecorder {
		requestCtx := ctx
		if authenticated {
			requestCtx = WithSubject(ctx, Subject{OrgID: org})
		}
		r := httptest.NewRequestWithContext(requestCtx, http.MethodGet, "/images?"+values.Encode(), nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", id)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		if export {
			h.ImagesCSV(w, r)
		} else {
			h.Images(w, r)
		}
		return w
	}
	type page struct {
		Images  []registryImageRow
		Total   int
		HasMore bool `json:"has_more"`
		Summary map[string]int
	}
	read := func(values url.Values) page {
		t.Helper()
		w := request(registry.String(), values, false, true)
		if w.Code != 200 {
			t.Fatalf("list%d %s", w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	all := read(nil)
	if all.Total != 610 || len(all.Images) != 100 || !all.HasMore || all.Summary["scanned"] != 2 || all.Summary["unscanned"] != 608 || all.Summary["critical"] != 1 || all.Summary["high"] != 1 || all.Images[0].FindingCount != 2 || all.Images[0].Repository != "team/app0001" {
		t.Fatalf("summary/latest %+v", all)
	}
	tail := read(url.Values{"q": {"%_"}})
	if tail.Total != 1 || tail.Images[0].Repository != "team/tail%_needle" {
		t.Fatalf("literal tail %+v", tail)
	}
	last := read(url.Values{"sort": {"repository"}, "order": {"asc"}, "offset": {"600"}})
	if last.Total != 610 || len(last.Images) != 10 || last.HasMore || last.Images[9].Repository != "team/tail%_needle" {
		t.Fatalf("tail continuation %+v", last)
	}
	empty := read(url.Values{"offset": {"9999"}})
	if empty.Total != 610 || len(empty.Images) != 0 || empty.HasMore || empty.Summary["scanned"] != 2 {
		t.Fatal("out-of-range metadata lost")
	}
	for _, test := range []struct {
		values url.Values
		total  int
	}{
		{url.Values{"scan_status": {"unscanned"}}, 608}, {url.Values{"scan_status": {"scanned"}}, 2}, {url.Values{"severity": {"critical"}}, 1}, {url.Values{"severity": {"high"}}, 1}, {url.Values{"severity": {"none"}}, 1}, {url.Values{"scan_status": {"unscanned"}, "severity": {"none"}}, 0}, {url.Values{"q": {"%_"}}, 1}, {url.Values{"sort": {"vulnerabilities"}, "order": {"desc"}, "offset": {"9999"}}, 610},
	} {
		p := read(test.values)
		if p.Total != test.total {
			t.Fatalf("filter%v total%d want%d", test.values, p.Total, test.total)
		}
		w := request(registry.String(), test.values, true, true)
		rows, err := csv.NewReader(w.Body).ReadAll()
		if err != nil || w.Code != 200 || len(rows) != test.total+1 || w.Header().Get("X-Export-Total") != strconv.Itoa(test.total) {
			t.Fatalf("matching export filter%v status%d rows%d err%v", test.values, w.Code, len(rows), err)
		}
		for _, row := range rows[1:] {
			if row[1] != registry.String() || row[2] == "team/tail%_sibling" || row[2] == "team/tail%_foreign" {
				t.Fatal("CSV borrowed registry")
			}
		}
	}
	repeated := read(nil)
	for i, row := range all.Images {
		if repeated.Images[i].ID != row.ID {
			t.Fatal("tie ordering changed")
		}
	}
	for _, export := range []bool{false, true} {
		for _, test := range []struct {
			id     string
			values url.Values
			auth   bool
			status int
		}{
			{foreignRegistry.String(), nil, true, 404}, {uuid.New().String(), nil, true, 404}, {"invalid", nil, true, 400}, {registry.String(), nil, false, 401},
			{registry.String(), url.Values{"sort": {"bad"}}, true, 400}, {registry.String(), url.Values{"scan_status": {"bad"}}, true, 400}, {registry.String(), url.Values{"severity": {"bad"}}, true, 400}, {registry.String(), url.Values{"order": {"bad"}}, true, 400},
		} {
			if w := request(test.id, test.values, export, test.auth); w.Code != test.status {
				t.Fatalf("boundary%d want%d %s", w.Code, test.status, w.Body.String())
			}
		}
	}
}
