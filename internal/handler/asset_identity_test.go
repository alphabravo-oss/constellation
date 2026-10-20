//go:build integration

package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestAssetImageDisplayIdentityAcrossListDetailSortAndExport(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool, ctx := d.Pool(), t.Context()
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "asset-name-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, labels, registry, repo, tag, want string }{
		{"sha256:aaa", `{"image_ref_normalized":"docker.io/pgvector/pgvector:pg16@sha256:aaa"}`, "", "", "", "docker.io/pgvector/pgvector:pg16"},
		{"sha256:bbb", `{}`, "registry:5000", "team/api", "v2", "registry:5000/team/api:v2"},
		{"sha256:ccc", `{}`, "registry:5000", "registry:5000/team/api", "v3", "registry:5000/team/api:v3"},
		{"sha256:ddd", `{"image_repository":"team/worker","image_tag":"v4"}`, "", "", "", "team/worker:v4"},
		{"sha256:eee", `{"image_ref":"sha256:eee"}`, "", "", "", "Unnamed image"},
		{"team/legacy:v5@sha256:fff", `{}`, "", "", "", "team/legacy:v5"},
	}
	ids := make([]uuid.UUID, len(cases))
	h := NewAssets(d)
	for n, c := range cases {
		id := uuid.New()
		ids[n] = id
		if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name,digest,labels) VALUES($1,$2,$3,'image',$4,$4,$5)`, id, org, cluster, c.name, c.labels); err != nil {
			t.Fatal(err)
		}
		if c.repo != "" {
			if _, err := pool.Exec(ctx, `INSERT INTO images(asset_id,registry,repository,tag,digest) VALUES($1,$2,$3,$4,$5)`, id, c.registry, c.repo, c.tag, c.name); err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequestWithContext(t.Context(), "GET", "/assets/"+id.String(), nil).WithContext(WithSubject(t.Context(), Subject{OrgID: org}))
		route := chi.NewRouteContext()
		route.URLParams.Add("id", id.String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		w := httptest.NewRecorder()
		h.Get(w, r)
		var result struct {
			Asset assetDTO `json:"asset"`
		}
		if w.Code != 200 {
			t.Fatalf("detail %d %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Asset.DisplayName != c.want || result.Asset.Name != c.name {
			t.Fatalf("identity got %q/%q want %q/raw %q", result.Asset.DisplayName, result.Asset.Name, c.want, c.name)
		}
	}
	request := func(export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(t.Context(), "GET", "/assets?cluster_id="+cluster.String()+"&sort=asset&order=asc", nil).WithContext(WithSubject(t.Context(), Subject{OrgID: org}))
		w := httptest.NewRecorder()
		if export {
			h.ExportCSV(w, r)
		} else {
			h.List(w, r)
		}
		if w.Code != 200 {
			t.Fatalf("read %d %s", w.Code, w.Body.String())
		}
		return w
	}
	var result struct {
		Assets []assetDTO `json:"assets"`
	}
	if err := json.Unmarshal(request(false).Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Assets) != len(cases) {
		t.Fatalf("rows %d", len(result.Assets))
	}
	for n := 1; n < len(result.Assets); n++ {
		if strings.ToLower(result.Assets[n-1].DisplayName) > strings.ToLower(result.Assets[n].DisplayName) {
			t.Fatal("sort must follow display names")
		}
	}
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/assets?cluster_id="+cluster.String()+"&search=registry%3A5000%2Fteam%2Fapi%3Av2", nil).WithContext(WithSubject(t.Context(), Subject{OrgID: org}))
	w := httptest.NewRecorder()
	h.List(w, r)
	var found struct {
		Assets []assetDTO `json:"assets"`
	}
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &found); err != nil {
		t.Fatal(err)
	}
	if len(found.Assets) != 1 || found.Assets[0].DisplayName != "registry:5000/team/api:v2" {
		t.Fatalf("display-name search: %+v", found)
	}
	records, err := csv.NewReader(request(true).Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	display := -1
	for n, key := range records[0] {
		if key == "Display name" {
			display = n
		}
	}
	if display < 0 {
		t.Fatal("missing display name CSV")
	}
	for n, row := range records[1:] {
		if row[display] != result.Assets[n].DisplayName {
			t.Fatal("CSV identity/order differs")
		}
	}
}
