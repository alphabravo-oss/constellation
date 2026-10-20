//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestAssetsClusterIdentityPreservesTenantAndListScope(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool, ctx := database.Pool(), t.Context()
	org, foreign := uuid.New(), uuid.New()
	cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New()
	mainAsset, siblingAsset, foreignAsset, unscopedAsset := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "asset-scope-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreign) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$4,'main'),($2,$4,'sibling'),($3,$5,'foreign')`, cluster, sibling, foreignCluster, org, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name,labels,criticality) VALUES
 ($1,$5,$7,'host','main','{}','medium'),($2,$5,$8,'host','sibling','{}','medium'),
 ($3,$6,$9,'host','foreign','{}','medium'),($4,$5,NULL,'host','unscoped','{}','medium')`,
		mainAsset, siblingAsset, foreignAsset, unscopedAsset, org, foreign, cluster, sibling, foreignCluster); err != nil {
		t.Fatal(err)
	}
	handler := NewAssets(database)
	get := func(id uuid.UUID) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/assets/"+id.String(), nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", id.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: org}))
		w := httptest.NewRecorder()
		handler.Get(w, req)
		return w
	}
	for _, fixture := range []struct{ asset, cluster uuid.UUID }{{mainAsset, cluster}, {siblingAsset, sibling}} {
		w := get(fixture.asset)
		if w.Code != http.StatusOK {
			t.Fatalf("get status=%d", w.Code)
		}
		var body struct{ Asset assetDTO }
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Asset.ID != fixture.asset || body.Asset.ClusterID == nil || *body.Asset.ClusterID != fixture.cluster {
			t.Fatalf("wrong exact asset identity: %+v", body.Asset)
		}
	}
	if w := get(foreignAsset); w.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant asset returned status=%d", w.Code)
	}
	w := get(unscopedAsset)
	if w.Code != http.StatusOK {
		t.Fatalf("unscoped get status=%d", w.Code)
	}
	var unscoped struct{ Asset map[string]json.RawMessage }
	if err := json.Unmarshal(w.Body.Bytes(), &unscoped); err != nil {
		t.Fatal(err)
	}
	if _, exists := unscoped.Asset["cluster_id"]; exists {
		t.Fatal("unscoped asset must not invent a cluster identity")
	}
	for _, scope := range []uuid.UUID{cluster, sibling, foreignCluster} {
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/assets?cluster_id="+scope.String(), nil)
		req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: org}))
		w := httptest.NewRecorder()
		handler.List(w, req)
		if scope == foreignCluster {
			if w.Code != http.StatusNotFound {
				t.Fatalf("foreign cluster list status=%d", w.Code)
			}
			continue
		}
		if w.Code != http.StatusOK {
			t.Fatalf("list status=%d", w.Code)
		}
		var result struct{ Assets []assetDTO }
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		want := 1
		if scope == foreignCluster {
			want = 0
		}
		if len(result.Assets) != want {
			t.Fatalf("scope %s returned %d assets, want %d", scope, len(result.Assets), want)
		}
		for _, asset := range result.Assets {
			if asset.ClusterID == nil || *asset.ClusterID != scope {
				t.Fatalf("list identity does not match requested scope: %+v", asset)
			}
		}
	}
}
