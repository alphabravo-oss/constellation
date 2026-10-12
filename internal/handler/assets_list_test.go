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

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/google/uuid"
)

func TestAssetsServerInventoryFiltersCountsPagingAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreign, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "assets-list-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id IN($1,$2)`, org, foreign)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$4,'main'),($2,$4,'sibling'),($3,$5,'foreign')`, cluster, sibling, foreignCluster, org, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(org_id,cluster_id,kind,name,labels,criticality,ai_workload,last_seen_at) SELECT $1,$2,'workload',CASE WHEN n=1205 THEN 'needle%_deep' ELSE 'workload-'||lpad(n::text,4,'0') END,jsonb_build_object('team','prod'),'high',n=1205,'2026-10-12' FROM generate_series(1,1205)n`, org, cluster); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		o, c uuid.UUID
		name string
	}{{org, sibling, "sibling"}, {foreign, foreignCluster, "foreign"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO assets(org_id,cluster_id,kind,name,labels,criticality) VALUES($1,$2,'workload',$3,'{}','high')`, item.o, item.c, item.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(org_id,kind,name,labels,criticality) VALUES($1,'ml-model','global','{}','low')`, org); err != nil {
		t.Fatal(err)
	}
	var needle uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM assets WHERE org_id=$1 AND name='needle%_deep'`, org).Scan(&needle); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,asset_id,cluster_id,kind,title,severity,lifecycle) VALUES($1,$2,$3,'runtime','main','critical','open'),($1,$2,$4,'runtime','wrong cluster','critical','open'),($5,$2,$3,'runtime','foreign','critical','open')`, org, needle, cluster, sibling, foreign); err != nil {
		t.Fatal(err)
	}
	for i, signed := range []any{false, true, nil} {
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name,labels,criticality,digest) VALUES($1,$2,$3,'image',$4,'{}','low',$4)`, id, org, cluster, "image-"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
		if signed != nil {
			if _, err := pool.Exec(ctx, `INSERT INTO images(asset_id,registry,repository,tag,digest,signed) VALUES($1,'registry','repo','tag','sha256:fixture',$2)`, id, signed); err != nil {
				t.Fatal(err)
			}
		}
	}
	h := NewAssets(d)
	request := func(query string, export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, "/assets?"+query, nil)
		w := httptest.NewRecorder()
		if export {
			h.ExportCSV(w, r)
		} else {
			h.List(w, r)
		}
		return w
	}
	type page struct {
		Rows []assetDTO `json:"assets"`
		inventorylist.Metadata
		Limit, Offset int
	}
	read := func(values url.Values) page {
		t.Helper()
		w := request(values.Encode(), false)
		if w.Code != 200 {
			t.Fatalf("list %d %s", w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	params := url.Values{"cluster_id": {cluster.String()}, "kind": {"workload"}, "limit": {"100"}, "sort": {"asset"}, "order": {"asc"}}
	first := read(params)
	if first.Total != 1205 || len(first.Rows) != 100 || !first.HasMore || first.Summary["critical_high"] != 1 {
		t.Fatalf("first %+v", first.Metadata)
	}
	params.Set("offset", "1200")
	last := read(params)
	if last.Total != 1205 || len(last.Rows) != 5 || last.HasMore {
		t.Fatalf("last %+v", last)
	}
	params.Set("offset", "9999")
	end := read(params)
	if end.Total != 1205 || len(end.Rows) != 0 || end.HasMore {
		t.Fatalf("empty %+v", end.Metadata)
	}
	params.Del("offset")
	params.Set("search", "%_")
	deep := read(params)
	if deep.Total != 1 || deep.Rows[0].ID != needle {
		t.Fatalf("literal search %+v", deep)
	}
	params.Del("search")
	params.Set("q", "kind:workload name:needle")
	if p := read(params); p.Total != 1 {
		t.Fatal("existing DSL changed")
	}
	params.Del("q")
	params.Set("ai_workload", "true")
	params.Set("criticality", "high")
	filtered := read(params)
	if filtered.Total != 1 || filtered.Summary["ai"] != 1 || filtered.Rows[0].CriticalFindings != 1 {
		t.Fatalf("filtered %+v", filtered)
	}
	csvW := request(params.Encode(), true)
	records, err := csv.NewReader(csvW.Body).ReadAll()
	if err != nil || csvW.Code != 200 || len(records) != 2 || records[1][0] != needle.String() || csvW.Header().Get("X-Export-Total") != "1" {
		t.Fatalf("filtered CSV %d rows%d err%v", csvW.Code, len(records), err)
	}
	params.Del("ai_workload")
	params.Del("criticality")
	csvW = request(params.Encode()+"&offset=9999", true)
	records, err = csv.NewReader(csvW.Body).ReadAll()
	if err != nil || len(records) != 1206 {
		t.Fatalf("full CSV count %d %v", len(records), err)
	}
	params.Set("kind", "image")
	images := read(params)
	if images.Total != 3 || images.Summary["unsigned_images"] != 1 || images.Summary["signed_images"] != 1 || images.Summary["signature_unknown"] != 1 || images.Summary["missing_sbom"] != 3 {
		t.Fatalf("signature counts %+v", images.Metadata)
	}
	params.Set("limit", "1000")
	if p := read(params); p.Limit != 1000 {
		t.Fatal("legacy limit1000 changed")
	}
	params = url.Values{"cluster_id": {cluster.String()}}
	risk := read(params)
	if risk.Rows[0].ID != needle {
		t.Fatal("risk rank lost source aggregates")
	}
	for _, query := range []string{"kind=invalid", "criticality=invalid", "ai_workload=maybe", "sort=unsafe", "order=unsafe", "q=unknown:value", "search=bad%ZZ"} {
		for _, export := range []bool{false, true} {
			if w := request(query, export); w.Code != 400 {
				t.Fatalf("invalid %s status%d", query, w.Code)
			}
		}
	}
	for _, export := range []bool{false, true} {
		if w := request("cluster_id="+foreignCluster.String(), export); w.Code != 404 {
			t.Fatalf("foreign cluster status%d", w.Code)
		}
		if w := request("cluster_id="+uuid.NewString(), export); w.Code != 404 {
			t.Fatalf("missing cluster status%d", w.Code)
		}
	}
	if strings.Contains(request("", true).Body.String(), "foreign") {
		t.Fatal("tenant leaked in org export")
	}
}
