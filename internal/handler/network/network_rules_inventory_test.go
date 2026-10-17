package network

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

type networkRulesInventoryResponse struct {
	Rules          []networkRuleInventoryRow   `json:"rules"`
	Total          int64                       `json:"total"`
	HasMore        bool                        `json:"has_more"`
	Summary        map[string]int64            `json:"summary"`
	Filters        networkRuleInventoryFilters `json:"filters"`
	SourceComplete bool                        `json:"source_complete"`
	Sort, Order    string
}

func TestNetworkRuleDisplayIDSQLMatchesGo(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	for _, pair := range [][2]string{{"", ""}, {"default/api", "default/db"}, {"external", "prod/api"}, {"équipe/服务", "🙂/数据库"}, {strings.Repeat("overflow", 100), strings.Repeat("雪", 60)}, {"a", "bc"}, {"ab", "c"}, {"App/API", "app/api"}} {
		var got int64
		if err := d.Pool().QueryRow(context.Background(), `SELECT network_rule_display_id($1,$2)`, pair[0], pair[1]).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != int64(ruleID(pair[0], pair[1])) {
			t.Fatalf("FNV %q got%d want%d", pair, got, ruleID(pair[0], pair[1]))
		}
	}
}
func TestNetworkRulesInventoryFullCohortPagingFiltersAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	p := d.Pool()
	ctx := context.Background()
	org, foreignOrg, cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, o := range []uuid.UUID{org, foreignOrg} {
		if _, err := p.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, o, "network-inventory-"+o.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = p.Exec(ctx, `DELETE FROM network_flow_rollups WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = p.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := p.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,sum_sessions) SELECT $1,$2,'app/w-'||lpad(i::text,4,'0'),'app/db','tcp',443,CASE WHEN i%2=0 THEN 'allow' ELSE 'deny' END,date_trunc('hour',NOW()),NOW(),i FROM generate_series(1,3105)i`, org, cluster); err != nil {
		t.Fatal(err)
	}
	for _, scope := range [][2]uuid.UUID{{org, sibling}, {foreignOrg, foreign}} {
		if _, err := p.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,sum_sessions) VALUES($1,$2,'app/tail-foreign','app/db','tcp',date_trunc('hour',NOW()),NOW(),9999)`, scope[0], scope[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(ctx, `INSERT INTO network_rule_overrides(org_id,cluster_id,from_ep,to_ep,ports,applications,action,disable,comment,priority,cfg_type) VALUES
 ($1,$2,'manual/api','manual/db','tcp/5432',ARRAY['postgres'],'deny',true,'literal 100%_safe',-5,'user_created'),
 ($1,$2,'app/w-3105','app/db','tcp/9999',ARRAY['ignored-authored-app'],'allow',true,'tail override',-10,'learned_override'),
 ($1,$2,'absent/override','app/db','any','{}','allow',false,'not an observed/manual rule',-20,'learned_override')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'app','w-3104','Deployment','{"helm.sh/chart":"constellation-1"}')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	request := func(cl uuid.UUID, query string, export bool) *httptest.ResponseRecorder {
		t.Helper()
		path := "/clusters/" + cl.String() + "/network-rules/inventory"
		if export {
			path += ".csv"
		}
		r := httptest.NewRequestWithContext(t.Context(), "GET", path+"?"+query, nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", cl.String())
		r = r.WithContext(authctx.WithSubject(context.WithValue(r.Context(), chi.RouteCtxKey, rc), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		w := httptest.NewRecorder()
		if export {
			NewNetwork(d).NetworkRulesInventoryCSV(w, r)
		} else {
			NewNetwork(d).NetworkRulesInventory(w, r)
		}
		return w
	}
	read := func(query string) networkRulesInventoryResponse {
		t.Helper()
		w := request(cluster, query, false)
		if w.Code != 200 {
			t.Fatalf("query%s status%d %s", query, w.Code, w.Body.String())
		}
		var v networkRulesInventoryResponse
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	all := read("")
	if all.Total != 3106 || len(all.Rules) != 100 || !all.HasMore || !all.SourceComplete || all.Summary["total"] != 3106 || all.Summary["learned"] != 3105 || all.Summary["disabled"] != 2 || all.Sort != "evaluation" || all.Order != "asc" {
		t.Fatalf("full summary %+v", all)
	}
	if all.Rules[0].From != "app/w-3105" || all.Rules[1].From != "manual/api" || all.Rules[0].Ports != "443" || all.Rules[0].Applications[0] != "tcp" || all.Rules[0].CfgType != "learned_override" {
		t.Fatalf("legacy override/evaluation semantics %+v", all.Rules[:2])
	}
	for _, row := range all.Rules {
		if row.ID != ruleID(row.From, row.To) {
			t.Fatalf("display ID changed %+v", row)
		}
	}
	tail := read("sort=from&order=asc&offset=3100&limit=10")
	if tail.Total != 3106 || len(tail.Rules) != 6 || tail.HasMore || tail.Rules[0].From != "app/w-3101" || tail.Rules[5].From != "manual/api" {
		t.Fatalf("tail %+v", tail)
	}
	filtered := read("q=w-3105&action=allow&status=disabled&cfg_type=learned_override")
	if filtered.Total != 1 || len(filtered.Rules) != 1 || filtered.Summary["allow"] != 1 || filtered.Filters.Q != "w-3105" {
		t.Fatalf("tail filter %+v", filtered)
	}
	literal := read("q=" + url.QueryEscape("100%_safe"))
	if literal.Total != 1 || literal.Rules[0].From != "manual/api" {
		t.Fatalf("literal %+v", literal)
	}
	if read("q=tail-foreign").Total != 0 {
		t.Fatal("foreign/sibling leaked")
	}
	if read("hide_platform=true").Total != 3105 {
		t.Fatal("platform hide must precede summary/page")
	}
	exact := read("from=app/w-3104")
	if exact.Total != 1 || exact.Rules[0].FromPlatformRole != "core" {
		t.Fatalf("exact role %+v", exact)
	}
	empty := read("offset=2000000")
	if empty.Total != 3106 || len(empty.Rules) != 0 || empty.HasMore {
		t.Fatalf("empty out of range %+v", empty)
	}
	for _, q := range []string{"limit=0", "limit=501", "limit=abc", "offset=-1", "offset=2147483648", "sort=from&sort=to", "sort=from;DROP", "order=sideways", "action=other", "status=other", "cfg_type=other"} {
		w := request(cluster, q, false)
		if w.Code != 400 {
			t.Fatalf("invalid%s %d %s", q, w.Code, w.Body.String())
		}
	}
	if request(foreign, "", false).Code != 404 || request(uuid.New(), "", false).Code != 404 {
		t.Fatal("owned cluster gate failed")
	}
	exported := request(cluster, "sort=from&order=asc&limit=1&offset=3100", true)
	if exported.Code != 200 || exported.Header().Get("X-Export-Total") != "3106" || exported.Header().Get("X-Export-Truncated") != "false" || exported.Header().Get("X-Export-Limit") != "100000" {
		t.Fatalf("export %d %s", exported.Code, exported.Body.String())
	}
	csvRows, err := csv.NewReader(strings.NewReader(exported.Body.String())).ReadAll()
	if err != nil || len(csvRows) != 3107 || csvRows[1][3] != "app/w-0001" || csvRows[3106][3] != "manual/api" {
		t.Fatalf("complete CSV rows%d %v", len(csvRows), err)
	}
	seen := map[string]bool{}
	for _, row := range csvRows[1:] {
		if seen[row[0]] {
			t.Fatal("duplicate exact row ID")
		}
		seen[row[0]] = true
	}
	filteredCSV := request(cluster, "q=w-3105&action=allow&status=disabled&cfg_type=learned_override", true)
	rows, err := csv.NewReader(strings.NewReader(filteredCSV.Body.String())).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][0] != filtered.Rules[0].RowID || rows[1][13] != "3105" {
		t.Fatalf("matching export mismatch %v %s", err, filteredCSV.Body.String())
	}
}

func TestNetworkRulesInventoryDeterministicVerdictAndCollisionIdentity(t *testing.T) {
	d, org, actor, cluster := moveRuleFixture(t)
	p := d.Pool()
	ctx := context.Background()
	t.Cleanup(func() { _, _ = p.Exec(ctx, `DELETE FROM network_flow_rollups WHERE org_id=$1`, org) })
	if _, err := p.Exec(ctx, `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,sum_sessions) VALUES($1,$2,'app/observed','app/db','tcp',80,'allow',date_trunc('hour',NOW()),'2026-10-13T00:00:00.123456Z',10),($1,$2,'app/observed','app/db','tcp',81,'deny',date_trunc('hour',NOW()),'2026-10-13T00:00:00.123456Z',10)`, org, cluster); err != nil {
		t.Fatal(err)
	}
	first, second := "", ""
	seen := map[uint32]string{}
	for i := 0; i < 100000; i++ {
		name := fmt.Sprintf("collision/%d", i)
		id := ruleID(name, "app/db")
		if old, ok := seen[id]; ok {
			first, second = old, name
			break
		}
		seen[id] = name
	}
	if first == "" {
		t.Fatal("collision fixture unavailable")
	}
	if _, err := p.Exec(ctx, `INSERT INTO network_rule_overrides(org_id,cluster_id,from_ep,to_ep,priority) VALUES($1,$2,$3,'app/db',0),($1,$2,$4,'app/db',0)`, org, cluster, first, second); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Get("/clusters/{id}/network-rules/inventory", NewNetwork(d).NetworkRulesInventory)
	request := func(query string) networkRulesInventoryResponse {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/clusters/"+cluster.String()+"/network-rules/inventory?"+query, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: actor}))
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != 200 {
			t.Fatalf("%d %s", res.Code, res.Body.String())
		}
		var v networkRulesInventoryResponse
		_ = json.Unmarshal(res.Body.Bytes(), &v)
		return v
	}
	selected := request("from=app/observed")
	if selected.Total != 1 || selected.Rules[0].Action != "allow" || selected.Rules[0].Ports != "80" || selected.Rules[0].LastMatchTS != time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("tie or precision %+v", selected)
	}
	one := request("q=collision&sort=id&limit=1")
	two := request("q=collision&sort=id&limit=1&offset=1")
	if one.Total != 2 || !one.HasMore || two.HasMore || one.Rules[0].ID != two.Rules[0].ID || one.Rules[0].RowID == two.Rules[0].RowID {
		t.Fatalf("hash collision identities %+v %+v", one, two)
	}
	legacyRes := httptest.NewRecorder()
	legacyReq := httptest.NewRequestWithContext(t.Context(), "GET", "/clusters/"+cluster.String()+"/network-rules", nil)
	legacyReq = legacyReq.WithContext(authctx.WithSubject(legacyReq.Context(), authctx.Subject{OrgID: org, UserID: actor}))
	legacyRouter := chi.NewRouter()
	legacyRouter.Get("/clusters/{id}/network-rules", NewNetwork(d).NetworkRules)
	legacyRouter.ServeHTTP(legacyRes, legacyReq)
	var legacy struct {
		Rules []networkRuleDTO `json:"rules"`
	}
	_ = json.Unmarshal(legacyRes.Body.Bytes(), &legacy)
	fresh := request("")
	if len(legacy.Rules) != len(fresh.Rules) {
		t.Fatal("legacy cohort mismatch")
	}
	for _, row := range fresh.Rules {
		if row.Priority < 0 {
			t.Fatal("invalid fixture precedence")
		}
	}
	// Configured priority precedes learned hash priority, independently of table sorting.
	if fresh.Rules[0].Priority != 0 || fresh.Rules[1].Priority != 0 || fresh.Rules[len(fresh.Rules)-1].CfgType != "learned" {
		t.Fatalf("default precedence %+v", fresh.Rules)
	}
}

func TestNetworkRuleInventoryStrictPaging(t *testing.T) {
	for _, raw := range []string{"offset=" + fmt.Sprint(inventorylist.MaxOffset+1), "limit=5000", "sort=unknown", "hide_platform=1", "limit=1&limit=2"} {
		values, err := url.ParseQuery(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := networkRuleInventoryOptions(values); err == nil {
			t.Fatal("accepted", raw)
		}
	}
}

func TestNetworkRulesInventoryReadFailureIsUnavailable(t *testing.T) {
	d, org, actor, cluster := moveRuleFixture(t)
	pool := d.Pool()
	ctx := context.Background()
	role := pgx.Identifier{"rule_inventory_test_" + uuid.New().String()}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP OWNED BY `+role); _, _ = pool.Exec(ctx, `DROP ROLE `+role) })
	for _, sql := range []string{`GRANT USAGE ON SCHEMA public TO ` + role, `GRANT SELECT ON clusters,network_flow_rollups TO ` + role} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg := pool.Config().Copy()
	cfg.MinConns = 0
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["role"] = role[1 : len(role)-1]
	restricted, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restricted.Close)
	h := NewNetwork(db.NewFromPool(restricted))
	router := chi.NewRouter()
	router.Get("/clusters/{id}/network-rules/inventory", h.NetworkRulesInventory)
	router.Get("/clusters/{id}/network-rules/inventory.csv", h.NetworkRulesInventoryCSV)
	for _, suffix := range []string{"", ".csv"} {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/clusters/"+cluster.String()+"/network-rules/inventory"+suffix, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: actor}))
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		var body map[string]any
		_ = json.Unmarshal(res.Body.Bytes(), &body)
		if res.Code != 500 || body["error"] == nil || body["rules"] != nil || res.Header().Get("X-Export-Total") != "" {
			t.Fatalf("query failure %d %s", res.Code, res.Body.String())
		}
	}
}
