//go:build integration

package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestComponentsInventoryContinuation(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := t.Context()
	org, foreign, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "components-continuation-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign); err != nil {
			t.Error(err)
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'selected'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreignCluster, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO component_heartbeats(org_id,cluster_id,component,hostname,version,commit,metadata,last_seen_at,first_seen_at,uptime_seconds) SELECT $1,$2,'runtime-agent','bulk-host-'||lpad(i::text,4,'0'),'v1','good','{}'::jsonb,NOW(),NOW(),i FROM generate_series(0,1004) i`, org, cluster); err != nil {
		t.Fatal(err)
	}
	insert := func(o uuid.UUID, c any, component, host, version, commit, age, metadata string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO component_heartbeats(id,org_id,cluster_id,component,hostname,version,commit,metadata,last_seen_at,first_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NOW()-$9::interval,NOW()-$9::interval)`, id, o, c, component, host, version, commit, metadata, age); err != nil {
			t.Fatal(err)
		}
		return id
	}
	selectedID := uuid.Nil
	healthyID := uuid.Nil
	if err := pool.QueryRow(ctx, `SELECT id FROM component_heartbeats WHERE org_id=$1 AND cluster_id=$2 AND hostname='bulk-host-0000'`, org, cluster).Scan(&selectedID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM component_heartbeats WHERE org_id=$1 AND cluster_id=$2 AND hostname='bulk-host-1004'`, org, cluster).Scan(&healthyID); err != nil {
		t.Fatal(err)
	}
	staleID := insert(org, cluster, "runtime-agent", "superseded-agent", "v0", "old", "10 minutes", "{}")
	insert(org, cluster, "scanner", "scanner-a", "v1", "good", "0 seconds", `{"active_jobs":1,"max_concurrent":5,"idle_capacity":4}`)
	insert(org, cluster, "scanner", "scanner-b", "v2", "good", "0 seconds", `{"active_jobs":2,"max_concurrent":10,"idle_capacity":8}`)
	insert(org, cluster, "worker", "literal%_\\host", "v1", "good", "0 seconds", "{}")
	insert(org, sibling, "runtime-agent", "bulk-host-0000", "v1", "good", "0 seconds", "{}")
	insert(org, nil, "api", "org-api", "v1", "good", "0 seconds", "{}")
	insert(org, foreignCluster, "scanner", "misattributed", "v1", "foreign-baseline", "0 seconds", "{}")
	insert(foreign, foreignCluster, "scanner", "foreign-org", "v1", "good", "0 seconds", "{}")
	insert(org, cluster, "worker", "older-than-source", "v1", "good", "25 hours", "{}")
	// Four relevant events were outside the old latest200 ledger bound. Hundreds of
	// unrelated later events must neither hide them nor classify sibling hosts.
	if _, err := pool.Exec(ctx, `INSERT INTO component_restart_events(org_id,cluster_id,component,hostname,prev_uptime_s,new_uptime_s,detected_at) SELECT $1,$2,'runtime-agent','bulk-host-0000',100,1,NOW()-INTERVAL '20 minutes' FROM generate_series(1,4);`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO component_restart_events(org_id,cluster_id,component,hostname,prev_uptime_s,new_uptime_s,detected_at) SELECT $1,$2,'runtime-agent','bulk-host-0010',100,1,NOW()-INTERVAL '5 minutes' FROM generate_series(1,205)`, org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewComponentsInventory(d)
	router := chi.NewRouter()
	router.Get("/components/{id}", h.Get)
	request := func(handle http.HandlerFunc, params string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, "/components?"+params, nil)
		w := httptest.NewRecorder()
		handle(w, r)
		return w
	}
	type response struct {
		Components           []componentInstanceDTO
		Rollups              []componentInventoryRollupDTO
		Summary              componentInventorySummaryDTO
		Total, Limit, Offset int
		HasMore              bool           `json:"has_more"`
		RoleCounts           map[string]int `json:"role_counts"`
		Window               int            `json:"source_window_hours"`
	}
	read := func(params string) response {
		t.Helper()
		w := request(h.List, params)
		if w.Code != 200 {
			t.Fatalf("list %d %s", w.Code, w.Body.String())
		}
		var body response
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	base := "cluster_id=" + cluster.String()
	t.Run("uncapped matching totals and coherent full rollups across pages", func(t *testing.T) {
		first := read(base + "&limit=100&sort=component&order=asc")
		if first.Total != 1009 || len(first.Components) != 100 || !first.HasMore || first.Summary.TotalInstances != 1009 || first.RoleCounts["enforcer"] != 1006 || first.Window != 24 {
			t.Fatalf("metadata total%d rows%d summary%+v counts%v", first.Total, len(first.Components), first.Summary, first.RoleCounts)
		}
		capacityFound := false
		for _, rollup := range first.Rollups {
			if rollup.Component == "scanner" {
				capacityFound = true
				if rollup.ScannerCapacity["active_jobs"] != 3 || rollup.ScannerCapacity["max_concurrent"] != 15 || rollup.ScannerCapacity["idle_capacity"] != 12 {
					t.Fatalf("full capacity %v", rollup.ScannerCapacity)
				}
			}
		}
		if !capacityFound {
			t.Fatal("scanner rollup missing")
		}
		seen := map[uuid.UUID]bool{}
		for offset := 0; offset < 1009; offset += 100 {
			values := url.Values{"cluster_id": {cluster.String()}, "limit": {"100"}, "offset": {strconv.Itoa(offset)}, "sort": {"runtime"}, "order": {"desc"}}
			page := read(values.Encode())
			if page.Total != 1009 || page.HasMore != (offset < 1000) {
				t.Fatalf("metadata page%d total%d more%t", offset, page.Total, page.HasMore)
			}
			for _, item := range page.Components {
				if seen[item.ID] {
					t.Fatalf("duplicate page id %s", item.ID)
				}
				seen[item.ID] = true
			}
		}
		if len(seen) != 1009 {
			t.Fatalf("loaded %d", len(seen))
		}
		empty := read(base + "&limit=100&offset=2000")
		if len(empty.Components) != 0 || empty.Total != 1009 || empty.HasMore {
			t.Fatalf("out of range %+v", empty)
		}
	})
	t.Run("server filters reach beyond1000 and preserve full health", func(t *testing.T) {
		late := read(base + "&q=bulk-host-1004&role=enforcer&status=healthy&limit=100")
		if late.Total != 1 || late.Components[0].Hostname != "bulk-host-1004" || late.Summary.TotalInstances != 1009 {
			t.Fatalf("late match total%d rows%v summary%+v", late.Total, late.Components, late.Summary)
		}
		scanner := read(base + "&role=scanner&limit=100&sort=build&order=desc")
		if scanner.Total != 2 || scanner.Components[0].Version != "v2" {
			t.Fatalf("scanner filter %+v", scanner)
		}
		for _, term := range []string{"literal%_\\host", "%_\\does-not-exist"} {
			match := read(base + "&q=" + url.QueryEscape(term))
			want := 0
			if strings.HasPrefix(term, "literal") {
				want = 1
			}
			if match.Total != want {
				t.Fatalf("literal %q total%d", term, match.Total)
			}
		}
		exact := read(base + "&component=worker")
		if exact.Total != 1 {
			t.Fatalf("component filter total%d", exact.Total)
		}
		missing := read(base + "&status=missing")
		if missing.Total != 0 || missing.Summary.Missing == 0 {
			t.Fatalf("missing family incorrectly creates matching instance %+v", missing)
		}
	})
	t.Run("restart and superseded status parity for exact details", func(t *testing.T) {
		crashed := read(base + "&status=crashlooping")
		if crashed.Total != 2 {
			t.Fatalf("crash count%d", crashed.Total)
		}
		siblingRows := read("cluster_id=" + sibling.String() + "&status=healthy")
		if siblingRows.Total != 1 {
			t.Fatalf("sibling misclassified total%d", siblingRows.Total)
		}
		stale := read(base + "&status=stale")
		if stale.Total != 1 || stale.Components[0].ID != staleID {
			t.Fatalf("superseded %+v", stale.Components)
		}
		for _, test := range []struct {
			id     uuid.UUID
			status string
		}{{selectedID, "crashlooping"}, {staleID, "stale"}, {healthyID, "healthy"}} {
			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, "/components/"+test.id.String(), nil)
			router.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var detail struct{ Component componentInstanceDTO }
			if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
				t.Fatal(err)
			}
			if detail.Component.ID != test.id || detail.Component.Status != test.status || strings.ContainsRune(detail.Component.Hostname, '\x00') {
				t.Fatalf("exact detail %+v", detail.Component)
			}
		}
	})
	t.Run("matching CSV ignores page limit and offset", func(t *testing.T) {
		w := request(h.ExportCSV, base+"&role=enforcer&sort=hostname&order=desc&limit=1&offset=1000")
		if w.Code != 200 {
			t.Fatalf("csv %d %s", w.Code, w.Body.String())
		}
		records, err := csv.NewReader(w.Body).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1007 || records[1][8] != "superseded-agent" || w.Header().Get("X-Export-Total") != "1006" || w.Header().Get("X-Export-Limit") != "100000" || w.Header().Get("X-Export-Truncated") != "false" {
			t.Fatalf("csv rows%d first%v headers%v", len(records), records[1], w.Header())
		}
	})

	t.Run("matching CSV carries explicit revisions beyond the first page and blanks unknown metadata", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `UPDATE component_heartbeats SET metadata = CASE WHEN id=$1 THEN '{"system_config_revision":9}'::jsonb WHEN id=$2 THEN '{"system_config_revision":" 10 "}'::jsonb ELSE metadata END WHERE id IN($1,$2)`, selectedID, healthyID); err != nil {
			t.Fatal(err)
		}
		w := request(h.ExportCSV, base+"&role=enforcer&sort=hostname&order=asc&limit=1&offset=1000")
		if w.Code != 200 {
			t.Fatalf("csv %d %s", w.Code, w.Body.String())
		}
		records, err := csv.NewReader(w.Body).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1007 || records[0][len(records[0])-1] != "System config revision" {
			t.Fatalf("rows/header: %d %v", len(records), records[0])
		}
		revisionByHost := map[string]string{}
		for _, row := range records[1:] {
			revisionByHost[row[8]] = row[len(row)-1]
		}
		if revisionByHost["bulk-host-0000"] != "9" || revisionByHost["bulk-host-1004"] != "10" || revisionByHost["superseded-agent"] != "" || revisionByHost["bulk-host-0001"] != "" {
			t.Fatalf("revision evidence: first=%q tail=%q unknown=%q", revisionByHost["bulk-host-0000"], revisionByHost["bulk-host-1004"], revisionByHost["superseded-agent"])
		}
		for _, host := range []string{"bulk-host-0000", "bulk-host-1004", "superseded-agent"} {
			data := read(base + "&q=" + url.QueryEscape(host))
			if len(data.Components) != 1 || componentReportedConfigRevision(data.Components[0].Metadata) != revisionByHost[host] {
				t.Fatalf("JSON/CSV revision mismatch for %s: %+v / %q", host, data.Components, revisionByHost[host])
			}
		}
		if _, found := revisionByHost["foreign-org"]; found {
			t.Fatal("foreign organization exported")
		}
		if _, found := revisionByHost["misattributed"]; found {
			t.Fatal("foreign cluster attribution exported")
		}
	})
	t.Run("scope and invalid filter rejection", func(t *testing.T) {
		orgRows := read("limit=1000")
		if orgRows.Total != 1011 {
			t.Fatalf("org scope %d", orgRows.Total)
		}
		for _, params := range []string{"cluster_id=" + foreignCluster.String(), "cluster_id=" + uuid.NewString()} {
			for _, method := range []http.HandlerFunc{h.List, h.ExportCSV} {
				if w := request(method, params); w.Code != 404 {
					t.Fatalf("foreign/missing %d", w.Code)
				}
			}
		}
		for _, params := range []string{"role=invalid", "status=invalid", "sort=DROP", "order=invalid", "sort=component;DROP", "cluster_id=invalid"} {
			for _, method := range []http.HandlerFunc{h.List, h.ExportCSV} {
				if w := request(method, params); w.Code != 400 {
					t.Fatalf("invalid %s: %d %s", params, w.Code, w.Body.String())
				}
			}
		}
	})
}
