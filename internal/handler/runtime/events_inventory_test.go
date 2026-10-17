package runtime

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestRuntimeEventsInventoryPagesScopeFiltersAndCSV(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := t.Context()
	org, otherOrg, cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$3,'events'),($2,$4,'other')`, org, otherOrg, "events-"+org.String(), "events-"+otherOrg.String())
	t.Cleanup(func() {
		_, _ = pool.Exec(t.Context(), `DELETE FROM events WHERE org_id IN($1,$2)`, org, otherOrg)
		_, _ = pool.Exec(t.Context(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, otherOrg)
	})
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'current'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreign, otherOrg)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'operations','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),($1,$3,'operations','api','Deployment','{}')`, org, cluster, sibling)
	exec(`INSERT INTO events(org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict,attack_techniques,payload,at) SELECT $1,$2,'node-a','operations/api','operations','ebpf',CASE WHEN i%2=0 THEN 'exec' ELSE 'file_open' END,CASE WHEN i%3=0 THEN 'info' WHEN i%3=1 THEN 'high' ELSE 'critical' END,CASE i%4 WHEN 0 THEN 'observed' WHEN 1 THEN 'alert' WHEN 2 THEN 'block' ELSE 'quarantine' END,ARRAY['T1059'],jsonb_build_object('message',CASE WHEN i%2=0 THEN 'literal %_ quoted "evidence"' ELSE 'other evidence' END),'2026-10-12T12:00:00.123456Z'::timestamptz FROM generate_series(1,205)i`, org, cluster)
	duplicate := uuid.New()
	exec(`INSERT INTO events(id,org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict,payload,at) VALUES($1,$2,$3,'node-a','operations/api','operations','ebpf','exec','critical','block','{}','2026-10-12T12:00:00.123455Z'),($1,$2,$3,'node-a','operations/api','operations','ebpf','exec','critical','block','{}','2026-10-12T12:00:00.123457Z')`, duplicate, org, cluster)
	exec(`INSERT INTO events(org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict) VALUES($1,$2,'node-a','operations/api','operations','ebpf','exec','critical','alert'),($3,$4,'node-a','operations/api','operations','ebpf','exec','critical','alert'),($1,$4,'node-a','operations/api','operations','ebpf','exec','critical','alert')`, org, sibling, otherOrg, foreign)
	handler := NewEventsIngest(database, nil, nil)
	read := func(path string, export bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r = r.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		if export {
			handler.ListCSV(w, r)
		} else {
			handler.List(w, r)
		}
		return w
	}
	decode := func(w *httptest.ResponseRecorder) eventInventoryResponse {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var data eventInventoryResponse
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	base := "/api/v1/events?cluster_id=" + cluster.String()
	full := decode(read(base+"&limit=1000", false))
	if full.Total != 207 || len(full.Events) != 207 || full.Summary.Total != 207 || full.Summary.Alerting != 156 || full.Summary.Blocks != 53 || full.Summary.Quarantines != 51 || full.Summary.AffectedWorkloads != 1 || full.HasMore {
		t.Fatalf("bad full summary %+v", full.Summary)
	}
	identities := map[string]bool{}
	duplicates := 0
	for _, event := range full.Events {
		if identities[event.RowID] {
			t.Fatal("duplicate physical identity")
		}
		identities[event.RowID] = true
		if event.ID == duplicate {
			duplicates++
		}
		if event.ClusterID != cluster || event.PlatformRole != "core" {
			t.Fatalf("bad scope or role %+v", event)
		}
	}
	if duplicates != 2 {
		t.Fatalf("physical UUID instances=%d", duplicates)
	}
	for _, offset := range []int{0, 100, 200, 300} {
		data := decode(read(base+"&offset="+strconv.Itoa(offset), false))
		end := min(offset+100, len(full.Events))
		start := min(offset, len(full.Events))
		if data.Total != 207 || len(data.Events) != end-start || data.HasMore != (offset < 200) || !slices.EqualFunc(data.Events, full.Events[start:end], func(a, b EventDTO) bool { return a.RowID == b.RowID }) {
			t.Fatalf("page offset=%d rows=%d total=%d", offset, len(data.Events), data.Total)
		}
	}
	large := decode(read(base+"&offset=2000000", false))
	if large.Offset != 2000000 || large.Total != 207 || len(large.Events) != 0 || large.HasMore {
		t.Fatalf("deep history page must retain full counts: %+v", large)
	}
	filter := "&kind=exec&source=ebpf&severity=high&verdict=block,alert&namespace=operations&node=node-a&workload=API&q=" + url.QueryEscape("%_")
	filtered := decode(read(base+filter, false))
	want := 0
	for _, event := range full.Events {
		if event.Kind == "exec" && event.Severity != "info" && (event.Verdict == "alert" || event.Verdict == "block") && strings.Contains(string(event.Payload), "%_") {
			want++
		}
	}
	if filtered.Total != want || len(filtered.Events) != want || want == 0 {
		t.Fatalf("filter total=%d want=%d", filtered.Total, want)
	}
	exact := decode(read(base+"&after=2026-10-12T14:00:00.123456%2B02:00&before=2026-10-12T12:00:00.123457Z&limit=1000", false))
	if exact.Total != 205 || exact.After != "2026-10-12T12:00:00.123456Z" || exact.Before != "2026-10-12T12:00:00.123457Z" {
		t.Fatalf("microsecond bounds %+v", exact.eventInventoryQuery)
	}
	orgwide := decode(read("/api/v1/events?limit=1000", false))
	if orgwide.Total != 208 || orgwide.Summary.AffectedWorkloads != 2 {
		t.Fatalf("org scope total=%d workloads=%d", orgwide.Total, orgwide.Summary.AffectedWorkloads)
	}
	for _, event := range orgwide.Events {
		if event.ClusterID == sibling && event.PlatformRole != "" {
			t.Fatal("borrowed sibling role")
		}
		if event.ClusterID == foreign {
			t.Fatal("foreign/misattributed row returned")
		}
	}
	csvResponse := read(base+"&limit=1&offset=200", true)
	if csvResponse.Code != 200 || csvResponse.Header().Get("X-Export-Total") != "207" || csvResponse.Header().Get("X-Export-Limit") != "100000" || csvResponse.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("CSV status/headers %d %v", csvResponse.Code, csvResponse.Header())
	}
	records, err := csv.NewReader(strings.NewReader(csvResponse.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 208 {
		t.Fatal("CSV only exported a page")
	}
	for i, event := range full.Events {
		var csvPayload, apiPayload any
		if err := json.Unmarshal([]byte(records[i+1][14]), &csvPayload); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(event.Payload, &apiPayload); err != nil {
			t.Fatal(err)
		}
		if records[i+1][0] != event.RowID || records[i+1][3] != "core" || !reflect.DeepEqual(csvPayload, apiPayload) {
			t.Fatalf("CSV record mismatch %d", i)
		}
	}
	filteredCSV := read(base+filter, true)
	if filteredCSV.Header().Get("X-Export-Total") != strconv.Itoa(want) {
		t.Fatal("CSV filters differ")
	}
	for _, bad := range []string{"q=%zz", "severity=bogus", "after=invalid", "before=invalid", "after=2026-10-12T12:00:00Z&before=2026-10-11T12:00:00Z", "sort=payload", "order=bad", "limit=0", "limit=1001", "offset=-1", "offset=2147483648", "verdict=unknown", "cluster_id=bad"} {
		for _, export := range []bool{false, true} {
			w := read(base+"&"+bad, export)
			if bad == "cluster_id=bad" {
				w = read("/api/v1/events?"+bad, export)
			}
			if w.Code != 400 {
				t.Errorf("bad=%s export=%v status=%d", bad, export, w.Code)
			}
		}
	}
	for _, id := range []uuid.UUID{foreign, uuid.New()} {
		for _, export := range []bool{false, true} {
			if w := read("/api/v1/events?cluster_id="+id.String(), export); w.Code != 404 {
				t.Errorf("foreign/missing cluster status=%d", w.Code)
			}
		}
	}
	exec(`INSERT INTO events(org_id,cluster_id,node_id,workload_id,source,kind,severity,verdict) VALUES($1,$2,'unknown-node','','ebpf','exec','info','observed'),($1,$2,'unknown-node','   ','ebpf','exec','info','observed')`, org, cluster)
	unknown := decode(read(base, false))
	if unknown.Total != 209 || unknown.Summary.AffectedWorkloads != 1 {
		t.Fatalf("unknown workload IDs invented identities: total=%d workloads=%d", unknown.Total, unknown.Summary.AffectedWorkloads)
	}
	database.Close()
	for _, export := range []bool{false, true} {
		w := read(base, export)
		if w.Code != 500 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("failed read confirms inventory export=%v status=%d", export, w.Code)
		}
	}
}

func TestRuntimeEventInventoryParsePreservesHistoryDefaults(t *testing.T) {
	q, err := parseEventInventory(url.Values{})
	if err != nil || q.Limit != 100 || q.Offset != 0 || q.Sort != "at" || q.Order != "desc" || q.After != "" || q.Before != "" {
		t.Fatalf("defaults changed %+v %v", q, err)
	}
	q, err = parseEventInventory(url.Values{"kind": {"exec,file_open"}, "severity": {"HIGH"}, "after": {time.Now().UTC().Format(time.RFC3339Nano)}})
	if err != nil || q.Severity != "high" || q.Kind != "exec,file_open" {
		t.Fatalf("legacy kind/minimum severity %+v %v", q, err)
	}
}

func TestRuntimeEventInventoryDeepOffsetBounds(t *testing.T) {
	for _, raw := range []string{"2000000", "2147483647"} {
		q, err := parseEventInventory(url.Values{"offset": {raw}})
		want, _ := strconv.Atoi(raw)
		if err != nil || q.Offset != want {
			t.Fatalf("deep offset %s parsed=%d err=%v", raw, q.Offset, err)
		}
	}
	if _, err := parseEventInventory(url.Values{"offset": {"2147483648"}}); err == nil {
		t.Fatal("offset beyond signed32-bit contract accepted")
	}
}
