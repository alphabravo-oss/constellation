package network

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/google/uuid"
)

func TestConversationStreamInventoryCompleteScopePagesAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, foreign, cluster, sibling := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'streams'),($2::uuid,$2::text,'foreign')`, org, foreign)
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM network_flow_rollups WHERE org_id IN($1,$2)`, org, foreign)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$3,'main'),($2,$3,'sibling')`, cluster, sibling, org)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'custom-install','agent','Deployment','{"helm.sh/chart":"constellation-1.0"}')`, org, cluster)
	exec(`INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,l7_protocol,verdict,bucket,max_at,sum_bytes,sum_packets,sum_client_bytes,sum_server_bytes,sum_sessions)
 SELECT $1,$2,'prod/api','prod/db','tcp',n,CASE WHEN n=1005 THEN 'needle%_literal' ELSE 'app-'||n END,CASE WHEN n%4=0 THEN 'block' ELSE 'allow' END,date_trunc('hour',now()),now(),n+1,2,n,1,3 FROM generate_series(1,1005)n`, org, cluster)
	for _, row := range []struct {
		org, cluster uuid.UUID
		from, to     string
	}{{org, sibling, "prod/api", "prod/db"}, {foreign, cluster, "prod/api", "prod/db"}, {org, cluster, "prod/api-extra", "prod/db"}, {org, cluster, "prod/db", "prod/api"}} {
		exec(`INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,sum_bytes) VALUES($1,$2,$3,$4,'tcp',443,'deny',date_trunc('hour',now()),now(),99999)`, row.org, row.cluster, row.from, row.to)
	}
	exec(`INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,dst_port,verdict,bucket,max_at,sum_bytes) VALUES($1,$2,'prod/api','prod/db','tcp',9999,'deny',date_trunc('hour',now()-interval '48 hours'),now()-interval '48 hours',99999),($1,$2,'custom-install/agent','prod/db','tcp',443,'allow',date_trunc('hour',now()),now(),9)`, org, cluster)
	exec(`INSERT INTO groups(org_id,cluster_id,name,kind,members) VALUES($1,$2,'exact-stream','ground','["prod/api"]'),($1,$2,'empty-stream','ground','["prod/api-extra"]')`, org, cluster)
	h := NewNetworkConversations(d)
	base := "cluster_id=" + cluster.String() + "&from=prod%2Fapi&to=prod%2Fdb&hours=24"
	call := func(query string, export bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", "/network/conversations/streams?"+query, nil)
		r = r.WithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		if export {
			h.EntriesCSV(w, r)
		} else {
			h.EntriesInventory(w, r)
		}
		return w
	}
	type page struct {
		Entries []conversationStream `json:"entries"`
		inventorylist.Metadata
		ClusterID      uuid.UUID `json:"cluster_id"`
		SourceComplete bool      `json:"source_complete"`
	}
	read := func(query string) page {
		t.Helper()
		w := call(base+query, false)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := read("&limit=100")
	if p.Total != 1005 || len(p.Entries) != 100 || !p.HasMore || p.Summary["bytes"] != 506520 || p.Summary["packets"] != 2010 || p.Summary["sessions"] != 3015 || p.Summary["blocked"] != 251 || p.ClusterID != cluster || !p.SourceComplete {
		t.Fatalf("metadata %+v", p)
	}
	seen := map[string]bool{}
	for offset := 0; offset < 1100; offset += 100 {
		p = read("&limit=100&offset=" + strconv.Itoa(offset))
		for _, row := range p.Entries {
			if seen[row.RowID] {
				t.Fatal("duplicate tuple")
			}
			seen[row.RowID] = true
		}
	}
	if len(seen) != 1005 {
		t.Fatalf("got%dtuples", len(seen))
	}
	if p := read("&group=exact-stream&namespace=prod"); p.Total != 1005 {
		t.Fatal("exact group/namespace source differs")
	}
	if p := read("&group=empty-stream"); p.Total != 0 {
		t.Fatal("group guessed workload prefix")
	}
	p = read("&offset=" + strconv.Itoa(inventorylist.MaxOffset))
	if p.Total != 1005 || len(p.Entries) != 0 || p.HasMore || p.Summary["bytes"] != 506520 {
		t.Fatal("deep page lost full total")
	}
	p = read("&q=needle%25_&protocol=tcp&port=1005&application=needle%25_literal")
	if p.Total != 1 || p.Entries[0].Application != "NEEDLE%_LITERAL" {
		t.Fatal("tail/literal mixed filters missed stream")
	}
	p = read("&verdict_group=blocked&sort=port&order=asc")
	if p.Total != 251 || p.Entries[0].Port != 4 || p.Summary["blocked"] != 251 {
		t.Fatal("filter/sort disagreement")
	}
	w := call(base+"&offset=2147483647&limit=1", true)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(rows) != 1006 || w.Header().Get("X-Export-Total") != "1005" || w.Header().Get("X-Export-Limit") != "100000" {
		t.Fatal("full matching CSV differs")
	}
	w = call("cluster_id="+cluster.String()+"&from=custom-install%2Fagent&to=prod%2Fdb&hide_platform=false", false)
	var classified page
	_ = json.Unmarshal(w.Body.Bytes(), &classified)
	if w.Code != 200 || classified.Total != 1 || classified.Entries[0].FromPlatformRole != "core" {
		t.Fatal("role classification missing")
	}
	w = call("cluster_id="+cluster.String()+"&from=custom-install%2Fagent&to=prod%2Fdb&hide_platform=true", false)
	_ = json.Unmarshal(w.Body.Bytes(), &classified)
	if w.Code != 200 || classified.Total != 0 {
		t.Fatal("platform filter must run before total/page")
	}
	for _, query := range []string{"from=a&to=b", base + "&limit=501", base + "&limit=", base + "&offset=2147483648", base + "&q=a&q=b", base + "&sort=invalid", base + "&hours=0"} {
		for _, export := range []bool{false, true} {
			if w := call(query, export); w.Code != 400 {
				t.Fatalf("invalid query%d %s", w.Code, query)
			}
		}
	}
	if w := call(base+"&group=missing", false); w.Code != 400 {
		t.Fatal("missing group not rejected")
	}
	r := httptest.NewRequest("GET", "/network/conversations/streams?"+base, nil)
	for _, export := range []bool{false, true} {
		w := httptest.NewRecorder()
		if export {
			h.EntriesCSV(w, r)
		} else {
			h.EntriesInventory(w, r)
		}
		if w.Code != 401 {
			t.Fatal("unauthenticated source not rejected")
		}
	}
	if w := call("cluster_id="+uuid.NewString()+"&from=a&to=b", false); w.Code != 404 {
		t.Fatal("missing cluster not rejected")
	}
}

func TestConversationStreamInventoryCSVFullCap(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, cluster := uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name)VALUES($1::uuid,$1::text,'cap')`, org)
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM network_flow_rollups WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	})
	exec(`INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'cap')`, cluster, org)
	exec(`INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket,max_at,sum_bytes,sum_packets)
 SELECT $1,$2,'prod/a','prod/b','tcp','app-'||n,443,'allow',date_trunc('hour',now()),now(),n,1 FROM generate_series(1,100001)n`, org, cluster)
	h := NewNetworkConversations(d)
	r := httptest.NewRequest("GET", "/network/conversations/streams.csv?cluster_id="+cluster.String()+"&from=prod%2Fa&to=prod%2Fb&offset=2147483647&limit=1&sort=bytes&order=asc", nil)
	r = r.WithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: org}))
	w := httptest.NewRecorder()
	h.EntriesCSV(w, r)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(rows) != 100001 || w.Header().Get("X-Export-Total") != "100001" || w.Header().Get("X-Export-Truncated") != "true" || rows[1][8] != "1" || rows[100000][8] != "100000" {
		t.Fatalf("CSV full cap status%d rows%d headers%v err%v", w.Code, len(rows), w.Header(), err)
	}
}

func TestConversationStreamInventoryStrictParser(t *testing.T) {
	base := "cluster_id=" + uuid.NewString() + "&from=prod%2Fa&to=prod%2Fb"
	for _, query := range []string{"&hours=0", "&hours=-1", "&hours=721", "&hours=bad", "&hours=", "&limit=0", "&offset=-1"} {
		values, err := url.ParseQuery(base + query)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseStreamOptions(values); err == nil {
			t.Fatalf("must reject%s", query)
		}
	}
	for _, query := range []string{"", "&hours=1", "&hours=720"} {
		values, err := url.ParseQuery(base + query)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseStreamOptions(values); err != nil {
			t.Fatalf("valid query%s %v", query, err)
		}
	}
}
