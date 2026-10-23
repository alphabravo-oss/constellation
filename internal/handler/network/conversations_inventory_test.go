//go:build integration

package network

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/alphabravocompany/constellation/pkg/livegraph"
)

type conversationTestResponse struct {
	Conversations  []platformConversation `json:"conversations"`
	Total          int64                  `json:"total"`
	Summary        map[string]int64       `json:"summary"`
	HasMore        bool                   `json:"has_more"`
	Source         string                 `json:"source"`
	SourceComplete bool                   `json:"source_complete"`
	SummaryScope   string                 `json:"summary_scope"`
	ClusterID      *uuid.UUID             `json:"cluster_id"`
	Filters        conversationFilters    `json:"filters"`
	Sort, Order    string
}

func conversationFixture(t *testing.T) (*db.DB, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	org, foreign, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, tenant := range []uuid.UUID{org, foreign} {
		if _, err := database.Pool().Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, tenant, "conversation-inventory-"+tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM network_flow_rollups WHERE org_id IN($1,$2)`, org, foreign)
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	if _, err := database.Pool().Exec(t.Context(), `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreignCluster, foreign); err != nil {
		t.Fatal(err)
	}
	return database, org, foreign, cluster, sibling, foreignCluster
}
func conversationRequest(t *testing.T, h *NetworkConversations, org uuid.UUID, query string, export bool, status int) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/network/conversations?"+query, nil)
	if org != uuid.Nil {
		request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
	}
	response := httptest.NewRecorder()
	if export {
		h.ListCSV(response, request)
	} else {
		h.List(response, request)
	}
	if response.Code != status {
		t.Fatalf("%s export=%t: status%d %s", query, export, response.Code, response.Body.String())
	}
	return response
}
func decodeConversations(t *testing.T, response *httptest.ResponseRecorder) conversationTestResponse {
	t.Helper()
	var body conversationTestResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}
func TestConversationInventoryFullCohortSortSummaryAndCSV(t *testing.T) {
	t.Parallel()
	database, org, foreign, cluster, sibling, foreignCluster := conversationFixture(t)
	pool := database.Pool()
	const total = 6007
	if _, err := pool.Exec(t.Context(), `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket,max_at,sum_bytes,sum_packets)
 SELECT $1,$2,'default/client','default/service-'||lpad(seq::text,5,'0'),'tcp','https',443,'allow',date_trunc('hour',NOW()),NOW()-seq*INTERVAL '1 second',seq,2*seq FROM generate_series(1,$3::int) seq`, org, cluster, total); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct{ org, cluster uuid.UUID }{{org, sibling}, {foreign, foreignCluster}, {org, foreignCluster}} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,sum_bytes) VALUES($1,$2,'default/client','default/service-06007','tcp',date_trunc('hour',NOW()),NOW(),900000)`, scope.org, scope.cluster); err != nil {
			t.Fatal(err)
		}
	}
	// Multiple protocol/port streams, duplicate l7/verdict buckets and an older
	// observation must fold once without losing sums or repeating stream counts.
	if _, err := pool.Exec(t.Context(), `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket,max_at,sum_bytes,sum_packets,max_severity) VALUES
 ($1,$2,'default/client','default/service-06007','tcp','http',443,'deny',date_trunc('hour',NOW()),NOW(),10,20,5),
 ($1,$2,'default/client','default/service-06007','udp','dns',53,'alert',date_trunc('hour',NOW()),NOW(),30,40,2),
 ($1,$2,'default/client','default/service-06007','tcp','old',443,'allow',date_trunc('hour',NOW()-INTERVAL '1 hour'),NOW()-INTERVAL '1 hour',50,60,1),
 ($1,$2,'default/client','outside/window','tcp','',1,'deny',date_trunc('hour',NOW()-INTERVAL '25 hour'),NOW()-INTERVAL '25 hour',999999,0,9)`, org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewNetworkConversations(database)
	query := "cluster_id=" + cluster.String() + "&limit=2&sort=bytes&order=desc"
	body := decodeConversations(t, conversationRequest(t, h, org, query, false, 200))
	expectedBytes := int64(total*(total+1)/2 + 90)
	if body.Total != total || len(body.Conversations) != 2 || !body.HasMore || body.Summary["bytes"] != expectedBytes || body.Summary["packets"] != int64(total*(total+1)+120) || body.Summary["edges"] != total+1 || body.Summary["nodes"] != total+1 || body.Summary["blocked"] != 1 || body.Summary["max_severity"] != 5 || body.Summary["source_clusters"] != 1 || body.Source != "rollups" || !body.SourceComplete || body.ClusterID == nil || *body.ClusterID != cluster {
		t.Fatalf("full cohort %+v", body)
	}
	first := body.Conversations[0]
	if first.To != "default/service-06007" || first.Bytes != 6097 || first.Edges != 2 || first.Verdict != "deny" || first.RowID != conversationRowID(first.From, first.To) || strings.Join(first.Apps, ",") != "dns,http" {
		t.Fatalf("folded streams %+v", first)
	}

	tied := decodeConversations(t, conversationRequest(t, h, org, "cluster_id="+cluster.String()+"&limit=2&offset=1&sort=severity&order=desc", false, 200))
	if tied.Conversations[0].To != "default/service-00001" || tied.Conversations[1].To != "default/service-00002" {
		t.Fatalf("unstable equal sort continuation %+v", tied)
	}
	tail := decodeConversations(t, conversationRequest(t, h, org, query+"&offset=6000", false, 200))
	if tail.Total != total || len(tail.Conversations) != 2 || tail.Conversations[0].To != "default/service-00007" || tail.Summary["bytes"] != expectedBytes {
		t.Fatalf("tail %+v", tail)
	}
	empty := decodeConversations(t, conversationRequest(t, h, org, query+"&offset=9999", false, 200))
	if len(empty.Conversations) != 0 || empty.HasMore || empty.Summary["bytes"] != expectedBytes {
		t.Fatalf("empty page %+v", empty)
	}

	for _, offset := range []int{2000000, inventorylist.MaxOffset} {
		high := decodeConversations(t, conversationRequest(t, h, org, query+"&offset="+strconv.Itoa(offset), false, 200))
		if len(high.Conversations) != 0 || high.HasMore || high.Total != total || high.Summary["bytes"] != expectedBytes {
			t.Fatalf("high offset %d %+v", offset, high)
		}
	}
	export := conversationRequest(t, h, org, query+"&offset="+strconv.Itoa(inventorylist.MaxOffset), true, 200)
	records, err := csv.NewReader(export.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != total+1 || records[1][2] != first.To || records[1][3] != "6097" || export.Header().Get("X-Export-Total") != strconv.Itoa(total) || export.Header().Get("X-Export-Limit") != "100000" || export.Header().Get("X-Export-Truncated") != "false" || export.Header().Get("X-Conversation-Source") != "rollups" || export.Header().Get("X-Conversation-Cluster") != cluster.String() {
		t.Fatalf("export count=%d headers=%v first=%v", len(records), export.Header(), records[1])
	}
	seen := map[string]bool{}
	for _, row := range records[1:] {
		if seen[row[0]] {
			t.Fatalf("duplicate rowID %s", row[0])
		}
		seen[row[0]] = true
	}
	for key := range conversationSorts {
		for _, order := range []string{"asc", "desc"} {
			sorted := decodeConversations(t, conversationRequest(t, h, org, "cluster_id="+cluster.String()+"&limit=2&sort="+key+"&order="+order, false, 200))
			if sorted.Sort != key || sorted.Order != order || sorted.Total != total {
				t.Fatalf("sort %s %s %+v", key, order, sorted)
			}
			if key == "bytes" && order == "asc" && sorted.Conversations[0].To != "default/service-00001" {
				t.Fatal("ascending bytes not applied before paging")
			}
			if key == "last_seen" && order == "desc" && sorted.Conversations[0].To != "default/service-06007" {
				t.Fatal("last_seen did not sort full source")
			}
		}
	}
	all := decodeConversations(t, conversationRequest(t, h, org, "sort=bytes&limit=1", false, 200))
	if all.Total != total || all.Conversations[0].Bytes != 906097 || all.Summary["source_clusters"] != 2 {
		t.Fatalf("org scope %+v", all)
	}
	// Equal-sort ties are stable by the exact endpoint tuple, including endpoints
	// containing the graph's separator. Row IDs never concatenate ambiguously.
	if conversationRowID("a→b", "c") == conversationRowID("a", "b→c") {
		t.Fatal("ambiguous identity")
	}
	for _, query := range []string{"sort=bad", "order=bad", "limit=0", "limit=5001", "limit=x", "offset=-1", "offset=" + strconv.Itoa(inventorylist.MaxOffset+1), "offset=", "port=0", "hide_platform=1", "sort=bytes&sort=bytes", "cluster_id=bad", "verdict_group=bad"} {
		for _, export := range []bool{false, true} {
			conversationRequest(t, h, org, query, export, 400)
		}
	}
	for _, id := range []uuid.UUID{foreignCluster, uuid.New()} {
		for _, export := range []bool{false, true} {
			conversationRequest(t, h, org, "cluster_id="+id.String(), export, 404)
		}
	}
	for _, export := range []bool{false, true} {
		conversationRequest(t, h, uuid.Nil, "", export, 401)
	}
}

func TestConversationInventoryExactFiltersPlatformAndLiveScope(t *testing.T) {
	t.Parallel()
	database, org, _, cluster, sibling, _ := conversationFixture(t)
	pool := database.Pool()
	owner, unlabelled := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'custom','agent','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($4,$2,$3,'custom','other','Deployment','{}'),
 (gen_random_uuid(),$2,$3,'ambiguous','agent','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 (gen_random_uuid(),$2,$3,'ambiguous','agent','StatefulSet','{}'),
 (gen_random_uuid(),$2,$5,'custom','agent','Deployment','{}')`, owner, org, cluster, unlabelled, sibling); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES
 ($1,$2,'custom','pod','p1','custom/pod/pod','Deployment','agent','custom/agent',$3),
 ($1,$2,'custom','ambiguous','p2','custom/pod/ambiguous','Deployment','agent','custom/agent',$3),
 ($1,$2,'custom','ambiguous','p3','custom/pod/ambiguous','Deployment','other','custom/other',$4)`, org, cluster, owner, unlabelled); err != nil {
		t.Fatal(err)
	}
	endpoints := []string{"custom/agent", "custom/pod/pod", "custom/pod/ambiguous", "ambiguous/agent", "kube-system/coredns", "kube-system/10.42.0.2", "default/client", "literal%_/client", "literalXX/client", "constellation"}
	for i, from := range endpoints {
		if _, err := pool.Exec(t.Context(), `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,min_src_port,min_src_addr,min_dst_addr,max_application,verdict,bucket,max_at,sum_bytes,sum_packets) VALUES($1,$2,$3,'default/api','tcp','https',443,32001,'10.0.0.2','10.0.0.3',777,'deny',date_trunc('hour',NOW()),NOW(),$4,2)`, org, cluster, from, i+1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket,max_at,sum_bytes) VALUES($1,$2,'custom/agent','default/api','tcp','https',443,'deny',date_trunc('hour',NOW()),NOW(),100)`, org, sibling); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO groups(org_id,cluster_id,name,kind,members) VALUES($1,$2,'tail-group','ground','["literal%_/client"]')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	live := livegraph.New(livegraph.Config{MaxEdgesPer: 1})
	live.Publish(livegraph.Flow{OrgID: org, ClusterID: cluster, SrcWorkload: "live/source", DstWorkload: "live/target", Bytes: 9999, At: time.Now()})
	h := NewNetworkConversations(database).WithLiveGraph(live)
	base := "cluster_id=" + cluster.String()
	hot := decodeConversations(t, conversationRequest(t, h, org, base, false, 200))
	if hot.Source != "live" || hot.SourceComplete || hot.SummaryScope != "live_snapshot" || hot.Total != 1 {
		t.Fatalf("bounded hot source %+v", hot)
	}
	cold := decodeConversations(t, conversationRequest(t, h, org, base+"&sort=bytes&limit=1", false, 200))
	if cold.Total != int64(len(endpoints)) || !cold.SourceComplete || cold.Source != "rollups" {
		t.Fatalf("inventory accidentally served from live %+v", cold)
	}
	hidden := decodeConversations(t, conversationRequest(t, h, org, base+"&hide_platform=true&limit=1", false, 200))
	if hidden.Total != 7 || hidden.Summary["bytes"] != 47 || !hidden.Filters.HidePlatform || hidden.Conversations[0].From != "constellation" {
		t.Fatalf("platform full cohort %+v", hidden)
	}
	full := conversationRequest(t, h, org, base+"&hide_platform=true&offset=100", true, 200)
	records, err := csv.NewReader(full.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 8 {
		t.Fatalf("filtered CSV %+v", records)
	}
	for _, row := range records[1:] {
		if row[1] == "custom/agent" || row[1] == "custom/pod/pod" || row[1] == "kube-system/coredns" {
			t.Fatalf("core leaked %+v", row)
		}
	}
	scoped := decodeConversations(t, conversationRequest(t, h, org, base+"&from=custom%2Fagent", false, 200))
	if scoped.Conversations[0].FromPlatformRole != "core" {
		t.Fatal("scoped exact role lost")
	}

	roleCSV, err := csv.NewReader(conversationRequest(t, h, org, base+"&from=custom%2Fagent", true, 200).Body).ReadAll()
	if err != nil || len(roleCSV) != 2 || roleCSV[1][10] != "core" {
		t.Fatalf("CSV exact role %v %v", roleCSV, err)
	}
	orgHidden := decodeConversations(t, conversationRequest(t, h, org, "hide_platform=true&from=custom%2Fagent&limit=1", false, 200))
	if orgHidden.Total != 1 || orgHidden.Conversations[0].Bytes != 100 || orgHidden.Conversations[0].FromPlatformRole != "" {
		t.Fatalf("cross-cluster names borrowed role %+v", orgHidden)
	}
	orgAll := decodeConversations(t, conversationRequest(t, h, org, "from=custom%2Fagent&limit=1", false, 200))
	if orgAll.Conversations[0].Bytes != 101 || orgAll.Conversations[0].FromPlatformRole != "" {
		t.Fatalf("org fold %+v", orgAll)
	}
	for _, filters := range []string{"namespace=" + url.QueryEscape("literal%_"), "group=tail-group", "from=" + url.QueryEscape("literal%_/client") + "&to=default%2Fapi", "peer=" + url.QueryEscape("literal%_"), "namespace=" + url.QueryEscape("literal%_") + "&port=32001&application=777&verdict=deny&verdict_group=blocked&hours=1"} {
		body := decodeConversations(t, conversationRequest(t, h, org, base+"&"+filters, false, 200))
		if body.Total != 1 || body.Conversations[0].From != "literal%_/client" || body.Conversations[0].Bytes != 8 {
			t.Fatalf("literal exact filters %s %+v", filters, body)
		}
		records, err := csv.NewReader(conversationRequest(t, h, org, base+"&"+filters, true, 200).Body).ReadAll()
		if err != nil || len(records) != 2 || records[1][1] != "literal%_/client" {
			t.Fatalf("filtered export %s %v %v", filters, records, err)
		}
	}
	missing := decodeConversations(t, conversationRequest(t, h, org, base+"&group=tail-group&application=dns", false, 200))
	if missing.Total != 0 || missing.Summary["bytes"] != 0 {
		t.Fatalf("empty intersection %+v", missing)
	}
}

func TestConversationInventoryCSVLimitIsExplicit(t *testing.T) {
	t.Parallel()
	database, org, _, cluster, _, _ := conversationFixture(t)
	const total = 100003
	if _, err := database.Pool().Exec(t.Context(), `INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,sum_bytes)
 SELECT $1,$2,'kube-system/client','kube-system/service-'||lpad(seq::text,6,'0'),'tcp',date_trunc('hour',NOW()),NOW(),seq FROM generate_series(1,$3::int) seq`, org, cluster, total); err != nil {
		t.Fatal(err)
	}
	response := conversationRequest(t, NewNetworkConversations(database), org, "cluster_id="+cluster.String()+"&limit=1&offset=100002&sort=bytes&order=desc", true, 200)
	reader := csv.NewReader(response.Body)
	headers, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(headers, ",") != "Conversation ID,From,To,Bytes,Packets,Streams,Last seen,Max severity,Verdict,Applications (JSON),From platform role,To platform role" {
		t.Fatalf("CSV headers %+v", headers)
	}
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 100000 || records[0][2] != "kube-system/service-100003" || records[len(records)-1][2] != "kube-system/service-000004" || response.Header().Get("X-Export-Total") != fmt.Sprint(total) || response.Header().Get("X-Export-Truncated") != "true" || response.Header().Get("X-Export-Limit") != "100000" {
		t.Fatalf("cap rows=%d headers=%v", len(records), response.Header())
	}
}

func TestConversationInventoryOptions(t *testing.T) {
	t.Parallel()
	for _, query := range []string{"limit=bad", "sort=bytes;DROP TABLE flows", "order=DESC;--", "offset=-1", "offset=" + strconv.Itoa(inventorylist.MaxOffset+1), "hide_platform=yes", "port=65536", "cluster_id=bad", "limit=2&limit=2"} {
		values, err := url.ParseQuery(query)
		if err == nil {
			_, err = parseConversationOptions(values)
		}
		if err == nil {
			t.Fatalf("accepted %s", query)
		}
	}
	values, _ := url.ParseQuery("limit=1&offset=5000&sort=last_seen&order=asc&hide_platform=true&namespace=literal%25_&hours=1")
	o, err := parseConversationOptions(values)
	if err != nil || o.Limit != 1 || o.Offset != 5000 || !o.HidePlatform || o.Namespace != "literal%_" || o.Hours != 1 || o.OrderSQL != "last_seen ASC NULLS LAST, src_workload ASC, dst_workload ASC" {
		t.Fatalf("options %+v %v", o, err)
	}
}

func TestConversationInventoryHighOffsetOptions(t *testing.T) {
	t.Parallel()
	for _, offset := range []int{1000001, 2000000, inventorylist.MaxOffset} {
		values := url.Values{"offset": {strconv.Itoa(offset)}}
		options, err := parseConversationOptions(values)
		if err != nil || options.Offset != offset {
			t.Fatalf("offset %d options=%+v err=%v", offset, options, err)
		}
	}
}

func TestConversationExpiredHistoryIsExplicitForJSONAndCSV(t *testing.T) {
	t.Parallel()
	database, org, _, cluster, _, _ := conversationFixture(t)
	if _, err := database.Pool().Exec(t.Context(), `UPDATE network_flow_rollup_state SET rollups_pruned_before=date_trunc('hour',now()-interval '12 hours')`); err != nil {
		t.Fatal(err)
	}
	h := NewNetworkConversations(database)
	for _, export := range []bool{false, true} {
		expired := conversationRequest(t, h, org, "cluster_id="+cluster.String()+"&hours=24", export, 410)
		if !strings.Contains(expired.Body.String(), "expired hourly flow history") || expired.Header().Get("X-History-Available-From") == "" {
			t.Fatalf("missing availability: %s", expired.Body.String())
		}
		conversationRequest(t, h, org, "cluster_id="+cluster.String()+"&hours=1", export, 200)
	}
}
