package network

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestNetworkSessionFullInventoryAndCSV(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := t.Context()
	org, foreign, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []uuid.UUID{org, foreign} {
		exec(`INSERT INTO orgs(id,name,display_name)VALUES($1,$2,$2)`, id, "sessions-inventory-"+id.String())
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign); err != nil {
			t.Error(err)
		}
	})
	exec(`INSERT INTO clusters(id,org_id,name,state)VALUES($1,$2,'selected','connected'),($3,$2,'sibling','disconnected'),($4,$5,'foreign','connected')`, cluster, org, sibling, foreignCluster, foreign)
	exec(`INSERT INTO network_sessions(org_id,cluster_id,node,id,workload_id,application,ip_proto,client_ip,client_port,server_ip,server_port,client_state,server_state,client_bytes,server_bytes,client_pkts,server_pkts,age,idle,severity,threat_id,updated_at)
 SELECT $1,$2,'node-a',i,'apps/client-'||lpad(i::text,4,'0'),CASE WHEN i%2=0 THEN 777 ELSE 0 END,CASE WHEN i%2=0 THEN 6 ELSE 17 END,'10.0.0.1',40000+i,'10.0.0.2',CASE WHEN i%2=0 THEN 443 ELSE 53 END,1,1,100,50,10,5,20,1,CASE WHEN i%2=0 THEN 2 ELSE 0 END,CASE WHEN i%10=0 THEN 99 ELSE 0 END,NOW() FROM generate_series(1,650)i`, org, cluster)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels)VALUES
 ($1,$2,'custom-install','controller','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($1,$2,'custom-install','ambiguous','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 ($1,$2,'custom-install','ambiguous','StatefulSet','{}'),
 ($1,$3,'custom-install','controller','Deployment','{}'),
 ($4,$2,'custom-install','foreign-only','Deployment','{"app.kubernetes.io/part-of":"astronomer"}')`, org, cluster, sibling, foreign)
	// Same numeric session ID is legitimate on another node. Unknown/ambiguous/IP
	// identities remain visible when platform sessions are hidden.
	type fixture struct {
		owner, scope   uuid.UUID
		node, workload string
		id             int64
		stale          bool
	}
	rows := []fixture{{org, cluster, "node-b", "apps/duplicate-id", 1, false}, {org, cluster, "node-platform", "custom-install/controller", 701, false}, {org, cluster, "node-platform", "kube-system/coredns", 702, false}, {org, cluster, "node-unknown", "custom-install/ambiguous", 703, false}, {org, cluster, "node-unknown", "external/8.8.8.8", 704, false}, {org, cluster, "node-unknown", "custom-install/foreign-only", 705, false}, {org, cluster, "literal%_\\node", "apps/literal%_\\workload", 706, false}, {org, cluster, "node-stale", "apps/stale", 707, true}, {org, sibling, "node-a", "custom-install/controller", 1, false}, {foreign, cluster, "foreign-org", "kube-system/foreign", 1, false}, {org, foreignCluster, "foreign-cluster", "apps/foreign", 1, false}}
	for _, row := range rows {
		interval := "0 minutes"
		if row.stale {
			interval = "6 minutes"
		}
		exec(`INSERT INTO network_sessions(org_id,cluster_id,node,id,workload_id,ip_proto,client_ip,client_port,server_ip,server_port,client_bytes,server_bytes,client_pkts,server_pkts,age,idle,updated_at)VALUES($1,$2,$3,$4,$5,6,'10.0.0.3',40001,'10.0.0.4',443,100,50,10,5,20,1,NOW()-$6::interval)`, row.owner, row.scope, row.node, row.id, row.workload, interval)
	}
	exec(`INSERT INTO groups(org_id,cluster_id,name,kind,criteria,members,policy_mode,profile_mode)VALUES
 ($1,NULL,'inherited-group','ground','[]','["apps/client-0001"]','monitor','monitor'),
 ($1,$2,'selected-group','ground','[]','["apps/client-0650","custom-install/controller"]','monitor','monitor'),
 ($1,$2,'empty-group','ground','[]','[]','monitor','monitor'),
 ($1,$3,'sibling-group','ground','[]','["apps/client-0001"]','monitor','monitor'),
 ($4,$2,'foreign-group','ground','[]','["apps/client-0001"]','monitor','monitor')`, org, cluster, sibling, foreign)
	handler := NewNetwork(database)
	request := func(t *testing.T, serve http.HandlerFunc, owner, scope uuid.UUID, query string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: owner}), http.MethodGet, "/network/sessions?cluster_id="+scope.String()+"&"+query, nil)
		w := httptest.NewRecorder()
		serve(w, r)
		return w
	}
	type response struct {
		Sessions             []sessionDTO
		Total, Limit, Offset int
		HasMore              bool `json:"has_more"`
		Summary              map[string]int64
		Sort, Order          string
		ClusterID            uuid.UUID `json:"cluster_id"`
		Group                string    `json:"selected_group"`
		Members              int       `json:"selected_group_members"`
		Hide                 bool      `json:"hide_platform"`
	}
	read := func(t *testing.T, query string) response {
		t.Helper()
		w := request(t, handler.Sessions, org, cluster, query)
		if w.Code != 200 {
			t.Fatalf("list %d %s", w.Code, w.Body.String())
		}
		var data response
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Run("all pages report full matching totals bytes and stable instance keys", func(t *testing.T) {
		seen := map[string]bool{}
		for offset := 0; offset < 657; offset += 100 {
			page := read(t, "limit=100&sort=bytes&order=desc&offset="+strconv.Itoa(offset))
			if page.Total != 657 || page.Summary["total"] != 657 || page.Summary["tcp"] != 332 || page.Summary["udp"] != 325 || page.Summary["icmp"] != 0 || page.Summary["other"] != 0 || page.Summary["client_bytes"] != 65700 || page.Summary["server_bytes"] != 32850 || page.Summary["bytes"] != 98550 || page.Summary["packets"] != 9855 || page.Summary["threats"] != 65 || page.HasMore != (offset < 600) || page.Offset != offset || page.ClusterID != cluster {
				t.Fatalf("metadata %+v", page)
			}
			for _, item := range page.Sessions {
				if seen[item.RowID] || item.ClusterID != cluster || item.UpdatedAt.IsZero() || item.Node == "node-stale" {
					t.Fatalf("invalid instance %+v", item)
				}
				seen[item.RowID] = true
			}
		}
		if len(seen) != 657 {
			t.Fatalf("rows %d", len(seen))
		}
		a := read(t, "limit=37&offset=120&sort=bytes&order=desc")
		b := read(t, "limit=37&offset=120&sort=bytes&order=desc")
		for i := range a.Sessions {
			if a.Sessions[i].RowID != b.Sessions[i].RowID {
				t.Fatal("unstable ties")
			}
		}
		empty := read(t, "offset=9999")
		if len(empty.Sessions) != 0 || empty.Total != 657 || empty.HasMore || empty.Summary["bytes"] != 98550 {
			t.Fatalf("empty %+v", empty)
		}
	})

	t.Run("high offsets preserve the full cohort on empty pages", func(t *testing.T) {
		for _, offset := range []int{1000001, 2000000, inventorylist.MaxOffset} {
			page := read(t, "offset="+strconv.Itoa(offset))
			if page.Offset != offset || len(page.Sessions) != 0 || page.HasMore || page.Total != 657 || page.Summary["bytes"] != 98550 {
				t.Fatalf("high offset %d %+v", offset, page)
			}
		}
		response := request(t, handler.SessionsCSV, org, cluster, "limit=1&offset="+strconv.Itoa(inventorylist.MaxOffset))
		records, err := csv.NewReader(response.Body).ReadAll()
		if response.Code != 200 || err != nil || len(records) != 658 || response.Header().Get("X-Export-Total") != "657" {
			t.Fatalf("high-offset export status=%d records=%d err=%v headers=%v", response.Code, len(records), err, response.Header())
		}
	})
	t.Run("filtering and platform exclusion happen before count page and CSV", func(t *testing.T) {
		for _, caseValue := range []struct {
			query string
			total int
		}{{"hide_platform=true", 655}, {"protocol=tcp&application=https&port=443&peer=10.0.0.2&workload=apps/client&node=node-a", 325}, {"application=777", 325}, {"application=unknown", 0}, {"protocol=udp&port=53", 325}, {"q=apps/client-0650", 1}, {"q=" + url.QueryEscape("%_\\"), 1}, {"protocol=icmp", 0}, {"hours=1", 657}} {
			page := read(t, caseValue.query+"&limit=100")
			if page.Total != caseValue.total || page.Summary["total"] != int64(caseValue.total) {
				t.Fatalf("%s %+v", caseValue.query, page)
			}
		}
		echoResponse := request(t, handler.Sessions, org, cluster, "hide_platform=true&protocol=TCP&application=HTTPS&port=443&node=%20NODE-A%20")
		var echo struct {
			Filters map[string]any `json:"filters"`
		}
		if err := json.Unmarshal(echoResponse.Body.Bytes(), &echo); err != nil || echoResponse.Code != 200 || echo.Filters["hide_platform"] != true || echo.Filters["protocol"] != float64(6) || echo.Filters["port"] != float64(443) || echo.Filters["node"] != "node-a" || echo.Filters["application"] != "https" {
			t.Fatalf("filter echo %d %s %v", echoResponse.Code, echoResponse.Body.String(), err)
		}
		hidden := read(t, "hide_platform=true&limit=2000")
		for _, item := range hidden.Sessions {
			if item.PlatformRole == "core" {
				t.Fatal("platform row survived filter")
			}
		}
		for _, workload := range []string{"custom-install/ambiguous", "external/8.8.8.8", "custom-install/foreign-only"} {
			page := read(t, "hide_platform=true&q="+url.QueryEscape(workload))
			if page.Total != 1 || page.Sessions[0].PlatformRole != "" {
				t.Fatalf("unknown classification %s %+v", workload, page)
			}
		}
		inherited := read(t, "group=inherited-group")
		if inherited.Total != 1 || inherited.Group != "inherited-group" || inherited.Members != 1 {
			t.Fatalf("organization group %+v", inherited)
		}
		group := read(t, "group=selected-group")
		if group.Total != 2 || group.Group != "selected-group" || group.Members != 2 {
			t.Fatalf("group %+v", group)
		}
		hiddenGroup := read(t, "group=selected-group&hide_platform=true")
		if hiddenGroup.Total != 1 || hiddenGroup.Sessions[0].WorkloadID != "apps/client-0650" {
			t.Fatalf("hidden group %+v", hiddenGroup)
		}
		empty := read(t, "group=empty-group")
		if empty.Total != 0 || empty.Group != "empty-group" || empty.Members != 0 {
			t.Fatalf("empty group %+v", empty)
		}
	})
	t.Run("summary endpoint uses the exact same filtered full cohort", func(t *testing.T) {
		for _, query := range []string{"", "hide_platform=true", "group=selected-group&hide_platform=true", "protocol=udp", "q=apps/client-0650"} {
			page := read(t, query+"&limit=1&offset=2000")
			w := request(t, handler.SessionsSummary, org, cluster, query)
			var summary map[string]int64
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &summary) != nil || !reflect.DeepEqual(summary, page.Summary) {
				t.Fatalf("summary %s %d %s vs %v", query, w.Code, w.Body.String(), page.Summary)
			}
		}
	})
	t.Run("CSV traverses every match in server order and preserves duplicated numeric IDs", func(t *testing.T) {
		for _, query := range []string{"sort=node&order=asc", "hide_platform=true&sort=workload&order=desc", "group=selected-group&sort=client_bytes&order=asc", "protocol=tcp&application=https&port=443&peer=10.0.0.2", "q=missing"} {
			all := []sessionDTO{}
			var page response
			for offset := 0; ; offset += 100 {
				page = read(t, query+"&limit=100&offset="+strconv.Itoa(offset))
				all = append(all, page.Sessions...)
				if !page.HasMore {
					break
				}
			}
			w := request(t, handler.SessionsCSV, org, cluster, query+"&offset=1000&limit=1")
			records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
			if err != nil || w.Code != 200 || len(records) != page.Total+1 || w.Header().Get("X-Export-Total") != strconv.Itoa(page.Total) || w.Header().Get("X-Export-Limit") != "100000" || w.Header().Get("X-Export-Truncated") != "false" {
				t.Fatalf("CSV %s %d records%d err%v headers%v", query, w.Code, len(records), err, w.Header())
			}
			for i, item := range all {
				if records[i+1][0] != item.RowID || records[i+1][1] != cluster.String() || records[i+1][2] != strconv.FormatInt(item.ID, 10) || records[i+1][5] != item.PlatformRole {
					t.Fatalf("CSV row %+v %v", item, records[i+1])
				}
			}
		}
		duplicates := read(t, "q=\"node\"&limit=2000") // quoted text is a literal, not a DSL.
		if duplicates.Total != 0 {
			t.Fatal("search unexpectedly became DSL")
		}
		w := request(t, handler.SessionsCSV, org, cluster, "sort=node&order=asc")
		records, _ := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
		ids := map[string]bool{}
		sameID := 0
		for _, record := range records[1:] {
			if record[2] == "1" {
				sameID++
				ids[record[0]] = true
			}
		}
		if sameID != 2 || len(ids) != 2 {
			t.Fatalf("numeric IDs conflated %d %v", sameID, ids)
		}
	})
	t.Run("all allowlisted sorts retain complete stable row sets", func(t *testing.T) {
		for _, sort := range []string{"workload", "node", "application", "protocol", "client", "server", "bytes", "packets", "client_bytes", "server_bytes", "age", "idle", "severity", "observed", "state"} {
			for _, order := range []string{"asc", "desc"} {
				page := read(t, "sort="+sort+"&order="+order+"&limit=2000")
				if page.Sort != sort || page.Order != order || len(page.Sessions) != 657 {
					t.Fatalf("sort %s %s %+v", sort, order, page)
				}
			}
		}
	})
	t.Run("rejects cross tenant cluster group and malformed requests", func(t *testing.T) {
		for _, serve := range []http.HandlerFunc{handler.Sessions, handler.SessionsCSV, handler.SessionsSummary} {
			for _, scope := range []uuid.UUID{foreignCluster, uuid.New()} {
				w := request(t, serve, org, scope, "")
				if w.Code != 400 {
					t.Fatalf("foreign cluster %d %s", w.Code, w.Body.String())
				}
			}
			for _, query := range []string{"group=foreign-group", "group=sibling-group", "group=missing", "protocol=bad", "port=0", "port=65536", "hours=0", "limit=0", "limit=2001", "offset=-1", "offset=" + strconv.Itoa(inventorylist.MaxOffset+1), "sort=bytes;DROP", "sort=bad", "order=bad", "hide_platform=maybe"} {
				if w := request(t, serve, org, cluster, query); w.Code != 400 {
					t.Fatalf("invalid %s %d %s", query, w.Code, w.Body.String())
				}
			}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/network/sessions?cluster_id="+cluster.String(), nil)
			w := httptest.NewRecorder()
			serve(w, r)
			if w.Code != 401 {
				t.Fatalf("missing subject %d", w.Code)
			}
		}
		w := request(t, handler.Sessions, org, sibling, "")
		var data response
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || data.Total != 1 || data.Sessions[0].PlatformRole != "" {
			t.Fatalf("sibling scope %d %s", w.Code, w.Body.String())
		}
		r := httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}), http.MethodGet, "/network/sessions?limit=1", nil)
		w = httptest.NewRecorder()
		handler.Sessions(w, r)
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || data.ClusterID != cluster || data.Total != 657 {
			t.Fatalf("preferred cluster %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("CSV cap is explicit and platform exclusion still precedes the cap", func(t *testing.T) {
		capCluster := uuid.New()
		exec(`INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'cap')`, capCluster, org)
		exec(`INSERT INTO network_sessions(org_id,cluster_id,node,id,workload_id,ip_proto,server_port,updated_at)SELECT $1,$2,'node-cap',i,'kube-system/cap',6,443,NOW() FROM generate_series(1,100001)i`, org, capCluster)
		w := request(t, handler.SessionsCSV, org, capCluster, "sort=bytes&order=desc&limit=1&offset=100000")
		if w.Code != 200 || w.Header().Get("X-Export-Total") != "100001" || w.Header().Get("X-Export-Limit") != "100000" || w.Header().Get("X-Export-Truncated") != "true" {
			t.Fatalf("cap %d %v %s", w.Code, w.Header(), w.Body.String()[:min(200, w.Body.Len())])
		}
		records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
		if err != nil || len(records) != 100001 {
			t.Fatalf("cap rows%d err%v", len(records), err)
		}
		hidden := request(t, handler.SessionsCSV, org, capCluster, "hide_platform=true")
		records, err = csv.NewReader(strings.NewReader(hidden.Body.String())).ReadAll()
		if hidden.Code != 200 || err != nil || len(records) != 1 || hidden.Header().Get("X-Export-Total") != "0" || hidden.Header().Get("X-Export-Truncated") != "false" {
			t.Fatalf("hidden cap %d rows%d err%v", hidden.Code, len(records), err)
		}
	})
	t.Run("failed scope reads never become empty success or downloadable CSV", func(t *testing.T) {
		closed := openTestDB(t)
		closed.Close()
		unavailable := NewNetwork(closed)
		for _, serve := range []http.HandlerFunc{unavailable.Sessions, unavailable.SessionsCSV, unavailable.SessionsSummary} {
			w := request(t, serve, org, cluster, "")
			if w.Code != 500 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || w.Header().Get("X-Export-Total") != "" {
				t.Fatalf("closed DB %d %v %s", w.Code, w.Header(), w.Body.String())
			}
		}
	})
}
