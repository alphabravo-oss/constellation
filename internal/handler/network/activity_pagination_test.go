package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestNetworkActivityLargeFixtureFiltersAndPages(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := context.Background()
	orgID, clusterID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "network-page-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'net-page', 'connected')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_sessions (org_id, cluster_id, node, id, workload_id, ip_proto, client_ip, client_port, server_ip, server_port, client_bytes, updated_at)
SELECT $1, $2, 'node-a', seq, 'default/client', 6, '10.0.0.1', 40000 + seq, '10.0.0.2', 443, seq, NOW()
  FROM generate_series(1, 250) AS seq`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_flow_rollups (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bucket, max_at, sum_bytes, min_src_addr, min_dst_addr)
SELECT $1, $2, 'default/client', 'default/service-' || seq, 'tcp', 'https', 443, 'allow', date_trunc('hour', NOW()), NOW(), seq, '10.0.0.1', '10.0.0.2'
  FROM generate_series(1, 250) AS seq`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	subject := authctx.Subject{OrgID: orgID, UserID: uuid.New()}
	request := func(path string, serve func(http.ResponseWriter, *http.Request)) map[string]json.RawMessage {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), subject))
		response := httptest.NewRecorder()
		serve(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", path, response.Code, response.Body.String())
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	checkPage := func(body map[string]json.RawMessage, key string, wantRows, wantTotal int, wantMore bool) {
		t.Helper()
		var rows []json.RawMessage
		var total int
		var hasMore bool
		_ = json.Unmarshal(body[key], &rows)
		_ = json.Unmarshal(body["total"], &total)
		_ = json.Unmarshal(body["has_more"], &hasMore)
		if len(rows) != wantRows || total != wantTotal || hasMore != wantMore {
			t.Fatalf("%s: rows=%d total=%d has_more=%t; want %d/%d/%t", key, len(rows), total, hasMore, wantRows, wantTotal, wantMore)
		}
	}
	for _, offset := range []int{0, 100, 200} {
		wantRows := 100
		if offset == 200 {
			wantRows = 50
		}
		path := fmt.Sprintf("/api/v1/network/sessions?cluster_id=%s&limit=100&offset=%d&port=443&application=https&peer=10.0.0.2", clusterID, offset)
		checkPage(request(path, NewNetwork(database).Sessions), "sessions", wantRows, 250, offset < 200)
		path = fmt.Sprintf("/api/v1/network/conversations?cluster_id=%s&limit=100&offset=%d&port=443&application=https&peer=default", clusterID, offset)
		checkPage(request(path, NewNetworkConversations(database).List), "conversations", wantRows, 250, offset < 200)
	}
	filtered := request(fmt.Sprintf("/api/v1/network/conversations?cluster_id=%s&port=53", clusterID), NewNetworkConversations(database).List)
	checkPage(filtered, "conversations", 0, 0, false)
	if _, err := pool.Exec(ctx, `
INSERT INTO network_flow_rollups (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bucket, max_at, sum_bytes, min_src_addr, min_dst_addr)
SELECT $1, $2, 'default/client', 'default/service-' || seq, 'tcp', 'https', 443, 'allow', date_trunc('hour', NOW()), NOW(), seq, '10.0.0.1', '10.0.0.2'
  FROM generate_series(251, 350) AS seq`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	activity := request(fmt.Sprintf("/api/v1/network/map?cluster_id=%s&port=443&application=https&peer=default", clusterID), NewNetwork(database).Map)
	var flows []json.RawMessage
	_ = json.Unmarshal(activity["flows"], &flows)
	var summary struct {
		FlowsTotal   int  `json:"flows_total"`
		FlowsHasMore bool `json:"flows_has_more"`
	}
	_ = json.Unmarshal(activity["summary"], &summary)
	if len(flows) != 300 || summary.FlowsTotal != 350 || !summary.FlowsHasMore {
		t.Fatalf("map rows=%d summary=%+v", len(flows), summary)
	}
	last := request(fmt.Sprintf("/api/v1/network/map?cluster_id=%s&port=443&application=https&peer=default&offset=300", clusterID), NewNetwork(database).Map)
	_ = json.Unmarshal(last["flows"], &flows)
	_ = json.Unmarshal(last["summary"], &summary)
	if len(flows) != 50 || summary.FlowsTotal != 350 || summary.FlowsHasMore {
		t.Fatalf("map last rows=%d summary=%+v", len(flows), summary)
	}
}
