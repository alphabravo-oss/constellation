package network

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestIngestSessionsUsesTokenClusterAndRejectsInvalidSnapshots(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, foreignOrgID := uuid.New(), uuid.New()
	clusterID, otherClusterID, foreignClusterID := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{orgID, foreignOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, id, "session-scope-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM network_session_kills WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM network_sessions WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM dpi_threat_settings WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgID, foreignOrgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'bound', 'disconnected'), ($3, $2, 'other', 'connected'), ($4, $5, 'foreign', 'connected')`, clusterID, orgID, otherClusterID, foreignClusterID, foreignOrgID); err != nil {
		t.Fatal(err)
	}
	issue := func(bundleClusters ...uuid.UUID) *handler.RuntimeAgentToken {
		t.Helper()
		_, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "session-scope-"+uuid.NewString(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for _, bundleCluster := range bundleClusters {
			if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`, orgID, bundleCluster, "session-scope-"+uuid.NewString(), tokenID); err != nil {
				t.Fatal(err)
			}
		}
		return &handler.RuntimeAgentToken{ID: tokenID, OrgID: orgID}
	}
	boundToken := issue(clusterID)
	unboundToken := issue()
	foreignToken := issue(foreignClusterID)
	conflictingToken := issue(clusterID, otherClusterID)
	const node = "shared-node"
	if _, err := pool.Exec(ctx, `INSERT INTO network_sessions (org_id, cluster_id, node, id) VALUES ($1, $2, $4, 11), ($1, $3, $4, 22)`, orgID, clusterID, otherClusterID, node); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_session_kills (org_id, cluster_id, node, session_id) VALUES ($1, $2, $4, 101), ($1, $3, $4, 202)`, orgID, clusterID, otherClusterID, node); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO dpi_threat_settings (org_id, cluster_id, weak_tls_enabled) VALUES ($1, $2, true), ($1, $3, false)`, orgID, clusterID, otherClusterID); err != nil {
		t.Fatal(err)
	}
	post := func(token *handler.RuntimeAgentToken, url string, rows []sessionIngestRow) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		request = request.WithContext(handler.WithRuntimeAgentToken(request.Context(), token))
		response := httptest.NewRecorder()
		NewNetwork(database).IngestSessions(response, request)
		return response
	}
	assertSnapshot := func(cluster uuid.UUID, wantID int64, wantKill int64) {
		t.Helper()
		var ids []int64
		rows, err := pool.Query(ctx, `SELECT id FROM network_sessions WHERE org_id = $1 AND cluster_id = $2 AND node = $3 ORDER BY id`, orgID, cluster, node)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
		if len(ids) != 1 || ids[0] != wantID {
			t.Fatalf("cluster %s session IDs = %v, want [%d]", cluster, ids, wantID)
		}
		var killID int64
		if err := pool.QueryRow(ctx, `SELECT session_id FROM network_session_kills WHERE org_id = $1 AND cluster_id = $2 AND node = $3`, orgID, cluster, node).Scan(&killID); err != nil {
			t.Fatal(err)
		}
		if killID != wantKill {
			t.Fatalf("cluster %s kill = %d, want %d", cluster, killID, wantKill)
		}
	}
	for _, testCase := range []struct {
		name   string
		token  *handler.RuntimeAgentToken
		url    string
		rows   []sessionIngestRow
		status int
	}{
		{"unbound multi-cluster token", unboundToken, "/api/v1/network-sessions:bulk", []sessionIngestRow{{ID: 33, Node: node}}, http.StatusForbidden},
		{"foreign bundle cluster", foreignToken, "/api/v1/network-sessions:bulk", []sessionIngestRow{{ID: 33, Node: node}}, http.StatusForbidden},
		{"conflicting bundles", conflictingToken, "/api/v1/network-sessions:bulk", []sessionIngestRow{{ID: 33, Node: node}}, http.StatusForbidden},
		{"other cluster query", boundToken, "/api/v1/network-sessions:bulk?cluster_id=" + otherClusterID.String(), []sessionIngestRow{{ID: 33, Node: node}}, http.StatusForbidden},
		{"foreign cluster query", boundToken, "/api/v1/network-sessions:bulk?cluster_id=" + foreignClusterID.String(), []sessionIngestRow{{ID: 33, Node: node}}, http.StatusForbidden},
		{"invalid cluster query", boundToken, "/api/v1/network-sessions:bulk?cluster_id=bad", []sessionIngestRow{{ID: 33, Node: node}}, http.StatusBadRequest},
		{"other cluster row", boundToken, "/api/v1/network-sessions:bulk", []sessionIngestRow{{ID: 33, Node: node}, {ID: 34, Node: node, ClusterID: otherClusterID.String()}}, http.StatusForbidden},
		{"foreign cluster row", boundToken, "/api/v1/network-sessions:bulk", []sessionIngestRow{{ID: 33, Node: node, ClusterID: foreignClusterID.String()}}, http.StatusForbidden},
		{"invalid cluster row", boundToken, "/api/v1/network-sessions:bulk", []sessionIngestRow{{ID: 33, Node: node, ClusterID: "bad"}}, http.StatusBadRequest},
		{"mixed nodes", boundToken, "/api/v1/network-sessions:bulk", []sessionIngestRow{{ID: 33, Node: node}, {ID: 34, Node: "other-node"}}, http.StatusBadRequest},
		{"missing node", boundToken, "/api/v1/network-sessions:bulk", []sessionIngestRow{{ID: 33}}, http.StatusBadRequest},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := post(testCase.token, testCase.url, testCase.rows)
			if response.Code != testCase.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, testCase.status, response.Body.String())
			}
			assertSnapshot(clusterID, 11, 101)
			assertSnapshot(otherClusterID, 22, 202)
		})
	}

	response := post(boundToken, "/api/v1/network-sessions:bulk?cluster_id="+clusterID.String(), []sessionIngestRow{{ID: 33, Node: node, ClusterID: clusterID.String(), ClientBytes: 123}})
	if response.Code != http.StatusOK {
		t.Fatalf("bound ingest status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Accepted int     `json:"accepted"`
		Kill     []int64 `json:"kill"`
		WeakTLS  bool    `json:"weak_tls"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 || len(result.Kill) != 1 || result.Kill[0] != 101 || !result.WeakTLS {
		t.Fatalf("bound ingest response = %+v", result)
	}
	var bytesWritten int64
	if err := pool.QueryRow(ctx, `SELECT client_bytes FROM network_sessions WHERE org_id = $1 AND cluster_id = $2 AND node = $3 AND id = 33`, orgID, clusterID, node).Scan(&bytesWritten); err != nil || bytesWritten != 123 {
		t.Fatalf("bound session bytes=%d err=%v", bytesWritten, err)
	}
	var oldCount, otherCount, remainingKills int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_sessions WHERE org_id = $1 AND cluster_id = $2 AND node = $3 AND id = 11`, orgID, clusterID, node).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_sessions WHERE org_id = $1 AND cluster_id = $2 AND node = $3 AND id = 22`, orgID, otherClusterID, node).Scan(&otherCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_session_kills WHERE org_id = $1 AND cluster_id = $2 AND node = $3`, orgID, clusterID, node).Scan(&remainingKills); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 || otherCount != 1 || remainingKills != 0 {
		t.Fatalf("snapshot isolation old=%d other=%d bound kills=%d", oldCount, otherCount, remainingKills)
	}
	assertSnapshot(otherClusterID, 22, 202)
}

func TestIngestSessionsAcceptsUnboundTokenForSingleCluster(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, clusterID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "session-single-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM network_sessions WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'single')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	_, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "session-single-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal([]sessionIngestRow{{ID: 77, Node: "node-a"}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/network-sessions:bulk", bytes.NewReader(body))
	request = request.WithContext(handler.WithRuntimeAgentToken(request.Context(), &handler.RuntimeAgentToken{ID: tokenID, OrgID: orgID}))
	response := httptest.NewRecorder()
	NewNetwork(database).IngestSessions(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Accepted int `json:"accepted"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Accepted != 1 {
		t.Fatalf("response=%s err=%v", response.Body.String(), err)
	}
	var storedCluster uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT cluster_id FROM network_sessions WHERE org_id = $1 AND node = 'node-a' AND id = 77`, orgID).Scan(&storedCluster); err != nil || storedCluster != clusterID {
		t.Fatalf("stored cluster=%s want=%s err=%v", storedCluster, clusterID, err)
	}
}
