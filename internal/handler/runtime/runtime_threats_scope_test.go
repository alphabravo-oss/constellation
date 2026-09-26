package runtime

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

func TestRuntimeThreatsUseReportingTokenCluster(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgA, orgB := uuid.New(), uuid.New()
	clusterA, clusterB, foreignCluster := uuid.New(), uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "threat-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'a'), ($3, $2, 'b'), ($4, $5, 'foreign')`, clusterA, orgA, clusterB, foreignCluster, orgB); err != nil {
		t.Fatal(err)
	}
	issue := func(bundleCluster *uuid.UUID) string {
		t.Helper()
		raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgA, "threat-scope-"+uuid.NewString(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if bundleCluster != nil {
			if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`, orgA, *bundleCluster, "threat-scope-"+uuid.NewString(), tokenID); err != nil {
				t.Fatal(err)
			}
		}
		return raw
	}
	boundToken := issue(&clusterA)
	unboundToken := issue(nil)
	foreignToken := issue(&foreignCluster)
	for _, testCase := range []struct {
		name     string
		token    string
		wantCode int
	}{
		{name: "bound token", token: boundToken, wantCode: http.StatusOK},
		{name: "unbound multi-cluster token", token: unboundToken, wantCode: http.StatusForbidden},
		{name: "foreign bundle cluster", token: foreignToken, wantCode: http.StatusForbidden},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			node := "threat-scope-" + uuid.NewString()
			body, err := json.Marshal([]ThreatIngestRow{{Node: node, ThreatID: 2022, Severity: 1, At: time.Now().UTC()}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-threats:bulk", bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+testCase.token)
			response := httptest.NewRecorder()
			handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(NewRuntimeThreats(database).Bulk)).ServeHTTP(response, request)
			if response.Code != testCase.wantCode {
				t.Fatalf("threat ingest status=%d want=%d body=%s", response.Code, testCase.wantCode, response.Body.String())
			}
			var count int
			var clusterID string
			if err := pool.QueryRow(ctx, `SELECT COUNT(*), COALESCE((array_agg(cluster_id::text))[1], '') FROM runtime_threats WHERE org_id = $1 AND node = $2`, orgA, node).Scan(&count, &clusterID); err != nil {
				t.Fatal(err)
			}
			if testCase.wantCode == http.StatusOK && (count != 1 || clusterID != clusterA.String()) {
				t.Fatalf("bound threat attribution count=%d cluster=%v", count, clusterID)
			}
			if testCase.wantCode != http.StatusOK && count != 0 {
				t.Fatalf("rejected threat wrote %d rows", count)
			}
		})
	}
}
