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

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
)

func seedBoundRuntimeAgentScope(t *testing.T, database *db.DB, orgID, clusterID uuid.UUID) *handler.RuntimeAgentToken {
	t.Helper()
	ctx := context.Background()
	pool := database.Pool()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "response-scope-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_response_actions WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'response-scope')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	_, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "response-scope-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO cluster_init_bundles
  (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`,
		orgID, clusterID, "response-scope-"+uuid.NewString(), tokenID); err != nil {
		t.Fatal(err)
	}
	return &handler.RuntimeAgentToken{ID: tokenID, OrgID: orgID}
}

func TestResponseActionsRejectCrossClusterAndAmbiguousTokens(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, clusterA, clusterB := uuid.New(), uuid.New(), uuid.New()
	tokenA := seedBoundRuntimeAgentScope(t, database, orgID, clusterA)
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'response-other')`, clusterB, orgID); err != nil {
		t.Fatal(err)
	}
	_, freeID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "response-free-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	freeToken := &handler.RuntimeAgentToken{ID: freeID, OrgID: orgID}
	foreignOrg, foreignCluster := uuid.New(), uuid.New()
	seedBoundRuntimeAgentScope(t, database, foreignOrg, foreignCluster)
	_, foreignID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "response-foreign-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO cluster_init_bundles
  (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`,
		foreignOrg, foreignCluster, "response-foreign-"+uuid.NewString(), foreignID); err != nil {
		t.Fatal(err)
	}
	foreignToken := &handler.RuntimeAgentToken{ID: foreignID, OrgID: orgID}
	var actionID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO runtime_response_actions (org_id, cluster_id, node, type, workload_id, state)
VALUES ($1, $2, 'node-a', 'kill_process', 'ns/target', 'pending') RETURNING id`, orgID, clusterB).Scan(&actionID); err != nil {
		t.Fatal(err)
	}
	h := NewResponseActions(database)
	for _, testCase := range []struct {
		name  string
		token *handler.RuntimeAgentToken
	}{
		{"other cluster", tokenA},
		{"ambiguous token", freeToken},
		{"foreign bundle", foreignToken},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			get := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/response-actions:pending?cluster_id="+clusterB.String()+"&node=node-a", nil)
			get = get.WithContext(handler.WithRuntimeAgentToken(get.Context(), testCase.token))
			gotPending := httptest.NewRecorder()
			h.Pending(gotPending, get)
			if gotPending.Code != http.StatusForbidden {
				t.Fatalf("pending status=%d body=%s", gotPending.Code, gotPending.Body.String())
			}
			body, err := json.Marshal(responseActionResultWire{ID: actionID.String(), Applied: true, Node: "node-a", At: time.Now().UTC()})
			if err != nil {
				t.Fatal(err)
			}
			post := httptest.NewRequest(http.MethodPost, "/api/v1/runtime/response-actions:result", bytes.NewReader(body))
			post = post.WithContext(handler.WithRuntimeAgentToken(post.Context(), testCase.token))
			gotResult := httptest.NewRecorder()
			h.Result(gotResult, post)
			if testCase.token != tokenA && gotResult.Code != http.StatusForbidden {
				t.Fatalf("invalid-binding result status=%d body=%s", gotResult.Code, gotResult.Body.String())
			}
			if testCase.token == tokenA && gotResult.Code != http.StatusOK {
				t.Fatalf("cross-cluster result status=%d body=%s", gotResult.Code, gotResult.Body.String())
			}
			var state string
			if err := pool.QueryRow(ctx, `SELECT state FROM runtime_response_actions WHERE id = $1`, actionID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != "pending" {
				t.Fatalf("cross-cluster action changed to %s", state)
			}
		})
	}
}
