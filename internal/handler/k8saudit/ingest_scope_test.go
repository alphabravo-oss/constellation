package k8saudit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestAuditIngestUsesTokenClusterAndRejectsInvalidBindings(t *testing.T) {
	databaseURL := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	database, err := db.Connect(context.Background(), databaseURL)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	createOrg := func() uuid.UUID {
		t.Helper()
		var orgID uuid.UUID
		name := "audit-scope-" + uuid.NewString()
		if err := pool.QueryRow(ctx, `INSERT INTO orgs (name, display_name) VALUES ($1, $1) RETURNING id`, name).Scan(&orgID); err != nil {
			t.Fatal(err)
		}
		return orgID
	}
	createCluster := func(orgID uuid.UUID) uuid.UUID {
		t.Helper()
		var clusterID uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO clusters (org_id, name) VALUES ($1, $2) RETURNING id`, orgID, "audit-scope-"+uuid.NewString()).Scan(&clusterID); err != nil {
			t.Fatal(err)
		}
		return clusterID
	}
	orgA, orgB, orgSingle := createOrg(), createOrg(), createOrg()
	marker := "audit-scope-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM k8s_audit_events WHERE audit_id LIKE $1`, marker+"%")
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2, $3)`, orgA, orgB, orgSingle)
	})
	clusterA := createCluster(orgA)
	clusterOther := createCluster(orgA)
	clusterForeign := createCluster(orgB)
	clusterSingle := createCluster(orgSingle)
	issueToken := func(orgID uuid.UUID, bundleOrgID, bundleClusterID *uuid.UUID) string {
		t.Helper()
		raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "audit-scope-"+uuid.NewString(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if bundleClusterID != nil {
			if _, err := pool.Exec(ctx, `
INSERT INTO cluster_init_bundles
  (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`,
				*bundleOrgID, *bundleClusterID, "audit-scope-"+uuid.NewString(), tokenID); err != nil {
				t.Fatal(err)
			}
		}
		return raw
	}
	boundToken := issueToken(orgA, &orgA, &clusterA)
	freeToken := issueToken(orgA, nil, nil)
	foreignClusterToken := issueToken(orgA, &orgA, &clusterForeign)
	foreignOrgToken := issueToken(orgA, &orgB, &clusterForeign)
	singleToken := issueToken(orgSingle, nil, nil)

	for _, testCase := range []struct {
		name       string
		token      string
		query      string
		wantStatus int
		wantOrg    uuid.UUID
		wantCID    uuid.UUID
	}{
		{"bound cluster despite spoofed query", boundToken, "?cluster_id=" + clusterOther.String(), http.StatusOK, orgA, clusterA},
		{"ambiguous multi-cluster token", freeToken, "", http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"foreign cluster bundle", foreignClusterToken, "", http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"foreign org bundle", foreignOrgToken, "", http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"single-cluster fallback", singleToken, "", http.StatusOK, orgSingle, clusterSingle},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			auditID := marker + "-" + uuid.NewString()
			body, err := json.Marshal([]map[string]any{{
				"auditID":    auditID,
				"verb":       "get",
				"objectRef":  map[string]string{"resource": "configmaps"},
				"cluster_id": clusterForeign.String(),
			}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/k8s-audit:bulk"+testCase.query, bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+testCase.token)
			recorder := httptest.NewRecorder()
			handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(NewIngest(database).Bulk)).ServeHTTP(recorder, request)
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, testCase.wantStatus, recorder.Body.String())
			}
			var count int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_audit_events WHERE audit_id=$1`, auditID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if testCase.wantStatus != http.StatusOK {
				if count != 0 {
					t.Fatalf("rejected audit event persisted %d rows", count)
				}
				return
			}
			if count != 1 {
				t.Fatalf("accepted audit event persisted %d rows, want 1", count)
			}
			var orgID, clusterID uuid.UUID
			if err := pool.QueryRow(ctx, `SELECT org_id, cluster_id FROM k8s_audit_events WHERE audit_id=$1`, auditID).Scan(&orgID, &clusterID); err != nil {
				t.Fatal(err)
			}
			if orgID != testCase.wantOrg || clusterID != testCase.wantCID {
				t.Fatalf("attribution=%s/%s want=%s/%s", orgID, clusterID, testCase.wantOrg, testCase.wantCID)
			}
		})
	}
}
