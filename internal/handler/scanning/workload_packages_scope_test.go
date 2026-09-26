package scanning

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

func TestWorkloadPackagesRejectsUnboundAndForeignClusterWrites(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgA, orgB := uuid.New(), uuid.New()
	clusterA, clusterB, foreignCluster := uuid.New(), uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "workload-scope-"+orgID.String()); err != nil {
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
		raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgA, "workload-scope-"+uuid.NewString(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if bundleCluster != nil {
			if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`, orgA, *bundleCluster, "workload-scope-"+uuid.NewString(), tokenID); err != nil {
				t.Fatal(err)
			}
		}
		return raw
	}
	boundToken := issue(&clusterA)
	unboundToken := issue(nil)
	foreignToken := issue(&foreignCluster)
	for _, testCase := range []struct {
		name      string
		token     string
		clusterID *uuid.UUID
		wantCode  int
	}{
		{name: "bound without body scope", token: boundToken, wantCode: http.StatusOK},
		{name: "same-org different cluster", token: boundToken, clusterID: &clusterB, wantCode: http.StatusForbidden},
		{name: "foreign cluster", token: boundToken, clusterID: &foreignCluster, wantCode: http.StatusNotFound},
		{name: "unbound multi-cluster token", token: unboundToken, wantCode: http.StatusForbidden},
		{name: "foreign bundle cluster", token: foreignToken, wantCode: http.StatusForbidden},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			workloadID := "scope/" + uuid.NewString()
			body, err := json.Marshal(WorkloadPackagesPayload{
				ClusterID:  testCase.clusterID,
				Node:       "node-a",
				WorkloadID: workloadID,
				Containers: []WorkloadPackageContainer{{
					ContainerID: "container-a",
					Distro:      "ubuntu",
					Source:      "dpkg",
					Items:       []handler.HostPackageItem{{Name: "openssl", Version: "3.0"}},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/workload-packages:report", bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+testCase.token)
			response := httptest.NewRecorder()
			handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(NewWorkloadPackages(database).Report)).ServeHTTP(response, request)
			if response.Code != testCase.wantCode {
				t.Fatalf("report status=%d want=%d body=%s", response.Code, testCase.wantCode, response.Body.String())
			}
			var targetCount, evidenceCount, jobCount int
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_targets WHERE org_id = $1 AND type = 'workload' AND ref = $2`, orgA, workloadID).Scan(&targetCount); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_evidence WHERE org_id = $1 AND target_type = 'workload' AND target_ref = $2`, orgA, workloadID).Scan(&evidenceCount); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_jobs sj JOIN scan_targets st ON st.id = sj.target_id WHERE sj.org_id = $1 AND st.ref = $2`, orgA, workloadID).Scan(&jobCount); err != nil {
				t.Fatal(err)
			}
			if testCase.wantCode != http.StatusOK && (targetCount != 0 || evidenceCount != 0 || jobCount != 0) {
				t.Fatalf("rejected report wrote target=%d evidence=%d jobs=%d", targetCount, evidenceCount, jobCount)
			}
			if testCase.wantCode == http.StatusOK && (targetCount != 1 || evidenceCount != 1 || jobCount != 1) {
				t.Fatalf("accepted report wrote target=%d evidence=%d jobs=%d", targetCount, evidenceCount, jobCount)
			}
		})
	}
}
