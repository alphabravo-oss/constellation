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

func TestEventsIngestClusterBinding(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	workloadID := "event-scope/" + uuid.NewString()

	createOrg := func() uuid.UUID {
		t.Helper()
		var orgID uuid.UUID
		name := "event-scope-" + uuid.NewString()
		if err := pool.QueryRow(ctx, `INSERT INTO orgs (name, display_name) VALUES ($1, $1) RETURNING id`, name).Scan(&orgID); err != nil {
			t.Fatal(err)
		}
		return orgID
	}
	createCluster := func(orgID uuid.UUID) uuid.UUID {
		t.Helper()
		var clusterID uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO clusters (org_id, name) VALUES ($1, $2) RETURNING id`, orgID, "event-scope-"+uuid.NewString()).Scan(&clusterID); err != nil {
			t.Fatal(err)
		}
		return clusterID
	}
	orgA, orgB, orgSingle := createOrg(), createOrg(), createOrg()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE workload_id=$1`, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2, $3)`, orgA, orgB, orgSingle)
	})
	clusterA := createCluster(orgA)
	clusterOther := createCluster(orgA)
	clusterForeign := createCluster(orgB)
	clusterSingle := createCluster(orgSingle)
	boundToken := issueBoundRuntimeEventToken(t, pool, orgA, clusterA, "event-scope-bound-"+uuid.NewString())
	issueToken := func(orgID uuid.UUID) (string, uuid.UUID) {
		t.Helper()
		raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "event-scope-"+uuid.NewString(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return raw, tokenID
	}
	freeToken, _ := issueToken(orgA)
	singleToken, _ := issueToken(orgSingle)
	foreignClusterToken, foreignClusterTokenID := issueToken(orgA)
	foreignBundleToken, foreignBundleTokenID := issueToken(orgA)
	for _, mapping := range []struct {
		bundleOrgID uuid.UUID
		clusterID   uuid.UUID
		tokenID     uuid.UUID
	}{
		{orgA, clusterForeign, foreignClusterTokenID},
		{orgB, clusterForeign, foreignBundleTokenID},
	} {
		if _, err := pool.Exec(ctx, `
INSERT INTO cluster_init_bundles
  (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`,
			mapping.bundleOrgID, mapping.clusterID, "event-scope-"+uuid.NewString(), mapping.tokenID); err != nil {
			t.Fatal(err)
		}
	}

	h := NewEventsIngest(d, nil, nil)
	post := func(rawToken, clusterQuery string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal([]IngestEvent{{At: time.Now().UTC(), Kind: "process_exec", Node: "node", WorkloadID: workloadID, Comm: "nginx"}})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/events:bulk"+clusterQuery, bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+rawToken)
		recorder := httptest.NewRecorder()
		handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(recorder, request)
		return recorder
	}
	count := func() int {
		t.Helper()
		var rows int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE workload_id=$1`, workloadID).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	for _, testCase := range []struct {
		name       string
		token      string
		query      string
		wantStatus int
		wantOrg    uuid.UUID
		wantCID    uuid.UUID
	}{
		{"bound without query", boundToken, "", http.StatusOK, orgA, clusterA},
		{"bound matching query", boundToken, "?cluster_id=" + clusterA.String(), http.StatusOK, orgA, clusterA},
		{"same-org other cluster", boundToken, "?cluster_id=" + clusterOther.String(), http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"foreign cluster query", boundToken, "?cluster_id=" + clusterForeign.String(), http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"malformed cluster query", boundToken, "?cluster_id=invalid", http.StatusBadRequest, uuid.Nil, uuid.Nil},
		{"ambiguous token without query", freeToken, "", http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"ambiguous token with query", freeToken, "?cluster_id=" + clusterA.String(), http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"foreign cluster bundle", foreignClusterToken, "", http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"foreign org bundle", foreignBundleToken, "", http.StatusForbidden, uuid.Nil, uuid.Nil},
		{"single-cluster fallback", singleToken, "", http.StatusOK, orgSingle, clusterSingle},
		{"single-cluster matching query", singleToken, "?cluster_id=" + clusterSingle.String(), http.StatusOK, orgSingle, clusterSingle},
		{"single-cluster mismatched query", singleToken, "?cluster_id=" + clusterA.String(), http.StatusForbidden, uuid.Nil, uuid.Nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			before := count()
			response := post(testCase.token, testCase.query)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, testCase.wantStatus, response.Body.String())
			}
			wantCount := before
			if testCase.wantStatus == http.StatusOK {
				wantCount++
			}
			if got := count(); got != wantCount {
				t.Fatalf("events=%d want=%d", got, wantCount)
			}
			if testCase.wantStatus == http.StatusOK {
				var orgID, clusterID uuid.UUID
				if err := pool.QueryRow(ctx, `SELECT org_id, cluster_id FROM events WHERE workload_id=$1 ORDER BY at DESC LIMIT 1`, workloadID).Scan(&orgID, &clusterID); err != nil {
					t.Fatal(err)
				}
				if orgID != testCase.wantOrg || clusterID != testCase.wantCID {
					t.Fatalf("attribution=%s/%s want=%s/%s", orgID, clusterID, testCase.wantOrg, testCase.wantCID)
				}
			}
		})
	}
}
