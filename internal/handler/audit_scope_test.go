package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestAuditListScopesOrgAndCluster(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgA, orgB := uuid.New(), uuid.New()
	clusterA, clusterB := uuid.New(), uuid.New()
	action := "audit.scope." + uuid.NewString()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "audit-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'local'), ($3, $4, 'foreign')`, clusterA, orgA, clusterB, orgB); err != nil {
		t.Fatal(err)
	}
	logger := audit.New(pool)
	for _, event := range []audit.Event{
		{OrgID: &orgA, Action: action, TargetKind: "cluster", TargetID: clusterA.String()},
		{OrgID: &orgB, Action: action, TargetKind: "cluster", TargetID: clusterB.String()},
	} {
		if _, _, err := logger.Log(ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	list := func(orgID uuid.UUID, clusterID *uuid.UUID) *httptest.ResponseRecorder {
		t.Helper()
		url := "/api/v1/audit/events?action=" + action
		if clusterID != nil {
			url += "&cluster_id=" + clusterID.String()
		}
		request := httptest.NewRequest(http.MethodGet, url, nil)
		request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: orgID}))
		response := httptest.NewRecorder()
		NewAudit(database).List(response, request)
		return response
	}
	for _, response := range []*httptest.ResponseRecorder{list(orgA, nil), list(orgA, &clusterA), list(orgB, nil), list(orgB, &clusterB)} {
		if response.Code != http.StatusOK {
			t.Fatalf("audit list status=%d body=%s", response.Code, response.Body.String())
		}
		var result struct {
			Events []auditDTO `json:"events"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Events) != 1 {
			t.Fatalf("audit list returned %d events, want 1: %s", len(result.Events), response.Body.String())
		}
	}
	if response := list(orgA, &clusterB); response.Code != http.StatusNotFound {
		t.Fatalf("foreign cluster filter status=%d body=%s", response.Code, response.Body.String())
	}
}
