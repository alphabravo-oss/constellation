package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestParseTimelineSources(t *testing.T) {
	all := parseTimelineSources("")
	for _, source := range allTimelineSources {
		if !all[source] {
			t.Fatalf("empty source filter did not enable %q: %+v", source, all)
		}
	}

	got := parseTimelineSources("audit,dpi_threat,unknown,AUDIT")
	if !got["audit"] || !got["dpi_threat"] {
		t.Fatalf("known sources missing from filter: %+v", got)
	}
	if got["runtime_event"] || got["network_violation"] || got["unknown"] {
		t.Fatalf("unexpected sources enabled: %+v", got)
	}
}

func TestSecurityTimelineDoesNotJoinForeignDeployment(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgA, orgB := uuid.New(), uuid.New()
	clusterA, clusterB := uuid.New(), uuid.New()
	deploymentA, deploymentB := uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "timeline-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'local'), ($3, $4, 'foreign')`, clusterA, orgA, clusterB, orgB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind) VALUES
($1, $2, $3, 'local-ns', 'local-app', 'Deployment'),
($4, $5, $6, 'foreign-ns', 'foreign-app', 'Deployment')`, deploymentA, orgA, clusterA, deploymentB, orgB, clusterB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO violations (org_id, deployment_id, severity, kind, message) VALUES
($1, $2, 'high', 'runtime', 'local event'),
($1, $3, 'high', 'runtime', 'cross-linked event'),
($4, $3, 'high', 'runtime', 'foreign event')`, orgA, deploymentA, deploymentB, orgB); err != nil {
		t.Fatal(err)
	}

	list := func(orgID uuid.UUID, clusterID *uuid.UUID) []timelineItem {
		t.Helper()
		url := "/api/v1/security/timeline?type=network_violation"
		if clusterID != nil {
			url += "&cluster_id=" + clusterID.String()
		}
		request := httptest.NewRequest(http.MethodGet, url, nil)
		request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: orgID}))
		response := httptest.NewRecorder()
		NewSecurityTimeline(database).List(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("timeline status=%d body=%s", response.Code, response.Body.String())
		}
		var result struct {
			Items []timelineItem `json:"items"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Items
	}

	items := list(orgA, nil)
	if len(items) != 2 {
		t.Fatalf("org A timeline has %d rows, want 2: %+v", len(items), items)
	}
	for _, item := range items {
		switch item.Title {
		case "local event":
			if item.WorkloadID != "local-app" || item.Namespace != "local-ns" || item.ClusterID != clusterA.String() {
				t.Fatalf("local event lost attribution: %+v", item)
			}
		case "cross-linked event":
			if item.WorkloadID != "" || item.Namespace != "" || item.ClusterID != "" {
				t.Fatalf("foreign deployment metadata leaked: %+v", item)
			}
		default:
			t.Fatalf("unexpected org A event: %+v", item)
		}
	}
	foreignRequest := httptest.NewRequest(http.MethodGet, "/api/v1/security/timeline?cluster_id="+clusterB.String(), nil)
	foreignRequest = foreignRequest.WithContext(WithSubject(foreignRequest.Context(), Subject{OrgID: orgA}))
	foreignResponse := httptest.NewRecorder()
	NewSecurityTimeline(database).List(foreignResponse, foreignRequest)
	if foreignResponse.Code != http.StatusNotFound {
		t.Fatalf("foreign cluster filter status=%d body=%s", foreignResponse.Code, foreignResponse.Body.String())
	}
	if got := list(orgA, &clusterA); len(got) != 1 || got[0].Title != "local event" {
		t.Fatalf("local cluster filter returned %+v", got)
	}
	if got := list(orgB, nil); len(got) != 1 || got[0].Title != "foreign event" {
		t.Fatalf("org B timeline returned %+v", got)
	}
}
