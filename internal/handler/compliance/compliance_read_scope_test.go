package compliance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestComplianceReadScope(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := context.Background()
	ensureComplianceExemptionsTestTable(t, pool)

	orgA, orgB := uuid.New(), uuid.New()
	clusterA, clusterB, foreignCluster := uuid.New(), uuid.New(), uuid.New()
	framework := "read-scope-" + uuid.NewString()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "compliance-read-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB); err != nil {
			t.Errorf("clean up orgs: %v", err)
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'local-a'), ($3, $2, 'local-b'), ($4, $5, 'foreign')`, clusterA, orgA, clusterB, foreignCluster, orgB); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		orgID, clusterID         uuid.UUID
		controlID, title, status string
	}{
		{orgA, clusterA, "a", "local-a", "pass"},
		{orgA, clusterB, "b", "local-b", "fail"},
		{orgA, uuid.Nil, "org", "org-wide", "manual"},
		{orgA, foreignCluster, "wrong", "misattributed", "fail"},
		{orgB, foreignCluster, "foreign", "foreign-org", "pass"},
	} {
		var clusterArg any
		if row.clusterID != uuid.Nil {
			clusterArg = row.clusterID
		}
		if _, err := pool.Exec(ctx, `INSERT INTO compliance_checks (org_id, cluster_id, framework, control_id, title, status, severity) VALUES ($1, $2, $3, $4, $5, $6, 'high')`, row.orgID, clusterArg, framework, row.controlID, row.title, row.status); err != nil {
			t.Fatal(err)
		}
	}

	handler := NewCompliance(database, nil)
	for _, endpoint := range []struct {
		name  string
		serve func(http.ResponseWriter, *http.Request)
	}{
		{"checks", handler.Checks},
		{"summary", handler.Summary},
	} {
		for _, test := range []struct {
			name               string
			orgID              uuid.UUID
			cluster            string
			status             int
			titles             []string
			pass, fail, manual int
		}{
			{"org-wide", orgA, "", http.StatusOK, []string{"local-a", "local-b", "org-wide"}, 1, 1, 1},
			{"local-a", orgA, clusterA.String(), http.StatusOK, []string{"local-a"}, 1, 0, 0},
			{"local-b", orgA, clusterB.String(), http.StatusOK, []string{"local-b"}, 0, 1, 0},
			{"foreign-cluster", orgA, foreignCluster.String(), http.StatusNotFound, nil, 0, 0, 0},
			{"missing-cluster", orgA, uuid.NewString(), http.StatusNotFound, nil, 0, 0, 0},
			{"invalid-cluster", orgA, "invalid", http.StatusBadRequest, nil, 0, 0, 0},
			{"other-org-wide", orgB, "", http.StatusOK, []string{"foreign-org"}, 1, 0, 0},
			{"other-org-cluster", orgB, foreignCluster.String(), http.StatusOK, []string{"foreign-org"}, 1, 0, 0},
		} {
			t.Run(endpoint.name+"/"+test.name, func(t *testing.T) {
				url := "/api/v1/compliance/" + endpoint.name + "?"
				if endpoint.name == "checks" {
					url += "framework=" + framework + "&"
				}
				if test.cluster != "" {
					url += "cluster_id=" + test.cluster
				}
				request := httptest.NewRequest(http.MethodGet, url, nil)
				request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: test.orgID}))
				response := httptest.NewRecorder()
				endpoint.serve(response, request)
				if response.Code != test.status {
					t.Fatalf("status=%d, want %d: %s", response.Code, test.status, response.Body.String())
				}
				if test.status != http.StatusOK {
					if len(response.Body.Bytes()) == 0 {
						t.Fatal("empty error response")
					}
					return
				}
				if endpoint.name == "checks" {
					var result struct {
						Checks []struct {
							Title string `json:"title"`
						} `json:"checks"`
					}
					if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if len(result.Checks) != len(test.titles) {
						t.Fatalf("checks=%s, want titles=%v", response.Body.String(), test.titles)
					}
					wanted := make(map[string]bool, len(test.titles))
					for _, title := range test.titles {
						wanted[title] = true
					}
					for _, check := range result.Checks {
						if !wanted[check.Title] {
							t.Fatalf("unexpected check %q: %s", check.Title, response.Body.String())
						}
						delete(wanted, check.Title)
					}
					if len(wanted) != 0 {
						t.Fatalf("missing checks %v: %s", wanted, response.Body.String())
					}
					return
				}
				var result struct {
					Frameworks []struct {
						Framework string `json:"framework"`
						Pass      int    `json:"pass"`
						Fail      int    `json:"fail"`
						Manual    int    `json:"manual"`
						Total     int    `json:"total"`
					} `json:"frameworks"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Frameworks) != 1 || result.Frameworks[0].Framework != framework ||
					result.Frameworks[0].Pass != test.pass || result.Frameworks[0].Fail != test.fail ||
					result.Frameworks[0].Manual != test.manual || result.Frameworks[0].Total != len(test.titles) {
					t.Fatalf("summary=%s, want pass=%d fail=%d manual=%d total=%d", response.Body.String(), test.pass, test.fail, test.manual, len(test.titles))
				}
			})
		}
	}
}
