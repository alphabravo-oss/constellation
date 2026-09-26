package compliance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

func TestComplianceEvidenceExemptionsStayInCluster(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := context.Background()
	ensureComplianceExemptionsTestTable(t, pool)
	orgA, orgB := uuid.New(), uuid.New()
	clusterA, clusterB, foreignCluster := uuid.New(), uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "evidence-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'a'), ($3, $2, 'b'), ($4, $5, 'foreign')`, clusterA, orgA, clusterB, foreignCluster, orgB); err != nil {
		t.Fatal(err)
	}
	payload := `{"checks":[{"id":"3.2.1","title":"Source routing","result":"fail","detail":"failed"}]}`
	for _, row := range []struct {
		clusterID uuid.UUID
		node      string
	}{{clusterA, "node-a"}, {clusterB, "node-b"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO host_cis (org_id, cluster_id, node, profile, passed, failed, warned, skipped, payload, observed_at) VALUES ($1, $2, $3, 'cis-distro-linux-min', 0, 1, 0, 0, $4, NOW())`, orgA, row.clusterID, row.node, payload); err != nil {
			t.Fatal(err)
		}
	}
	var scopedID, orgWideID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO compliance_exemptions (org_id, cluster_id, framework, control_id, reason, expires_at) VALUES ($1, $2, $3, '3.2.1', 'approved scoped exception', $4) RETURNING id`, orgA, clusterA, compliancepkg.FrameworkCISLinux, time.Now().Add(24*time.Hour)).Scan(&scopedID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO compliance_exemptions (org_id, cluster_id, framework, control_id, reason, expires_at) VALUES ($1, $2, $3, '3.2.1', 'misattributed exception', $4)`, orgA, foreignCluster, compliancepkg.FrameworkCISLinux, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO compliance_checks (org_id, cluster_id, framework, control_id, title, status, severity) VALUES ($1, $2, $4, '3.2.1', 'local', 'fail', 'high'), ($1, $3, $4, '3.2.1', 'misattributed', 'fail', 'high')`, orgA, clusterA, foreignCluster, compliancepkg.FrameworkCISLinux); err != nil {
		t.Fatal(err)
	}
	checksRequest := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/checks?framework="+compliancepkg.FrameworkCISLinux, nil)
	checksRequest = checksRequest.WithContext(authctx.WithSubject(checksRequest.Context(), authctx.Subject{OrgID: orgA}))
	checksResponse := httptest.NewRecorder()
	NewCompliance(database, nil).Checks(checksResponse, checksRequest)
	if checksResponse.Code != http.StatusOK {
		t.Fatalf("checks status=%d body=%s", checksResponse.Code, checksResponse.Body.String())
	}
	var checksResult struct {
		Checks []struct {
			Title           string `json:"title"`
			EffectiveStatus string `json:"effective_status"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(checksResponse.Body.Bytes(), &checksResult); err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, check := range checksResult.Checks {
		statuses[check.Title] = check.EffectiveStatus
	}
	if len(checksResult.Checks) != 1 || statuses["local"] != "exempted" || statuses["misattributed"] != "" {
		t.Fatalf("misattributed check exemption: %s", checksResponse.Body.String())
	}
	summaryRequest := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/summary", nil)
	summaryRequest = summaryRequest.WithContext(authctx.WithSubject(summaryRequest.Context(), authctx.Subject{OrgID: orgA}))
	summaryResponse := httptest.NewRecorder()
	NewCompliance(database, nil).Summary(summaryResponse, summaryRequest)
	if summaryResponse.Code != http.StatusOK {
		t.Fatalf("summary status=%d body=%s", summaryResponse.Code, summaryResponse.Body.String())
	}
	var summaryResult struct {
		Frameworks []struct {
			Fail     int `json:"fail"`
			Exempted int `json:"exempted"`
		} `json:"frameworks"`
	}
	if err := json.Unmarshal(summaryResponse.Body.Bytes(), &summaryResult); err != nil {
		t.Fatal(err)
	}
	if len(summaryResult.Frameworks) != 1 || summaryResult.Frameworks[0].Fail != 0 || summaryResult.Frameworks[0].Exempted != 1 {
		t.Fatalf("misattributed summary exemption: %s", summaryResponse.Body.String())
	}
	list := func(clusterID *uuid.UUID) *httptest.ResponseRecorder {
		t.Helper()
		url := "/api/v1/compliance/evidence/node?framework=" + compliancepkg.FrameworkCISLinux
		if clusterID != nil {
			url += "&cluster_id=" + clusterID.String()
		}
		request := httptest.NewRequest(http.MethodGet, url, nil)
		request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgA}))
		response := httptest.NewRecorder()
		NewCompliance(database, nil).NodeEvidence(response, request)
		return response
	}
	check := func(response *httptest.ResponseRecorder, expected, expectedExemptions map[string]string) {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("evidence status=%d body=%s", response.Code, response.Body.String())
		}
		var result struct {
			Items []struct {
				Target          string `json:"target"`
				EffectiveStatus string `json:"effective_status"`
				Exemption       *struct {
					ID string `json:"id"`
				} `json:"exemption"`
			} `json:"items"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != len(expected) {
			t.Fatalf("evidence rows=%d want=%d: %s", len(result.Items), len(expected), response.Body.String())
		}
		for _, item := range result.Items {
			want, ok := expected[item.Target]
			if !ok || item.EffectiveStatus != want {
				t.Fatalf("unexpected evidence item %+v: %s", item, response.Body.String())
			}
			gotID := ""
			if item.Exemption != nil {
				gotID = item.Exemption.ID
			}
			if gotID != expectedExemptions[item.Target] {
				t.Fatalf("evidence exemption for %s=%q want %q: %s", item.Target, gotID, expectedExemptions[item.Target], response.Body.String())
			}
		}
	}
	check(list(nil), map[string]string{"node-a": "exempted", "node-b": "fail"}, map[string]string{"node-a": scopedID.String()})
	check(list(&clusterB), map[string]string{"node-b": "fail"}, nil)
	if response := list(&foreignCluster); response.Code != http.StatusNotFound {
		t.Fatalf("foreign cluster status=%d body=%s", response.Code, response.Body.String())
	}
	if err := pool.QueryRow(ctx, `INSERT INTO compliance_exemptions (org_id, framework, control_id, reason, expires_at) VALUES ($1, $2, '3.2.1', 'approved org-wide exception', $3) RETURNING id`, orgA, compliancepkg.FrameworkCISLinux, time.Now().Add(24*time.Hour)).Scan(&orgWideID); err != nil {
		t.Fatal(err)
	}
	check(list(nil), map[string]string{"node-a": "exempted", "node-b": "exempted"}, map[string]string{"node-a": scopedID.String(), "node-b": orgWideID.String()})
}
