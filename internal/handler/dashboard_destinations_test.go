package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/findings"
	"github.com/google/uuid"
)

func TestDashboardFixableDestinationAndWorkloadIdentity(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx, pool := t.Context(), d.Pool()
	org, foreign, cluster, sibling, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "dashboard-destinations-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreign) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$3,'selected'),($2,$3,'sibling')`, cluster, sibling, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,kind,name) VALUES($1,$2,'image','fixture')`, asset, org); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"fixed":"1.2"}`, `{"fixed_version":"2.3"}`, `{"affected_range":{"fixed_version":"3.4"}}`, `{"fixed":"","fixed_version":"4.5"}`,
		`{}`, `{"fixed":"FALSE"}`, `{"fixed":"not-fixed"}`, `{"fixed":"WONT-FIX"}`, `{"fixed":"won't-fix"}`, `{"fixed":"false","fixed_version":"9.9"}`,
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,asset_id,cluster_id,kind,title,severity,lifecycle,target_type,detail_json) VALUES($1,$2,$3,'vulnerability','fixability','high','open','image-workload',$4::jsonb)`, org, asset, cluster, raw); err != nil {
			t.Fatal(err)
		}
	}
	// Resolved, rolled-up workload, sibling-cluster and foreign-tenant findings
	// must not inflate the linked open vulnerability instance cohort.
	if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,asset_id,cluster_id,kind,title,severity,lifecycle,target_type,detail_json) VALUES
	 ($1,$2,$3,'vulnerability','resolved','high','resolved','image-workload','{"fixed":"1"}'),
	 ($1,$2,$3,'vulnerability','rollup','high','open','workload','{"fixed":"1"}'),
	 ($1,$2,$4,'vulnerability','sibling','high','open','image-workload','{"fixed":"1"}'),
	 ($5,$2,$3,'vulnerability','foreign','high','open','image-workload','{"fixed":"1"}')`, org, asset, cluster, sibling, foreign); err != nil {
		t.Fatal(err)
	}
	selectedID, siblingID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,critical_count,high_count) VALUES
	 ($1,$3,$4,'payments','same-name','Deployment',2,3),
	 ($2,$3,$5,'payments','same-name','Deployment',90,90)`, selectedID, siblingID, org, cluster, sibling); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE deployments SET labels='{"helm.sh/chart":"constellation-1"}'::jsonb WHERE id=$1`, selectedID); err != nil {
		t.Fatal(err)
	}
	request := func(path string) *http.Request {
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		return r.WithContext(WithSubject(r.Context(), Subject{OrgID: org}))
	}
	w := httptest.NewRecorder()
	NewDashboard(d).Summary(w, request("/api/v1/dashboard/summary?cluster_id="+cluster.String()))
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard: %d %s", w.Code, w.Body.String())
	}
	var summary dashboardSummaryDTO
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Posture.VulnSignals["fixable"] != 4 {
		t.Fatalf("fixable=%d, want 4", summary.Posture.VulnSignals["fixable"])
	}
	if len(summary.Posture.TopVulnerable) != 1 || summary.Posture.TopVulnerable[0].ID != selectedID.String() || summary.Posture.TopVulnerable[0].ClusterID == nil || *summary.Posture.TopVulnerable[0].ClusterID != cluster || summary.Posture.TopVulnerable[0].PlatformRole != "core" {
		t.Fatalf("wrong workload identity: %+v", summary.Posture.TopVulnerable)
	}
	w = httptest.NewRecorder()
	findings.NewFindings(d, nil, nil).List(w, request("/api/v1/findings?kind=vulnerability&lifecycle=open&fixable=true&cluster_id="+cluster.String()))
	if w.Code != http.StatusOK {
		t.Fatalf("destination: %d %s", w.Code, w.Body.String())
	}
	var destination struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &destination); err != nil {
		t.Fatal(err)
	}
	if destination.Total != summary.Posture.VulnSignals["fixable"] {
		t.Fatalf("destination=%d, dashboard=%d", destination.Total, summary.Posture.VulnSignals["fixable"])
	}
}
