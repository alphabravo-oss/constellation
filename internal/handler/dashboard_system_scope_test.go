//go:build integration

package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/findings"
)

func TestDashboardFindingScopeMatchesDestinations(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org, cluster, system, app := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'dashboard scope')`, org, org.String())
	defer func() {
		_, _ = d.Pool().Exec(ctx, `DELETE FROM findings WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	}()
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'scope')`, cluster, org)
	exec(`INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels,critical_count) VALUES
 ($1,$3,$4,'constellation-system','api','Deployment','{"app.kubernetes.io/name":"constellation","app.kubernetes.io/part-of":"constellation","app.kubernetes.io/managed-by":"Helm","helm.sh/chart":"constellation-0.2.0"}',3),
 ($2,$3,$4,'constellation-system','customer','Deployment','{}',2)`, system, app, org, cluster)
	exec(`INSERT INTO groups(org_id,cluster_id,name,kind,policy_mode,members) VALUES($1,$2,'all','ground','monitor','["constellation-system/api","constellation-system/customer"]')`, org, cluster)
	for _, link := range []struct {
		id        uuid.UUID
		name, ref string
	}{{system, "api", "sha256:system"}, {system, "api", "sha256:shared"}, {app, "customer", "sha256:shared"}, {app, "customer", "sha256:app"}} {
		exec(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_digest) VALUES($1,$2,$3,'constellation-system/'||$4,'constellation-system',$4,'Deployment',$5,$5,$5)`, org, cluster, link.id, link.name, link.ref)
	}
	for _, ref := range []string{"sha256:system", "sha256:shared", "sha256:app", "sha256:unknown"} {
		exec(`INSERT INTO findings(org_id,cluster_id,asset_id,kind,title,external_id,severity,lifecycle,target_type,target_ref,detail_json) VALUES($1,$2,$3,'vulnerability','scope',$4,'high','open','image-workload',$4,'{"fixed":"2.0"}')`, org, cluster, uuid.New(), ref)
	}
	for _, tc := range []struct {
		scope               string
		total, monitor, top int
	}{{"application", 3, 2, 1}, {"constellation", 1, 1, 1}, {"all", 4, 3, 2}, {"", 4, 3, 2}} {
		t.Run(tc.scope, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/?cluster_id="+cluster.String()+"&workload_scope="+tc.scope, nil)
			req = req.WithContext(WithSubject(ctx, Subject{OrgID: org}))
			w := httptest.NewRecorder()
			NewDashboard(d).Summary(w, req)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var summary dashboardSummaryDTO
			if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
				t.Fatal(err)
			}
			if summary.OpenFindings != tc.total || summary.FindingsByLevel["high"] != tc.total || summary.Posture.VulnsByLocation["image"] != tc.total || summary.Posture.VulnSignals["fixable"] != tc.total || summary.Posture.CvesByMode["monitor"] != tc.monitor || len(summary.Posture.TopVulnerable) != tc.top {
				t.Fatalf("wrong scope: %+v", summary)
			}
			if summary.Posture.Hardening["workloads"] != 2 || summary.Posture.Enforcement["groups"] != 1 {
				t.Fatal("cluster context was hidden")
			}
			dest := httptest.NewRecorder()
			findings.NewFindings(d, nil, nil).List(dest, req)
			if dest.Code != 200 {
				t.Fatal(dest.Body.String())
			}
			var list struct {
				Total int `json:"total"`
			}
			if err := json.Unmarshal(dest.Body.Bytes(), &list); err != nil {
				t.Fatal(err)
			}
			if list.Total != summary.OpenFindings {
				t.Fatalf("destination %d != tile %d", list.Total, summary.OpenFindings)
			}
		})
	}
	req := httptest.NewRequest("GET", "/?workload_scope=invalid", nil)
	req = req.WithContext(WithSubject(ctx, Subject{OrgID: org}))
	w := httptest.NewRecorder()
	NewDashboard(d).Summary(w, req)
	if w.Code != 400 {
		t.Fatal("invalid scope accepted")
	}
}
