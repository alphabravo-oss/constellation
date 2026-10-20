package handler

import (
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/inventorypresence"
)

func TestDeploymentPresenceListCSVAndDashboardParity(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org, cluster := uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'presence')`, org, org.String())
	defer func() { _, _ = d.Pool().Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org) }()
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'presence')`, cluster, org)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,critical_count,risk_score,last_seen_at) SELECT $1,$2,'apps',name,'Deployment',1,80,NOW()-INTERVAL '1 minute' FROM unnest(ARRAY['live','zero','gone']) name`, org, cluster)
	now := time.Now().UTC()
	if err := inventorypresence.StoreWorkloads(ctx, d.Pool(), org, cluster, now, now.Add(time.Hour), map[string]string{"apps/Deployment/live": "present", "apps/Deployment/zero": "scaled_to_zero"}); err != nil {
		t.Fatal(err)
	}
	h := NewDeployments(d, nil)
	for _, tc := range []struct {
		scope string
		total int
	}{{"", 2}, {"all", 3}, {"absent", 1}, {"scaled_to_zero", 1}, {"unverified", 0}} {
		req := httptest.NewRequest("GET", "/?cluster_id="+cluster.String()+"&presence="+tc.scope, nil)
		req = req.WithContext(WithSubject(ctx, Subject{OrgID: org}))
		w := httptest.NewRecorder()
		h.List(w, req)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var list struct {
			Total       int
			Deployments []deploymentListRow
		}
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if list.Total != tc.total {
			t.Fatalf("%s total %d want %d", tc.scope, list.Total, tc.total)
		}
		csvResponse := httptest.NewRecorder()
		h.ExportCSV(csvResponse, req)
		if csvResponse.Code != 200 {
			t.Fatal(csvResponse.Body.String())
		}
		rows, err := csv.NewReader(csvResponse.Body).ReadAll()
		if err != nil || len(rows) != tc.total+1 {
			t.Fatal("CSV mismatch", len(rows), err)
		}
	}
	req := httptest.NewRequest("GET", "/?cluster_id="+cluster.String(), nil)
	req = req.WithContext(WithSubject(ctx, Subject{OrgID: org}))
	w := httptest.NewRecorder()
	NewDashboard(d).Summary(w, req)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var summary dashboardSummaryDTO
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Posture.Hardening["workloads"] != 2 || len(summary.Posture.TopVulnerable) != 2 {
		t.Fatalf("dashboard includes absent: %+v", summary.Posture)
	}
	seenZero := false
	for _, row := range summary.Posture.TopVulnerable {
		if row.Name == "gone" {
			t.Fatal("absent top workload")
		}
		if row.Name == "zero" && row.InventoryPresence == "scaled_to_zero" {
			seenZero = true
		}
	}
	if !seenZero {
		t.Fatal("zero replicas lost")
	}
	exec(`UPDATE cluster_workload_presence SET observed_at=NOW()-INTERVAL '2 hours',expires_at=NOW()-INTERVAL '1 hour' WHERE org_id=$1`, org)
	w = httptest.NewRecorder()
	h.List(w, req)
	var stale struct{ Total int }
	if err := json.Unmarshal(w.Body.Bytes(), &stale); err != nil {
		t.Fatal(err)
	}
	if stale.Total != 3 {
		t.Fatal("stale snapshot still hid inventory")
	}
}
