package runtime

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/google/uuid"
)

func TestRuntimePolicyManagementInventoryIncludesDisabledButAgentDoesNot(t *testing.T) {
	f := reviewedFixture(t)
	pool := f.h.store.db.Pool()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_policies(org_id,cluster_id,workload,namespace,name,mode) VALUES($1,$2,'app/disabled','app','disabled','disabled'),($1,$2,'app/enforced','app','enforced','enforce'),($1,$3,'app/sibling','app','sibling','disabled'),($4,$5,'app/foreign','app','foreign','disabled')`, f.org, f.cluster, f.sibling, f.foreignOrg, f.foreignCluster); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/runtime-policies?cluster_id="+f.cluster.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: f.org, UserID: f.actor}))
	res := httptest.NewRecorder()
	f.h.List(res, req)
	var result struct {
		Policies []*RuntimePolicy `json:"policies"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if res.Code != 200 || len(result.Policies) != 3 {
		t.Fatalf("management%d %s", res.Code, res.Body.String())
	}
	modes := map[PolicyMode]int{}
	for _, p := range result.Policies {
		modes[p.Mode]++
		if p.ClusterID != f.cluster || p.OrgID != f.org || p.Revision != "1" {
			t.Fatalf("scope/revision %+v", p)
		}
	}
	if modes[PolicyModeDisabled] != 1 || modes[PolicyModeMonitor] != 1 || modes[PolicyModeEnforce] != 1 {
		t.Fatalf("missing management modes %+v", modes)
	}
	agent, err := f.h.store.ListForCluster(ctx, f.org, f.cluster)
	if err != nil || len(agent) != 2 {
		t.Fatalf("agent%d %v", len(agent), err)
	}
	for _, p := range agent {
		if p.Mode == PolicyModeDisabled {
			t.Fatal("disabled policy distributed to agent")
		}
	}
	// Disabling an existing management row must leave it discoverable and editable.
	disabled := f.request(f.id, f.org, "disable", map[string]any{"cluster_id": f.cluster, "expected_version": "1"})
	if disabled.Code != 200 {
		t.Fatalf("disable%d %s", disabled.Code, disabled.Body.String())
	}
	res = httptest.NewRecorder()
	f.h.List(res, req)
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range result.Policies {
		if p.ID == f.id {
			found = true
			if p.Mode != PolicyModeDisabled || p.Revision != "2" {
				t.Fatalf("disabled receipt %+v", p)
			}
		}
	}
	if !found {
		t.Fatal("disabled policy disappeared from management inventory")
	}
	agent, err = f.h.store.ListForCluster(ctx, f.org, f.cluster)
	if err != nil || len(agent) != 1 || agent[0].Mode != PolicyModeEnforce {
		t.Fatalf("agent afterdisable %+v %v", agent, err)
	}
	for _, cluster := range []uuid.UUID{f.foreignCluster, uuid.New()} {
		r := httptest.NewRequestWithContext(t.Context(), "GET", "/runtime-policies?cluster_id="+cluster.String(), nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: f.org}))
		w := httptest.NewRecorder()
		f.h.List(w, r)
		if w.Code != 404 {
			t.Fatalf("unknown scope%d %s", w.Code, w.Body.String())
		}
	}
}
