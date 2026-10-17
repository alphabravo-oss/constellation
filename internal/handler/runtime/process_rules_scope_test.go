package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

func TestProcessRulesClusterScopeAndPreconditions(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	org, user, a, b, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Rule scope')`, id, "rules-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = ANY($1::uuid[])`, []uuid.UUID{org, foreign})
	})
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,org_id,email,display_name,password_hash) VALUES($1,$2,$3,'Rule author','x')`, user, org, user.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	for _, cluster := range []uuid.UUID{a, b} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name,distro,state) VALUES($1,$2,$3,'k3s','connected')`, cluster, org, "cluster-"+cluster.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,first_seen_at,last_seen_at) VALUES($1,$2,$3,'default','api','Deployment',NOW(),NOW())`, uuid.New(), org, cluster); err != nil {
			t.Fatal(err)
		}
	}
	h := NewBaselines(d, audit.New(pool))
	request := func(handler http.HandlerFunc, method, cluster, rule string, body any, subject uuid.UUID) *httptest.ResponseRecorder {
		target := "/api/v1/runtime/baselines/default%2Fapi/rules"
		if cluster != "" {
			target += "?cluster_id=" + cluster
		}
		raw, _ := json.Marshal(body)
		req := baselineRequest(method, target, "default/api", bytes.NewReader(raw), subject, user)
		chi.RouteContext(req.Context()).URLParams.Add("rule_id", rule)
		out := httptest.NewRecorder()
		handler(out, req)
		return out
	}
	created := map[uuid.UUID]processRuleDTO{}
	for _, cluster := range []uuid.UUID{a, b} {
		action := "allow"
		if cluster == b {
			action = "deny"
		}
		out := request(h.CreateRule, http.MethodPost, cluster.String(), "", map[string]any{"name": "nginx", "path": "/usr/sbin/nginx", "action": action, "sha256": "abc", "parent_name": "init", "require_absent": true}, org)
		if out.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", cluster, out.Code, out.Body.String())
		}
		var rule processRuleDTO
		if err := json.Unmarshal(out.Body.Bytes(), &rule); err != nil {
			t.Fatal(err)
		}
		created[cluster] = rule
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='process_profile.rule.upsert' AND after->>'cluster_id' = ANY($2::text[])`, org, []string{a.String(), b.String()}).Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("rule audit lacks exact cluster: count%d err%v", audited, err)
	}
	// Both cluster contexts retain their own match; no source identity substitution.
	out := request(h.ListRules, http.MethodGet, b.String(), "", nil, org)
	if out.Code != http.StatusOK {
		t.Fatal(out.Code, out.Body.String())
	}
	var listed struct {
		Rules []processRuleDTO `json:"rules"`
	}
	_ = json.Unmarshal(out.Body.Bytes(), &listed)
	if len(listed.Rules) != 1 || listed.Rules[0].RuleID != created[b].RuleID || listed.Rules[0].Action != "deny" {
		t.Fatalf("wrong cluster rules: %+v", listed.Rules)
	}
	for _, method := range []struct {
		fn   http.HandlerFunc
		verb string
	}{{h.Get, http.MethodGet}, {h.SetMode, http.MethodPost}, {h.ListRules, http.MethodGet}, {h.CreateRule, http.MethodPost}, {h.UpdateRule, http.MethodPut}, {h.DeleteRule, http.MethodDelete}} {
		t.Run("ambiguous-"+method.verb+"-"+string(rune(len(method.verb))), func(t *testing.T) {
			out := request(method.fn, method.verb, "", created[a].RuleID, map[string]any{"name": "nginx", "mode": "monitor"}, org)
			if out.Code != http.StatusConflict {
				t.Fatalf("ambiguous status=%d %s", out.Code, out.Body.String())
			}
		})
	}
	for _, fn := range []http.HandlerFunc{h.UpdateRule, h.DeleteRule} {
		out := request(fn, http.MethodPut, a.String(), created[b].RuleID, map[string]any{"name": "nginx", "action": "allow"}, org)
		if out.Code != http.StatusNotFound {
			t.Fatalf("foreign rule status=%d %s", out.Code, out.Body.String())
		}
	}
	for _, cluster := range []string{a.String(), "invalid"} {
		out := request(h.CreateRule, http.MethodPost, cluster, "", map[string]any{"name": "foreign"}, foreign)
		expected := http.StatusNotFound
		if cluster == "invalid" {
			expected = http.StatusBadRequest
		}
		if out.Code != expected {
			t.Fatalf("foreign cluster status=%d want%d", out.Code, expected)
		}
	}
	// New authoring never silently overwrites an existing match; legacy upsert stays available.
	out = request(h.CreateRule, http.MethodPost, a.String(), "", map[string]any{"name": "nginx", "path": "/usr/sbin/nginx", "action": "deny", "require_absent": true}, org)
	if out.Code != http.StatusConflict {
		t.Fatalf("require absent=%d %s", out.Code, out.Body.String())
	}
	old := created[a].UpdatedAt
	if _, err := pool.Exec(ctx, `UPDATE process_profile_rules SET updated_at=updated_at+INTERVAL '1 microsecond', description='concurrent change' WHERE id=$1`, created[a].RuleID); err != nil {
		t.Fatal(err)
	}
	out = request(h.UpdateRule, http.MethodPut, a.String(), created[a].RuleID, map[string]any{"name": "nginx", "path": "/usr/sbin/nginx", "action": "deny", "expected_updated_at": old}, org)
	if out.Code != http.StatusConflict {
		t.Fatalf("stale update=%d %s", out.Code, out.Body.String())
	}
	deleteReq := baselineRequest(http.MethodDelete, "/rules?cluster_id="+a.String()+"&expected_updated_at="+old, "default/api", nil, org, user)
	chi.RouteContext(deleteReq.Context()).URLParams.Add("rule_id", created[a].RuleID)
	out = httptest.NewRecorder()
	h.DeleteRule(out, deleteReq)
	if out.Code != http.StatusConflict {
		t.Fatalf("stale delete=%d %s", out.Code, out.Body.String())
	}
	var timestamp time.Time
	var description, action string
	if err := pool.QueryRow(ctx, `SELECT updated_at,description,action FROM process_profile_rules WHERE id=$1`, created[a].RuleID).Scan(&timestamp, &description, &action); err != nil {
		t.Fatal(err)
	}
	if description != "concurrent change" || action != "allow" {
		t.Fatal("stale mutation altered rule")
	}
	out = request(h.UpdateRule, http.MethodPut, a.String(), created[a].RuleID, map[string]any{"name": "nginx", "path": "/usr/sbin/nginx", "action": "deny", "expected_updated_at": timestamp.UTC().Format(time.RFC3339Nano)}, org)
	if out.Code != http.StatusOK {
		t.Fatalf("current update=%d %s", out.Code, out.Body.String())
	}
	// A real database failure is an error, never an empty successful source.
	failedDB := openTestDB(t)
	failedHandler := NewBaselines(failedDB, nil)
	failedDB.Close()
	if rules, err := failedHandler.loadProcessRules(ctx, org, a.String(), "default/api"); err == nil || rules != nil {
		t.Fatal("failed rule source returned successful/partial rows")
	}
}

func TestBaselinesModePreconditionIsAtomic(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	org, user, cluster := uuid.New(), uuid.New(), uuid.New()
	pool := d.Pool()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Mode CAS')`, org, "mode-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org) })
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,org_id,email,display_name,password_hash) VALUES($1,$2,$3,'Author','x')`, user, org, user.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name,distro,state) VALUES($1,$2,'mode-cas','k3s','connected')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,first_seen_at,last_seen_at) VALUES($1,$2,$3,'default','api','Deployment',NOW(),NOW())`, uuid.New(), org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewBaselines(d, audit.New(pool))
	wl := observedWorkload{OrgID: org, ClusterID: cluster.String(), WorkloadID: "default/api", Namespace: "default", Name: "api"}
	if _, err := h.ensureState(ctx, org, wl, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE process_baseline_states SET mode='monitor' WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	req := baselineRequest(http.MethodPost, "/mode?cluster_id="+cluster.String(), "default/api", bytes.NewReader([]byte(`{"mode":"enforce","expected_mode":"learn","reason":"stale review"}`)), org, user)
	h.SetMode(out, req)
	if out.Code != http.StatusConflict {
		t.Fatalf("stale mode=%d %s", out.Code, out.Body.String())
	}
	subject := authctx.Subject{OrgID: org, UserID: user}
	if err := h.persistModeTransition(ctx, subject, wl, baseline.ModeLearn, baseline.ModeMonitor, "raced", time.Now()); !errors.Is(err, errBaselineChanged) {
		t.Fatalf("raced transition=%v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_baseline_transitions WHERE org_id=$1`, org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed transition appended history: count%d err%v", count, err)
	}
	req = baselineRequest(http.MethodPost, "/mode?cluster_id="+cluster.String(), "default/api", bytes.NewReader([]byte(`{"mode":"enforce","expected_mode":"monitor","reason":"current review"}`)), org, user)
	out = httptest.NewRecorder()
	h.SetMode(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("current mode=%d %s", out.Code, out.Body.String())
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='baseline.transition' AND after->>'cluster_id'=$2`, org, cluster.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("mode audit lacks exact cluster: count%d err%v", audited, err)
	}
}
