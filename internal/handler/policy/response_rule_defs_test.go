package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// ensureResponseRuleDefTable provisions the E1 response_rules table for tests, mirroring
// the self-provisioning pattern other policy tests use (ensureResponseRuleTables). It is
// the exact shape of migration 103.
func ensureResponseRuleDefTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS response_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    priority    INTEGER NOT NULL DEFAULT 1000,
    event_type  TEXT NOT NULL,
    conditions  JSONB NOT NULL DEFAULT '[]'::jsonb,
    actions     JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);`); err != nil {
		t.Fatalf("response_rules table: %v", err)
	}
}

func seedOrgUser(t *testing.T, pool *pgxpool.Pool) (orgID, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	orgID = uuid.New()
	userID = uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'RR Def Org')`,
		orgID, "rr-defs-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Op')`,
		userID, orgID, "rr-defs-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	return orgID, userID
}

func withSubj(req *http.Request, org, user uuid.UUID) *http.Request {
	return req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: user, OrgID: org}))
}

func TestResponseRuleDefs_CreateValidatesAndPersists(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRuleDefTable(t, pool)
	orgID, userID := seedOrgUser(t, pool)

	h := NewResponseRuleDefs(d, audit.New(pool))
	r := chi.NewRouter()
	r.Post("/api/v1/response-rule-defs", h.Create)
	r.Get("/api/v1/response-rule-defs", h.List)

	// Invalid: bad op -> 400.
	bad := `{"name":"bad","enabled":true,"event_type":"process","conditions":[{"field":"p","op":"startswith","value":"x"}],"actions":[{"type":"tag"}]}`
	req := withSubj(httptest.NewRequest("POST", "/api/v1/response-rule-defs", strings.NewReader(bad)), orgID, userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid op create = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}

	// Valid.
	good := `{"name":"curl-quarantine","enabled":true,"priority":10,"event_type":"process","conditions":[{"field":"process_name","op":"contains","value":"curl"}],"actions":[{"type":"quarantine"}]}`
	req = withSubj(httptest.NewRequest("POST", "/api/v1/response-rule-defs", strings.NewReader(good)), orgID, userID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid create = %d, want 201 (body=%s)", w.Code, w.Body.String())
	}

	// List reflects it.
	req = withSubj(httptest.NewRequest("GET", "/api/v1/response-rule-defs", nil), orgID, userID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var got struct {
		Rules []responseRuleDefDTO `json:"rules"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Name != "curl-quarantine" || got.Rules[0].Priority != 10 {
		t.Fatalf("list mismatch: %+v", got.Rules)
	}
}

// TestResponseRuleDefs_WebhookReceiverValidation asserts RSP-WEBHOOK-04's save-time check:
// a webhook action whose receiver does not exist for the org is rejected (400), and one
// naming a real receiver is accepted (201). This exercises resolveReceiverID/validateReceivers
// — the same resolution fireWebhook uses to route (DispatchTo) instead of broadcast.
func TestResponseRuleDefs_WebhookReceiverValidation(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRuleDefTable(t, pool)
	orgID, userID := seedOrgUser(t, pool)

	h := NewResponseRuleDefs(d, audit.New(pool))
	r := chi.NewRouter()
	r.Post("/api/v1/response-rule-defs", h.Create)

	// Unknown receiver -> 400.
	unknown := `{"name":"wh-unknown","enabled":true,"event_type":"process","conditions":[],"actions":[{"type":"webhook","params":{"receiver":"no-such-receiver"}}]}`
	req := withSubj(httptest.NewRequest("POST", "/api/v1/response-rule-defs", strings.NewReader(unknown)), orgID, userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown-receiver create = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}

	// Seed a receiver, then reference it by name -> 201.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO receivers (org_id, name, kind, endpoint) VALUES ($1,'pagerduty-oncall','webhook','https://example.test/hook')`,
		orgID); err != nil {
		t.Fatalf("seed receiver: %v", err)
	}
	good := `{"name":"wh-ok","enabled":true,"event_type":"process","conditions":[],"actions":[{"type":"webhook","params":{"receiver":"pagerduty-oncall"}}]}`
	req = withSubj(httptest.NewRequest("POST", "/api/v1/response-rule-defs", strings.NewReader(good)), orgID, userID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid webhook create = %d, want 201 (body=%s)", w.Code, w.Body.String())
	}
}

func TestResponseRuleDefs_AgentSyncSerializesEnabledByPriority(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRuleDefTable(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	ctx := context.Background()

	insert := func(name string, enabled bool, prio int) {
		if _, err := pool.Exec(ctx, `
INSERT INTO response_rules (org_id, name, enabled, priority, event_type, conditions, actions)
VALUES ($1,$2,$3,$4,'process','[]'::jsonb,'[{"type":"tag"}]'::jsonb)`,
			orgID, name, enabled, prio); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}
	insert("third", true, 300)
	insert("first", true, 10)
	insert("second", true, 100)
	insert("disabled", false, 1)
	_ = userID

	h := NewResponseRuleDefs(d, audit.New(pool))
	// Agent sync requires a runtime-agent token on the context (not a user subject).
	req := httptest.NewRequest("GET", "/api/v1/runtime/response-rules:sync", nil)
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), &handler.RuntimeAgentToken{ID: uuid.New(), OrgID: orgID, Name: "agent"}))
	w := httptest.NewRecorder()
	h.AgentSyncBundle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sync = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var bundle struct {
		GeneratedAt string               `json:"generated_at"`
		Rules       []responseRuleDefDTO `json:"rules"`
	}
	if err := json.NewDecoder(w.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bundle.GeneratedAt == "" {
		t.Fatal("sync bundle missing generated_at")
	}
	want := []string{"first", "second", "third"} // disabled excluded, priority-ordered
	if len(bundle.Rules) != len(want) {
		t.Fatalf("sync rules = %d, want %d (%+v)", len(bundle.Rules), len(want), bundle.Rules)
	}
	for i, n := range want {
		if bundle.Rules[i].Name != n {
			t.Fatalf("sync order pos %d = %q, want %q", i, bundle.Rules[i].Name, n)
		}
	}
}

// TestResponseRuleDefs_CrossOrgIsolation seeds two orgs each with their own rules and
// asserts org B's runtime-agent token only ever sees org B's rules via the :sync bundle,
// and likewise that a user-scoped List for org B never leaks org A's rules. This guards
// the cross-org isolation the loadRules WHERE org_id=$1 filter provides.
func TestResponseRuleDefs_CrossOrgIsolation(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRuleDefTable(t, pool)
	ctx := context.Background()

	orgA, _ := seedOrgUser(t, pool)
	orgB, userB := seedOrgUser(t, pool)

	insert := func(org uuid.UUID, name string) {
		if _, err := pool.Exec(ctx, `
INSERT INTO response_rules (org_id, name, enabled, priority, event_type, conditions, actions)
VALUES ($1,$2,true,10,'process','[]'::jsonb,'[{"type":"tag"}]'::jsonb)`, org, name); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}
	insert(orgA, "org-a-rule")
	insert(orgB, "org-b-rule")

	h := NewResponseRuleDefs(d, audit.New(pool))

	// Agent :sync with org B's token returns ONLY org B's rule.
	req := httptest.NewRequest("GET", "/api/v1/runtime/response-rules:sync", nil)
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), &handler.RuntimeAgentToken{ID: uuid.New(), OrgID: orgB, Name: "agent-b"}))
	w := httptest.NewRecorder()
	h.AgentSyncBundle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sync = %d (body=%s)", w.Code, w.Body.String())
	}
	var bundle struct {
		Rules []responseRuleDefDTO `json:"rules"`
	}
	if err := json.NewDecoder(w.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(bundle.Rules) != 1 || bundle.Rules[0].Name != "org-b-rule" {
		t.Fatalf("sync leaked across orgs: %+v", bundle.Rules)
	}

	// User-scoped List for org B returns ONLY org B's rule.
	req = withSubj(httptest.NewRequest("GET", "/api/v1/response-rule-defs", nil), orgB, userB)
	w = httptest.NewRecorder()
	h.List(w, req)
	var listed struct {
		Rules []responseRuleDefDTO `json:"rules"`
	}
	if err := json.NewDecoder(w.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Rules) != 1 || listed.Rules[0].Name != "org-b-rule" {
		t.Fatalf("list leaked across orgs: %+v", listed.Rules)
	}
}

func TestResponseRuleDefs_AgentSyncRequiresAgentToken(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	h := NewResponseRuleDefs(d, audit.New(d.Pool()))
	w := httptest.NewRecorder()
	// No runtime-agent token on the context -> 401.
	h.AgentSyncBundle(w, httptest.NewRequest("GET", "/api/v1/runtime/response-rules:sync", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing agent token = %d, want 401", w.Code)
	}
}

func TestResponseRuleDefs_EvaluateReturnsOrderedActions(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRuleDefTable(t, pool)
	orgID, _ := seedOrgUser(t, pool)
	ctx := context.Background()

	// Two enabled matching rules + one disabled + one non-matching.
	if _, err := pool.Exec(ctx, `
INSERT INTO response_rules (org_id, name, enabled, priority, event_type, conditions, actions) VALUES
 ($1,'p10', true, 10,  'process', '[{"field":"process_name","op":"contains","value":"curl"}]'::jsonb, '[{"type":"quarantine"}]'::jsonb),
 ($1,'p50', true, 50,  'process', '[]'::jsonb, '[{"type":"suppress_log"}]'::jsonb),
 ($1,'off', false, 1,  'process', '[]'::jsonb, '[{"type":"quarantine"}]'::jsonb),
 ($1,'miss',true, 5,   'process', '[{"field":"process_name","op":"eq","value":"/bin/sh"}]'::jsonb, '[{"type":"tag"}]'::jsonb)`,
		orgID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := NewResponseRuleDefs(d, audit.New(pool)) // nil dispatcher: webhook delivery is a no-op
	ev := &responserule.Event{Type: responserule.EventProcess, Fields: map[string]string{"process_name": "/usr/bin/curl"}}
	actions, err := h.Evaluate(ctx, orgID, ev)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(actions) != 2 ||
		actions[0].Type != responserule.ActionQuarantine ||
		actions[1].Type != responserule.ActionSuppressLog {
		t.Fatalf("Evaluate actions = %+v, want [quarantine, suppress_log] in priority order", actions)
	}
}

// TestResponseRuleDefs_RBAC403 asserts the manage-response-rules gate: a caller WITHOUT
// the verb is forbidden, a ClusterAdmin (which carries it) is allowed. The wrapper mirrors
// server.requireVerb's authorization decision exactly.
func TestResponseRuleDefs_RBAC403(t *testing.T) {
	org := uuid.New()
	gate := func(verb rbac.Verb, asg []rbac.RoleAssignment, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := rbac.Authorize(asg, verb, rbac.Resource{OrgID: org}); err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}
	called := false
	next := func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) }

	// Auditor lacks manage-response-rules -> 403, handler not reached.
	auditor := []rbac.RoleAssignment{{Role: rbac.RoleAuditor, Scope: rbac.Scope{OrgID: org}}}
	w := httptest.NewRecorder()
	gate(rbac.VerbManageResponseRules, auditor, next)(w, httptest.NewRequest("POST", "/api/v1/response-rule-defs", nil))
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("auditor: code=%d called=%v, want 403 and not called", w.Code, called)
	}

	// ClusterAdmin carries manage-response-rules -> passes.
	called = false
	admin := []rbac.RoleAssignment{{Role: rbac.RoleClusterAdmin, Scope: rbac.Scope{OrgID: org}}}
	w = httptest.NewRecorder()
	gate(rbac.VerbManageResponseRules, admin, next)(w, httptest.NewRequest("POST", "/api/v1/response-rule-defs", nil))
	if w.Code != http.StatusOK || !called {
		t.Fatalf("clusteradmin: code=%d called=%v, want 200 and called", w.Code, called)
	}
}
