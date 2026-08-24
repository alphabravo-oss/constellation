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

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/response"
)

func ensureResponseRulesV2Table(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS response_rules_v2 (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    event_type      TEXT NOT NULL,
    conditions      JSONB NOT NULL DEFAULT '[]'::jsonb,
    actions         JSONB NOT NULL DEFAULT '[]'::jsonb,
    workload_match  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);`); err != nil {
		t.Fatalf("response_rules_v2 table: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
ALTER TABLE response_rules_v2 ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE SET NULL;
ALTER TABLE response_rules_v2 ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 1000;
CREATE INDEX IF NOT EXISTS idx_response_rules_v2_org_priority ON response_rules_v2(org_id, priority);`); err != nil {
		t.Fatalf("response_rules_v2 migrations: %v", err)
	}
}

func ensureResponseRulesV2ReceiversTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS receivers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,
    endpoint        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    supported_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);`); err != nil {
		t.Fatalf("receivers table: %v", err)
	}
}

func seedResponseRuleV2Cluster(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	clusterID := uuid.New()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, $3, 'connected')`,
		clusterID, orgID, name); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	return clusterID
}

func insertResponseRuleV2(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, clusterID any, name string, priority int) uuid.UUID {
	t.Helper()
	conditions, _ := json.Marshal([]response.Condition{{Type: response.CondLevel, Value: "high"}})
	actions, _ := json.Marshal([]response.Action{{Kind: response.ActionQuarantine}})
	selector, _ := json.Marshal(response.WorkloadSelector{})
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), `
INSERT INTO response_rules_v2 (org_id, cluster_id, name, description, enabled, priority, event_type, conditions, actions, workload_match)
VALUES ($1, $2, $3, '', true, $4, 'runtime', $5, $6, $7)
RETURNING id`, orgID, clusterID, name, priority, conditions, actions, selector).Scan(&id); err != nil {
		t.Fatalf("insert response rule %s: %v", name, err)
	}
	return id
}

func responseRuleV2Router(d *db.DB, pool *pgxpool.Pool) *chi.Mux {
	r := chi.NewRouter()
	h := NewResponseRulesV2(d, audit.New(pool))
	r.Get("/api/v1/response-rules-v2", h.List)
	r.Get("/api/v1/response-rules-v2/options", h.Options)
	r.Post("/api/v1/response-rules-v2", h.Create)
	r.Patch("/api/v1/response-rules-v2:reorder", h.Reorder)
	return r
}

func listResponseRulesV2(t *testing.T, r http.Handler, orgID, userID, clusterID uuid.UUID) []responseRuleV2DTO {
	t.Helper()
	req := withSubj(httptest.NewRequest(http.MethodGet, "/api/v1/response-rules-v2?cluster_id="+clusterID.String(), nil), orgID, userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Rules []responseRuleV2DTO `json:"rules"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return got.Rules
}

func TestResponseRulesV2_ReorderIsScopedAndDrivesListOrder(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	clusterA := seedResponseRuleV2Cluster(t, pool, orgID, "rrv2-a")
	clusterB := seedResponseRuleV2Cluster(t, pool, orgID, "rrv2-b")

	globalID := insertResponseRuleV2(t, pool, orgID, nil, "global", 10)
	clusterAID := insertResponseRuleV2(t, pool, orgID, clusterA, "cluster-a", 20)
	clusterBID := insertResponseRuleV2(t, pool, orgID, clusterB, "cluster-b", 900)
	router := responseRuleV2Router(d, pool)

	before := listResponseRulesV2(t, router, orgID, userID, clusterA)
	if len(before) != 2 || before[0].ID != globalID || before[1].ID != clusterAID {
		t.Fatalf("initial cluster-a order = %+v", before)
	}

	req := withSubj(httptest.NewRequest(http.MethodPatch, "/api/v1/response-rules-v2:reorder?cluster_id="+clusterA.String(),
		strings.NewReader(`{"ordered_ids":["`+clusterAID.String()+`","`+globalID.String()+`"]}`)), orgID, userID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("reorder status=%d body=%s", w.Code, w.Body.String())
	}
	after := listResponseRulesV2(t, router, orgID, userID, clusterA)
	if len(after) != 2 || after[0].ID != clusterAID || after[0].Priority != 10 || after[1].ID != globalID || after[1].Priority != 20 {
		t.Fatalf("reordered cluster-a order = %+v", after)
	}

	createBody := `{"name":"cluster-a-new","description":"","enabled":true,"event_type":"runtime","conditions":[{"type":"level","value":"high"}],"actions":[{"kind":"quarantine"}],"workload_match":{}}`
	req = withSubj(httptest.NewRequest(http.MethodPost, "/api/v1/response-rules-v2?cluster_id="+clusterA.String(), strings.NewReader(createBody)), orgID, userID)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	afterCreate := listResponseRulesV2(t, router, orgID, userID, clusterA)
	if len(afterCreate) != 3 || afterCreate[2].Name != "cluster-a-new" || afterCreate[2].Priority != 30 {
		t.Fatalf("new rule should append after visible cluster-a scope, got %+v", afterCreate)
	}
	var clusterBPriority int
	if err := pool.QueryRow(context.Background(), `SELECT priority FROM response_rules_v2 WHERE id=$1`, clusterBID).Scan(&clusterBPriority); err != nil {
		t.Fatal(err)
	}
	if clusterBPriority != 900 {
		t.Fatalf("cluster-b priority changed to %d", clusterBPriority)
	}
}

func TestResponseRulesV2_ReorderRejectsPartialDuplicateAndOutOfScopeIDs(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	clusterA := seedResponseRuleV2Cluster(t, pool, orgID, "rrv2-guard-a")
	clusterB := seedResponseRuleV2Cluster(t, pool, orgID, "rrv2-guard-b")

	globalID := insertResponseRuleV2(t, pool, orgID, nil, "guard-global", 10)
	clusterAID := insertResponseRuleV2(t, pool, orgID, clusterA, "guard-cluster-a", 20)
	clusterBID := insertResponseRuleV2(t, pool, orgID, clusterB, "guard-cluster-b", 30)
	router := responseRuleV2Router(d, pool)

	cases := []struct {
		name string
		body string
	}{
		{"partial", `{"ordered_ids":["` + clusterAID.String() + `"]}`},
		{"duplicate", `{"ordered_ids":["` + clusterAID.String() + `","` + clusterAID.String() + `"]}`},
		{"out-of-scope", `{"ordered_ids":["` + globalID.String() + `","` + clusterBID.String() + `"]}`},
	}
	for _, tc := range cases {
		req := withSubj(httptest.NewRequest(http.MethodPatch, "/api/v1/response-rules-v2:reorder?cluster_id="+clusterA.String(), strings.NewReader(tc.body)), orgID, userID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s reorder status=%d body=%s", tc.name, w.Code, w.Body.String())
		}
	}

	got := listResponseRulesV2(t, router, orgID, userID, clusterA)
	if len(got) != 2 || got[0].ID != globalID || got[0].Priority != 10 || got[1].ID != clusterAID || got[1].Priority != 20 {
		t.Fatalf("invalid reorders should not change priorities, got %+v", got)
	}
}

func TestResponseRulesV2_OptionsExposeNVEventCatalogAndReceivers(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	ensureResponseRulesV2ReceiversTable(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO receivers (org_id, name, kind, endpoint, status) VALUES
($1, 'sec-webhook', 'webhook', 'https://example.test/hook', 'healthy'),
($1, 'jira-sec', 'jira', 'https://example.test/jira', 'healthy')`,
		orgID); err != nil {
		t.Fatalf("receivers: %v", err)
	}
	router := responseRuleV2Router(d, pool)
	req := withSubj(httptest.NewRequest(http.MethodGet, "/api/v1/response-rules-v2/options", nil), orgID, userID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("options status=%d body=%s", w.Code, w.Body.String())
	}
	var got responseRuleV2OptionsDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	hasEvent := func(id string) bool {
		for _, ev := range got.EventTypes {
			if ev.ID == id {
				return true
			}
		}
		return false
	}
	for _, id := range []string{"security-event", "threat", "cve-report", "admission-control", "runtime"} {
		if !hasEvent(id) {
			t.Fatalf("event type %q missing from options: %+v", id, got.EventTypes)
		}
	}
	hasAction := func(id string) bool {
		for _, ak := range got.ActionKinds {
			if ak.ID == id {
				return true
			}
		}
		return false
	}
	if !hasAction("suppress-log") {
		t.Fatalf("suppress-log action missing from options: %+v", got.ActionKinds)
	}
	if len(got.Receivers) != 2 {
		t.Fatalf("receivers = %+v", got.Receivers)
	}
	if len(got.Webhooks) != 1 || got.Webhooks[0] != "sec-webhook" {
		t.Fatalf("webhooks = %+v", got.Webhooks)
	}
	if opts, ok := got.ResponseRuleOptions["security-event"]; !ok || len(opts.Types) == 0 {
		t.Fatalf("NV-compatible security-event options missing: %+v", got.ResponseRuleOptions)
	}
}

func TestResponseRulesV2_CreateAcceptsNVEventAndWebhookAction(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	router := responseRuleV2Router(d, pool)
	body := `{"name":"nv-threat-webhook","description":"","enabled":true,"event_type":"threat","conditions":[{"type":"level","value":"high"}],"actions":[{"kind":"webhook","target":"sec-webhook"}],"workload_match":{}}`
	req := withSubj(httptest.NewRequest(http.MethodPost, "/api/v1/response-rules-v2", strings.NewReader(body)), orgID, userID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var savedEventType string
	var savedActions []byte
	if err := pool.QueryRow(context.Background(), `SELECT event_type, actions FROM response_rules_v2 WHERE org_id=$1 AND name='nv-threat-webhook'`, orgID).Scan(&savedEventType, &savedActions); err != nil {
		t.Fatal(err)
	}
	if savedEventType != "threat" || !strings.Contains(string(savedActions), `"webhook"`) {
		t.Fatalf("saved event/action = %q %s", savedEventType, string(savedActions))
	}
}

func TestResponseRulesV2_CreateAcceptsSuppressLogAction(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	router := responseRuleV2Router(d, pool)

	body := `{"name":"nv-threat-suppress","description":"","enabled":true,"event_type":"threat","conditions":[{"type":"level","value":"high"}],"actions":[{"kind":"suppress-log"}],"workload_match":{}}`
	req := withSubj(httptest.NewRequest(http.MethodPost, "/api/v1/response-rules-v2", strings.NewReader(body)), orgID, userID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var savedActions []byte
	if err := pool.QueryRow(context.Background(), `SELECT actions FROM response_rules_v2 WHERE org_id=$1 AND name='nv-threat-suppress'`, orgID).Scan(&savedActions); err != nil {
		t.Fatalf("saved suppress-log rule: %v", err)
	}
	if !strings.Contains(string(savedActions), `"suppress-log"`) {
		t.Fatalf("saved actions = %s", string(savedActions))
	}
}

func TestResponseRulesV2_CreatePreservesGroupSelector(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	router := responseRuleV2Router(d, pool)

	body := `{"name":"nv-threat-group","description":"","enabled":true,"event_type":"threat","conditions":[{"type":"level","value":"high"}],"actions":[{"kind":"suppress-log"}],"workload_match":{"group":"nv.api","namespace":"prod"}}`
	req := withSubj(httptest.NewRequest(http.MethodPost, "/api/v1/response-rules-v2", strings.NewReader(body)), orgID, userID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var savedSelector []byte
	if err := pool.QueryRow(context.Background(), `SELECT workload_match FROM response_rules_v2 WHERE org_id=$1 AND name='nv-threat-group'`, orgID).Scan(&savedSelector); err != nil {
		t.Fatalf("saved group selector rule: %v", err)
	}
	var selector response.WorkloadSelector
	if err := json.Unmarshal(savedSelector, &selector); err != nil {
		t.Fatalf("decode selector: %v", err)
	}
	if selector.Group != "nv.api" || selector.Namespace != "prod" {
		t.Fatalf("selector = %+v", selector)
	}
}
