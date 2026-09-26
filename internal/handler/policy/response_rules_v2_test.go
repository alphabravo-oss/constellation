package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	r.Put("/api/v1/response-rules-v2/{id}", h.Update)
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

func TestResponseRulesV2_ReorderAuditCompletionIsAtomic(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	clusterID := seedResponseRuleV2Cluster(t, pool, orgID, "rrv2-audit")
	firstID := insertResponseRuleV2(t, pool, orgID, clusterID, "audit-first", 10)
	secondID := insertResponseRuleV2(t, pool, orgID, clusterID, "audit-second", 20)
	path := "/api/v1/response-rules-v2:reorder?cluster_id=" + clusterID.String()
	body := `{"ordered_ids":["` + secondID.String() + `","` + firstID.String() + `"]}`
	request := func(handler *ResponseRulesV2) *httptest.ResponseRecorder {
		t.Helper()
		request := withSubj(httptest.NewRequest(http.MethodPatch, path, strings.NewReader(body)), orgID, userID)
		response := httptest.NewRecorder()
		handler.Reorder(response, request)
		return response
	}
	if response := request(NewResponseRulesV2(d, nil)); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing audit status=%d body=%s", response.Code, response.Body.String())
	}
	const constraint = "test_response_reorder_audit_guard"
	statement := fmt.Sprintf(`ALTER TABLE audit_events ADD CONSTRAINT %s CHECK (NOT (org_id='%s' AND action='response_rule_v2.reorder')) NOT VALID`, constraint, orgID)
	if _, err := pool.Exec(context.Background(), statement); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS `+constraint)
	})
	if response := request(NewResponseRulesV2(d, audit.New(pool))); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed completion status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := pool.Exec(context.Background(), `ALTER TABLE audit_events DROP CONSTRAINT `+constraint); err != nil {
		t.Fatal(err)
	}
	var firstPriority, secondPriority, attempts, completions int
	if err := pool.QueryRow(context.Background(), `SELECT priority FROM response_rules_v2 WHERE id=$1`, firstID).Scan(&firstPriority); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT priority FROM response_rules_v2 WHERE id=$1`, secondID).Scan(&secondPriority); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE action='response_rule_v2.reorder_attempt'), count(*) FILTER (WHERE action='response_rule_v2.reorder') FROM audit_events WHERE org_id=$1`, orgID).Scan(&attempts, &completions); err != nil {
		t.Fatal(err)
	}
	if firstPriority != 10 || secondPriority != 20 || attempts != 1 || completions != 0 {
		t.Fatalf("failed reorder priorities=%d/%d attempts=%d completions=%d", firstPriority, secondPriority, attempts, completions)
	}
	response := request(NewResponseRulesV2(d, audit.New(pool)))
	if response.Code != http.StatusOK {
		t.Fatalf("reorder retry status=%d body=%s", response.Code, response.Body.String())
	}
	var receipt struct {
		AuditAttemptID    int64 `json:"audit_attempt_id"`
		CompletionAuditID int64 `json:"completion_audit_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil || receipt.AuditAttemptID == 0 || receipt.CompletionAuditID == 0 {
		t.Fatalf("reorder receipt=%+v err=%v", receipt, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT priority FROM response_rules_v2 WHERE id=$1`, secondID).Scan(&secondPriority); err != nil || secondPriority != 10 {
		t.Fatalf("reordered priority=%d err=%v", secondPriority, err)
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
	if _, err := pool.Exec(context.Background(), `INSERT INTO groups (org_id, name, kind) VALUES ($1, 'nv.api', 'ground')`, orgID); err != nil {
		t.Fatalf("group: %v", err)
	}
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

func responseRuleV2GroupBody(name, selector string) []byte {
	body, _ := json.Marshal(responseRuleV2Body{
		Name: name, Enabled: true, EventType: "threat",
		Conditions:    []response.Condition{{Type: response.CondLevel, Value: "high"}},
		Actions:       []response.Action{{Kind: response.ActionSuppressLog}},
		WorkloadMatch: response.WorkloadSelector{Group: selector},
	})
	return body
}

func sendResponseRuleV2Group(r http.Handler, method, path string, orgID, userID uuid.UUID, body []byte) *httptest.ResponseRecorder {
	req := withSubj(httptest.NewRequest(method, path, strings.NewReader(string(body))), orgID, userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestResponseRulesV2_GroupSelectorRequiresScopedGroup(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	otherOrgID, _ := seedOrgUser(t, pool)
	clusterID := seedResponseRuleV2Cluster(t, pool, orgID, "group-scope-a")
	otherClusterID := seedResponseRuleV2Cluster(t, pool, orgID, "group-scope-b")
	globalGroupID := uuid.New()
	clusterGroupID := uuid.New()
	for _, group := range []struct {
		id        uuid.UUID
		orgID     uuid.UUID
		clusterID any
		name      string
	}{
		{globalGroupID, orgID, nil, "global-group"},
		{clusterGroupID, orgID, clusterID, "cluster-group"},
		{uuid.New(), otherOrgID, nil, "foreign-group"},
	} {
		if _, err := pool.Exec(context.Background(), `INSERT INTO groups (id, org_id, cluster_id, name, kind) VALUES ($1,$2,$3,$4,'ground')`,
			group.id, group.orgID, group.clusterID, group.name); err != nil {
			t.Fatalf("group %s: %v", group.name, err)
		}
	}
	router := responseRuleV2Router(d, pool)
	basePath := "/api/v1/response-rules-v2?cluster_id=" + clusterID.String()
	for _, tc := range []struct {
		name     string
		selector string
		path     string
		status   int
	}{
		{"missing", "missing-group", basePath, http.StatusBadRequest},
		{"foreign", "foreign-group", basePath, http.StatusBadRequest},
		{"other-cluster", "cluster-group", "/api/v1/response-rules-v2?cluster_id=" + otherClusterID.String(), http.StatusBadRequest},
		{"org-wide-rejects-cluster", "cluster-group", "/api/v1/response-rules-v2", http.StatusBadRequest},
		{"org-wide-global", "global-group", "/api/v1/response-rules-v2", http.StatusCreated},
		{"global-name", "global-group", basePath, http.StatusCreated},
		{"global-id", globalGroupID.String(), basePath, http.StatusCreated},
		{"cluster-name", "cluster-group", basePath, http.StatusCreated},
		{"cluster-id", clusterGroupID.String(), basePath, http.StatusCreated},
	} {
		resp := sendResponseRuleV2Group(router, http.MethodPost, tc.path, orgID, userID, responseRuleV2GroupBody(tc.name, tc.selector))
		if resp.Code != tc.status {
			t.Fatalf("create %s status=%d body=%s", tc.name, resp.Code, resp.Body.String())
		}
		if tc.status == http.StatusBadRequest && !strings.Contains(resp.Body.String(), "workload_match.group") {
			t.Fatalf("create %s error=%s", tc.name, resp.Body.String())
		}
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM response_rules_v2 WHERE org_id=$1`, orgID).Scan(&count); err != nil || count != 5 {
		t.Fatalf("created rules=%d err=%v", count, err)
	}

	ruleID := insertResponseRuleV2(t, pool, orgID, clusterID, "update-group", 100)
	updatePath := "/api/v1/response-rules-v2/" + ruleID.String() + "?cluster_id=" + clusterID.String()
	for _, tc := range []struct {
		selector string
		status   int
	}{
		{"missing-group", http.StatusBadRequest},
		{"foreign-group", http.StatusBadRequest},
		{"cluster-group", http.StatusOK},
		{clusterGroupID.String(), http.StatusOK},
	} {
		resp := sendResponseRuleV2Group(router, http.MethodPut, updatePath, orgID, userID, responseRuleV2GroupBody("update-group", tc.selector))
		if resp.Code != tc.status {
			t.Fatalf("update %q status=%d body=%s", tc.selector, resp.Code, resp.Body.String())
		}
		if tc.status == http.StatusBadRequest && !strings.Contains(resp.Body.String(), "workload_match.group") {
			t.Fatalf("update %q error=%s", tc.selector, resp.Body.String())
		}
	}
	otherRuleID := insertResponseRuleV2(t, pool, orgID, otherClusterID, "update-other-cluster", 100)
	resp := sendResponseRuleV2Group(router, http.MethodPut,
		"/api/v1/response-rules-v2/"+otherRuleID.String()+"?cluster_id="+clusterID.String(),
		orgID, userID, responseRuleV2GroupBody("update-other-cluster", "cluster-group"))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "workload_match.group") {
		t.Fatalf("update against misleading cluster status=%d body=%s", resp.Code, resp.Body.String())
	}
	orgWideRuleID := insertResponseRuleV2(t, pool, orgID, nil, "update-org-wide", 100)
	orgWidePath := "/api/v1/response-rules-v2/" + orgWideRuleID.String()
	resp = sendResponseRuleV2Group(router, http.MethodPut, orgWidePath,
		orgID, userID, responseRuleV2GroupBody("update-org-wide", "cluster-group"))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "workload_match.group") {
		t.Fatalf("org-wide update with cluster group status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = sendResponseRuleV2Group(router, http.MethodPut, orgWidePath,
		orgID, userID, responseRuleV2GroupBody("update-org-wide", "global-group"))
	if resp.Code != http.StatusOK {
		t.Fatalf("org-wide update with global group status=%d body=%s", resp.Code, resp.Body.String())
	}
	var savedSelector response.WorkloadSelector
	var selectorJSON []byte
	if err := pool.QueryRow(context.Background(), `SELECT workload_match FROM response_rules_v2 WHERE id=$1`, ruleID).Scan(&selectorJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(selectorJSON, &savedSelector); err != nil || savedSelector.Group != clusterGroupID.String() {
		t.Fatalf("saved update selector=%+v err=%v", savedSelector, err)
	}
}

func TestResponseRulesV2_GroupMutationWinsBeforeCreateAndUpdate(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	router := responseRuleV2Router(d, pool)
	for _, tc := range []struct {
		name   string
		method string
		change string
	}{
		{"create-after-rename", http.MethodPost, "rename"},
		{"update-after-delete", http.MethodPut, "delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groupID := uuid.New()
			groupName := "race-" + groupID.String()
			if _, err := pool.Exec(context.Background(), `INSERT INTO groups (id, org_id, name, kind) VALUES ($1,$2,$3,'ground')`, groupID, orgID, groupName); err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/response-rules-v2"
			if tc.method == http.MethodPut {
				ruleID := insertResponseRuleV2(t, pool, orgID, nil, tc.name, 100)
				path += "/" + ruleID.String()
			}
			tx, err := pool.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			var lockedOrgID uuid.UUID
			if err := tx.QueryRow(context.Background(), `SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE`, orgID).Scan(&lockedOrgID); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(context.Background(), `LOCK TABLE response_rules_v2 IN SHARE MODE`); err != nil {
				t.Fatal(err)
			}
			if tc.change == "rename" {
				_, err = tx.Exec(context.Background(), `UPDATE groups SET name=$1 WHERE id=$2`, groupName+"-renamed", groupID)
			} else {
				_, err = tx.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, groupID)
			}
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- sendResponseRuleV2Group(router, tc.method, path, orgID, userID, responseRuleV2GroupBody(tc.name, groupName))
			}()
			select {
			case resp := <-result:
				t.Fatalf("%s completed before group mutation committed: %d %s", tc.name, resp.Code, resp.Body.String())
			case <-time.After(100 * time.Millisecond):
			}
			if err := tx.Commit(context.Background()); err != nil {
				t.Fatal(err)
			}
			select {
			case resp := <-result:
				if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "workload_match.group") {
					t.Fatalf("%s status=%d body=%s", tc.name, resp.Code, resp.Body.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("rule mutation deadlocked with group mutation")
			}
			var count int
			if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM response_rules_v2 WHERE org_id=$1 AND workload_match->>'group'=$2`, orgID, groupName).Scan(&count); err != nil || count != 0 {
				t.Fatalf("stale group references=%d err=%v", count, err)
			}
		})
	}
}

func TestResponseRulesV2_GroupRowLockReturnsConflict(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	groupID := uuid.New()
	groupName := "locked-" + groupID.String()
	if _, err := pool.Exec(context.Background(), `INSERT INTO groups (id, org_id, name, kind) VALUES ($1,$2,$3,'ground')`, groupID, orgID, groupName); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var lockedID uuid.UUID
	if err := tx.QueryRow(context.Background(), `SELECT id FROM groups WHERE id=$1 FOR UPDATE`, groupID).Scan(&lockedID); err != nil {
		t.Fatal(err)
	}
	router := responseRuleV2Router(d, pool)
	resp := sendResponseRuleV2Group(router, http.MethodPost, "/api/v1/response-rules-v2", orgID, userID, responseRuleV2GroupBody("locked-create", groupName))
	if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "workload_match.group") {
		t.Fatalf("locked group create status=%d body=%s", resp.Code, resp.Body.String())
	}
	ruleID := insertResponseRuleV2(t, pool, orgID, nil, "locked-update", 100)
	resp = sendResponseRuleV2Group(router, http.MethodPut, "/api/v1/response-rules-v2/"+ruleID.String(), orgID, userID, responseRuleV2GroupBody("locked-update", groupName))
	if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "workload_match.group") {
		t.Fatalf("locked group update status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestResponseRulesV2_GroupUpdateDoesNotDeadlockReorder(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	groupName := "reorder-group-" + uuid.NewString()
	if _, err := pool.Exec(context.Background(), `INSERT INTO groups (org_id, name, kind) VALUES ($1,$2,'ground')`, orgID, groupName); err != nil {
		t.Fatal(err)
	}
	ruleID := insertResponseRuleV2(t, pool, orgID, nil, "reorder-lock", 100)
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var lockedID uuid.UUID
	if err := tx.QueryRow(context.Background(), `SELECT id FROM response_rules_v2 WHERE id=$1 FOR UPDATE`, ruleID).Scan(&lockedID); err != nil {
		t.Fatal(err)
	}
	router := responseRuleV2Router(d, pool)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- sendResponseRuleV2Group(router, http.MethodPut,
			"/api/v1/response-rules-v2/"+ruleID.String(), orgID, userID,
			responseRuleV2GroupBody("reorder-lock", groupName))
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(context.Background(), `
SELECT EXISTS (SELECT 1 FROM pg_locks
 WHERE relation='response_rules_v2'::regclass
   AND mode='ExclusiveLock' AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("group update did not wait behind reorder row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := tx.Exec(ctx, `UPDATE response_rules_v2 SET priority=110 WHERE id=$1`, ruleID); err != nil {
		t.Fatalf("reorder update blocked by group update: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-result:
		if resp.Code != http.StatusOK {
			t.Fatalf("group update status=%d body=%s", resp.Code, resp.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("group update did not resume after reorder commit")
	}
}
