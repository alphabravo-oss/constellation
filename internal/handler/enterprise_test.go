package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestEnterpriseEndpointsReturnCatalogs(t *testing.T) {
	h := NewEnterprise()
	tests := []struct {
		name           string
		fn             func(http.ResponseWriter, *http.Request)
		key            string
		allowEmptyList bool
	}{
		{"runtime", h.RuntimeOverview, "subsystems", false},
		{"integrations", h.Integrations, "receivers", true},
		{"migration", h.MigrationSources, "sources", false},
		{"onboarding", h.Onboarding, "install_methods", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.fn(w, httptest.NewRequest("GET", "/", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status: %d", w.Code)
			}
			var got map[string]any
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			items, ok := got[tt.key].([]any)
			if !ok || (!tt.allowEmptyList && len(items) == 0) {
				t.Fatalf("missing %s in %+v", tt.key, got)
			}
		})
	}
}

func TestEnterpriseOnboardingNoStorageDoesNotReportReadyHealth(t *testing.T) {
	w := httptest.NewRecorder()
	NewEnterprise().Onboarding(w, httptest.NewRequest(http.MethodGet, "/api/v1/onboarding", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		HealthGates []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"health_gates"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.HealthGates) == 0 {
		t.Fatalf("missing health gates")
	}
	for _, gate := range got.HealthGates {
		if gate.Status == "ready" {
			t.Fatalf("no-storage onboarding health gate must not be ready: %+v", gate)
		}
	}
}

func TestEnterpriseOnboardingCommandsMapToImplementedChartPaths(t *testing.T) {
	w := httptest.NewRecorder()
	NewEnterprise().Onboarding(w, httptest.NewRequest(http.MethodGet, "/api/v1/onboarding", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		InstallMethods []struct {
			ID      string `json:"id"`
			Command string `json:"command"`
		} `json:"install_methods"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.InstallMethods) == 0 {
		t.Fatalf("missing install methods")
	}
	for _, method := range got.InstallMethods {
		if !strings.Contains(method.Command, "deploy/charts/constellation") {
			t.Fatalf("%s command should target the supported Helm chart: %q", method.ID, method.Command)
		}
		if strings.Contains(method.Command, "sample-cr") {
			t.Fatalf("%s command must not advertise sample manifests: %q", method.ID, method.Command)
		}
	}
}

func TestEnterpriseIntegrationsUsesLiveReceivers(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()

	orgID := uuid.New()
	userID := uuid.New()
	receiverID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Enterprise Integrations Org')`,
		orgID, "enterprise-integrations-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Integration Admin')`,
		userID, orgID, "enterprise-integrations-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO receivers (id, org_id, name, kind, endpoint, secret_ref, owner, environment, status, supported_events, config)
VALUES ($1, $2, 'Ops Webhook', 'webhook', 'https://hooks.example.test/ops', 'vault://ops/webhook', 'secops', 'production', 'healthy', '["finding.created"]'::jsonb, '{}'::jsonb)`,
		receiverID, orgID); err != nil {
		t.Fatalf("receiver: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO routing_configs (org_id, yaml, revision, updated_by)
VALUES ($1, 'route:
  receivers: ["Ops Webhook"]', 3, $2)`, orgID, userID); err != nil {
		t.Fatalf("routing: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integrations", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewEnterprise(d).Integrations(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Receivers []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Kind   string `json:"kind"`
			Status string `json:"status"`
		} `json:"receivers"`
		Routing map[string]any `json:"routing"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Receivers) != 1 || got.Receivers[0].ID != receiverID.String() || got.Receivers[0].Name != "Ops Webhook" {
		t.Fatalf("expected live receiver only, got %+v", got.Receivers)
	}
	if got.Routing["status"] != "configured" || got.Routing["revision"].(float64) != 3 {
		t.Fatalf("expected live routing metadata, got %+v", got.Routing)
	}
}

func TestEnterpriseMigrationPreviewConvertsAndDiffsReadOnly(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration Preview Org')`, orgID, "migration-preview-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration Admin')`, userID, orgID, "migration-preview-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO policies (org_id, name, description, engine, category, spec_yaml, enabled, mode)
VALUES ($1, 'nv-1001-block-latest-tag', 'existing', 'kyverno', 'admission', 'existing: true', true, 'monitor')`, orgID); err != nil {
		t.Fatalf("policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	body := `{
		"source": "neuvector",
		"export": "admission:\n  rules:\n    - id: 1001\n      desc: Block latest tag\n      criteria:\n        - key: image_name\n          op: regex\n          value: latest\n      action: deny\nresponse:\n  rules:\n    - id: 2001\n      event: process\n      conditions: [process_baseline]\n      actions: [alert, quarantine]\n"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(body))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewEnterprise(d).MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Summary.Total != 2 || got.Summary.Update != 1 || got.Summary.Create != 1 || !got.Summary.ReadOnly {
		t.Fatalf("bad summary: %+v", got.Summary)
	}
	if got.Policies[0].DiffAction != "update" || got.Policies[1].Mode != "enforce" {
		t.Fatalf("bad policy preview: %+v", got.Policies)
	}
	if !strings.Contains(got.RollbackBundle, "restore previous policy versions") {
		t.Fatalf("missing rollback bundle: %s", got.RollbackBundle)
	}
	var policyCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id = $1`, orgID).Scan(&policyCount); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policyCount != 1 {
		t.Fatalf("preview must be read-only, got %d policies", policyCount)
	}
}

func TestEnterpriseRuntimeOverviewIncludesRuntimeEvidence(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Runtime Evidence Org')`, orgID, "runtime-evidence-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Runtime Analyst')`, userID, orgID, "runtime-evidence-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'runtime-prod', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO events (org_id, cluster_id, node_id, workload_id, source, kind, severity, verdict, attack_techniques, payload, at)
VALUES ($1,$2,'ip-10-0-1-2','default/api','falco','process_shell','high','alert',ARRAY['T1059.004'],'{"rule_id":"container-process-shell","rule_name":"Container shell spawned","message":"shell spawned in api container"}'::jsonb,NOW()),
       ($1,$2,'ip-10-0-1-3','default/frontend','waf','sql_injection','critical','block',ARRAY['T1190'],'{"rule_id":"waf-sql-injection","rule_name":"SQL injection payload","message":"SQL injection payload blocked"}'::jsonb,NOW() - INTERVAL '5 minutes')`, orgID, clusterID); err != nil {
		t.Fatalf("events: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	req := httptest.NewRequest("GET", "/api/v1/runtime/overview?hours=24", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewEnterprise(d).RuntimeOverview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Summary   runtimeEvidenceSummaryDTO    `json:"summary"`
		Events    []runtimeEventEvidenceDTO    `json:"recent_events"`
		Workloads []runtimeWorkloadEvidenceDTO `json:"workloads"`
		Rules     []runtimeRuleOverviewDTO     `json:"rules"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Summary.Events != 2 || got.Summary.Alerts != 2 || got.Summary.Blocks != 1 || got.Summary.AffectedWorkloads != 2 || got.Summary.Techniques != 2 {
		t.Fatalf("unexpected summary: %+v", got.Summary)
	}
	if len(got.Events) != 2 || got.Events[0].ClusterName != "runtime-prod" {
		t.Fatalf("missing recent runtime evidence: %+v", got.Events)
	}
	if len(got.Workloads) != 2 {
		t.Fatalf("missing workload evidence: %+v", got.Workloads)
	}
	rule, ok := findRuntimeRuleForTest(got.Rules, "container-process-shell")
	if !ok || rule.EventCount != 1 || rule.AffectedWorkloads != 1 || rule.LastTriggeredAt == "" {
		t.Fatalf("missing correlated runtime rule evidence: %+v", got.Rules)
	}
	if got.Events[0].RuleID == "" || got.Events[0].RuleName == "" {
		t.Fatalf("missing event rule correlation: %+v", got.Events[0])
	}
}

func findRuntimeRuleForTest(rules []runtimeRuleOverviewDTO, id string) (runtimeRuleOverviewDTO, bool) {
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return runtimeRuleOverviewDTO{}, false
}
