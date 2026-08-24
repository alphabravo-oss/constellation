package handler

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
	"github.com/alphabravocompany/constellation/pkg/rbac"
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
	ensureMigrationImportsTestTable(t, d)

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
	if got.Summary.SourceTotal != 2 ||
		got.Summary.SourceCounts["policies"] != 2 ||
		got.Summary.SourceCounts["admission_rules"] != 1 ||
		got.Summary.SourceCounts["response_rules"] != 1 ||
		got.Summary.Unaccounted != 0 {
		t.Fatalf("bad source count summary: %+v", got.Summary)
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
	if got.ImportID == "" {
		t.Fatalf("preview should persist a migration import id")
	}
}

func TestEnterpriseMigrationApplyAndRollbackPolicies(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration Apply Org')`, orgID, "migration-apply-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration Apply Admin')`, userID, orgID, "migration-apply-"+userID.String()+"@example.com"); err != nil {
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
		"export": "admission:\n  rules:\n    - id: 1001\n      desc: Block latest tag\n      criteria:\n        - key: image_name\n          op: regex\n          value: latest\n      action: deny\nresponse:\n  rules:\n    - id: 2001\n      event: process\n      conditions: [process_baseline]\n      actions: [alert, quarantine]\nprofiles:\n  - group: nv.default.api\n    mode: protect\n    filters:\n      - filter: /etc/passwd\n        behavior: block_access\n        applications: [cat]\n"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(body))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.ImportID == "" {
		t.Fatal("preview missing import id")
	}
	if len(preview.Unsupported) != 1 {
		t.Fatalf("preview should report unsupported file profile, got %+v", preview.Unsupported)
	}

	previewBundleReq := migrationActionRequest(http.MethodGet, "/api/v1/migration/imports/"+preview.ImportID+"/rollback-bundle", preview.ImportID, orgID, userID)
	previewBundleW := httptest.NewRecorder()
	h.MigrationRollbackBundle(previewBundleW, previewBundleReq)
	if previewBundleW.Code != http.StatusConflict {
		t.Fatalf("preview rollback bundle status=%d body=%s", previewBundleW.Code, previewBundleW.Body.String())
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var policyCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1`, orgID).Scan(&policyCount); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policyCount != 2 {
		t.Fatalf("apply should upsert two policies, got %d", policyCount)
	}
	bundleReq := migrationActionRequest(http.MethodGet, "/api/v1/migration/imports/"+preview.ImportID+"/rollback-bundle", preview.ImportID, orgID, userID)
	bundleW := httptest.NewRecorder()
	h.MigrationRollbackBundle(bundleW, bundleReq)
	if bundleW.Code != http.StatusOK {
		t.Fatalf("rollback bundle status=%d body=%s", bundleW.Code, bundleW.Body.String())
	}
	if got := bundleW.Header().Get("Content-Disposition"); !strings.Contains(got, "constellation-neuvector-rollback-") {
		t.Fatalf("rollback bundle filename header=%q", got)
	}
	var bundle struct {
		Source   string                       `json:"source"`
		Policies []migrationPolicyRollbackDTO `json:"policies"`
	}
	if err := json.NewDecoder(bundleW.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode rollback bundle: %v", err)
	}
	if bundle.Source != "neuvector" || len(bundle.Policies) == 0 {
		t.Fatalf("unexpected rollback bundle: %+v", bundle)
	}
	var updatedSpec string
	if err := pool.QueryRow(ctx, `SELECT spec_yaml FROM policies WHERE org_id=$1 AND name='nv-1001-block-latest-tag'`, orgID).Scan(&updatedSpec); err != nil {
		t.Fatalf("updated policy: %v", err)
	}
	if updatedSpec == "existing: true" {
		t.Fatalf("existing policy was not updated")
	}

	secondApplyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	secondApplyW := httptest.NewRecorder()
	h.MigrationApply(secondApplyW, secondApplyReq)
	if secondApplyW.Code != http.StatusOK {
		t.Fatalf("second apply status=%d body=%s", secondApplyW.Code, secondApplyW.Body.String())
	}
	var secondApply struct {
		AlreadyApplied bool `json:"already_applied"`
	}
	if err := json.NewDecoder(secondApplyW.Body).Decode(&secondApply); err != nil {
		t.Fatalf("decode second apply: %v", err)
	}
	if !secondApply.AlreadyApplied {
		t.Fatalf("second apply should be idempotent: %+v", secondApply)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1`, orgID).Scan(&policyCount); err != nil {
		t.Fatalf("count policies after rollback: %v", err)
	}
	if policyCount != 1 {
		t.Fatalf("rollback should restore one original policy, got %d", policyCount)
	}
	if err := pool.QueryRow(ctx, `SELECT spec_yaml FROM policies WHERE org_id=$1 AND name='nv-1001-block-latest-tag'`, orgID).Scan(&updatedSpec); err != nil {
		t.Fatalf("rolled-back policy: %v", err)
	}
	if updatedSpec != "existing: true" {
		t.Fatalf("rollback did not restore original spec: %q", updatedSpec)
	}

	badApplyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/not-a-uuid:apply", "not-a-uuid", orgID, userID)
	badApplyW := httptest.NewRecorder()
	h.MigrationApply(badApplyW, badApplyReq)
	if badApplyW.Code != http.StatusBadRequest {
		t.Fatalf("bad apply status=%d body=%s", badApplyW.Code, badApplyW.Body.String())
	}

	assertMigrationAuditCount(t, pool, orgID, preview.ImportID, "migration.import.preview", 1)
	assertMigrationAuditCount(t, pool, orgID, preview.ImportID, "migration.import.skipped_object", 1)
	assertMigrationAuditCount(t, pool, orgID, preview.ImportID, "migration.import.apply", 1)
	assertMigrationAuditCount(t, pool, orgID, preview.ImportID, "migration.import.apply.skipped", 1)
	assertMigrationAuditCount(t, pool, orgID, preview.ImportID, "migration.import.rollback", 1)
	assertMigrationAuditCount(t, pool, orgID, "not-a-uuid", "migration.import.apply.failed", 1)
}

func TestEnterpriseMigrationApplyRollbackRequireManagePolicies(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	previewedID := uuid.New()
	appliedID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration RBAC Org')`, orgID, "migration-rbac-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration RBAC User')`, userID, orgID, "migration-rbac-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO migration_imports (id, org_id, source, source_hash, status, preview_json, rollback_json, created_by)
VALUES
	($1, $2, 'neuvector', 'rbac-previewed', 'previewed', '{}'::jsonb, '{}'::jsonb, $3),
	($4, $2, 'neuvector', 'rbac-applied', 'applied', '{}'::jsonb, '{}'::jsonb, $3)`,
		previewedID, orgID, userID, appliedID); err != nil {
		t.Fatalf("migration imports: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	h := NewEnterprise(d).WithAudit(audit.New(pool))
	subjects := []struct {
		name string
		subj Subject
	}{
		{
			name: "analyst lacks manage policies",
			subj: Subject{UserID: userID, OrgID: orgID, Assignments: []rbac.RoleAssignment{{
				Role:  rbac.RoleAnalyst,
				Scope: rbac.Scope{OrgID: orgID},
			}}},
		},
		{
			name: "token scope narrows admin role",
			subj: Subject{
				UserID: userID,
				OrgID:  orgID,
				Assignments: []rbac.RoleAssignment{{
					Role:  rbac.RoleSecurityAdmin,
					Scope: rbac.Scope{OrgID: orgID},
				}},
				TokenScopes: []rbac.Verb{rbac.VerbReadFindings},
			},
		},
	}
	for _, tc := range subjects {
		t.Run(tc.name+"/apply", func(t *testing.T) {
			req := migrationActionRequestWithSubject(http.MethodPost, "/api/v1/migration/imports/"+previewedID.String()+":apply", previewedID.String(), tc.subj)
			w := httptest.NewRecorder()
			h.MigrationApply(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("apply status=%d body=%s", w.Code, w.Body.String())
			}
		})
		t.Run(tc.name+"/rollback", func(t *testing.T) {
			req := migrationActionRequestWithSubject(http.MethodPost, "/api/v1/migration/imports/"+appliedID.String()+":rollback", appliedID.String(), tc.subj)
			w := httptest.NewRecorder()
			h.MigrationRollback(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("rollback status=%d body=%s", w.Code, w.Body.String())
			}
		})
		t.Run(tc.name+"/rollback bundle", func(t *testing.T) {
			req := migrationActionRequestWithSubject(http.MethodGet, "/api/v1/migration/imports/"+appliedID.String()+"/rollback-bundle", appliedID.String(), tc.subj)
			w := httptest.NewRecorder()
			h.MigrationRollbackBundle(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("rollback bundle status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	var previewedStatus, appliedStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM migration_imports WHERE id=$1 AND org_id=$2`, previewedID, orgID).Scan(&previewedStatus); err != nil {
		t.Fatalf("previewed status: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM migration_imports WHERE id=$1 AND org_id=$2`, appliedID, orgID).Scan(&appliedStatus); err != nil {
		t.Fatalf("applied status: %v", err)
	}
	if previewedStatus != "previewed" || appliedStatus != "applied" {
		t.Fatalf("denied migration changed status: previewed=%s applied=%s", previewedStatus, appliedStatus)
	}
}

func TestEnterpriseMigrationApplyNativeAdmissionExceptionRules(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration Admission Exception Org')`, orgID, "migration-admission-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration Admission Admin')`, userID, orgID, "migration-admission-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	body := `{
		"source": "neuvector",
		"export": "rules:\n  - id: 11\n    comment: Allow platform namespace exception\n    rule_type: exception\n    disable: false\n    criteria:\n      - name: namespace\n        op: containsAny\n        value: kube-system, neuvector\n      - name: runAsPrivileged\n        op: =\n        value: true\n  - id: 12\n    comment: Deny privileged workloads\n    rule_type: deny\n    rule_mode: protect\n    criteria:\n      - name: runAsPrivileged\n        op: =\n        value: true\n"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(body))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.Summary.Total != 2 || preview.Summary.Enforce != 2 || preview.Summary.Unsupported != 0 {
		t.Fatalf("unexpected preview summary: %+v", preview.Summary)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}

	var exceptionMode, exceptionSpec string
	var exceptionEnabled bool
	if err := pool.QueryRow(ctx, `
SELECT mode, enabled, spec_yaml
  FROM policies
 WHERE org_id=$1 AND name='nv-11-allow-platform-namespace-exception'`, orgID).
		Scan(&exceptionMode, &exceptionEnabled, &exceptionSpec); err != nil {
		t.Fatalf("exception policy: %v", err)
	}
	if exceptionMode != "enforce" || !exceptionEnabled || !strings.Contains(exceptionSpec, "action: allow") || !strings.Contains(exceptionSpec, "kube-system") {
		t.Fatalf("unexpected exception policy mode=%s enabled=%v spec=%s", exceptionMode, exceptionEnabled, exceptionSpec)
	}

	var denySpec string
	if err := pool.QueryRow(ctx, `
SELECT spec_yaml
  FROM policies
 WHERE org_id=$1 AND name='nv-12-deny-privileged-workloads'`, orgID).Scan(&denySpec); err != nil {
		t.Fatalf("deny policy: %v", err)
	}
	if !strings.Contains(denySpec, "spec.containers[*].securityContext.privileged") || strings.Contains(denySpec, "action: allow") {
		t.Fatalf("unexpected deny policy spec=%s", denySpec)
	}
	assertMigrationAuditCount(t, pool, orgID, preview.ImportID, "migration.import.apply", 1)
}

func TestEnterpriseMigrationApplyNeuVectorDPIToRuntimeRules(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration DPI Org')`, orgID, "migration-dpi-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration DPI Admin')`, userID, orgID, "migration-dpi-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'migration-dpi-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	export := `kind: List
items:
  - apiVersion: neuvector.com/v1
    kind: NvDlpSecurityRule
    metadata: {name: pii-sensor}
    spec:
      sensor:
        name: pii-sensor
        cfg_type: federal
        rules:
          - name: ssn
            cfg_type: federal
            patterns:
              - key: pattern
                op: regex
                value: "[0-9]{3}-[0-9]{2}-[0-9]{4}"
                context: body
  - apiVersion: neuvector.com/v1
    kind: NvWafSecurityRule
    metadata: {name: waf-sensor}
    spec:
      sensor:
        name: waf-sensor
        rules:
          - name: sql-injection
            patterns:
              - key: pattern
                op: regex
                value: "(?i)union select"
                context: url
`
	bodyBytes, err := json.Marshal(map[string]string{
		"source":     "neuvector",
		"cluster_id": clusterID.String(),
		"export":     export,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(bodyBytes)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.ImportID == "" || preview.Summary.DPIRules != 2 || len(preview.DPIRules) != 2 || preview.Summary.Unsupported != 0 {
		t.Fatalf("unexpected dpi preview: summary=%+v rules=%+v unsupported=%+v", preview.Summary, preview.DPIRules, preview.Unsupported)
	}
	if dlp := preview.DPIRules[0]; dlp.Category != "dlp" || dlp.SourcePath != "items[0].spec.sensor.rules[0]" || dlp.SourceCfgType != "federal" || dlp.SourceRuleCfgType != "federal" || !dlp.Federated {
		t.Fatalf("preview dlp provenance missing: %+v", dlp)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var got struct {
		Applied map[string]int `json:"applied"`
	}
	if err := json.NewDecoder(applyW.Body).Decode(&got); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
	if got.Applied["dpi_rules"] != 2 || got.Applied["created"] != 2 {
		t.Fatalf("unexpected applied summary: %+v", got.Applied)
	}
	var dlpApplyDir, wafApplyDir int
	var dlpMode, dlpDescription, dlpSource, dlpCfgType, dlpSourcePath, wafMode, wafPatterns string
	if err := pool.QueryRow(ctx, `
SELECT apply_dir, mode, COALESCE(description,''), source, cfg_type, source_path
  FROM runtime_dlp_rules
 WHERE org_id=$1 AND cluster_id=$2 AND category='dlp'`, orgID, clusterID).Scan(&dlpApplyDir, &dlpMode, &dlpDescription, &dlpSource, &dlpCfgType, &dlpSourcePath); err != nil {
		t.Fatalf("dlp runtime rule: %v", err)
	}
	if err := pool.QueryRow(ctx, `
SELECT apply_dir, mode, patterns::text
  FROM runtime_dlp_rules
 WHERE org_id=$1 AND cluster_id=$2 AND category='waf'`, orgID, clusterID).Scan(&wafApplyDir, &wafMode, &wafPatterns); err != nil {
		t.Fatalf("waf runtime rule: %v", err)
	}
	if dlpApplyDir != 1 || wafApplyDir != 2 || dlpMode != "monitor" || wafMode != "monitor" || !strings.Contains(wafPatterns, `"context": "uri"`) {
		t.Fatalf("unexpected runtime dpi rows: dlp dir=%d mode=%s waf dir=%d mode=%s patterns=%s", dlpApplyDir, dlpMode, wafApplyDir, wafMode, wafPatterns)
	}
	if !strings.Contains(dlpDescription, "source: items[0].spec.sensor.rules[0]") {
		t.Fatalf("runtime dlp description lost source path: %q", dlpDescription)
	}
	if dlpSource != "neuvector" || dlpCfgType != "federated" || dlpSourcePath != "items[0].spec.sensor.rules[0]" {
		t.Fatalf("runtime dlp provenance = %s/%s/%s", dlpSource, dlpCfgType, dlpSourcePath)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_dlp_rules WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&remaining); err != nil {
		t.Fatalf("count runtime dpi rows: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("rollback should remove imported dpi rows, got %d", remaining)
	}
}

func TestEnterpriseMigrationRollbackRestoresUpdatedNeuVectorDPI(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	ruleID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration DPI Restore Org')`, orgID, "migration-dpi-restore-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration DPI Restore Admin')`, userID, orgID, "migration-dpi-restore-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'migration-dpi-restore-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO runtime_dlp_rules
  (id, org_id, cluster_id, name, category, apply_dir, severity, mode, patterns, scope_macs, description, version, created_by, updated_by)
VALUES ($1,$2,$3,'nv-waf-waf-sensor-sql-injection','signature',3,3,'enforce',
        '[{"pattern":"original","op":"regex","context":"body"}]'::jsonb,
        '["aa:bb:cc:dd:ee:ff"]'::jsonb,
        'original description',7,$4,$4)`, ruleID, orgID, clusterID, userID); err != nil {
		t.Fatalf("existing runtime rule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	export := `kind: NvWafSecurityRule
metadata: {name: waf-sensor}
spec:
  sensor:
    name: waf-sensor
    rules:
      - name: sql-injection
        patterns:
          - key: pattern
            op: regex
            value: "(?i)union select"
            context: url
`
	bodyBytes, err := json.Marshal(map[string]string{
		"source":     "neuvector",
		"cluster_id": clusterID.String(),
		"export":     export,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(bodyBytes)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.Summary.Update != 1 || len(preview.DPIRules) != 1 || preview.DPIRules[0].DiffAction != "update" {
		t.Fatalf("expected one DPI update preview, summary=%+v rules=%+v", preview.Summary, preview.DPIRules)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var category, mode, patterns, scope, description string
	var applyDir, severity int
	var version int64
	if err := pool.QueryRow(ctx, `
SELECT category, apply_dir, severity, mode, patterns::text, COALESCE(scope_macs::text,''), COALESCE(description,''), version
  FROM runtime_dlp_rules
 WHERE id=$1 AND org_id=$2`, ruleID, orgID).Scan(&category, &applyDir, &severity, &mode, &patterns, &scope, &description, &version); err != nil {
		t.Fatalf("updated runtime rule: %v", err)
	}
	if category != "waf" || applyDir != 2 || severity != 6 || mode != "monitor" || !strings.Contains(patterns, "union select") || scope == "" {
		t.Fatalf("apply did not update expected WAF fields: category=%s dir=%d severity=%d mode=%s patterns=%s scope=%s", category, applyDir, severity, mode, patterns, scope)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	if err := pool.QueryRow(ctx, `
SELECT category, apply_dir, severity, mode, patterns::text, COALESCE(scope_macs::text,''), COALESCE(description,''), version
  FROM runtime_dlp_rules
 WHERE id=$1 AND org_id=$2`, ruleID, orgID).Scan(&category, &applyDir, &severity, &mode, &patterns, &scope, &description, &version); err != nil {
		t.Fatalf("restored runtime rule: %v", err)
	}
	if category != "signature" || applyDir != 3 || severity != 3 || mode != "enforce" ||
		!strings.Contains(patterns, "original") || !strings.Contains(scope, "aa:bb:cc:dd:ee:ff") ||
		description != "original description" || version != 7 {
		t.Fatalf("rollback did not restore original rule: category=%s dir=%d severity=%d mode=%s patterns=%s scope=%s description=%s version=%d",
			category, applyDir, severity, mode, patterns, scope, description, version)
	}
}

func TestEnterpriseMigrationApplyNeuVectorDPIGroupBindings(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	groupID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration DPI Binding Org')`, orgID, "migration-dpi-binding-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration DPI Binding Admin')`, userID, orgID, "migration-dpi-binding-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'migration-dpi-binding-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO groups (id, org_id, cluster_id, name, kind, comment, criteria, members, cfg_type, policy_mode, profile_mode, created_by)
VALUES ($1,$2,$3,'nv.default.api','ground','API services','[]'::jsonb,'["default/api"]'::jsonb,'user','monitor','monitor',$4)`, groupID, orgID, clusterID, userID); err != nil {
		t.Fatalf("group: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	export := `dlp_groups:
  - name: nv.default.api
    status: true
    sensors:
      - name: pii-sensor
        action: deny
waf_groups:
  - name: nv.missing.frontend
    status: true
    sensors:
      - name: waf-sensor
        action: alert
`
	bodyBytes, err := json.Marshal(map[string]string{
		"source":     "neuvector",
		"cluster_id": clusterID.String(),
		"export":     export,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(bodyBytes)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.ImportID == "" || preview.Summary.DPIBindings != 1 || len(preview.DPIBindings) != 1 {
		t.Fatalf("expected one resolved DPI binding, summary=%+v bindings=%+v", preview.Summary, preview.DPIBindings)
	}
	if preview.DPIBindings[0].TargetGroupID != groupID.String() || preview.DPIBindings[0].SensorKind != "dlp" || preview.DPIBindings[0].DiffAction != "create" {
		t.Fatalf("unexpected binding preview: %+v", preview.DPIBindings[0])
	}
	if preview.Summary.Unsupported != 1 || len(preview.Unsupported) != 1 || preview.Unsupported[0].Kind != "waf_group_scope" {
		t.Fatalf("expected missing WAF group as unsupported, summary=%+v unsupported=%+v", preview.Summary, preview.Unsupported)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var applyRes struct {
		Status  string         `json:"status"`
		Applied map[string]int `json:"applied"`
	}
	if err := json.NewDecoder(applyW.Body).Decode(&applyRes); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
	if applyRes.Status != "partial_applied" || applyRes.Applied["dpi_bindings"] != 1 || applyRes.Applied["created"] != 1 {
		t.Fatalf("unexpected apply response: %+v", applyRes)
	}
	var sensorKind string
	var sensorID uuid.UUID
	if err := pool.QueryRow(ctx, `
SELECT sensor_kind, sensor_id
  FROM group_dpi_sensor_bindings
 WHERE org_id=$1 AND group_id=$2`, orgID, groupID).Scan(&sensorKind, &sensorID); err != nil {
		t.Fatalf("created group binding: %v", err)
	}
	if sensorKind != "dlp" || sensorID.String() != "00000000-0000-4000-8000-0000000000d1" {
		t.Fatalf("unexpected group binding kind=%s sensor=%s", sensorKind, sensorID)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	var bindings int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_dpi_sensor_bindings WHERE org_id=$1 AND group_id=$2`, orgID, groupID).Scan(&bindings); err != nil {
		t.Fatalf("count group bindings: %v", err)
	}
	if bindings != 0 {
		t.Fatalf("rollback should remove imported group binding, got %d", bindings)
	}
}

func TestEnterpriseMigrationApplyNeuVectorGroupsAndDPIBindingsFromSameExport(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration Group Import Org')`, orgID, "migration-group-import-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration Group Admin')`, userID, orgID, "migration-group-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'migration-group-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count)
VALUES ($1,$2,'default','api','Deployment','{"tier":"backend"}'::jsonb,0,'{}'::jsonb,0)`, orgID, clusterID); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	export := `groups:
  - name: nv.api.default
    comment: API service
    policy_mode: protect
    profile_mode: monitor
    criteria:
      - key: service
        op: "="
        value: api.default
      - key: domain
        op: "="
        value: default
      - key: label
        op: "="
        value: tier=backend
dlp_groups:
  - name: nv.api.default
    status: true
    sensors:
      - name: pii-sensor
        action: deny
`
	bodyBytes, err := json.Marshal(map[string]string{
		"source":     "neuvector",
		"cluster_id": clusterID.String(),
		"export":     export,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(bodyBytes)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.ImportID == "" || preview.Summary.Groups != 1 || preview.Summary.DPIBindings != 1 || preview.Summary.Unsupported != 0 {
		t.Fatalf("unexpected group preview: summary=%+v groups=%+v bindings=%+v unsupported=%+v", preview.Summary, preview.Groups, preview.DPIBindings, preview.Unsupported)
	}
	if len(preview.Groups) != 1 || preview.Groups[0].DiffAction != "create" || !hasPortableGroupCriterion(preview.Groups[0].Criteria, "id", "eq", "default/api") {
		t.Fatalf("unexpected imported group preview: %+v", preview.Groups)
	}
	if len(preview.DPIBindings) != 1 || preview.DPIBindings[0].TargetGroupID != "" || preview.DPIBindings[0].TargetGroupName != "nv.api.default" {
		t.Fatalf("binding should resolve to same-import group by name: %+v", preview.DPIBindings)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var applyRes struct {
		Status  string         `json:"status"`
		Applied map[string]int `json:"applied"`
	}
	if err := json.NewDecoder(applyW.Body).Decode(&applyRes); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
	if applyRes.Status != "applied" || applyRes.Applied["groups"] != 1 || applyRes.Applied["dpi_bindings"] != 1 || applyRes.Applied["created"] != 2 {
		t.Fatalf("unexpected apply response: %+v", applyRes)
	}
	var groupID uuid.UUID
	var membersText, criteriaText string
	if err := pool.QueryRow(ctx, `
SELECT id, members::text, criteria::text
  FROM groups
 WHERE org_id=$1 AND cluster_id=$2 AND name='nv.api.default'`, orgID, clusterID).Scan(&groupID, &membersText, &criteriaText); err != nil {
		t.Fatalf("imported group: %v", err)
	}
	if !strings.Contains(membersText, "default/api") || !strings.Contains(criteriaText, "default/api") {
		t.Fatalf("group membership/criteria not computed: members=%s criteria=%s", membersText, criteriaText)
	}
	var bindings int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_dpi_sensor_bindings WHERE org_id=$1 AND group_id=$2 AND sensor_kind='dlp'`, orgID, groupID).Scan(&bindings); err != nil {
		t.Fatalf("count imported binding: %v", err)
	}
	if bindings != 1 {
		t.Fatalf("expected imported DLP binding, got %d", bindings)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	var groupsLeft int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND name='nv.api.default'`, orgID).Scan(&groupsLeft); err != nil {
		t.Fatalf("count groups after rollback: %v", err)
	}
	if groupsLeft != 0 {
		t.Fatalf("rollback should remove imported group, got %d", groupsLeft)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_dpi_sensor_bindings WHERE org_id=$1`, orgID).Scan(&bindings); err != nil {
		t.Fatalf("count bindings after rollback: %v", err)
	}
	if bindings != 0 {
		t.Fatalf("rollback should remove imported binding, got %d", bindings)
	}
}

func TestEnterpriseMigrationApplyNeuVectorNetworkRulesFromSameExport(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration Network Org')`, orgID, "migration-network-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration Network Admin')`, userID, orgID, "migration-network-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'migration-network-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count)
VALUES
  ($1,$2,'default','api','Deployment','{"tier":"api"}'::jsonb,0,'{}'::jsonb,0),
  ($1,$2,'default','db','Deployment','{"tier":"db"}'::jsonb,0,'{}'::jsonb,0)`, orgID, clusterID); err != nil {
		t.Fatalf("deployments: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	export := `groups:
  - name: nv.api.default
    criteria:
      - key: service
        op: "="
        value: api.default
      - key: domain
        op: "="
        value: default
  - name: nv.db.default
    criteria:
      - key: service
        op: "="
        value: db.default
      - key: domain
        op: "="
        value: default
network_rules:
  - id: 1001
    comment: API to database
    from: nv.api.default
    to: nv.db.default
    ports: tcp/5432
    action: allow
    priority: 10
`
	bodyBytes, err := json.Marshal(map[string]string{
		"source":     "neuvector",
		"cluster_id": clusterID.String(),
		"export":     export,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(bodyBytes)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.ImportID == "" || preview.Summary.Groups != 2 || preview.Summary.NetworkRules != 1 || preview.Summary.Unsupported != 0 {
		t.Fatalf("unexpected network preview: summary=%+v groups=%+v rules=%+v unsupported=%+v", preview.Summary, preview.Groups, preview.NetworkRules, preview.Unsupported)
	}
	if len(preview.NetworkRules) != 1 || preview.NetworkRules[0].DiffAction != "create" || preview.NetworkRules[0].FromGroup != "nv.api.default" || preview.NetworkRules[0].ToGroup != "nv.db.default" {
		t.Fatalf("unexpected network rule preview: %+v", preview.NetworkRules)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var applyRes struct {
		Status  string         `json:"status"`
		Applied map[string]int `json:"applied"`
	}
	if err := json.NewDecoder(applyW.Body).Decode(&applyRes); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
	if applyRes.Status != "applied" || applyRes.Applied["groups"] != 2 || applyRes.Applied["network_rules"] != 1 || applyRes.Applied["created"] != 3 {
		t.Fatalf("unexpected apply response: %+v", applyRes)
	}
	var portsText, mode, comment string
	if err := pool.QueryRow(ctx, `
SELECT ports::text, mode, comment
  FROM group_rule_edges
 WHERE org_id=$1 AND cluster_id=$2 AND from_group='nv.api.default' AND to_group='nv.db.default'`, orgID, clusterID).Scan(&portsText, &mode, &comment); err != nil {
		t.Fatalf("imported network edge: %v", err)
	}
	if !strings.Contains(portsText, "5432") || mode != "monitor" || comment != "API to database" {
		t.Fatalf("unexpected network edge ports=%s mode=%s comment=%s", portsText, mode, comment)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	var edgesLeft, groupsLeft int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1`, orgID).Scan(&edgesLeft); err != nil {
		t.Fatalf("count network edges after rollback: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND name IN ('nv.api.default','nv.db.default')`, orgID).Scan(&groupsLeft); err != nil {
		t.Fatalf("count groups after rollback: %v", err)
	}
	if edgesLeft != 0 || groupsLeft != 0 {
		t.Fatalf("rollback should remove imported edges/groups, edges=%d groups=%d", edgesLeft, groupsLeft)
	}
}

func TestEnterpriseMigrationApplyNeuVectorFileProfileFromSameExportGroup(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration File Profile Org')`, orgID, "migration-file-profile-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration File Profile Admin')`, userID, orgID, "migration-file-profile-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'migration-file-profile-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count)
VALUES ($1,$2,'default','api','Deployment','{"tier":"backend"}'::jsonb,0,'{}'::jsonb,0)`, orgID, clusterID); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	export := `groups:
  - name: nv.api.default
    criteria:
      - key: service
        op: "="
        value: api.default
      - key: domain
        op: "="
        value: default
profiles:
  - group: nv.api.default
    mode: protect
    filters:
      - filter: /etc/passwd
        behavior: block_access
        applications: [cat]
`
	bodyBytes, err := json.Marshal(map[string]string{
		"source":     "neuvector",
		"cluster_id": clusterID.String(),
		"export":     export,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(bodyBytes)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.ImportID == "" || preview.Summary.Groups != 1 || preview.Summary.FileProfiles != 1 || preview.Summary.Unsupported != 0 {
		t.Fatalf("unexpected file-profile preview: summary=%+v profiles=%+v unsupported=%+v", preview.Summary, preview.FileProfiles, preview.Unsupported)
	}
	if len(preview.FileProfiles) != 1 || len(preview.FileProfiles[0].TargetWorkloads) != 1 || preview.FileProfiles[0].TargetWorkloads[0] != "default/api" {
		t.Fatalf("file profile did not resolve target workload: %+v", preview.FileProfiles)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var applyRes struct {
		Status  string         `json:"status"`
		Applied map[string]int `json:"applied"`
	}
	if err := json.NewDecoder(applyW.Body).Decode(&applyRes); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
	if applyRes.Status != "applied" || applyRes.Applied["groups"] != 1 || applyRes.Applied["file_profiles"] != 1 || applyRes.Applied["file_profile_rules"] != 1 {
		t.Fatalf("unexpected apply response: %+v", applyRes)
	}
	var mode, filter, behavior string
	var applications []string
	if err := pool.QueryRow(ctx, `
SELECT s.mode, r.filter, r.behavior, r.applications
  FROM file_profile_states s
  JOIN file_profile_rules r
    ON r.org_id=s.org_id AND r.cluster_id=s.cluster_id AND r.workload_id=s.workload_id
 WHERE s.org_id=$1 AND s.cluster_id=$2 AND s.workload_id='default/api'`, orgID, clusterID).Scan(&mode, &filter, &behavior, &applications); err != nil {
		t.Fatalf("imported file profile: %v", err)
	}
	if mode != "enforce" || filter != "/etc/passwd" || behavior != "block_access" || len(applications) != 1 || applications[0] != "cat" {
		t.Fatalf("unexpected file profile row: mode=%s filter=%s behavior=%s apps=%v", mode, filter, behavior, applications)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	var states, rules, groupsLeft int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM file_profile_states WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&states); err != nil {
		t.Fatalf("count file states: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM file_profile_rules WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&rules); err != nil {
		t.Fatalf("count file rules: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND name='nv.api.default'`, orgID).Scan(&groupsLeft); err != nil {
		t.Fatalf("count groups: %v", err)
	}
	if states != 0 || rules != 0 || groupsLeft != 0 {
		t.Fatalf("rollback should remove imported file profile/group rows, states=%d rules=%d groups=%d", states, rules, groupsLeft)
	}
}

func TestEnterpriseMigrationApplyNeuVectorProcessProfileFromSameExportGroup(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration Process Profile Org')`, orgID, "migration-process-profile-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration Process Profile Admin')`, userID, orgID, "migration-process-profile-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'migration-process-profile-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count)
VALUES ($1,$2,'default','api','Deployment','{"tier":"backend"}'::jsonb,0,'{}'::jsonb,0)`, orgID, clusterID); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	export := `groups:
  - name: nv.api.default
    criteria:
      - key: service
        op: "="
        value: api.default
      - key: domain
        op: "="
        value: default
process_profiles:
  - group: nv.api.default
    mode: protect
    baseline: zero-drift
    process_list:
      - name: nginx
        path: /usr/sbin/nginx
        action: allow
        allow_update: true
      - name: sh
        path: /bin/sh
        action: deny
        user: root
`
	bodyBytes, err := json.Marshal(map[string]string{
		"source":     "neuvector",
		"cluster_id": clusterID.String(),
		"export":     export,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(bodyBytes)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.ImportID == "" || preview.Summary.Groups != 1 || preview.Summary.ProcessProfiles != 1 || preview.Summary.Unsupported != 0 {
		t.Fatalf("unexpected process-profile preview: summary=%+v profiles=%+v unsupported=%+v", preview.Summary, preview.ProcessProfiles, preview.Unsupported)
	}
	if len(preview.ProcessProfiles) != 1 || len(preview.ProcessProfiles[0].TargetWorkloads) != 1 || preview.ProcessProfiles[0].TargetWorkloads[0] != "default/api" {
		t.Fatalf("process profile did not resolve target workload: %+v", preview.ProcessProfiles)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var applyRes struct {
		Status  string         `json:"status"`
		Applied map[string]int `json:"applied"`
	}
	if err := json.NewDecoder(applyW.Body).Decode(&applyRes); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
	if applyRes.Status != "applied" || applyRes.Applied["groups"] != 1 || applyRes.Applied["process_profiles"] != 1 || applyRes.Applied["process_profile_rules"] != 2 {
		t.Fatalf("unexpected apply response: %+v", applyRes)
	}
	var mode, allowPath, denyUser string
	var allowUpdate bool
	if err := pool.QueryRow(ctx, `
SELECT s.mode,
       max(CASE WHEN r.name='nginx' THEN r.path ELSE '' END),
       bool_or(r.name='nginx' AND r.allow_update),
       max(CASE WHEN r.name='sh' THEN r.proc_user ELSE '' END)
  FROM process_baseline_states s
  JOIN process_profile_rules r
    ON r.org_id=s.org_id AND r.cluster_id=s.cluster_id AND r.workload_id=s.workload_id
 WHERE s.org_id=$1 AND s.cluster_id=$2 AND s.workload_id='default/api'
 GROUP BY s.mode`, orgID, clusterID).Scan(&mode, &allowPath, &allowUpdate, &denyUser); err != nil {
		t.Fatalf("imported process profile: %v", err)
	}
	if mode != "enforce" || allowPath != "/usr/sbin/nginx" || !allowUpdate || denyUser != "root" {
		t.Fatalf("unexpected process profile rows: mode=%s allowPath=%s allowUpdate=%v denyUser=%s", mode, allowPath, allowUpdate, denyUser)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	var states, rules, groupsLeft int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_baseline_states WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&states); err != nil {
		t.Fatalf("count process states: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_profile_rules WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&rules); err != nil {
		t.Fatalf("count process rules: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND name='nv.api.default'`, orgID).Scan(&groupsLeft); err != nil {
		t.Fatalf("count groups: %v", err)
	}
	if states != 0 || rules != 0 || groupsLeft != 0 {
		t.Fatalf("rollback should remove imported process profile/group rows, states=%d rules=%d groups=%d", states, rules, groupsLeft)
	}
}

func TestEnterpriseMigrationRollbackRestoresUpdatedNeuVectorNetworkRule(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureMigrationImportsTestTable(t, d)

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	edgeID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration Network Restore Org')`, orgID, "migration-network-restore-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration Network Restore Admin')`, userID, orgID, "migration-network-restore-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'migration-network-restore-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	for _, name := range []string{"nv.api.default", "nv.db.default"} {
		if _, err := pool.Exec(ctx, `
INSERT INTO groups (org_id, cluster_id, name, kind, comment, criteria, members, cfg_type, policy_mode, profile_mode, created_by)
VALUES ($1,$2,$3,'ground','existing','[]'::jsonb,'[]'::jsonb,'user','monitor','monitor',$4)`, orgID, clusterID, name, userID); err != nil {
			t.Fatalf("group %s: %v", name, err)
		}
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO group_rule_edges (id, org_id, cluster_id, from_group, to_group, ports, mode, comment, created_by, updated_by)
VALUES ($1,$2,$3,'nv.api.default','nv.db.default','[{"protocol":"TCP","port":8080}]'::jsonb,'protect','original edge',$4,$4)`,
		edgeID, orgID, clusterID, userID); err != nil {
		t.Fatalf("existing edge: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	export := `network_rules:
  - id: 1001
    comment: imported edge
    from: nv.api.default
    to: nv.db.default
    ports: udp/53
    action: allow
`
	bodyBytes, err := json.Marshal(map[string]string{
		"source":     "neuvector",
		"cluster_id": clusterID.String(),
		"export":     export,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(bodyBytes)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h := NewEnterprise(d).WithAudit(audit.New(pool))
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.NewDecoder(w.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.Summary.Update != 1 || preview.Summary.NetworkRules != 1 || preview.NetworkRules[0].DiffAction != "update" {
		t.Fatalf("expected one network update preview, summary=%+v rules=%+v", preview.Summary, preview.NetworkRules)
	}

	applyReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, orgID, userID)
	applyW := httptest.NewRecorder()
	h.MigrationApply(applyW, applyReq)
	if applyW.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyW.Code, applyW.Body.String())
	}
	var portsText, mode, comment string
	if err := pool.QueryRow(ctx, `SELECT ports::text, mode, comment FROM group_rule_edges WHERE id=$1 AND org_id=$2`, edgeID, orgID).Scan(&portsText, &mode, &comment); err != nil {
		t.Fatalf("updated edge: %v", err)
	}
	if !strings.Contains(portsText, "UDP") || !strings.Contains(portsText, "53") || mode != "monitor" || comment != "imported edge" {
		t.Fatalf("apply did not update edge: ports=%s mode=%s comment=%s", portsText, mode, comment)
	}

	rollbackReq := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, orgID, userID)
	rollbackW := httptest.NewRecorder()
	h.MigrationRollback(rollbackW, rollbackReq)
	if rollbackW.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackW.Code, rollbackW.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT ports::text, mode, comment FROM group_rule_edges WHERE id=$1 AND org_id=$2`, edgeID, orgID).Scan(&portsText, &mode, &comment); err != nil {
		t.Fatalf("restored edge: %v", err)
	}
	if !strings.Contains(portsText, "8080") || mode != "protect" || comment != "original edge" {
		t.Fatalf("rollback did not restore edge: ports=%s mode=%s comment=%s", portsText, mode, comment)
	}
}

func hasPortableGroupCriterion(criteria []portableGroupCriterion, key, op, value string) bool {
	for _, criterion := range criteria {
		if criterion.Key == key && criterion.Op == op && criterion.Value == value {
			return true
		}
	}
	return false
}

func migrationActionRequest(method, path, importID string, orgID, userID uuid.UUID) *http.Request {
	return migrationActionRequestWithSubject(method, path, importID, Subject{
		UserID: userID,
		OrgID:  orgID,
		Assignments: []rbac.RoleAssignment{{
			Role:  rbac.RoleSecurityAdmin,
			Scope: rbac.Scope{OrgID: orgID},
		}},
	})
}

func migrationActionRequestWithSubject(method, path, importID string, subj Subject) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", importID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	return req.WithContext(WithSubject(req.Context(), subj))
}

func ensureMigrationImportsTestTable(t *testing.T, d *db.DB) {
	t.Helper()
	_, err := d.Pool().Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS migration_imports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    source            TEXT NOT NULL,
    source_hash       TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'previewed',
    preview_json      JSONB NOT NULL,
    applied_json      JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
    unsupported_json  JSONB NOT NULL DEFAULT '[]'::jsonb,
    error             TEXT NOT NULL DEFAULT '',
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
	    applied_by        UUID REFERENCES users(id) ON DELETE SET NULL,
	    rolled_back_by    UUID REFERENCES users(id) ON DELETE SET NULL,
	    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    applied_at        TIMESTAMPTZ,
	    rolled_back_at    TIMESTAMPTZ,
	    CONSTRAINT migration_imports_status_chk CHECK (status IN ('previewed', 'applied', 'partial_applied', 'rolled_back', 'failed'))
	)`)
	if err != nil {
		t.Fatalf("ensure migration_imports: %v", err)
	}
}

func assertMigrationAuditCount(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, targetID string, action string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(), `
SELECT count(*) FROM audit_events
 WHERE org_id = $1 AND target_id = $2 AND action = $3`, orgID, targetID, action).Scan(&got); err != nil {
		t.Fatalf("count audit %s: %v", action, err)
	}
	if got != want {
		t.Fatalf("audit %s rows=%d want %d", action, got, want)
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
