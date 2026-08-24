package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestPolicies_AssessPersistsDryRunHistoryAndAudit(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"admission_dry_run_history", "admission_state", "audit_events", "policies"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	policyID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Admission Dry Run History Test')`,
		orgID, "admission-history-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Admission History User')`,
		userID, orgID, "admission-history-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, 'admission-history', 'k3s', 'connected')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO admission_state (org_id, cluster_id, enabled, mode, default_action, failure_policy, updated_by)
VALUES ($1, $2, TRUE, 'monitor', 'allow', 'ignore', $3)`,
		orgID, clusterID, userID); err != nil {
		t.Fatalf("admission state: %v", err)
	}
	specYAML := `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: disallow-latest-tag
spec:
  match:
    kinds: ["Pod"]
  images:
    disallowLatestTag: true
  action: deny
`
	if _, err := pool.Exec(ctx, `
INSERT INTO policies (id, org_id, cluster_id, name, description, engine, category, spec_yaml, enabled, mode, version)
VALUES ($1, $2, $3, 'disallow-latest-tag', 'deny latest tag', 'constellation-admission', 'admission', $4, TRUE, 'enforce', 1)`,
		policyID, orgID, clusterID, specYAML); err != nil {
		t.Fatalf("policy: %v", err)
	}

	body := []byte(`{"image":"ghcr.io/acme/app:latest","namespace":"prod"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/assess?cluster_id="+clusterID.String(), bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewPolicies(d, audit.New(pool), nil).Assess(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("assess status=%d body=%s", rec.Code, rec.Body.String())
	}
	var assessed admissionAssessResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &assessed); err != nil {
		t.Fatal(err)
	}
	if assessed.DryRunID == "" || assessed.AssessedAt == "" {
		t.Fatalf("missing persisted history metadata: %+v", assessed)
	}
	if assessed.Decision != "deny" || assessed.EnforcementMode != "enforce" || len(assessed.Matches) != 1 {
		t.Fatalf("unexpected admission result: %+v", assessed)
	}
	if assessed.CurrentOutcome != "Admit + log" || assessed.ProtectOutcome != "Block" {
		t.Fatalf("unexpected outcomes: %+v", assessed)
	}
	if !strings.Contains(assessed.Matches[0].Reason, "latest") {
		t.Fatalf("expected latest-tag reason, got %+v", assessed.Matches[0])
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/policies/admission/dry-runs?cluster_id="+clusterID.String(), nil)
	listReq = listReq.WithContext(authctx.WithSubject(listReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	listRec := httptest.NewRecorder()
	NewPolicies(d, audit.New(pool), nil).AdmissionDryRunHistory(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", listRec.Code, listRec.Body.String())
	}
	var listed struct {
		History []admissionDryRunHistoryDTO `json:"history"`
		Total   int                         `json:"total"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Total != 1 || len(listed.History) != 1 {
		t.Fatalf("history length=%d/%d body=%s", listed.Total, len(listed.History), listRec.Body.String())
	}
	if listed.History[0].ID != assessed.DryRunID ||
		listed.History[0].Image != "ghcr.io/acme/app:latest" ||
		listed.History[0].Namespace != "prod" ||
		listed.History[0].Matches != 1 ||
		listed.History[0].CurrentOutcome != "Admit + log" {
		t.Fatalf("unexpected history row: %+v", listed.History[0])
	}

	var auditAssess int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int
  FROM audit_events
 WHERE org_id = $1
   AND actor_id = $2
   AND action = 'admission.dry-run.assess'
   AND target_id = $3`, orgID, userID, assessed.DryRunID).Scan(&auditAssess); err != nil {
		t.Fatalf("query assess audit: %v", err)
	}
	if auditAssess != 1 {
		t.Fatalf("assess audit count=%d want 1", auditAssess)
	}

	clearReq := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/admission/dry-runs?cluster_id="+clusterID.String(), nil)
	clearReq = clearReq.WithContext(authctx.WithSubject(clearReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	clearRec := httptest.NewRecorder()
	NewPolicies(d, audit.New(pool), nil).ClearAdmissionDryRunHistory(clearRec, clearReq)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("clear status=%d body=%s", clearRec.Code, clearRec.Body.String())
	}
	var clearResp struct {
		Deleted int `json:"deleted"`
	}
	if err := json.Unmarshal(clearRec.Body.Bytes(), &clearResp); err != nil {
		t.Fatal(err)
	}
	if clearResp.Deleted != 1 {
		t.Fatalf("deleted=%d want 1", clearResp.Deleted)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int FROM admission_dry_run_history WHERE org_id = $1`, orgID).Scan(&remaining); err != nil {
		t.Fatalf("query remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining history rows=%d", remaining)
	}
	var auditClear int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int
  FROM audit_events
 WHERE org_id = $1
   AND actor_id = $2
   AND action = 'admission.dry-run.clear'
   AND target_id = $3`, orgID, userID, clusterID.String()).Scan(&auditClear); err != nil {
		t.Fatalf("query clear audit: %v", err)
	}
	if auditClear != 1 {
		t.Fatalf("clear audit count=%d want 1", auditClear)
	}
}
