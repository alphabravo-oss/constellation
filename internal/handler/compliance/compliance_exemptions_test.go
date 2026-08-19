package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestComplianceExemptions_ApplyAndRevoke(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := t.Context()
	ensureComplianceExemptionsTestTable(t, pool)

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Compliance Exemption Org')`, orgID, "compliance-exemption-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Compliance Approver')`, userID, orgID, "compliance-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO compliance_checks (org_id, framework, control_id, title, description, status, severity, evidence)
VALUES ($1, 'cis-k8s-1.9', '1.1.1', 'API server pod spec', 'fixture', 'fail', 'high', 'kube-bench fixture')`, orgID); err != nil {
		t.Fatalf("insert compliance check: %v", err)
	}

	h := NewCompliance(d, audit.New(pool))
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	createBody, _ := json.Marshal(map[string]any{
		"framework":  "cis-k8s-1.9",
		"control_id": "1.1.1",
		"reason":     "approved compensating control for test",
		"expires_at": expiresAt,
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/exemptions", bytes.NewReader(createBody))
	createReq = createReq.WithContext(authctx.WithSubject(createReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	createResp := httptest.NewRecorder()
	h.CreateExemption(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create exemption status %d: %s", createResp.Code, createResp.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(created.ID); err != nil {
		t.Fatalf("created id is not uuid: %q", created.ID)
	}

	checks := complianceChecksForTest(t, h, orgID)
	if got := checks.Checks[0].EffectiveStatus; got != "exempted" {
		t.Fatalf("effective status after exemption = %q, want exempted", got)
	}
	if checks.Checks[0].Status != "fail" {
		t.Fatalf("raw status mutated to %q, want fail", checks.Checks[0].Status)
	}
	if checks.Checks[0].Exemption == nil || checks.Checks[0].Exemption.ID == "" {
		t.Fatalf("missing active exemption on check: %+v", checks.Checks[0])
	}
	summary := complianceSummaryForTest(t, h, orgID)
	if summary.Frameworks[0].Fail != 0 || summary.Frameworks[0].Exempted != 1 {
		t.Fatalf("summary after exemption = %+v, want fail=0 exempted=1", summary.Frameworks[0])
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/exemptions/"+created.ID+"/revoke", nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", created.ID)
	revokeReq = revokeReq.WithContext(authctx.WithSubject(revokeReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	revokeReq = revokeReq.WithContext(context.WithValue(revokeReq.Context(), chi.RouteCtxKey, routeCtx))
	revokeResp := httptest.NewRecorder()
	h.RevokeExemption(revokeResp, revokeReq)
	if revokeResp.Code != http.StatusOK {
		t.Fatalf("revoke exemption status %d: %s", revokeResp.Code, revokeResp.Body.String())
	}

	checks = complianceChecksForTest(t, h, orgID)
	if got := checks.Checks[0].EffectiveStatus; got != "fail" {
		t.Fatalf("effective status after revoke = %q, want fail", got)
	}
	summary = complianceSummaryForTest(t, h, orgID)
	if summary.Frameworks[0].Fail != 1 || summary.Frameworks[0].Exempted != 0 {
		t.Fatalf("summary after revoke = %+v, want fail=1 exempted=0", summary.Frameworks[0])
	}

	var auditCount int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*) FROM audit_events
 WHERE org_id = $1 AND action IN ('compliance.exemption.create', 'compliance.exemption.revoke')`, orgID).Scan(&auditCount); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditCount != 2 {
		t.Fatalf("audit events = %d, want 2", auditCount)
	}
}

func complianceChecksForTest(t *testing.T, h *Compliance, orgID uuid.UUID) struct {
	Checks []struct {
		Status          string `json:"status"`
		EffectiveStatus string `json:"effective_status"`
		Exemption       *struct {
			ID string `json:"id"`
		} `json:"exemption"`
	} `json:"checks"`
} {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/checks?framework=cis-k8s-1.9", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: uuid.New(), OrgID: orgID}))
	resp := httptest.NewRecorder()
	h.Checks(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("checks status %d: %s", resp.Code, resp.Body.String())
	}
	var got struct {
		Checks []struct {
			Status          string `json:"status"`
			EffectiveStatus string `json:"effective_status"`
			Exemption       *struct {
				ID string `json:"id"`
			} `json:"exemption"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Checks) != 1 {
		t.Fatalf("checks len = %d, want 1: %+v", len(got.Checks), got.Checks)
	}
	return got
}

func complianceSummaryForTest(t *testing.T, h *Compliance, orgID uuid.UUID) struct {
	Frameworks []struct {
		Fail     int `json:"fail"`
		Exempted int `json:"exempted"`
	} `json:"frameworks"`
} {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/summary", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: uuid.New(), OrgID: orgID}))
	resp := httptest.NewRecorder()
	h.Summary(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("summary status %d: %s", resp.Code, resp.Body.String())
	}
	var got struct {
		Frameworks []struct {
			Fail     int `json:"fail"`
			Exempted int `json:"exempted"`
		} `json:"frameworks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Frameworks) != 1 {
		t.Fatalf("summary len = %d, want 1: %+v", len(got.Frameworks), got.Frameworks)
	}
	return got
}

func ensureComplianceExemptionsTestTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
CREATE TABLE IF NOT EXISTS compliance_exemptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id  UUID REFERENCES clusters(id) ON DELETE CASCADE,
    framework   TEXT NOT NULL,
    control_id  TEXT NOT NULL,
    reason      TEXT NOT NULL,
    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`); err != nil {
		t.Fatalf("ensure compliance_exemptions: %v", err)
	}
}
