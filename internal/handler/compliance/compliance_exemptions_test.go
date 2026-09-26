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

func TestComplianceExemptions_TenantAndClusterBoundaries(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := t.Context()
	ensureComplianceExemptionsTestTable(t, pool)

	orgA, orgB := uuid.New(), uuid.New()
	userA := uuid.New()
	clusterA, clusterB := uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Exemption Boundary')`, orgID, "exemption-boundary-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB) }()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Exemption Approver')`, userA, orgA, "exemption-"+userA.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'owned'), ($3, $4, 'foreign')`, clusterA, orgA, clusterB, orgB); err != nil {
		t.Fatal(err)
	}

	framework := "boundary-" + uuid.NewString()
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)
	var foreignID, misattributedID uuid.UUID
	for _, row := range []struct {
		orgID     uuid.UUID
		clusterID uuid.UUID
		id        *uuid.UUID
	}{
		{orgB, clusterB, &foreignID},
		{orgA, clusterB, &misattributedID},
	} {
		if err := pool.QueryRow(ctx, `
INSERT INTO compliance_exemptions (org_id, cluster_id, framework, control_id, reason, expires_at)
VALUES ($1, $2, $3, '1.1.1', 'existing boundary fixture', $4) RETURNING id`,
			row.orgID, row.clusterID, framework, expiresAt).Scan(row.id); err != nil {
			t.Fatal(err)
		}
	}

	h := NewCompliance(d, audit.New(pool))
	subject := authctx.Subject{UserID: userA, OrgID: orgA}
	create := func(clusterID string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{
			"cluster_id": clusterID, "framework": framework, "control_id": "1.1.1",
			"reason": "approved boundary fixture", "expires_at": expiresAt.Format(time.RFC3339),
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/exemptions", bytes.NewReader(body))
		req = req.WithContext(authctx.WithSubject(req.Context(), subject))
		resp := httptest.NewRecorder()
		h.CreateExemption(resp, req)
		return resp
	}
	list := func(url string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), subject))
		resp := httptest.NewRecorder()
		h.ListExemptions(resp, req)
		return resp
	}
	revoke := func(id uuid.UUID) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/exemptions/"+id.String()+"/revoke", nil)
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("id", id.String())
		req = req.WithContext(authctx.WithSubject(req.Context(), subject))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		resp := httptest.NewRecorder()
		h.RevokeExemption(resp, req)
		return resp
	}

	for _, clusterID := range []uuid.UUID{clusterB, uuid.New()} {
		if resp := create(clusterID.String()); resp.Code != http.StatusNotFound {
			t.Fatalf("create for unavailable cluster %s: %d: %s", clusterID, resp.Code, resp.Body.String())
		}
	}
	for _, clusterID := range []uuid.UUID{clusterB, uuid.New()} {
		resp := list("/api/v1/compliance/exemptions?cluster_id=" + clusterID.String())
		if resp.Code != http.StatusNotFound {
			t.Fatalf("list for unavailable cluster %s: %d: %s", clusterID, resp.Code, resp.Body.String())
		}
	}
	for _, id := range []uuid.UUID{foreignID, misattributedID} {
		if resp := revoke(id); resp.Code != http.StatusNotFound {
			t.Fatalf("revoke %s: %d: %s", id, resp.Code, resp.Body.String())
		}
	}

	for _, clusterID := range []string{"", clusterA.String()} {
		if resp := create(clusterID); resp.Code != http.StatusCreated {
			t.Fatalf("create valid cluster %q: %d: %s", clusterID, resp.Code, resp.Body.String())
		}
	}
	for _, url := range []string{
		"/api/v1/compliance/exemptions?framework=" + framework,
		"/api/v1/compliance/exemptions?framework=" + framework + "&cluster_id=" + clusterA.String(),
	} {
		resp := list(url)
		if resp.Code != http.StatusOK {
			t.Fatalf("list %s: %d: %s", url, resp.Code, resp.Body.String())
		}
		var result struct {
			Exemptions []complianceExemptionDTO `json:"exemptions"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if len(result.Exemptions) != 2 {
			t.Fatalf("list %s returned %d exemptions, want 2", url, len(result.Exemptions))
		}
		for _, exemption := range result.Exemptions {
			if exemption.ID == foreignID || exemption.ID == misattributedID {
				t.Fatalf("list %s exposed foreign cluster exemption %s", url, exemption.ID)
			}
		}
	}
	var rowCount, revokedCount, auditCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE revoked_at IS NOT NULL) FROM compliance_exemptions WHERE org_id = $1 AND framework = $2`, orgA, framework).Scan(&rowCount, &revokedCount); err != nil {
		t.Fatal(err)
	}
	if rowCount != 3 || revokedCount != 0 {
		t.Fatalf("org A rows = %d, revoked = %d; want 3 and 0", rowCount, revokedCount)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM compliance_exemptions WHERE id = $1 AND revoked_at IS NULL`, foreignID).Scan(&rowCount); err != nil {
		t.Fatal(err)
	}
	if rowCount != 1 {
		t.Fatalf("foreign exemption changed: rows = %d", rowCount)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE org_id = $1 AND action IN ('compliance.exemption.create', 'compliance.exemption.revoke')`, orgA).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 {
		t.Fatalf("audit events = %d, want only two successful creates", auditCount)
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
