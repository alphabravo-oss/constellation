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

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestResponseRules_ListReturnsCatalog(t *testing.T) {
	w := httptest.NewRecorder()
	NewResponseRules().List(w, httptest.NewRequest("GET", "/api/v1/response-rules", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}

	var got struct {
		Rules   []responseRuleDTO `json:"rules"`
		Summary struct {
			Total   int `json:"total"`
			Enabled int `json:"enabled"`
			Monitor int `json:"monitor"`
			Enforce int `json:"enforce"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Rules) < 5 {
		t.Fatalf("expected seeded response rules, got %d", len(got.Rules))
	}
	if got.Summary.Total != len(got.Rules) || got.Summary.Enabled == 0 || got.Summary.Monitor == 0 || got.Summary.Enforce == 0 {
		t.Fatalf("unexpected summary: %+v", got.Summary)
	}
	for _, rule := range got.Rules {
		if rule.ID == "" || rule.Name == "" || rule.EventType == "" || rule.Match == "" || rule.Mode == "" || rule.Severity == "" {
			t.Fatalf("incomplete response rule: %+v", rule)
		}
		if len(rule.Actions) == 0 {
			t.Fatalf("missing actions for %s", rule.ID)
		}
	}
}

func TestResponseRules_UpdatePersistsOverrideAndAudit(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	ensureResponseRuleTables(t, pool)

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Response Rule Org')`, orgID, "response-rules-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Runtime Operator')`, userID, orgID, "response-rules-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	r := chi.NewRouter()
	h := NewResponseRules(d, audit.New(pool))
	r.Get("/api/v1/response-rules", h.List)
	r.Post("/api/v1/response-rules/{id}/preview", h.Preview)
	r.Patch("/api/v1/response-rules/{id}", h.Update)

	previewReq := httptest.NewRequest("POST", "/api/v1/response-rules/dlp-secret-exfiltration/preview", strings.NewReader(`{"mode":"enforce","enabled":true,"reason":"pilot DLP enforcement"}`))
	previewReq = previewReq.WithContext(authctx.WithSubject(previewReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	previewResp := httptest.NewRecorder()
	r.ServeHTTP(previewResp, previewReq)
	if previewResp.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", previewResp.Code, previewResp.Body.String())
	}
	if !strings.Contains(previewResp.Body.String(), `"persists":false`) || !strings.Contains(previewResp.Body.String(), "privileged Linux runtime agent") {
		t.Fatalf("unexpected preview: %s", previewResp.Body.String())
	}

	updateReq := httptest.NewRequest("PATCH", "/api/v1/response-rules/dlp-secret-exfiltration", strings.NewReader(`{"mode":"enforce","enabled":true,"reason":"pilot DLP enforcement"}`))
	updateReq = updateReq.WithContext(authctx.WithSubject(updateReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	updateResp := httptest.NewRecorder()
	r.ServeHTTP(updateResp, updateReq)
	if updateResp.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updateResp.Code, updateResp.Body.String())
	}

	listReq := httptest.NewRequest("GET", "/api/v1/response-rules", nil)
	listReq = listReq.WithContext(authctx.WithSubject(listReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	listResp := httptest.NewRecorder()
	r.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listResp.Code, listResp.Body.String())
	}
	var got struct {
		Rules   []responseRuleDTO `json:"rules"`
		Summary struct {
			Managed int `json:"managed"`
			Enforce int `json:"enforce"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rule, ok := findResponseRule("dlp-secret-exfiltration", got.Rules)
	if !ok || rule.Mode != "enforce" || !rule.Enabled || !rule.Managed || !rule.Drifted || !strings.Contains(rule.OverrideReason, "pilot") {
		t.Fatalf("override not reflected in list: %+v", rule)
	}
	if got.Summary.Managed != 1 || got.Summary.Enforce < 2 {
		t.Fatalf("summary did not include override: %+v", got.Summary)
	}
	var auditEvents int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE org_id = $1 AND action = 'response_rule.update' AND target_id = 'dlp-secret-exfiltration'`, orgID).Scan(&auditEvents); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditEvents != 1 {
		t.Fatalf("expected response rule audit event, got %d", auditEvents)
	}
}

func TestResponseRules_UpdateRequiresReason(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ensureResponseRuleTables(t, pool)

	r := chi.NewRouter()
	h := NewResponseRules(d)
	r.Patch("/api/v1/response-rules/{id}", h.Update)
	req := httptest.NewRequest("PATCH", "/api/v1/response-rules/network-unauthorized-egress", strings.NewReader(`{"mode":"monitor","enabled":true}`))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: uuid.New(), OrgID: uuid.New()}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "reason is required") {
		t.Fatalf("expected reason guard, got %d body=%s", w.Code, w.Body.String())
	}
}

func ensureResponseRuleTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS response_rule_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('learn', 'monitor', 'enforce')),
    enabled BOOLEAN NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, rule_id)
);`); err != nil {
		t.Fatalf("response rule tables: %v", err)
	}
}
