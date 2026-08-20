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

func TestDashboard_SummaryAggregates(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	assetID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Dash Test')`,
		orgID, "dash-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', 'ghcr.io/test/dash', 'sha256:dash', '{}'::jsonb, 'high')`, assetID, orgID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	for _, sev := range []string{"high", "critical", "medium"} {
		if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, asset_id, kind, external_id, title, description, severity, risk_score, lifecycle)
VALUES ($1, $2, 'vulnerability', $3, $4, $4, $5, 80, 'open')`,
			orgID, assetID, "CVE-2099-"+sev, "dash "+sev, sev); err != nil {
			t.Fatalf("finding %s: %v", sev, err)
		}
	}

	req := httptest.NewRequest("GET", "/api/v1/dashboard/summary", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewDashboard(d).Summary(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
	var got dashboardSummaryDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.FindingsTotal != 3 {
		t.Fatalf("expected 3 findings, got %d (severity rollup=%v)", got.FindingsTotal, got.FindingsByLevel)
	}
	if got.OpenFindings != 3 {
		t.Fatalf("expected 3 open findings, got %d", got.OpenFindings)
	}

	// A resolved/accepted finding must NOT inflate the severity rollup — the tiles
	// count OPEN posture only (they link to the open findings view). Insert a
	// resolved critical and confirm FindingsTotal and the critical bucket are
	// unchanged.
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, asset_id, kind, external_id, title, description, severity, risk_score, lifecycle)
VALUES ($1, $2, 'vulnerability', 'CVE-2099-resolved', 'dash resolved', 'dash resolved', 'critical', 90, 'resolved')`,
		orgID, assetID); err != nil {
		t.Fatalf("resolved finding: %v", err)
	}
	w = httptest.NewRecorder()
	NewDashboard(d).Summary(w, req)
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode 2: %v", err)
	}
	if got.FindingsTotal != 3 {
		t.Fatalf("resolved finding must not inflate severity rollup; got total=%d rollup=%v", got.FindingsTotal, got.FindingsByLevel)
	}
	if got.FindingsByLevel["critical"] != 1 {
		t.Fatalf("expected 1 OPEN critical, got %d", got.FindingsByLevel["critical"])
	}
	if got.AssetsTotal < 1 {
		t.Fatalf("expected at least 1 asset, got %d", got.AssetsTotal)
	}
}

func TestSettings_OrgRoundtrip(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Settings Test')`,
		orgID, "settings-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}

	h := NewSettings(d, nil)

	// Patch.
	body := strings.NewReader(`{"theme":"dark","ai_enabled":true}`)
	req := httptest.NewRequest("PATCH", "/api/v1/settings/org", body)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h.PatchOrg(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}

	// Get.
	req = httptest.NewRequest("GET", "/api/v1/settings/org", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w = httptest.NewRecorder()
	h.GetOrg(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Settings["theme"] != "dark" {
		t.Fatalf("expected theme=dark, got %+v", got.Settings)
	}
}
