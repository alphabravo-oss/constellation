package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TestVEX_OpenVEXFromFindings proves SCAN-VEX-37: the handler builds an OpenVEX document
// from an asset's vulnerability findings, mapping lifecycle → VEX status.
func TestVEX_OpenVEXFromFindings(t *testing.T) {
	d := openTestDB(t)
	pool := d.Pool()
	ctx := context.Background()

	orgID := uuid.New()
	userID := uuid.New()
	assetID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'VEX Test')`,
		orgID, "vex-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,'VEX User')`,
		userID, orgID, "vex-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets (id, org_id, kind, name) VALUES ($1,$2,'image','vex.example/app:1.0')`,
		assetID, orgID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	// One suppressed finding (→ not_affected) and one open (→ under_investigation). The
	// 'workload' duplicate must be excluded from the document.
	seed := []struct{ ext, lifecycle, targetType string }{
		{"CVE-2024-0001", "suppressed", "image"},
		{"CVE-2024-0002", "open", "image"},
		{"CVE-2024-0002", "open", "workload"}, // duplicate — excluded
	}
	for _, s := range seed {
		if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, asset_id, kind, external_id, title, severity, lifecycle, target_type)
VALUES ($1,$2,'vulnerability',$3,$4,'high',$5,$6)`,
			orgID, assetID, s.ext, s.ext+" in app", s.lifecycle, s.targetType); err != nil {
			t.Fatalf("finding %s: %v", s.ext, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vex/openvex/"+assetID.String(), nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID, Email: "vex@example.com"}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("asset_id", assetID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	NewVEX(d).OpenVEX(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Author     string `json:"author"`
		Statements []struct {
			Status        string `json:"status"`
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Author != "vex@example.com" {
		t.Errorf("author = %q", doc.Author)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d, want 2 (workload duplicate excluded): %s", len(doc.Statements), rec.Body.String())
	}
	byCVE := map[string]string{}
	for _, s := range doc.Statements {
		byCVE[s.Vulnerability.Name] = s.Status
	}
	if byCVE["CVE-2024-0001"] != "not_affected" {
		t.Errorf("CVE-2024-0001 status = %q, want not_affected", byCVE["CVE-2024-0001"])
	}
	if byCVE["CVE-2024-0002"] != "under_investigation" {
		t.Errorf("CVE-2024-0002 status = %q, want under_investigation", byCVE["CVE-2024-0002"])
	}
}
