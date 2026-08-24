package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestNetworkRulesPortableExportImportAuthoredOverrides(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	sourceClusterID := uuid.New()
	targetClusterID := uuid.New()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Rules Portable Test')`,
		orgID, "network-rules-portable-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Network Rules Portable User')`,
		userID, orgID, "network-rules-portable-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, state)
VALUES ($1, $2, 'source-cluster', 'connected'),
       ($3, $2, 'target-cluster', 'connected')`,
		sourceClusterID, orgID, targetClusterID); err != nil {
		t.Fatalf("clusters: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_rule_overrides
  (org_id, cluster_id, from_ep, to_ep, ports, applications, action, disable, comment, priority, cfg_type, updated_by)
VALUES ($1, $2, 'prod/api', 'prod/db', 'tcp/5432', ARRAY['postgres','postgres'], 'deny', false, 'block direct db', 42, 'user_created', $3)`,
		orgID, sourceClusterID, userID); err != nil {
		t.Fatalf("override: %v", err)
	}

	router := chi.NewRouter()
	h := NewNetwork(d)
	router.Get("/clusters/{id}/network-rules:export", h.ExportNetworkRules)
	router.Post("/clusters/{id}/network-rules:import", h.ImportNetworkRules)

	req := httptest.NewRequest(http.MethodGet, "/clusters/"+sourceClusterID.String()+"/network-rules:export", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status: %d %s", rec.Code, rec.Body.String())
	}
	exported := rec.Body.String()
	if !strings.Contains(exported, "NetworkRuleBundle") || !strings.Contains(exported, "prod/api") || !strings.Contains(exported, "block direct db") {
		t.Fatalf("exported bundle missing rule: %s", exported)
	}

	req = httptest.NewRequest(http.MethodPost, "/clusters/"+targetClusterID.String()+"/network-rules:import", strings.NewReader(exported))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status: %d %s", rec.Code, rec.Body.String())
	}
	var importResp struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&importResp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if importResp.Created != 1 || importResp.Updated != 0 {
		t.Fatalf("import response = %+v", importResp)
	}
	var ports, action, comment, cfgType string
	var apps []string
	var priority int
	if err := pool.QueryRow(ctx, `
SELECT ports, applications, action, comment, priority, cfg_type
  FROM network_rule_overrides
 WHERE org_id=$1 AND cluster_id=$2 AND from_ep='prod/api' AND to_ep='prod/db'`,
		orgID, targetClusterID).Scan(&ports, &apps, &action, &comment, &priority, &cfgType); err != nil {
		t.Fatalf("imported override: %v", err)
	}
	if ports != "tcp/5432" || action != "deny" || comment != "block direct db" || priority != 42 || cfgType != "user_created" {
		t.Fatalf("imported row ports=%s action=%s comment=%s priority=%d cfg=%s", ports, action, comment, priority, cfgType)
	}
	if len(apps) != 1 || apps[0] != "postgres" {
		t.Fatalf("apps = %+v, want deduped postgres", apps)
	}
}
