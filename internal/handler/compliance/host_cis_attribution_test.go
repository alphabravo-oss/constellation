package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestHostCISRejectsCrossTenantBundleAttribution(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgA, orgB := uuid.New(), uuid.New()
	clusterB := uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "cis-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN ($1, $2)`, orgA, orgB)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'foreign')`, clusterB, orgB); err != nil {
		t.Fatal(err)
	}
	raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgA, "cis-scope-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO cluster_init_bundles
  (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`,
		orgA, clusterB, "cis-scope-"+uuid.NewString(), tokenID); err != nil {
		t.Fatal(err)
	}
	node := "cis-scope-" + uuid.NewString()
	body, err := json.Marshal(HostCISPayload{Node: node})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host-cis:report", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(NewHostCIS(d).Report)).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("report status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM host_cis WHERE node = $1`, node).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("cross-tenant report persisted %d host_cis rows", count)
	}
}
