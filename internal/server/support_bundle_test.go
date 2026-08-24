package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSupportBundle_DownloadRedactedRBACAndAudit(t *testing.T) {
	_, ts, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	ctx := context.Background()
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)

	caPEM := testCAPEM(t)
	st, body := doJSON(t, http.MethodPatch, ts.URL+"/api/v1/system/config", admin, map[string]any{
		"egress_proxy":  map[string]any{"https_proxy": "https://alice:hunter2@proxy.test:3128"},
		"ca_bundle_pem": caPEM,
		"nvd_api_key":   "nvd-secret-key",
		"smtp": map[string]any{
			"host":     "smtp.test",
			"port":     587,
			"from":     "alerts@example.test",
			"password": "smtp-secret-password",
		},
	})
	if st != http.StatusOK {
		t.Fatalf("config patch status = %d body=%+v, want 200", st, body)
	}

	if st, _ := doJSON(t, http.MethodGet, ts.URL+"/api/v1/support/bundle", auditor, nil); st != http.StatusForbidden {
		t.Fatalf("auditor support bundle = %d, want 403", st)
	}

	st, body = doJSON(t, http.MethodGet, ts.URL+"/api/v1/support/bundle", admin, nil)
	if st != http.StatusOK {
		t.Fatalf("admin support bundle = %d body=%+v, want 200", st, body)
	}
	if got, _ := body["schema_version"].(string); got != "constellation.support_bundle.v1" {
		t.Fatalf("schema_version = %q body=%+v", got, body)
	}
	sections, _ := body["sections"].(map[string]any)
	if len(sections) == 0 || sections["system_config"] == nil || sections["system_health"] == nil || sections["component_inventory"] == nil {
		t.Fatalf("support bundle missing expected sections: %+v", body)
	}
	integrity, _ := body["integrity"].(map[string]any)
	if integrity == nil || integrity["sha256"] == "" || integrity["signed"] != false {
		t.Fatalf("support bundle integrity metadata = %+v", integrity)
	}

	raw, _ := json.Marshal(body)
	payload := string(raw)
	for _, forbidden := range []string{"hunter2", "alice", caPEM, "nvd-secret-key", "smtp-secret-password"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("support bundle leaked %q in %s", forbidden, payload)
		}
	}
	if !strings.Contains(payload, "***REDACTED***") {
		t.Fatalf("support bundle missing redaction markers: %s", payload)
	}

	var auditRows int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int
  FROM audit_events
 WHERE org_id = $1
   AND actor_id = $2
   AND action = 'support.bundle.download'`, orgID, adminID).Scan(&auditRows); err != nil {
		t.Fatalf("count support bundle audit rows: %v", err)
	}
	if auditRows == 0 {
		t.Fatalf("support bundle download was not audited")
	}
}

func TestComponentsDiagnostics_RBACRequiresAdmin(t *testing.T) {
	_, ts, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	ctx := context.Background()

	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.component_heartbeats')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: component_heartbeats migration not applied (%v)", err)
	}

	heartbeatID := uuid.New()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats (
    id, org_id, cluster_id, component, version, commit, hostname,
    uptime_seconds, restart_count, metadata, last_seen_at, first_seen_at
) VALUES ($1, $2, NULL, 'scanner', 'test', 'abcdef123456', 'scanner-rbac',
          120, 0, '{"active_jobs":0,"idle_capacity":1,"max_concurrent":1}'::jsonb, $3, $3)`,
		heartbeatID, orgID, now); err != nil {
		t.Fatalf("insert component heartbeat: %v", err)
	}

	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	path := ts.URL + "/api/v1/components/" + heartbeatID.String() + "/diagnostics"
	if st, body := doJSON(t, http.MethodGet, path, admin, nil); st != http.StatusOK {
		t.Fatalf("admin diagnostics = %d body=%+v, want 200", st, body)
	}
	if st, _ := doJSON(t, http.MethodGet, path, auditor, nil); st != http.StatusForbidden {
		t.Fatalf("auditor diagnostics = %d, want 403", st)
	}
}
