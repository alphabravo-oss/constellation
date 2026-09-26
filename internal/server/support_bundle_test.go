package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
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

func TestSupportBundle_DownloadSignsRedactedSectionsAndIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "support-bundle-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_SUPPORT_BUNDLE_SIGNING_KEY_FILE", keyPath)
	_, server, _, signer, adminID, _, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	status, body := doJSON(t, http.MethodGet, server.URL+"/api/v1/support/bundle", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("signed support bundle status=%d body=%+v", status, body)
	}
	integrity, ok := body["integrity"].(map[string]any)
	if !ok || integrity["signed"] != true || integrity["signature_algorithm"] != "ed25519" {
		t.Fatalf("signed integrity = %+v", integrity)
	}
	sections, ok := body["sections"].(map[string]any)
	if !ok {
		t.Fatalf("sections = %+v", body["sections"])
	}
	sectionsJSON, err := json.Marshal(sections)
	if err != nil {
		t.Fatal(err)
	}
	sectionsHash := sha256.Sum256(sectionsJSON)
	if integrity["sha256"] != hex.EncodeToString(sectionsHash[:]) {
		t.Fatalf("signed sections hash = %+v", integrity)
	}
	if integrity["public_key"] != base64.StdEncoding.EncodeToString(publicKey) {
		t.Fatal("bundle public key does not match configured key")
	}
	keyHash := sha256.Sum256(publicKey)
	if integrity["key_id"] != hex.EncodeToString(keyHash[:]) {
		t.Fatal("bundle key ID does not match configured key")
	}
	signature, err := base64.StdEncoding.DecodeString(integrity["signature"].(string))
	if err != nil {
		t.Fatal(err)
	}
	generatedAt, err := time.Parse(time.RFC3339Nano, body["generated_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	signedPayload := strings.Join([]string{
		"constellation.support_bundle.signature.v1",
		body["schema_version"].(string),
		body["bundle_id"].(string),
		generatedAt.UTC().Format(time.RFC3339Nano),
		body["org_id"].(string),
		integrity["sha256"].(string),
	}, "\n")
	if !ed25519.Verify(publicKey, []byte(signedPayload), signature) {
		t.Fatal("support bundle signature failed against configured public key")
	}
	if ed25519.Verify(publicKey, []byte(signedPayload+"-tampered"), signature) {
		t.Fatal("support bundle signature accepted changed identity or sections")
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
