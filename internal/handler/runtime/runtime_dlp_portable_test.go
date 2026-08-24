package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestRuntimeDLPPortableSeparatesDLPAndSignatures(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	importClusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Runtime Portable Org')`, orgID, "runtime-portable-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Runtime Portable Admin')`, userID, orgID, "runtime-portable-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, 'portable-source', 'k3s', 'connected'), ($3, $2, 'portable-import', 'k3s', 'connected')`, clusterID, orgID, importClusterID); err != nil {
		t.Fatalf("clusters: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM runtime_dlp_rules WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM clusters WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM users WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM orgs WHERE id=$1`, orgID)
	})

	store := NewRuntimeDLPStore(d, nil)
	insertRule := func(name string, category DLPCategory, applyDir int16, patterns string) {
		t.Helper()
		if _, err := store.Insert(ctx, &DLPRule{
			OrgID: orgID, ClusterID: clusterID, Name: name,
			Category: category, ApplyDir: applyDir, Severity: 6, Mode: DLPModeMonitor,
			Patterns: json.RawMessage(patterns),
		}, "portable-test"); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}
	insertRule("portable-dlp", CategoryDLP, 1, `["secret"]`)
	insertRule("portable-signature", CategorySignature, 3, `[{"pattern":"(?i)cmd","op":"regex","context":"packet"}]`)
	insertRule("portable-waf", CategoryWAF, 2, `[{"pattern":"(?i)union select","op":"regex","context":"uri"}]`)

	subject := authctx.Subject{OrgID: orgID, UserID: userID}
	dlpExport := httptest.NewRecorder()
	dlpReq := httptest.NewRequest(http.MethodGet, "/api/v1/runtime-dlp-rules:export?cluster_id="+clusterID.String(), nil)
	dlpReq = dlpReq.WithContext(authctx.WithSubject(dlpReq.Context(), subject))
	NewRuntimeDLPHTTP(d, nil).Export(dlpExport, dlpReq)
	if dlpExport.Code != http.StatusOK {
		t.Fatalf("dlp export status=%d body=%s", dlpExport.Code, dlpExport.Body.String())
	}
	if body := dlpExport.Body.String(); !strings.Contains(body, "portable-dlp") || strings.Contains(body, "portable-waf") || strings.Contains(body, "portable-signature") {
		t.Fatalf("dlp export category filtering failed:\n%s", body)
	}

	sigExport := httptest.NewRecorder()
	sigReq := httptest.NewRequest(http.MethodGet, "/api/v1/runtime-signatures:export?cluster_id="+clusterID.String(), nil)
	sigReq = sigReq.WithContext(authctx.WithSubject(sigReq.Context(), subject))
	NewRuntimeSignaturesHTTP(d, nil).Export(sigExport, sigReq)
	if sigExport.Code != http.StatusOK {
		t.Fatalf("signature export status=%d body=%s", sigExport.Code, sigExport.Body.String())
	}
	if body := sigExport.Body.String(); !strings.Contains(body, "DPISignatureBundle") ||
		!strings.Contains(body, "portable-waf") ||
		!strings.Contains(body, "portable-signature") ||
		strings.Contains(body, "portable-dlp") ||
		!strings.Contains(body, "context: uri") {
		t.Fatalf("signature export did not preserve expected rows/context:\n%s", body)
	}

	importBody := `apiVersion: constellation/v1
kind: DPISignatureBundle
rules:
  - name: imported-waf
    category: waf
    apply_dir: 2
    severity: 6
    mode: monitor
    patterns:
      - pattern: "(?i)union select"
        op: regex
        context: uri
`
	importRec := httptest.NewRecorder()
	importReq := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-signatures:import?cluster_id="+importClusterID.String(), strings.NewReader(importBody))
	importReq = importReq.WithContext(authctx.WithSubject(importReq.Context(), subject))
	NewRuntimeSignaturesHTTP(d, nil).Import(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("signature import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var category, patterns, source, cfgType string
	if err := pool.QueryRow(ctx, `
SELECT category, patterns::text, source, cfg_type
  FROM runtime_dlp_rules
 WHERE org_id=$1 AND cluster_id=$2 AND name='imported-waf'`, orgID, importClusterID).Scan(&category, &patterns, &source, &cfgType); err != nil {
		t.Fatalf("imported waf row: %v", err)
	}
	if category != string(CategoryWAF) || !strings.Contains(patterns, "uri") || !strings.Contains(patterns, "union select") {
		t.Fatalf("import lost waf category/context: category=%s patterns=%s", category, patterns)
	}
	if source != "import" || cfgType != "imported" {
		t.Fatalf("import provenance = %s/%s, want import/imported", source, cfgType)
	}
}
