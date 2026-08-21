package compliance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// kbRemediationSampleJSON is a kube-bench report whose FAIL control carries a
// per-control remediation string (CMP-REM-32). The parser captures it and the
// ingest must persist it so Checks can surface it.
const kbRemediationSampleJSON = `
{
  "Controls": [{
    "id":"1","text":"Master Node","tests":[
      {"section":"1.2","desc":"API Server","results":[
        {"test_number":"1.2.22","test_desc":"Ensure audit policy file is set","status":"FAIL","actual_value":"--audit-policy-file not set","scored":true,"remediation":"Edit the API server pod spec and set --audit-policy-file."}
      ]}
    ]
  }]
}`

// TestComplianceRemediation_PersistedAndReturned is the CMP-REM-32 regression:
// kube-bench parses a remediation string per control, and both the ingest INSERT
// and the Checks read DTO must carry it end-to-end.
func TestComplianceRemediation_PersistedAndReturned(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := t.Context()

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'CMP Rem Org')`, orgID, "cmp-rem-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'CMP Rem')`, userID, orgID, "cmp-rem-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'cluster-rem')`, clusterID, orgID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	h := NewCompliance(d, audit.New(pool))

	// Ingest.
	ingReq := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/ingest?profile=kube-bench&cluster_id="+clusterID.String(), bytes.NewReader([]byte(kbRemediationSampleJSON)))
	ingReq = ingReq.WithContext(authctx.WithSubject(ingReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	ingResp := httptest.NewRecorder()
	h.Ingest(ingResp, ingReq)
	if ingResp.Code != http.StatusOK {
		t.Fatalf("ingest status %d: %s", ingResp.Code, ingResp.Body.String())
	}

	// Persisted directly in the column.
	var stored string
	if err := pool.QueryRow(ctx, `
SELECT remediation FROM compliance_checks
 WHERE org_id=$1 AND cluster_id=$2 AND control_id='1.2.22'`, orgID, clusterID).Scan(&stored); err != nil {
		t.Fatalf("select remediation: %v", err)
	}
	if stored != "Edit the API server pod spec and set --audit-policy-file." {
		t.Fatalf("stored remediation = %q, want the parsed guidance", stored)
	}

	// Returned by the Checks read DTO.
	chkReq := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/checks?cluster_id="+clusterID.String(), nil)
	chkReq = chkReq.WithContext(authctx.WithSubject(chkReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	chkResp := httptest.NewRecorder()
	h.Checks(chkResp, chkReq)
	if chkResp.Code != http.StatusOK {
		t.Fatalf("checks status %d: %s", chkResp.Code, chkResp.Body.String())
	}
	var out struct {
		Checks []struct {
			ControlID   string `json:"control_id"`
			Remediation string `json:"remediation"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(chkResp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode checks: %v", err)
	}
	found := false
	for _, c := range out.Checks {
		if c.ControlID == "1.2.22" {
			found = true
			if c.Remediation != "Edit the API server pod spec and set --audit-policy-file." {
				t.Fatalf("checks remediation = %q, want the parsed guidance", c.Remediation)
			}
		}
	}
	if !found {
		t.Fatalf("control 1.2.22 not returned by Checks; body=%s", chkResp.Body.String())
	}
}
