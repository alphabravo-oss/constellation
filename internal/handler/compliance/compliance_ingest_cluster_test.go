package compliance

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// kbClusterSampleJSON is a minimal kube-bench report: one FAIL control the
// parser maps to CIS-K8s 1.2.22 (mirrors pkg/compliance's kbSampleJSON).
const kbClusterSampleJSON = `
{
  "Controls": [{
    "id":"1","text":"Master Node","tests":[
      {"section":"1.2","desc":"API Server","results":[
        {"test_number":"1.2.22","test_desc":"Ensure audit policy file is set","status":"FAIL","actual_value":"--audit-policy-file not set","scored":true}
      ]}
    ]
  }]
}`

// TestComplianceIngest_PerClusterNoClobber is the CMP-CLOBBER-03 regression: the
// same kube-bench control ingested from two clusters in one org must yield two
// rows (one per cluster), not a single clobbered row. Before migration 136 the
// upsert keyed on the partial index (org_id, framework, control_id) WHERE
// cluster_id IS NULL, so the second cluster's scan overwrote the first's.
func TestComplianceIngest_PerClusterNoClobber(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := t.Context()

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'CMP Clobber Org')`, orgID, "cmp-clobber-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'CMP Clobber')`, userID, orgID, "cmp-clobber-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	clusterA := uuid.New()
	clusterB := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'cluster-a'), ($3, $2, 'cluster-b')`, clusterA, orgID, clusterB); err != nil {
		t.Fatalf("insert clusters: %v", err)
	}

	h := NewCompliance(d, audit.New(pool))

	ingest := func(clusterID uuid.UUID) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/ingest?profile=kube-bench&cluster_id="+clusterID.String(), bytes.NewReader([]byte(kbClusterSampleJSON)))
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		resp := httptest.NewRecorder()
		h.Ingest(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("ingest for cluster %s status %d: %s", clusterID, resp.Code, resp.Body.String())
		}
	}

	// Ingest the identical control from both clusters, twice each — a re-run must
	// refresh in place per-cluster, never clobber the other cluster's row.
	ingest(clusterA)
	ingest(clusterB)
	ingest(clusterA)

	// Exactly one row per cluster for the shared control: two rows, two clusters.
	var rowCount, clusterCount int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*), COUNT(DISTINCT cluster_id)
  FROM compliance_checks
 WHERE org_id = $1 AND framework = $2 AND control_id = '1.2.22'`,
		orgID, compliancepkg.FrameworkCISK8s).Scan(&rowCount, &clusterCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 2 {
		t.Fatalf("control 1.2.22 row count = %d, want 2 (one per cluster; got a clobber or a duplicate)", rowCount)
	}
	if clusterCount != 2 {
		t.Fatalf("control 1.2.22 distinct cluster count = %d, want 2", clusterCount)
	}

	// And each cluster owns exactly one of them.
	for _, cid := range []uuid.UUID{clusterA, clusterB} {
		var n int
		if err := pool.QueryRow(ctx, `
SELECT COUNT(*) FROM compliance_checks
 WHERE org_id = $1 AND framework = $2 AND control_id = '1.2.22' AND cluster_id = $3`,
			orgID, compliancepkg.FrameworkCISK8s, cid).Scan(&n); err != nil {
			t.Fatalf("count for cluster %s: %v", cid, err)
		}
		if n != 1 {
			t.Fatalf("cluster %s has %d rows for control 1.2.22, want 1", cid, n)
		}
	}
}
