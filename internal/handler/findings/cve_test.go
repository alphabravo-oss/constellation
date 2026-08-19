package findings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestCVE_AffectedUsesCanonicalImageResults(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	deploymentID := uuid.New()
	assetID := uuid.New()
	resultID := uuid.New()
	findingID := uuid.New()
	cveID := "CVE-2026-5150"
	digest := "sha256:cveaffected5150"
	imageRef := "registry.example.test/payments/api@" + digest

	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'CVE Affected Test')`, orgID, "cve-affected-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state)
VALUES ($1, $2, 'local-k3s', 'k3s', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', 'registry.example.test/payments/api', $3, '{}'::jsonb, 'high')`, assetID, orgID, digest); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind, image_refs)
VALUES ($1, $2, $3, 'payments', 'api', 'Deployment', $4)`, deploymentID, orgID, clusterID, []string{imageRef}); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest
) VALUES ($1, $2, $3, 'payments/api', 'payments', 'api', 'Deployment',
          $4, $4, 'registry.example.test/payments/api', '', $5)`,
		orgID, clusterID, deploymentID, imageRef, digest); err != nil {
		t.Fatalf("image workload link: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
    id, org_id, asset_id, image_ref, image_ref_normalized, image_repository,
    image_tag, image_digest, platform, scanner_profile, package_count, finding_count,
    vulndb_bundle_version, vulndb_bundle_hash
) VALUES ($1, $2, $3, $4, $4, 'registry.example.test/payments/api',
          '', $5, 'linux/amd64', 'default', 12, 1, 'fixture-20260613', 'sha256:bundle')`,
		resultID, orgID, assetID, imageRef, digest); err != nil {
		t.Fatalf("image scan result: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (
    id, org_id, image_scan_result_id, finding_key, external_id, title, description,
    severity, risk_score, canonical_engine, engines, package_ecosystem, package_name,
    package_version, fixed_version, detail_json
) VALUES ($1, $2, $3, 'fixture:key', $4, 'openssl vuln', 'openssl vuln',
          'critical', 96, 'vulndb', '[]'::jsonb, 'deb', 'openssl', '3.0.0', '3.0.2', '{}'::jsonb)`,
		findingID, orgID, resultID, cveID); err != nil {
		t.Fatalf("image scan finding: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cve/"+cveID+"/affected", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", cveID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	NewCVE(d, "").Affected(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		CVEID     string                   `json:"cve_id"`
		Summary   cveAffectedSummaryDTO    `json:"summary"`
		Images    []cveAffectedImageDTO    `json:"images"`
		Workloads []cveAffectedWorkloadDTO `json:"workloads"`
		Clusters  []cveAffectedClusterDTO  `json:"clusters"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.CVEID != cveID || got.Summary.ImageCount != 1 || got.Summary.WorkloadCount != 1 || got.Summary.ClusterCount != 1 {
		t.Fatalf("summary = %+v cve=%s", got.Summary, got.CVEID)
	}
	if len(got.Images) != 1 || got.Images[0].ImageScanResultID != resultID || got.Images[0].Packages[0].PackageName != "openssl" {
		t.Fatalf("images = %+v", got.Images)
	}
	if len(got.Workloads) != 1 || got.Workloads[0].ClusterID != clusterID || got.Workloads[0].DeploymentID != deploymentID {
		t.Fatalf("workloads = %+v", got.Workloads)
	}
	if len(got.Clusters) != 1 || got.Clusters[0].ClusterID != clusterID || got.Clusters[0].MaxRiskScore != 96 {
		t.Fatalf("clusters = %+v", got.Clusters)
	}
}
