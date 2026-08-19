package compliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

func TestComplianceEvidence_AllScopesAndExemptions(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := t.Context()
	ensureComplianceExemptionsTestTable(t, pool)
	ensureNetworkPolicyLifecycleTables(t, pool)
	for _, table := range []string{"image_workload_links", "image_scan_results", "image_scan_artifacts"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	deploymentID := uuid.New()
	imageResultID := uuid.New()
	assetID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	imageDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imageRef := "registry.example.test/default/api@" + imageDigest
	t.Cleanup(func() {
		_, _ = pool.Exec(t.Context(), `DELETE FROM findings WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(t.Context(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Compliance Evidence Org')`, orgID, "compliance-evidence-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Compliance Evidence User')`, userID, orgID, "evidence-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, $3, 'connected')`, clusterID, orgID, "evidence-"+clusterID.String()); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO compliance_checks (org_id, cluster_id, framework, control_id, title, description, status, severity, evidence)
VALUES ($1, $2, 'cis-k8s-1.9', '1.2.22', 'API audit logging', 'fixture', 'pass', 'high', 'audit-policy-file set')`,
		orgID, clusterID); err != nil {
		t.Fatalf("insert compliance check: %v", err)
	}
	hostPayload := map[string]any{
		"node":        "node-a",
		"profile":     "cis-distro-linux-min",
		"observed_at": now,
		"checks": []map[string]any{
			{"id": "3.2.1", "title": "Source routed packets are not accepted", "result": "fail", "detail": "net.ipv4.conf.all.accept_source_route=1"},
			{"id": "3.3.1", "title": "TCP SYN cookies are enabled", "result": "pass", "detail": "net.ipv4.tcp_syncookies=1"},
		},
	}
	hostRaw, _ := json.Marshal(hostPayload)
	if _, err := pool.Exec(ctx, `
INSERT INTO host_cis (org_id, cluster_id, node, profile, passed, failed, warned, skipped, payload, observed_at)
VALUES ($1, $2, 'node-a', 'cis-distro-linux-min', 1, 1, 0, 0, $3, $4)`,
		orgID, clusterID, hostRaw, now); err != nil {
		t.Fatalf("insert host_cis: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO compliance_exemptions (org_id, cluster_id, framework, control_id, reason, approved_by, expires_at)
VALUES ($1, $2, $3, '3.2.1', 'approved test compensating control', $4, $5)`,
		orgID, clusterID, compliancepkg.FrameworkCISLinux, userID, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert exemption: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count, critical_count, high_count, image_refs, last_seen_at)
VALUES ($1, $2, $3, 'default', 'api', 'Deployment', '{}'::jsonb, 91, '{}'::jsonb, 2, 1, 1, $4, $5)`,
		deploymentID, orgID, clusterID, []string{imageRef}, now); err != nil {
		t.Fatalf("insert deployment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest, last_seen_at
) VALUES ($1, $2, $3, 'default/api', 'default', 'api', 'Deployment',
          $4, $4, 'registry.example.test/default/api', '', $5, $6)`,
		orgID, clusterID, deploymentID, imageRef, imageDigest, now); err != nil {
		t.Fatalf("insert image workload link: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
    id, org_id, image_ref, image_ref_normalized, image_repository, image_tag,
    image_digest, platform, scanner_profile, vulndb_bundle_version,
    vulndb_bundle_hash, package_count, finding_count, last_scanned_at
) VALUES ($1, $2, $3, $3, 'registry.example.test/default/api', '',
          $4, 'linux/amd64', 'default', 'fixture-20260614',
          'sha256:bundle', 7, 0, $5)`,
		imageResultID, orgID, imageRef, imageDigest, now); err != nil {
		t.Fatalf("insert image scan result: %v", err)
	}
	secretPayload, _ := json.Marshal(map[string]any{
		"schema_version": "constellation.image-secrets.v1",
		"image_ref":      imageRef,
		"image_digest":   imageDigest,
		"status":         "observed",
		"engine":         "trivy",
		"secret_count":   1,
		"secrets": []map[string]any{{
			"engine":   "trivy",
			"rule_id":  "aws-access-key-id",
			"severity": "high",
			"path":     "app/config.py",
		}},
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_artifacts (
    org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES ($1, $2, 'secret-scan', 'constellation-image-secrets-v1', $3::jsonb, 'sha256:secret-fixture', 1)`,
		orgID, imageResultID, string(secretPayload)); err != nil {
		t.Fatalf("insert secret artifact: %v", err)
	}
	fileRiskPayload, _ := json.Marshal(map[string]any{
		"schema_version":  "constellation.image-file-risk.v1",
		"image_ref":       imageRef,
		"image_digest":    imageDigest,
		"status":          "observed",
		"file_risk_count": 1,
		"findings": []map[string]any{{
			"path":       "/usr/bin/suid-helper",
			"severity":   "high",
			"risk_types": []string{"setuid"},
		}},
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_artifacts (
    org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES ($1, $2, 'file-risk', 'constellation-image-file-risk-v1', $3::jsonb, 'sha256:file-risk-fixture', 1)`,
		orgID, imageResultID, string(fileRiskPayload)); err != nil {
		t.Fatalf("insert file-risk artifact: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_policy_lifecycle_states (org_id, cluster_id, workload, namespace, current_mode, target_mode, approval_status, reason, preview_yaml, preview_manifests)
VALUES ($1, $2, 'default/api', 'default', 'protect', 'protect', 'applied', 'test', 'kind: NetworkPolicy', '{"native":"kind: NetworkPolicy"}'::jsonb)`,
		orgID, clusterID); err != nil {
		t.Fatalf("insert policy lifecycle: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_policy_apply_status (org_id, cluster_id, workload, namespace, flavor, resource_ref, desired_mode, approval_status, last_action, status, updated_at)
VALUES ($1, $2, 'default/api', 'default', 'native', 'NetworkPolicy/default/api', 'protect', 'applied', 'apply', 'ok', $3)`,
		orgID, clusterID, now); err != nil {
		t.Fatalf("insert policy apply status: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, cluster_id, kind, name, labels, criticality, last_seen_at)
VALUES ($1, $2, $3, 'cloud-resource', 'arn:aws:s3:::public-test', '{}'::jsonb, 'high', $4)`,
		assetID, orgID, clusterID, now); err != nil {
		t.Fatalf("insert cloud asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, cluster_id, asset_id, kind, external_id, title, description, severity, risk_score, lifecycle, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, 'cloud-config', 'AWS-S3-PUBLIC', 'Public S3 bucket', 'bucket allows public read', 'high', 90, 'open', $4, $4)`,
		orgID, clusterID, assetID, now); err != nil {
		t.Fatalf("insert cloud finding: %v", err)
	}

	h := NewCompliance(d, audit.New(pool))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	resp := httptest.NewRecorder()
	h.Evidence(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("evidence status %d: %s", resp.Code, resp.Body.String())
	}
	var got struct {
		Items []struct {
			Scope           string `json:"scope"`
			Source          string `json:"source"`
			Framework       string `json:"framework"`
			ControlID       string `json:"control_id"`
			InternalID      string `json:"internal_id"`
			EffectiveStatus string `json:"effective_status"`
			Target          string `json:"target"`
		} `json:"items"`
		Summary struct {
			Total    int `json:"total"`
			Exempted int `json:"exempted"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Total == 0 {
		t.Fatalf("expected evidence rows, got none")
	}
	wantScopes := map[string]bool{"kubernetes": false, "node": false, "workload": false, "cloud": false}
	var exemptedHost bool
	var appliedPolicy bool
	var imageSecretsFail bool
	var imageFileRiskFail bool
	for _, item := range got.Items {
		if _, ok := wantScopes[item.Scope]; ok {
			wantScopes[item.Scope] = true
		}
		if item.Framework == compliancepkg.FrameworkCISLinux && item.ControlID == "3.2.1" && item.EffectiveStatus == "exempted" {
			exemptedHost = true
		}
		if item.Scope == "workload" && item.Source == "network_policy_lifecycle" && item.Target == "default/api" && item.EffectiveStatus == "pass" {
			appliedPolicy = true
		}
		if item.Scope == "workload" && item.Source == "image_scan_artifacts" && item.InternalID == "container.image-secrets-absent" && item.EffectiveStatus == "fail" {
			imageSecretsFail = true
		}
		if item.Scope == "workload" && item.Source == "image_scan_artifacts" && item.InternalID == "container.image-file-risks-absent" && item.EffectiveStatus == "fail" {
			imageFileRiskFail = true
		}
	}
	for scope, found := range wantScopes {
		if !found {
			t.Fatalf("missing %s evidence in %+v", scope, got.Items)
		}
	}
	if !exemptedHost || got.Summary.Exempted == 0 {
		t.Fatalf("missing exempted host evidence: summary=%+v items=%+v", got.Summary, got.Items)
	}
	if !appliedPolicy {
		t.Fatalf("missing applied workload policy evidence: %+v", got.Items)
	}
	if !imageSecretsFail || !imageFileRiskFail {
		t.Fatalf("missing image artifact compliance evidence: secrets=%v fileRisk=%v items=%+v", imageSecretsFail, imageFileRiskFail, got.Items)
	}
}
