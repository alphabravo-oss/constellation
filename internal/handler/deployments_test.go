package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestDeploymentsGetIncludesWorkloadEvidenceAggregate(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"deployments", "image_workload_links", "image_scan_results", "image_scan_artifacts", "scan_evidence", "events", "runtime_threats", "network_flows", "pod_workload_links", "pod_ips", "network_policy_lifecycle_states", "quarantine_entries", "process_baseline_states", "process_baseline_transitions", "file_profile_states", "file_profile_transitions", "file_profile_rules", "file_profile_watch_inventory"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	deploymentID := uuid.New()
	otherDeploymentID := uuid.New()
	assetID := uuid.New()
	scanTargetID := uuid.New()
	prefixSiblingScanTargetID := uuid.New()
	imageResultID := uuid.New()
	otherImageResultID := uuid.New()
	now := time.Now().UTC()
	workloadID := "payments/api"
	podWorkloadID := "payments/pod/api-7d9c"
	prefixSiblingWorkloadID := "payments/pod/api-worker-6f7d"
	imageRef := "registry.local/payments/api@sha256:abcdef"
	otherImageRef := "registry.local/payments/other-api@sha256:123456"

	_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, orgID)
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Deployment Aggregate Test')`, orgID, "deployment-aggregate-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'Test User', 'x')`, userID, orgID, "deployment-aggregate@example.test"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, 'aggregate-cluster', 'k3s', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (
    id, org_id, cluster_id, namespace, name, kind, labels, risk_score,
    risk_factors, finding_count, critical_count, high_count, image_refs,
    first_seen_at, last_seen_at
) VALUES (
    $1, $2, $3, 'payments', 'api', 'Deployment', '{"app":"api"}'::jsonb, 88,
    '{"cvss":40,"kev":20}'::jsonb, 3, 1, 2, $4, $5, $5
)`, deploymentID, orgID, clusterID, []string{imageRef}, now); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest, last_seen_at
) VALUES (
    $1, $2, $3, $4, 'payments', 'api', 'Deployment',
    $5, $5, 'registry.local/payments/api', '', 'sha256:abcdef', $6
)`, orgID, clusterID, deploymentID, workloadID, imageRef, now); err != nil {
		t.Fatalf("image workload link: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (
    id, org_id, cluster_id, namespace, name, kind, labels, risk_score,
    risk_factors, finding_count, critical_count, high_count, image_refs,
    first_seen_at, last_seen_at
) VALUES (
    $1, $2, $3, 'payments', 'other-api', 'Deployment', '{}'::jsonb, 40,
    '{}'::jsonb, 0, 0, 0, $4, $5, $5
)`, otherDeploymentID, orgID, clusterID, []string{otherImageRef}, now); err != nil {
		t.Fatalf("other deployment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_workload_links (
    org_id, cluster_id, deployment_id, workload_id, namespace, name, kind,
    image_ref, image_ref_normalized, image_repository, image_tag, image_digest, last_seen_at
) VALUES (
    $1, $2, $3, 'payments/other-api', 'payments', 'other-api', 'Deployment',
    $4, $4, 'registry.local/payments/other-api', '', 'sha256:123456', $5
)`, orgID, clusterID, otherDeploymentID, otherImageRef, now); err != nil {
		t.Fatalf("other image workload link: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
    id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
    platform, scanner_profile, vulndb_bundle_version, package_count, finding_count,
    last_scanned_at
) VALUES (
    $1, $2, $3, $3, 'registry.local/payments/api', 'sha256:abcdef',
    'linux/amd64', 'default', 'fixture-1', 12, 3, $4
)`, imageResultID, orgID, imageRef, now); err != nil {
		t.Fatalf("image scan result: %v", err)
	}
	// Severity rollups (critical=1, high=2, max_risk=91) are computed from
	// image_scan_findings by the handler, so seed findings rather than
	// non-existent denormalized columns on image_scan_results.
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (org_id, image_scan_result_id, finding_key, title, severity, risk_score) VALUES
    ($1, $2, 'k-crit-1', 'crit', 'critical', 91),
    ($1, $2, 'k-high-1', 'high a', 'high', 70),
    ($1, $2, 'k-high-2', 'high b', 'high', 60)`, orgID, imageResultID); err != nil {
		t.Fatalf("image scan findings: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
    id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
    platform, scanner_profile, vulndb_bundle_version, package_count, finding_count,
    last_scanned_at
) VALUES (
    $1, $2, $3, $3, 'registry.local/payments/other-api', 'sha256:123456',
    'linux/amd64', 'default', 'fixture-1', 1, 0, $4
)`, otherImageResultID, orgID, otherImageRef, now); err != nil {
		t.Fatalf("other image scan result: %v", err)
	}
	secretPayload, _ := json.Marshal(map[string]any{
		"schema_version": "constellation.image-secrets.v1",
		"image_ref":      imageRef,
		"image_digest":   "sha256:abcdef",
		"status":         "observed",
		"engine":         "trivy",
		"secret_count":   1,
		"secrets": []map[string]any{{
			"engine":   "trivy",
			"rule_id":  "github-token",
			"severity": "high",
			"path":     "app/config.py",
		}},
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_artifacts (
    org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES ($1, $2, 'secret-scan', 'constellation-image-secrets-v1', $3::jsonb, 'sha256:deployment-secret-fixture', 1)`,
		orgID, imageResultID, string(secretPayload)); err != nil {
		t.Fatalf("secret artifact: %v", err)
	}
	fileRiskPayload, _ := json.Marshal(map[string]any{
		"schema_version":  "constellation.image-file-risk.v1",
		"image_ref":       imageRef,
		"image_digest":    "sha256:abcdef",
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
) VALUES ($1, $2, 'file-risk', 'constellation-image-file-risk-v1', $3::jsonb, 'sha256:deployment-file-risk-fixture', 1)`,
		orgID, imageResultID, string(fileRiskPayload)); err != nil {
		t.Fatalf("file-risk artifact: %v", err)
	}
	otherSecretPayload, _ := json.Marshal(map[string]any{
		"schema_version": "constellation.image-secrets.v1",
		"image_ref":      otherImageRef,
		"image_digest":   "sha256:123456",
		"status":         "observed",
		"engine":         "trivy",
		"secret_count":   1,
		"secrets":        []map[string]any{{"engine": "trivy", "rule_id": "other-secret", "severity": "high"}},
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_artifacts (
    org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES ($1, $2, 'secret-scan', 'constellation-image-secrets-v1', $3::jsonb, 'sha256:other-secret-fixture', 1)`,
		orgID, otherImageResultID, string(otherSecretPayload)); err != nil {
		t.Fatalf("other secret artifact: %v", err)
	}
	otherFileRiskPayload, _ := json.Marshal(map[string]any{
		"schema_version":  "constellation.image-file-risk.v1",
		"image_ref":       otherImageRef,
		"image_digest":    "sha256:123456",
		"status":          "observed",
		"file_risk_count": 1,
		"findings":        []map[string]any{{"path": "/other/suid", "severity": "high", "risk_types": []string{"setuid"}}},
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_artifacts (
    org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES ($1, $2, 'file-risk', 'constellation-image-file-risk-v1', $3::jsonb, 'sha256:other-file-risk-fixture', 1)`,
		orgID, otherImageResultID, string(otherFileRiskPayload)); err != nil {
		t.Fatalf("other file-risk artifact: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO pod_workload_links (
    org_id, cluster_id, namespace, pod_name, pod_uid, pod_workload_id,
    owner_kind, owner_name, owner_uid, owner_workload_id,
    deployment_id, node_name, phase
) VALUES
    ($1, $2, 'payments', 'api-7d9c', 'pod-uid-api', $3,
     'Deployment', 'api', 'owner-uid-api', $4, $5, 'node-a', 'Running'),
    ($1, $2, 'payments', 'api-worker-6f7d', 'pod-uid-api-worker', $6,
     'Deployment', 'api-worker', 'owner-uid-api-worker', 'payments/api-worker', NULL, 'node-a', 'Running')`,
		orgID, clusterID, podWorkloadID, workloadID, deploymentID, prefixSiblingWorkloadID); err != nil {
		t.Fatalf("pod workload links: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO pod_ips (org_id, cluster_id, namespace, pod_name, deployment, kind, ip)
VALUES
    ($1, $2, 'payments', 'api-7d9c', 'api', 'Deployment', '10.42.0.6'::inet),
    ($1, $2, 'payments', 'api-worker-6f7d', 'api-worker', 'Deployment', '10.42.0.7'::inet)`,
		orgID, clusterID); err != nil {
		t.Fatalf("pod ips: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (
    id, org_id, type, ref, cluster_id, source_type, source_ref, image_ref, image_digest, inventory_hash
) VALUES ($1, $2, 'workload', $3, $4, 'runtime-agent', $3, $5, 'sha256:abcdef', 'hash-workload')`,
		scanTargetID, orgID, podWorkloadID, clusterID, imageRef); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	payload, _ := json.Marshal(map[string]any{
		"packages": []map[string]any{{"name": "openssl", "version": "3.0.13", "ecosystem": "deb"}},
		"containers": []map[string]any{{
			"container_name": "api",
			"image_ref":      imageRef,
			"package_count":  1,
		}},
		"node":        "node-a",
		"workload_id": podWorkloadID,
		"namespace":   "payments",
		"pod_name":    "api-7d9c",
		"pod_uid":     "pod-uid",
		"runtime":     "containerd",
		"distro":      "ubuntu",
		"source":      "dpkg",
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_evidence (
    org_id, scan_target_id, cluster_id, target_type, target_ref, source_type, source_ref,
    evidence_type, inventory_hash, package_count, payload, observed_at
) VALUES ($1, $2, $3, 'workload', $4, 'runtime-agent', $4, 'package-inventory', 'hash-workload', 1, $5::jsonb, $6)`,
		orgID, scanTargetID, clusterID, podWorkloadID, string(payload), now); err != nil {
		t.Fatalf("scan evidence: %v", err)
	}
	prefixSiblingPayload, _ := json.Marshal(map[string]any{
		"packages":    []map[string]any{{"name": "leak", "version": "1.0.0", "ecosystem": "deb"}},
		"node":        "node-a",
		"workload_id": prefixSiblingWorkloadID,
		"namespace":   "payments",
		"pod_name":    "api-worker-6f7d",
		"runtime":     "containerd",
		"source":      "dpkg",
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (
    id, org_id, type, ref, cluster_id, source_type, source_ref, image_ref, image_digest, inventory_hash
) VALUES ($1, $2, 'workload', $3, $4, 'runtime-agent', $3, $5, 'sha256:abcdef', 'hash-prefix-sibling')`,
		prefixSiblingScanTargetID, orgID, prefixSiblingWorkloadID, clusterID, imageRef); err != nil {
		t.Fatalf("prefix sibling scan target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_evidence (
    org_id, scan_target_id, cluster_id, target_type, target_ref, source_type, source_ref,
    evidence_type, inventory_hash, package_count, payload, observed_at
) VALUES ($1, $2, $3, 'workload', $4, 'runtime-agent', $4, 'package-inventory', 'hash-prefix-sibling', 1, $5::jsonb, $6)`,
		orgID, prefixSiblingScanTargetID, clusterID, prefixSiblingWorkloadID, string(prefixSiblingPayload), now); err != nil {
		t.Fatalf("prefix sibling scan evidence: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, cluster_id, kind, name, labels, criticality)
VALUES ($1, $2, $3, 'deployment', $4, '{}'::jsonb, 'high')`, assetID, orgID, clusterID, workloadID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (
    org_id, cluster_id, asset_id, kind, external_id, title, severity, risk_score,
    detail_json, target_type, target_ref, target_cluster_id
) VALUES (
    $1, $2, $3, 'vulnerability', 'CVE-2099-0001', 'openssl vuln', 'critical', 95,
    '{"package":{"name":"openssl","version":"3.0.13"},"fixed":"3.0.14"}'::jsonb,
    'workload', $4, $2
)`, orgID, clusterID, assetID, podWorkloadID); err != nil {
		t.Fatalf("finding: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO events (
    org_id, cluster_id, node_id, workload_id, namespace, container_id,
    source, kind, severity, verdict, attack_techniques, payload, at
) VALUES (
    $1, $2, 'node-a', $3, 'payments', 'container-a',
    'ebpf', 'process_exec', 'high', 'alert', '{T1059}', '{"comm":"sh","filename":"/bin/sh","args":["-c","whoami"]}'::jsonb, $4
)`, orgID, clusterID, podWorkloadID, now); err != nil {
		t.Fatalf("event: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO events (
    org_id, cluster_id, node_id, workload_id, namespace, container_id,
    source, kind, severity, verdict, attack_techniques, payload, at
) VALUES
    ($1, $2, 'node-a', $3, 'payments', 'container-a',
     'ebpf', 'process_exec', 'info', 'observed', '{}', '{"comm":"sh","filename":"/bin/sh","args":["-c","id"]}'::jsonb, $4),
    ($1, $2, 'node-a', $3, 'payments', 'container-a',
     'ebpf', 'process_exec', 'info', 'observed', '{}', '{"comm":"curl","filename":"/usr/bin/curl","args":["https://example.test"]}'::jsonb, $5),
    ($1, $2, 'node-a', 'payments/pod/other-api-7d9c', 'payments', 'container-b',
     'ebpf', 'process_exec', 'high', 'alert', '{T1059}', '{"comm":"python","filename":"/usr/bin/python"}'::jsonb, $4),
    ($1, $2, 'node-a', 'payments/pod/api-worker-6f7d', 'payments', 'container-c',
     'ebpf', 'process_exec', 'high', 'alert', '{T1059}', '{"comm":"ruby","filename":"/usr/bin/ruby"}'::jsonb, $4)`,
		orgID, clusterID, podWorkloadID, now.Add(-time.Minute), now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("additional process events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO events (
    org_id, cluster_id, node_id, workload_id, namespace, container_id,
    source, kind, severity, verdict, attack_techniques, payload, at
) VALUES
    ($1, $2, 'node-a', $3, 'payments', 'container-a',
     'ebpf', 'file_open', 'medium', 'alert', '{T1552.001}', '{"pid":42,"comm":"cat","path":"/var/run/secrets/kubernetes.io/serviceaccount/token","flags":0,"mode":0}'::jsonb, $4),
    ($1, $2, 'node-a', 'payments/pod/other-api-7d9c', 'payments', 'container-b',
     'ebpf', 'file_open', 'medium', 'alert', '{T1552.001}', '{"pid":43,"comm":"cat","path":"/other/secret"}'::jsonb, $4),
    ($1, $2, 'node-a', 'payments/pod/api-worker-6f7d', 'payments', 'container-c',
     'ebpf', 'file_open', 'medium', 'alert', '{T1552.001}', '{"pid":44,"comm":"cat","path":"/prefix/secret"}'::jsonb, $4)`,
		orgID, clusterID, podWorkloadID, now.Add(-3*time.Minute)); err != nil {
		t.Fatalf("file events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO runtime_threats (
    org_id, cluster_id, node, ep_mac, workload_id, namespace, pod_name,
    threat_id, severity, action, application, msg, dlp_name_hash,
    ip_proto, src_ip, src_port, dst_ip, dst_port,
    pkt_len, cap_len, pkt_ingress, sess_ingress, tap_mode,
    reported_at, at
) VALUES
    ($1, $2, 'node-a', 'aa:bb:cc:dd:ee:01', $3, 'payments', '',
     2024, 8, 6, 1004, 'Sensitive data exfiltration pattern', 4242,
     6, '10.42.0.6', 41000, '198.51.100.20', 443,
     128, 256, false, false, true, $4, $4),
    ($1, $2, 'node-a', 'aa:bb:cc:dd:ee:02', $3, 'payments', '',
     2022, 7, 7, 1001, 'SQL injection payload', 0,
     6, '198.51.100.21', 51000, '10.42.0.6', 8080,
     96, 120, true, true, true, $4, $4),
    ($1, $2, 'node-a', 'aa:bb:cc:dd:ee:03', 'payments/other-api', 'payments', '',
     2022, 7, 7, 1001, 'Sibling SQL injection payload', 0,
     6, '198.51.100.22', 51001, '10.42.0.7', 8080,
     96, 120, true, true, true, $4, $4)`,
		orgID, clusterID, workloadID, now.Add(-4*time.Minute)); err != nil {
		t.Fatalf("runtime threats: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_flows (
    org_id, cluster_id, src_workload, dst_workload, src_addr, dst_addr,
    src_port, dst_port, protocol, l7_protocol, bytes, packets, verdict, at
) VALUES (
    $1, $2, $3, 'external/198.51.100.10', '10.0.0.10', '198.51.100.10',
    42000, 443, 'tcp', 'https', 4096, 12, 'allow', $4
), (
    $1, $2, 'payments/api-worker', 'external/198.51.100.11', '10.0.0.11', '198.51.100.11',
    42001, 443, 'tcp', 'https', 2048, 6, 'allow', $4
)`, orgID, clusterID, workloadID, now); err != nil {
		t.Fatalf("network flow: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_policy_lifecycle_states (
    org_id, cluster_id, workload, namespace, current_mode, target_mode,
    approval_status, reason, rollback_available
) VALUES ($1, $2, $3, 'payments', 'monitor', 'protect', 'pending', 'observed external traffic', true)`,
		orgID, clusterID, workloadID); err != nil {
		t.Fatalf("network policy: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO quarantine_entries (
    org_id, cluster_id, scope, match_key, reason, origin, created_by, expires_at
) VALUES ($1, $2, 'workload', $3, 'manual containment', 'manual', $4, $5)`,
		orgID, clusterID, workloadID, userID, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO process_baseline_states (
    org_id, cluster_id, workload_id, namespace, name, mode, learn_started_at, monitor_started_at, updated_by
) VALUES ($1, $2, $3, 'payments', 'api', 'monitor', $4, $5, $6)`,
		orgID, clusterID, workloadID, now.Add(-48*time.Hour), now.Add(-2*time.Hour), userID); err != nil {
		t.Fatalf("process baseline state: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO process_baseline_transitions (
    org_id, cluster_id, workload_id, from_mode, to_mode, reason, actor_id, created_at
) VALUES ($1, $2, $3, 'learn', 'monitor', 'validated observed process set', $4, $5)`,
		orgID, clusterID, workloadID, userID, now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("process baseline transition: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO file_profile_states (
    org_id, cluster_id, workload_id, namespace, name, mode, learn_started_at, monitor_started_at, updated_by
) VALUES ($1, $2, $3, 'payments', 'api', 'monitor', $4, $5, $6)`,
		orgID, clusterID, workloadID, now.Add(-48*time.Hour), now.Add(-90*time.Minute), userID); err != nil {
		t.Fatalf("file profile state: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO file_profile_transitions (
    org_id, cluster_id, workload_id, from_mode, to_mode, reason, actor_id, created_at
) VALUES ($1, $2, $3, 'learn', 'monitor', 'validated observed file set', $4, $5)`,
		orgID, clusterID, workloadID, userID, now.Add(-90*time.Minute)); err != nil {
		t.Fatalf("file profile transition: %v", err)
	}
	var fileRuleID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO file_profile_rules (
    org_id, cluster_id, workload_id, filter, path, regex, recursive, behavior,
    applications, enabled, description, created_by, updated_by
) VALUES (
    $1, $2, $3, '/var/run/secrets/kubernetes.io/serviceaccount/*',
    '/var/run/secrets/kubernetes\.io/serviceaccount', '.*', true, 'block_access',
    ARRAY['cat']::text[], true, 'block token reads', $4, $4
) RETURNING id`, orgID, clusterID, workloadID, userID).Scan(&fileRuleID); err != nil {
		t.Fatalf("file profile rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO file_profile_watch_inventory (
    org_id, cluster_id, node, workload_id, rule_id, filter, path, regex,
    recursive, behavior, applications, profile_mode, desired_protect, protect,
    enforcement_state, files, files_count, sensitive_count, bundle_fingerprint,
    observed_at
) VALUES (
    $1, $2, 'node-a', $3, $4,
    '/var/run/secrets/kubernetes.io/serviceaccount/*',
    '/var/run/secrets/kubernetes\.io/serviceaccount', '.*', true, 'block_access',
    ARRAY['cat']::text[], 'monitor', false, false, 'synced',
    '[{"path":"/var/run/secrets/kubernetes.io/serviceaccount/token","container_id":"abc123","pod_name":"api-7d9c","pod_namespace":"payments"}]'::jsonb,
    1, 1, 'fp-test', $5
)`, orgID, clusterID, workloadID, fileRuleID, now); err != nil {
		t.Fatalf("file profile watch inventory: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO violations (org_id, deployment_id, policy_name, severity, kind, message, at)
VALUES ($1, $2, 'deny-shell', 'high', 'runtime', 'shell executed', $3)`, orgID, deploymentID, now); err != nil {
		t.Fatalf("violation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_threats WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM network_flows WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM pod_workload_links WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM pod_ips WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM quarantine_entries WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM process_baseline_transitions WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM process_baseline_states WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM file_profile_watch_inventory WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM file_profile_rules WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM file_profile_transitions WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM file_profile_states WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+deploymentID.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", deploymentID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	// The network-policy lifecycle computation now lives behind an injected seam
	// (netpolicy.NetworkPolicies.LifecycleForWorkload, wired in server.go). This
	// handler test verifies Deployments.Get surfaces the lookup result under
	// "network_policy"; the computation itself is covered in the netpolicy package.
	npLookup := func(_ *http.Request, _ uuid.UUID, _ *uuid.UUID, _ string) (any, error) {
		return map[string]any{
			"current_mode":       "monitor",
			"rollback_available": true,
			"candidate_hash":     "test-candidate-hash",
			"preview":            map[string]any{"yaml": "kind: NetworkPolicy\n"},
		}, nil
	}
	NewDeployments(d, nil).WithNetworkPolicyLookup(npLookup).Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var got deploymentDetailDTO
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ClusterID != clusterID.String() || got.Namespace != "payments" || got.Name != "api" {
		t.Fatalf("deployment identity = %+v", got)
	}
	if len(got.Images) != 1 || got.Images[0].ImageScanResultID != imageResultID.String() || got.Images[0].CriticalCount != 1 {
		t.Fatalf("images = %+v", got.Images)
	}
	if len(got.PackageEvidence) != 1 || got.PackageEvidence[0].WorkloadID != podWorkloadID || got.PackageEvidence[0].PackageCount != 1 {
		t.Fatalf("package evidence = %+v", got.PackageEvidence)
	}
	if !containsString(got.WorkloadIDs, podWorkloadID) || containsString(got.WorkloadIDs, prefixSiblingWorkloadID) {
		t.Fatalf("workload ids = %+v", got.WorkloadIDs)
	}
	if len(got.Findings) != 1 || got.Findings[0].ExternalID != "CVE-2099-0001" || got.Findings[0].PackageName != "openssl" {
		t.Fatalf("findings = %+v", got.Findings)
	}
	if len(got.RuntimeEvents) != 4 || got.RuntimeEvents[0].WorkloadID != podWorkloadID {
		t.Fatalf("runtime events = %+v", got.RuntimeEvents)
	}
	if len(got.FileRisks) != 1 || got.FileRisks[0].ImageDigest != "sha256:abcdef" || len(got.FileRisks[0].Findings) != 1 || got.FileRisks[0].Findings[0].Path != "/usr/bin/suid-helper" {
		t.Fatalf("file risks = %+v", got.FileRisks)
	}
	for _, risk := range got.FileRisks {
		if strings.Contains(risk.ImageRef, "other-api") || risk.ImageDigest == "sha256:123456" {
			t.Fatalf("file risks leaked sibling image artifact: %+v", got.FileRisks)
		}
	}
	var filePivot, dlpPivot, wafPivot bool
	for _, pivot := range got.ThreatPivots {
		if strings.Contains(pivot.WorkloadID, "other-api") || strings.Contains(pivot.Title, "Sibling") || strings.Contains(pivot.Message, "/other/secret") {
			t.Fatalf("threat pivot leaked sibling evidence: %+v", got.ThreatPivots)
		}
		switch pivot.Kind {
		case "file":
			filePivot = pivot.File != nil && pivot.File.Path == "/var/run/secrets/kubernetes.io/serviceaccount/token"
		case "dlp":
			dlpPivot = pivot.RuntimeThreatID != "" && pivot.Rule != nil && pivot.Rule.Category == "dlp" && pivot.Verdict == "alert"
		case "waf":
			wafPivot = pivot.RuntimeThreatID != "" && pivot.Rule != nil && pivot.Rule.Category == "waf" && pivot.Verdict == "deny"
		}
	}
	if !filePivot || !dlpPivot || !wafPivot {
		t.Fatalf("missing threat pivots file=%v dlp=%v waf=%v pivots=%+v", filePivot, dlpPivot, wafPivot, got.ThreatPivots)
	}
	if got.ProcessBaseline == nil || got.ProcessBaseline.WorkloadID != podWorkloadID || got.ProcessBaseline.LearnedProcessesCount != 2 || got.ProcessBaseline.MonitoredAlerts24h != 1 {
		t.Fatalf("process baseline = %+v", got.ProcessBaseline)
	}
	if got.ProcessBaseline.ControlWorkloadID != workloadID || got.ProcessBaseline.Mode != "monitor" || len(got.ProcessBaseline.Transitions) != 1 {
		t.Fatalf("process baseline lifecycle = %+v", got.ProcessBaseline)
	}
	if len(got.ProcessBaseline.Processes) != 2 || got.ProcessBaseline.Processes[0].Name != "sh" || got.ProcessBaseline.Processes[0].ObservedCount != 2 || got.ProcessBaseline.Processes[0].Path != "/bin/sh" {
		t.Fatalf("process baseline processes = %+v", got.ProcessBaseline.Processes)
	}
	for _, process := range got.ProcessBaseline.Processes {
		if process.Name == "python" || process.Name == "ruby" {
			t.Fatalf("process baseline leaked sibling workload process: %+v", got.ProcessBaseline.Processes)
		}
	}
	if got.FileProfile == nil || got.FileProfile.WorkloadID != podWorkloadID || got.FileProfile.LearnedPathsCount != 1 || got.FileProfile.SensitivePathCount != 1 {
		t.Fatalf("file profile = %+v", got.FileProfile)
	}
	if got.FileProfile.ControlWorkloadID != workloadID || got.FileProfile.Mode != "monitor" || len(got.FileProfile.Transitions) != 1 {
		t.Fatalf("file profile lifecycle = %+v", got.FileProfile)
	}
	if len(got.FileProfile.Files) != 1 || got.FileProfile.Files[0].Path != "/var/run/secrets/kubernetes.io/serviceaccount/token" || !got.FileProfile.Files[0].Sensitive {
		t.Fatalf("file profile files = %+v", got.FileProfile.Files)
	}
	if got.FileProfile.RuleCount != 1 ||
		len(got.FileProfile.Rules) != 1 ||
		got.FileProfile.Rules[0].Behavior != "block_access" ||
		got.FileProfile.Rules[0].Path != "/var/run/secrets/kubernetes\\.io/serviceaccount" ||
		got.FileProfile.Rules[0].Regex != ".*" {
		t.Fatalf("file profile rules = %+v", got.FileProfile.Rules)
	}
	if got.FileProfile.WatchedFileCount != 1 ||
		len(got.FileProfile.WatchedFiles) != 1 ||
		got.FileProfile.WatchedFiles[0].FilesCount != 1 ||
		got.FileProfile.WatchedFiles[0].SensitiveCount != 1 ||
		got.FileProfile.WatchedFiles[0].EnforcementState != "synced" {
		t.Fatalf("file profile watched files = %+v", got.FileProfile.WatchedFiles)
	}
	for _, file := range got.FileProfile.Files {
		if strings.Contains(file.Path, "/other/") || strings.Contains(file.Path, "/prefix/") {
			t.Fatalf("file profile leaked sibling workload file: %+v", got.FileProfile.Files)
		}
	}
	if len(got.NetworkFlows) != 1 || got.NetworkFlows[0].Src != workloadID {
		t.Fatalf("network flows = %+v", got.NetworkFlows)
	}
	// NetworkPolicy is an opaque any (the concrete DTO lives in the
	// handler/netpolicy sub-package); assert the equivalent fields off the
	// decoded JSON object. Expectation is unchanged from when the field was a
	// typed *networkPolicyLifecycleDTO.
	np, npOK := got.NetworkPolicy.(map[string]any)
	npPreview, _ := np["preview"].(map[string]any)
	if !npOK ||
		np["current_mode"] != "monitor" ||
		np["rollback_available"] != true ||
		np["candidate_hash"] == nil || np["candidate_hash"] == "" ||
		npPreview == nil || npPreview["yaml"] == nil || npPreview["yaml"] == "" {
		t.Fatalf("network policy = %+v", got.NetworkPolicy)
	}
	if got.Quarantine == nil || got.Quarantine.MatchKey != workloadID || got.Quarantine.Reason != "manual containment" {
		t.Fatalf("quarantine = %+v", got.Quarantine)
	}
	var secretCompliance, fileRiskCompliance bool
	for _, item := range got.Compliance {
		if item.Source == "image_scan_artifacts" && item.InternalID == "container.image-secrets-absent" && item.EffectiveStatus == "fail" {
			secretCompliance = true
		}
		if item.Source == "image_scan_artifacts" && item.InternalID == "container.image-file-risks-absent" && item.EffectiveStatus == "fail" {
			fileRiskCompliance = true
		}
		if strings.Contains(item.Target, "other-api") {
			t.Fatalf("compliance evidence leaked from sibling workload: %+v", got.Compliance)
		}
	}
	if !secretCompliance || !fileRiskCompliance {
		t.Fatalf("missing image secret compliance evidence: %+v", got.Compliance)
	}
	if len(got.Violations) != 1 || got.Violations[0].PolicyName != "deny-shell" {
		t.Fatalf("violations = %+v", got.Violations)
	}
}
