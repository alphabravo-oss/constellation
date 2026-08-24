// constellation-seed populates a fresh Postgres with a demo org, admin user, sample assets,
// findings (one per kind), policies, and an audit-event for the dashboard / Playwright tests.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/obslog"
	auditlog "github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/risk"
)

func main() {
	password := flag.String("password", "Constellation!1", "Local admin password to provision")
	flag.Parse()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL required")
		os.Exit(2)
	}
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "seed")
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		logger.Error("db", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	// Make seed idempotent: clear the volatile tables first. Tenancy + users are upserted
	// below so they stay stable across runs.
	for _, table := range []string{"findings", "image_acceptances", "cve_records", "cve_bundles", "policy_decisions", "policies", "assets"} {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE"); err != nil {
			logger.Warn("truncate", slog.String("table", table), slog.String("err", err.Error()))
		}
	}
	// audit_events has DELETE-blocking triggers but allows TRUNCATE.
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE audit_events RESTART IDENTITY"); err != nil {
		logger.Warn("truncate audit_events", slog.String("err", err.Error()))
	}

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO orgs (name, display_name, region, ai_enabled)
VALUES ('demo', 'Demo Org', 'us-east-1', FALSE)
ON CONFLICT (name) DO UPDATE SET display_name = EXCLUDED.display_name
RETURNING id`).Scan(&orgID); err != nil {
		logger.Error("org", slog.String("err", err.Error()))
		os.Exit(1)
	}

	for _, cleanup := range []struct {
		name string
		stmt string
	}{
		{"connector_configs", `DELETE FROM connector_configs WHERE org_id = $1`},
		{"registry_scan_jobs", `DELETE FROM scan_jobs WHERE org_id = $1 AND target_id IN (SELECT id FROM scan_targets WHERE org_id = $1 AND metadata->>'seed' = 'demo')`},
		{"registry_scan_targets", `DELETE FROM scan_targets WHERE org_id = $1 AND metadata->>'seed' = 'demo'`},
		{"registries", `DELETE FROM registries WHERE org_id = $1`},
		{"compliance_runs", `DELETE FROM compliance_runs WHERE org_id = $1`},
		{"compliance_schedules", `DELETE FROM compliance_schedules WHERE org_id = $1`},
		{"scanner_heartbeats", `DELETE FROM component_heartbeats WHERE org_id = $1 AND component = 'scanner'`},
		{"receiver_deliveries", `DELETE FROM receiver_deliveries WHERE org_id = $1`},
		{"receivers", `DELETE FROM receivers WHERE org_id = $1`},
		{"routing_configs", `DELETE FROM routing_configs WHERE org_id = $1`},
		{"role_assignments", `DELETE FROM role_assignments WHERE scope_org_id = $1`},
		{"role_bindings", `DELETE FROM role_bindings WHERE org_id = $1`},
		{"api_tokens", `DELETE FROM api_tokens
 WHERE service_account_id IN (SELECT id FROM service_accounts WHERE org_id = $1)
    OR user_id IN (SELECT id FROM users WHERE org_id = $1)`},
		{"service_accounts", `DELETE FROM service_accounts WHERE org_id = $1`},
		{"auth_servers", `DELETE FROM auth_servers WHERE org_id = $1 AND name = 'Okta Workforce'`},
	} {
		if _, err := pool.Exec(ctx, cleanup.stmt, orgID); err != nil {
			logger.Warn("reset access-control seed", slog.String("table", cleanup.name), slog.String("err", err.Error()))
		}
	}

	hash, _ := auth.HashPassword(*password)
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO users (org_id, email, display_name, password_hash)
VALUES ($1, 'admin@demo.test', 'Demo Admin', $2)
ON CONFLICT (org_id, email) DO UPDATE
   SET password_hash = EXCLUDED.password_hash,
       disabled = FALSE,
       must_change_password = FALSE,
       failed_login_count = 0,
       block_login_since = NULL,
       password_changed_at = NOW()
RETURNING id`, orgID, hash).Scan(&userID); err != nil {
		logger.Error("user", slog.String("err", err.Error()))
		os.Exit(1)
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO role_assignments (user_id, role, scope_org_id)
VALUES ($1, 'GlobalAdmin', $2)
ON CONFLICT DO NOTHING`, userID, orgID); err != nil {
		logger.Error("role", slog.String("err", err.Error()))
		os.Exit(1)
	}
	seedAccessControl(ctx, pool, orgID, userID, logger)

	var clusterID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO clusters (org_id, name, distro, cloud_provider, region, state, agent_version, last_heartbeat_at)
VALUES ($1, 'prod-east', 'eks', 'aws', 'us-east-1', 'connected', 'demo-agent-0.1.0', NOW())
ON CONFLICT (org_id, name) DO UPDATE SET state = EXCLUDED.state, last_heartbeat_at = NOW()
RETURNING id`, orgID).Scan(&clusterID); err != nil {
		logger.Error("cluster", slog.String("err", err.Error()))
		os.Exit(1)
	}
	seedExtraCluster(ctx, pool, orgID, "prod-west", "eks", "aws", "us-west-2", logger)
	seedExtraCluster(ctx, pool, orgID, "edge-lab", "k3s", "onprem", "lab", logger)

	// One asset per kind so the Assets page is non-empty.
	imgID := upsertAsset(ctx, pool, orgID, clusterID, "image", "ghcr.io/demo/api", "sha256:aaaa", "high")
	workloadID := upsertAsset(ctx, pool, orgID, clusterID, "workload", "default/Deployment/api", "", "high")
	iacID := upsertAsset(ctx, pool, orgID, clusterID, "iac-resource", "terraform/main.tf", "sha256:bbbb", "medium")
	mlID := upsertAsset(ctx, pool, orgID, clusterID, "ml-model", "huggingface/llama-2-7b", "sha256:cccc", "medium")
	cloudID := upsertAsset(ctx, pool, orgID, clusterID, "cloud-resource", "aws:s3:public-bucket", "", "critical")

	if _, err := pool.Exec(ctx, `
INSERT INTO images (asset_id, registry, repository, tag, digest, layers, architectures, size_bytes, signed, signature_info)
VALUES ($1, 'ghcr.io', 'demo/api', '1.0.0', 'sha256:aaaa',
        '[{"digest":"sha256:layer1","size":12000000},{"digest":"sha256:layer2","size":8400000}]'::jsonb,
        '["linux/amd64","linux/arm64"]'::jsonb,
        20400000, false, '{"reason":"demo image intentionally unsigned"}'::jsonb)
ON CONFLICT (asset_id) DO UPDATE SET pulled_at = NOW()`, imgID); err != nil {
		logger.Warn("image seed", slog.String("err", err.Error()))
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO sbom_documents (asset_id, format, document, sha256)
VALUES ($1, 'spdx-2.3', '{"SPDXID":"SPDXRef-DOCUMENT","name":"ghcr.io/demo/api"}'::jsonb, 'sha256-spdx-demo'),
       ($1, 'cyclonedx-1.6', '{"bomFormat":"CycloneDX","metadata":{"component":{"name":"api"}}}'::jsonb, 'sha256-cdx-demo')
ON CONFLICT DO NOTHING`, imgID); err != nil {
		logger.Warn("sbom seed", slog.String("err", err.Error()))
	}

	// Findings across kinds with realistic risk scores.
	insertFinding(ctx, pool, orgID, clusterID, imgID, "vulnerability", "CVE-2024-0001",
		"glibc heap overflow", "critical", 8.8, 0.95, true, true, "high")
	insertFinding(ctx, pool, orgID, clusterID, imgID, "vulnerability", "CVE-2023-1234",
		"openssl side-channel", "high", 7.5, 0.4, false, true, "high")
	insertFinding(ctx, pool, orgID, clusterID, imgID, "license", "license-AGPL-3.0",
		"AGPL-3.0 in commercial workload", "medium", 0, 0, false, false, "high")
	insertFinding(ctx, pool, orgID, clusterID, iacID, "iac", "AVD-AWS-0001",
		"S3 bucket has no encryption", "high", 0, 0, false, false, "medium")
	insertFinding(ctx, pool, orgID, clusterID, cloudID, "cloud-config", "cspm-s3-public",
		"S3 bucket allows public read", "critical", 0, 0, false, false, "critical")
	insertFinding(ctx, pool, orgID, clusterID, workloadID, "runtime", "FALCO-1001",
		"shell spawned in container", "high", 0, 0, false, true, "high",
		"T1059.004")
	insertFinding(ctx, pool, orgID, clusterID, workloadID, "drift", "drift-rolebinding",
		"RoleBinding declared in Git missing from cluster", "medium", 0, 0, false, false, "medium")
	insertFinding(ctx, pool, orgID, clusterID, mlID, "ml-model", "MBOM-LLAMA-001",
		"Pickle deserialization in model artifact", "high", 0, 0, false, false, "medium")
	insertFinding(ctx, pool, orgID, clusterID, imgID, "signature", "sig-missing",
		"Image not signed by trusted identity", "high", 0, 0, false, false, "high")
	insertFinding(ctx, pool, orgID, clusterID, imgID, "secret", "secret-aws-key",
		"Hardcoded AWS access key in layer 4", "critical", 0, 0, false, false, "high")
	insertFinding(ctx, pool, orgID, clusterID, workloadID, "compliance", "cis-k8s-5.1.3",
		"Minimize wildcard use in Roles and ClusterRoles", "medium", 0, 0, false, false, "high")
	seedConnectorCoverage(ctx, pool, orgID, clusterID, userID, imgID, logger)
	seedComplianceSchedules(ctx, pool, orgID, clusterID, userID, logger)
	seedIntegrations(ctx, pool, orgID, userID, logger)

	// Sample CVE record so the CVE page shows content + bundle metadata.
	if _, err := pool.Exec(ctx, `
INSERT INTO cve_records (cve_id, title, description, cvss_base, kev_listed, epss_probability,
                         aliases, affected, "references", sources, published_at, modified_at)
VALUES
  ('CVE-2024-0001', 'glibc heap overflow', 'Heap buffer overflow in glibc nss_compat.', 8.8, TRUE, 0.95,
   ARRAY['GHSA-aaaa-bbbb-cccc'], '[]'::jsonb, ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2024-0001'],
   ARRAY['nvd','kev','epss'], NOW() - INTERVAL '7 days', NOW()),
  ('CVE-2023-1234', 'openssl side-channel', 'OpenSSL timing side-channel in RSA padding.', 7.5, FALSE, 0.4,
   ARRAY['GHSA-xxxx-yyyy-zzzz'], '[]'::jsonb, ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2023-1234'],
   ARRAY['nvd','epss'], NOW() - INTERVAL '30 days', NOW())
ON CONFLICT (cve_id) DO UPDATE SET modified_at = EXCLUDED.modified_at`); err != nil {
		logger.Error("cve", slog.String("err", err.Error()))
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO cve_bundles (version, oci_ref, sha256, record_count, signed, signer_identity, published_at)
VALUES ('2026-05-11T120000Z', 'ghcr.io/alphabravocompany/constellation-cve-bundle:demo',
        'fakesha256-demo', 2, TRUE, 'sigstore-demo', NOW())
ON CONFLICT (version) DO NOTHING`); err != nil {
		logger.Error("bundle", slog.String("err", err.Error()))
	}

	// A demo policy so /policies isn't empty.
	if _, err := pool.Exec(ctx, `
INSERT INTO policies (org_id, name, description, engine, category, spec_yaml, enabled, mode)
VALUES ($1, 'block-unsigned-images', 'Reject unsigned images at admission',
        'constellation-admission', 'signature-verification',
        $policy$apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-unsigned-images
spec:
  match:
    kinds: ["Pod"]
  provenance:
    requireSignatureAnnotation: constellation.alphabravo.io/image-signed
  images:
    disallowLatestTag: true
    disallowImplicitTag: true
  action: deny
$policy$, TRUE, 'enforce')
ON CONFLICT (org_id, name, version) DO NOTHING`, orgID); err != nil {
		logger.Error("policy", slog.String("err", err.Error()))
	}

	// Audit log: a couple of seed events so the Audit page renders rows.
	auditor := auditlog.New(pool)
	for _, event := range []auditlog.Event{
		{Action: "org.create", TargetKind: "demo", TargetID: "seed"},
		{Action: "user.invite", TargetKind: "demo", TargetID: "seed"},
		{Action: "policy.create", TargetKind: "demo", TargetID: "seed"},
		{Action: "cluster.seed", TargetKind: "cluster", TargetID: clusterID.String()},
	} {
		_, _, err := auditor.Log(ctx, auditlog.Event{
			OrgID: &orgID, ActorID: &userID,
			Action: event.Action, TargetKind: event.TargetKind, TargetID: event.TargetID,
			Before: map[string]any{}, After: map[string]any{},
			RequestID: "seed-" + event.Action,
		})
		if err != nil {
			logger.Warn("audit insert", slog.String("err", err.Error()))
		}
	}

	// Deployments + violations seed (Risk dashboard / Violation timeline parity).
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE violations CASCADE")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE deployments CASCADE")
	depSeed := []struct {
		ns, name, kind string
		risk           int
		fc, cc, hc     int
		labels         string
		factors        string
	}{
		{"default", "api-service", "Deployment", 92, 14, 2, 5, `{"app":"api-service","env":"prod"}`, `{"cvss":40,"epss":20,"kev":20,"privileged":0,"net_exposure":12}`},
		{"default", "frontend", "Deployment", 71, 9, 1, 3, `{"app":"frontend","env":"prod"}`, `{"cvss":30,"epss":15,"kev":10,"privileged":0,"net_exposure":16}`},
		{"data", "postgres", "StatefulSet", 58, 6, 0, 2, `{"app":"postgres","env":"prod"}`, `{"cvss":20,"epss":8,"kev":0,"privileged":0,"net_exposure":30}`},
		{"data", "redis", "StatefulSet", 38, 3, 0, 1, `{"app":"redis","env":"prod"}`, `{"cvss":12,"epss":4,"kev":0,"privileged":0,"net_exposure":22}`},
		{"default", "background-worker", "Deployment", 35, 4, 0, 1, `{"app":"worker","env":"prod"}`, `{"cvss":15,"epss":3,"kev":0,"privileged":0,"net_exposure":17}`},
		{"ingress-nginx", "nginx-ingress", "DaemonSet", 28, 2, 0, 0, `{"app":"ingress","env":"prod"}`, `{"cvss":10,"epss":2,"kev":0,"privileged":15,"net_exposure":1}`},
	}
	depIDs := map[string]uuid.UUID{}
	for _, d := range depSeed {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, risk_score, risk_factors, finding_count, critical_count, high_count)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::jsonb, $9, $10, $11)
ON CONFLICT (org_id, cluster_id, namespace, name, kind) DO UPDATE SET risk_score = EXCLUDED.risk_score
RETURNING id`,
			orgID, clusterID, d.ns, d.name, d.kind, d.labels, d.risk, d.factors, d.fc, d.cc, d.hc).Scan(&id); err != nil {
			logger.Warn("deployment seed", slog.String("err", err.Error()))
			continue
		}
		depIDs[d.name] = id
	}

	_, _ = pool.Exec(ctx, "TRUNCATE TABLE network_flows CASCADE")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE events CASCADE")
	flowSeed := []struct {
		src, dst, proto, l7, verdict string
		port                         int
		bytes, packets               int
		minutesAgo                   int
	}{
		{"ingress-nginx/nginx-ingress", "default/frontend", "tcp", "http", "allow", 8080, 28_100_000, 46_200, 2},
		{"default/frontend", "default/api-service", "tcp", "grpc", "allow", 8443, 19_700_000, 31_400, 4},
		{"default/api-service", "data/postgres", "tcp", "postgres", "allow", 5432, 42_500_000, 22_600, 6},
		{"default/api-service", "data/redis", "tcp", "redis", "allow", 6379, 7_900_000, 18_200, 9},
		{"default/background-worker", "data/postgres", "tcp", "postgres", "allow", 5432, 16_300_000, 9_100, 15},
		{"default/background-worker", "external/external.api.com", "tcp", "http", "alert", 443, 4_600_000, 3_200, 12},
		{"default/frontend", "external/tracker.example", "tcp", "http", "block", 443, 118_000, 140, 18},
		{"default/api-service", "kube-system/kube-dns", "udp", "dns", "allow", 53, 940_000, 8_900, 3},
	}
	for _, f := range flowSeed {
		if _, err := pool.Exec(ctx, `
INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bytes, packets, at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW() - ($11 || ' minutes')::interval)`,
			orgID, clusterID, f.src, f.dst, f.proto, f.l7, f.port, f.verdict, f.bytes, f.packets, fmt.Sprintf("%d", f.minutesAgo)); err != nil {
			logger.Warn("network flow seed", slog.String("err", err.Error()))
		}
	}
	refreshNetworkFlowRollups(ctx, pool, orgID, logger)

	runtimeEventSeed := []struct {
		node, workload, source, kind, severity, verdict, ruleID, ruleName, message string
		techniques                                                                 []string
		minutesAgo                                                                 int
	}{
		{"ip-10-42-1-12", "default/api-service", "falco", "process_shell", "high", "alert", "container-process-shell", "Container shell spawned", "interactive shell spawned in api-service container", []string{"T1059.004"}, 4},
		{"ip-10-42-2-7", "default/frontend", "waf", "sql_injection", "critical", "block", "waf-sql-injection", "SQL injection payload", "SQL injection payload blocked at ingress", []string{"T1190"}, 8},
		{"ip-10-42-3-19", "default/background-worker", "network", "unauthorized_egress", "high", "alert", "network-unauthorized-egress", "Unauthorized external egress", "egress to external.api.com outside learned baseline", []string{"T1105"}, 12},
		{"ip-10-42-1-12", "default/api-service", "dlp", "secret_exfiltration", "critical", "quarantine", "dlp-secret-exfiltration", "Secret exfiltration pattern", "secret-like payload matched DLP detector", []string{"T1041"}, 19},
	}
	for _, ev := range runtimeEventSeed {
		if _, err := pool.Exec(ctx, `
INSERT INTO events (org_id, cluster_id, node_id, workload_id, source, kind, severity, verdict, attack_techniques, payload, at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
        jsonb_build_object('rule_id', $10::text, 'rule_name', $11::text, 'message', $12::text),
        NOW() - ($13 || ' minutes')::interval)`,
			orgID, clusterID, ev.node, ev.workload, ev.source, ev.kind, ev.severity, ev.verdict, ev.techniques,
			ev.ruleID, ev.ruleName, ev.message, fmt.Sprintf("%d", ev.minutesAgo)); err != nil {
			logger.Warn("runtime event seed", slog.String("err", err.Error()))
		}
	}

	violSeed := []struct {
		dep, policy, sev, kind, msg string
		minutesAgo                  int
	}{
		{"api-service", "block-privileged", "high", "admission", "blocked privileged container in pod api-service-7d4f", 5},
		{"api-service", "image-signed", "medium", "admission", "image lacks constellation.alphabravo.io/image-signed annotation (monitor)", 47},
		{"frontend", "require-read-only-rootfs", "medium", "admission", "container missing readOnlyRootFilesystem=true (monitor)", 122},
		{"background-worker", "egress-allowed-list", "high", "runtime", "egress to external.api.com outside allow-list", 12},
		{"postgres", "cve-critical-fixed", "critical", "finding", "CVE-2024-0001 critical with fix available; reachable=true", 60},
		{"nginx-ingress", "host-network", "high", "admission", "hostNetwork=true required by ingress (monitor)", 240},
		{"redis", "cve-medium", "medium", "finding", "CVE-2023-1234 medium; not reachable", 700},
		{"api-service", "policy-drift", "medium", "drift", "RoleBinding api-svc-rb modified out-of-band from Git", 30},
	}
	for _, v := range violSeed {
		dep := depIDs[v.dep]
		if dep == uuid.Nil {
			continue
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO violations (org_id, deployment_id, policy_name, severity, kind, message, at)
VALUES ($1, $2, $3, $4, $5, $6, NOW() - ($7 || ' minutes')::interval)`,
			orgID, dep, v.policy, v.sev, v.kind, v.msg, fmt.Sprintf("%d", v.minutesAgo)); err != nil {
			logger.Warn("violation seed", slog.String("err", err.Error()))
		}
	}

	logger.Info("seed complete",
		slog.String("org_id", orgID.String()),
		slog.String("user_id", userID.String()),
		slog.String("email", "admin@demo.test"))
}

func seedAccessControl(ctx context.Context, pool *pgxpool.Pool, orgID, adminID uuid.UUID, logger *slog.Logger) {
	var analystID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO users (org_id, email, display_name, oidc_issuer, oidc_subject, disabled)
VALUES ($1, 'ava.patel@demo.test', 'Ava Patel', 'https://okta.example.com/oauth2/default', 'okta-ava-patel', FALSE)
ON CONFLICT (org_id, email) DO UPDATE
   SET display_name = EXCLUDED.display_name,
       oidc_issuer = EXCLUDED.oidc_issuer,
       oidc_subject = EXCLUDED.oidc_subject,
       disabled = FALSE
RETURNING id`, orgID).Scan(&analystID); err != nil {
		logger.Warn("access user seed", slog.String("err", err.Error()))
		return
	}

	var bindingID uuid.UUID
	scopes := `[{"kind":"org","values":["demo"]}]`
	if err := pool.QueryRow(ctx, `
INSERT INTO role_bindings (org_id, subject_id, subject_type, role_id, scopes, granted_by)
VALUES ($1, $2, 'user', 'GlobalAdmin', $3::jsonb, $4)
ON CONFLICT (org_id, subject_id, role_id) DO UPDATE
   SET scopes = EXCLUDED.scopes,
       granted_by = EXCLUDED.granted_by,
       granted_at = NOW(),
       expires_at = NULL
RETURNING id`, orgID, analystID.String(), scopes, adminID).Scan(&bindingID); err != nil {
		logger.Warn("access binding seed", slog.String("err", err.Error()))
		return
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_assignments (user_id, role, scope_org_id, binding_id)
VALUES ($1, 'GlobalAdmin', $2, $3)
ON CONFLICT DO NOTHING`, analystID, orgID, bindingID); err != nil {
		logger.Warn("access assignment seed", slog.String("err", err.Error()))
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO auth_servers (org_id, type, name, enabled, auth_order, config, role_mapping)
VALUES ($1, 'oidc', 'Okta Workforce', TRUE, 10,
        '{"issuer_url":"https://okta.example.com/oauth2/default","client_id":"constellation-demo","scopes":["openid","email","profile"]}'::jsonb,
        '{"rules":{"group:platform-security":"GlobalAdmin","group:security-analysts":"Analyst"},"default":"Auditor"}'::jsonb)
ON CONFLICT (org_id, name) DO UPDATE
   SET enabled = EXCLUDED.enabled,
       auth_order = EXCLUDED.auth_order,
       config = EXCLUDED.config,
       role_mapping = EXCLUDED.role_mapping,
       revision = auth_servers.revision + 1,
       updated_at = NOW()`, orgID); err != nil {
		logger.Warn("auth server seed", slog.String("err", err.Error()))
	}

	var serviceAccountID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO service_accounts (org_id, name, description, owner, status, scopes, roles)
VALUES ($1, 'CI scanner', 'Automation identity for registry and workload scans', 'platform-security', 'active',
        '["registry:ghcr.io/demo","cluster:prod-east"]'::jsonb,
        '["SecurityAdmin"]'::jsonb)
ON CONFLICT (org_id, name) DO UPDATE
   SET description = EXCLUDED.description,
       owner = EXCLUDED.owner,
       status = EXCLUDED.status,
       scopes = EXCLUDED.scopes,
       roles = EXCLUDED.roles
RETURNING id`, orgID).Scan(&serviceAccountID); err != nil {
		logger.Warn("service account seed", slog.String("err", err.Error()))
		return
	}
	sum := sha256.Sum256([]byte("cst_demo_ci_scanner"))
	if _, err := pool.Exec(ctx, `
INSERT INTO api_tokens (service_account_id, name, token_hash, scopes, status, expires_at)
VALUES ($1, 'CI scanner', $2, '["scan:registry","assets:read"]'::jsonb, 'active', NOW() + INTERVAL '90 days')
ON CONFLICT (token_hash) DO UPDATE
   SET service_account_id = EXCLUDED.service_account_id,
       name = EXCLUDED.name,
       scopes = EXCLUDED.scopes,
       status = EXCLUDED.status,
       expires_at = EXCLUDED.expires_at`, serviceAccountID, hex.EncodeToString(sum[:])); err != nil {
		logger.Warn("api token seed", slog.String("err", err.Error()))
	}
}

func seedConnectorCoverage(ctx context.Context, pool *pgxpool.Pool, orgID, clusterID, adminID, imageAssetID uuid.UUID, logger *slog.Logger) {
	type registrySeed struct {
		key, name, kind, endpoint, authKind, cadence string
		imagesSeen                                   int
		repositories                                 []struct {
			name string
			tags []string
		}
	}
	registries := []registrySeed{
		{
			key:        "ghcr",
			name:       "GitHub Container Registry",
			kind:       "ghcr",
			endpoint:   "ghcr.io",
			authKind:   "static",
			cadence:    "hourly",
			imagesSeen: 4,
			repositories: []struct {
				name string
				tags []string
			}{
				{"ghcr.io/demo/api", []string{"1.0.0", "stable"}},
				{"ghcr.io/demo/worker", []string{"1.0.0", "canary"}},
			},
		},
		{
			key:        "ecr",
			name:       "AWS ECR production",
			kind:       "ecr",
			endpoint:   "123456789012.dkr.ecr.us-east-1.amazonaws.com",
			authKind:   "aws-iam-role",
			cadence:    "6h",
			imagesSeen: 12,
			repositories: []struct {
				name string
				tags []string
			}{
				{"123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api", []string{"2026.08.23", "prod"}},
			},
		},
		{
			key:        "jfrog",
			name:       "JFrog Artifactory shared",
			kind:       "jfrog",
			endpoint:   "artifactory.demo.test",
			authKind:   "static",
			cadence:    "daily",
			imagesSeen: 8,
			repositories: []struct {
				name string
				tags []string
			}{
				{"artifactory.demo.test/shared/frontend", []string{"2.4.1", "stable"}},
			},
		},
	}

	for _, reg := range registries {
		registryID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("constellation-demo-registry-"+reg.key))
		if err := pool.QueryRow(ctx, `
INSERT INTO registries (id, org_id, name, kind, endpoint, auth_kind, auth_secret, scan_cadence,
                        image_globs, last_sync_at, last_sync_status, images_seen, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ARRAY['*'], NOW() - INTERVAL '10 minutes', 'ok', $9, $10)
ON CONFLICT (org_id, name) DO UPDATE
   SET kind = EXCLUDED.kind,
       endpoint = EXCLUDED.endpoint,
       auth_kind = EXCLUDED.auth_kind,
       auth_secret = EXCLUDED.auth_secret,
       scan_cadence = EXCLUDED.scan_cadence,
       image_globs = EXCLUDED.image_globs,
       last_sync_at = EXCLUDED.last_sync_at,
       last_sync_status = EXCLUDED.last_sync_status,
       images_seen = EXCLUDED.images_seen,
       updated_at = NOW()
RETURNING id`, registryID, orgID, reg.name, reg.kind, reg.endpoint, reg.authKind, []byte("demo-encrypted-secret"), reg.cadence, reg.imagesSeen, adminID).Scan(&registryID); err != nil {
			logger.Warn("registry seed", slog.String("registry", reg.name), slog.String("err", err.Error()))
			continue
		}
		for _, repo := range reg.repositories {
			if _, err := pool.Exec(ctx, `
INSERT INTO registry_images (org_id, registry_id, repository, tags, last_pushed_at, last_seen_at)
VALUES ($1, $2, $3, $4, NOW()::text, NOW())
ON CONFLICT (registry_id, repository) DO UPDATE
   SET tags = EXCLUDED.tags,
       last_pushed_at = EXCLUDED.last_pushed_at,
       last_seen_at = EXCLUDED.last_seen_at`, orgID, registryID, repo.name, repo.tags); err != nil {
				logger.Warn("registry image seed", slog.String("repository", repo.name), slog.String("err", err.Error()))
			}
		}
		credentialRef := "vault://kv/constellation/" + reg.key + "-prod"
		fingerprint := sha256.Sum256([]byte(credentialRef))
		if _, err := pool.Exec(ctx, `
INSERT INTO connector_configs (org_id, connector_id, connector_type, provider, display_name, endpoint,
                               auth_mode, owner, scan_cadence, rotation_due_at, credential_ref,
                               credential_fingerprint, credential_present, last_test_status, last_test_at,
                               created_by, updated_by)
VALUES ($1, $2, 'registry', $3, $4, $5, $6, 'platform-security', $7,
        NOW() + INTERVAL '21 days', $8, $9, TRUE, 'healthy', NOW() - INTERVAL '5 minutes', $10, $10)
ON CONFLICT (org_id, connector_type, connector_id) DO UPDATE
   SET provider = EXCLUDED.provider,
       display_name = EXCLUDED.display_name,
       endpoint = EXCLUDED.endpoint,
       auth_mode = EXCLUDED.auth_mode,
       owner = EXCLUDED.owner,
       scan_cadence = EXCLUDED.scan_cadence,
       rotation_due_at = EXCLUDED.rotation_due_at,
       credential_ref = EXCLUDED.credential_ref,
       credential_fingerprint = EXCLUDED.credential_fingerprint,
       credential_present = TRUE,
       last_test_status = EXCLUDED.last_test_status,
       last_test_at = EXCLUDED.last_test_at,
       updated_by = EXCLUDED.updated_by,
       updated_at = NOW()`, orgID, registryID.String(), reg.kind, reg.name, reg.endpoint, reg.authKind, reg.cadence, credentialRef, hex.EncodeToString(fingerprint[:]), adminID); err != nil {
			logger.Warn("connector config seed", slog.String("connector", reg.name), slog.String("err", err.Error()))
		}
	}

	for _, cloud := range []struct {
		id, provider, name, account, authMode string
	}{
		{"aws-production", "aws", "AWS production", "123456789012", "cross-account role"},
		{"azure-enterprise", "azure", "Azure enterprise subscription", "00000000-0000-0000-0000-000000000042", "federated workload identity"},
	} {
		credentialRef := "vault://kv/constellation/" + cloud.id
		fingerprint := sha256.Sum256([]byte(credentialRef))
		if _, err := pool.Exec(ctx, `
INSERT INTO connector_configs (org_id, connector_id, connector_type, provider, display_name, endpoint,
                               auth_mode, owner, scan_cadence, rotation_due_at, credential_ref,
                               credential_fingerprint, credential_present, last_test_status, last_test_at,
                               created_by, updated_by)
VALUES ($1, $2, 'cloud', $3, $4, $5, $6, 'cloud-security', 'daily',
        NOW() + INTERVAL '18 days', $7, $8, TRUE, 'healthy', NOW() - INTERVAL '7 minutes', $9, $9)
ON CONFLICT (org_id, connector_type, connector_id) DO UPDATE
   SET provider = EXCLUDED.provider,
       display_name = EXCLUDED.display_name,
       endpoint = EXCLUDED.endpoint,
       auth_mode = EXCLUDED.auth_mode,
       owner = EXCLUDED.owner,
       scan_cadence = EXCLUDED.scan_cadence,
       rotation_due_at = EXCLUDED.rotation_due_at,
       credential_ref = EXCLUDED.credential_ref,
       credential_fingerprint = EXCLUDED.credential_fingerprint,
       credential_present = TRUE,
       last_test_status = EXCLUDED.last_test_status,
       last_test_at = EXCLUDED.last_test_at,
       updated_by = EXCLUDED.updated_by,
       updated_at = NOW()`, orgID, cloud.id, cloud.provider, cloud.name, cloud.account, cloud.authMode, credentialRef, hex.EncodeToString(fingerprint[:]), adminID); err != nil {
			logger.Warn("cloud connector seed", slog.String("connector", cloud.name), slog.String("err", err.Error()))
		}
	}

	metadata := map[string]any{
		"instance_id":                "scanner-prod-east-0",
		"max_concurrent":             4,
		"active_jobs":                1,
		"idle_capacity":              3,
		"target_capacity":            map[string]int{"image": 4, "host": 1},
		"active_jobs_by_target_type": map[string]int{"image": 1},
		"cache_hits":                 37,
		"cache_misses":               4,
		"cache_health":               map[string]any{"syft": map[string]any{"configured": true, "writable": true, "status": "ready"}, "trivy": map[string]any{"configured": true, "writable": true, "status": "ready"}},
		"cache_records":              []map[string]any{{"cache": "trivy", "layer": "sha256:layer1", "size": 12_000_000, "ref_count": 3, "ref_last": time.Now().UTC().Format(time.RFC3339)}},
		"vulndb":                     map[string]any{"enabled": true, "ready": true, "status": "ready", "bundle_version": "2026-05-11T120000Z"},
	}
	metadataRaw, _ := json.Marshal(metadata)
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats (org_id, cluster_id, component, version, hostname, uptime_seconds, metadata, last_seen_at)
VALUES ($1, $2, 'scanner', 'demo-scanner-0.1.0', 'scanner-prod-east-0', 7200, $3::jsonb, NOW())
ON CONFLICT (org_id, cluster_id, component, hostname) DO UPDATE
   SET version = EXCLUDED.version,
       uptime_seconds = EXCLUDED.uptime_seconds,
       metadata = EXCLUDED.metadata,
       last_seen_at = NOW()`, orgID, clusterID, metadataRaw); err != nil {
		logger.Warn("scanner heartbeat seed", slog.String("err", err.Error()))
	}

	ghcrID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("constellation-demo-registry-ghcr"))
	targetID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("constellation-demo-scan-target-api"))
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, cluster_id, type, ref, source_type, source_ref,
                          image_ref, image_digest, registry_id, platform, metadata)
VALUES ($1, $2, $3, 'image', 'ghcr.io/demo/api:1.0.0', 'registry', 'demo-seed',
        'ghcr.io/demo/api:1.0.0', 'sha256:aaaa', $4, 'linux/amd64', '{"seed":"demo"}'::jsonb)
ON CONFLICT (id) DO UPDATE
   SET last_seen_at = NOW(),
       metadata = EXCLUDED.metadata`, targetID, orgID, clusterID, ghcrID); err != nil {
		logger.Warn("scan target seed", slog.String("err", err.Error()))
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, worker_id, requested_by, package_count, finding_count,
                       requested_at, claimed_at, finished_at, attempt_count, max_attempts)
VALUES ($1, $2, $3, 'completed', 'scanner-prod-east-0', $4, 124, 2,
        NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '14 minutes', NOW() - INTERVAL '12 minutes', 1, 3)
ON CONFLICT (id) DO UPDATE
   SET status = EXCLUDED.status,
       worker_id = EXCLUDED.worker_id,
       package_count = EXCLUDED.package_count,
       finding_count = EXCLUDED.finding_count,
       requested_at = EXCLUDED.requested_at,
       claimed_at = EXCLUDED.claimed_at,
       finished_at = EXCLUDED.finished_at`, uuid.NewSHA1(uuid.NameSpaceOID, []byte("constellation-demo-scan-job-api")), orgID, targetID, adminID); err != nil {
		logger.Warn("scan job seed", slog.String("err", err.Error()))
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, requested_by, requested_at, attempt_count, max_attempts)
VALUES ($1, $2, $3, 'pending', $4, NOW() - INTERVAL '3 minutes', 0, 3)
ON CONFLICT (id) DO UPDATE
   SET status = EXCLUDED.status,
       requested_at = EXCLUDED.requested_at,
       attempt_count = EXCLUDED.attempt_count,
       max_attempts = EXCLUDED.max_attempts`, uuid.NewSHA1(uuid.NameSpaceOID, []byte("constellation-demo-scan-job-api-pending")), orgID, targetID, adminID); err != nil {
		logger.Warn("pending scan job seed", slog.String("err", err.Error()))
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (org_id, scan_target_id, asset_id, image_ref, image_ref_normalized,
                                image_repository, image_tag, image_digest, platform,
                                scanner_profile, vulndb_bundle_version, vulndb_bundle_hash,
                                package_count, finding_count, bundle_metadata,
                                first_seen_at, last_scanned_at, updated_at)
VALUES ($1, $2, $3, 'ghcr.io/demo/api:1.0.0', 'ghcr.io/demo/api:1.0.0',
        'ghcr.io/demo/api', '1.0.0', 'sha256:aaaa', 'linux/amd64',
        'default', '2026-05-11T120000Z', 'fakesha256-demo',
        124, 2, '{"signed":true,"source":"demo-seed"}'::jsonb,
        NOW() - INTERVAL '2 days', NOW() - INTERVAL '12 minutes', NOW())
ON CONFLICT (org_id, image_digest, platform, scanner_profile, vulndb_bundle_version, vulndb_bundle_hash)
DO UPDATE SET scan_target_id = EXCLUDED.scan_target_id,
              asset_id = EXCLUDED.asset_id,
              package_count = EXCLUDED.package_count,
              finding_count = EXCLUDED.finding_count,
              last_scanned_at = EXCLUDED.last_scanned_at,
              updated_at = NOW()`, orgID, targetID, imageAssetID); err != nil {
		logger.Warn("image scan result seed", slog.String("err", err.Error()))
	}
}

func seedComplianceSchedules(ctx context.Context, pool *pgxpool.Pool, orgID, clusterID, adminID uuid.UUID, logger *slog.Logger) {
	schedules := []struct {
		name, description, framework, cron, format, template string
		clusterScoped                                        bool
		delivery                                             string
	}{
		{
			name:          "CIS Kubernetes production weekly",
			description:   "Weekly evidence package for the production Kubernetes benchmark.",
			framework:     "cis-k8s-1.9",
			cron:          "0 6 * * 1",
			format:        "pdf",
			template:      "compliance-detailed",
			clusterScoped: true,
			delivery:      `[{"kind":"email","target":"security-compliance@demo.test"},{"kind":"s3","bucket":"constellation-demo-reports","prefix":"cis/"}]`,
		},
		{
			name:        "SOC 2 controls daily",
			description: "Daily SOC 2 evidence export for audit readiness.",
			framework:   "soc2",
			cron:        "0 5 * * *",
			format:      "json",
			template:    "compliance-summary",
			delivery:    `[{"kind":"webhook","receiver_id":"pagerduty-critical"}]`,
		},
		{
			name:        "PCI DSS merchant monthly",
			description: "Monthly PCI DSS evidence snapshot for cardholder-data environments.",
			framework:   "pci-dss-4.0",
			cron:        "0 7 1 * *",
			format:      "sarif",
			template:    "compliance-detailed",
			delivery:    `[{"kind":"file","target":"file:///tmp/constellation-compliance/"}]`,
		},
	}
	for _, schedule := range schedules {
		var scopedCluster any
		if schedule.clusterScoped {
			scopedCluster = clusterID
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO compliance_schedules (org_id, cluster_id, name, description, framework, cron_expression,
                                  timezone, enabled, delivery, report_format, report_template,
                                  last_run_at, next_run_at, last_status, last_artifact_uri, created_by)
VALUES ($1, $2, $3, $4, $5, $6, 'UTC', TRUE, $7::jsonb, $8, $9,
        NOW() - INTERVAL '1 day', NOW() + INTERVAL '1 day', 'succeeded', 's3://constellation-demo-reports/evidence/demo.pdf', $10)
ON CONFLICT (org_id, name) DO UPDATE
   SET cluster_id = EXCLUDED.cluster_id,
       description = EXCLUDED.description,
       framework = EXCLUDED.framework,
       cron_expression = EXCLUDED.cron_expression,
       timezone = EXCLUDED.timezone,
       enabled = EXCLUDED.enabled,
       delivery = EXCLUDED.delivery,
       report_format = EXCLUDED.report_format,
       report_template = EXCLUDED.report_template,
       last_run_at = EXCLUDED.last_run_at,
       next_run_at = EXCLUDED.next_run_at,
       last_status = EXCLUDED.last_status,
       last_artifact_uri = EXCLUDED.last_artifact_uri,
       updated_at = NOW()`, orgID, scopedCluster, schedule.name, schedule.description, schedule.framework, schedule.cron, schedule.delivery, schedule.format, schedule.template, adminID); err != nil {
			logger.Warn("compliance schedule seed", slog.String("schedule", schedule.name), slog.String("err", err.Error()))
		}
	}
}

func seedIntegrations(ctx context.Context, pool *pgxpool.Pool, orgID, adminID uuid.UUID, logger *slog.Logger) {
	type receiverSeed struct {
		key, name, kind, endpoint, secretRef, owner, env, status, message string
		events                                                            []string
		rate                                                              int
	}
	receivers := []receiverSeed{
		{
			key:       "pagerduty-critical",
			name:      "Critical PagerDuty service",
			kind:      "pagerduty",
			endpoint:  "https://events.pagerduty.com/v2/enqueue",
			secretRef: "vault://kv/constellation/pagerduty-critical",
			owner:     "secops",
			env:       "production",
			status:    "healthy",
			message:   "Verified through read-only preview and recent successful delivery.",
			events:    []string{"finding.escalated", "runtime.threat"},
			rate:      30,
		},
		{
			key:       "secops-slack",
			name:      "SecOps Slack",
			kind:      "slack",
			endpoint:  "https://hooks.slack.com/services/T000/B000/SECRET",
			secretRef: "vault://kv/constellation/slack-secops",
			owner:     "secops",
			env:       "production",
			status:    "healthy",
			message:   "Slack receiver responding inside target latency.",
			events:    []string{"finding.accept_risk", "policy.deny"},
			rate:      60,
		},
		{
			key:       "servicenow-sec-queue",
			name:      "ServiceNow security queue",
			kind:      "servicenow",
			endpoint:  "https://demo.service-now.com/api/now/table/incident",
			secretRef: "vault://kv/constellation/servicenow-sec",
			owner:     "security-operations",
			env:       "production",
			status:    "degraded",
			message:   "One delivery is retrying and one dead letter is retained for audit.",
			events:    []string{"finding.escalated", "compliance.failed"},
			rate:      20,
		},
	}
	receiverIDs := map[string]uuid.UUID{}
	for _, receiver := range receivers {
		id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("constellation-demo-receiver-"+receiver.key))
		receiverIDs[receiver.key] = id
		eventsRaw, _ := json.Marshal(receiver.events)
		configRaw, _ := json.Marshal(map[string]any{"seed": "demo", "routing_key": receiver.key})
		if _, err := pool.Exec(ctx, `
INSERT INTO receivers (id, org_id, name, kind, endpoint, secret_ref, owner, environment, status,
                       status_message, supported_events, config, last_verified_at,
                       secret_key, rate_per_min, template_id, paused)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb,
        NOW() - INTERVAL '10 minutes', 'demo-hmac-secret', $13, 'default', FALSE)
ON CONFLICT (org_id, name) DO UPDATE
   SET kind = EXCLUDED.kind,
       endpoint = EXCLUDED.endpoint,
       secret_ref = EXCLUDED.secret_ref,
       owner = EXCLUDED.owner,
       environment = EXCLUDED.environment,
       status = EXCLUDED.status,
       status_message = EXCLUDED.status_message,
       supported_events = EXCLUDED.supported_events,
       config = EXCLUDED.config,
       last_verified_at = EXCLUDED.last_verified_at,
       secret_key = EXCLUDED.secret_key,
       rate_per_min = EXCLUDED.rate_per_min,
       template_id = EXCLUDED.template_id,
       paused = FALSE,
       updated_at = NOW()`, id, orgID, receiver.name, receiver.kind, receiver.endpoint, receiver.secretRef, receiver.owner, receiver.env, receiver.status, receiver.message, eventsRaw, configRaw, receiver.rate); err != nil {
			logger.Warn("receiver seed", slog.String("receiver", receiver.name), slog.String("err", err.Error()))
		}
	}

	deliveries := []struct {
		key, receiverKey, eventType, severity, status, finalState, ruleID, errMsg string
		attempts, latency                                                         int
		minutesAgo                                                                int
	}{
		{"pagerduty-success", "pagerduty-critical", "finding.escalated", "critical", "delivered", "delivered", "pagerduty-critical", "", 1, 420, 11},
		{"slack-success", "secops-slack", "policy.deny", "high", "delivered", "delivered", "secops-slack", "", 1, 180, 17},
		{"servicenow-retry", "servicenow-sec-queue", "finding.escalated", "high", "retrying", "", "servicenow-sec-queue", "HTTP 429 rate limit", 2, 0, 6},
		{"servicenow-dlq", "servicenow-sec-queue", "compliance.failed", "critical", "dropped", "dropped", "servicenow-sec-queue", "DLQ after max attempts", 4, 0, 34},
	}
	for _, delivery := range deliveries {
		receiverID := receiverIDs[delivery.receiverKey]
		if receiverID == uuid.Nil {
			continue
		}
		id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("constellation-demo-delivery-"+delivery.key))
		idempotency := uuid.NewSHA1(uuid.NameSpaceOID, []byte("constellation-demo-delivery-idem-"+delivery.key))
		if _, err := pool.Exec(ctx, `
INSERT INTO receiver_deliveries (id, org_id, receiver_id, event_type, severity, status, routing_rule_id,
                                 attempts, latency_ms, trace_id, error, artifacts, payload_hash,
                                 created_at, delivered_at, idempotency_key, next_retry_at, signed_at, final_state)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'trace-demo', $10,
        '["hash-chain","demo-seed"]'::jsonb, 'sha256-demo',
        NOW() - (($11::int)::text || ' minutes')::interval,
        CASE WHEN $6 = 'delivered' THEN NOW() - (($11::int - 1)::text || ' minutes')::interval ELSE NULL END,
        $12,
        CASE WHEN $6 = 'retrying' THEN NOW() + INTERVAL '5 minutes' ELSE NULL END,
        NOW() - (($11::int)::text || ' minutes')::interval,
        NULLIF($13, ''))
ON CONFLICT (id) DO UPDATE
   SET status = EXCLUDED.status,
       attempts = EXCLUDED.attempts,
       latency_ms = EXCLUDED.latency_ms,
       error = EXCLUDED.error,
       created_at = EXCLUDED.created_at,
       delivered_at = EXCLUDED.delivered_at,
       next_retry_at = EXCLUDED.next_retry_at,
       signed_at = EXCLUDED.signed_at,
       final_state = EXCLUDED.final_state`, id, orgID, receiverID, delivery.eventType, delivery.severity, delivery.status, delivery.ruleID, delivery.attempts, delivery.latency, delivery.errMsg, delivery.minutesAgo, idempotency, delivery.finalState); err != nil {
			logger.Warn("receiver delivery seed", slog.String("delivery", delivery.key), slog.String("err", err.Error()))
		}
	}

	routingYAML := `route:
  receiver: secops-slack
  routes:
    - receiver: pagerduty-critical
      match:
        severity: critical
      receivers: ["pagerduty-critical"]
    - receiver: servicenow-sec-queue
      match:
        kind: compliance
      receivers: ["servicenow-sec-queue"]
`
	if _, err := pool.Exec(ctx, `
INSERT INTO routing_configs (org_id, yaml, revision, updated_at, updated_by)
VALUES ($1, $2, 3, NOW(), $3)
ON CONFLICT (org_id) DO UPDATE
   SET yaml = EXCLUDED.yaml,
       revision = EXCLUDED.revision,
       updated_at = NOW(),
       updated_by = EXCLUDED.updated_by`, orgID, routingYAML, adminID); err != nil {
		logger.Warn("routing config seed", slog.String("err", err.Error()))
	}
}

func seedExtraCluster(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, name, distro, provider, region string, logger *slog.Logger) {
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (org_id, name, distro, cloud_provider, region, state, agent_version, last_heartbeat_at)
VALUES ($1, $2, $3, $4, $5, 'connected', 'demo-agent-0.1.0', NOW())
ON CONFLICT (org_id, name) DO UPDATE
   SET distro = EXCLUDED.distro,
       cloud_provider = EXCLUDED.cloud_provider,
       region = EXCLUDED.region,
       state = EXCLUDED.state,
       last_heartbeat_at = NOW()`, orgID, name, distro, provider, region); err != nil {
		logger.Warn("extra cluster seed", slog.String("cluster", name), slog.String("err", err.Error()))
	}
}

func upsertAsset(ctx context.Context, pool *pgxpool.Pool, orgID, clusterID uuid.UUID, kind, name, digest, criticality string) uuid.UUID {
	labels, _ := json.Marshal(map[string]string{"env": "demo"})
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO assets (org_id, cluster_id, kind, name, digest, labels, ai_workload, criticality)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (org_id, kind, name, digest) DO UPDATE
   SET cluster_id = EXCLUDED.cluster_id,
       labels = EXCLUDED.labels,
       ai_workload = EXCLUDED.ai_workload,
       criticality = EXCLUDED.criticality,
       last_seen_at = NOW()
RETURNING id`, orgID, clusterID, kind, name, digest, labels, kind == "ml-model", criticality).Scan(&id); err != nil {
		panic(err)
	}
	return id
}

func refreshNetworkFlowRollups(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, logger *slog.Logger) {
	if _, err := pool.Exec(ctx, `INSERT INTO network_flow_rollup_state (id) VALUES (true) ON CONFLICT DO NOTHING`); err != nil {
		logger.Warn("network flow rollup state", slog.String("err", err.Error()))
		return
	}
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE network_flow_rollups`); err != nil {
		logger.Warn("network flow rollup reset", slog.String("err", err.Error()))
		return
	}
	tag, err := pool.Exec(ctx, `
INSERT INTO network_flow_rollups (
    org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bucket,
    sum_bytes, sum_packets, flow_count, max_at, min_src_addr, min_dst_addr, min_src_port,
    has_dp, has_hubble, has_bpf, min_source, sum_client_bytes, sum_server_bytes, sum_sessions,
    max_threat_id, max_severity, max_application, fqdn)
SELECT f.org_id, f.cluster_id, f.src_workload, f.dst_workload, f.protocol,
       COALESCE(f.l7_protocol, ''), COALESCE(f.dst_port, 0), COALESCE(f.verdict, ''),
       date_trunc('hour', f.at),
       SUM(COALESCE(f.bytes, 0))::bigint, SUM(COALESCE(f.packets, 0))::bigint, COUNT(*)::bigint, MAX(f.at),
       COALESCE(MIN(f.src_addr), ''), COALESCE(MIN(f.dst_addr), ''), COALESCE(MIN(f.src_port), 0),
       bool_or(f.source = 'dp'), bool_or(f.source = 'hubble'), bool_or(f.source = 'bpf'), COALESCE(MIN(f.source), ''),
       SUM(COALESCE(f.client_bytes, 0))::bigint, SUM(COALESCE(f.server_bytes, 0))::bigint, SUM(COALESCE(f.sessions, 0))::bigint,
       MAX(f.threat_id), MAX(f.severity), MAX(f.application), COALESCE(MIN(NULLIF(f.fqdn, '')), '')
  FROM network_flows f
 WHERE f.org_id = $1
   AND f.cluster_id IS NOT NULL
 GROUP BY f.org_id, f.cluster_id, f.src_workload, f.dst_workload, f.protocol,
          COALESCE(f.l7_protocol, ''), COALESCE(f.dst_port, 0), COALESCE(f.verdict, ''),
          date_trunc('hour', f.at)
ON CONFLICT (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bucket)
DO UPDATE SET
    sum_bytes        = EXCLUDED.sum_bytes,
    sum_packets      = EXCLUDED.sum_packets,
    flow_count       = EXCLUDED.flow_count,
    max_at           = EXCLUDED.max_at,
    min_src_addr     = EXCLUDED.min_src_addr,
    min_dst_addr     = EXCLUDED.min_dst_addr,
    min_src_port     = EXCLUDED.min_src_port,
    has_dp           = EXCLUDED.has_dp,
    has_hubble       = EXCLUDED.has_hubble,
    has_bpf          = EXCLUDED.has_bpf,
    min_source       = EXCLUDED.min_source,
    sum_client_bytes = EXCLUDED.sum_client_bytes,
    sum_server_bytes = EXCLUDED.sum_server_bytes,
    sum_sessions     = EXCLUDED.sum_sessions,
    max_threat_id    = EXCLUDED.max_threat_id,
    max_severity     = EXCLUDED.max_severity,
    max_application  = EXCLUDED.max_application,
    fqdn             = EXCLUDED.fqdn`,
		orgID)
	if err != nil {
		logger.Warn("network flow rollup refresh", slog.String("err", err.Error()))
		return
	}
	if _, err := pool.Exec(ctx, `UPDATE network_flow_rollup_state SET watermark = COALESCE((SELECT MAX(at) FROM network_flows), '1970-01-01T00:00:00Z'::timestamptz)`); err != nil {
		logger.Warn("network flow rollup watermark", slog.String("err", err.Error()))
		return
	}
	logger.Info("network flow rollups seeded", slog.Int64("rows", tag.RowsAffected()))
}

func insertFinding(ctx context.Context, pool *pgxpool.Pool, orgID, clusterID, assetID uuid.UUID,
	kind, externalID, title, severity string,
	cvss, epss float64, kev, reachable bool, criticality string,
	techniques ...string,
) {
	score := risk.Compute(risk.Inputs{
		CVSSBase: cvss, KEVListed: kev, EPSSProbability: epss,
		ReachableRuntime: reachable, AssetCriticality: criticality,
	})
	inputs, _ := json.Marshal(map[string]any{
		"cvss_base": cvss, "kev_listed": kev, "epss_probability": epss,
		"reachable_runtime": reachable, "asset_criticality": criticality,
	})
	engines, _ := json.Marshal([]map[string]any{{"engine": "demo", "confidence": 0.95}})
	if len(techniques) == 0 {
		techniques = []string{}
	}
	targetType := "asset"
	targetRef := assetID.String()
	canonicalEngine := ""
	detail := map[string]any{}
	switch kind {
	case "vulnerability", "license", "signature", "secret":
		targetType = "image"
		targetRef = "ghcr.io/demo/api@sha256:aaaa"
	case "runtime", "drift", "compliance":
		targetType = "workload"
		targetRef = "default/Deployment/api"
	case "cloud-config":
		targetType = "platform"
		targetRef = "aws:s3:public-bucket"
	case "iac":
		targetType = "repository"
		targetRef = "terraform/main.tf"
	case "ml-model":
		targetType = "repository"
		targetRef = "huggingface/llama-2-7b"
	}
	if kind == "vulnerability" {
		pkg := map[string]any{
			"ecosystem": "deb",
			"name":      "glibc",
			"version":   "2.37-3",
			"purl":      "pkg:deb/debian/glibc@2.37-3",
		}
		fixed := "2.37-9"
		if externalID == "CVE-2023-1234" {
			pkg = map[string]any{
				"ecosystem": "deb",
				"name":      "openssl",
				"version":   "3.0.8",
				"purl":      "pkg:deb/debian/openssl@3.0.8",
			}
			fixed = "3.0.12"
		}
		detail = map[string]any{
			"image_ref":         "ghcr.io/demo/api:1.0.0",
			"image_digest":      "sha256:aaaa",
			"package":           pkg,
			"package_name":      pkg["name"],
			"fixed":             fixed,
			"fixed_version":     fixed,
			"cvss_base":         cvss,
			"kev":               kev,
			"epss":              epss,
			"canonical_engine":  "demo-vulndb",
			"vulndb_bundle":     map[string]any{"version": "2026-05-11T120000Z", "sha256": "fakesha256-demo"},
			"reachable_runtime": reachable,
		}
		canonicalEngine = "demo-vulndb"
	}
	detailRaw, _ := json.Marshal(detail)
	// Add jitter to last_seen so the dashboard ordering is meaningful.
	jitter := time.Duration(rand.Intn(60)) * time.Minute
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, cluster_id, asset_id, kind, external_id, title, description, severity,
                      risk_score, risk_inputs, lifecycle, engines, detail_json, canonical_engine,
                      target_type, target_ref, target_cluster_id, source_type, attack_techniques,
                      first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
        $9, $10, 'open', $11, $12::jsonb, NULLIF($13, ''),
        $14, $15, $2, 'demo-seed', $16,
        NOW() - INTERVAL '2 days', NOW() - $17::interval)`,
		orgID, clusterID, assetID, kind, externalID, title, title, severity, score,
		inputs, engines, detailRaw, canonicalEngine, targetType, targetRef, techniques,
		fmt.Sprintf("%d minutes", int(jitter.Minutes()))); err != nil {
		panic(err)
	}
}
