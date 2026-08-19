// constellation-seed populates a fresh Postgres with a demo org, admin user, sample assets,
// findings (one per kind), policies, and an audit-event for the dashboard / Playwright tests.
package main

import (
	"context"
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

	hash, _ := auth.HashPassword(*password)
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO users (org_id, email, display_name, password_hash)
VALUES ($1, 'admin@demo.test', 'Demo Admin', $2)
ON CONFLICT (org_id, email) DO UPDATE SET password_hash = EXCLUDED.password_hash
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

	var clusterID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO clusters (org_id, name, distro, cloud_provider, region, state, agent_version, last_heartbeat_at)
VALUES ($1, 'prod-east', 'eks', 'aws', 'us-east-1', 'connected', 'demo-agent-0.1.0', NOW())
ON CONFLICT (org_id, name) DO UPDATE SET state = EXCLUDED.state, last_heartbeat_at = NOW()
RETURNING id`, orgID).Scan(&clusterID); err != nil {
		logger.Error("cluster", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// One asset per kind so the Assets page is non-empty.
	imgID := upsertAsset(ctx, pool, orgID, "image", "ghcr.io/demo/api", "sha256:aaaa", "high")
	workloadID := upsertAsset(ctx, pool, orgID, "workload", "default/Deployment/api", "", "high")
	iacID := upsertAsset(ctx, pool, orgID, "iac-resource", "terraform/main.tf", "sha256:bbbb", "medium")
	mlID := upsertAsset(ctx, pool, orgID, "ml-model", "huggingface/llama-2-7b", "sha256:cccc", "medium")
	cloudID := upsertAsset(ctx, pool, orgID, "cloud-resource", "aws:s3:public-bucket", "", "critical")

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
	insertFinding(ctx, pool, orgID, imgID, "vulnerability", "CVE-2024-0001",
		"glibc heap overflow", "critical", 8.8, 0.95, true, true, "high")
	insertFinding(ctx, pool, orgID, imgID, "vulnerability", "CVE-2023-1234",
		"openssl side-channel", "high", 7.5, 0.4, false, true, "high")
	insertFinding(ctx, pool, orgID, imgID, "license", "license-AGPL-3.0",
		"AGPL-3.0 in commercial workload", "medium", 0, 0, false, false, "high")
	insertFinding(ctx, pool, orgID, iacID, "iac", "AVD-AWS-0001",
		"S3 bucket has no encryption", "high", 0, 0, false, false, "medium")
	insertFinding(ctx, pool, orgID, cloudID, "cloud-config", "cspm-s3-public",
		"S3 bucket allows public read", "critical", 0, 0, false, false, "critical")
	insertFinding(ctx, pool, orgID, workloadID, "runtime", "FALCO-1001",
		"shell spawned in container", "high", 0, 0, false, true, "high",
		"T1059.004")
	insertFinding(ctx, pool, orgID, workloadID, "drift", "drift-rolebinding",
		"RoleBinding declared in Git missing from cluster", "medium", 0, 0, false, false, "medium")
	insertFinding(ctx, pool, orgID, mlID, "ml-model", "MBOM-LLAMA-001",
		"Pickle deserialization in model artifact", "high", 0, 0, false, false, "medium")
	insertFinding(ctx, pool, orgID, imgID, "signature", "sig-missing",
		"Image not signed by trusted identity", "high", 0, 0, false, false, "high")
	insertFinding(ctx, pool, orgID, imgID, "secret", "secret-aws-key",
		"Hardcoded AWS access key in layer 4", "critical", 0, 0, false, false, "high")
	insertFinding(ctx, pool, orgID, workloadID, "compliance", "cis-k8s-5.1.3",
		"Minimize wildcard use in Roles and ClusterRoles", "medium", 0, 0, false, false, "high")

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
        'kyverno', 'signature-verification',
        'apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: block-unsigned\n', TRUE, 'enforce')
ON CONFLICT (org_id, name, version) DO NOTHING`, orgID); err != nil {
		logger.Error("policy", slog.String("err", err.Error()))
	}

	// Audit log: a couple of seed events so the Audit page renders rows.
	auditor := auditlog.New(pool)
	for _, action := range []string{"org.create", "user.invite", "policy.create"} {
		_, _, err := auditor.Log(ctx, auditlog.Event{
			OrgID: &orgID, ActorID: &userID,
			Action: action, TargetKind: "demo", TargetID: "seed",
			Before: map[string]any{}, After: map[string]any{},
			RequestID: "seed-" + action,
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

func upsertAsset(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, kind, name, digest, criticality string) uuid.UUID {
	labels, _ := json.Marshal(map[string]string{"env": "demo"})
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO assets (org_id, kind, name, digest, labels, ai_workload, criticality)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, kind, name, digest) DO UPDATE SET last_seen_at = NOW()
RETURNING id`, orgID, kind, name, digest, labels, kind == "ml-model", criticality).Scan(&id); err != nil {
		panic(err)
	}
	return id
}

func insertFinding(ctx context.Context, pool *pgxpool.Pool, orgID, assetID uuid.UUID,
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
	// Add jitter to last_seen so the dashboard ordering is meaningful.
	jitter := time.Duration(rand.Intn(60)) * time.Minute
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, asset_id, kind, external_id, title, description, severity,
                      risk_score, risk_inputs, lifecycle, engines, detail_json, attack_techniques,
                      first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6, $7,
        $8, $9, 'open', $10, '{}'::jsonb, $11,
        NOW() - INTERVAL '2 days', NOW() - $12::interval)`,
		orgID, assetID, kind, externalID, title, title, severity, score,
		inputs, engines, techniques, fmt.Sprintf("%d minutes", int(jitter.Minutes()))); err != nil {
		panic(err)
	}
}
