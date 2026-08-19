"""E3 admission webhook — verify the chart's default rules deny the
cases they should and admit the cases they should.

Important: this test depends on the Wave-E chart fixes (post-install
caBundle patch + namespaceSelector self-exclusion). On a chart that
has the original bug, every assertion here would silently pass-by-failing
because failurePolicy=Ignore admits everything.
"""
from __future__ import annotations

import json
import time

from lib.deployer import TEST_CLUSTER_ID

PRIV_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod-test
  namespace: default
spec:
  containers:
    - name: c
      image: alpine:3
      command: ["sleep", "1d"]
      securityContext:
        privileged: true
"""

HOSTNET_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: hn-pod-test
  namespace: default
spec:
  hostNetwork: true
  containers:
    - name: c
      image: alpine:3
      command: ["sleep", "1d"]
"""

OK_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: ok-pod-test
  namespace: default
spec:
  containers:
    - name: c
      image: alpine:3
      command: ["sleep", "1d"]
      securityContext:
        readOnlyRootFilesystem: true
"""

EVIDENCE_IMAGE_DIGEST = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EVIDENCE_IMAGE_REF = "ghcr.io/alphabravocompany/e2e-admission@" + EVIDENCE_IMAGE_DIGEST
EVIDENCE_POLICY_NAME = "e2e-block-critical-vulndb"
EVIDENCE_POD = f"""\
apiVersion: v1
kind: Pod
metadata:
  name: e2e-vulndb-deny
  namespace: default
spec:
  containers:
    - name: app
      image: {EVIDENCE_IMAGE_REF}
      command: ["sleep", "1d"]
      securityContext:
        readOnlyRootFilesystem: true
"""


def _cleanup(kubectl):
    for n in ("priv-pod-test", "hn-pod-test", "ok-pod-test", "e2e-vulndb-deny"):
        kubectl.delete("pod", n, namespace="default", check=False)
    time.sleep(2)


def _psql(kubectl, sql: str, *, timeout: int = 60) -> str:
    return kubectl.exec_in_pod(
        "constellation-postgres-0",
        ["psql", "-U", "constellation", "-d", "constellation", "-tAc", sql],
        namespace="constellation-system",
        timeout=timeout,
    ).strip()


def _seed_vulndb_admission_evidence(kubectl) -> None:
    org_id = _psql(
        kubectl,
        "SELECT org_id::text FROM clusters WHERE id = '" + TEST_CLUSTER_ID + "'",
    )
    assert org_id, "test cluster row was not bootstrapped"
    _psql(kubectl, f"""
DELETE FROM image_scan_results
 WHERE org_id = '{org_id}'
   AND image_digest = '{EVIDENCE_IMAGE_DIGEST}'
   AND scanner_profile = 'e2e';

WITH c AS (
  SELECT org_id FROM clusters WHERE id = '{TEST_CLUSTER_ID}'
)
INSERT INTO image_scan_results (
  id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
  platform, scanner_profile, vulndb_bundle_version, vulndb_bundle_hash,
  package_count, finding_count, bundle_metadata, last_scanned_at, updated_at
)
SELECT
  '22222222-2222-4222-8222-222222222222', c.org_id,
  '{EVIDENCE_IMAGE_REF}', '{EVIDENCE_IMAGE_REF}',
  'ghcr.io/alphabravocompany/e2e-admission', '{EVIDENCE_IMAGE_DIGEST}',
  'linux/amd64', 'e2e', 'e2e-bundle-20260614', 'sha256:e2ebundle',
  12, 1, '{{"source":"constellation-vulndb-e2e"}}'::jsonb, NOW(), NOW()
FROM c;

INSERT INTO image_scan_findings (
  id, org_id, image_scan_result_id, finding_key, external_id, title,
  description, severity, risk_score, canonical_engine, engines,
  package_ecosystem, package_name, package_version, package_purl,
  fixed_version, detail_json, first_seen_at, last_seen_at
)
VALUES (
  '33333333-3333-4333-8333-333333333333', '{org_id}',
  '22222222-2222-4222-8222-222222222222',
  'CVE-2026-E2E-0001|openssl|3.0.0',
  'CVE-2026-E2E-0001',
  'OpenSSL critical e2e fixture',
  'Deterministic Constellation VulnDB admission e2e fixture.',
  'critical', 98, 'vulndb', '[{{"engine":"vulndb","severity":"critical"}}]'::jsonb,
  'deb', 'openssl', '3.0.0', 'pkg:deb/debian/openssl@3.0.0',
  '3.0.2', '{{"confidence":"high"}}'::jsonb, NOW(), NOW()
)
ON CONFLICT (org_id, image_scan_result_id, finding_key) DO UPDATE SET
  external_id = EXCLUDED.external_id,
  title = EXCLUDED.title,
  severity = EXCLUDED.severity,
  risk_score = EXCLUDED.risk_score,
  canonical_engine = EXCLUDED.canonical_engine,
  engines = EXCLUDED.engines,
  package_ecosystem = EXCLUDED.package_ecosystem,
  package_name = EXCLUDED.package_name,
  package_version = EXCLUDED.package_version,
  package_purl = EXCLUDED.package_purl,
  fixed_version = EXCLUDED.fixed_version,
  detail_json = EXCLUDED.detail_json,
  last_seen_at = NOW();
""")
    spec_yaml = f"""
apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: {EVIDENCE_POLICY_NAME}
spec:
  match:
    kinds: ["Pod"]
  scanEvidence:
    maxAge: 24h
    requireVulnDBBundle: true
    canonicalEngine: vulndb
  vulnerability:
    maxAllowedSeverity: high
    requireKnownScanResult: true
    honorActiveExceptions: true
    requireFixAvailable: true
  action: deny
""".strip()
    _psql(kubectl, f"""
INSERT INTO policies (
  org_id, cluster_id, name, description, engine, category, spec_yaml,
  enabled, mode, source, lifecycle_stages, enforcement_actions
)
VALUES (
  '{org_id}', '{TEST_CLUSTER_ID}', '{EVIDENCE_POLICY_NAME}',
  'E2E critical VulnDB admission deny policy',
  'constellation-admission', 'admission', $policy${spec_yaml}$policy$,
  TRUE, 'enforce', 'declarative', ARRAY['DEPLOY'], ARRAY['deny']
)
ON CONFLICT (org_id, name, version) DO UPDATE SET
  cluster_id = EXCLUDED.cluster_id,
  description = EXCLUDED.description,
  engine = EXCLUDED.engine,
  category = EXCLUDED.category,
  spec_yaml = EXCLUDED.spec_yaml,
  enabled = TRUE,
  mode = 'enforce',
  source = 'declarative',
  lifecycle_stages = ARRAY['DEPLOY'],
  enforcement_actions = ARRAY['deny'],
  updated_at = NOW();
""")


def _apply_until_evidence_denied(kubectl) -> str:
    last = ""
    for _ in range(8):
        rc, out = kubectl.apply_yaml(
            EVIDENCE_POD,
            namespace="default",
            check=False,
            dry_run_server=True,
        )
        last = out
        if rc != 0 and EVIDENCE_POLICY_NAME in out and "CVE-2026-E2E-0001" in out:
            return out
        time.sleep(3)
    raise AssertionError(f"evidence-backed policy did not deny pod; last output: {last}")


def _latest_evidence_audit_details(kubectl) -> list[dict]:
    for _ in range(10):
        raw = _psql(kubectl, f"""
SELECT COALESCE(after->'evidence_details', '[]'::jsonb)::text
  FROM audit_events
 WHERE action = 'admission.deny'
   AND target_id = 'default/e2e-vulndb-deny'
   AND after->>'cluster_id' = '{TEST_CLUSTER_ID}'
   AND after->>'rule_id' = '{EVIDENCE_POLICY_NAME}'
 ORDER BY id DESC
 LIMIT 1
""")
        if raw:
            details = json.loads(raw)
            if details:
                return details
        time.sleep(1)
    return []


def test_admission_blocks_privileged(kubectl):
    _cleanup(kubectl)
    rc, out = kubectl.apply_yaml(PRIV_POD, namespace="default", check=False)
    assert rc != 0, f"privileged pod should be denied; got rc={rc}, out={out}"
    assert "block-privileged" in out, \
        f"deny message should name the rule; got: {out}"
    assert "denied by constellation policy" in out, \
        f"missing constellation deny prefix: {out}"


def test_admission_blocks_hostnetwork(kubectl):
    _cleanup(kubectl)
    rc, out = kubectl.apply_yaml(HOSTNET_POD, namespace="default", check=False)
    assert rc != 0, f"hostNetwork pod should be denied; got rc={rc}, out={out}"
    assert "block-host-network" in out, \
        f"deny message should name the rule; got: {out}"


def test_admission_admits_compliant_with_warning(kubectl):
    _cleanup(kubectl)
    rc, out = kubectl.apply_yaml(OK_POD, namespace="default", check=False)
    assert rc == 0, f"compliant pod should be admitted; got rc={rc}, out={out}"
    # Monitor-mode rules surface as Warnings on apply output.
    assert "require-image-signature" in out or "monitor" in out.lower(), \
        f"expected monitor-mode warning on compliant pod: {out}"


def test_admission_doesnt_block_runtime_agent(kubectl):
    """The runtime-agent itself is privileged (BPF + NFQUEUE); the chart's
    namespaceSelector self-exclusion should let it through. Existence of
    a Running runtime-agent pod proves this."""
    pods = kubectl.list_pods(namespace="constellation-system",
                             selector="app.kubernetes.io/component=runtime-agent")
    running = [p for p in pods if p["status"].get("phase") == "Running"]
    assert running, "runtime-agent pod is not Running — webhook may be blocking it"


def test_admission_blocks_vulndb_backed_image_and_audits_evidence(kubectl):
    _cleanup(kubectl)
    _seed_vulndb_admission_evidence(kubectl)
    out = _apply_until_evidence_denied(kubectl)
    assert "denied by constellation policy" in out, out
    assert "OpenSSL critical e2e fixture" in out, out

    details = _latest_evidence_audit_details(kubectl)
    assert len(details) == 1, f"missing audit evidence details: {details}"
    detail = details[0]
    assert detail["kind"] == "image-finding"
    assert detail["image"]["ref"] == EVIDENCE_IMAGE_REF
    assert detail["image"]["digest"] == EVIDENCE_IMAGE_DIGEST
    assert detail["scan_result"]["id"] == "22222222-2222-4222-8222-222222222222"
    assert detail["scan_result"]["vulndb_bundle_version"] == "e2e-bundle-20260614"
    assert detail["scan_result"]["package_count"] == 12
    assert detail["finding"]["external_id"] == "CVE-2026-E2E-0001"
    assert detail["finding"]["canonical_engine"] == "vulndb"
    assert detail["finding"]["fixed_version"] == "3.0.2"
