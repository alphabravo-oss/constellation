# Constellation, VulnDB, and NeuVector Alignment Plan

Date: 2026-06-12

Repository status:

- Plan document committed under `constellation/docs` on 2026-06-13.
- Primary implementation sweep was pushed to `constellation` main as `34aed74`.
- Primary VulnDB consumer-contract sweep was pushed to `constellation-vulndb` main as `1d2ca76`.
- `constellation-vulndb` consumer contract is tagged as `v0.1.0`, and Constellation now requires that tag.
- Release/image validation has started in a Docker/BuildKit-enabled environment. On 2026-06-13 the production scanner image built successfully with the sibling `constellation-vulndb` BuildKit context.
- Greenfield NeuVector parity work has started with first-class `scan_targets`: manual queueing, cluster cross-scan, registry sync, scanner claim/complete, findings stamping, connector coverage, and frontend API contracts now use typed targets instead of `scan_jobs.image_ref` as the runtime source of truth.
- First repository package-evidence scanning slice is implemented: CI or an operator can upload Syft package evidence for a repository checkout, Constellation queues a `repository` scan target, and scanner workers match the evidence through the local VulnDB bundle.
- Repository/CI scan attestations now have persisted org-level trust policies, server-side verifier promotion by policy, matching auto-verify on report, policy-triggered pending verification, immutable verification history, authenticated export, hash-chained audit coverage, and admission reuse that requires a live enabled policy link instead of trusting client-supplied state.
- Remaining environment-gated validation is focused on representative live registries, cloud-native registry identities, production signing/publishing credentials, and a CNI-enforced cluster.

Scope:

- `constellation` at `a2c90865417dc093721b1c28284c160da5dd9a2e`
- `constellation-vulndb` at `a6f4795078a8d88b70d5770d9fdb936fa8e0f1a4`
- `neuvector` local comparison checkout at `19f4412c9540412a398c3f0224ab7c7d9366b36f`
- Constellation vendored VulnDB copy under `constellation/third_party/constellation-vulndb`
- Constellation vendored NeuVector data plane under `constellation/third_party/neuvector`

Greenfield stance:

- Breaking changes are allowed.
- Redoing APIs, packages, Helm values, binaries, workflows, and storage layout is allowed.
- Compatibility with the current vendored VulnDB shape is not a goal.
- Correct producer/consumer alignment is the top goal.
- There is no legacy-code preservation requirement. Reuse existing code only when it is already the clean target shape.

## Executive Summary

Constellation and Constellation VulnDB are not aligned at the boundary that matters most. VulnDB is supposed to be the producer of signed, deterministic vulnerability intelligence bundles for Constellation and other products. The standalone `constellation-vulndb` repository is structured as that producer, but Constellation currently consumes a divergent vendored copy through public `pkg/*` packages that no longer exist in the standalone repository.

This must be fixed before feature work continues. The clean target is:

1. `constellation-vulndb` owns source ingestion, schema, bundle export, bundle verification, bbolt materialization, scan matching, and compatibility fixtures.
2. `constellation` consumes VulnDB through a stable public consumer API and/or a CLI contract, never a drifted nested repo.
3. Constellation image and host scanning use VulnDB as the canonical vulnerability matcher.
4. Trivy and Grype remain useful as reconciliation or evidence engines, not as the primary source of vulnerability truth.
5. NeuVector remains the model for runtime architecture, scanner/updater separation, policy lifecycle, admission, compliance profiles, and CI discipline.

Highest priority findings:

- P0: The VulnDB package boundary has been corrected: Constellation consumes public `constellation-vulndb/pkg/*` APIs, while VulnDB remains the standalone producer.
- P0: Constellation now consumes the sibling VulnDB repository through normal module/workspace wiring; the stale nested `third_party/constellation-vulndb` copy has been removed.
- P0: The VulnDB importer story now uses the producer-owned `vulndb-bundle-install` binary and shared storage. Constellation consumes delivered artifacts from upload, mounted files, HTTPS/S3, OCI, or prebuilt stores instead of generating VulnDB itself.
- P0: JWT signing is production-wired in Helm through stable `JWT_KEYS` Secret rendering and startup requirements.
- P0: Constellation CI workflows now exist for Go, Helm, frontend, security, RBAC, and release-image guardrails; Docker/BuildKit and live cluster validations still need an environment that provides those tools.
- P1: The scanner wrapper now preserves the process environment and appends registry credentials, with tests covering PATH/proxy/cache-safe behavior.
- P1: Dockerfiles previously used mutable helper/base tags and downloaded scanner tools over curl without checksum verification. Current worktree digest-pins production/helper images, verifies downloaded tool checksums, removes mutable application image publishing, adds release image SBOM/provenance/signing automation, and validates the full production scanner image through Docker/BuildKit.
- P1: Kubernetes hardening now covers non-agent workload security contexts, service account token automount controls, hook-job contexts, and optional production NetworkPolicies; remaining depth is CNI-enforced e2e validation.
- P1: Host package enumeration now covers dpkg, apk, and rpm, including SQLite, NDB, and Berkeley DB rpmdb layouts.
- P1: Astronomer JWKS validation is now wired into the mounted `/api/v1/security/*` server middleware; the lower-level reverse-tunnel protocol is out of scope for first stable release and no longer exposed through Helm values or the cluster CRD.
- P2: Several visible placeholder surfaces have been implemented or removed. Remaining future-scope or environment-dependent gaps are tracked explicitly instead of being presented as working product paths.

## Implementation Progress - 2026-06-12

Current implementation work has started on the P0 producer/consumer boundary. The goal is not to make Constellation own VulnDB generation. The goal is:

1. `constellation-vulndb` generates, validates, signs, publishes, and optionally materializes vulnerability database artifacts.
2. `constellation` consumes those artifacts however the deployment chooses: manual API upload, mounted files, HTTPS or presigned S3 URLs, native S3 URIs, OCI artifacts, or a prebuilt bbolt store.
3. No Constellation build depends on a drifted vendored VulnDB source tree.

Completed in the current worktree:

- Added public VulnDB consumer packages in standalone `constellation-vulndb`:
  - `pkg/model`
  - `pkg/bundleimport`
  - `pkg/bundledb`
  - `pkg/version`
  - `pkg/compat`
  - `pkg/contract`
- Removed the duplicate consumer-safe implementations from `internal/model`,
  `internal/bundleimport`, `internal/bundledb`, and `internal/compat`; internal
  VulnDB code now imports the public `pkg/*` implementations.
- Expanded `pkg/compat` into a stable downstream compatibility fixture covering:
  - OS namespace matching
  - language ecosystem matching
  - manifest/media/schema validation
  - table counts
  - CVSS, KEV, and EPSS risk signal coverage
- Added a Constellation downstream compatibility test:
  - `constellation/internal/vulndb/bundle_compat_test.go`
  - It builds a bbolt store from the VulnDB compatibility fixture and verifies Constellation's `BundleMatcher` consumes it.
- Removed Constellation's vendored VulnDB dependency path:
  - `constellation/go.mod` now requires a normal VulnDB pseudo-version.
  - The local `replace => ./third_party/constellation-vulndb` is removed.
  - `constellation/third_party/constellation-vulndb` is deleted from the target source tree.
  - Dockerfiles no longer copy `third_party/constellation-vulndb` before `go mod download`.
- Added a root local development workspace:
  - `go.work` uses `./constellation` and `./constellation-vulndb`.
  - It has a version-specific local replace for the checked-out VulnDB pseudo-version.
- Added a producer-owned artifact installer:
  - `constellation-vulndb/cmd/vulndb-bundle-install`
  - Supports bundle directory, manifest/payload files, HTTPS or presigned S3 URLs, native S3 URIs, OCI refs, local prebuilt bbolt stores, HTTPS store URLs, and S3 store URIs.
  - Builds or installs the bbolt store atomically.
  - Validates prebuilt stores by opening metadata before install.
- Updated the VulnDB image build to include:
  - `vulndb-aggregator`
  - `vulndb-bundle-install`
  - `vulndb-bundle-pull`
  - `vulndb-bundle-store`
- Replaced the Constellation Helm VulnDB storage/importer shape:
  - Added configurable `vulndb` storage.
  - Default storage is a PVC sized for realistic stores plus importer scratch and atomic replacement headroom.
  - API and scheduled importer share the same configured VulnDB volume.
  - API mount is writable only while `vulndb.manualUpload.enabled=true`; production values disable direct API writes.
  - Scheduled importer is optional and source-agnostic through `vulndbImporter.source.kind`.
  - Importer work files default to `<vulndb.mountPath>/.vulndb-work` so large bundle/store downloads use the VulnDB PVC instead of small pod-local ephemeral storage.
  - Optional `vulndbImporter.installJob.enabled` renders a one-shot Helm install/upgrade Job so production installs can load a bundle immediately instead of waiting for the cron schedule.
  - Importer resources now include memory and ephemeral-storage requests/limits.
  - Supported scheduled source kinds: `oci`, `bundleDir`, `files`, `urls`, `s3`, `store`, `storeUrl`, `storeS3`.
  - Helm now fails at render time if the selected source kind is missing required fields.
- Fixed JWT production wiring:
  - Chart creates a stable `<fullname>-jwt-keys` Secret unless `api.jwtKeysSecret` is supplied.
  - API receives `JWT_KEYS` from the Secret key `keys`.
  - API accepts comma-separated base64 keys and raw 32+ byte keys.
  - Parser tests cover base64/raw behavior and short-key rejection.
- Fixed scanner environment inheritance:
  - `registryEnv` now starts with `os.Environ()` and appends registry credentials.
  - Regression test covers environment inheritance and credential override behavior.
- Added VulnDB-backed image package matching in Constellation:
  - Introduced a `PackageMatcher` stage so Syft remains the image/SBOM inventory engine and VulnDB consumes discovered packages.
  - Default image scans now run Syft package inventory through `VulnDBMatcher` when a local store is present.
  - `VulnDBMatcher` resolves the bbolt path from `ScanOptions.VulnDBPath`, `CONSTELLATION_VULNDB_PATH`, or the chart default `/var/lib/constellation/vulndb.bbolt`.
  - Matching supports exact/base PURL candidates for any package and language namespace mapping from Syft/PURL ecosystems.
  - Syft OS distro metadata is now propagated into `scanner.Package` as optional namespace metadata.
  - OS package matching is safe for `deb`, `rpm`, and `apk` packages when Syft provides distro name/version or package URLs carry explicit distro/version qualifiers, avoiding unsafe package-manager-only guesses.
  - Syft CPEs are now propagated into VulnDB package queries, and CPE matching in `constellation-vulndb` no longer rejects valid CPE ranges only because the inventory package name differs from the advisory product name.
  - Constellation now carries base-image, image repository/tag, repository, and module-stream hints into every VulnDB package query so repository mappings can select the correct distro namespace when explicit namespace metadata is incomplete.
  - Added Constellation scanner fixture tests that build a bbolt store from `constellation-vulndb/pkg/compat` and verify OS image matching, language image matching, EPSS/CVSS/KEV propagation, severity normalization, and `vulndb` provenance.
- Added VulnDB bundle provenance propagation for image scans:
  - `VulnDBMatcher` reads bbolt metadata and attaches `schema_version`, `bundle_version`, `producer`, `media_type`, `exported_at`, `payload_hash`, and `record_count` to the engine result.
  - The scanner aggregator promotes the first available bundle metadata to `ScanResult.BundleMetadata`.
  - The scanner worker and E2E scanner driver include bundle metadata in scan completion payloads.
  - The API completion endpoint writes bundle metadata into each inserted finding's `detail_json`, the `scan_jobs.bundle_metadata` JSONB column, and the `scan-job.complete` audit event.
  - `GET /api/v1/scan-jobs` returns first-class `bundle_metadata`, and the coverage UI shows the latest scan bundle version/hash for image scanning.
  - Tests cover fixture-derived bundle metadata, handler detail JSON behavior, and scan-job completion/list metadata when the test DB is available.
- Added scanner engine controls and in-cluster VulnDB store access:
  - `NewDefaultWithConfig` can disable Syft, VulnDB, Trivy, and Grype independently while keeping the default pipeline unchanged.
  - `constellation-scanner` exposes `--syft-enabled`, `--vulndb-enabled`, `--trivy-enabled`, `--grype-enabled`, and `--vulndb-path`, with matching `CONSTELLATION_SCANNER_*_ENABLED` environment variables.
  - Helm values now expose `scanner.engines.syft`, `scanner.engines.vulndb`, `scanner.engines.trivy`, and `scanner.engines.grype`.
  - The scanner Deployment mounts the configured VulnDB volume read-only and sets `CONSTELLATION_VULNDB_PATH`, so in-cluster image scans can actually consume the delivered bbolt store.
  - Helm docs now describe the shared VulnDB store and engine toggles.
- Added Kubernetes hardening defaults:
  - New Helm `security.podSecurityContext` and `security.containerSecurityContext` helpers apply to non-privileged app workloads.
  - Defaults include `seccompProfile: RuntimeDefault`, `fsGroup: 10001`, `allowPrivilegeEscalation: false`, dropped Linux capabilities, `readOnlyRootFilesystem: true`, `runAsNonRoot: true`, and UID/GID `10001`.
  - API, scanner, admission, operator, audit archiver, and VulnDB importer now render the stricter container security context.
  - API, scanner, admission, operator, audit archiver, VulnDB importer, and frontend now have explicit writable `/tmp` or cache/run volumes for read-only-root operation.
  - Frontend renders a tailored nginx container security context with read-only root filesystem, dropped capabilities, no privilege escalation, and writable nginx cache/run/lib/temp mounts while keeping the image's own non-root nginx user.
  - API, scanner, admission, frontend, audit archiver, and VulnDB importer disable service account token automount.
  - Constellation-owned Go runtime images now declare numeric `USER 10001:10001`.
- Removed or hid several visible stub surfaces:
  - `constellationctl policy validate` and `policy check` now validate/evaluate real Constellation policy DSL documents and have tests.
  - `pkg/abbot` now posts the query envelope to `/api/v1/chat` when `ABBOT_SERVICE_URL` is configured and degrades only when the service is disabled or unavailable.
  - Plugin SDK 501 responses now identify undeclared optional capabilities instead of unfinished implementation.
  - Astronomer `/api/v1/security/*` middleware now validates Astronomer JWTs through JWKS, maps `sub`/stable subject claims through `astronomer_identity_map`, rejects unmapped or disabled users, and then uses the normal Constellation RBAC subject flow.
- Fixed hostscan fixture isolation:
  - Explicit `HostRoot` now wins over `/proc/1/root` for OS and package DB discovery.
  - `TestCollectOS_UsesHostRoot` now passes consistently.
- Added Constellation CI workflows:
  - Go tests.
  - VulnDB public package tests through a temporary workspace.
  - Helm lint/render for default and importer-enabled chart modes.
  - Vendored VulnDB drift guard.
  - govulncheck and CodeQL.

Validation evidence from the current worktree:

```bash
cd /root/constellation-all/constellation
go test ./internal/scanner ./internal/handler -run 'TestDedupe|TestAggregator_RunsPackageMatchersAfterSyft|TestScannerFindingDetailIncludesVulnDBBundle'
go test ./cmd/constellation-scanner ./internal/scanner ./internal/handler
go test ./...
helm lint ./deploy/charts/constellation
helm template constellation ./deploy/charts/constellation >/tmp/constellation-helm-validation/default.yaml
helm template constellation ./deploy/charts/constellation \
  -f ./deploy/charts/constellation/examples/values-prod.yaml \
  >/tmp/constellation-helm-validation/prod.yaml
helm template constellation ./deploy/charts/constellation \
  --set vulndb.manualUpload.enabled=false \
  --set vulndbImporter.enabled=true \
  --set vulndbImporter.source.kind=storeS3 \
  --set vulndbImporter.source.storeS3=s3://constellation-vulndb/store.bbolt \
  >/tmp/constellation-helm-validation/importer.yaml
helm template constellation ./deploy/charts/constellation \
  --set vulndbImporter.enabled=true \
  --set vulndbImporter.source.kind=s3 \
  --set vulndbImporter.source.manifestS3=s3://constellation-vulndb/manifest.json \
  --set vulndbImporter.source.payloadS3=s3://constellation-vulndb/bundle.jsonl.gz \
  --set vulndb.trust.requireSignatures=true \
  --set vulndb.trust.publicKeySecret=constellation-vulndb-cosign-public-key \
  --set vulndb.freshness.maxAge=168h \
  >/tmp/constellation-helm-validation/trust.yaml
helm template constellation ./deploy/charts/constellation \
  --set astronomer.enabled=true \
  --set astronomer.jwksURL=https://astronomer.example/.well-known/jwks.json \
  --set astronomer.jwtIssuer=https://astronomer.example/ \
  --set astronomer.jwtAudience=constellation \
  >/tmp/constellation-helm-validation/astronomer.yaml
helm template constellation ./deploy/charts/constellation \
  --set auditArchiver.enabled=true \
  --set auditArchiver.bucket=constellation-audit-prod \
  --set auditArchiver.sign.mode=static-key \
  --set auditArchiver.sign.keySecretName=constellation-audit-signing \
  --set auditArchiver.sign.keySecretKey=cosign.key \
  >/tmp/constellation-helm-validation/audit.yaml
python3 - <<'PY'
from pathlib import Path
import yaml
base = Path('/tmp/constellation-helm-validation')
for path in sorted(base.glob('*.yaml')):
    if path.name.startswith('negative-'):
        continue
    with path.open() as fh:
        docs = [doc for doc in yaml.safe_load_all(fh) if doc]
    print(f'{path.name}: {len(docs)} docs')
PY
git diff --check

cd /root/constellation-all/constellation/frontend
npm ci
npm run type-check
npm test
npm run build
rm -rf node_modules dist

cd /root/constellation-all/constellation-vulndb
GOWORK=off go test ./...
git diff --check
```

Additional validation completed on 2026-06-13:

```bash
cd /root/constellation-all/constellation
helm template constellation ./deploy/charts/constellation \
  --set vulndbImporter.enabled=true \
  --set vulndbImporter.installJob.enabled=true \
  >/tmp/constellation-vulndb-importer-job.yaml
go test ./internal/handler -run 'TestRegistryScanRequeuesWhenVulnDBBundleChanges|TestRegistryScanPolicy|TestDigestFromResolvedRef|TestCurrentVulnDBBundleVersion'
docker buildx build --platform linux/amd64 \
  --build-context constellation-vulndb=../constellation-vulndb \
  -f deploy/docker/Dockerfile.scanner \
  -t constellation/scanner:dev-vulndb-context --load .
```

Additional scanner orchestration validation completed on 2026-06-14:

```bash
cd /root/constellation-all/constellation
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestScanJobs_(QueueLifecycle|ClaimReclaimsExpiredLeaseAndFailureRequiresWorker|ListIncludesQueueMetricsByTargetType)|TestConnectorCoverage_OverviewUsesDatabaseState' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestScanJobs_(RenewRequiresSameScannerInstance|RetryBackoffAndMaxAttempts|QueueLifecycle|ClaimReclaimsExpiredLeaseAndFailureRequiresWorker|ListIncludesQueueMetricsByTargetType)' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestScanObjects' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestVulnDB|TestCurrentVulnDBBundleVersion|TestRegistryScanRequeuesWhenVulnDBBundleChanges' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/scanner ./internal/handler ./pkg/sbom -run 'TestPackageFromSyftArtifact|TestPackagesFromSyftDocument|TestSyftCPEs|TestScanJobs_CompleteWritesImageScanArtifacts|TestImageScanArtifacts|TestScanFindingStableKeyIgnoresPackageLocations|TestSPDX2_3|TestCycloneDX1_6' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./cmd/constellation-scanner -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./... -count=1
helm template constellation deploy/charts/constellation --set scanner.maxConcurrent=4 --set scanner.leaseRenewInterval=2m

cd /root/constellation-all/constellation/frontend
npm test
npm run build
```

The Docker build validated the full production scanner image path with Syft,
Trivy, Grype, cosign, oras, checksum verification, Trivy DB warm-up, and the
sibling VulnDB module resolved through a BuildKit named context.

Additional admission evidence/audit validation completed on 2026-06-14:

- The admission engine now carries typed evidence details from the shared Postgres evidence source into live deny events.
- `internal/admissionevidence` emits the shared `pkg/admission.EvidenceDetail` contract for missing scan results, scan-quality gates, canonical image findings, and image artifacts.
- The live admission audit hook persists optional `after.evidence_details` on `admission.deny` rows with stable snake_case JSON fields.
- The Helm test profile now installs a deterministic local cluster ID, enables DB-backed admission policies and audit, and uses `failurePolicy: Fail` for e2e admission validation.
- The live k3s release at `https://constellation.dev.alphabravo.io` was upgraded to API, admission, scanner, and migrate images tagged `dev-k3s-admission-evidence-20260614-1`.
- Live Postgres migrated from goose version 60 to 82, including `scan_targets`, `image_scan_results`, and `image_scan_findings`.
- Live admission is configured with DB-backed policy reload and audit for installed cluster `2a46e2a1-9485-4bd6-a622-b1fcd6ee4130`.
- A live server-side dry-run pod using a digest-pinned image was denied from a canonical `image_scan_results` + `image_scan_findings` VulnDB fixture, and the resulting audit row contained typed image, scan-result, VulnDB bundle, package, fixed-version, and CVE evidence.

Validation evidence:

```bash
cd /root/constellation-all/constellation
python3 -m py_compile tools/constellation-test-suite/lib/deployer.py tools/constellation-test-suite/lib/kubectl.py tools/constellation-test-suite/tests/test_admission.py tools/constellation-test-suite/conftest.py
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./pkg/admission ./internal/admissionevidence ./cmd/constellation-admission ./internal/handler -run 'TestEvaluate_EvidenceGate|TestAdmissionEvidence|TestAdmissionDenyAuditEvent|TestChainDenyHooks|TestPolicies_SimulateEvaluatesStoredCriticalVulnerabilityEvidence' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./cmd/constellation-admission ./pkg/admission ./internal/admissionevidence ./internal/handler -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./... -count=1
PYTHONPATH=tools/constellation-test-suite python3 - <<'PY' | helm template constellation deploy/charts/constellation -n constellation-system -f - >/tmp/constellation-test-render.yaml
from lib.deployer import TEST_VALUES_YAML
print(TEST_VALUES_YAML)
PY
KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm upgrade constellation deploy/charts/constellation -n constellation-system -f /tmp/constellation-live-values.yaml \
  --set api.image.tag=dev-k3s-admission-evidence-20260614-1 \
  --set admission.image.tag=dev-k3s-admission-evidence-20260614-1 \
  --set scanner.image.tag=dev-k3s-admission-evidence-20260614-1 \
  --set migrate.image.tag=dev-k3s-admission-evidence-20260614-1 \
  --set clusterRegistration.clusterId=2a46e2a1-9485-4bd6-a622-b1fcd6ee4130 \
  --set admission.policies.enabled=true \
  --set admission.policies.clusterId=2a46e2a1-9485-4bd6-a622-b1fcd6ee4130 \
  --set admission.audit.enabled=true \
  --set admission.audit.clusterId=2a46e2a1-9485-4bd6-a622-b1fcd6ee4130 \
  --set vulndb.storage.size=2Gi \
  --set 'vulndb.storage.accessModes[0]=ReadWriteOnce' \
  --wait --timeout 10m
KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n constellation-system exec constellation-postgres-0 -- \
  psql -U constellation -d constellation -tAc "SELECT max(version_id) FROM goose_db_version; SELECT to_regclass('public.image_scan_results'); SELECT to_regclass('public.image_scan_findings');"
KUBECONFIG=/etc/rancher/k3s/k3s.yaml CONSTELLATION_TEST_CLUSTER_ID=2a46e2a1-9485-4bd6-a622-b1fcd6ee4130 PYTHONPATH=tools/constellation-test-suite python3 - <<'PY'
import runpy
from lib.kubectl import Kubectl
from lib.remote import LocalShell
ns = runpy.run_path('tools/constellation-test-suite/tests/test_admission.py')
kubectl = Kubectl(LocalShell())
ns['_cleanup'](kubectl)
ns['_seed_vulndb_admission_evidence'](kubectl)
out = ns['_apply_until_evidence_denied'](kubectl)
details = ns['_latest_evidence_audit_details'](kubectl)
assert 'CVE-2026-E2E-0001' in out
assert len(details) == 1
assert details[0]['finding']['canonical_engine'] == 'vulndb'
assert details[0]['scan_result']['vulndb_bundle_version'] == 'e2e-bundle-20260614'
PY
curl -k -I --max-time 20 https://constellation.dev.alphabravo.io/
```

Additional local whole-stack evidence validation completed on 2026-06-14:

- The live k3s release at `https://constellation.dev.alphabravo.io` now runs
  current local-cluster producers by default:
  - `discoverer`, `operator`, and `runtime-agent` image tag
    `dev-k3s-local-evidence-20260614-1`.
  - API image tag `dev-k3s-local-evidence-20260614-3` after the health and node
    API fixes described below.
  - Existing admission/scanner/migrate tag
    `dev-k3s-admission-evidence-20260614-1` remains in place.
- The installed local cluster
  `2a46e2a1-9485-4bd6-a622-b1fcd6ee4130` now auto-populates the
  NeuVector-style baseline without manual queueing:
  - platform facts from `discoverer`
  - host facts, process inventory, container inventory, package inventory, and
    CIS evidence from `runtime-agent`
  - workload package evidence from `runtime-agent`
  - runtime image package evidence and workload exposure links from
    `runtime-agent` plus `discoverer`
  - typed `host`, `workload`, `image`, and `platform` scan targets, evidence,
    jobs, queue metrics, and completed scanner work
- The e2e test suite now includes a local-cluster default test profile that
  installs `discoverer` with the rest of the control plane and asserts:
  - `/api/v1/clusters` reports five healthy local sensors:
    `operator`, `scanner`, `admission`, `runtime-agent`, and `discoverer`
  - `/api/v1/clusters/{id}/health` reports all expected local sensors ready
  - `/api/v1/clusters/{id}/platform-facts` has platform facts, platform scan
    target, and package evidence
  - `/api/v1/clusters/{id}/nodes` and node detail include host facts,
    packages, containers, processes, CIS, runtime-agent freshness, scan target,
    scan status, and inventory hash
  - database rows contain `host`, `workload`, `image`, and `platform` target
    evidence and jobs
  - `/api/v1/scan-jobs` exposes host/workload/image/platform jobs and
    target-type queue metrics
- Validation found and fixed two product bugs that only showed up after a real
  local rollout:
  - Cluster health counted stale heartbeat rows from replaced producer pods as
    desired replicas, so a healthy one-pod `operator` or `discoverer` rollout
    could be reported as degraded. Health now derives desired readiness from
    fresh ready instances and keeps stale errors only when no fresh ready
    instance exists.
  - Node inventory list SQL used an ambiguous `last_seen_at` alias once host
    facts, host packages, and runtime-agent heartbeat data were all present.
    The aggregate sort now uses an unambiguous `node_last_seen_at` alias.

Live local default evidence proof:

```text
scan_targets:
  host/platform/workload/runtime-agent image targets are present
scan_evidence:
  host, image, platform, and workload evidence rows are present
scan_jobs:
  host, runtime-agent image, platform, and workload jobs are completed
image_workload_links:
  local running image exposure links are present
```

Live database snapshot:

```json
{
  "targets": [
    {"type": "host", "source_type": "host", "count": 1},
    {"type": "image", "source_type": "runtime-agent", "count": 12},
    {"type": "platform", "source_type": "platform", "count": 1},
    {"type": "workload", "source_type": "runtime-agent", "count": 13}
  ],
  "evidence": [
    {"target_type": "host", "count": 1},
    {"target_type": "image", "count": 14},
    {"target_type": "platform", "count": 1},
    {"target_type": "workload", "count": 13}
  ],
  "jobs": [
    {"target_type": "host", "source_type": "host", "status": "completed", "count": 1},
    {"target_type": "image", "source_type": "runtime-agent", "status": "completed", "count": 22},
    {"target_type": "platform", "source_type": "platform", "status": "completed", "count": 37},
    {"target_type": "workload", "source_type": "runtime-agent", "status": "completed", "count": 24}
  ],
  "image_workload_links": 36
}
```

Validation evidence:

```bash
cd /root/constellation-all/constellation
python3 -m py_compile tools/constellation-test-suite/lib/deployer.py tools/constellation-test-suite/lib/api.py tools/constellation-test-suite/conftest.py tools/constellation-test-suite/tests/test_install.py tools/constellation-test-suite/tests/test_local_cluster_defaults.py
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestClusters_Health|TestNodes' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -count=1
git diff --check
KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm upgrade constellation deploy/charts/constellation -n constellation-system -f /tmp/constellation-live-values-current.yaml --set api.image.tag=dev-k3s-local-evidence-20260614-3 --wait --timeout 10m
```

Live one-shot API/database validation completed with:

```text
live local-cluster default evidence assertions passed
```

Definition-of-done updates:

- Local in-cluster install is not considered NeuVector-parity-ready unless the
  installed cluster auto-registers, all five local sensors are healthy, and
  host/workload/image/platform scan target classes are populated without manual
  operator action.
- Local default scanning is not considered done unless node inventory includes
  host facts, packages, containers, processes, CIS, runtime-agent health,
  scanner target/job state, and active image exposure links.
- New producer rollouts must not degrade cluster health because of stale
  historical heartbeat rows from older pods.

Additional single-org/RBAC auth cleanup completed on 2026-06-14:

- Public local login is now explicitly email/password only. The backend derives
  the login subject from exactly one active user row matching the email and
  issues the JWT with that user's existing `org_id`; `org_id` remains the
  internal RBAC, audit, token, and query-scope boundary.
- The hidden `CONSTELLATION_DEFAULT_ORG` auth fallback and API Deployment env
  wiring were removed. A default org may still be bootstrapped for storage/RBAC,
  but login no longer asks users or tools to select it.
- `constellationctl login`, cluster init-bundle commands, and serverless
  evidence sync now authenticate with server/email/password only. Backup export
  keeps explicit org selection because backup scope is data selection, not login
  disambiguation.
- E2E login helpers and runbook snippets now post only `email` and `password`.
- Duplicate active emails across org rows are rejected for org-less local login
  instead of silently selecting the wrong tenant. This keeps the single-org UX
  clean while preserving the safety of the existing RBAC subject model.

Validation evidence:

```bash
cd /root/constellation-all/constellation
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestAuth_Login' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./cmd/constellationctl -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -count=1
helm template constellation deploy/charts/constellation >/tmp/constellation-auth-render.yaml
cd frontend && npm run type-check && npm test -- --run
git diff --check
```

Live k3s validation:

- API image `dev-k3s-single-org-auth-20260614-1` was built for linux/amd64,
  imported into k3s, and rolled into Helm revision 14.
- A live port-forward smoke logged in with only `email` and `password`, called
  `/api/v1/auth/me`, and confirmed the bootstrap admin's `org_id` and
  `GlobalAdmin` role were derived from the user/RBAC rows.

Repository package-evidence scan slice completed on 2026-06-14:

- Added `POST /api/v1/repository-packages:report` for authenticated CI/operator
  upload of repository package evidence. The handler upserts a first-class
  `repository` scan target, persists target-scoped `scan_evidence`, records
  repository URL/commit/branch/workflow/run metadata, and queues scanner work
  without overloading image-specific fields.
- Scanner claim now attaches package evidence to `repository` targets, and
  `constellation-scanner` advertises and executes repository jobs through the
  same VulnDB-backed `ScanPackages` path used for host, workload, platform, and
  serverless evidence.
- `constellationctl repository scan` catalogs a checked-out repository with
  Syft, infers repo URL/ref/commit/branch from git when available, posts the
  evidence to Constellation, and reports the scan target/evidence/job IDs.
- Added repository scan inventory APIs and UI: `GET /api/v1/repository-scans`
  and `GET /api/v1/repository-scans/{id}` expose latest package evidence, job
  state, finding rollups, and source metadata; the cluster console now has a
  Repositories page beside Images, Serverless, and Registries.
- Manual `/scan-jobs` creation for `target_type=repository` remains rejected:
  repository scans must be created from evidence so the scanner never guesses
  source package inventory or pulls arbitrary repository contents.

Validation evidence:

```bash
cd /root/constellation-all/constellation
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestRepositoryPackages|TestScannerPackagesFromRepositoryPackages|TestScanJobs_ClaimFiltersTargetTypes' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestRepositoryInventory|TestRepositoryPackages' -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/server ./cmd/constellation-scanner ./cmd/constellationctl -count=1
cd frontend && npm run type-check
git diff --check
```

Repository/CI attestation verification history/export completed on 2026-06-14:

- Added `scan_attestation_verifications` as an append-only verification attempt
  ledger with database triggers blocking update/delete. Rows capture policy
  snapshot, verifier metadata, status, trust result, signer, issuer, reason or
  error, actor, manual/auto source, subject digest, predicate type, payload
  hash, and Rekor requirement.
- Added `GET /api/v1/repository-scan-attestations/{id}/verifications` for
  authenticated verification history and
  `GET /api/v1/repository-scan-attestations/{id}/export` for an authenticated
  JSON evidence bundle containing the full attestation payload/envelope/signature
  plus verification history.
- Added hash-chain audit events for attestation trust policy lifecycle and each
  server-side verification attempt.
- Added frontend client methods and a Repositories-page attestation history
  panel with recent attestation rows, verification attempts, and JSON export.

Validation evidence:

The second Helm command is expected to fail with
`scanner.signatures.mode=public-key requires scanner.signatures.publicKeySecret or scanner.signatures.publicKeyPath`.

```bash
cd /root/constellation-all/constellation
/tmp/constellation-tools/goose -dir db/migrations postgres 'postgres://constellation:constellation@localhost:15433/constellation?sslmode=disable' up
CONSTELLATION_TEST_DATABASE_URL='postgres://constellation:constellation@localhost:15433/constellation?sslmode=disable' GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run TestScanAttestationsReportLinksRepositoryScan -count=1 -v
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/server -run '^$' -count=1
go test ./pkg/audit -run TestRulesCoverEveryDocumentedActionFamily -count=1
cd frontend && npm run type-check
```

Repository/CI attestation verifier modes completed on 2026-06-14:

- Added explicit `keyless` and `public-key` verifier modes to repository/CI
  attestation trust policies. Keyless policies require signer identity and OIDC
  issuer constraints; public-key policies require PEM public key material.
- Extended shared cosign verification so `sigverify.TrustPolicy` can run
  keyless certificate verification or keyed `cosign --key` verification for
  image signatures and attestations.
- Closed the broad-trust default: empty keyless identity/issuer settings can
  still detect a valid signature, but no longer mark it trusted.
- Wired scanner image-signature verification through `scanner.signatures.mode`
  and optional public-key Secret/path Helm values, including a render-time guard
  when public-key mode has no key source.
- Updated the attestation trust UI and API client so operators can create keyed
  or keyless promotion policies from one settings surface.

Validation evidence:

```bash
cd /root/constellation-all/constellation
/tmp/constellation-tools/goose -dir db/migrations postgres 'postgres://constellation:constellation@localhost:15433/constellation?sslmode=disable' up
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./pkg/sigverify -count=1 -v
CONSTELLATION_TEST_DATABASE_URL='postgres://constellation:constellation@localhost:15433/constellation?sslmode=disable' GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/handler -run 'TestScanAttestationsReportLinksRepositoryScan|TestScanAttestationTrustPolicyPublicKeyMode' -count=1 -v
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./cmd/constellation-scanner -count=1
GOWORK=off GOPRIVATE=github.com/alphabravocompany go test ./internal/server -run '^$' -count=1
helm template constellation deploy/charts/constellation --set scanner.signatures.mode=public-key --set scanner.signatures.publicKeySecret=cosign-pub >/tmp/constellation-scanner-public-key.yaml
helm template constellation deploy/charts/constellation --set scanner.signatures.mode=public-key
cd frontend && npm run type-check && npm test -- --run && npm run build
git diff --check
```

Broader VulnDB producer/consumer proof completed on 2026-06-13:

- `constellation-vulndb/scripts/local-population-smoke.sh` ran with the capped
  `full-smoke` profile and optional `ghsa,vulnrichment`.
- Required sources passed: NVD, OSV, KEV, EPSS, and distro feeds.
- Distro coverage included Alpine, AlmaLinux, Amazon, Azure Linux, Debian,
  Oracle, Photon, Rocky, SUSE, Ubuntu, RHEL, and Wolfi.
- The generated bundle was schema v2, version
  `local-full-smoke-20260613T200730Z`, with `record_count=468185` and payload
  hash `834382386cb84182772522516f1e9ded7106ca43e6a38b5783f3412713f7f5a7`.
- The local bbolt store was installed into the live k3s Constellation PVC and
  `/readyz` returned ready.
- Authenticated `/api/v1/vulndb/status` reported bundle
  `local-full-smoke-20260613T200730Z` with `record_count=468185`.
- A live `alpine:3.16` scan completed against that bundle with 14 packages and
  21 findings; `GET /api/v1/scan-jobs` recorded the same bundle version and
  record count in `bundle_metadata`.

Frontend build note: `npm run build` succeeds and emits the existing Vite large-chunk warning for `index`/dashboard chunks.

Expected negative validation:

```bash
cd /root/constellation-all/constellation
helm template constellation ./deploy/charts/constellation \
  --set vulndbImporter.enabled=true \
  --set vulndb.trust.requireSignatures=true
helm template constellation ./deploy/charts/constellation \
  --set astronomer.enabled=true
```

These fail as intended with:

```text
vulndb.trust.requireSignatures requires vulndb.trust.publicKeySecret/publicKeyPath or both certificateIdentity and certificateOIDCIssuer
astronomer.jwksURL is required when astronomer.enabled=true
```

Follow-up items discovered while implementing:

- `go mod tidy` in `constellation` without a local workspace or GitHub credentials still cannot fetch the private VulnDB repo. CI now checks out both repos and creates a temporary workspace. Release CI for Constellation must either have access to the private VulnDB module or consume a public/tagged VulnDB module.
- Local multi-repo development is now documented in `constellation/docs/development.md`, with `constellation/go.work.example` mapping the required VulnDB module version to a sibling `../constellation-vulndb` checkout while keeping `go.mod` free of permanent local replacement directives.
- The source-agnostic installer now supports trust and integrity through manifest/payload verification, bbolt metadata validation, optional cosign signature enforcement, OCI ref signature verification, and max-age freshness policy.
- API manual upload is still supported for dev/emergency workflows, and production values now disable direct API writes while leaving importer-driven installs as the normal path.
- The duplicate public/internal consumer packages have been converged: VulnDB internal callers now use `pkg/model`, `pkg/bundleimport`, `pkg/bundledb`, and `pkg/compat` directly, and the equivalent internal package trees were removed.
- Direct S3 support adds AWS SDK dependencies to `constellation-vulndb`. This is correct for native S3 consumption, but presigned HTTPS remains available for deployments that want a smaller credential surface.
- Image OS package matching now has the Syft distro metadata path, including Alpine `3.x`/`v3.x` namespace-version aliasing, Syft CPE propagation, base-image image repository/tag hints, Syft package metadata repository/module-stream hints when present, and bundle-side CPE identity handling for distro package/product name differences. Remaining OS matching depth is live Syft capture coverage across Debian, Ubuntu, Alpine, RHEL-compatible, SUSE, Wolfi, and Amazon images in an environment with Syft plus a container runtime.
- Constellation scanner tests now cover representative Syft distro metadata for Ubuntu, Alpine, RHEL/UBI, Amazon Linux, SUSE/SLES, and Wolfi. Full Syft JSON-shaped fixtures under `internal/scanner/testdata/syft` verify document decoding, object and legacy string license forms, CPE propagation, image hints, RPM repository metadata, and module-stream metadata. RHEL/SUSE-family query generation now adds major-line namespace aliases such as `9.4 -> 9` and `15.5 -> 15`.
- Image scan persistence now preserves bundle metadata (`bundle_version`, `schema_version`, `payload_hash`, `record_count`) in scanner results, worker completion payloads, per-finding `detail_json`, the `scan_jobs.bundle_metadata` JSONB column, `GET /api/v1/scan-jobs`, the coverage UI, and scan completion audit events.
- Trivy and Grype still run by default for compatibility, but scanner binary flags/env and Helm `scanner.engines.*` values can disable them for VulnDB-canonical deployments. Scanner aggregation now treats VulnDB as the canonical source when it reports the same advisory/package key, and stores Trivy/Grype as evidence provenance rather than allowing them to override VulnDB severity, CVSS, title, or fixed version.
- Trivy and Grype JSON parsing is now split from CLI execution and covered by minimized scanner JSON-shaped fixtures under `internal/scanner/testdata/trivy` and `internal/scanner/testdata/grype`. These fixtures lock down package identity, fixed-version extraction, CVSS/vector selection, references, title fallback, and the current boundary that evidence scanners do not populate `affected_range` unless their output exposes a comparable range beyond fixed-version fields.
- Finding persistence now promotes `canonical_engine` to a nullable indexed column, backfills it from existing finding detail JSON, writes it during scan completion, and points the findings search DSL at the column for large-install filtering.
- Kubernetes hardening now covers app workload security contexts, hook job security contexts, read-only root filesystems with explicit writable temp/cache volumes, service account token automount, numeric non-root runtime images, optional production NetworkPolicies with default-deny plus explicit Constellation flows, and documented accepted exceptions for the privileged runtime-agent. Remaining hardening depth is CNI-enforced policy e2e tests.
- Operator RBAC has been reduced and guarded in CI: cluster-scoped permissions are limited to the cluster-scoped `ConstellationCluster` CR/status, while managed workload permissions render as a namespaced `Role` by default and as a workload `ClusterRole` only when `.Values.namespaced=false`. The operator now separates `OPERATOR_NAMESPACE` from `WATCH_NAMESPACE` so chart RBAC scope and controller-runtime cache scope align.
- Frontend dependency hardening upgraded Vite/Vitest/plugin tooling and the `ws` transitive dependency; `npm audit --omit=dev` and full `npm audit` now report zero vulnerabilities.
- Scanner/runtime image hardening now verifies pinned upstream tool downloads by SHA-256 before install: Syft, Trivy, Grype, cosign, oras, and crictl.
- Host package inventory now implements rpm enumeration through Anchore's pure-Go rpmdb reader, covering modern `/usr/lib/sysimage/rpm/rpmdb.sqlite`, legacy `/var/lib/rpm/rpmdb.sqlite`, NDB `Packages.db`, and Berkeley DB `Packages` files without shelling out. rpm versions are normalized as `epoch:version-release` when epoch is present and `version-release` otherwise. Distro dispatch now treats Wolfi/Chainguard as apk-family and still attempts rpm enumeration for unknown non-Debian/non-apk hosts that have an rpmdb. Host OS detection now has representative distro fixtures and deterministic explicit `HostRoot` behavior for tests and alternate roots.
- Audit archiver now verifies the audit hash chain, emits gzip JSONL plus a manifest with archive and JSONL hashes, supports static-key/keyless manifest signing through the existing backup signer, uploads archive/manifest/signature/certificate artifacts to S3 through AWS SDK default credentials, and renders as an enabled Helm CronJob with validation instead of a fail-fast placeholder.
- Astronomer JWKS route authentication is now live for `/api/v1/security/*`: Helm requires `astronomer.jwksURL` when enabled, optional issuer/audience constraints are supported, mapped users are loaded from the Constellation DB, integration-tagged tests cover the real mapping route, and reverse-tunnel configuration has been removed from first-release Helm/CRD surfaces.
- Cluster registration surfaces no longer return demo health data: `/api/v1/clusters` rolls sensor readiness from recent `component_heartbeats`, `/api/v1/clusters/{id}/health` validates cluster UUID/org ownership and reports DB-backed component status, init-bundle registration state, last check-in, restart counts, and health gates.
- Connector coverage no longer returns a hard-coded production-style registry/cloud catalog in DB-backed mode: `/api/v1/connector-coverage` rolls registry connectors from `registries`/`registry_images`/`scan_jobs`, cloud posture from saved cloud connector configs plus cloud-resource assets/findings, scanner capacity from `component_heartbeats` and queue depth, and recent jobs from `scan_jobs`; the frontend now requires an explicit image ref instead of queueing a baked-in sample image.
- Compliance schedule UI calls are now aligned to the DB-backed `/api/v1/compliance/schedules` contract: the framework tab uses `listDBSchedules`, renders delivery/cron/last-run fields from production rows, and no longer expects the old catalog-only shape from the same route.
- VulnDB installer trust policy now supports `--require-signatures`, `--cosign-public-key`, keyless certificate identity/issuer constraints, and `--max-age`; OCI sources run `cosign verify` before pull, while file/URL/S3/store sources verify detached `.sig` bundles. Helm exposes these through `vulndb.trust.*` and `vulndb.freshness.maxAge`.
- VulnDB installer now writes an optional JSON status file with installed bundle metadata, source kind/ref, table counts, and trust policy. Helm wires a shared status path, `/api/v1/vulndb/status` reads it, and the frontend VulnDB settings page displays installer freshness/provenance/trust.

## Implementation Progress - 2026-06-13 Live k3s Validation

The first live validation used the deployed k3s environment at `constellation.dev.alphabravo.io`, with Constellation consuming a VulnDB artifact generated by the separate `constellation-vulndb` repository. This validates the intended producer/consumer split: VulnDB generated and materialized the database, and Constellation consumed the delivered bbolt store.

Live bundle evidence:

- VulnDB smoke profile: `distros,kev,epss` with Alpine distro data.
- Bundle version: `local-alpine-kev-epss-20260613T190803Z`.
- Manifest schema: `v2`.
- Producer: `vulndb-bundle`.
- Bundle record count: `401833`.
- Table counts:
  - `vuln_advisories=8743`
  - `vuln_aliases=8743`
  - `vuln_package_ranges=41402`
  - `vuln_risk_signals=342928`
- Quality result: `PASS`.
- API status proof: `/api/v1/vulndb/status` reported the installed `/var/lib/constellation/vulndb.bbolt`, size `926892032` bytes, with the expected bundle version and payload hash.

Live scanner evidence:

- Scanner ran with Syft enabled, VulnDB enabled, and Trivy/Grype disabled for the first VulnDB-canonical smoke.
- Image scanned: `alpine:3.16`.
- Successful scan job: `0552d57c-c99f-41e0-be72-c01c8cf4c2be`.
- Result: `completed`, `package_count=14`, `finding_count=12`.
- Stored findings carried `canonical_engine=vulndb` and `vulndb_bundle` metadata.
- Direct database inspection showed package/range details for Alpine findings such as `busybox`, installed version, affected range, fixed version, and source range ID.

Implementation fixes from the live smoke:

- Syft 1.42 emits CPEs as object entries in addition to legacy strings. Constellation now accepts both JSON shapes and has a regression test for mixed string/object CPE lists.
- Scanner package detail JSON now uses stable lowercase keys (`name`, `version`, `ecosystem`, `purl`, `cpes`, `licenses`) instead of accidental Go field names.
- Findings list/detail APIs now promote package name, installed version, ecosystem, purl, and fixed version from scanner detail JSON, with compatibility for old capitalized package rows and affected-range fallback fields.
- Findings UI now displays package/fixed-version fields in the drawer and detail provenance panel, and query hints/client filtering support `package:`, `purl:`, and `fixed:`.
- Findings search DSL now supports server-side `package:`, `purl:`, and `fixed:` filters across both old and new detail JSON shapes.
- Heartbeat service-token middleware now accepts prefixed `cst_`/`cra_` tokens and legacy prefixless bootstrap tokens. Prefixless lookup tries scanner tokens first and runtime-agent tokens second, preserving distinct request subjects.
- Helm bootstrap token generation now creates prefixed scanner/runtime-agent tokens for new installs, and compose bootstrap no longer uses the scanner prefix for runtime-agent tokens.
- Heartbeat persistence now handles NULL `cluster_id` correctly. The handler uses a transaction-scoped advisory lock plus explicit latest-row update/insert behavior, and migration `061_component_heartbeats_nullsafe_unique.sql` deduplicates existing rows before adding a NULL-safe unique index.

Live issues converted into plan tasks:

- API manual upload accepted the compressed bundle but OOMKilled the API pod under a 1Gi limit while materializing the roughly 884 MiB bbolt store. Production update flow must treat the VulnDB producer/importer/prebuilt-store path as primary; direct API upload remains a dev/emergency path and needs explicit size/resource policy if retained.
- Public ingress rejected the manual bundle upload with HTTP 413 before the port-forward bypass. If manual upload remains supported through ingress, chart values need a documented max body size annotation and tests.
- The k3s smoke image was a lean scanner image with Syft only. Production scanner image validation still needs the full pinned toolchain path with Syft, Trivy, Grype, cosign, oras, and crictl.
- The current bundle is intentionally a distro smoke bundle. Production quality requires a fuller source mix with NVD/OSV/GHSA/vendor advisories/CVSS enrichment, then severity/risk validation across representative images.
- The first heartbeat auth fix exposed a schema bug: `UNIQUE(org_id, cluster_id, component, hostname)` did not prevent duplicate rows for NULL cluster IDs. This is now fixed in code and migration, and the live k3s database has been deduplicated and indexed.

Definition-of-done updates:

- VulnDB-first image scanning is not considered done until a live cluster scan proves `Syft -> VulnDB -> persisted finding -> API/UI package/fixed fields` with the current production chart and scanner image.
- VulnDB update flow is not considered production-ready until a large generated bundle can be installed without API OOM, with status metadata, freshness/trust policy, rollback behavior, and scanner rescan trigger validation.
- Service-token work is not done until scanner, runtime-agent, operator, and any shared-token components all emit successful heartbeats in a fresh install and after upgrading from a prefixless-token install.

## Target Architecture

### VulnDB Producer

`constellation-vulndb` is the system of record for vulnerability intelligence. It should:

- Ingest NVD, OSV, GHSA, KEV, EPSS, distro/vendor feeds, Vulnrichment, and future sources.
- Normalize into the v2 `vuln_*` schema.
- Preserve source provenance, snapshots, watermarks, and source lock metadata.
- Build deterministic `bundle.jsonl.gz` plus `manifest.json`.
- Sign bundle artifacts.
- Push bundles to OCI and optionally immutable object storage.
- Build bbolt stores from verified bundles.
- Expose scanner-grade matching over a stable consumer API and CLI.
- Provide public compatibility fixtures so every downstream consumer can run the same tests.

### Constellation Consumer

`constellation` consumes released VulnDB artifacts. It should:

- Consume and verify VulnDB bundles or stores from a configured delivery channel: manual upload, mounted files, HTTPS/presigned URL, native S3 URI, OCI immutable ref, or pinned tag.
- Reject unsupported schema/media type combinations.
- Materialize or receive a read-only bbolt store from a verified bundle.
- Use VulnDB matching for host packages and image SBOM packages.
- Record `bundle_version`, `payload_hash`, `record_count`, `schema_version`, and media type on every finding batch.
- Display freshness and provenance in API and UI. Implemented for installed VulnDB status via importer status JSON plus store metadata, and for scan jobs through persisted batch-level `bundle_metadata`.
- Treat Trivy and Grype as optional cross-check engines.
- Never import from a drifted vendored copy.

### NeuVector-Inspired Runtime Model

NeuVector is a mature full lifecycle container security platform with manager, controller, enforcer, scanner, updater, admission, registry scanning, compliance profiles, runtime policy, and a C data plane for Layer 7 inspection. Constellation should borrow the pattern, not blindly copy the code:

- Dedicated scanner and updater/importer roles.
- Strong controller/enforcer separation.
- Runtime agent with explicit host privileges, documented and validated.
- Policy lifecycle: discover, monitor, protect.
- Admission and registry controls backed by testable policy profiles.
- CI that builds the native data plane and runs security scanners.
- Clear upgrade and data compatibility contracts.

## NeuVector Whole-Stack Scan Baseline - 2026-06-13

This section is the source-level baseline for greenfield Constellation parity. NeuVector is not only an image scanner. It presents one posture system across running containers, hosts/nodes, registry images, Kubernetes/OpenShift platform packages, admission control, compliance checks, and runtime enforcement telemetry.

Source references used for this baseline:

- `../neuvector/share/scan.proto`
- `../neuvector/share/scanner_service.proto`
- `../neuvector/share/enforcer_service.proto`
- `../neuvector/agent/grpc.go`
- `../neuvector/agent/bench.go`
- `../neuvector/controller/cache/scan.go`
- `../neuvector/controller/rpc/scanner.go`
- `../neuvector/controller/scan/image.go`
- `../neuvector/controller/scan/registry.go`
- `../neuvector/controller/scan/interface.go`
- `../neuvector/controller/cache/admission.go`
- `../neuvector/controller/rest/scanner.go`
- `../neuvector/controller/rest/registry.go`
- `../neuvector/controller/rest/repository.go`
- `../neuvector/controller/grpc.go`

### NeuVector Scan Object Model

NeuVector's protobuf model names the important scan target classes directly:

- `CONTAINER`: a running workload/container scan.
- `HOST`: a node/host scan.
- `IMAGE`: a registry or repository image scan.
- `PLATFORM`: Kubernetes/OpenShift platform package scan.
- `SERVERLESS`: AWS Lambda/serverless scan shape exposed in scanner protocol and logs.

NeuVector's scanner service exposes these RPCs:

- `ScanRunning`: scan a running container or host by asking the relevant enforcer for filesystem/package data.
- `ScanImageData`: scan data already collected elsewhere.
- `ScanImage`: pull and inspect an image from a registry/repository.
- `ScanAppPackage`: scan application/platform packages, used for Kubernetes/OpenShift version checks.
- `ScanAwsLambda`: serverless/Lambda package scan shape.
- `ScanCacheGetStat` and `ScanCacheGetData`: scanner cache visibility.
- `SetScannerSettings`: scanner runtime settings.

Constellation target:

- Add a first-class `scan_targets` model with explicit target types: `workload`, `host`, `image`, `platform`, `registry`, `repository`, and `serverless`.
- Every `scan_jobs` row should point to a target type plus a target identity, not only `image_ref`.
- Findings should keep both `target_type` and `cluster_id` so dashboard, node, deployment, image, and platform views can all drill into the same evidence graph.

Implementation status, 2026-06-14:

- Completed the storage/API foundation with `scan_targets`, `scan_jobs.target_id`, target-aware findings fields, target-aware list/claim/complete paths, registry-target queueing, local cluster image-target queueing, scanner unsupported-target rejection, and frontend typed target contracts.
- Completed first package-evidence execution slice: `scan_evidence` stores target-scoped package inventories, host package reports upsert `host` scan targets and queue scanner work, scanner workers fetch package evidence and run VulnDB package matching without pulling an image, host vulnerability reads use unified host-target findings, and connector coverage exposes host package evidence coverage.
- Added first NeuVector-style node aggregate API: `/api/v1/clusters/{id}/nodes` and `/api/v1/clusters/{id}/nodes/{node}` roll host facts, package evidence, containers, processes, CIS, runtime-agent freshness, scanner target/job state, and host CVE counts/detail into one cluster-scoped node surface.
- Added the first running workload package-evidence relay: runtime-agent resolves running container PIDs through CRI, reads package databases from `/proc/<pid>/root`, groups sidecars into a workload evidence report, posts `/api/v1/workload-packages:report`, and the API stores `workload` scan targets/evidence for scanner workers to match through the existing `ScanPackages` path.
- Added first image-to-workload reverse index: discoverer maintains `image_workload_links` with raw ref, normalized ref, repository, tag, digest, and workload identity; `GET /api/v1/scan-targets/{id}/impacted-workloads` exposes NeuVector-style impacted workloads for image scan targets by raw ref, normalized ref, and digest.
- Added first canonical image-result write path: `image_scan_results` is keyed by org, image digest, platform, scanner profile, VulnDB bundle version, and bundle hash; `image_scan_findings` stores stable per-result finding identities; scanner completion now requires claimed-worker ownership, requires digest identity for image completions, upserts canonical results/findings, and resolves stale canonical findings.
- Scanner workers now resolve tag refs to digest-pinned refs before image scanning when the target is not already pinned, and report `image_ref`, `image_digest`, `platform`, and `scanner_profile` back to the API.
- Deployment risk rollups and admission evidence gates now read canonical image scan results/findings by digest/ref instead of image asset projections, with active workload exposure joined through `image_workload_links` for cluster risk.
- Added the first canonical image scan result read API: `GET /api/v1/image-scan-results`, `GET /api/v1/image-scan-results/{id}`, and `GET /api/v1/image-scan-results/{id}/affected-workloads` return digest/platform/profile/bundle scan summaries, canonical findings, severity counts, max risk, VulnDB provenance, and affected workloads.
- Asset list/detail and deployed-image connector coverage now summarize image vulnerability risk from canonical image scan results/findings. Generic findings remain the read model for non-image assets.
- Discoverer now merges Kubernetes runtime image IDs from pod status into `image_workload_links`, including ReplicaSet-owned Deployment pods and bare `sha256:` node-local image IDs, so local-cluster exposure is keyed by actual running digest instead of only declared tag refs.
- Image scan completion no longer writes image vulnerabilities into the general `findings` table. Image targets write only canonical `image_scan_results` and `image_scan_findings`; non-image scan targets write target-scoped general findings with stable `scan_finding_key` identities.
- CVE detail now reads canonical image scan evidence through `GET /api/v1/cve/{id}/affected`, returning affected image scan results, workload exposure, and cluster exposure without depending on image rows in `/findings`.
- Added first-class cluster-scoped image scan inventory and detail screens at `/clusters/{id}/images` and `/clusters/{id}/images/{image_scan_result_id}`. The UI now surfaces canonical image identity, digest, package and finding counts, severity rollups, local-image/running-workload/stale-scan badges, affected workloads, vulnerable packages, and VulnDB bundle provenance directly from `image_scan_results` and `image_scan_findings`.
- Added first-class cluster-scoped node inventory and detail screens at `/clusters/{id}/nodes` and `/clusters/{id}/nodes/{node}`. The UI now surfaces host OS/kernel/runtime identity, runtime-agent freshness, scan target status, coverage gaps, package/container/process inventory counts, CIS rollups/evidence, host CVEs, and raw host evidence payloads from the node aggregate API.
- Expanded workload detail into a NeuVector-style aggregate at `/clusters/{id}/deployments/{deployment_id}`. `GET /api/v1/deployments/{id}` now returns deployment identity, active image exposure, canonical image scan summaries, workload package evidence, direct workload findings, runtime events, network flows, full runtime network-policy lifecycle state, active workload quarantine state, and violations in one response.
- Cluster navigation, command palette, CVE affected-image pivots, and cluster-scoped asset/finding drilldowns now route to canonical cluster paths, including image scan detail pages.
- Scanner queue operations now expose target-type buckets. `GET /api/v1/scan-jobs` returns `queue_metrics`, and connector coverage scanner capacity renders pending/running/failed/oldest-pending queue depth by scan target type so image, host, workload, platform, repository, and serverless pressure are visible separately.
- Scanner worker orchestration now has first-class queue lease semantics: claim sets `lease_expires_at`, complete/fail clears the lease, expired running jobs can be reclaimed by another scanner worker, stale running counts are exposed through `GET /api/v1/scan-jobs` and connector coverage, and the coverage UI shows stale scanner work separately from pending queue depth. The scanner binary now fills available worker slots without claiming more jobs than local concurrency allows, and job failure is bound to the scanner worker that owns the current claim.
- Scanner ownership, renewal, and retry accounting are now first-class: scanner pods send a per-instance ID so replicas sharing one token do not share a lease owner, workers renew active job leases, `/api/v1/scan-jobs/{id}/renew` rejects non-owner renewal, retryable scanner failures are returned to pending with bounded exponential backoff, max attempts terminally fail jobs, and `/api/v1/scan-jobs/{id}/retry` gives operators an audited manual requeue path.
- Scanner capacity and readiness telemetry now moves through heartbeats: `component_heartbeats.metadata` stores scanner max concurrency, active jobs, idle slots, target-type credits, active jobs by target type, engine toggles, cache paths, and local VulnDB store status; scanners can enforce configured per-target credits by passing target-type allow-lists to claim; connector coverage renders active scanner pods with busy/idle capacity and per-pod VulnDB status; Helm renders a scanner metrics Service, optional scanner HPA, target capacity values, and an optional scanner readiness gate requiring a readable local VulnDB store.
- Scanner dependency health is now first-class in operations surfaces: scanner heartbeats include per-cache configured/present/writable/free-space status plus bounded record counts, byte totals, and cache-record samples; System Health marks alive-but-broken scanner pods as `degraded`; the scanner-worker component warns when no scanner is ready even with an empty queue; Connector Coverage shows cluster-aware scanner rows with cache health and an inline cache-record drilldown; `/api/v1/scanner-cache/{scanner_id}/stat` and `/api/v1/scanner-cache/{scanner_id}/data` provide Constellation-native cache stat/data views over the latest scanner heartbeat; NeuVector-compatible aliases `/api/v1/scan/scanner`, `/api/v1/scan/cache_stat/{scanner_id}`, and `/api/v1/scan/cache_data/{scanner_id}` expose the same scanner/cache telemetry with NeuVector field names; and `/api/v1/vulndb/status` shows cluster-aware scanner consumers of the installed VulnDB bundle.
- Added first-class component inventory: `/api/v1/components` and `/api/v1/components/{id}` now expose heartbeat-backed API, scanner, VulnDB importer, operator, discoverer, admission, registry-walker, runtime-agent, and future sidecar instances with expected/missing rollups, cluster scope, role, build version, commit drift, restart counts, stale/crashloop/degraded status, and allowlisted public metadata; the cluster console now has `/clusters/{id}/components` for NeuVector-style controller/enforcer inventory.
- Expanded component heartbeat coverage and local-cluster attribution: heartbeat payloads can now send `cluster_name` when Helm cannot know the DB-generated UUID, the API resolves that name within the token's org, token-file based heartbeat emitters retry through bootstrap races, scanner/runtime-agent/operator/admission/network-policy-applier/k8s-compliance-collector/registry-walker/compliance-scheduler emit canonical component heartbeats, and Helm wires API URL, cluster name, token file mounts, and production NetworkPolicy API paths for the default installed roles.
- Closed the remaining component producer heartbeat gap: the API now self-reports through the authenticated heartbeat route using a loopback URL plus token-file retry; audit-archiver sends bounded success/failure one-shot metadata without leaking bucket credentials; `constellation-vulndb`'s `vulndb-bundle-install` sends install success/failure heartbeats with sanitized source, trust, and bundle metadata; and Helm renders token mounts plus NetworkPolicy API paths for audit-archiver and both VulnDB importer CronJob/install Job modes.
- Added admin-gated component diagnostics: `/api/v1/components/{id}/diagnostics` is gated by `manage-org` and returns normalized status flags, scanner capacity counters, VulnDB/cache checks, safe config, and explicit debug gate state without returning raw heartbeat metadata, paths, cache records, token-shaped strings, or unauthenticated profiling/log access. The Components UI now renders role-aware counters, diagnostics checks, safe config, and a GlobalAdmin-required state.
- Runtime-agent heartbeats now carry NeuVector-style enforcer/probe telemetry sourced from the same counters as `/metrics`: eBPF event totals/drops, upload drops, flow/threat upload counters, DP lifecycle/IPC/keepalive/tap/enforcement/session counters, CNI detection, policy mode, and probe status. Component diagnostics maps that metadata into runtime-agent DP/eBPF/probe checks and counters for node-agent parity.
- Runtime-agent component diagnostics now pivot into the node evidence map for the same cluster/node, adding freshness checks and counters for host facts, container inventory, process inventory, host packages, and CIS evidence without returning raw process payloads, container labels, sockets, command lines, or image refs. This closes the first controller/enforcer inventory bridge from component health to node probe maps.
- Scanner lifecycle/status parity now has a NeuVector-style aggregate read path and visible operator controls: `/api/v1/scan/status` reports scanned/scheduled/scanning/failed plus Constellation-native paused/canceled counts and VulnDB bundle version/create time; target-type queue metrics include paused and canceled counts; Connector Coverage exposes pause/resume/cancel/retry actions for recent scan jobs; and late scanner complete/fail reports for operator-canceled running jobs return a dropped acknowledgment without writing results.
- Added NeuVector-style scan object aliases over the evidence-backed scanner queue: `/api/v1/scan/workload/{id}`, `/api/v1/scan/host/{id}`, `/api/v1/scan/platform`, and `/api/v1/scan/platform/platform` now expose workload, host, and platform trigger/report shapes. Triggers require existing package evidence instead of creating empty targets, reports always include NeuVector's `report.vulnerabilities` wrapper, platform summaries expose Kubernetes version and scan brief fields, and trigger routes are gated by `manage-policies` while report routes use `read-findings`.
- Added VulnDB bundle-change rescans for evidence-backed targets: manual bundle imports now queue stale host, workload, platform, serverless, and runtime-agent local-image scans after the bbolt store is installed; `/api/v1/vulndb:rescan` lets operators trigger the same pass after an external importer update; and the API runs a configurable status/store poller (`vulndb.rescan.interval`, default `2m`) so S3/OCI/file-driven importer updates converge without API ownership of bundle generation. Dedupe compares bundle version plus payload hash, leaves last-good reports intact, and skips registry images because registry policy sync owns pull-based image rescans.
- Added the first platform scan execution path: discoverer reports Kubernetes server version, kubelet versions, provider, and known platform add-on image versions; `/api/v1/platform-facts:report` persists `cluster_platform_facts`, upserts a `platform` scan target, stores package evidence, and queues scanner work; scanner package queries now preserve explicit `generic` namespaces such as `generic/kubernetes` and `generic/k3s`.
- Added platform read/actions: `/api/v1/clusters/{id}/platform-facts` returns platform facts, evidence, job status, findings summary, and VulnDB bundle provenance when a scan completes; `/api/v1/clusters/{id}/platform-scan` requeues the latest platform evidence. Cluster dashboard, cluster picker, and cluster health now surface platform version/freshness/scan posture.
- Added the VulnDB platform producer contract: `constellation-vulndb` compatibility fixtures now include `generic/kubernetes` and `generic/k3s` advisories, Constellation downstream tests consume those platform matches, and the VulnDB aggregator has a `platform` source for curated Kubernetes-family advisory JSON files or URLs.
- Added repository/CI image-scan provenance: repository-sourced scans use `target_type=image` with `source_type=repository`, require `source_ref`, reject fake executable `target_type=repository` jobs, preserve source metadata on scan jobs, image scan results, assets, and finding detail JSON, and show repository-scan source context in the image inventory/detail UI.
- Added runtime-agent local image package-evidence scans: `/api/v1/workload-packages:report` now also upserts image scan targets/evidence per running container, queues runtime-agent-sourced image jobs, scanner claim returns evidence and image digest for those targets, and scanner workers use `ScanPackages` instead of pulling from a registry when image package evidence is attached.
- Added result-scoped image scan artifacts: scanner completion now persists the package inventory, SPDX 2.3 SBOM, and CycloneDX 1.6 SBOM under `image_scan_artifacts`; `/api/v1/image-scan-results/{id}/packages`, `/sbom/spdx`, and `/sbom/cyclonedx` expose those artifacts; asset SBOM summaries read the latest canonical image scan artifacts instead of the old asset document table; and the image scan detail UI has authenticated downloads for inventory/SPDX/CycloneDX.
- Added first-class image secret, signature, layer metadata, and file-risk scan artifacts: Trivy now runs `vuln,secret`, scanner aggregation carries normalized secret hits, scan completion sanitizes worker-provided secret display values, `image_scan_artifacts` stores `secret-scan` reports in `constellation-image-secrets-v1` format, `/api/v1/image-scan-results/{id}/secrets` exposes the redacted report, and the image scan detail UI shows secret counts plus authenticated secret-report download. Scanner workers also verify digest-pinned registry image signatures with cosign when enabled, store `signature-scan` reports in `constellation-image-signature-v1` format, update `images.signed/signature_info`, expose `/api/v1/image-scan-results/{id}/signature`, and show signed/trusted status in image detail. Registry image scans now also inspect OCI/Docker manifests, persist `layer-metadata` reports in `constellation-image-layers-v1` format, update image layer/architecture/size metadata when observed, expose `/api/v1/image-scan-results/{id}/layers`, and show layer counts plus authenticated layer metadata download in image detail. Scanner workers also stream image layers with `go-containerregistry`, apply whiteouts/overwrites, detect setuid, setgid, world-writable, device-node, and FIFO metadata risks, persist `file-risk` reports in `constellation-image-file-risk-v1` format, expose `/api/v1/image-scan-results/{id}/file-risks`, and show file-risk counts/downloads in image detail.
- Added first artifact-backed admission controls: AdmissionRule YAML now supports `imageArtifacts.secrets`, `imageArtifacts.fileRisks`, and `imageArtifacts.signature`; the admission webhook evaluates the latest canonical `image_scan_results` row plus result-scoped `image_scan_artifacts` for the admitted image; built-in profiles can now require trusted image-signature scan evidence and deny scanner-confirmed high-severity secrets or dangerous file metadata such as setuid, setgid, world-writable, device-node, and FIFO entries.
- Added scan-evidence quality admission gates: AdmissionRule YAML now supports shared `scanEvidence.maxAge`, `scanEvidence.requireVulnDBBundle`, `scanEvidence.canonicalEngine(s)`, vulnerability `requireFixAvailable`, and signature `requireVerifierIdentity` / allowed verifier identities. The live admission evidence source fails closed for unscanned, stale, or bundle-less images when requested, filters vulnerability decisions by canonical engine and fixed-version availability, and validates signature verifier identity from result-scoped signature artifacts. Built-in profiles now include fresh VulnDB-backed critical-vulnerability gates, fresh trusted signature verifier gates, and a separate fixable-vulnerability profile; the Policies UI exposes evidence badges for these gate types.
- Added source-aware admission scan evidence gates: AdmissionRule YAML now supports `scanEvidence.sourceType(s)` and `scanEvidence.requireDigestMatch`, scan completion persists `source_type`/`source_ref` directly on canonical image scan results, admission evidence lookups filter source type before choosing results, and repository/CI reuse can require exact admitted digest matches instead of trusting mutable tag evidence.
- Added stored-scan dry-run simulation parity: admission evidence lookup now lives in `internal/admissionevidence`, the webhook and policy simulator share the same canonical scan-result/artifact SQL path, and dry-run simulation evaluates persisted `constellation-admission` rules through the production admission parser/engine instead of static policy-name matching.
- Added admission evidence-detail and builder UX parity: dry-run simulation now threads `cluster_id`, returns typed evidence details for scan results/findings/artifacts, carries scan-result source provenance such as repository/CI evidence into admission explanations, renders safe internal pivots to cluster image detail pages, and exposes compact AdmissionRule builder controls for common VulnDB freshness, canonical-engine, fixability, and trusted signature gates.
- Connected vulnerability profiles to canonical scan result writes: scan completion now loads active org/cluster vulnerability profiles and tags each canonical image/workload finding's detail JSON with the first matching profile decision, profile identity, entry name, and reason. This is intentionally non-destructive for the first slice so image scan evidence remains complete while downstream finding filters, admission decisions, and UI badges can consume the explicit profile outcome.
- Added first image artifact drilldown UI: the image scan detail page now fetches the authenticated artifact APIs and renders signature verifier status/identity, OCI layer digest/size/media metadata, redacted secret findings, and file-risk findings inline while preserving JSON artifact downloads for audit/export workflows.
- Added image artifact compliance joins: scan completion carries engine success/error provenance, clean Trivy secret scans now persist zero-count `secret-scan` artifacts, and workload compliance evidence joins `image_workload_links -> image_scan_results -> image_scan_artifacts` to emit framework-expanded controls for embedded image secrets and risky image filesystem metadata.
- Added workload-detail compliance evidence: `GET /api/v1/deployments/{id}` now includes workload-scoped compliance evidence from the shared collector, filters out sibling workload rows in the same namespace, and the cluster deployment detail UI renders compliance failures/manual rows alongside runtime policy, packages, events, and violations.
- Added workload-detail process baseline joins: `GET /api/v1/deployments/{id}` now derives a process baseline from persisted `process_exec` runtime events, including learned process counts, top observed commands, first/last seen timestamps, alert/block rollups, persisted mode, and transition history, with an indexed lookup path and UI panel on the deployment detail screen.
- Added workload-detail file/DLP/WAF threat pivots: runtime DLP/WAF threat ingest now persists workload attribution, deployment detail exposes exact workload-scoped `threat_pivots` for file-open, DLP, and WAF signals plus deployment-rooted image `file_risks`, and the UI renders filterable runtime pivots with evidence drilldown without using unsafe MAC/prefix matching.
- Added exact pod-owner projection for workload detail: discoverer now writes `pod_workload_links` with pod UID, owner UID, deployment ID, owner workload ID, node, and phase, mirrors the same ownership onto `pod_ips`, and deployment detail uses that deployment-ID owner set for package evidence, runtime events, file/DLP/WAF pivots, flows, process baselines, findings, and compliance filtering instead of prefix or asset-name fallbacks.
- Added workload-detail action controls: deployment detail now returns full network-policy lifecycle data and active workload quarantine state, and the UI exposes approve/apply/demote/rollback controls with candidate hash/stale handling, live applier status, manifest/diff/audit review, and workload quarantine/lift actions against the real product APIs.
- Added persistent process-baseline lifecycle controls: process baseline modes and transitions now persist in `process_baseline_states` and `process_baseline_transitions`, the baseline API aggregates pod-scoped process evidence through owner links, and deployment detail exposes promote/rollback controls with required audit reasons.
- Added first workload file-profile lifecycle controls: `file_profile_states` and `file_profile_transitions` now persist learn/monitor/enforce state for workload file monitoring, `/api/v1/runtime/file-profiles` exposes list/detail/mode transitions from real `file_open` runtime telemetry, deployment detail returns file profile evidence with sensitive-path and alert/block rollups, and the UI exposes file monitor promote/rollback controls with required audit reasons.
- Added first NeuVector-style file monitor rule controls: `file_profile_rules` persists operator-authored filters with derived regex-ready `path`/`regex` match fields, recursive matching, `monitor_change`/`block_access` behaviors, application constraints, enablement, audit metadata, and reasoned create/update/delete APIs. Deployment detail and the file-profile API now return rule counts/rules, and the UI exposes an editable file monitor rule form plus rule list on the workload detail screen.
- Added first agent-facing file monitor rule distribution/classification path: runtime-agent token auth now exposes `GET /api/v1/runtime/file-profile-rules:bundle?cluster_id=...`, the runtime agent pulls and caches that cluster-scoped bundle independently of the DP supervisor, `/api/v1/events:bulk` honors the agent's `cluster_id`, and server-side `file_open` ingest classifies enabled monitor/enforce profile rules with NeuVector-style block-before-monitor, recursive-before-nonrecursive, app-scoped matching. `block_access` records high-severity `alert` evidence with `would_block=true` when observe-only and `block` evidence when the node-local enforcer actually denies the open.
- Added first live watched-file inventory path: rule bundles now include pod workload IDs, the runtime agent resolves running containers through CRI and walks bounded rule-matching paths under `/proc/<pid>/root`, reports metadata-only snapshots to `POST /api/v1/runtime/file-profile-watches:report`, and the API stores cluster/node/rule inventory with derived sensitive counts, desired-protect state, sync freshness, and bundle fingerprint. File-profile detail and deployment detail now expose watched files/counts/status, and the workload detail UI renders the synced watch inventory. Helm and operator-managed runtime-agent DaemonSets now align on `/host` hostscan mounts so local-cluster CRI and container-root discovery work by default.
- Added first NeuVector-style file access deny path: runtime-agent now starts a Linux fanotify permission loop by default, selects only `mode=enforce` + `block_access` rules, resolves matching running containers through CRI, marks exact files and bounded wildcard directories under container roots with `FAN_OPEN_PERM`, treats application lists as allowlists, denies non-allowlisted opens with `FAN_DENY`, uploads blocked `file_open` events with `blocked=true`, and feeds `enforced/error/unsupported` status back into watched-file inventory. This still needs privileged live-cluster validation before it is considered enterprise-complete.
- Added file-profile portability and NeuVector migration coverage: `GET /api/v1/runtime/file-profiles/{workload_id}/export` now emits `constellation-file-profile-v1` bundles, `POST /api/v1/runtime/file-profiles/{workload_id}:import` supports audited dry-run/replace/retarget imports with direct mode restore, the TypeScript client exposes the bundle contract, and the NeuVector migration preview now carries first-class file profile imports from REST `file_monitor` profiles, REST profile lists, direct profile exports, `NvSecurityRule.spec.file`, and Kubernetes list YAML while preserving `applications`/`app`, `monitor_change`/`block_access`, recursive matching, group, and cfg-type metadata.
- Added file-profile exception workflows: `file_profile_exceptions` now stores audited workload-wide or rule-scoped path/application exceptions with optional expiration; file-profile detail/export/import, deployment detail, runtime-agent bundles, server-side event classification, and Linux fanotify deny decisions all honor active exceptions. The workload detail UI can create/delete exceptions and import/export reviewed file-profile bundles, and Settings migration preview now shows migrated file profiles as first-class artifacts.
- Added first serverless package-evidence execution path: `/api/v1/serverless-packages:report` accepts function package inventory, upserts `serverless` scan targets/evidence, queues scanner work, and scanner claim attaches the evidence for the existing VulnDB `ScanPackages` path.
- Added first automatic AWS Lambda serverless producer: `constellationctl serverless aws-lambda sync` uses AWS SDK default credentials to list or fetch Lambda ZIP functions, download deployment packages and layers through AWS presigned URLs, safely extract archives, catalog packages with Syft, and post per-function evidence to `/api/v1/serverless-packages:report`. Target metadata now retains function name, code SHA, role, handler, package type, layer ARNs, and best-effort execution-role permission analysis.
- Added first AWS Lambda execution-role permission analyzer: the Lambda sync path inspects only the target function's execution role, URL-decodes AWS IAM policy documents, parses statement object/array plus string/list actions/resources, handles inline and attached managed policy documents, and reports critical/high permission posture such as AdministratorAccess, broad NotAction, `Action=* Resource=*`, sensitive service wildcards, and broad `iam:PassRole`. Missing IAM permissions degrade to `permission_analysis.status=unavailable` instead of blocking package CVE evidence.
- Added serverless permission posture promotion: `/api/v1/serverless-packages:report` now maps Lambda execution-role analysis into first-class `cloud-resource` assets and `cloud-config` findings tied back to the `serverless` scan target, with stable finding keys, risk scoring, evidence detail, unavailable-analysis findings, and stale finding resolution after a clean complete analysis.
- Added first serverless inventory surface: `GET /api/v1/serverless-functions` and `GET /api/v1/serverless-functions/{id}` expose serverless scan targets with latest package evidence, job history, permission posture, and findings; the cluster console now has Serverless list/detail pages with posture filters, role-policy evidence, package inventory, findings, and scan-job history.
- Added first repository package-evidence execution path: `/api/v1/repository-packages:report` accepts CI/operator package inventory for a repository checkout, upserts `repository` scan targets/evidence with URL/commit/branch/workflow/run metadata, queues scanner work, and scanner claim attaches the evidence for the existing VulnDB `ScanPackages` path. `constellationctl repository scan` catalogs a checkout with Syft and posts the evidence without overloading image-specific package fields. `GET /api/v1/repository-scans`, `GET /api/v1/repository-scans/{id}`, and the cluster Repositories page expose repository scan inventory, latest evidence, job state, package counts, and finding rollups. Admission evidence details now preserve repository/CI source context from image scan results so dry-run denies can explain which upstream scan produced the reusable evidence, and AdmissionRule scan-evidence gates can require repository/CI source plus exact digest matching.
- Added first repository/CI scan attestation storage path: `scan_result_attestations`, `POST /api/v1/repository-scan-attestations:report`, `GET /api/v1/repository-scan-attestations/{id}`, `GET /api/v1/repository-scans/{id}/attestations`, and `GET /api/v1/image-scan-results/{id}/attestations` store in-toto/SLSA/DSSE-style material with server-computed payload hashes, strict scan-target/evidence/job/result ownership checks, repository inventory latest-attestation summaries, and UI provenance badges/details. Uploaded attestations remain `trusted=false` and `unverified`/`unsigned` until a server-side verifier promotes them; client-supplied `trusted=true` is rejected.
- Added verifier-backed repository/CI attestation promotion and admission reuse: `POST /api/v1/repository-scan-attestations/{id}:verify` runs server-side cosign `verify-attestation` through a persisted trust policy, requires the verified predicate type, payload hash, and in-toto subject digest to match the stored row, preserves trusted status across idempotent re-reports, and rejects digestless image subjects. AdmissionRule `scanEvidence` now supports `requireTrustedAttestation`, `attestationPredicateType(s)`, `allowedAttestationIdentities`, and `allowedAttestationIssuers`; live admission evidence fails closed when trusted repository/CI provenance is missing for the admitted digest, and the policy builder can generate these gates.
- Added persisted org-level repository/CI attestation trust policies: `scan_attestation_trust_policies`, CRUD APIs, source/repository/predicate/signer matching, policy-id verification, matching auto-verify on report, `:verify-pending` batch promotion, first-class `trust_policy_id` and `verification_reason` on attestation rows and repository summaries, and admission evidence that requires trusted non-expired attestations to remain linked to an enabled policy.
- Added attestation trust-policy operations UI: `/settings/attestation-trust` lists policies, creates/edits source/predicate/signer policy fields, toggles enabled and auto-verify state, runs verify-pending actions, and links from the Settings overview with policy/auto-verify counts.
- Added immutable attestation verification history and export: `scan_attestation_verifications` records every manual or automatic verification attempt with policy snapshot, verifier metadata, status, signer, reason/error, actor, and append-only database triggers; `GET /api/v1/repository-scan-attestations/{id}/verifications` lists attempts, `GET /api/v1/repository-scan-attestations/{id}/export` downloads the full attestation/evidence/history bundle, trust policy CRUD and `attestation.verify` now emit hash-chained audit events, and the Repositories UI shows recent attestation history, verification attempts, and export actions.
- Added repository-scan retention lifecycle: the API now has a Helm/env-driven retention worker for old repository scan targets, guarded by a transaction advisory lock for multi-replica installs. It prunes repository findings, repository scan-target assets, jobs, evidence, and unverified attestation rows through the target cascade, skips pending/running/paused jobs, and skips targets that have immutable attestation verification history or unexpired trusted attestations.
- Added package-to-layer image provenance: Syft package locations now persist in `scanner.Package`, package inventory artifacts preserve path/layer digest evidence, `/api/v1/image-scan-results/{id}/packages` returns a derived `package_layers` summary joined against layer metadata, SPDX/CycloneDX exports carry Constellation package-location metadata, and the image scan detail UI shows package provenance inline. Remaining depth is full file inventory, per-layer vulnerability rollups, and local-image layer attribution when runtime-agent evidence is package-only.
- New scan jobs use `scan_targets` as the source of truth. Existing `scan_jobs.image_ref` data is only migration input/backfill context, not the runtime identity model.
- Remaining work: live AWS Lambda validation with real package/layer ZIPs, live keyless/keyed cosign validation against real CI issuer material, generated-bundle/live k3s validation of local workload/image/platform/serverless/repository/secret/signature/layer/file-risk/admission/compliance/file-enforcement gates, full per-layer vulnerability and file-inventory provenance joins, advanced admission policy-builder controls, and privileged live file-enforcement validation.

Definition of done:

- The API can create, list, claim, complete, fail, retry, and cancel scans for every supported target type.
- The UI exposes scan coverage by target type and shows missing coverage explicitly.
- The scanner worker can reject unsupported target types with a typed terminal error.
- Queue metrics break down by target type, status, age, stale lease count, retry count, and scanner pod.
- Scanner pool telemetry distinguishes pending queue pressure from stale running work, and stale running jobs are reclaimable without manual database repair.
- Long scans renew leases before expiry, while stale completions from a different scanner pod instance are rejected even when both pods share the same scanner token.

Validation:

```bash
cd /root/constellation-all/constellation
go test ./internal/handler -run 'TestScanJobs_.*Target'
go test ./internal/handler -run 'TestScanJobs_(RenewRequiresSameScannerInstance|RetryBackoffAndMaxAttempts|ClaimReclaimsExpiredLeaseAndFailureRequiresWorker)'
go test ./internal/handler -run 'Test(HeartbeatsIngestPersistsMetadata|ConnectorCoverage_OverviewUsesDatabaseState|ScanJobs_ClaimFiltersTargetTypes)'
go test ./internal/handler -run 'Test(SystemHealth_ScannerMetadataSignals|VulnDBStatusIncludesScannerConsumers|ScannerCacheStatAndDataFromHeartbeatMetadata)'
go test ./internal/handler -run 'TestScanJobs_(ListIncludesQueueMetricsByTargetType|StatusReportsNeuVectorAggregate|CanceledRunningWorkerReportsAreDropped)'
go test ./cmd/constellation-scanner -run 'Test(ParseTargetCapacities|ReadyzRequiresVulnDB|StatusSnapshotReportsCacheHealth)'
helm template constellation deploy/charts/constellation --set scanner.autoscaling.enabled=true --set-string scanner.targetCapacity='image=2\,host=8' --set scanner.readiness.requireVulnDB=true
curl -s "$CONSTELLATION_API/api/v1/scan-jobs?target_type=host" | jq .
curl -s "$CONSTELLATION_API/api/v1/scan-jobs?target_type=platform" | jq .
```

### Running Workload and Local Image Scan Flow

NeuVector running workload scans are not just remote registry pulls:

1. The controller tracks workloads in `scanMap`.
2. New workloads are added as `ScanObjectType_CONTAINER`.
3. Scanner pods are acquired through a scanner-credit manager.
4. The scanner calls `ScanRunning`.
5. `ScanRunning` contains the enforcer RPC endpoint.
6. The enforcer handles `ScanGetFiles`.
7. The enforcer's walker reads package data from the running container filesystem by PID.
8. The scanner performs matching and returns a `ScanResult`.
9. The controller stores scan reports and summaries.

This is the important local-image lesson. If an image is only present in node-local containerd, a central scanner pod that tries to pull `constellation/api:dev` from a registry will fail. NeuVector avoids that class of failure by having the node enforcer provide the running container filesystem/package data to the scanner.

Constellation target:

- Keep `constellation-scanner` as the scalable CPU/memory-heavy scanner worker.
- Add a runtime-agent scan relay for node-local evidence:
  - snapshot running container filesystem/SBOM by container ID or pod UID.
  - stream package inventory or archive chunks to a scanner worker.
  - keep node-local image scans separate from registry image scans.
- Use Syft as the inventory engine when a filesystem or image ref is available.
- Use Constellation VulnDB as the canonical matcher over the inventory.
- Keep Trivy/Grype optional as evidence scanners only.

Greenfield improvements over NeuVector:

- Prefer streaming SBOM/package inventory over shipping arbitrary container files to the scanner whenever possible.
- Use content-addressed scan evidence: image digest, container ID, pod UID, node name, inventory hash, and bundle hash.
- Avoid duplicate findings for the same image digest across workloads while preserving workload impact.
- Make local-only images visible in the UI as `local image`, not as failed registry pulls.

Tasks:

- Add `target_type` and `target_ref` to scan job and finding storage.
- Add `runtime-agent` endpoint: `POST /api/v1/scan-evidence/workload:prepare` or equivalent control-plane mediated claim path. First API-mediated package evidence report is done as `POST /api/v1/workload-packages:report`.
- Add scanner endpoint or API-mediated artifact flow for SBOM evidence upload/download. First package-inventory image evidence path is complete for runtime-agent reports, and canonical image scan results now persist package inventory, SPDX/CycloneDX artifacts, redacted secret-scan artifacts, signature-scan artifacts, OCI/Docker layer metadata artifacts, and file-risk artifacts. Remaining depth is richer local filesystem evidence and per-layer package/file provenance.
- Add CRI resolver in runtime-agent for container ID, image ID, image ref, pod namespace/name, workload owner, and node. First implementation resolves CRI container PID, image/image ref, pod namespace/name/UID, container name, and node for package evidence.
- Add local-image scan job enqueue from the discoverer/runtime-agent when a deployed image has no resolvable remote registry digest. Discoverer now records runtime image IDs, including bare `sha256:` node-local image IDs, in the image-to-workload reverse index; runtime-agent workload package reports now create runtime-agent-sourced image scan targets/evidence and queue image scans that use package evidence.
- Add UI badges for `registry image`, `running workload`, `node-local image`, and `stale image scan`. Current UI shows registry/local/running/stale and repository-scan provenance; remaining badge refinement is a distinct runtime-agent image-evidence badge.
- Add impacted-workload reverse index. First backend slice completed with `image_workload_links` and `GET /api/v1/scan-targets/{id}/impacted-workloads`.
- Add canonical image scan result storage. First backend write slice completed with `image_scan_results`, `image_scan_findings`, digest-required image completion, and stale finding pruning.
- Move deployment risk rollups, admission evidence, `/findings`, asset detail, CVE detail, and image inventory to query canonical image results by digest and join active exposure through `image_workload_links`. Deployment risk rollups, admission evidence, asset list/detail, deployed-image coverage, CVE detail, and dedicated image inventory/detail screens now use canonical image results; image scan completion no longer writes image vulnerabilities into `/findings`.
- Add canonical image result read APIs. Completed first API/client slice with list, detail, affected workloads, typed frontend client contracts, severity counts, max risk, canonical findings, and VulnDB provenance.
- Add workload detail aggregate and UI. Done for deployment identity, image scan summaries, package evidence, direct workload findings, runtime events, persisted process baseline joins/actions, file profile joins/actions/rules, file monitor agent bundle distribution/rule-hit classification/watched-file inventory/fanotify deny status/import-export, file/DLP/WAF threat pivots, image file-risk pivots, network flows, full runtime network-policy lifecycle state, workload quarantine actions, workload compliance evidence, and violations. Remaining depth is privileged file-enforcement validation and live generated-bundle k3s validation.

Definition of done:

- A k3s install using local `constellation/*:dev` images produces completed workload scans without requiring a registry push.
- The same image digest running in ten pods has one canonical image scan result plus ten impacted workload links.
- A deleted pod keeps historical scan evidence but no longer counts as active exposure.
- Scanner pods can be scaled without changing runtime-agent privileges.

Validation:

```bash
kubectl -n constellation-system get pods -o wide
kubectl -n constellation-system logs deploy/constellation-runtime-agent --tail=200
kubectl -n constellation-system logs deploy/constellation-scanner --tail=200
curl -s "$CONSTELLATION_API/api/v1/clusters/$CLUSTER_ID/images?source=local" | jq .
curl -s "$CONSTELLATION_API/api/v1/findings?cluster_id=$CLUSTER_ID&q=source:local-image" | jq .
```

### Host and Node Scan Flow

NeuVector host scans use the same controller/scanner/enforcer split as workload scans:

1. The controller adds each agent host as `ScanObjectType_HOST`.
2. The scanner calls `ScanRunning` for the host target.
3. The enforcer handles host scan data using PID 1 and a host scan cache.
4. The scanner matches packages and returns a host/node report.
5. REST endpoints expose single-host and all-host scan reports.

Constellation current state:

- Runtime-agent reports host packages through `/api/v1/host-packages:report`.
- Host package storage exists in `host_packages`.
- Host package reports now become first-class `host` scan targets with `package-inventory` evidence and scanner queue status.
- Cluster-scoped node list/detail APIs now aggregate host facts, package inventory, container/process snapshots, host CIS, runtime-agent freshness, scanner status, and unified host-target findings. Cluster-scoped node list/detail UI now exposes that evidence under `/clusters/{id}/nodes`. Remaining host work is explicit stale evidence rescan triggers, runtime-event joins, and live cluster validation.
- Host CIS reporting exists separately through `host_cis`.

Constellation target:

- Treat every Kubernetes node as a first-class `host` scan target.
- Keep host package inventory collection in runtime-agent.
- Run host vulnerability matching through Constellation VulnDB with the same provenance model as image scans.
- Show node table, node detail, host package inventory, host CVEs, host CIS results, and runtime-agent health on one node page.

Greenfield improvements over NeuVector:

- Make host package collection and vulnerability matching independently observable.
- Store inventory hash and bundle hash so host rescans can be skipped safely.
- Support distro-specific rpm/apk/dpkg package metadata without shelling out.
- Make host scan freshness a cluster health gate.

Tasks:

- Add `/api/v1/clusters/{id}/nodes` and `/api/v1/clusters/{id}/nodes/{node}`. Done.
- Add node scan summaries: package count, critical/high CVEs, CIS pass/fail/manual counts, last runtime-agent heartbeat, kernel, OS, kubelet version, container runtime.
- Add host scan job type that consumes stored `host_packages`.
- Add host rescan trigger when VulnDB bundle changes.
- Add node UI table and node detail page. Done.

Definition of done:

- The local k3s node appears in the UI with package inventory, host vulnerabilities, CIS status, runtime-agent health, and recent runtime events.
- A VulnDB bundle update schedules or marks stale every affected host inventory.
- Nodes without a runtime-agent are shown as coverage gaps, not silently omitted.

Validation:

```bash
curl -s "$CONSTELLATION_API/api/v1/clusters/$CLUSTER_ID/nodes" | jq .
curl -s "$CONSTELLATION_API/api/v1/host-packages?cluster_id=$CLUSTER_ID" | jq .
curl -s "$CONSTELLATION_API/api/v1/host-cis?cluster_id=$CLUSTER_ID" | jq .
```

### Kubernetes/OpenShift Platform Scan Flow

NeuVector has a distinct `PLATFORM` scan:

1. The controller always schedules platform scan, even when workload/host autoscan is disabled.
2. It reads Kubernetes or OpenShift version.
3. It builds synthetic app package entries such as `kubernetes` or `openshift.kubernetes`.
4. It calls scanner `ScanAppPackage`.
5. It stores a platform report and exposes platform summary/report endpoints.

Constellation target:

- Add a platform scan target for each cluster.
- Discover Kubernetes distribution and versions: Kubernetes, k3s, RKE2, EKS, GKE, AKS, OpenShift.
- Convert platform version facts into VulnDB package queries.
- Track platform CVEs separately from node OS CVEs and workload image CVEs.
- Display platform vulnerabilities in the cluster dashboard and cluster health page.

Greenfield improvements over NeuVector:

- Make platform package identity explicit and versioned in VulnDB fixtures.
- Include control plane component versions when available: kube-apiserver, controller-manager, scheduler, kubelet, kube-proxy, etcd, CoreDNS, CNI plugin, ingress controller, cert-manager.
- Support managed-control-plane caveats in the UI.

Tasks:

- Extend discoverer/runtime-agent to report `cluster_components`. First slice complete: discoverer now reports Kubernetes server version, kubelet version distribution, provider, and known platform add-ons to `/api/v1/platform-facts:report`.
- Add VulnDB records/namespace conventions for Kubernetes platform packages in `constellation-vulndb`. Complete for producer/consumer contract: compatibility fixtures, bbolt scan validation, Constellation downstream scanner tests, and a source-agnostic `platform` advisory source now use `namespace_kind=generic`, `namespace_name=kubernetes|k3s|<addon>`, `package_name=kubernetes|k3s|kubelet|coredns|ingress-nginx|cert-manager|...`.
- Add platform scan job type. Complete for Constellation consumer path: platform facts upsert `scan_targets.type='platform'`, store `scan_evidence.evidence_type='package-inventory'`, and queue existing scanner workers through `ScanPackages`.
- Add platform UI panel on cluster dashboard and system health. Complete for cluster dashboard, cluster picker, and cluster health page; remaining depth is a dedicated platform vulnerability drilldown if platform findings become dense.

Definition of done:

- A k3s cluster shows a platform scan result for k3s/Kubernetes version.
- If no platform vulnerabilities match, the UI still shows the platform scan as completed with bundle provenance.
- Managed Kubernetes clusters show which control-plane facts are unavailable from the installed agent.

Validation:

```bash
kubectl version -o json
curl -s "$CONSTELLATION_API/api/v1/clusters/$CLUSTER_ID/platform-facts" | jq .
curl -s -X POST "$CONSTELLATION_API/api/v1/clusters/$CLUSTER_ID/platform-scan" | jq .
curl -s "$CONSTELLATION_API/api/v1/scan-jobs?target_type=platform" | jq .
curl -s "$CONSTELLATION_API/api/v1/findings?cluster_id=$CLUSTER_ID&q=target_type:platform" | jq .
```

### Registry and Repository Scan Flow

NeuVector has a separate registry scanning product surface:

1. Users configure registries and credentials.
2. Registry drivers enumerate repositories, tags, manifests, digests, and image metadata.
3. The scheduler decides whether a vulnerability scan, signature scan, or both are needed.
4. Scanner pods pull and inspect images with registry credentials, proxy settings, layer scanning, secret scanning, and sigstore roots of trust.
5. Results are stored as registry image summaries and full reports.
6. Repo/CI scan APIs can scan a single image or submit an external scan result into `_repo_scan`.
7. Admission control can then use those scan summaries.

Constellation current state:

- Registry CRUD, registry image storage, registry scan policy, registry walker, and scan jobs exist.
- Scanner workers can scan pullable images.
- Scan jobs use typed targets; repository package-evidence scans now have their own evidence-backed target path.
- Local-only image refs still need node-agent scan relay.

Constellation target:

- Keep registry scanning as a distinct area from running workload scans.
- Scan policies should include tag selection, exclusions, max age, digest drift, signature requirements, secret scanning, layer evidence, and bundle-change rescans.
- CI/repository package-evidence scans should produce reusable repository scan results and signed attestations that admission can use before deployment once server-side verification promotes them.
- Registry image pages should show repository, tags, digest, scan state, vulnerabilities, secrets, setuid/setgid files, signatures, SBOM, and impacted clusters/workloads.

Greenfield improvements over NeuVector:

- Use OCI artifact references for SBOMs and Constellation scan attestations.
- Normalize registry identities across Docker Hub, GHCR, ECR, GCR/Artifact Registry, ACR, Harbor, GitLab, Quay, JFrog, and private OCI registries.
- Show scan queue and stale coverage directly on registry pages.

Tasks:

- Add registry-specific scan target rows and target status rollups.
- Add repo/CI scan namespace and API distinct from registry scan. Evidence-backed repository scan API, CLI producer, inventory API, UI, attestation upload/storage, result linking, latest-attestation summaries, persisted org trust policies, trust-policy operations UI, server-side attestation verification, auto-verify, verify-pending workflows, and trusted admission reuse gates are implemented; remaining depth is verification history/export and live issuer validation.
- Add signature/sigstore verification storage and UI. First scanner-owned signature artifact, API download, image-row summary, and UI status are implemented.
- Add image secrets and setuid/setgid scan evidence into image reports. Redacted secret artifacts and scanner-owned file-risk artifacts are implemented with API downloads and UI counts/downloads.
- Add impacted-workloads reverse index by digest and image ref.
- Add canonical image result read APIs: image result list/detail, affected clusters/workloads, scan freshness, bundle provenance, and canonical finding detail by digest/platform/profile/bundle.

Definition of done:

- Adding a registry can discover images, schedule scans, show queue progress, and produce image findings with VulnDB provenance.
- A CI scan can be submitted before deployment and admission can reuse it.
- Registry images can be filtered by unscanned, stale, critical/high, unsigned, secret-bearing, and running-in-cluster.

Validation:

```bash
curl -s "$CONSTELLATION_API/api/v1/registries" | jq .
curl -s "$CONSTELLATION_API/api/v1/registries/$REGISTRY_ID/images" | jq .
curl -s "$CONSTELLATION_API/api/v1/scan-jobs?registry_id=$REGISTRY_ID" | jq .
```

### Admission Control Fed by Scan Results

NeuVector admission does not only evaluate Kubernetes manifest fields. It fetches image scan summaries and evaluates rules against:

- image scanned/not scanned state
- critical/high/medium CVE counts
- critical/high CVEs with fixes
- vulnerability age windows
- run-as-root from image metadata
- image environment variables and labels
- resource environment variables and labels
- image secrets and setuid/setgid counts
- image signature verifier data
- registry/repository/tag

Constellation target:

- Admission should consume the same scan result graph used by findings and image pages.
- Rules should be able to express:
  - deny unscanned images
  - deny stale scans
  - deny critical/high counts above threshold
  - deny fixable critical/high vulnerabilities
  - require approved signatures/verifiers
  - deny image secrets or setuid/setgid files
  - deny run-as-root unless exception applies
  - enforce namespace/workload/cluster scoped exceptions
- Admission should support monitor, warn, and enforce modes.

Greenfield improvements over NeuVector:

- Make every admission decision explainable with links to exact scan evidence.
- Support dry-run simulation against manifests and real stored image scan summaries.
- Avoid ambiguous "latest tag" decisions by resolving digest where possible.
- Integrate VulnDB bundle freshness into admission policy.

Tasks:

- Expand admission evidence lookup to use Constellation scan targets and image digest index. Implemented for canonical image scan result and finding lookup by ref/normalized ref/digest; remaining depth is scan-target lineage in the denial response.
- Add policy fields for scan freshness, canonical engine, bundle version, signature verifier, secrets count, setid count, run-as-root, and fixable CVE counts. Implemented for known-scan, stale-scan, VulnDB bundle provenance, canonical-engine vulnerability filtering, fixable CVE filtering, trusted signature scan evidence, verifier identity matching, secret count/severity, and file-risk count/severity/risk-type gates through canonical image scan results and result-scoped image artifacts; remaining depth is live denial/audit e2e with typed evidence details.
- Add admission decision audit entries with typed evidence details and internal pivots.
- Add UI policy builder controls for image-scanning gates.

Definition of done:

- A deployment using an unscanned image can be denied in enforce mode and allowed in monitor mode with audit evidence.
- A signed image can pass a signature policy and an unsigned image can fail with verifier context.
- An exception can be scoped to cluster, namespace, workload, image, CVE, and expiration.

Validation:

```bash
kubectl apply --server-side --dry-run=server -f ./deploy/e2e/admission/unscanned-image.yaml
curl -s "$CONSTELLATION_API/api/v1/audit?event=admission.deny" | jq .
```

### Compliance and Bench Flow

NeuVector compliance/bench coverage is separate from CVE scan results:

- Docker host CIS benchmark.
- Docker container CIS benchmark.
- Kubernetes master benchmark.
- Kubernetes worker benchmark.
- K3s/RKE2/GKE/EKS/AKS/OpenShift profile selection.
- Custom host checks.
- Custom container checks.
- Container image secret checks.
- Container setuid/setgid checks.
- Compliance profiles filter and present the evidence.

Constellation current state:

- Compliance framework APIs, checks, schedules, evidence surfaces, and host CIS upload path exist.
- Runtime-agent has host CIS reporting.
- Image secret scanning and setuid/setgid file-risk scanning are first-class scanner artifacts, and workload compliance evidence now consumes those artifacts as control evidence for image-secret and image-file-risk checks.

Constellation target:

- Treat compliance as a first-class posture surface, not as vulnerability findings.
- Support node, workload, Kubernetes, image, registry, cloud, and custom control evidence.
- Version every compliance profile and every check.
- Support exemptions with owner, reason, expiration, and evidence.
- Link compliance failures to runtime/scan findings where useful without conflating them.

Greenfield improvements over NeuVector:

- Make profile versioning and evidence schema explicit.
- Keep compliance results queryable through the same cluster/node/workload graph.
- Render concise remediation and exact evidence, not only script output.

Tasks:

- Add Kubernetes CIS profile runner or kube-bench integration for k3s/RKE2/standard clusters.
- Add image compliance checks for secrets and setuid/setgid evidence from scanner/Syft/custom walkers. First scanner-artifact-backed secret and file-risk controls are implemented through the shared compliance evidence collector.
- Add compliance profile import/export.
- Add custom check runtime with strict resource and timeout controls.
- Add UI for node/workload/platform compliance drilldown.

Definition of done:

- Local k3s shows Kubernetes CIS profile result, host CIS result, and node/workload evidence.
- A compliance exemption affects compliance posture but does not suppress vulnerability findings.
- Reports can be exported with profile version, cluster ID, node/workload IDs, evidence hashes, and run metadata.

Validation:

```bash
curl -s "$CONSTELLATION_API/api/v1/compliance/summary?cluster_id=$CLUSTER_ID" | jq .
curl -s "$CONSTELLATION_API/api/v1/compliance/nodes?cluster_id=$CLUSTER_ID" | jq .
curl -s "$CONSTELLATION_API/api/v1/compliance/kubernetes?cluster_id=$CLUSTER_ID" | jq .
```

### Runtime Security Surface

NeuVector's full product stack also includes runtime protection beyond scanning:

- process profile learning and enforcement
- file monitor/access profiles
- network learning and enforcement
- L7/DPI threat detection
- DLP and WAF-style inspection
- incident/threat/violation logging
- policy modes such as discover/monitor/protect

Constellation current state:

- Runtime-agent, eBPF, vendored NeuVector data plane supervisor, network flows, runtime threats, DLP/WAF/signature APIs, runtime policies, baselines, and PCAP requests exist.
- The runtime side needs the same cluster/node/workload identity model as scan findings.

Constellation target:

- Keep runtime separate from vulnerability scanning but connected through the same asset graph.
- Use modes: discover, monitor, enforce.
- Show runtime posture next to scan posture on deployment, node, and cluster pages.
- Keep privileged runtime-agent as the only host-privileged workload.

Definition of done:

- A workload detail page shows image vulnerabilities, runtime policy mode and actions, observed processes, network flows, threats, DLP/WAF hits, active quarantine state/actions, and compliance checks.
- Runtime-agent loss degrades runtime coverage visibly but does not hide vulnerability scan evidence.
- Enforcement actions are auditable and reversible.

### Scanner Scaling and Updater Separation

NeuVector uses dedicated scanner pods and a scanner acquisition/credit system:

- The controller chooses an available scanner.
- Scanner capacity is limited by per-scanner credits.
- Queue depth drives autoscaling.
- Scanner DB/updater behavior is separate from controller/API serving.

Constellation current state:

- `constellation-scanner` is already a separate worker binary and Helm deployment.
- It polls scan jobs, runs Syft -> VulnDB plus optional Trivy/Grype, and reports results.
- VulnDB importer is a separate component.
- Scan jobs need target generalization and better scanner capacity controls.

Constellation target:

- Maintain separate API, scanner, runtime-agent, discoverer, operator, admission, registry-walker, and VulnDB importer roles.
- Add scanner leases/credits so multiple scanner pods can safely claim many scan target types.
- Autoscale scanner pods from queue depth, target type mix, and per-target resource profiles.
- Keep VulnDB updates in the importer/updater role and make scanners reopen stores safely after bundle changes.

Greenfield improvements over NeuVector:

- Use Kubernetes-native leases or database leases instead of implicit in-memory scan ownership.
- Make scanner pod capacity transparent in UI and metrics.
- Add target-type resource profiles: image pulls, local SBOM match, host inventory match, platform package match, signature verification.

Tasks:

- Add `scan_leases` or extend `scan_jobs` with lease owner, lease deadline, scanner ID, and heartbeat. Completed for the database-backed path: `scan_jobs` now carries lease deadlines, retry attempt accounting, next-attempt scheduling, and scanner instance ownership; scanner workers send pod instance IDs and renew active leases.
- Add scanner capacity config per target type. Completed for the Helm/scanner/claim path: `scanner.targetCapacity` and `--target-capacity` configure per-target credits, scanner workers only claim target types with available local credits, and connector coverage shows configured and active per-target capacity from heartbeat metadata.
- Add scanner autoscaling values and metrics. Partially completed: Helm renders a scanner metrics Service with Prometheus scrape annotations and an optional `autoscaling/v2` HPA; queue-depth-driven external metrics are still operator-supplied through `scanner.autoscaling.externalMetrics` until first-class queue gauges are exported.
- Add stale lease recovery and idempotent completion semantics. Completed for current claim/complete/fail/renew paths: expired running jobs are reclaimable, completion/failure require current worker ownership, retryable failures requeue with backoff, and manual retry resets exhausted terminal jobs.

Definition of done:

- Killing a scanner pod while it owns a scan causes the job to return to pending after lease expiry.
- Increasing scanner replicas increases scan throughput without duplicate findings.
- Scanner UI shows active scanners, busy/idle capacity, queue depth, and oldest pending job.

Validation:

```bash
kubectl -n constellation-system scale deploy/constellation-scanner --replicas=3
kubectl -n constellation-system delete pod -l app.kubernetes.io/component=scanner --field-selector=status.phase=Running
go test ./internal/handler -run 'Test(HeartbeatsIngestPersistsMetadata|ConnectorCoverage_OverviewUsesDatabaseState|ScanJobs_ClaimFiltersTargetTypes)'
go test ./cmd/constellation-scanner -run 'Test(ParseTargetCapacities|ReadyzRequiresVulnDB)'
helm template constellation deploy/charts/constellation --set scanner.autoscaling.enabled=true --set-string scanner.targetCapacity='image=2\,host=8' --set scanner.readiness.requireVulnDB=true
curl -s "$CONSTELLATION_API/api/v1/scan-jobs?status=pending" | jq .
curl -s "$CONSTELLATION_API/api/v1/connector-coverage" | jq '.scanner_pools'
curl -s "$CONSTELLATION_API/api/v1/system-health" | jq '.heartbeats[] | select(.component=="scanner")'
```

## Constellation Greenfield Parity Target

The target is not "look a bit like NeuVector". The target is NeuVector-class coverage with cleaner boundaries, stronger provenance, and a better UI.

### Full NeuVector Area Coverage Matrix

Constellation should track every NeuVector product area as a parity track. Some tracks already exist in Constellation, but the greenfield bar is not "route exists"; the bar is product-grade data collection, policy workflow, UI, tests, and operator validation.

| NeuVector area | NeuVector surface | Constellation target |
|---|---|---|
| Authentication | login, logout, token refresh, federated auth, token auth servers | Local auth, OIDC/JWKS/SAML-compatible enterprise identity, session refresh, audit, break-glass admin, service-token separation. |
| Users and roles | users, custom user roles, role permission options, server/group role mapping | Single-org RBAC with global admin, security admin, cluster admin, analyst, auditor, custom roles, scoped permissions, API/service tokens. |
| Password and API keys | password profile, password change, API key CRUD, self API key | Password policy for local auth, PAT/service-token lifecycle, token prefixing, rotation, expiry, last-used, scope. |
| System configuration | system summary, config, alerts, score metrics, webhooks, usage | System health, config profiles, webhooks, alert routing, posture score model, tenant-wide settings, configuration drift tracking. |
| Domains/namespaces | domain list/config and domain entries | Kubernetes namespace/domain model with RBAC scoping, namespace risk rollups, namespace policy defaults. |
| Controllers | controller list/show/config/stats/counter/profiling | API/operator component inventory, health, version drift, metrics, profiling/debug gates for admins only. |
| Enforcers/agents | enforcer list/show/config/stats/counter/probe summary/process/container maps | Runtime-agent DaemonSet inventory, node health, node-local container inventory, eBPF/DP status, version drift, debug gated endpoints. |
| Hosts/nodes | host list/show/compliance/process profile | Node list/detail with OS, kernel, kubelet, runtime, packages, vulnerabilities, CIS, runtime-agent, local containers, runtime events. |
| Workloads | workload list/show/stats/config/process/history/profiles/compliance | Deployment/pod/workload views with process history, package/image scan, runtime policy, network, compliance, findings, actions. |
| Conversations/network map | conversation endpoints, conversations, sessions, session summary | Network graph with flows, services, peers, sessions, L4/L7 metadata, policy recommendations, PCAP pivot. |
| Groups | group CRUD/stats, learned groups, fed/local scope | Dynamic groups for workloads/nodes/namespaces/images, label selectors, learned groups, policy mode inheritance. |
| Services | service create/list/show/config/profile/network | Service/application abstraction over workloads for policy grouping, risk, and rollout actions. |
| Network policy | policy rules list/show/action/config/delete/promote | Discover/monitor/enforce network policy lifecycle, generated policies, review/apply/rollback, CNI-specific output, federation-ready promotion later. |
| Process profile | process profile list/show/config, process rules | Process baseline learning, process allow/deny profiles, rule explainability, runtime enforcement and exceptions. |
| File monitor profile | file monitor list/show/config/file evidence | File access/modify baselines, sensitive path monitoring, workload/node file policies, incident linkage. |
| DLP | DLP sensors, groups, rules, import/export | DLP detector library, runtime policy binding, group scoping, audit events, payload-safe evidence, import/export. |
| WAF | WAF sensors, groups, rules, import/export | HTTP inspection rules, managed rule packs, workload binding, event triage, false-positive workflow, import/export. |
| Response rules | response rules list/show/workload/action/config/delete/promote/options | Event-driven response workflows for admission, runtime, scan, compliance, quarantine, notifications, webhooks, ticketing. |
| Admission | admission state/options/stats/rules/promote/assess/debug | Admission profiles, monitor/enforce modes, scan-evidence gates, Pod Security gates, signature gates, dry-run simulator, decision audit. |
| Pod Security | baseline/restricted admission checks | First-class Kubernetes Pod Security controls with clear remediation, exceptions, and namespace/workload scoping. |
| Scanner management | scanner list/config/status/cache stats/cache data | Scanner worker health, cache/store status, queue depth, leases, capacity, autoscaling, bundle freshness, target-type throughput. |
| Workload scan | scan running workload/container | Runtime-agent local evidence path plus scalable scanner worker matching, local-only image support. |
| Host scan | scan host/node | Host package inventory plus VulnDB host matching, node scan status and stale detection. |
| Image scan | image summary/report from running workloads | Image digest inventory, SBOM/packages, vulnerabilities, impacted workloads, source/freshness/provenance. |
| Platform scan | Kubernetes/OpenShift platform scan | Kubernetes/k3s/RKE2/OpenShift/EKS/GKE/AKS platform component version posture and vulnerabilities. |
| Registry scan | registry CRUD/test/start/stop/images/report/layers | Registry connectors, image discovery, scan policies, secrets/signatures/layers, stale coverage, pull credentials. |
| Repository/CI scan | scan repository, submit scan result | Evidence-backed repository package scan API/CLI, inventory API/UI, signed attestation storage/reporting, persisted trust policies, trust-policy operations UI, server-side verification, auto-verify, pending verification, immutable verification history/export, retention lifecycle, and trusted admission reuse gates are implemented; next depth is live issuer validation and richer CI provenance cross-checking. |
| Sigstore | roots of trust and verifier CRUD | Cosign/sigstore trust roots, verifier policies, signature evidence on image/admission pages. |
| Vulnerability profiles | vulnerability profile CRUD entries | Vulnerability policy profiles: severity, fixability, age, KEV/EPSS/CVSS, exceptions, bundle requirements. |
| Vulnerability assets | asset vulnerability views | Asset/vulnerability graph: CVE -> packages -> images -> workloads -> nodes -> clusters. |
| Compliance | asset compliance, host/workload compliance, profiles, available filters | Versioned compliance frameworks, node/workload/platform/image/cloud evidence, exemptions, schedules, reports. |
| Benchmarks | Docker bench, Kubernetes bench, custom checks | Kubernetes CIS, host CIS, container/image checks, custom checks with sandboxed execution and resource limits. |
| Logs and incidents | activity, event, security, incident, threat, violation, audit | Unified audit/security event store with filters, correlation, retention, archive, typed evidence pivots, export. |
| Packet capture/sniffer | sniffer CRUD and pcap download | Runtime PCAP request/claim/upload/download flow, RBAC controls, size limits, chain of custody. |
| Debug/support | debug endpoints, profiling, support package, system stats | Admin-gated diagnostics, support bundle generation, redaction, signed support artifacts, no unauthenticated debug exposure. |
| Federation | master/joint roles, join/leave, deploy fed rules, forward requests, scan data sync | Multi-cluster management roadmap. For current single-org target: design data model so later federation does not require rewriting policy/scan scope. |
| Import/export | config, groups, admission, response, DLP, WAF, compliance/vulnerability profiles | Portable YAML/JSON bundles for every policy/profile class, diff/preview/import validation, rollback. |
| Remote repository | remote export repository config | External backup/export destinations for config/report/audit artifacts. |
| Cloud/serverless | AWS Lambda scan model, cloud resources, IBM Security Advisor/CSP hooks | Serverless package-evidence scan targets, an AWS Lambda ZIP/layer package producer, execution-role permission analysis, cloud-config finding promotion, and inventory/detail UI are implemented; remaining work is live AWS validation, cloud posture graph joins, and integration webhooks. |
| Licensing/EULA/telemetry | EULA, license, telemetry/system usage | Product settings appropriate for Constellation deployments: license state if needed, telemetry opt-in, EULA if required. |
| CRD/Kubernetes resources | admission CRDs, security rule CRDs, webhook resource management | Kubernetes-native CRDs for profiles/policies where useful, Helm/operator reconciliation, drift detection, webhook health. |

Parity acceptance rule:

- Every row must be marked `implemented`, `intentionally different`, or `future/deferred` before enterprise release.
- `Intentionally different` must include a better Constellation design, not a missing feature renamed as strategy.
- `Future/deferred` must have an owner, rationale, and compatibility placeholder so UI/API do not pretend it works.

Cross-cutting definition of done for every area:

- API supports list/detail/create/update/delete where the workflow needs it.
- UI has a first-class route or panel with empty, loading, error, and populated states.
- RBAC permissions and audit events cover read/write/admin actions.
- Import/export exists for policy/profile areas.
- E2E or integration validation exists for the local k3s install where the area is cluster-dependent.
- Metrics and health signals exist for components that run in-cluster.
- Documentation includes operating model, defaults, and failure modes.

### Release-Blocking NeuVector Coverage Gate

Every NeuVector route family and product workflow must be mapped to a Constellation parity track. This is a release gate, not a comparison note. Enterprise release cannot happen while any NeuVector area is unmapped, silently ignored, or represented only by placeholder UI.

Allowed disposition values:

- `implemented`: Constellation has product-grade API, UI, storage, RBAC, audit, validation, and docs for the area.
- `partial`: useful capability exists, but at least one required layer is missing.
- `planned`: the design is accepted and the backlog is explicit.
- `intentionally different`: Constellation uses a better design, and the plan says how users accomplish the equivalent outcome.
- `deferred`: the area is not in the current release, but data-model/API placeholders prevent a later rewrite.

Required evidence for each disposition:

- Source mapping to NeuVector route/API, controller, agent, scanner, or CRD surface.
- Constellation user workflow and target personas.
- Data model and retention policy.
- API contract and authz verbs.
- UI route or panel.
- Import/export or migration behavior when the area is policy/profile/config state.
- Local k3s validation path where the area depends on Kubernetes.
- Negative tests for unauthorized access, stale data, and unavailable collectors.

### NeuVector Route Family Coverage Ledger

This ledger is the "no area left behind" checklist. It is intentionally broader than vulnerability scanning because NeuVector's value is the whole platform: asset discovery, scanning, runtime, policy, admission, compliance, operations, and federation.

| NeuVector route family or source surface | Product area | Constellation disposition now | Required next deliverable |
|---|---|---|---|
| `/v1/auth`, `/v1/fed_auth`, `/v1/token_auth_server`, `/v1/server`, `/v1/password_profile` | Authentication, external identity, password policy | Partial | Finish enterprise identity matrix: local admin, OIDC/JWKS, SAML-compatible mapping, password policy, session refresh, IdP group-to-role mapping, login audit, lockout, break-glass path. |
| `/v1/user`, `/v1/user_role`, `/v1/user_role_permission/options`, `/v1/api_key`, `/v1/selfapikey` | Users, custom roles, API keys | Partial | Complete single-org RBAC with custom roles, per-cluster/namespace scopes, API token rotation/expiry/last-used, service-token separation, and access-control UI parity. |
| `/v1/eula`, `/v1/system/usage`, `/v1/meter` | Product settings, usage, telemetry, license/EULA | Planned | Decide Constellation license/telemetry stance, add explicit opt-in usage collection, show component usage, and avoid hidden outbound telemetry. |
| `/v1/file/config`, `/v1/file/fed_config`, `/v1/file/group`, `/v1/file/admission`, `/v1/file/response/rule`, `/v1/file/dlp`, `/v1/file/waf`, `/v1/file/compliance/profile`, `/v1/file/vulnerability/profile` | Import/export | Partial | Admission and workload file-profile typed bundles now have validation, dry-run/preview, audit, and NeuVector migration coverage. Add the same bundle discipline for response, DLP, WAF, compliance, vulnerability profiles, groups, and global config. |
| `/v1/system/summary`, `/v1/system/config`, `/v2/system/config`, `/v1/system/alerts`, `/v1/system/score/metrics`, `/v1/system/config/webhook`, `/v1/system/request` | System health, posture score, webhooks, requests | Partial | Unify health/score/alert routing in the UI, add webhook receivers and test-fire workflows, document posture scoring inputs, and make config drift visible. |
| `/v1/domain` | Domains/namespaces | Partial | Treat namespaces as first-class security domains with risk, policy mode, RBAC scope, scan coverage, compliance, and default profile inheritance. |
| `/v1/controller`, `/v1/enforcer`, enforcer probe endpoints | Control plane and agent inventory | Partial | Component inventory API/UI now covers API, scanner, importer, operator, discoverer, admission, registry walker, runtime-agent, and future sidecars with version drift, stale/degraded/missing status, restart counts, sanitized public metadata, admin-gated diagnostics counters/checks/config, runtime-agent DP/eBPF/probe heartbeat telemetry, and node probe freshness/counts for host facts, containers, processes, packages, and CIS. Default-installed scanner/runtime-agent/operator/admission/network-policy-applier/k8s-compliance-collector/vulndb-importer roles now have Helm cluster-name/token/API wiring where cluster-scoped, while org-scoped API and audit-archiver report without cluster IDs. Remaining work is live component actions, signed support bundles, profiling controls, component log snapshots, and richer per-node map drilldowns. |
| `/v1/host`, `/v1/host/:id/compliance`, `/v1/bench/host/:id/*`, agent `RunDockerBench`, `RunKubernetesBench`, host `ScanObjectType_HOST` | Node/host scanning and CIS | Partial | Finish node list/detail UI, host package inventory, host CVEs, host CIS, kubelet/runtime facts, runtime-agent health, stale scan state, and forced rescan. |
| `/v1/workload`, `/v2/workload`, `/v1/workload/:id/process`, `/process_history`, `/process_profile`, `/file_profile`, workload compliance, container `ScanObjectType_CONTAINER` | Workload runtime and scan | Partial | Running workload/local-image scan relay, workload package evidence, runtime policy state/actions, persisted process-baseline actions, persisted file-profile actions/rules/exceptions, file monitor agent distribution/classification/watched-file inventory/fanotify deny path, active quarantine actions, compliance, and workload aggregate are live. Remaining depth is process history, file-enforcement live validation, and live cluster validation. |
| `/v1/conversation_endpoint`, `/v1/conversation`, `/v1/session`, `/v1/session/summary` | Network map, conversations, sessions | Partial | Complete flow/session graph with service/workload/node pivots, time windows, L4/L7 metadata, generated policy recommendations, session search, and PCAP pivot. |
| `/v1/group`, `/v1/service` | Groups and services | Partial | Finish dynamic groups and service abstraction: selectors, learned groups, label drift, policy mode inheritance, risk rollups, import/export, and migration from NeuVector groups. |
| `/v1/policy/rule`, `/v1/policy/rules/promote` | Network policy lifecycle | Partial | Complete live discover/monitor/protect e2e under supported CNI, violation feedback loop, Cilium L7 tightening, rollback evidence, import/export, and policy simulation. |
| `/v1/process_profile`, `/v1/process_rules`, host/workload process profile endpoints | Process controls | Partial | Persisted workload process-baseline learn/monitor/enforce lifecycle and deployment-detail promote/rollback controls are live. Remaining depth is diff approval, exceptions, command-line matching, host process policy, and incidents. |
| `/v1/file_monitor`, `/v1/file_monitor_file`, workload file profile endpoints | File monitor controls | Partial | Workload file-profile state, transitions, sensitive-path evidence, editable path filters, recursive matching, application constraints, `monitor_change`/`block_access` behaviors, deployment detail promote/rollback/rule/exception/watch/import-export controls, agent rule bundle distribution, server-side rule-hit classification, live watched-file inventory, fanotify deny path, typed import/export bundles, and NeuVector migration preview now read/enforce real cluster/runtime evidence. Next: privileged live-cluster enforcement validation, richer file-diff approval, and host-level file policy. |
| `/v1/dlp/sensor`, `/v1/dlp/group`, `/v1/dlp/rule`, DP DLP build controls | DLP | Partial | Finish DLP sensors/groups/rules with managed detector packs, runtime binding, safe evidence capture, import/export, policy simulation, event triage, and e2e packet/payload validation. |
| `/v1/waf/sensor`, `/v1/waf/group`, `/v1/waf/rule` | WAF | Partial | Finish WAF sensors/groups/rules with managed HTTP rule packs, workload binding, false-positive workflow, import/export, and runtime validation through HTTP fixtures. |
| `/v1/response/rule`, `/v1/response/options`, response rule import/export | Response rules | Partial | Make response rules event-driven across scan/admission/runtime/compliance: quarantine, notify, webhook, ticket, suppress, and rollback with dry-run and audit. |
| `/v1/admission/state`, `/options`, `/stats`, `/rules`, `/assess`, admission debug/test | Admission control | Partial | Scan-evidence and signature gates now cover known/fresh scan, VulnDB bundle provenance, canonical engine, fixability, trusted signature artifacts, verifier identity, secrets, file-risk evidence, stored-scan simulator evaluation, typed simulator evidence details, and first builder controls. Remaining work is per-namespace defaults, decision audit UI, and fail-open/fail-closed live e2e. |
| `/v1/scan/scanner`, `/config`, `/status`, `/cache_stat`, `/cache_data`, scanner RPCs | Scanner management | Partial | Add scanner leases, capacity, autoscaling, cache metrics, worker health UI, stale job recovery, target-type queues, and bundle freshness gates. |
| `/v1/scan/workload`, `/v1/scan/image`, `/v1/scan/host`, `/v1/scan/platform`, scanner RPC object types | Workload, image, host, platform scan | Partial | Generalize typed scan targets and scan results so host, platform, running workload, registry image, repo image, and local runtime image all share provenance and dedupe semantics. |
| `/v1/scan/registry`, `/v2/scan/registry`, registry drivers for Docker/JFrog/OpenShift/ECR/DockerHub/GCR/GitLab/IBM/Harbor/GitHub | Registry scanning | Partial | Add live-registry e2e matrix, cloud identity modes, digest-only dedupe, layer view, stale coverage, promotion/admission reuse, and connector health. |
| `/v1/scan/repository`, `/v1/scan/result/repository`, controller scan adapter | Repository/CI scanning | Partial | Evidence-backed repository package scan API/CLI, target/evidence storage, scanner claim, VulnDB matching, repository inventory API/UI, attestation upload/storage/reporting, persisted trust policies, trust-policy operations UI, server-side verification, auto-verify, pending verification, immutable verification history/export, retention lifecycle, hash-chained audit coverage, and trusted admission reuse gates are implemented. Next: live issuer validation and richer CI provenance cross-checking. |
| `/v1/scan/sigstore/root_of_trust`, `/verifier` | Signature verification | Partial | Repository/CI attestation policies now support explicit keyless and public-key cosign verification modes, scanner image-signature trust no longer defaults empty keyless policy to trusted, and Helm can mount a public-key verifier Secret. Next: first-class trust-root inventory/import-export, per-registry trust binding, live issuer-material fixtures, and image-page policy linkage. |
| `/v1/vulnerability/profile`, `/v1/scan/asset`, `/v1/vulasset`, `/v1/assetvul` | Vulnerability profiles and asset graph | Partial | Vulnerability profiles now tag canonical scan finding detail with matching active profile decisions. Complete profile-driven filtering/escalation in findings/UI/admission, CVE/package/image/workload/node graph breadth, profiles by fixability/age/KEV/EPSS/source, exceptions, and risk rollups. |
| `/v1/compliance/asset`, `/v1/compliance/profile`, `/v1/custom_check`, `/v1/list/compliance`, bench reports | Compliance and custom checks | Partial | Finish profile versioning, custom check sandboxing, benchmark catalog, live node/workload/platform evidence, report signing, and managed-cluster coverage matrix. |
| `/v1/log/activity`, `/event`, `/security`, `/incident`, `/threat`, `/violation`, `/audit` | Logs, incidents, threats, audit | Partial | Unify audit/security/runtime/admission/compliance events, add retention/archive/export, incident correlation, rule links, evidence chains, and searchable UI. |
| `/v1/sniffer`, `/v1/sniffer/:id/pcap`, agent `SnifferCmd`/`GetSnifferPcap` | Packet capture and forensics | Planned | Build RBAC-gated PCAP workflow: request, node-agent claim, capture constraints, upload, signed chain-of-custody metadata, download, expiry, and audit. |
| `/v1/debug/*`, controller/enforcer profiling/counter/log endpoints, `/v1/csp/file/support` | Debug, profiling, support bundle | Partial | Admin-gated heartbeat-derived component diagnostics are live without raw metadata or unauthenticated debug exposure. Remaining work is redacted support bundle generation, profiling controls, component logs snapshot, signed artifacts, retention policy, and audited download/expiry. |
| `/v1/fed/*`, internal fed join/poll/scan data, `RESTFedRulesSettings` | Federation and multi-cluster rule sync | Intentionally different for initial release | Keep single-org product model now, but design cluster scope, policy scope, scan provenance, and import/export so later federation or hub/spoke management does not require schema rewrite. |
| `/v1/partner/ibm_sa_*`, CSP support internals | Partner/CSP integrations | Deferred | Replace vendor-specific IBM SA hooks with generic integration/export framework, plus optional CSPM connector events and support package upload later. |
| `ScanAwsLambda`, `ScanObjectType_SERVERLESS`, cloud connector code | Cloud and serverless scanning | Partial | Serverless target/evidence/job execution is implemented through `/api/v1/serverless-packages:report`, and `constellationctl serverless aws-lambda sync` discovers Lambda ZIP functions/layers, analyzes execution-role permission posture, and posts package evidence plus first-class cloud-config findings; inventory/detail APIs and UI are implemented. Remaining work is live AWS validation and cloud posture graph joins. |
| NeuVector CRDs and Kubernetes webhook/resource management | Kubernetes-native policy resources | Partial | Keep Helm/operator reconciliation, add CRDs where they improve GitOps workflows, detect drift, and make admission/network/runtime/compliance profiles declarative. |

### Full-Parity Milestone Sequence

Milestone A: Local k3s whole-stack slice.

- Local cluster auto-registers and defaults to enabled.
- Runtime-agent supplies node facts, host packages, running containers, local image evidence, processes, file events, and network/runtime events.
- Scanner workers consume typed scan jobs for images, workloads, hosts, platform, serverless, and repository evidence.
- Dashboard, node, workload, image, finding, scan-job, and VulnDB pages show real local data.

Milestone B: Scanner and vulnerability parity.

- Host, running workload, local image, registry image, repository package evidence, repo/CI image, and platform scans share one target model.
- Results include SBOM/packages, vulnerabilities, secrets, setuid/setgid, envs, labels, layers, signatures, provenance, and stale/fresh status.
- VulnDB bundle provenance is mandatory on every vulnerability result.
- Scanner workers are separately scalable and lease-protected.

Milestone C: Runtime, network, and policy parity.

- Runtime-agent observe mode collects process, file, network, DLP/WAF, and threat events.
- Network policy, process profile, file monitor, DLP, WAF, and response rules support discover, monitor, enforce, exception, rollback, import/export, and audit.
- UI shows policy recommendations, enforcement state, violations, and evidence.

Milestone D: Admission, compliance, and supply-chain parity.

- Admission consumes scan, signature, compliance, and runtime evidence.
- Compliance covers node, workload, Kubernetes/platform, image, and cloud evidence.
- Registry, repo/CI, sigstore, vulnerability profiles, and exceptions are connected to admission and response workflows.
- Reports are scheduled, signed, exportable, and auditable.

Milestone E: Enterprise operations parity.

- Identity, RBAC, custom roles, API keys, audit, import/export, backup, webhooks, support bundles, diagnostics, and system health are complete.
- Namespace/domain scoping and single-org global admin workflows are clean.
- Federation is either implemented or explicitly shipped as a compatible future hub/spoke design.

Milestone F: Cloud, serverless, and partner extension.

- Cloud/serverless scan targets, CSPM assets, generic partner/export integrations, and optional external support upload are implemented after Kubernetes parity is strong.

### Constellation Improvements Over NeuVector

These are explicit product principles for doing NeuVector parity better:

- Single asset graph: cluster, node, namespace, workload, image, package, CVE, policy, runtime event, and compliance evidence are linked instead of split across isolated reports.
- Strong provenance: every vulnerability result carries scanner engine, canonical/evidence role, VulnDB bundle version, payload hash, record count, source target, and inventory hash.
- Local-image correctness: running workloads can be scanned from node-local evidence without pushing local images to a registry.
- Cleaner separation: API, operator, scanner, runtime-agent, discoverer, registry-walker, admission, and VulnDB importer remain distinct roles.
- Better UI: cluster-first navigation, node/workload/image drilldowns, explicit coverage gaps, stale scan badges, explainable admission decisions, and typed evidence pivots.
- Safer policy modes: discover, monitor, enforce, and rollback are explicit for runtime, network, admission, and compliance workflows.
- Better updater model: VulnDB generation remains in `constellation-vulndb`; Constellation consumes signed bundles/stores through importer/update workflows.
- Kubernetes-native deployment: Helm/operator defaults should be secure, observable, and reproducible in k3s first, then EKS/GKE/AKS/OpenShift.

### Product Surfaces Required for Parity

Cluster:

- Cluster dashboard with findings, platform vulnerabilities, compliance, runtime coverage, scanner health, agent health, admission mode, registry coverage, and stale scan coverage.
- Cluster components: API, scanner, admission, operator, discoverer, registry-walker, runtime-agent, importer, with sanitized inventory plus admin diagnostics/counters, runtime-agent DP/eBPF/probe telemetry, and node probe freshness/counts.
- Kubernetes distribution and version posture.

Nodes:

- Node list and node detail.
- Host packages, host vulnerabilities, host CIS, kubelet/runtime details, runtime-agent heartbeat, node-local containers, runtime events, PCAP controls.

Workloads:

- Deployment/workload list and detail. Done for the first aggregate detail screen.
- Running image, digest, image scan result, workload scan result, package inventory, process baseline, file profile, runtime policy, network flows, runtime events, and compliance evidence. Done for the first aggregate detail screen.
- Remaining: file-enforcement live validation, live generated-bundle k3s validation, and import/export hardening.

Images:

- Image inventory by digest/ref.
- Registry source, local source, CI/repository source.
- Vulnerabilities, packages, SBOM, secrets, setuid/setgid, signatures, layers, impacted workloads/clusters, scan freshness, VulnDB bundle provenance.

Registries:

- Registry CRUD, credential test, image discovery, tag/digest policy, schedule, scan queue, scan reports, stale scans, connector health.

Platform:

- Kubernetes/OpenShift/k3s/RKE2/EKS/GKE/AKS platform package scan.
- Control-plane and add-on component version posture.

Admission:

- Policy profiles and rule builder.
- Dry-run simulator.
- Enforce/monitor modes.
- Decision audit with typed scan evidence details and internal pivots.

Compliance:

- CIS and custom profiles.
- Node/workload/platform/image checks.
- Exemptions, evidence, reports.

Runtime:

- Discover/monitor/enforce lifecycle.
- Network/DPI/DLP/WAF/process/file telemetry.
- Runtime policies, baselines, incidents, response actions.

VulnDB:

- Separate producer repository.
- Signed deterministic bundles.
- Installer/updater/importer role.
- Store status, freshness, bundle metadata, rollback.
- Canonical matcher for host/image/platform package queries.

### Near-Term Implementation Order

1. Generalize scan jobs to typed scan targets.
2. Add runtime-agent local workload scan relay for node-local images and running containers. First package-evidence slices are complete for workload targets and runtime-agent-sourced image targets, and canonical image results now persist package inventory, SPDX/CycloneDX artifacts, redacted secret-scan artifacts, signature-scan artifacts, layer metadata artifacts, and file-risk artifacts; remaining depth is live k3s validation and richer local image report artifacts.
3. Add node inventory and node detail UI backed by host packages, host CVEs, host CIS, and runtime-agent health.
4. Add platform scan target and cluster platform UI.
5. Expand image report model with secrets, setuid/setgid, signatures, SBOM, layers, source type, and impacted workloads. Source type, impacted workloads, package inventory, SPDX, CycloneDX, redacted secret-scan reports, signature-scan reports, layer metadata reports, file-risk reports, first inline image artifact drilldowns, and compliance joins are implemented for canonical image results; remaining depth is richer per-layer/package provenance.
6. Connect admission rules to scan-result evidence and bundle freshness. Implemented for vulnerability, known-scan, stale-scan, VulnDB bundle, canonical-engine, fixable vulnerability, trusted signature artifact, verifier identity, secret artifact, file-risk artifact gates, stored-scan dry-run simulation, typed nested `evidence_details`, and first AdmissionRule builder controls; remaining depth is live cluster e2e.
7. Harden scanner leases, scanner capacity, and autoscaling.
8. Add Kubernetes CIS profile runner and image compliance evidence.
9. Polish UI around the asset graph: cluster -> node -> workload -> image -> finding -> evidence.

### First Milestone: Local k3s Whole-Stack Parity Slice

This is the next concrete milestone for the deployed `constellation.dev.alphabravo.io` cluster.

Scope:

- The installed local k3s cluster is auto-registered and enabled by default.
- The dashboard shows local cluster data by default.
- Pullable public images scan through registry/image path.
- Local-only `constellation/*:dev` images have a runtime-agent package evidence scan path; live validation must prove the deployed k3s scanner consumes that evidence end to end.
- The k3s node shows host package inventory, host vulnerabilities, host CIS, and runtime-agent health.
- The cluster shows Kubernetes/k3s platform scan status.
- Findings are cluster-scoped and target-typed.
- VulnDB bundle provenance is visible on scan jobs, findings, node scans, and platform scans.

Definition of done:

- No "empty dashboard" for a healthy local install.
- No failed scan solely because an image exists only in local node containerd.
- Cluster dashboard counts match API and direct database queries.
- Every severe finding links to an image, workload, node, or platform target.
- Every target shows last scanned time, scanner/source, bundle version, payload hash, and stale/fresh state.

Validation:

```bash
export CLUSTER_ID=2a46e2a1-9485-4bd6-a622-b1fcd6ee4130

curl -s "$CONSTELLATION_API/api/v1/dashboard/summary?cluster_id=$CLUSTER_ID" | jq .
curl -s "$CONSTELLATION_API/api/v1/clusters/$CLUSTER_ID/nodes" | jq .
curl -s "$CONSTELLATION_API/api/v1/clusters/$CLUSTER_ID/images" | jq .
curl -s "$CONSTELLATION_API/api/v1/clusters/$CLUSTER_ID/platform-facts" | jq .
curl -s "$CONSTELLATION_API/api/v1/scan-jobs?cluster_id=$CLUSTER_ID" | jq .

kubectl -n constellation-system get deploy,ds,pods
kubectl -n constellation-system logs deploy/constellation-discoverer --tail=200
kubectl -n constellation-system logs deploy/constellation-scanner --tail=200
kubectl -n constellation-system logs ds/constellation-runtime-agent --tail=200
```

## Current State Inventory

### Repository Size and Test Shape

Observed with `rg --files`, excluding vendored folders where noted:

| Repo | Go files | Go test files | Notes |
|---|---:|---:|---|
| `constellation` | 525 | 171 | Broad product surface, many binaries and package areas. |
| `constellation-vulndb` | 147 | 61 | Focused producer and bundle toolchain. |
| `neuvector` | 8267 | 86 | Large mature platform, includes vendor and native data plane. |

Top-level size:

| Repo | Size |
|---|---:|
| `constellation` | 44M |
| `constellation-vulndb` | 3.5M |
| `neuvector` | 392M |

Command count:

| Repo | Command directories |
|---|---:|
| `constellation/cmd` | 19 |
| `constellation-vulndb/cmd` | 24 |

### Verification Run During Review

| Repo | Command | Result |
|---|---|---|
| `constellation-vulndb` | `GOWORK=off go test ./...` | Passed. |
| `constellation` | `make verify` | Passed; `golangci-lint` is skipped because it is not installed locally, while `go vet ./...`, `go test ./...`, and Helm lint pass. |
| `constellation` | `helm lint deploy/charts/constellation && make helm-template-smoke` | Passed. |
| `constellation` | rendered-manifest security assertion over `/tmp/constellation.yaml` | Passed; runtime-agent is the only privileged workload and non-agent containers render restricted context defaults. |
| `constellation` and `constellation-vulndb` | anchored workflow action pin guard | Passed. |
| `neuvector` | `make test` | Build failed because local system lacks `pcre.h`; NeuVector CI installs `libpcre3-dev`. |

Local environment limits: this workspace does not have Docker, kind, Syft, Trivy, Grype, kube-score, Polaris, Kyverno, or NeuVector's native PCRE development headers installed. Docker/BuildKit image builds, kind/k3s CNI enforcement, live scanner-output captures, third-party policy-engine scoring, and NeuVector native build validation remain environment-bound.

## Feature Comparison

| Area | NeuVector | Constellation Current | Target Constellation + VulnDB |
|---|---|---|---|
| Vulnerability intelligence | Scanner/updater model, integrated DB flow, mature product consumption. | VulnDB is the canonical producer; Constellation scanner consumes signed bundle stores, uses Syft inventory for matching, preserves Syft repository/module-stream hints when present, and keeps Trivy/Grype as optional evidence engines with fixture-backed parsers. Host matching reads the same bundle store. | Finish live Syft/Trivy/Grype output capture coverage in an environment with scanner binaries plus a container runtime. |
| Bundle/update channel | Updater image and release discipline. | Helm `vulndbImporter` maps to producer-owned `vulndb-bundle-install`; API, scanner, and importer share the configured bundle store. Sources include upload, mounted files, HTTPS/S3, OCI, and prebuilt bbolt with trust/freshness policy. | Validate image builds in Docker/BuildKit and keep producer/consumer contract tests in CI. |
| Runtime data plane | Mature C data plane, DPI parsers, Layer 7 firewall, enforcer/controller architecture. | Vendored NeuVector `dp` subset plus Go supervisor and BPF event collection. | Keep NeuVector DP as a disciplined vendored upstream or replace with a deliberate data plane. Add conformance tests and CNI matrix. |
| Network policy lifecycle | Learned policies, enforcement, controller distribution. | Native/Cilium/Calico YAML generation exists; UI/API lifecycle now derives candidates from deployment/flow evidence and persists approve/apply/demote/rollback state without mock fallback. | Validate live cluster apply, CNI distribution, policy convergence, and false-positive review in a real cluster matrix. |
| Image scanning | Registry scan APIs, scanners, updater. | Scanner worker wraps Syft, Trivy, Grype CLIs. Registry walker exists. | Syft inventory -> VulnDB scan. Trivy/Grype optional validation. Registry scheduler and per-registry credentials tested end to end. |
| Host scanning | Enforcer host inventory and compliance hooks. | Host OS/packages/modules/CNI/CRI scanning exists. rpm package enumeration now covers sqlite/ndb/bdb rpmdb files. | Host inventory normalized, namespace mapping tested against distro fixtures. |
| Admission control | Mature admission APIs, CRDs, rules, import/export. | Admission webhook and quarantine hooks exist, default failure policy is Ignore. | Policy profile based admission with explicit modes, tests for fail-open and fail-closed, and production profile defaulting to enforce where selected. |
| Compliance | CIS/kube bench assets and compliance profiles. | `pkg/compliance`, runtime docs, and some handlers exist. | Ship benchmark profiles, evidence collection, exemptions, profile versioning, and UI/API workflows. |
| RBAC and auth | Mature permissions and SSO integration. | Local auth, JWT, OIDC, PAT, RBAC, production JWT Helm wiring, Astronomer JWKS route authentication, and integration-tagged JWKS mapping tests exist. | Ship JWKS-backed HTTP route integration first; keep reverse-tunnel protocol work future-only until the Astronomer multiplex contract is implemented end to end. |
| CI/security | Pinned Actions, CodeQL, govulncheck, Scorecard, FOSSA, native deps installed. | Repo CI workflows now run Go, Helm, frontend, security, RBAC, and release-image guardrails with pinned actions and checksum validation. | Validate Docker/BuildKit image builds and live cluster/CNI e2e in an environment with Docker/kind. |
| Supply chain | Release workflows and pinned action SHAs. | Production/helper image references and scanner-tool downloads needed hardening. Current worktree digest-pins image refs and verifies downloaded tool checksums. | Digest-pinned bases, verified tool downloads, SBOM/provenance/signatures for every image. |
| Product maturity | Broad stable platform. | Several visible placeholder surfaces have been implemented or removed; remaining known gaps are tracked as explicit validation or future-scope items. | No visible feature ships without implementation, tests, and documented operating boundaries. |

## Definitions

Bundle:

- The portable VulnDB handoff consisting of `manifest.json` and `bundle.jsonl.gz`.
- This is the durable artifact Constellation and other products should consume.

Manifest:

- The JSON metadata file that identifies schema version, media type, bundle version, payload hash, record counts, table counts, producer, export time, and optional signature metadata.
- Consumers must validate it before trusting bundle contents.

bbolt store:

- A local read-only query cache built from a verified VulnDB bundle.
- It is optimized for fast package matching.
- It is regenerable and should not be treated as the canonical artifact.

Producer:

- `constellation-vulndb`.
- Owns source ingestion, normalization, bundle export, signing, OCI publication, compatibility fixtures, and scanner matching semantics.

Consumer:

- `constellation` or any other product/tool that reads VulnDB artifacts.
- Owns product policy, UI, workflow, risk scoring, suppression behavior, and storage of scan results.

Consumer contract:

- The versioned public interface between VulnDB and consumers.
- Includes manifest rules, schema/media compatibility, public Go packages, CLI behavior, bbolt metadata policy, and compatibility fixtures.

Compatibility fixture:

- A small deterministic VulnDB test dataset published by VulnDB and imported by Constellation tests.
- It catches breaking producer/consumer changes before either repo ships.

Canonical matcher:

- The matching implementation that determines whether a package version is affected by an advisory.
- Target state: VulnDB is the canonical matcher for Constellation host and image vulnerability findings.

Inventory:

- A list of discovered packages, versions, ecosystems/namespaces, package URLs, and optional image/base OS hints.
- Syft is the preferred image inventory source. Host inventory comes from runtime-agent host package collection.

Reconciliation engine:

- A non-canonical scanner such as Trivy or Grype that can provide comparison evidence.
- It may raise disagreement signals, but it should not create the primary vulnerability truth when VulnDB is enabled.

Runtime agent:

- The Constellation node DaemonSet responsible for host inventory, eBPF events, and the vendored NeuVector data plane supervisor.

Data plane:

- The packet/session/L7 inspection component.
- Current Constellation data plane is a vendored subset of NeuVector `dp`.

Importer/updater:

- The component that pulls a signed VulnDB artifact, verifies it, materializes a bbolt store, and atomically publishes it for Constellation API pods to read.

Production mode:

- A Helm/runtime profile where unsigned VulnDB bundles, ephemeral JWT keys, floating image tags, missing security contexts, and missing readiness gates are not accepted unless explicitly overridden.

Dev mode:

- A profile that can allow optional VulnDB, ephemeral keys, local OCI layout bundles, and faster iteration defaults.

## NeuVector Practices to Copy

Separate updater/importer from scanner:

- NeuVector has a scanner/updater-style separation. Constellation should not make API pods responsible for mutating vulnerability databases.
- VulnDB import/update should be its own role, with its own permissions, storage, logs, and health.

Separate controller from enforcer:

- NeuVector's controller/enforcer split keeps cluster policy and node enforcement responsibilities distinct.
- Constellation should keep API/operator policy decisions separate from runtime-agent enforcement mechanics.

Treat native dependencies as first-class CI inputs:

- NeuVector CI installs native dependencies such as `libpcre3-dev` before test/build steps.
- Constellation CI should install the NeuVector DP build dependencies and fail on native build drift.

Run security workflows continuously:

- NeuVector runs CodeQL, govulncheck, Scorecard, and FOSSA/license checks.
- Constellation should add the same class of checks, with Go, Actions, and C/C++ coverage.

Pin GitHub Actions:

- NeuVector pins workflow actions by SHA.
- Constellation and VulnDB should pin actions in production workflows.

Model policy lifecycle explicitly:

- NeuVector has mature lifecycle concepts for learning and enforcing policy.
- Constellation should formalize discover, monitor, protect, violation, and rollback states instead of exposing ad hoc generated YAML.

Keep runtime privileges explicit:

- NeuVector-style enforcement requires privileged host access.
- Constellation should keep this limited to runtime-agent and document every hostPath, capability, and namespace option.

Ship profile-based controls:

- NeuVector exposes policy, admission, vulnerability, and compliance profile concepts.
- Constellation should use versioned profiles for admission, vulnerability gating, compliance, and runtime enforcement.

Build release evidence:

- NeuVector release workflows and VulnDB publish workflows both point toward a release-evidence model.
- Constellation releases should include image SBOM, image signatures, source revision, VulnDB contract version, chart render evidence, and e2e results.

## Core Decisions

### D1: VulnDB Is Not a Vendored Library Copy

Decision:

- Remove `constellation/third_party/constellation-vulndb` from the target architecture.
- Use the standalone `constellation-vulndb` repository as a normal versioned module and release artifact producer.
- Use `go.work` for local multi-repo development.
- Use semantic tags or normal pseudo-versions in `constellation/go.mod`.

Definition of done:

- `constellation/go.mod` has no zero pseudo-version for VulnDB.
- `constellation/go.mod` has no `replace github.com/alphabravocompany/constellation-vulndb => ./third_party/constellation-vulndb`.
- There is no nested git checkout for VulnDB under `constellation/third_party`.
- Local development docs use `go work use ./constellation ./constellation-vulndb`.
- CI builds Constellation without any local replace.

Validation:

```bash
cd /root/constellation-all
test ! -d constellation/third_party/constellation-vulndb
cd constellation
go list -m github.com/alphabravocompany/constellation-vulndb
go test ./...
```

### D2: VulnDB Owns the Public Consumer Contract

Decision:

- Move consumer-safe packages out of `internal/*` in VulnDB.
- Preferred package layout:
  - `pkg/contract`: schema version, media type, manifest validation, record/table count policy.
  - `pkg/model`: public scanner records and result types.
  - `pkg/bundle`: bundle read/write verification helpers.
  - `pkg/bundledb`: bbolt materialized store open/query/scan.
  - `pkg/compat`: stable compatibility fixtures.
  - `pkg/inventory`: Syft/CycloneDX/SPDX/native package-list parsers where safe.
- Keep source ingestion, Postgres writes, and producer-only internals under `internal/*`.

Definition of done:

- Constellation imports only `github.com/alphabravocompany/constellation-vulndb/pkg/...`.
- No Constellation code imports `internal` VulnDB packages.
- VulnDB internal callers use the same public consumer-safe implementations instead of carrying duplicate package copies.
- `pkg/compat` is usable by downstream tests.
- The consumer contract is versioned and tested.
- Unknown additive fields are ignored by consumers.
- Unsupported schema/media types are rejected with clear errors.

Validation:

```bash
cd constellation-vulndb
go test ./pkg/... ./internal/...

cd ../constellation
go test ./internal/vulndb ./internal/scanner ./internal/handler -run VulnDB
```

### D3: Bundle Is the Durable Handoff, bbolt Is a Cache

Decision:

- `manifest.json` plus `bundle.jsonl.gz` is the durable handoff.
- `vulndb.bbolt` is a regenerable read-only query cache.
- Constellation may consume a prebuilt bbolt for fast startup, but the source of truth is the signed bundle.

Definition of done:

- Constellation stores bundle metadata with every scan batch.
- Constellation can rebuild bbolt from bundle.
- Constellation can reject stale or unsigned bundles according to policy.
- Operators can inspect `bundle_version`, `payload_hash`, and freshness from the API.

Validation:

```bash
cd constellation-vulndb
go run ./cmd/vulndb-bundle-import -dir /tmp/vulndb-bundle
go run ./cmd/vulndb-bundle-store -dir /tmp/vulndb-bundle -out /tmp/vulndb.bbolt -overwrite
go run ./cmd/vulndb-bundle-query -db /tmp/vulndb.bbolt -metadata
go run ./cmd/vulndb-bundle-query -db /tmp/vulndb.bbolt -counts
```

### D4: VulnDB Is Canonical for Vulnerability Matching

Decision:

- Constellation image scans use Syft for inventory.
- Constellation sends inventory to VulnDB for vulnerability matching.
- Trivy and Grype can stay as reconciliation engines, but their output is not the canonical vulnerability source.
- Host scans use the same VulnDB matcher and the same namespace semantics as image scans.

Definition of done:

- One code path maps package inventory into VulnDB scan queries.
- Image and host vulnerability rows include VulnDB provenance.
- Trivy/Grype disagreements are represented as evidence, not primary identity.
- UI/API wording makes bundle version and source clear.

Validation:

```bash
cd constellation-vulndb
go run ./cmd/vulndb-bundle-scan-list -db /tmp/vulndb.bbolt -format syft-json -input tests/fixtures/inventory/syft.json

cd ../constellation
go test ./internal/scanner ./internal/vulndb
```

## P0 Workstream: Producer/Consumer Realignment

### P0.1 Remove Vendored VulnDB Drift

Tasks:

- Delete `constellation/third_party/constellation-vulndb`.
- Remove the zero pseudo-version from `constellation/go.mod`.
- Add a real module version for `github.com/alphabravocompany/constellation-vulndb`.
- Add a root `go.work.example` or docs for multi-repo development.
- Fix every Constellation import to use the new VulnDB public packages.
- Add CI that runs without local replace directives.
- Add a check that fails if `third_party/constellation-vulndb` reappears.

Definition of done:

- `go test ./...` in Constellation succeeds from a fresh clone with no sibling VulnDB checkout.
- `go mod verify` succeeds.
- `go list -m -json github.com/alphabravocompany/constellation-vulndb` reports a real version.
- A fresh `gh repo clone AlphaBravoCompany/constellation` can build without copying VulnDB into `third_party`.

Testing and validation:

```bash
cd constellation
go mod tidy
go mod verify
go test ./...
rg -n "third_party/constellation-vulndb|v0.0.0-00010101000000|replace github.com/alphabravocompany/constellation-vulndb"
```

Current worktree status:

- Completed:
  - `constellation/third_party/constellation-vulndb` is removed.
  - `constellation/go.mod` uses a real VulnDB pseudo-version instead of the zero pseudo-version.
  - Constellation imports VulnDB through public `pkg/*` packages.
  - `constellation/go.work.example` documents a local sibling-repo workspace for Constellation plus VulnDB without adding a permanent `go.mod` replace.
  - `constellation/docs/development.md` documents the producer/consumer module boundary and local guard commands.
  - Constellation CI checks out `constellation-vulndb`, creates a temporary workspace, and fails if `third_party/constellation-vulndb`, the zero pseudo-version, or a permanent VulnDB `go.mod` replace reappears.
- Validation:
  - `GOWORK=/root/constellation-all/constellation/go.work.example go list -m all` succeeds and resolves both sibling modules locally.
  - `go mod verify` succeeds in `constellation`.
  - The module-boundary guard succeeds: no vendored VulnDB directory exists, `go.mod` has no VulnDB replace, and the zero pseudo-version is absent.
- Remaining:
  - Fresh-clone validation without sibling checkout still requires GitHub credentials or a publicly accessible/tagged VulnDB module version.

### P0.2 Publish VulnDB Public Consumer API

Tasks:

- Create `pkg/contract` with constants and validation:
  - schema version `v2`
  - media type `application/vnd.alphabravo.vulndb.bundle.v2+jsonl+gzip`
  - payload name `bundle.jsonl.gz`
  - manifest name `manifest.json`
  - required manifest fields
- Move or wrap `internal/bundledb` into `pkg/bundledb`. Completed in current worktree by removing the duplicate internal package and retargeting callers to `pkg/bundledb`.
- Move or wrap consumer-safe model types from `internal/model` into `pkg/model`. Completed in current worktree by removing the duplicate internal package and retargeting callers to `pkg/model`.
- Move the compatibility fixture from `internal/compat` to `pkg/compat`. Completed in current worktree by removing the duplicate internal package and retargeting callers to `pkg/compat`.
- Keep producer-only code internal.
- Write a `docs/public-api.md` file that says what is stable and what is not. Completed in current worktree.
- Add examples:
  - open bbolt and read metadata. Completed in `pkg/bundledb` executable examples.
  - scan one package. Completed in `pkg/bundledb` executable examples.
  - scan a package list. Completed in `pkg/bundledb` executable examples.
  - build a bbolt store from a bundle. Completed in `pkg/bundledb` executable examples.

Definition of done:

- `go doc ./pkg/contract ./pkg/bundledb ./pkg/model ./pkg/compat` is useful.
- Public API has tests and examples.
- Constellation imports public packages only.
- Compatibility fixture validates both standalone VulnDB and Constellation behavior.

Testing and validation:

```bash
cd constellation-vulndb
go test ./pkg/... -run .
go test ./pkg/... -run Example
go vet ./pkg/...
go doc ./pkg/contract
go doc ./pkg/bundleimport
go doc ./pkg/bundledb
go doc ./pkg/model
go doc ./pkg/compat
```

Current worktree status:

- Completed:
  - `pkg/contract`, `pkg/model`, `pkg/bundleimport`, `pkg/bundledb`, and `pkg/compat` expose consumer-facing APIs.
  - `docs/public-api.md` defines stable versus producer-internal package boundaries.
  - `pkg/bundledb` has executable examples for building a store from a fixture bundle, opening a store and reading metadata, scanning one package, and scanning a package list.
- Validation:
  - `go test ./pkg/... -run .` passes.
  - `go test ./pkg/... -run Example -count=1 -v` passes.
  - `go vet ./pkg/...` passes.
  - `go doc ./pkg/contract`, `go doc ./pkg/bundleimport`, `go doc ./pkg/bundledb`, `go doc ./pkg/model`, and `go doc ./pkg/compat` all return useful public package summaries.

### P0.3 Build a Contract Test Suite Shared by Both Repos

Tasks:

- In VulnDB, publish a fixture containing:
  - at least one OS namespace advisory. Completed in `pkg/compat.DefaultFixture`.
  - at least one language ecosystem advisory. Completed in `pkg/compat.DefaultFixture`.
  - aliases. Completed in `pkg/compat.DefaultFixture`.
  - references. Completed in `pkg/compat.DefaultFixture`.
  - fixed version. Completed in `pkg/compat.DefaultFixture`.
  - KEV/EPSS risk signals. Completed in `pkg/compat.DefaultFixture`.
  - withdrawn advisory that must not match. Completed in `pkg/compat.DefaultFixture` and enforced by `compat.ValidateStore`.
  - unknown additive JSON field that must be ignored. Completed in `pkg/compat.DefaultFixture`.
- In Constellation, add tests that import this fixture and assert:
  - manifest validation behavior. Completed in `internal/scanner`.
  - bbolt metadata behavior. Completed in `internal/scanner`.
  - package match behavior. Completed in `internal/scanner`.
  - host package match behavior. Completed in `internal/vulndb`.
  - image inventory match behavior. Completed in `internal/scanner`.
  - result provenance behavior. Completed in `internal/scanner`.

Definition of done:

- A change to VulnDB matching semantics breaks Constellation tests before release.
- Fixture tests run without network and without Postgres.
- Fixture tests complete quickly enough for every PR.

Testing and validation:

```bash
cd constellation-vulndb
go test ./pkg/compat ./pkg/bundledb

cd ../constellation
go test ./internal/vulndb ./internal/scanner -run Compat
```

Current worktree status:

- Completed:
  - `pkg/compat.DefaultFixture` now exercises OS and language advisories, aliases, advisory references, fixed-version ranges, CVSS/KEV/EPSS risk signals, a withdrawn advisory that must not match, and unknown additive JSON fields that consumers ignore.
  - `pkg/compat.ValidateStore` enforces required table presence, fixed-version propagation, withdrawn non-match behavior, and reference-row presence.
  - Constellation downstream tests validate the fixture manifest/payload, bbolt metadata propagation, scanner image-inventory matching, host package matching, and VulnDB provenance.
- Validation:
  - `go test ./pkg/compat ./pkg/bundledb -run 'TestCompatibility|TestRequiredTables|Example|TestScanPackageSkipsWithdrawn' -count=1 -v` passes in `constellation-vulndb`.
  - `go test ./internal/scanner ./internal/vulndb -run 'TestVulnDBCompatibilityFixtureManifestValidation|TestVulnDBMatcherConsumesGeneratedFixtureStore|TestBundleMatcherConsumesVulnDBCompatibilityFixture' -count=1 -v` passes in `constellation`.

### P0.4 Replace the VulnDB Importer Story

Original issue:

- `internal/handler/vulndb.go` implements `POST /api/v1/vulndb:import` by writing to the bbolt path.
- `api-deployment.yaml` mounts `/var/lib/constellation` read-only.
- `vulndb-importer-cronjob.yaml` previously referenced an importer image/behavior without a producer-owned installer contract.

Current status:

- The scheduled importer now maps to VulnDB-owned `vulndb-bundle-install`.
- API, scanner, and importer share the configured VulnDB store volume.
- The installer supports OCI, file, URL, S3, and prebuilt-store sources, trust/freshness policy, atomic install, and status JSON.
- The manual API upload path is now policy-gated by `CONSTELLATION_VULNDB_MANUAL_UPLOAD_ENABLED` / `vulndb.manualUpload.enabled`; production values disable it and the API mounts the store read-only.

Greenfield target:

- VulnDB remains the generator and publisher of durable artifacts.
- Constellation consumes whatever artifact delivery mode the deployment chooses.
- Operators configure source type, trust policy, schedule, storage, and freshness SLO.
- Supported delivery modes should include:
  - manual multipart upload to the API
  - mounted `manifest.json` plus `bundle.jsonl.gz`
  - mounted prebuilt `vulndb.bbolt`
  - HTTPS URLs, including presigned S3 URLs
  - native `s3://` manifest/payload or store URIs
  - OCI artifacts where a registry promotion workflow is useful
- The installer verifies manifest/payload, builds bbolt when needed, validates prebuilt stores, and atomically swaps the target file.
- API pods and installer jobs share the configured VulnDB store volume.
- Manual upload remains valid for small teams, local development, and emergency updates when explicitly enabled. Production installs should consume signed artifacts through the importer.

Tasks:

- Add a real installer binary. Preferred:
  - VulnDB-owned `cmd/vulndb-bundle-install` image because VulnDB owns the artifact contract and can serve Constellation and other products.
- Implement:
  - `--ref`
  - `--bundle-dir`
  - `--manifest`
  - `--payload`
  - `--manifest-url`
  - `--payload-url`
  - `--manifest-s3`
  - `--payload-s3`
  - `--store`
  - `--store-url`
  - `--store-s3`
  - `--out`
  - `--cosign-public-key`
  - `--certificate-identity`
  - `--certificate-oidc-issuer`
  - `--max-age`
  - `--require-signatures`
  - `--atomic-target`
  - `--status-file`
- Replace hostPath with a PVC or configurable volume.
- Use RWX storage by default when API replicas are greater than one.
- Make installer mount the configured volume read-write.
- Keep API write support only while manual upload is enabled.
- Add readiness policy for clusters that want to block API readiness until a first valid store exists. Completed in current worktree with `CONSTELLATION_VULNDB_READY_REQUIRED`, `CONSTELLATION_VULNDB_READY_MAX_AGE`, and Helm `vulndb.readiness.*`.
- Update `/api/v1/vulndb/status` to expose importer metadata and freshness. Completed in current worktree via `CONSTELLATION_VULNDB_STATUS_PATH`.
- Add a production policy switch for `POST /api/v1/vulndb:import`:
  - dev/manual mode: API writes directly
  - production mode: API creates an installer job or upload is disabled
  - Completed in current worktree as upload-disabled production mode; a future one-shot installer Job mode can be added if needed.

Definition of done:

- A Helm install can configure a VulnDB source kind and get a populated store.
- The API reaches ready state only according to configured policy:
  - dev: can be ready with no bundle
  - production: requires valid bundle unless explicitly disabled
- `kubectl describe cronjob` shows a real image built by CI.
- Installer logs include bundle version, payload hash, record count, schema version, and source identity/ref digest where available.
- Failed signature verification does not replace the old store.
- Failed manifest validation does not replace the old store.
- Failed bbolt build does not replace the old store.
- With `vulndb.readiness.requireBundle=true`, `/readyz` fails until the API can open a valid local store.
- With `vulndb.readiness.maxAge` set, `/readyz` fails when the loaded bundle's `exported_at` exceeds the allowed age.

Testing and validation:

```bash
cd constellation-vulndb
go run ./cmd/vulndb-bundle-push -dir /tmp/vulndb-bundle -ref oci-layout:/tmp/vulndb-oci:test
go run ./cmd/vulndb-bundle-install -ref oci-layout:/tmp/vulndb-oci:test -out /tmp/vulndb.bbolt

go run ./cmd/vulndb-bundle-install \
  -manifest /tmp/vulndb-bundle/manifest.json \
  -payload /tmp/vulndb-bundle/bundle.jsonl.gz \
  -out /tmp/vulndb-from-files.bbolt

go run ./cmd/vulndb-bundle-install \
  -manifest-url https://example.com/manifest.json \
  -payload-url https://example.com/bundle.jsonl.gz \
  -out /tmp/vulndb-from-url.bbolt

cd ../constellation
helm template constellation deploy/charts/constellation \
  --set vulndbImporter.enabled=true \
  --set vulndbImporter.source.ref=oci-layout:/tmp/vulndb-oci:test >/tmp/constellation.yaml
helm template constellation deploy/charts/constellation \
  --set vulndbImporter.enabled=true \
  --set vulndbImporter.source.kind=s3 \
  --set vulndbImporter.source.manifestS3=s3://bucket/path/manifest.json \
  --set vulndbImporter.source.payloadS3=s3://bucket/path/bundle.jsonl.gz >/tmp/constellation-s3.yaml
helm lint deploy/charts/constellation
```

### P0.5 Align Bundle Trust Policy

Tasks:

- Require signature verification for production imports.
- Do not default keyless verification to `.*` identity and issuer in production.
- Make insecure or permissive verification available only under an explicit dev flag.
- Store trust policy in Helm values:
  - static public key secret
  - keyless identity
  - keyless issuer
  - require tlog, unless static/offline mode is selected
  - allowed registry/repository
- Record verification mode in importer status.

Definition of done:

- Production values cannot render with signature verification disabled unless `vulndb.allowUnsigned=true` is explicitly set.
- Keyless mode requires configured identity and issuer.
- Static key mode requires a mounted public key.
- CI has negative tests for unsigned, wrong key, wrong identity, wrong issuer, wrong payload hash, wrong media type.

Testing and validation:

```bash
cd constellation-vulndb
go run ./cmd/vulndb-bundle-sign -dir /tmp/vulndb-bundle
go run ./cmd/vulndb-bundle-verify -dir /tmp/vulndb-bundle
```

### P0.6 Make VulnDB Product-Neutral

Tasks:

- Keep product-specific Constellation fields out of VulnDB core schema.
- Put Constellation policy choices in Constellation:
  - severity display
  - risk scoring
  - suppressions/exceptions
  - UI groupings
  - action workflow
- Keep VulnDB focused on source facts and scanner-grade matching.
- Add an example second consumer to prove product neutrality:
  - a tiny CLI package list scanner
  - or a CI policy gate using only VulnDB public packages

Definition of done:

- VulnDB public API has no Constellation-only imports.
- Constellation-specific behavior is implemented in Constellation.
- A separate sample consumer can run VulnDB matching without Constellation.

## P0 Workstream: Scanner Alignment

### P0.7 Make Image Scanning VulnDB-First

Current issue:

- `internal/scanner` runs Syft, Trivy, and Grype.
- Syft is the authoritative SBOM source.
- Trivy and Grype are vulnerability matchers using their own databases.
- This duplicates VulnDB's intended role.

Target:

- Syft produces package inventory.
- VulnDB matches package inventory.
- Trivy and Grype run only as optional evidence engines.
- Constellation stores one canonical finding per VulnDB advisory/package match.

Tasks:

- Add a VulnDB package matcher to `internal/scanner`.
- Convert Syft package results to VulnDB package queries.
- Add namespace mapping:
  - OS packages: distro name and version from image metadata or SBOM.
  - Language packages: purl type or Syft type to VulnDB namespace.
  - CPE hints: base image and repository mappings when available.
- Add result mapping:
  - primary advisory id
  - aliases
  - severity
  - fixed version
  - normalized affected range
  - references
  - KEV/EPSS/risk signals
  - source provenance
  - bundle provenance
- Add config:
  - `scanner.engines.syft`
  - `scanner.engines.vulndb`
  - `scanner.engines.trivy`
  - `scanner.engines.grype`
  - `scanner.reconciliation.enabled`
- Fix `registryEnv` to inherit `os.Environ()` and append registry variables.
- Add tests for empty env, proxy env, cache env, and registry auth env.

Current worktree status:

- Completed:
  - `PackageMatcher` interface added.
  - `VulnDBMatcher` added.
  - Default aggregator runs Syft inventory through VulnDB matching when a bbolt store is present.
  - Language package mapping is implemented for common ecosystems (`npm`, `pypi`, `go`, `maven`, `gem`, `nuget`, `cargo`, `composer`, and related aliases).
  - Exact/base PURL matching is implemented, including version stripping for Syft-style package URLs.
  - `scanner.Package` carries optional namespace metadata from Syft distro data.
  - OS package matching is implemented for `deb`, `rpm`, and `apk` packages when distro name/version are available from Syft or explicit package URL qualifiers.
  - Scanner tests consume the public VulnDB compatibility fixture and assert OS matching, language matching, and `vulndb` provenance.
  - VulnDB bundle metadata is read from bbolt, carried through `ScanResult.BundleMetadata`, posted by scanner workers, stored on inserted finding detail JSON, and written to scan completion audit events.
  - Scan-job batch metadata is stored in `scan_jobs.bundle_metadata`, returned by `GET /api/v1/scan-jobs`, and summarized in the coverage UI.
  - Scanner engine toggles are implemented in the scanner constructor, scanner binary flags/env, and Helm values.
  - Scanner pods mount the shared VulnDB volume read-only and set `CONSTELLATION_VULNDB_PATH`.
  - `registryEnv` now inherits the process environment.
  - Scanner deduplication now records `canonical_engine` and engine provenance roles.
  - When VulnDB reports a matching advisory/package, VulnDB owns canonical severity, CVSS, title, description, fixed version, and package namespace fields.
  - Trivy/Grype findings for the same key are retained as evidence provenance and can enrich aliases/references/freshness signals without overriding VulnDB-owned fields.
  - Field-level reconciliation signals are recorded when evidence engines disagree with VulnDB on severity, CVSS, or fixed version.
  - Alpine namespace-version aliasing is implemented in Constellation's VulnDB query generation: APK packages with `3.x` query both `3.x` and `v3.x`, and packages with `v3.x` query both `v3.x` and `3.x`.
  - Syft parser tests include representative Ubuntu, Alpine, RHEL/UBI, Amazon Linux, SUSE/SLES, and Wolfi distro metadata.
  - Full Syft JSON-shaped fixtures cover representative distro documents, including legacy string license arrays and object license arrays.
  - Trivy and Grype parser tests consume JSON-shaped fixtures without requiring local scanner binaries, covering package identity, fixed version, CVSS/vector selection, references, title fallback, and the no-affected-range boundary for fixed-version-only output.
  - VulnDB query tests cover both Alpine namespace-version directions, RHEL/SUSE major-line aliases, and non-alias controls.
  - Findings API and UI expose VulnDB-vs-evidence reconciliation signals for stored scan findings.
  - Syft CPEs are de-duplicated and converted into VulnDB `PackageCPE` queries.
  - Base-image, image repository/tag, Syft package metadata repository hints, and Syft package metadata module-stream hints are attached to generated VulnDB package queries.
  - `constellation-vulndb` CPE identity matching now allows valid CPE matches when the inventory package name differs from the advisory CPE product name, and falls back to the CPE-derived product name for non-CPE package ranges.
  - `constellation-vulndb` exposes scanner-facing `matched_range` metadata on `PackageMatch`, and Constellation carries it through VulnDB findings, dedupe, scan-job detail JSON, findings APIs, and the finding detail UI.
- Remaining:
  - Replace or supplement the minimized Syft/Trivy/Grype JSON-shaped fixtures with captured live scanner outputs across representative distro images once scanner binaries plus a container runtime are available.

Definition of done:

- Default image scan path works with Syft + VulnDB.
- Trivy/Grype can be disabled with no loss of canonical vulnerability matching.
- Findings include bundle provenance.
- Reconciliation results are visible but do not change canonical advisory identity.
- Scanner child processes inherit required environment.

Testing and validation:

```bash
cd constellation
go test ./internal/scanner

HTTP_PROXY=http://proxy.example.invalid HTTPS_PROXY=http://proxy.example.invalid \
  go test ./internal/scanner -run Env
```

### P0.8 Make Host Scanning VulnDB-First

Current issue:

- Host package matching uses `BundleMatcher`; the older OSV matcher has been removed from production code.
- Host package query construction now uses VulnDB namespace names instead of OSV ecosystem strings.
- rpm enumeration now reads sqlite/ndb/bdb rpmdb files through a pure-Go reader.

Tasks:

- Remove `internal/vulndb/osv.go` from production code. Completed in current worktree.
- If an OSV dev fallback is still desired, put it behind an explicit test/dev package or separate tool. Not kept in production path.
- Implement rpm inventory. Completed in current worktree.
- Normalize host OS release fields into VulnDB namespace inputs. Completed in current worktree: runtime-agent reports `distro` and `distro_version`, and the API maps them to VulnDB namespace name/version.
- Add distro fixtures. Completed in current worktree for host OS detection and namespace mapping:
  - Ubuntu
  - Debian
  - Alpine
  - RHEL/Rocky/Alma
  - SUSE
  - Amazon Linux
  - Wolfi
- Fix `TestCollectOS_UsesHostRoot` so it uses fixture paths and never reads host `/etc/os-release`. Completed in current worktree; explicit non-`/host` roots no longer fall back to `/proc/1/root`.
- Add negative tests for unsupported or ambiguous distro state. Completed in current worktree for empty explicit OS roots and unknown host vulnerability namespaces.

Definition of done:

- Host package scans do not call public OSV.
- Host package matching uses the same VulnDB code path as image inventory.
- rpm hosts produce package inventory from SQLite, NDB, and Berkeley DB rpmdb layouts.
- Tests pass on hosts with different OS releases.

Testing and validation:

```bash
cd constellation
go test ./internal/runtime/hostscan ./internal/vulndb
go test ./cmd/constellation-runtime-agent ./internal/runtime/hostscan
CONSTELLATION_VULNDB_PATH=/tmp/vulndb.bbolt go test ./internal/handler -run HostPackages
```

### P0.9 Define Finding Provenance and Dedup Semantics

Tasks:

- Define canonical finding identity:
  - advisory primary id
  - package namespace
  - package name
  - installed version
  - artifact identity
- Define alias handling:
  - CVE/GHSA/OSV/vendor aliases do not create duplicate findings.
  - Primary id is source-native when appropriate.
- Define fixed version handling:
  - package-manager-specific version comparison comes from VulnDB namespace.
  - no fixed version is a first-class state.
- Define reconciliation handling:
  - Trivy/Grype match agreement increases confidence only as evidence.
  - Trivy/Grype disagreement creates reconciliation notes, not separate canonical findings.

Current worktree status:

- Completed:
  - Scanner `Finding` records `CanonicalEngine`.
  - Engine provenance records a `role` of `canonical` or `evidence`.
  - VulnDB takes precedence for canonical vulnerability fields when it appears in a dedupe bucket.
  - Non-VulnDB-only scans keep the previous aggregate fallback behavior and mark scanner provenance as canonical fallback.
  - Scan-job finding detail JSON includes `canonical_engine`.
  - Scan-job finding detail JSON includes reconciliation signals for severity, CVSS, and fixed-version disagreement.
  - Findings list/detail APIs now project scanner provenance from stored `engines` and `detail_json`: `canonical_engine`, engine roles, `reconciliation`, `reconciliation_count`, and `vulndb_bundle`.
  - Findings search DSL supports `canonical_engine:vulndb`, `engine:trivy`, and `disagreement:true`.
  - Findings UI surfaces canonical/evidence engines in the drawer and renders full source provenance, VulnDB bundle metadata, and field-level reconciliation rows on the detail page.
  - `canonical_engine` is promoted to an indexed `findings` column, backfilled from existing detail JSON, written by scan completion, and used by the findings search DSL.
  - VulnDB affected-range metadata is persisted as `affected_range` and exposed by findings list/detail APIs.
  - Reconciliation can now emit an `affected_range` signal when a supporting evidence engine provides comparable affected-range metadata that differs from the canonical VulnDB range.
  - Trivy and Grype parsing is fixture-tested independently of CLI execution, including fixed-version extraction, CVSS/vector selection, reference preservation, and explicit no-`affected_range` behavior for fixed-version-only scanner output.
- Remaining:
  - Extend Trivy/Grype parsers if captured stable JSON outputs expose richer affected-range metadata beyond fixed-version fields.

Definition of done:

- Duplicate CVE/GHSA/OSV aliases do not create duplicate UI rows.
- A finding can be traced to bundle version and source advisory rows.
- Reconciliation evidence is queryable and auditable.
- Canonical VulnDB fields cannot be overridden by Trivy/Grype output for the same advisory/package key.

## P0 Workstream: CI and Release

### P0.10 Add Real Constellation CI

NeuVector has a baseline worth borrowing:

- CI installs native dependencies before Go tests.
- Actions are pinned by SHA.
- CodeQL covers Go, Actions, and C/C++.
- govulncheck runs.
- Scorecard runs.
- FOSSA/license scanning runs.

Constellation target workflows:

- `ci.yml`
  - checkout pinned action
  - setup Go
  - install native DP dependencies
  - `go test ./...`
  - `go vet ./...`
  - `go test -race` for selected packages
  - `helm lint`
  - `make helm-template-smoke`
  - frontend install/build/test
- `codeql.yml`
  - Go
  - C/C++ for vendored NeuVector DP wrapper/build
  - Actions
- `govulncheck.yml`
- `scorecard.yml`
- `license.yml`
- `container-build.yml`
  - build every role image
  - scan images
  - generate SBOM
  - sign images
- `vulndb-contract.yml`
  - pull latest released VulnDB module
  - run compatibility fixture
  - build a fixture bundle and scan through Constellation

Definition of done:

- Every PR runs CI.
- CI fails if Constellation depends on a local VulnDB replace.
- CI fails if vendored NeuVector DP drifts from recorded upstream.
- CI fails if Helm renders invalid workloads.
- CI fails if tool downloads are not pinned or verified.

Current worktree status:

- Constellation workflows now pin all third-party GitHub Actions to exact commit SHAs instead of mutable tags.
- Constellation CI includes a `Guard pinned GitHub Actions` step that scans `.github/workflows/*.yml` and fails on any `uses:` ref that is not a 40-character SHA.
- The guard is anchored to actual YAML `uses:` keys so it does not match its own shell-script regex.
- Current pinned action refs include checkout, setup-go, setup-helm, CodeQL, govulncheck, upload-artifact, github-script, Docker build/login/setup actions, and cosign installer.
- Validation:
  - `make verify` passes in `constellation`; `golangci-lint` is skipped because it is not installed locally, while `go vet ./...`, `go test ./...`, and `helm lint deploy/charts/constellation` pass.
  - `make helm-template-smoke` passes.
  - `make vendor-neuvector-diff` passes and reports the vendored NeuVector tree is byte-identical to upstream revision `4247e24561a9cd225db73a7cfaf5c7b2c99ba0a5`.
  - A Python guard scan over `constellation/.github/workflows/*.yml` passed.
  - `rg -n "uses: [^\\s]+@(v[0-9]|main|master|latest)" .github/workflows` in `constellation` returned no matches.

Testing and validation:

```bash
cd constellation
make verify
make helm-template-smoke
make vendor-neuvector-diff
```

### P0.11 Tighten VulnDB CI for Consumer Guarantees

VulnDB already has real workflows. Add or strengthen:

- Public API compatibility checks.
- Fixture generation stability.
- Bundle determinism test.
- Bundle verification negative tests.
- OCI local layout push/pull test.
- Signed artifact verification with pinned identity policy.
- `govulncheck`.
- CodeQL.
- Scorecard.
- Release workflow that tags module versions and publishes bundle artifacts.

Definition of done:

- A public API breaking change requires an intentional major/minor compatibility decision.
- Consumer fixture changes are reviewed as contract changes.
- A published bundle has evidence:
  - source quality
  - source freshness
  - manifest verification
  - bbolt store validation
  - scan smoke
  - signature verification
  - OCI pull verification

Current worktree status:

- VulnDB workflows now pin all third-party GitHub Actions to exact commit SHAs instead of mutable tags.
- VulnDB CI includes a `Guard pinned GitHub Actions` step that scans `.github/workflows/*.yml` and fails on any `uses:` ref that is not a 40-character SHA.
- The guard is anchored to actual YAML `uses:` keys so it does not match its own shell-script regex.
- Current pinned action refs include checkout, setup-go, upload-artifact, and cosign installer.
- Validation:
  - A Python guard scan over `constellation-vulndb/.github/workflows/*.yml` passed.
  - `rg -n "uses: [^\\s]+@(v[0-9]|main|master|latest)" .github/workflows` in `constellation-vulndb` returned no matches.

Validation:

```bash
cd constellation-vulndb
go test ./...
go test ./internal/bundledb -run '^$' -bench '^BenchmarkScanPackageList$' -benchmem
go test ./internal/perf -run TestBundlePathQualityReport -count=1 -v
go test ./internal/perf -run '^$' -bench . -benchmem
```

## P0 Workstream: Deployment Correctness

### P0.12 Replace VulnDB Storage Wiring

Tasks:

- Add Helm values:
  - `vulndb.mountPath`
  - `vulndb.dbFile`
  - `vulndb.storage.existingClaim`
  - `vulndb.storage.size`
  - `vulndb.storage.class`
  - `vulndb.storage.accessModes`
  - `vulndbImporter.enabled`
  - `vulndbImporter.schedule`
  - `vulndbImporter.source.kind`
  - `vulndbImporter.source.ref`
  - `vulndbImporter.source.bundleDir`
  - `vulndbImporter.source.manifestPath`
  - `vulndbImporter.source.payloadPath`
  - `vulndbImporter.source.manifestURL`
  - `vulndbImporter.source.payloadURL`
  - `vulndbImporter.source.manifestS3`
  - `vulndbImporter.source.payloadS3`
  - `vulndbImporter.source.storePath`
  - `vulndbImporter.source.storeURL`
  - `vulndbImporter.source.storeS3`
  - `vulndb.trust.requireSignatures`
  - `vulndb.trust.publicKeySecret`
  - `vulndb.trust.certificateIdentity`
  - `vulndb.trust.certificateOIDCIssuer`
  - `vulndb.freshness.maxAge`
  - Completed in current worktree: installer and Helm now implement these trust/freshness flags, including OCI ref signature verification and detached file/store signature verification.
- Remove hard-coded hostPath for VulnDB.
- API and installer share the configured volume.
- Installer gets read-write mount.
- API gets write access only while manual upload mode is enabled. Completed in current worktree with `vulndb.manualUpload.enabled`; production values set it false and render the API mount read-only.
- API readiness reflects configured mode. Completed in current worktree with optional required-bundle and max-age checks.
- Add status ConfigMap or file written by importer. Completed in current worktree with `--status-file` JSON written by `vulndb-bundle-install` and read by the API.

Definition of done:

- Default dev install works with optional VulnDB.
- Production values require a valid bundle unless disabled.
- Multiple API replicas safely read the same store.
- Installer update is atomic.
- No API pod needs write access to the VulnDB store in production mode.

Validation:

```bash
cd constellation
helm template constellation deploy/charts/constellation \
  --set vulndbImporter.enabled=true \
  --set vulndbImporter.source.kind=s3 \
  --set vulndbImporter.source.manifestS3=s3://bucket/path/manifest.json \
  --set vulndbImporter.source.payloadS3=s3://bucket/path/bundle.jsonl.gz \
  >/tmp/constellation-vulndb.yaml
helm lint deploy/charts/constellation
```

Current worktree status:

- Validation:
  - `helm template constellation deploy/charts/constellation --set vulndbImporter.enabled=true --set vulndbImporter.source.kind=s3 --set vulndbImporter.source.manifestS3=s3://bucket/path/manifest.json --set vulndbImporter.source.payloadS3=s3://bucket/path/bundle.jsonl.gz` passes.
  - `helm lint deploy/charts/constellation` passes.

### P0.13 Fix JWT Production Wiring

Current issue:

- API code signs HS256 JWTs using `JWT_KEYS`.
- If `JWT_KEYS` is empty, API creates an ephemeral key only when `CONSTELLATION_REQUIRE_JWT_KEYS=false`.
- Helm renders or references a stable Secret and injects `JWT_KEYS` into the API environment.
- Helm sets `CONSTELLATION_REQUIRE_JWT_KEYS=true` by default so a broken secret reference fails API startup instead of silently using ephemeral keys.

Tasks:

- Choose one production JWT model:
  - HS256 secret loaded from Kubernetes secret env.
  - Or Ed25519/RS256 keypair loaded from files.
- Implement exactly that model end to end.
- Remove misleading Helm comments. Completed in current worktree.
- Make production install fail if JWT keys are absent. Completed in current worktree with `api.requireJWTKeys` / `CONSTELLATION_REQUIRE_JWT_KEYS`.
- Support key rotation with active and previous keys. Completed in current worktree with comma-separated active-first `JWT_KEYS`.
- Add readiness or startup validation that refuses production mode with ephemeral keys. Completed as startup validation.

Definition of done:

- Two API replicas verify each other's issued tokens.
- Restarting API pods does not invalidate existing tokens unless keys rotated.
- Helm renders required secret references clearly.
- Dev mode can still use ephemeral keys only when `CONSTELLATION_REQUIRE_JWT_KEYS=false`.

Validation:

```bash
cd constellation
go test ./internal/auth ./cmd/constellation-api
helm template constellation deploy/charts/constellation --set api.jwtKeysSecret=jwt-keys >/tmp/jwt.yaml
rg -n "JWT_KEYS|jwt-keys" /tmp/jwt.yaml
```

Current worktree status:

- Validation:
  - `go test ./internal/auth ./cmd/constellation-api` passes.
  - `helm template constellation deploy/charts/constellation --set api.jwtKeysSecret=jwt-keys` passes.
  - `rg -n "JWT_KEYS|jwt-keys" /tmp/jwt.yaml` confirms the API deployment references `JWT_KEYS`, the configured `jwt-keys` Secret, and `CONSTELLATION_REQUIRE_JWT_KEYS`.

## P1 Workstream: Kubernetes and Supply Chain Hardening

### P1.1 Workload Security Contexts

Tasks:

- Add default pod and container security contexts for:
  - API
  - scanner
  - operator
  - admission
  - frontend
  - migrate job
  - bootstrap jobs
  - audit archiver
  - VulnDB importer
- Defaults for non-agent containers:
  - `runAsNonRoot: true`
  - explicit `runAsUser` and `runAsGroup`
  - `readOnlyRootFilesystem: true` where possible
  - `allowPrivilegeEscalation: false`
  - drop all capabilities
  - `seccompProfile: RuntimeDefault`
  - no service account token unless needed
- Keep runtime-agent privileged, but isolate its permissions and document why.

Definition of done:

- Helm rendered manifests pass a policy check such as kube-score, Polaris, or Kyverno.
- Runtime-agent is the only privileged pod.
- Every exception is documented in values and docs.

Validation:

```bash
cd constellation
helm template constellation deploy/charts/constellation >/tmp/constellation.yaml
kube-score score /tmp/constellation.yaml
```

Current worktree status:

- Completed:
  - Default helper hook containers now render explicit non-root UID/GID, `allowPrivilegeEscalation: false`, dropped capabilities, read-only root filesystems, and RuntimeDefault seccomp.
  - Embedded Postgres now renders configurable pod/container security contexts with non-root UID/GID, dropped capabilities, no privilege escalation, and RuntimeDefault seccomp; its root filesystem remains writable because the database image needs runtime/data paths.
- Validation:
  - `helm template constellation deploy/charts/constellation >/tmp/constellation.yaml` passes.
  - A rendered-manifest assertion over `/tmp/constellation.yaml` confirms only `DaemonSet/constellation-runtime-agent` renders `privileged: true` and all non-agent containers render `allowPrivilegeEscalation: false`, dropped `ALL` capabilities, `runAsNonRoot`, and RuntimeDefault seccomp.
  - `helm lint deploy/charts/constellation` passes.
  - `make helm-template-smoke` passes.
  - `kube-score`, `polaris`, and `kyverno` are not installed in this workspace, so third-party policy-engine validation remains environment/tooling-bound.

### P1.2 NetworkPolicies

Tasks:

- Add default deny ingress and egress for the Constellation namespace. Completed in `deploy/charts/constellation/templates/networkpolicies.yaml`, gated by `networkPolicies.enabled`.
- Allow only required flows. Initial production profile now renders:
  - frontend -> API
  - API -> Postgres
  - scanner -> API and registries as required
  - admission -> Postgres if quarantine enabled
  - importer -> registry/S3/OCI/HTTPS sources and DNS
  - runtime-agent -> API
  - jobs -> API/Postgres/Kubernetes API where needed
- Make NetworkPolicy optional for CNIs that do not enforce it, but render by default in production profile. Completed via disabled default values plus `examples/values-prod.yaml` enabling policies.

Definition of done:

- Helm default dev profile can run locally.
- Production profile renders NetworkPolicies. Completed for the sample production values.
- E2E tests prove required flows work and blocked flows fail.

Remaining validation:

- Run a CNI-enforced cluster smoke test that proves frontend/API/scanner/runtime-agent/importer/bootstrap flows pass and an unrelated pod cannot connect to API/Postgres.
- Tighten example CIDRs to concrete environment ranges in deployment-specific values.

### P1.3 RBAC Reduction

Current issue:

- Operator ClusterRole can create/update/delete broad resources including secrets, services, namespaces, deployments, daemonsets, jobs, cronjobs, HPAs, webhook configurations, and `constellationclusters/*`.

Tasks:

- Split RBAC by role. Completed in current worktree: hook jobs, importer, long-running workloads, and operator controller use separate service accounts/roles where Kubernetes API access is needed.
- Scope namespaced resources when possible. Completed for operator-managed services, deployments, daemonsets, cronjobs, HPAs, leases, and events: default installs render a namespaced `Role`, while cluster-wide installs render a workload `ClusterRole`.
- Remove namespace create/delete unless truly required. Completed for the operator role.
- Remove secrets write from long-running components unless required. Completed for the operator role; secret writes remain only in bootstrap/init/TLS hook jobs that project credentials and certs.
- Add RBAC tests with rendered manifests. Completed locally and in CI with Helm rendering of namespaced and cluster-wide modes plus a structured check that operator roles no longer include secrets, namespaces, webhook configurations, or Jobs.
- Fix operator namespace scoping. Completed in current worktree: `OPERATOR_NAMESPACE` controls where managed workloads are created, `WATCH_NAMESPACE` controls controller-runtime cache scope, and the chart sets both consistently.

Definition of done:

- Each service account has the minimum permissions needed for its job.
- Cluster-scoped permissions are documented and tested.
- A policy check can assert no unexpected verbs appear. Completed for the operator RBAC scope in CI; broader policy-engine checks remain part of P1.1 hardening validation.

### P1.4 Pin and Verify Images and Tool Downloads

Current issues:

- Several image tags were mutable, including base and helper images.
- Scanner Dockerfile downloaded Syft, Trivy, Grype, cosign, and oras via curl without checksum or signature verification.

Tasks:

- Pin base images by digest or immutable version.
- Pin helper images:
  - `bitnami/kubectl`
  - `alpine/openssl`
  - `pgvector/pgvector`
  - Chainguard/Wolfi base
- Verify downloaded tools:
  - checksums
  - signatures where available
  - expected version output
- Generate SBOM for every Constellation image.
- Sign every image.
- Add release provenance.

Current worktree status:

- Completed:
  - Chainguard/Wolfi base image refs are digest-qualified in production Dockerfiles, including nginx and FIPS variants.
  - Helm helper images are digest-qualified: `bitnami/kubectl`, `alpine/openssl`, `postgres:16.10-alpine3.22`, and embedded dev/test `pgvector/pgvector:pg16`.
  - Downloaded scanner/helper tools are SHA-256 verified for Syft, Trivy, Grype, cosign, oras, and crictl.
  - `goose` is version-pinned in the migration image build instead of installed from `latest`.
  - Makefile image build/push targets no longer tag or push production images as `:latest` or `:fips-latest`.
  - Release image workflow builds role images with immutable release/SHA tags, requests BuildKit SBOM and max provenance attestations, signs published image digests with cosign keyless signing, and uploads per-image digest metadata.
  - CI now fails on bare mutable production image references in the Makefile, Dockerfiles, and chart values while allowing the documented signed VulnDB artifact channel.
  - The remaining `constellation-vulndb-bundle:latest` references are documented as a signed/freshness-checked VulnDB artifact channel, not Constellation application images. Operators can pin them to OCI digests for exact replay.
- Remaining:
  - Docker image builds must be validated in an environment with Docker/BuildKit.

Definition of done:

- No production application/helper image reference uses a bare mutable tag.
- Every curl-downloaded binary has checksum/signature verification.
- CI fails on unpinned production image references.

Validation:

```bash
cd constellation
rg -n '(:|=)latest(["[:space:]]|$)' deploy/docker deploy/charts/constellation | rg -v 'constellation-vulndb-bundle'
rg -n "curl -fsSL" deploy/docker
```

Current worktree validation:

- The mutable `latest` scan returns no active Constellation application/helper image references outside the documented signed VulnDB artifact channel.
- Every remaining `curl -fsSL` download in Constellation Dockerfiles is paired with an architecture-specific SHA-256 build arg and `sha256sum -c` verification for Syft, Trivy, Grype, cosign, oras, and crictl.

## P1 Workstream: NeuVector Parity Features

### P1.5 Runtime Agent and Data Plane Parity

Tasks:

- Keep NeuVector DP vendoring disciplined:
  - upstream rev recorded
  - diff check in CI
  - no local edits outside patch workflow
  - build validation in CI
- Add DP wire protocol tests:
  - connect/session messages. Completed in `internal/runtime/dp` decoder and dispatch tests.
  - threat logs. Completed in `internal/runtime/dp` decoder and dispatch tests.
  - parser metadata. Completed as `EventOther` raw-kind dispatch coverage for app/parser update metadata.
  - control messages. Completed for policy push fragmentation, delete, DLP build envelopes, and constants.
- Add CNI matrix:
  - kind
  - k3s
  - Calico
  - Cilium
  - Flannel
  - RKE2
  - OpenShift if available
- Define enforcement modes:
  - observe only
  - alert
  - block
  - quarantine
- Add failure behavior tests:
  - DP process exits
  - BPF load fails
  - CNI unsupported
  - API unreachable
  - token missing

Definition of done:

- Runtime-agent can run in observe mode on supported clusters.
- Unsupported CNI behavior is explicit and visible.
- DP drift check runs on every PR.
- Native dependencies are installed in CI.
- Privileged host access is documented and policy-audited.

Current worktree status:

- Completed:
  - DP wire decoding tests cover connection, session, threat-log, keepalive, and malformed header/payload paths.
  - DP dispatch tests prove datagrams emit typed connection/threat/session/keepalive events, preserve parser/app metadata as `EventOther.RawKind`, and count back-pressure drops.
  - DP control-message tests cover policy push single-message and fragmented datagrams, delete-table messages, DLP build envelopes, and command/flag constants.
  - The DP package overview no longer claims the request path is absent; it documents the implemented policy, DLP, tap, and session-list request paths.
  - Runtime-agent token bootstrap behavior now has harness tests for existing token files, late-populated file-mounted Secrets, and timeout fallback to stdout-only mode.
  - Runtime-agent upload retry behavior now has harness tests proving 5xx responses retry, 4xx responses fail without retrying, and network-level API unreachable behavior returns a context error instead of hanging indefinitely.
  - DP supervisor process-exit behavior now has harness tests proving non-zero exits increment crash counters and clean exits do not.
- Validation:
  - `go test ./internal/runtime/dp -run 'TestIPCDispatch|TestDecode|TestPushPolicy|TestBuildDLPRules|TestApplyDirConstants' -count=1 -v` passes.
  - `go test ./internal/runtime/dp -run 'TestSupervisorRunOnce|TestIPCDispatch|TestDecode|TestPushPolicy|TestBuildDLPRules|TestApplyDirConstants'` passes.
  - `go test ./cmd/constellation-runtime-agent -run 'Test(WaitForToken|PostBatch)'` passes.
- Remaining:
  - Live runtime-agent observe/enforce behavior still needs Docker/kind/CNI or equivalent cluster validation with the actual dp process and native dependencies.
  - BPF load failure with the actual object-loading/attach path still needs live or privileged-kernel harness coverage.

### P1.6 Policy Lifecycle

Completed in the current worktree:

- Network policy lifecycle is DB-backed from observed `deployments` and `network_flows`; no-storage mode returns an empty live state instead of generated examples.
- The lifecycle API derives discover/monitor/protect candidates from observed flow volume and out-of-policy verdicts, including tuple evidence, blast-radius summaries, deterministic diffs, and candidate hashes.
- Approve/apply/demote/rollback actions are persisted with idempotency keys, candidate-hash guards, stale-candidate rejection, rollback refs, and hash-chained audit events.
- The Network Map UI exposes lifecycle state, candidate hash/staleness, tuple inclusion/hold reasons, approve/apply/demote/rollback controls, rollback preview, and audit trail.
- Candidates now emit and persist a deterministic manifest bundle for all supported Kubernetes policy flavors:
  - native `NetworkPolicy`
  - `CiliumNetworkPolicy`
  - Calico `GlobalNetworkPolicy`
- L7 protocol intent from observed flows is preserved as policy manifest metadata for every flavor, so native NetworkPolicy and Calico artifacts do not silently lose application-layer context they cannot enforce.
- Lifecycle action rows, lifecycle state rows, and rollback refs now store `preview_manifests` JSONB alongside legacy `preview_yaml`, giving future appliers and rollback workflows the exact approved artifact set.
- Added a real in-cluster NetworkPolicy lifecycle applier path:
  - `cmd/constellation-netpolicy-applier` polls actionable lifecycle rows for one cluster.
  - It consumes approved `preview_manifests`, server-side applies the selected flavor when the persisted mode is `protect`, and deletes the managed resource when a policy is demoted or rolled back out of protect.
  - Supported apply flavors are native `NetworkPolicy`, `CiliumNetworkPolicy`, and Calico `GlobalNetworkPolicy`.
  - `network_policy_apply_status` records the last action, status, resource ref, candidate hash, applied/rollback refs, timestamps, and errors.
  - The lifecycle API overlays applier status on each policy, and the Network Map UI displays the latest live-applier result.
  - Helm renders a dedicated `network-policy-applier` Deployment, service account, narrow policy-resource RBAC, and production NetworkPolicy egress to Postgres plus the Kubernetes API.
  - The operator image now includes `/usr/local/bin/constellation-netpolicy-applier`, so every rendered applier workload maps to a real binary.
  - Helm docs now describe `networkPolicyApplier.enabled`, `flavor`, `clusterId`, `clusterName`, and `interval`.
- Focused validation passed:
  - `go test ./pkg/netpolicy`
  - `go test ./internal/handler -run 'TestNetworkPolicies|TestRuntimePolicies'`
  - `go test ./internal/netpolicyapply`
  - `go test ./cmd/constellation-netpolicy-applier`
  - `helm template constellation deploy/charts/constellation --set networkPolicies.enabled=true --set networkPolicyApplier.flavor=cilium`
- Broader validation passed after the policy lifecycle artifact work:
  - `go test ./...` in `constellation`
  - `GOWORK=off go test ./...` in `constellation-vulndb`
  - `npm ci && npm run build` in `constellation/frontend` followed by removal of `frontend/node_modules`
  - `helm lint deploy/charts/constellation`
  - `make helm-template-smoke`
  - `git diff --check` in both repos
  - exact conflict-marker scans in both repos
  - exact cleanup scan `rg -n "stub|not implemented|TODO\\(|TODO endpoint" --glob '!third_party/**'` in `constellation`

Tasks:

- Implement full discover/monitor/protect lifecycle:
  - learn observed flows. Completed for DB-backed deployment and flow evidence.
  - generate policies. Completed for deterministic native/Cilium/Calico manifests.
  - preview blast radius. Completed for tuple summaries, diffs, and included/held flow evidence.
  - approve. Completed with audit, idempotency, and candidate-hash guards.
  - apply. Completed through audited persisted desired-state transition plus in-cluster server-side apply of the selected manifest flavor.
  - observe violations. Partially completed through out-of-policy verdict counts and held tuples; full violation feedback needs live DP/CNI enforcement e2e.
  - rollback. Completed for persisted lifecycle state, rollback refs, and in-cluster deletion when the persisted mode exits protect.
- Support native NetworkPolicy, CiliumNetworkPolicy, and Calico GlobalNetworkPolicy. Completed for generated artifact bundles.
- Preserve L7 intent even when native NetworkPolicy cannot enforce it. Completed as manifest metadata; Cilium-specific L7 enforcement can be tightened after richer HTTP/gRPC method/path evidence is available.
- Add UI/API states and audit rows. Completed for current lifecycle surface.

Remaining:

- Add live e2e showing a sample app moving from discover to protect and blocking an unexpected flow under a supported CNI.
- Add violation feedback from live enforced policies back into the lifecycle API, beyond current out-of-policy flow verdict summaries.

Definition of done:

- A sample app can move from discover to protect and block an unexpected flow.
- Generated YAML is deterministic.
- Rollback restores prior state.
- Audit log records who approved and what changed.

### P1.7 Admission Controls

Tasks:

- Define admission profiles:
  - baseline
  - restricted
  - image provenance required
  - critical vulnerabilities blocked
  - secrets/misconfig blocked
  - privileged workload approval required
- Add dry-run mode.
- Add namespace selector defaults.
- Add failure policy profiles:
  - dev: Ignore
  - production enforce: Fail
- Add import/export of admission rules.
- Add tests against Kubernetes admission review fixtures.

Current implementation status:

- Completed local admission fixture coverage:
  - `cmd/constellation-admission/testdata/admissionreviews/` now covers privileged pods, privileged ephemeral containers, compliant pods, and monitor-only unsigned/writable pods through the production `/validate` handler.
  - Malformed AdmissionReview and missing-request bodies return HTTP 400.
  - `pkg/admission.PolicyEngine` now evaluates ephemeral containers in the same rule path as regular and init containers.
  - Dry-run admission simulation now extracts ephemeral-container evidence, honors pod-template signature annotations, and only treats digest references as provenance when every image is digest-pinned unless a signature annotation is present.
- Completed Helm profile wiring for the current chart surface:
  - Default/dev chart values remain `failurePolicy: Ignore`.
  - `deploy/charts/constellation/examples/values-prod.yaml` now renders `failurePolicy: Fail` with an explicit `constellation.alphabravo.io/enforce=true` namespace selector.
- Completed first-class admission profile API/catalog:
  - `pkg/admission` now defines deterministic built-in profile bundles for baseline, restricted, image provenance required, critical vulnerabilities blocked, secrets/misconfig blocked, and privileged workload approval required.
  - `/api/v1/policies/admission-profiles` lists built-in profiles, `/api/v1/policies/admission-profiles/{profile}/export` returns an import/export bundle, and `/api/v1/policies/admission-profiles:import` supports built-in profile IDs or direct bundle JSON.
  - Admission profile import supports dry-run without storage, mode/enabled overrides, profile-prefixed policy row names, idempotent upsert into `policies`, audit logging, notification dispatch, a 1 MiB request cap, and a 200-rule bundle cap.
  - `frontend/src/api/client.ts` has typed profile list/export/import methods.
- Completed live webhook reload for profile rules:
  - `cmd/constellation-admission` can now load enabled `constellation-admission` policy rows from Postgres using `--policy-dsn`, `--policy-cluster-id`, and `--policy-refresh`.
  - Policy loading is cluster/org scoped through the `clusters` table and only admits global or matching `cluster_id` policy rows.
  - Loaded rules are atomically swapped into `pkg/admission.PolicyEngine` alongside built-in defaults; `SetRules`/`SnapshotRules` and quarantine updates are concurrency-safe.
  - The YAML parser executes supported profile-rule controls for privileged, hostNetwork, hostPID, read-only root filesystem, non-root execution, latest/implicit tags, digest-pinned images, signature annotation, and privileged-workload approval.
  - Finding-backed profile rows for critical vulnerabilities, secrets, and misconfigurations now parse into evidence gates instead of being skipped.
  - When DB-backed policy reload is enabled, the webhook installs a Postgres evidence source scoped by the configured cluster's org. It maps pod image refs to existing image assets/findings, requires known scan results where the profile asks for them, honors active image/finding exceptions, and fail-closes evidence rules when the source is unavailable or errors.
  - Helm exposes `admission.policies.enabled`, DSN, refresh, and cluster ID settings and renders the required admission-to-Postgres NetworkPolicy when enabled.
- Completed NeuVector admission profile-bundle parity coverage:
  - `internal/migration/neuvector.ConvertAdmissionProfileBundle` now converts NeuVector admission exports into the same `AdmissionProfileBundle` envelope consumed by Constellation's profile import API.
  - Locally enforceable NeuVector criteria for latest tags, privileged containers, host namespaces, non-root/root filesystem posture, image signatures, digest pinning, and registry allowlists are emitted as `constellation-admission` rules.
  - Critical/high vulnerability, secret, and misconfiguration criteria are retained as evidence-backed admission gates and execute through the live DB evidence source when imported into a policy-enabled webhook.
  - Unsupported vendor-specific criteria are preserved as disabled `manual-review` rules with the original key/op/value payload, preventing silent rule loss during migration.
  - Tests verify the converted bundle envelope, manual-review preservation, evidence-backed CVE gate retention, YAML parser compatibility, and live webhook denial behavior for converted latest-tag and privileged-container rules.
- Completed live admission deny audit persistence:
  - `cmd/constellation-admission` now accepts `--audit-dsn` / `CONSTELLATION_ADMISSION_AUDIT_DSN` and `--audit-cluster-id`, resolves the cluster's org from `clusters`, and chains an `OnDeny` hook that writes hash-chained `admission.deny` rows through `pkg/audit`.
  - Audit rows include cluster ID, rule ID, deny reason, namespace, pod, operation, and Kubernetes username in the `after` payload, with the target set to the denied pod.
  - The hook is best-effort per deny event after successful startup; audit write failures are logged and do not panic or change the AdmissionReview decision.
  - Helm exposes `admission.audit.enabled`, DSN, and cluster ID settings, renders the audit DSN env var and `--audit-cluster-id`, and includes the admission-to-Postgres NetworkPolicy when audit persistence is enabled.
  - Tests cover audit-event construction, hook chaining, focused admission packages, and Helm rendering with audit enabled.
- Completed admission profile UI workflows:
  - `frontend/src/pages/PoliciesPage.tsx` now includes an Admission Profiles panel backed by the typed profile list/export/import API methods.
  - Operators can choose a built-in profile, override mode/enabled state, export a bundle, upload or paste a bundle JSON file, dry-run preview the generated policy rows, import them, and compare previewed rows against installed policies by policy name/spec/mode/enabled state.
  - Admission profile rows now show evidence badges for fresh scan, VulnDB bundle, canonical-engine, fixability, and verifier-identity gates.
  - The workflow invalidates policy queries after import so newly materialized profile rows appear in the existing policy catalog/editor.
  - Frontend validation passed with `npm ci && npm run build`; the only frontend warning was the existing Vite large-chunk warning, and `frontend/node_modules` was removed after validation.
- Completed admission scan-evidence quality gates:
  - `pkg/admission` parses shared `scanEvidence` policy fields plus vulnerability fixability/canonical-engine requirements and signature verifier identity requirements.
  - `cmd/constellation-admission` evaluates those gates from canonical image scan results, image findings, and signature artifacts, failing closed for missing/stale/bundle-less scans only when the policy requests that behavior.
  - Tests cover parser semantics, profile catalog inclusion, stale/bundle-less scan denial, canonical-engine filtering, fixability filtering, and allowed/disallowed verifier identities.
- Completed stored-scan admission simulation:
  - `internal/admissionevidence` now owns the shared Postgres evidence source used by both the live admission webhook and the API simulator.
  - `/api/v1/policies/simulate` parses enabled `constellation-admission` `AdmissionRule` YAML through `pkg/admission.RuleFromYAML`, evaluates rules through `pkg/admission.PolicyEngine`, and uses canonical `image_scan_results`, `image_scan_findings`, and result-scoped artifacts for evidence-backed dry-run decisions.
  - Live admission and simulation policy loading are admission-only, latest-version-aware within the selected scope, and prefer a matching cluster-specific policy over an org-wide policy of the same name; dry-runs still do not write `policy_decisions`, send webhooks, or mutate cluster state.
  - Tests cover shared evidence source extraction plus a DB-backed critical-vulnerability simulation that denies from stored VulnDB scan evidence without persisting a decision.
- Completed typed admission evidence-detail and builder UX slice:
  - `internal/admissionevidence` now emits first-class decision details for missing scan results, scan-quality gates, image findings, and result-scoped image artifacts while the Kubernetes webhook still returns a plain admission denial reason.
  - `/api/v1/policies/simulate` returns optional `evidence_details` for matching policies, including image identity, scan result freshness, VulnDB bundle version/hash, finding package/fix metadata, artifact identity/status/path/counts, and cluster-local image detail hrefs when `cluster_id` is present.
  - The previous link-only simulator shape was removed from the implementation path; UI rendering now consumes the typed details directly and keeps hrefs as presentation only.
  - The Policies UI passes active `cluster_id` into simulation, renders safe internal evidence pivots from dry-run matches, and adds an in-editor AdmissionRule builder for fresh VulnDB-backed vulnerability gates, canonical-engine/fixability controls, and trusted signature verifier controls.
  - Tests cover stored vulnerability evidence details from the API simulator, shared evidence-source details for vulnerability, stale-scan, missing-scan, and image artifact gates, plus frontend type/build validation.
- Remaining product work:
  - Add live Kubernetes e2e for fail-open versus fail-closed behavior once Docker/kind or equivalent cluster infrastructure is available.

Definition of done:

- Admission behavior is predictable by profile.
- Every blocked admission includes a clear reason and audit event.
- Production profile can be installed fail-closed intentionally.

### P1.8 Compliance and CIS

Completed in the current worktree:

- Compliance checks now expose both raw `status` and `effective_status`, so audited evidence rows are not mutated when a temporary exception applies.
- Added `compliance_exemptions` storage with org scope, optional cluster scope, framework/control binding, approver, reason, expiry, revocation, and indexes for active lookup.
- Added compliance exemption APIs:
  - `GET /api/v1/compliance/exemptions`
  - `POST /api/v1/compliance/exemptions`
  - `POST /api/v1/compliance/exemptions/{id}/revoke`
- Active, unexpired exemptions now affect `/api/v1/compliance/checks` and `/api/v1/compliance/summary`; failed controls with active exemptions count as `exempted` instead of open `fail`, while raw check status remains `fail`.
- Exemption create and revoke operations emit hash-chained audit events:
  - `compliance.exemption.create`
  - `compliance.exemption.revoke`
- Audit-to-control mappings cover the exemption lifecycle, so exception approvals become compliance evidence themselves.
- The Compliance UI now supports failed-control exemption creation, expiry selection, active exemption display, framework-level exemption counts, and revocation from the control table or exemption list.
- Added handler coverage for create/apply/summary/revoke/audit behavior.
- DB-backed scheduled compliance runs, run history, report delivery targets, and artifact downloads already exist through `/api/v1/compliance/schedules` and `/api/v1/compliance/runs/{id}/artifact`.
- Added a host compliance framework and mappings:
  - `cis-linux-2.0`
  - host CIS module, sysctl, file-mode, and SSH checks
  - cross-framework tags for NIST, PCI, and other mapped controls where applicable.
- Added workload and cloud compliance mappings:
  - `k8s.namespace.pod-security-enforce`
  - `workload.network-policy-enforced`
  - `workload.high-critical-vulnerabilities`
  - `cloud.posture.open-findings`
- Added a shared compliance evidence collector in `internal/complianceevidence` that emits one typed evidence model across:
  - persisted Kubernetes compliance checks from `compliance_checks`
  - node CIS evidence from `host_cis`
  - workload risk evidence from `deployments`
  - workload policy enforcement evidence from `network_policy_lifecycle_states` plus `network_policy_apply_status`
  - cloud posture evidence from `cloud-resource` assets plus open `cloud-config` findings.
- Added first-class compliance evidence APIs:
  - `GET /api/v1/compliance/evidence`
  - `GET /api/v1/compliance/nodes`
  - `GET /api/v1/compliance/workloads`
  - `GET /api/v1/compliance/kubernetes`
  - `GET /api/v1/compliance/cloud`
- The evidence API supports `cluster_id`, `framework`, `namespace`, `scope`, and `limit` filters.
- Active exemptions now overlay the broader evidence model, not only the persisted `/compliance/checks` table. Raw evidence status remains unchanged; `effective_status=exempted` is added when a failed row has a valid exemption.
- Scheduled compliance reports now use the shared evidence collector instead of reading only `compliance_checks`, so scheduled artifacts include host, workload, persisted Kubernetes, and cloud posture evidence for the selected framework.
- Scheduled JSON exports now use structured lower-case check field names, HTML/PDF renders style `exempted` and `not_applicable`, and SARIF exports do not emit exempted or not-applicable rows as failures.
- The Compliance UI now has an Evidence tab with summary counts and a scope/target/control/status/evidence table backed by the same evidence API.
- Added a direct Kubernetes object collector:
  - `internal/k8scompliance` evaluates live Namespaces, ClusterRoles, Deployments, StatefulSets, and DaemonSets.
  - It emits PSA enforce-label evidence, wildcard ClusterRole evidence, hostNetwork evidence, privileged-container evidence, and read-only-root-filesystem evidence.
  - `cmd/constellation-k8s-compliance-collector` resolves the Constellation cluster, reads the Kubernetes API, replaces only prior `collector=constellation-k8s-object` rows, and writes framework-expanded `compliance_checks` rows.
  - The operator and shared Docker build stages now include `/usr/local/bin/constellation-k8s-compliance-collector`.
  - Helm now renders an enabled-by-default read-only CronJob, ServiceAccount, ClusterRole, ClusterRoleBinding, and production NetworkPolicy egress for the collector.
  - Helm docs now cover collector schedule, namespace filtering, system namespace inclusion, and cluster binding values.
- Validation evidence from this slice:
  - `go test ./pkg/compliance ./internal/complianceevidence ./internal/handler -run 'Test(AllFrameworks|ExpandInternal|ComplianceEvidence|ComplianceExemptions)'` passed.
  - `go test ./cmd/constellation-compliance-scheduler ./pkg/report` passed.
  - `go test ./internal/k8scompliance ./cmd/constellation-k8s-compliance-collector ./pkg/compliance` passed.
  - `helm lint deploy/charts/constellation` passed.
  - `helm template constellation deploy/charts/constellation --set networkPolicies.enabled=true --set kubernetesComplianceCollector.enabled=true` passed.
  - `make helm-template-smoke` passed.
  - `go test ./...` in `constellation` passed.
  - `GOWORK=off go test ./...` in `constellation-vulndb` passed.
  - `npm ci && npm run build` in `constellation/frontend` passed; the only frontend warning was the existing Vite large-chunk warning, and `frontend/node_modules` was removed after validation.

Tasks:

- Decide which benchmark engines to ship. Current implementation choice:
  - kube-bench compatible ingest remains the Kubernetes benchmark input path.
  - custom native host checks are shipped through runtime-agent host CIS snapshots.
  - direct Kubernetes object checks are shipped through the `constellation-k8s-compliance-collector` CronJob for RBAC, PSA, and workload pod-template controls.
  - workload checks are DB-backed from deployment risk and network policy enforcement state.
  - cloud posture checks are DB-backed from cloud-resource assets and cloud-config findings.
  - API-server flag checks remain sourced from kube-bench compatible ingest, which is the correct path because managed clusters often do not expose control-plane static pod specs.
- Build profile model:
  - benchmark id
  - control id
  - severity
  - remediation
  - evidence
  - exemption
  - expiration
  - Completed for API/report evidence rows; remaining persistence work is optional profile-version storage if operators need immutable benchmark catalogs.
- Add node and workload compliance APIs. Completed.
- Broaden scheduled compliance runs beyond current persisted checks to host, workload, Kubernetes object, and cloud posture evidence. Completed.
- Expand evidence export to include the broader host/workload/Kubernetes/cloud evidence model. Completed for scheduled report artifacts and UI/API evidence exports.

Definition of done:

- A cluster run produces host, workload, and Kubernetes control evidence. Completed for DB-backed scheduled reports plus the direct Kubernetes object collector CronJob; remaining depth is live cluster e2e against representative managed and self-managed clusters.
- Exemptions are audited and expire.
- UI can show pass/fail/not-applicable with evidence.

### P1.9 Registry Scanning

Completed in the current worktree:

- Registry CRUD, credential sealing, cadence-based walker scheduling, sync-now, discovered-image listing, and scan job enqueueing already exist.
- Added per-registry scan policy storage and API/UI payloads:
  - include repositories
  - exclude repositories
  - tag selection (`all` or `latest`)
  - maximum image age
  - rescan interval
  - block-promotion threshold metadata
- Existing `image_globs` are preserved for compatibility and are folded into the richer scan policy so old clients do not drift from new policy behavior.
- Registry sync now applies include/exclude/max-age/tag-selection policy before enqueue decisions.
- Registry sync now resolves tag refs to digest refs where registry adapters support it, stores tag-to-digest snapshots on `registry_images`, and queues scanner jobs with pinned digest refs when available.
- Scan jobs now store registry provenance:
  - `registry_id`
  - `image_digest`
  - `enqueue_reason`
  - `registry_policy_hash`
  - `vulndb_bundle_version`
- Registry sync dedupes by digest, policy hash, and current VulnDB bundle version; unchanged pending/running/completed scans are skipped, failed scans can be retried, policy changes enqueue fresh work, and a new VulnDB bundle version creates a new scan key.
- Optional `rescan_interval` forces periodic rescans even when digest, policy, and bundle version are unchanged.
- The registry UI now exposes scan policy controls in the create/edit dialog.
- Added unit coverage for registry scan policy normalization, filtering, tag selection, policy hash stability, and digest extraction.

Tasks:

- Finish registry walker and scheduler. Completed for DB-backed cadence scheduling and sync-now; remaining depth is live-registry e2e against representative registries.
- Add credential storage and rotation. Completed for AES-GCM-sealed credential storage and update-time rotation; remaining depth is cloud-native identity e2e.
- Add per-registry scan policy:
  - include/exclude repos. Completed.
  - tag selection. Completed for `all` and `latest`.
  - max age. Completed.
  - rescan interval. Completed.
  - block promotion threshold. Stored in policy; enforcement belongs to promotion/admission gates.
- Store image digest and scan provenance. Completed for registry-originated scan jobs.
- Avoid rescanning identical digest unless policy changes or VulnDB changes. Completed for registry-originated scan jobs.
- Trigger rescans when VulnDB bundle version changes. Completed for DB-backed `cve_bundles` rows and for importer/status-file-only installs: registry sync now resolves the current bundle version from the actual mounted bbolt store first, then the importer status file, then the legacy `cve_bundles` table.

Validation:

- `go test ./internal/handler -run 'Test(CurrentVulnDBBundleVersion|RegistryScanPolicy|DigestFromResolvedRef|VulnDBStatus)'` passes.
- `go test ./internal/handler -run 'TestRegistryScanRequeuesWhenVulnDBBundleChanges|TestRegistryScanPolicy|TestDigestFromResolvedRef|TestCurrentVulnDBBundleVersion'` passes and proves an unchanged digest/policy is requeued when the VulnDB bundle version changes.

Definition of done:

- Registry scan can enumerate, queue, scan, and report images.
- Rescan on new VulnDB bundle is automatic for DB-recorded VulnDB imports.
- Registry-originated scan jobs are keyed by digest when digest resolution succeeds, with tag-ref fallback only when a registry cannot provide a digest.

## P1 Workstream: Cleanup of Duplicate and Dead Code

### P1.10 Remove or Implement Stubs

Observed stubs/scaffolds:

- Completed in current worktree:
  - `cmd/constellationctl policy validate` now parses and validates Constellation policy DSL JSON.
  - `cmd/constellationctl policy check` now validates and can evaluate a policy against `--record` JSON.
  - `pkg/abbot.Client.Query` now performs the real envelope-over-HTTP POST to `/api/v1/chat` and keeps graceful degradation for unset/unavailable service URLs.
  - `pkg/plugin.Server` now reports absent optional capabilities as "capability not declared" rather than "not implemented."
  - Astronomer JWKS middleware now authenticates `/api/v1/security/*`, maps the Astronomer subject to an existing Constellation user/org, rejects disabled users, and uses normal RBAC checks.
  - `internal/server` now has an integration-tagged Astronomer route test that uses a local JWKS server plus real Postgres `astronomer_identity_map` state to verify accepted mapped users, unmapped identities, disabled users, wrong audience tokens, and bad signatures.
  - `cmd/audit-archiver` now uploads archive artifacts to S3 and signs manifests with static-key or keyless signing.
  - Helm now renders `auditArchiver.enabled=true` with bucket/signing validation instead of fail-fast placeholder behavior.
  - Helm `vulndbImporter` now maps to the producer-owned `vulndb-bundle-install` binary and supports OCI, files, URLs, S3, and prebuilt stores.
  - Frontend Coverage now uses the existing process-baseline and connector-coverage APIs instead of TODO rows.
  - Frontend Network Map no longer shows inert "mark expected" or "block conversation" buttons without backing endpoints.
  - The unused frontend `Stub` shell component was removed.
  - Frontend Vite/Vitest toolchain was upgraded and npm audit is clean for production and dev dependencies.
  - `internal/runtime/hostscan/packages.go` now implements rpm enumeration for SQLite, NDB, and Berkeley DB rpmdb files without shelling out.
  - GitHub App README now points to the implemented webhook server instead of describing it as queued.
  - The test-suite README now distinguishes frontend browser coverage under `frontend/e2e` from the Python cluster/API/runtime harness.
  - The root README no longer describes the project as only Phase-1 scaffolding and points to this plan for remaining gaps.
  - Jenkins shared-library docs now describe the implemented gate scope and use a pinned CLI image example instead of scaffold/floating-tag language.
  - `internal/registry` no longer exposes the stale `ErrNotImplemented` sentinel or outdated "three connectors" package comment; tests now assert all nine configured registry providers are constructed.
  - Deployment risk-factor rollups no longer label CVSS/KEV/network exposure as stubs: CVSS and KEV come from stored finding detail metadata, network exposure comes from recent external network flows, and the deployment UI copy now matches those implemented factors.
  - Connector coverage no longer serves the hard-coded registry/cloud catalog in production mode; the API derives connector, scan coverage, scanner capacity, and recent job panels from registry discovery tables, saved connector configs, cloud assets/findings, heartbeats, and `scan_jobs`, while the UI queues only an operator-entered image ref.
  - Settings no longer renders static GHCR/ECR/Azure connector cards; the connector overview panel now reads the same live connector-coverage API and shows an empty configured state when no connectors exist.
  - The legacy `/api/v1/integrations` summary no longer falls back to a fixed Slack/PagerDuty/Jira/ServiceNow catalog; it returns live `receivers` rows, saved `routing_configs` metadata, and empty report jobs unless real org settings override them.
  - Compliance schedule frontend calls no longer use the old mock-catalog shape for the production `/compliance/schedules` route; both framework metrics/cards and the Schedules tab consume the DB-backed schedule rows.
  - The Settings migration preview wizard now derives its source selector from `/migration/sources` and includes working sample payloads for every backend-supported converter: NeuVector, StackRox/RHACS, Aqua, and Prisma.
  - `/api/v1/onboarding` health gates no longer report scanner, admission, runtime, API, or VulnDB importer readiness as fixed `ready` values; DB mode uses the database health probe plus component heartbeat freshness, while no-storage mode reports `not-observed`/`not-instrumented`.
  - `/api/v1/system-health` no longer starts from a dated production incident/remediation catalog. It now builds a fresh neutral component inventory per request, leaves incidents/actions empty unless real data is added, and lets live DB probes plus heartbeats provide concrete health.
  - `/api/v1/access-control` no-storage mode no longer returns named fake users, providers, service accounts, role bindings, or API tokens; it returns only the role/permission/guardrail catalog, while DB mode now requires an authenticated subject.
  - Integration delivery operations no longer expose the fixed Slack/PagerDuty/ServiceNow/Jira catalog. `/api/v1/integration-deliveries` is DB-backed from `receivers`, `receiver_deliveries`, and `routing_configs`; read-only previews require a real receiver UUID and return redacted endpoint shapes instead of raw webhook URLs or tokens.
  - Compliance scheduling no longer exposes the deleted legacy fixed schedule catalog, and the scheduler no longer synthesizes `sample.audit` / `sample.rbac` evidence rows when a report has no checks.
  - Network policy lifecycle no longer invents static workloads or applied/rollback history when no storage or observed deployment data exists.
  - Vulnerability exceptions no longer expose the fixed sample image/CVE/user catalog; DB-backed mode returns only persisted accepted or suppressed findings and image acceptances, while no-storage mode returns an empty live state plus workflow metadata.
  - Admission simulation no longer falls back to sample policies or static cluster resource manifests; it evaluates only persisted policies and explicit request manifests.
  - Audit chain verification now reports the actual verification time instead of a hard-coded future timestamp.
  - Process baselines now initialize from observed workloads in neutral learn mode without generated process names or fake lifecycle transitions.
  - `/api/v1/onboarding` install commands now point to executable Helm chart invocations instead of sample CR or shorthand configuration text.
  - Runtime-agent exec/file events now derive container IDs from cgroup v2 paths and resolve them through the existing CRI container inventory into `namespace/pod/<pod>` workload IDs, with an explicit `node-local/<container>` fallback only when Kubernetes labels are unavailable; discoverer now owns pod-to-deployment attribution through `pod_workload_links`, and deployment detail consumes that exact owner projection.
  - The sample scanner plugin is retained as a dev/reference SDK fixture, but its emitted smoke-test finding no longer presents itself as a placeholder vulnerability.
  - `constellationctl backup create --s3` now uploads through the AWS CLI and records `s3_uri`/`object_uri`; `--verify-key` now performs real post-write signature verification instead of being ignored.
  - The exact cleanup scan `rg -n "stub|not implemented|TODO\\(|TODO endpoint" --glob '!third_party/**'` is now clean after rewording the docker-compose empty-kubeconfig comments and test-suite README language.
- Still present:
  - Reverse-tunnel protocol support is explicitly out of scope for first stable release: Helm `astronomer.agentNamespace`/`agentService` and CRD `spec.astronomerTunnel` were removed, while `internal/tunnel` remains an internal future contract only.

Greenfield rule:

- If a feature is visible in Helm, API, CLI, or UI, it must work.
- If it does not work, remove it from the visible product surface until implemented.
- Keep internal prototypes only behind clearly named experimental flags.

Definition of done:

- `rg -n "stub|not implemented|TODO\\(|TODO endpoint"` is clean across active code, docs, deploy files, frontend source, and README.
- Every visible CLI command has tests.
- Every Helm-rendered workload maps to a real image target.
- Every UI action calls a real API or is removed.

Validation:

```bash
cd constellation
rg -n "stub|not implemented|TODO\\(|TODO endpoint" --glob '!third_party/**'
go test ./cmd/constellationctl ./internal/server ./internal/handler
go test -tags=integration ./internal/server # skips without DATABASE_URL
```

### P1.11 Documentation Truth Pass

Tasks:

- Update Constellation README from "Phase 1 scaffolded" to current actual state.
- Add architecture diagrams. Completed in `constellation/docs/architecture.md`:
  - producer VulnDB
  - Constellation consumer
  - runtime agent/DP
  - scanner flow
  - importer/update flow
- Update Helm docs for VulnDB, JWT, security contexts, and production profiles.
- Update developer setup for `go.work`.
- Add "What is greenfield and subject to change" note until first stable release. Completed in `constellation/docs/architecture.md`.

Definition of done:

- Docs do not claim unimplemented production paths work.
- Every documented command is exercised by CI or a smoke test.
- The VulnDB/Constellation boundary is documented in both repos.

## P2 Workstream: Product Completion

### P2.1 Frontend and API Completion

Tasks:

- Remove dead buttons and placeholder UI.
- Implement coverage endpoints for all frontend panels.
- Add VulnDB status and freshness UI. Completed for current bundle plus importer metadata/trust status.
- Add scanner reconciliation UI.
- Add runtime policy lifecycle UI.
- Add compliance evidence UI.
- Add registry scan UI.

Definition of done:

- No visible UI control points to missing endpoints.
- Frontend e2e tests cover core workflows.
- Empty/loading/error states are implemented.

### P2.2 Multi-Cluster and Remote Mode

Tasks:

- Finish init bundle flow. Mostly completed: API mint/list/read/rotate/revoke, Helm pre-install bundle projection, token revocation, and bundle-backed registration state are implemented; live remote install validation remains.
- Finish cluster registration. Mostly completed: Helm bootstrap upserts the cluster row/CR, cluster list and health endpoints now use real DB state, and component heartbeats drive sensor readiness; live disconnect/reconnect validation remains.
- Add Astronomer JWKS integration tests against a real Postgres mapping and JWKS server. Completed in current worktree with `internal/server` integration-tagged coverage; it skips unless `DATABASE_URL` points at a migrated Postgres.
- Decide whether Astronomer reverse-tunnel protocol support is in scope for first stable release. Completed: out of scope for first stable release.
- Keep only JWKS-backed HTTP route integration in first-release product surfaces. Completed in current worktree by removing unused reverse-tunnel Helm values and CRD fields.
- Future release only: wire the tunnel client/server protocol and agent accept path after the Astronomer multiplex contract is available and tested end to end.

Definition of done:

- A remote cluster can be installed and reports runtime/scanner/admission data. Partially covered by DB-backed API paths; live cluster validation remains blocked locally by missing Docker/kind/CNI.
- Tokens rotate.
- Cluster disconnect/reconnect behavior is tested.

## Security Findings and Required Fixes

### S1: API JWT Keys Are Not Production-Wired

Fix:

- Implement one JWT key loading mechanism and wire Helm to it.
- Make production fail without stable keys. Completed in current worktree with `CONSTELLATION_REQUIRE_JWT_KEYS=true` in Helm/systemd production examples.

Validation:

- Two API replicas issue/verify tokens across restarts.

### S2: VulnDB Import Path Writes to Read-Only Mount

Fix:

- Move writes to importer.
- API reads only.
- Replace hostPath with PVC/configurable volume.

Validation:

- Helm e2e import succeeds.
- Failed import leaves previous DB intact.

### S3: Scanner Child Env Is Replaced

Fix:

- `registryEnv` should start with `os.Environ()`.
- Append registry-specific variables.
- Add tests.

Validation:

- Proxy/cache/env tests pass.

### S4: Tool Downloads Are Not Verified

Fix:

- Verify checksums/signatures for Syft, Trivy, Grype, cosign, oras, crictl.
- Completed in current worktree with hard-coded SHA-256 verification in the scanner, scanner-driver, audit-archiver, and runtime-agent Dockerfiles.

Validation:

- Build fails on bad checksum.

### S5: Production Images and Helpers Use Floating Tags

Fix:

- Pin base/helper images to immutable versions or digests.

Current worktree status:

- Completed:
  - Dockerfile base ARGs are digest-qualified.
  - Helm bootstrap, TLS, init-bundle, migration, and embedded Postgres helper images are digest-qualified.
  - Makefile image targets publish only immutable `$(VERSION)` or `$(VERSION)-fips` tags.
  - Production sample values require signed VulnDB artifact consumption through the importer.
  - VulnDB bundle `:latest` remains only as a signed artifact update channel and is documented separately from production app/helper images.
  - CI guard rejects bare mutable production image references in the Makefile, `deploy/docker`, and the Helm chart.
  - Docker/BuildKit validation passed for the full production scanner image with the sibling VulnDB build context.

Validation:

- CI fails on bare mutable production image references in Dockerfiles/values.
- `docker buildx build --platform linux/amd64 --build-context constellation-vulndb=../constellation-vulndb -f deploy/docker/Dockerfile.scanner -t constellation/scanner:dev-vulndb-context --load .` passes.

### S6: Kubernetes Hardening Defaults Are Incomplete

Fix:

- Add security contexts, NetworkPolicies, and service account token controls.

Current worktree status:

- Completed:
  - Shared Helm security context helpers.
  - Non-root UID/GID 10001 for Constellation-owned Go runtime images.
  - Seccomp, dropped capabilities, no privilege escalation, and non-root runtime defaults on non-privileged app workloads.
  - Read-only root filesystems plus explicit writable temp/cache volumes for API, scanner, admission, operator, audit archiver, VulnDB importer, and frontend.
  - Service account token automount disabled on workloads that do not call the Kubernetes API.
  - Optional production NetworkPolicies for API, frontend, scanner, admission, runtime-agent, importer, hook jobs, and Postgres flows.
  - Bootstrap, TLS, init-bundle, migration, and bootstrap-admin hook jobs now render seccomp and restricted container contexts with writable temp/cache volumes for read-only roots.
  - Helper hook containers now render explicit non-root UID/GID, and embedded Postgres renders a configurable restricted non-root context.
  - Runtime-agent privileged/root requirements are documented as the accepted exception, including host networking/PID, capabilities, host paths, and the feature impact of disabling the DaemonSet.
- Remaining:
  - Validate NetworkPolicy behavior in a CNI-enforced cluster e2e suite.

Validation:

- Policy scanner passes with accepted exceptions only.
- Local rendered-manifest assertion confirms the runtime agent is the only privileged workload and all non-agent containers render restricted context defaults; third-party policy-engine execution remains environment/tooling-bound.

### S7: Signing Verification Policy Is Too Permissive for Production

Fix:

- Require configured key or identity/issuer in production.
- Keep permissive mode only under explicit dev flag.

Validation:

- Negative signature tests pass.

## Testing Matrix

| Layer | Tests |
|---|---|
| VulnDB unit | `go test ./...`, source parser fixtures, manifest validation, bbolt scan matching. |
| VulnDB integration | Postgres-backed store/query/bundle/quality tests with disposable DB. |
| VulnDB bundle | deterministic export, import, bbolt build, metadata, counts, scan smoke. |
| VulnDB OCI | local OCI layout push/pull, registry push/pull, digest pinning. |
| VulnDB signing | static key positive/negative, keyless positive/negative, wrong identity, wrong issuer, corrupt payload. |
| Constellation unit | auth, hostscan, vulndb, scanner, handlers, RBAC, runtime adapters. |
| Contract | Constellation consumes VulnDB `pkg/compat` fixture and rejects unsupported schema/media. |
| Scanner | Syft -> VulnDB matching, Trivy/Grype optional reconciliation, env inheritance, registry auth. |
| Host inventory | dpkg, apk, rpm, distro mapping, no host leakage in tests. |
| Helm | lint, template smoke, production values, VulnDB required/optional modes, JWT secret modes. |
| Kubernetes e2e | kind/k3s install, API readiness, importer update, runtime-agent reports, scanner scan, admission policy. |
| Runtime data plane | DP build, DP health, CNI matrix, observe/alert/block behavior, failure modes. |
| Security | govulncheck, CodeQL, container scans, SBOM, image signing, policy scanner, RBAC check. |
| Performance | VulnDB scan throughput, bbolt open time, image scan latency, runtime-agent CPU/memory under pod density. |
| Airgap | bundle generated outside cluster, imported from private registry or object storage, no public network needed. |
| Upgrade | old bundle remains during failed update, new bundle swaps atomically, API reloads without restart if desired. |

## Golden End-to-End Scenario

This scenario should become the main release gate.

Setup:

1. Build a fixture VulnDB bundle from `constellation-vulndb`.
2. Sign the bundle.
3. Push it to a local OCI layout or registry.
4. Install Constellation with VulnDB importer enabled.
5. Wait for importer to materialize `vulndb.bbolt`.
6. Confirm API `/api/v1/vulndb/status` reports the expected bundle.
7. Scan a vulnerable image with Syft + VulnDB.
8. Report host packages from a fixture node.
9. Confirm both image and host findings include the same bundle provenance.
10. Promote a network policy from discover to protect.
11. Enforce an admission rule against a known bad workload.
12. Export evidence.

Definition of done:

- The scenario runs in CI on kind or k3s.
- The test fails if VulnDB and Constellation drift.
- The test fails if importer cannot update the store.
- The test fails if scanner falls back to Trivy/Grype for canonical matching.

## Proposed Milestones

### Milestone 0: Contract Reset

Goal:

- Fix the VulnDB producer and Constellation consumer boundary.

Exit criteria:

- Constellation no longer vendors VulnDB.
- VulnDB exposes public consumer packages.
- Shared compatibility fixture exists.
- Constellation uses fixture tests.
- Constellation builds from a fresh clone.

### Milestone 1: Working VulnDB Update Path

Goal:

- Make signed VulnDB bundles flow into Constellation correctly.

Exit criteria:

- Real importer image exists.
- Helm uses PVC, not hostPath, for VulnDB store.
- API reads store and reports status.
- Production trust policy is enforceable.
- Golden importer e2e passes.

### Milestone 2: VulnDB-First Scanning

Goal:

- Make VulnDB canonical for image and host vulnerability matching.

Exit criteria:

- Syft -> VulnDB image scan works.
- Host packages -> VulnDB scan works.
- Repository package evidence -> VulnDB scan works.
- Trivy/Grype are optional reconciliation.
- OSV fallback removed from production.
- rpm package inventory works.

### Milestone 3: CI, Supply Chain, and Deployment Baseline

Goal:

- Bring Constellation up to NeuVector-like engineering discipline.

Exit criteria:

- CI exists and runs on PRs.
- Native DP build dependencies installed in CI.
- CodeQL/govulncheck/Scorecard/license checks run.
- Images are pinned and signed.
- Helm security defaults are in place.

### Milestone 4: Runtime and Policy Parity

Goal:

- Mature the NeuVector-inspired runtime path.

Exit criteria:

- DP conformance tests exist.
- CNI matrix is tested.
- Policy lifecycle works end to end.
- Admission profiles work.
- Registry scanning is scheduled and tied to VulnDB bundle changes.

### Milestone 5: Product Surface Cleanup

Goal:

- Remove visible stubs and make docs true.

Exit criteria:

- No visible feature is a stub.
- Docs match behavior.
- Frontend e2e tests cover core workflows.
- First stable release criteria are written.

## Open Design Questions

These are choices to make, not blockers:

- What exact Astronomer multiplex contract, package boundary, and e2e environment should a future reverse-tunnel release use?
- Should Constellation continue using NeuVector DP long term, or use this greenfield window to evaluate a different data plane?
- Should production admission default to fail-closed in enforce namespaces only, or globally when enabled?

Resolved decisions now reflected in the plan:

- The installer/importer binary lives in `constellation-vulndb`; Constellation schedules it only as a consumer-side install job.
- Constellation consumes VulnDB through both public Go APIs for in-process matching and producer-owned CLI/install artifacts for delivery.
- Manual upload remains available for dev/emergency paths but is policy-gated and disabled in production values by default.
- Astronomer reverse-tunnel mode is out of first stable release scope; JWKS-backed HTTP route integration is the shipped path.

## Immediate Next Actions

Recommended order:

1. Create a VulnDB public consumer API branch. Completed in current worktree.
2. Add `pkg/compat` fixture and tests. Completed in current worktree.
3. Update Constellation to consume the branch through `go.work`. Completed in current worktree.
4. Delete `third_party/constellation-vulndb` from Constellation. Completed in current worktree.
5. Replace Constellation image scan matching with VulnDB-first matching. Mostly completed; language/PURL matching, Syft distro-backed OS package matching, representative distro metadata tests, full Syft JSON-shaped parser fixtures, Trivy/Grype evidence-parser fixtures, CPE queries, base-image image repository/tag hints, package metadata repository/module-stream hints, normalized affected-range propagation, bundle provenance propagation, scanner engine toggles, in-cluster scanner VulnDB volume access, canonical-engine tracking, evidence-role provenance, stored reconciliation signals, first-class job-list bundle provenance, indexed canonical-engine search, disagreement API/UI presentation, and repository/CI attestation storage/verification/admission reuse are implemented, while captured live Syft/Trivy/Grype JSON outputs from real distro images remain environment-gated.
6. Replace Helm VulnDB importer/storage with a real source-agnostic installer and shared storage. Completed in current worktree for the planned consumer contract: source-agnostic installer, shared storage, trust/freshness policy, importer status metadata, production manual-upload disablement, and configurable API readiness behavior are implemented.
7. Add Constellation CI. Completed in current worktree.
8. Fix JWT production wiring. Completed in current worktree.
9. Persist VulnDB bundle metadata on image scan batches and findings. Completed in current worktree: metadata reaches finding detail JSON, `scan_jobs.bundle_metadata`, `GET /api/v1/scan-jobs`, coverage UI image-scan evidence, and scan completion audit events.
10. Add Kubernetes hardening defaults. Partially completed; app workload and hook job security contexts, read-only root filesystems with writable temp/cache mounts, numeric non-root runtime images, service account token automount controls, optional production NetworkPolicies, and documented runtime-agent privilege exceptions are in place, while CNI e2e policy enforcement tests remain.
11. Move scanning to the NeuVector-style target model. First foundation slices completed in current worktree: `scan_targets` owns typed target identity, scan jobs point to targets, registry and local-cluster fan-out queue target-backed jobs, scanner claim/complete carries target metadata, findings preserve target identity, host/workload/platform/serverless/repository package evidence flows through scanner workers, runtime-agent reports also create image-scoped package evidence for local images, repository/CI image scans preserve source provenance on canonical image results, image scan results persist package inventory plus SPDX/CycloneDX/redacted-secret/signature/layer/file-risk artifacts, image artifact drilldowns and compliance joins are live, UI/API clients queue typed targets, component inventory exposes scanner/importer/operator/admission/runtime-agent/API/audit-archiver state with token-file heartbeat attribution for local installs, VulnDB platform fixture/source depth now covers Kubernetes/k3s generic namespaces, `constellationctl serverless aws-lambda sync` discovers Lambda ZIP functions/layers, analyzes execution-role permission posture, posts package evidence plus first-class cloud-config findings, `constellationctl repository scan` catalogs checked-out repositories with Syft and posts package evidence for VulnDB matching with repository inventory API/UI, and repository/CI attestations can be stored, linked, displayed, verified through persisted trust policies, managed through Settings, auto-promoted on report, batch-promoted through policy actions, recorded in immutable verification history, exported with full evidence, audited through the hash chain, and reused by admission without client-forged trust. Remaining work is richer per-layer/package provenance and live generated-bundle k3s/AWS validation.
12. Remove or hide visible stubs. Completed for the current visible product surfaces: policy CLI and Abbot client are implemented, plugin optional-capability responses are accurate, audit archiver S3/signing is implemented, Astronomer JWKS route authentication and integration-tagged mapping tests are implemented, first-release reverse-tunnel Helm/CRD surfaces are removed, VulnDB importer now maps to a real binary, cluster health/list demo data was replaced with DB-backed state, system-health dated incidents/actions were removed in favor of a neutral live-probe inventory, access-control no-storage invented identities were removed, onboarding health gates and install commands now use live evidence and executable Helm chart paths, connector coverage static catalog data was replaced with DB-backed registry/scan/config/heartbeat state, the Settings connector overview now uses live connector-coverage data, the legacy integrations summary now uses live receiver/routing state, the Settings migration wizard exposes all backend-supported migration converters, integration delivery operations were replaced with DB-backed receiver/delivery/routing state plus endpoint redaction, compliance schedule mock-catalog frontend usage and the dead backend static schedule catalog were replaced with DB-backed schedule rows, compliance report generation no longer invents sample controls when no evidence rows exist, process baseline profiles now start from observed deployments in neutral learn mode without fake process lists or lifecycle history, network policy lifecycle mock workloads were removed so candidates require observed deployment/flow evidence, vulnerability exception sample users/images/CVEs were removed so the surface reflects accepted/suppressed findings and image acceptances only, admission simulation no longer returns Rancher Desktop sample resources or fallback policies, audit chain verification now reports the actual verification time, runtime-agent exec/file attribution resolves cgroup-derived container IDs through CRI inventory when available, visible frontend TODO endpoints were removed or wired to existing APIs, rpm host package inventory is implemented, and the `stub|not implemented|TODO endpoint` scan is clean. Remaining work is live Astronomer-tenant e2e only if future reverse-tunnel mode is selected.

## Appendix: Important Local References

- `constellation/go.mod`: should carry a normal VulnDB pseudo-version and no permanent local replace.
- `constellation/internal/vulndb/bundle.go`: current VulnDB bbolt consumer.
- `constellation/internal/handler/vulndb.go`: current API import/status endpoints.
- `constellation/deploy/charts/constellation/templates/api-deployment.yaml`: shared VulnDB volume and `JWT_KEYS` wiring.
- `constellation/deploy/charts/constellation/templates/vulndb-importer-cronjob.yaml`: source-agnostic scheduled installer surface.
- `constellation/deploy/charts/constellation/values.yaml`: VulnDB storage and installer source configuration.
- `constellation/cmd/constellation-api/main.go`: `JWT_KEYS` env handling, base64/raw key parser, and ephemeral fallback.
- `constellation/internal/auth/jwt.go`: HS256 signer.
- `constellation/internal/scanner/*.go`: Syft, Trivy, Grype scanner wrappers.
- `constellation/internal/runtime/hostscan/packages.go`: host package enumeration for dpkg, apk, and rpm.
- `constellation/third_party/neuvector/NOTICE`: recorded NeuVector upstream revision.
- `constellation/scripts/sync-neuvector.sh`: vendored NeuVector sync and drift workflow.
- `constellation-vulndb/docs/consumer-contract.md`: current bundle and bbolt consumer policy.
- `constellation-vulndb/docs/schema-v2.md`: product-neutral schema design.
- `constellation-vulndb/README.md`: source catalog, commands, bundle output, verification.
- `neuvector/.github/workflows`: CI, CodeQL, govulncheck, Scorecard, FOSSA examples.
