# Constellation Helm Deployment Guide

This guide walks you from a fresh Kubernetes cluster to a fully-functional
Constellation control plane using the chart at
`deploy/charts/constellation/`.

The chart is the *production* deployment path. For local laptop development
use docker-compose (see `docker-compose.yaml`); for end-to-end driver tests
see `deploy/e2e/`.

---

## When to pick Helm

| Path                     | Best for                                              |
| ------------------------ | ----------------------------------------------------- |
| docker-compose           | local dev, no Kubernetes needed                       |
| deploy/e2e               | CI smoke tests against ephemeral k3d clusters         |
| **Helm (this guide)**    | every shared/staging/prod cluster: EKS, GKE, AKS, k3s |

The chart deploys:

- api (Deployment + Service)
- operator (Deployment + ClusterRole + ServiceAccount)
- discoverer (Deployment + read-only Kubernetes inventory RBAC)
- admission webhook (Deployment + Service + ValidatingWebhookConfiguration)
- scanner (Deployment)
- runtime-agent (DaemonSet)
- frontend nginx (Deployment + Service + optional Ingress)
- optional audit-archiver CronJob
- embedded pgvector StatefulSet (optional; off in prod)
- bootstrap Jobs (TLS certs + service tokens)
- optional namespace NetworkPolicies with default-deny and explicit flows

## Three-node HA and shared Gateway

`examples/values-k3s-ha.yaml` is the reference profile for the three-node K3s
deployment at `constellation.dev.alphabravo.io`. It enables three API,
frontend, scanner, and admission replicas; two leader-elected operator
replicas; two discoverers and policy appliers; node-level, revision-aware
topology spreading; and a `maxUnavailable: 1` PDB for every replicated
Deployment. The runtime agent remains a per-node DaemonSet with its own PDB.

The profile creates an HTTPRoute attached to the shared
`platform-gateway/public` HTTPS listener. TLS for the public hostname belongs
to that Gateway and is not duplicated by this chart. Admission-webhook TLS is
a separate private certificate: the profile creates a namespaced self-signed
cert-manager Issuer because a public ACME issuer cannot issue Kubernetes
`.svc` names.

PostgreSQL uses CloudNativePG. `instances: 1` is supported for small installs;
HA mode fails Helm rendering unless it has at least three instances. The
release includes a CNPG-compatible pgvector operand image. Before calling an
installation production-ready, configure `postgres.cloudnativepg.backup`,
enable `scheduledBackup`, and prove a point-in-time restore. Longhorn can be
selected explicitly and remains the cluster-default CSI in the K3s profile.
When NetworkPolicies are enabled, the chart also permits the documented CNPG
operator-to-instance traffic on ports 8000 and 5432; change
`networkPolicies.cnpgOperator` if the operator uses another namespace or label.

Run `make release-check VERSION=v0.2.0` before publishing. After images are
published, run the same command with `VERIFY_PUBLISHED=1`; it fails unless
every role image has a trusted keyless signature and source-bound SLSA
provenance.

---

## Building Images Locally

The scanner image builds from this repository and includes Syft, Trivy, and
Grype; it does not require the retired `constellation-vulndb` checkout:

```bash
make image-scanner
make images
```

The normal scanner image refreshes its Trivy and Grype databases at runtime.
For a disconnected first boot, build `make image-scanner-airgap` or pre-load
the scanner caches as described in `docs/offline-scanning.md`.

---

## Recommended: install via cluster init-bundle (multi-cluster path)

When you operate Constellation across more than one cluster, the **preferred**
install path is to pre-mint a cluster init-bundle on the control plane and ship
it to ops to install on the remote cluster. The bundle is a single YAML file
containing the cluster's scoped tokens, admission webhook TLS material, and an
audit HMAC secret — minted by the control plane so the new cluster's credentials
are known and rotatable from one place.

This is Constellation's analogue of StackRox's `roxctl central init-bundles
generate` workflow.

```bash
# On the control plane (authoring admin):
constellationctl --server https://constellation.example.com cluster create prod-us-east-1 \
    --distro=k3s --region=us-east-1 --expiry=720h \
    --output cluster-init.yaml

# Ship cluster-init.yaml to the operator of the new cluster, then on that cluster:
kubectl create ns constellation-system
kubectl -n constellation-system create secret generic constellation-init-bundle \
    --from-file=bundle.yaml=cluster-init.yaml

helm install constellation deploy/charts/constellation \
    -n constellation-system \
    --set initBundle.secretName=constellation-init-bundle
```

When `initBundle.secretName` is set, the chart switches into consumer mode:

- The token bootstrap-job is **skipped** (no fresh scanner / runtime-agent
  tokens are minted; the bundle-supplied ones are projected verbatim).
- The TLS bootstrap-job is **skipped** (the bundle-supplied CA + cert/key are
  projected into `constellation-admission-tls`).
- A small pre-install consumer Job (`templates/initbundle-consumer-job.yaml`)
  reads `bundle.yaml` and writes its components into the chart-managed Secrets
  before any application Pod boots.

Rotate or revoke a bundle anytime from the control plane:

```bash
constellationctl --server https://constellation.example.com cluster list
constellationctl --server https://constellation.example.com cluster rotate <bundle-id>
constellationctl --server https://constellation.example.com cluster revoke <bundle-id>
```

The UI offers the same wizard at **Clusters → Register cluster**, with an
inline table of active / expired / revoked bundles and one-click Rotate /
Revoke buttons.

The self-mint path described below (bootstrap-job + tls-bootstrap-job) remains
the **demo / single-cluster** fallback — turn it off in production by setting
`initBundle.secretName`.

---

## Quickstart

### k3d (local)

```bash
k3d cluster create constellation --servers 1 --agents 1 -p "8443:443@loadbalancer"
make deploy NS=constellation-system
kubectl -n constellation-system rollout status deploy/constellation-api
kubectl -n constellation-system port-forward svc/constellation-frontend 8080:80
# open http://localhost:8080
```

### Bare-metal k3s

```bash
helm upgrade --install constellation deploy/charts/constellation \
  -n constellation-system --create-namespace \
  -f deploy/charts/constellation/examples/values-k3s.yaml
```

### Amazon EKS

```bash
# Create the RDS credentials secret first.
kubectl -n constellation-system create secret generic constellation-db-credentials \
  --from-literal=url="postgres://user:pass@constellation.rds.amazonaws.com:5432/constellation?sslmode=require"

helm upgrade --install constellation deploy/charts/constellation \
  -n constellation-system --create-namespace \
  -f deploy/charts/constellation/examples/values-prod.yaml
```

### Google GKE

```bash
helm upgrade --install constellation deploy/charts/constellation \
  -n constellation-system --create-namespace \
  -f deploy/charts/constellation/examples/values-gke.yaml
```

---

## TLS for the admission webhook

The admission webhook requires TLS — apiserver refuses to call HTTP webhooks.
The chart supports two paths, picked via `values.yaml`:

### 1. Bootstrap Job (default, no external dependencies)

```yaml
tls:
  certManager:
    enabled: false
  bootstrap:
    enabled: true
```

On every `helm install`/`helm upgrade` a pre-install Job:

1. Mints a self-signed CA + server cert for
   `constellation-admission.<namespace>.svc` (SANs cover all four service-DNS
   variants).
2. Stores cert/key/CA in Secret `<release>-admission-tls`.
3. Patches the ValidatingWebhookConfiguration's `caBundle` so the apiserver
   trusts the cert.

The Job is idempotent: subsequent runs reuse an existing valid cert. To
rotate, delete the Secret and run `helm upgrade`.

### 2. cert-manager (recommended for prod)

Install cert-manager once on the cluster, create a `ClusterIssuer`
(`letsencrypt-prod` or an internal CA), then:

```yaml
tls:
  certManager:
    enabled: true
    issuer: letsencrypt-prod
    issuerKind: ClusterIssuer
  bootstrap:
    enabled: false
```

The chart renders a `cert-manager.io/v1 Certificate` resource. cert-manager
provisions and renews the certificate (1y duration, 30d renewBefore) and the
`cert-manager.io/inject-ca-from` annotation tells cert-manager to populate
the webhook's `caBundle`.

### Verifying

```bash
kubectl run privileged-test --image=nginx --restart=Never --privileged
# Expect: Error from server: admission webhook "pods.constellation.alphabravo.io" denied the request
```

A pure HTTP webhook would produce `x509: failed to load system roots` errors
in the apiserver log; if you see the deny message above, signed TLS is
working end-to-end.

---

## Service tokens (scanner + runtime-agent)

The post-install bootstrap Job:

1. Waits for Postgres + API migrations.
2. Creates a default org row (`default`) if absent.
3. Mints two random tokens (32 raw bytes hex), inserts their sha256 into
   `scanner_tokens` / `runtime_agent_tokens`, and stores the raw token in:
   - `<release>-scanner-token` (key `token`)
   - `<release>-runtime-agent-token` (key `token`)
4. Optionally upserts a `ConstellationCluster` CR named after the namespace.

The scanner Deployment reads `CONSTELLATION_SCANNER_TOKEN` + `SCANNER_TOKEN`
from the first Secret. It uses Syft, Trivy, and Grype, with scanner database
caches under `/var/lib/scanner-cache`. The runtime-agent DaemonSet reads
`RUNTIME_AGENT_TOKEN` from the second Secret.

To override the bootstrap mint with a pre-existing token Secret:

```yaml
scanner:
  tokenSecret: my-scanner-credentials
runtimeAgent:
  tokenSecret: my-runtime-agent-credentials
```

---

## NetworkPolicies

The default values keep NetworkPolicies disabled so k3d/k3s/dev clusters with
partial or non-enforcing CNIs still install cleanly. Production values should
enable them:

```yaml
networkPolicies:
  enabled: true
  kubeAPI:
    cidrs: ["10.0.0.0/8"]
  externalPostgres:
    cidrs: ["10.0.0.0/8"]
  frontendIngressCIDRs: ["10.0.0.0/8"]
  admissionIngressCIDRs: ["10.0.0.0/8"]
```

When enabled, the chart renders a namespace default-deny policy and explicit
allows for frontend-to-API, scanner/runtime-agent-to-API, API/jobs/admission to
Postgres, hook Jobs to the Kubernetes API, DNS, and HTTPS egress for registry,
S3, OCI, OIDC, and webhook integrations. Native NetworkPolicy cannot address
the Kubernetes API server, ingress controllers, or managed databases by Service
name, so tighten the CIDR defaults to your cluster, VPC, control-plane, ingress,
and RDS/Cloud SQL ranges.

The Network Map policy lifecycle has a separate applier Deployment. It watches
approved lifecycle rows in Postgres and applies only protect-mode manifest
bundles to the cluster. Demoted or rolled-back rows delete the managed resource.
The default flavor is native Kubernetes `NetworkPolicy`; switch to `cilium` or
`calico` only when the matching CRDs are installed:

```yaml
networkPolicyApplier:
  enabled: true
  flavor: native # native | cilium | calico
  # Prefer clusterId in multi-cluster installs. clusterName falls back to
  # clusterRegistration.name, then the Helm release namespace.
  clusterId: ""
  clusterName: ""
```

The Kubernetes compliance collector is a read-only CronJob that records direct
object evidence for Compliance. It lists Namespaces, ClusterRoles, Deployments,
StatefulSets, and DaemonSets; expands findings into the existing compliance
framework mappings; and replaces only rows it previously wrote with
`collector=constellation-k8s-object` evidence. Those rows feed
`/api/v1/compliance/evidence` and scheduled compliance artifacts.

```yaml
kubernetesComplianceCollector:
  enabled: true
  schedule: "17 */6 * * *"
  namespaceFilter: "*"
  includeSystemNamespaces: false
  clusterId: ""
  clusterName: ""
```

---

## Runtime-Agent Privilege Exception

The runtime-agent DaemonSet is the intentional exception to the chart's
non-privileged app workload defaults. It runs on every node with `hostPID`,
`hostNetwork`, `securityContext.privileged=true`, and the capabilities
`SYS_ADMIN`, `BPF`, `NET_ADMIN`, and `SYS_RESOURCE`.

Those permissions are required for the node-local data plane:

- eBPF program loading and BTF discovery use `/sys`, `/sys/fs/bpf`, and
  `/sys/kernel/btf`.
- Process and host package attribution use host PID context plus read-only
  host views under `/host/proc`, `/host/etc`, and `/host/lib/modules`.
- NeuVector-style packet inspection/enforcement needs host networking,
  pod-veth discovery, CNI config reads, and NFQUEUE/iptables access.
- CRI socket discovery reads `/host/run` and `/host/var/run` so workload
  identity can be correlated with runtime events.

The mounted host paths are intentionally narrow and are read-only except for
`/sys/fs/bpf`, which must be writable for BPF object pinning. The runtime-agent
does not receive the shared app workload security context because that would
break BPF and network enforcement. If a cluster policy disallows privileged
DaemonSets, set `runtimeAgent.enabled=false`; image scanning, admission, and API
workflows continue to run, but runtime telemetry, reachability confirmation, and
inline network enforcement are disabled.

---

## Operator RBAC

`namespaced=true` is the default. In that mode the operator watches namespaced
resources only in the Helm release namespace and receives a namespaced Role for
services, deployments, daemonsets, cronjobs, HPAs, leases, and events.

The `ConstellationCluster` CRD is cluster-scoped, so the operator still receives
a small ClusterRole for `constellationclusters` and `constellationclusters/status`.
Set `namespaced=false` only when the operator should reconcile managed workloads
across namespaces; the chart then renders the workload permissions as a
ClusterRole.

---

## Vulnerability Databases

The active scanner uses Syft for package/SBOM inventory and Trivy plus Grype
for vulnerability matching. `scanner.engines.*` selects those engines. The
scanner refreshes its own vulnerability databases according to
`scanner.vulnDB.refreshInterval`; `scanner.vulnDB.offline=true` disables
internet refreshes and requires pre-loaded data. With one scanner replica,
`scanner.cache.persistent=true` mounts a dedicated PVC for the caches. A
multi-replica scanner uses pod-local caches instead of sharing a RWO claim.

The API's `cve_records` catalog is separate from those scanner caches and is
updated by the live KEV/EPSS importers; NVD enrichment is opt-in through system
configuration. The old `constellation-vulndb` bundle importer and its Helm
values are not part of the active chart. The `scanner.vulnDB` value name refers
to Trivy/Grype cache refresh settings, not that retired producer.

---

## Audit Archiver

`auditArchiver.enabled=true` creates a CronJob that verifies the full audit hash
chain before exporting the selected rolling window to S3 as gzip JSONL plus an
adjacent manifest. The job uses the AWS SDK default credential chain, so use
IRSA/workload identity or inject explicit AWS env vars through
`auditArchiver.env`.

For signed manifests, use `auditArchiver.sign.mode=static-key` with a Secret
containing an ed25519 private key generated by `constellationctl backup gen-key`,
or `auditArchiver.sign.mode=keyless` when the image has `cosign` and an ambient
OIDC token.

```yaml
auditArchiver:
  enabled: true
  bucket: constellation-audit-prod
  prefix: constellation/audit
  sign:
    mode: static-key
    keySecretName: constellation-audit-signing
    keySecretKey: cosign.key
```

---

## Astronomer Integration

`astronomer.enabled=true` exposes `/api/v1/security/*` routes that validate
Astronomer-issued JWTs against `astronomer.jwksURL`. Set
`astronomer.jwtIssuer` and `astronomer.jwtAudience` when the Astronomer token
contract is known so Constellation rejects tokens signed by the same JWKS for
other audiences.

Each Astronomer principal must be linked before it can use Constellation:
`astronomer_identity_map.astronomer_user_id` stores the JWT `sub` value and maps
it to an existing Constellation `users.id` and `orgs.id`. Unmapped, deleted, or
disabled users are rejected before RBAC checks run.

```yaml
astronomer:
  enabled: true
  jwksURL: https://astronomer.example/.well-known/jwks.json
  jwtIssuer: https://astronomer.example
  jwtAudience: constellation-security
```

---

## Signed support bundles

Support-bundle signing is optional and uses a dedicated Ed25519 PKCS#8 PEM key,
not the API's JWT or federation keys. Keep the private key in an existing
Kubernetes Secret; the chart never creates or embeds it in Helm values.

```bash
openssl genpkey -algorithm Ed25519 -out support-bundle-signing-key.pem
kubectl -n constellation-system create secret generic constellation-support-bundle-signing \
  --from-file=private-key.pem=support-bundle-signing-key.pem
helm upgrade constellation deploy/charts/constellation -n constellation-system \
  --reuse-values --set api.supportBundleSigningKeySecret=constellation-support-bundle-signing
```

The API reads the mounted key from
`CONSTELLATION_SUPPORT_BUNDLE_SIGNING_KEY_FILE` when generating a bundle. A
configured but missing or invalid key makes the request fail rather than return
an unsigned bundle. Without the setting, bundles remain explicitly unsigned.
The optional `api.supportBundleSigningKeySecretKey` value changes the Secret
data key from its default `private-key.pem`.

For a signed bundle, first recompute `integrity.sha256` from the redacted
`sections` object using Go `encoding/json` serialization. Then verify the
base64 Ed25519 `integrity.signature` over the UTF-8 string formed by joining
these lines with `\n` and **no trailing newline**:

1. `constellation.support_bundle.signature.v1`
2. `schema_version`
3. `bundle_id`
4. `generated_at` normalized to UTC RFC3339Nano
5. `org_id`
6. `integrity.sha256`

`integrity.public_key` is the base64 raw Ed25519 public key and
`integrity.key_id` is its lowercase SHA-256 hex fingerprint. Pin the expected
public key or fingerprint through a separate trusted channel; a key carried in
the bundle alone does **not** authenticate who signed it. Retain old public
keys when rotating the Secret so older bundles remain verifiable.

From the repository root, verify a downloaded bundle with the standalone
offline command and a fingerprint obtained independently of the bundle:

```bash
GOWORK=off go run ./cmd/constellation-support-bundle-verify \
  --file support-bundle.json --key-id "$PINNED_SUPPORT_BUNDLE_KEY_ID"
```

The verifier checks the redacted sections hash, signing-key fingerprint,
bundle identity signature, and Ed25519 signature. It rejects unsigned bundles,
untrusted keys, malformed input, and tampering.

## Asynchronous support-bundle jobs

System Health's **Bundle jobs** tab queues redacted bundles and shows persisted
job history, expiry, and a link to each job's audit/download history. Component
diagnostics can queue the same job and link to System Health. The original
`GET /api/v1/support/bundle` endpoint remains available for synchronous CLI
downloads.

The job API requires `manage_system_config`:

| Method | Path | Result |
|---|---|---|
| `POST` | `/api/v1/support/bundle/jobs` | Persist a queued job; returns `202` with its ID and audit link. |
| `GET` | `/api/v1/support/bundle/jobs?limit=50` | List newest jobs; follow `next_cursor` for older pages. |
| `GET` | `/api/v1/support/bundle/jobs/{id}` | Read queued, running, ready, failed, or expired status. |
| `GET` | `/api/v1/support/bundle/jobs/{id}/download` | Download a ready bundle; returns `409` while pending or `410` after expiry. |

The audit-history link uses
`GET /api/v1/audit/events?support_bundle_job_id={id}` (requires `read_audit`) to
show every create, completion and download receipt for that job.

API replicas claim jobs through PostgreSQL, so queued work survives a replica
restart and stale leases are recovered. Only verified, redacted bundle JSON is
stored. Ready and failed jobs expire after seven days; expiry clears the stored
payload. Creation and download fail closed when their audit receipt cannot be
written. Worker completion waits for a retried audit receipt before advertising
a bundle as ready for download. The deployment signing key above also signs
asynchronous bundles.

## Values reference

| Key                                   | Default                                              | When to change                                                  |
| ------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------- |
| `image.registry`                      | `ghcr.io/alphabravocompany/constellation`            | Mirror to private registry                                      |
| `image.tag`                           | `""` (uses `.Chart.appVersion`)                      | Pin to a SHA-stable tag                                         |
| `image.pullPolicy`                    | `IfNotPresent`                                       | Set to `Always` for floating tags                               |
| `image.pullSecrets`                   | `[]`                                                 | Required for private registries                                 |
| `revisionHistoryLimit`                | `3`                                                  | Raise only if you need more in-cluster rollback history          |
| `migrate.psqlImage`                   | digest-pinned `postgres:16.10-alpine3.22`            | Mirror/pin the Postgres client helper image                     |
| `security.podSecurityContext.enabled` | `true`                                               | Apply shared pod hardening to non-privileged app workloads      |
| `security.containerSecurityContext.enabled` | `true`                                        | Drop caps, disallow escalation, run Go/distroless roles as UID/GID 10001, and keep app root filesystems read-only |
| app workload service account automount | `false` for API/scanner/admission/frontend/importer/archiver | Keep Kubernetes API tokens off pods that do not need them |
| `networkPolicies.enabled`              | `false`                                              | Enable namespace default-deny and explicit component flows in production |
| `networkPolicies.kubeAPI.cidrs`         | `["0.0.0.0/0"]`                                      | CIDRs for the Kubernetes API server used by operator/bootstrap/TLS jobs |
| `networkPolicies.externalPostgres.cidrs`| `["0.0.0.0/0"]`                                      | CIDRs for external managed Postgres when `postgres.embedded=false` |
| `networkPolicies.frontendIngressCIDRs`  | `["0.0.0.0/0"]`                                      | Ingress-controller/client CIDRs allowed to reach frontend pods |
| `networkPolicies.admissionIngressCIDRs` | `["0.0.0.0/0"]`                                      | Kubernetes API/control-plane CIDRs allowed to call the webhook |
| `api.replicas`                        | `2`                                                  | Bump for HA                                                     |
| `api.jwtKeysSecret`                   | `""`                                                 | Existing Secret with JWT signing keys at key `keys`; empty renders a chart-managed Secret |
| `api.supportBundleSigningKeySecret`  | `""`                                                 | Existing Secret with an Ed25519 PKCS#8 PEM signing key; empty leaves support bundles unsigned |
| `api.supportBundleSigningKeySecretKey` | `private-key.pem`                                  | Data key within that Secret |
| `api.requireJWTKeys`                  | `true`                                               | Refuse API startup when `JWT_KEYS` is absent; keep true outside one-off dev overrides |
| `operator.replicas`                   | `1`                                                  | Keep at 1; operator uses leader-election leases                 |
| `discoverer.enabled`                  | `true`                                               | Populate local cluster workloads, pod/service IPs, and workload risk rollups |
| `discoverer.namespaceFilter`          | `*`                                                  | Comma-separated namespace globs; `kube-system` is always excluded |
| `discoverer.reconcileInterval`        | `30s`                                                | Poll cadence for Kubernetes inventory refresh                   |
| `discoverer.orgID`                    | `""`                                                 | Set when multiple orgs can register same-named clusters         |
| `discoverer.clusterName`              | `""`                                                 | Fallback cluster lookup by name; defaults to registration name / namespace |
| `networkPolicyApplier.enabled`        | `true`                                               | Apply approved Network Map lifecycle policies in-cluster         |
| `networkPolicyApplier.flavor`         | `native`                                             | Use `cilium` or `calico` only when those CRDs are installed      |
| `networkPolicyApplier.clusterId`      | `""`                                                 | Prefer explicit cluster UUID for multi-cluster installs          |
| `networkPolicyApplier.clusterName`    | `""`                                                 | Fallback cluster lookup by name; defaults to registration name / namespace |
| `networkPolicyApplier.interval`       | `15s`                                                | Poll cadence for approved lifecycle rows                         |
| `kubernetesComplianceCollector.enabled` | `true`                                             | Run the read-only Kubernetes object compliance CronJob            |
| `kubernetesComplianceCollector.schedule` | `17 */6 * * *`                                    | Cron cadence for direct Kubernetes object evidence collection     |
| `kubernetesComplianceCollector.namespaceFilter` | `*`                                      | Comma-separated namespace globs; supports `!` exclusions          |
| `kubernetesComplianceCollector.includeSystemNamespaces` | `false`                              | Include `kube-system`, `kube-public`, and `kube-node-lease` in object checks |
| `kubernetesComplianceCollector.clusterId` | `""`                                            | Prefer explicit cluster UUID for multi-cluster installs           |
| `kubernetesComplianceCollector.clusterName` | `""`                                          | Fallback cluster lookup by name; defaults to registration name / namespace |
| `admission.replicas`                  | `2`                                                  | 2-3 for HA                                                      |
| `admission.webhook.failurePolicy`     | `Ignore`                                             | Switch to `Fail` once you have multi-AZ HA                      |
| `admission.webhook.namespaceSelector` | `{}`                                                 | Scope enforcement to labeled namespaces only                    |
| `scanner.replicas`                    | `2`                                                  | Scale with job queue depth                                      |
| `scanner.engines.syft`                | `true`                                               | Package and SBOM inventory                                       |
| `scanner.engines.trivy`               | `true`                                               | Trivy image and package vulnerability matching                  |
| `scanner.engines.grype`               | `true`                                               | Grype image and package vulnerability matching                  |
| `scanner.vulnDB.refreshInterval`      | `6h`                                                 | Trivy/Grype database refresh cadence                            |
| `scanner.vulnDB.offline`              | `false`                                              | Disable internet database refreshes; pre-load for offline use   |
| `scanner.cache.persistent`            | `true`                                               | Use a cache PVC with one non-autoscaled scanner replica         |
| `scanner.cache.size`                  | `8Gi`                                                | Scanner cache PVC size                                           |
| `frontend.replicas`                   | `2`                                                  | Behind an ingress controller                                    |
| `runtimeAgent.tolerations`            | tolerate all NoSchedule/NoExecute                    | DaemonSet must land on every node                               |
| `postgres.embedded`                   | `true`                                               | **Always set to `false` in prod**                               |
| `postgres.dsn`                        | `""`                                                 | DSN string (alternative to existingSecret)                      |
| `postgres.existingSecret`             | `""`                                                 | Reference an externally-managed Postgres Secret                 |
| `postgres.embeddedConfig.image`       | digest-pinned `pgvector/pgvector:pg16`               | Mirror or upgrade the dev/test embedded Postgres image          |
| `postgres.embeddedConfig.storage`     | `20Gi`                                               | Sizing for the embedded PVC                                     |
| `postgres.embeddedConfig.storageClass`| `""`                                                 | Override the cluster default StorageClass                       |
| `tls.certManager.enabled`             | `false`                                              | Set true when cert-manager is installed                         |
| `tls.bootstrap.enabled`               | `true`                                               | Set false when using cert-manager                               |
| `ingress.enabled`                     | `false`                                              | Expose the frontend Service via Ingress                         |
| `ingress.className`                   | `""`                                                 | `nginx`, `traefik`, `alb`, `gce`, …                             |
| `ingress.host`                        | `constellation.example.com`                          | Your DNS hostname                                               |
| `ingress.tls.enabled`                 | `false`                                              | Enable TLS termination on the Ingress                           |
| `clusterRegistration.name`            | `""` (uses `.Release.Namespace`)                     | Cluster name shown in the Constellation UI                      |
| `bootstrap.org.name`                  | `default`                                            | Org row name (must be unique across the install)                |
| `auditArchiver.enabled`               | `false`                                              | Enable scheduled hash-chain-verified audit export to S3          |
| `auditArchiver.bucket`                | `""`                                                 | Required when audit archiver is enabled                          |
| `auditArchiver.sign.mode`             | `none`                                               | Set `static-key` or `keyless` to emit signed manifests           |
| `auditArchiver.sign.keySecretName`    | `""`                                                 | Secret containing the static signing key when `mode=static-key`  |
| `astronomer.enabled`                  | `false`                                              | Enable `/api/v1/security/*` routes authenticated with Astronomer JWKS |
| `astronomer.jwksURL`                  | `""`                                                 | Required when `astronomer.enabled=true`                              |
| `astronomer.jwtIssuer`                | `""`                                                 | Optional required `iss` claim for Astronomer JWTs                    |
| `astronomer.jwtAudience`              | `""`                                                 | Optional required `aud` claim for Astronomer JWTs                    |
| `ai.enabled`                          | `false`                                              | Enable Abbot GenAI integration                                  |
| `fips.enabled`                        | `false`                                              | Switch to FIPS-validated base images for every role             |

---

## Upgrade flow

```bash
git pull
helm dependency update deploy/charts/constellation 2>/dev/null || true
helm diff upgrade constellation deploy/charts/constellation -n constellation-system
helm upgrade constellation deploy/charts/constellation \
  -n constellation-system -f ops/values-prod.yaml
kubectl -n constellation-system rollout status deploy/constellation-api
```

The pre-install Job runs again on `helm upgrade`; it reuses the existing TLS
secret + tokens. The post-install Job re-runs idempotently. CRD updates are
**not** applied automatically by Helm — apply them manually:

```bash
kubectl apply -f deploy/charts/constellation/crds/
```

### Rollback

```bash
helm history constellation -n constellation-system
helm rollback constellation <REV> -n constellation-system
```

Rolling back does **not** revert Postgres schema migrations. Treat schema
changes as forward-only.

---

## Make targets

| Target                  | What it does                                                    |
| ----------------------- | --------------------------------------------------------------- |
| `make helm-lint`        | `helm lint deploy/charts/constellation`                         |
| `make helm-template-smoke` | render the chart with several value combos; fails on errors  |
| `make deploy`           | `helm upgrade --install` with `CLUSTER=`, `NS=`, `VALUES=` knobs |
| `make deploy-dryrun`    | dry-run with `--debug`                                          |
| `make undeploy`         | `helm uninstall`                                                |
| `make values-prod`      | scaffold `ops/values-prod.yaml` from the EKS sample             |

---

## Troubleshooting

**Admission webhook denies everything (`failurePolicy: Fail`)**

Confirm the webhook Pods are Ready and the cert has the right SAN:

```bash
kubectl -n constellation-system get pods -l app.kubernetes.io/component=admission
kubectl -n constellation-system get secret constellation-admission-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -text | grep DNS
```

If you switch from bootstrap to cert-manager (or vice versa), delete the
existing Secret + ValidatingWebhookConfiguration first.

**Scanner pod looping 401**

Re-run the bootstrap Job:

```bash
kubectl -n constellation-system delete job constellation-bootstrap
helm upgrade constellation deploy/charts/constellation -n constellation-system
```

**Runtime-agent has no `RUNTIME_AGENT_TOKEN`**

Same fix as scanner. The Secret is `optional: true` on the DaemonSet so the
agent boots in stdout-only mode without a token.
