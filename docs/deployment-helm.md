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
- CloudNativePG `Cluster` running the chart's pgvector operand image (the
  default `postgres.mode=cnpg`; `external` points at an operator-managed DSN)
- optional in-cluster backup object store (`backup.objectStore`: RustFS +
  Barman Cloud `ObjectStore` + bucket Job) for CNPG WAL archiving
- bootstrap Jobs (TLS certs + service tokens)
- optional namespace NetworkPolicies with default-deny and explicit flows
- optional Prometheus Operator `ServiceMonitor` for the API admin listener

Helm is the only supported deployment path (ADR 0007). There is no embedded
single-replica Postgres any more: in-cluster Postgres is always CloudNativePG,
so the CNPG operator is a prerequisite for the default install.

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
installation production-ready, point `postgres.cloudnativepg.barmanCloud` at
an off-host `ObjectStore` (or enable the in-cluster `backup.objectStore` for
development), enable `scheduledBackup`, and prove a point-in-time restore
(see `docs/cnpg-recovery.md`). Longhorn can be selected explicitly and remains
the cluster-default CSI in the K3s profile.
When NetworkPolicies are enabled, the chart also permits the documented CNPG
operator-to-instance traffic on ports 8000 and 5432; change
`networkPolicies.cnpgOperator` if the operator uses another namespace or label.

Run `make release-check VERSION=v0.3.0` before publishing. After images are
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
# Once per cluster: the CloudNativePG operator (not bundled by the chart).
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.24/releases/cnpg-1.24.1.yaml

helm upgrade --install constellation deploy/charts/constellation \
  -n constellation-system --create-namespace \
  -f deploy/charts/constellation/examples/values-k3s.yaml
```

The k3s profile runs a single CNPG instance on `local-path` storage; raise
`postgres.cloudnativepg.instances` to 3 for HA.

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
Postgres, CNPG instance-to-instance and operator traffic, the Barman sidecar to
the in-cluster object store (when `backup.objectStore.enabled`), hook Jobs to
the Kubernetes API, DNS, and HTTPS egress for registry, S3, OCI, OIDC, and
webhook integrations. Native NetworkPolicy cannot address the Kubernetes API
server, ingress controllers, or managed databases by Service name, so tighten
the CIDR defaults to your cluster, VPC, control-plane, ingress, and RDS/Cloud
SQL ranges.

The API admin listener (port 9090, `/metrics`) is reachable from any pod in the
release namespace; add a monitoring namespace with
`api.metrics.allowFrom: { kubernetes.io/metadata.name: monitoring }`. Kubelet
readiness/liveness probes come from the node, not from a pod, so default-deny
does not block them on the supported CNIs.

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
services, deployments, daemonsets, cronjobs, HPAs, leases, and events. The
leases/events grants back `operator.leaderElection.enabled` (default `true`),
so `operator.replicas` can be raised without a second reconciler running. The
chart always passes the managed-workload image flags (`--agent-image`,
`--runtime-agent-image`, `--scanner-image`, `--admission-image`) derived from
the same role images it deploys; the operator has no `:latest` fallback.

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

## Storage health monitoring

The API exposes bounded read-only database storage metrics on its admin listener.
Enable `metrics.prometheusRule.enabled` for the storage warning group and
`metrics.storageDashboard.enabled` for the Grafana dashboard ConfigMap. Both
parent features remain disabled by default. Tune
`metrics.prometheusRule.storage` warning budgets for the installation.

These rules require the API ServiceMonitor (or equivalent namespace/service
labels), and they distinguish collector failure, active archive lag and overdue
organization backups. They do not enable cleanup or establish PITR coverage.
See [storage health metrics and operating limits](storage-health.md) for metric
semantics, all ten implementation items, alert tests and safe response steps.

## Audit Archiver

`auditArchiver.enabled=true` creates a CronJob that catches up the global audit
chain in bounded ID order. It signs each segment, uploads it to S3 and verifies
an independent download before committing its durable cursor. Backdated events
are included. The default schedule is every five minutes with 1,000 rows per run;
size both settings for the backlog and arrival rate.

The job uses AWS SDK credentials with PUT and GET permission. Static-key signing
requires a Secret containing the private key and trusted public key. Keyless mode
requires `auditArchiver.sign.verifyIdentity`, `cosign` and ambient OIDC credentials.
Unsigned durable archives are rejected. The old `window` setting is replaced by
`batchSize`.

```yaml
auditArchiver:
  enabled: true
  bucket: constellation-audit-prod
  prefix: constellation/audit
  batchSize: 1000
  sign:
    mode: static-key
    keySecretName: constellation-audit-signing
    keySecretKey: cosign.key
    verifySecretKey: cosign.pub
```

See [audit archive publication and offline verification](audit-archive.md) for
failure/retry semantics, migration requirements and the remaining immutable
storage/recovery gates. The archiver never prunes the source ledger.

---

## Single sign-on provider (OIDC)

Constellation is a plain OIDC relying party. Configure one provider through Helm:

```yaml
auth:
  oidc:
    enabled: true
    issuerURL: https://identity.example.com
    clientID: constellation
    clientSecretName: constellation-oidc # existing Secret, key client-secret
    audience: constellation
    redirectURL: https://constellation.example.com/api/v1/auth/oidc/callback
    rolesClaim: alphabravo_roles
    roleMapping:
      security-admins: SecurityAdmin
      analysts: Analyst
    orgName: default
```

The roles claim accepts a flat string/array, or the platform object
`{"constellation":["security-admins"]}`. Mapping is exact and grants no default
role. Other claim names (for example `groups`) work directly against an existing
external provider. Request the client’s own audience; no cross-project audience
scopes are required. Configure ID and access token lifetimes to **ten minutes or
less**, with `iat`, `exp` and a stable `sub`. HTTPS discovery and endpoints are
mandatory. Settings → Sign-in methods edits local policy and the provider role map. Provider
secrets edited there are age encrypted in Postgres. Replicas reload within two seconds.
Changed chart values replace the saved policy on rollout; unchanged values preserve UI edits.

The browser uses authorization code + PKCE and a one-use, cookie-bound nonce/state
record. It receives an opaque, HttpOnly, Secure host cookie that expires with the
verified ID token. No local refresh extends the role lifetime. Removing a group
removes access on the next token, within ten minutes. Logout ends local sessions;
the provider’s SSO session remains active. `constellationctl login --server …`
reads an OIDC access token or API token from stdin and validates it before saving
it to the protected local config file.

This destructive identity cutover requires a CNPG backup first. Migration 187
drops legacy provider configuration, passwords, policies and refresh sessions.
Roll the API and frontend together; old API builds cannot use the new schema.
SSO identities are keyed by issuer + subject and never auto-linked by email.

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

## Metrics and the admin listener

Every Go role serves `/healthz`, `/readyz` and `/metrics` on an admin listener
(`ADMIN_LISTEN_ADDR`, `:9090`, container port `admin`); the API additionally
serves pprof there when enabled. Metrics are never on the API port, so they are
not reachable through the Ingress/Gateway `/api` route. The chart:

- sets `prometheus.io/scrape|port|path` annotations on API pods
  (`api.metrics.annotations`, default `true`);
- exposes `admin` (9090) on the API Service;
- optionally renders a `monitoring.coreos.com/v1 ServiceMonitor`
  (`api.metrics.serviceMonitor.enabled`, default `false`; add
  `serviceMonitor.labels` to match your Prometheus `serviceMonitorSelector`);
- uses the admin listener for the discoverer, network-policy applier,
  compliance scheduler and kube-bench worker readiness/liveness probes.

```yaml
api:
  metrics:
    serviceMonitor:
      enabled: true
      labels: { release: kube-prometheus-stack }
    allowFrom: { kubernetes.io/metadata.name: monitoring }
```

---

## Backups: in-cluster object store

`backup.objectStore.enabled=true` renders a single-replica RustFS StatefulSet
on one PVC, a Barman Cloud `ObjectStore` pointing at it, random credentials
(re-used on upgrade), and a revision-scoped Job that creates the bucket with
the AWS CLI. It requires `postgres.mode=cnpg` and the CNPG Barman Cloud plugin
installed cluster-wide. With `barmanCloud.objectStoreName` left empty the CNPG
Cluster archives to the rendered store automatically:

```yaml
backup:
  objectStore:
    enabled: true
    storage: 8Gi
    bucket: constellation-recovery
    retentionPolicy: 7d
postgres:
  cloudnativepg:
    barmanCloud: { enabled: true }
    scheduledBackup: { enabled: true }
```

This lives in the same cluster and failure domain as the database: it is a
development/small-install WAL archive, not off-host disaster recovery. For
production supply an externally managed `ObjectStore` through
`postgres.cloudnativepg.barmanCloud.objectStoreName`. See
`docs/cnpg-recovery.md` for the restore procedure.

---

## Values reference

| Key                                   | Default                                              | When to change                                                  |
| ------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------- |
| `image.registry`                      | `ghcr.io/alphabravo-oss/constellation`            | Mirror to private registry                                      |
| `image.tag`                           | `""` (uses `v` + `.Chart.appVersion`)                      | Pin to a SHA-stable tag                                         |
| `image.pullPolicy`                    | `IfNotPresent`                                       | Set to `Always` for floating tags                               |
| `image.pullSecrets`                   | `[]`                                                 | Required for private registries                                 |
| `revisionHistoryLimit`                | `3`                                                  | Raise only if you need more in-cluster rollback history          |
| `security.podSecurityContext.enabled` | `true`                                               | Apply shared pod hardening to non-privileged app workloads      |
| `security.containerSecurityContext.enabled` | `true`                                        | Drop caps, disallow escalation, run Go/distroless roles as UID/GID 10001, and keep app root filesystems read-only |
| app workload service account automount | `false` for API/scanner/admission/frontend/importer/archiver | Keep Kubernetes API tokens off pods that do not need them |
| `networkPolicies.enabled`              | `false`                                              | Enable namespace default-deny and explicit component flows in production |
| `networkPolicies.kubeAPI.cidrs`         | `["0.0.0.0/0"]`                                      | CIDRs for the Kubernetes API server used by operator/bootstrap/TLS jobs |
| `networkPolicies.externalPostgres.cidrs`| `["0.0.0.0/0"]`                                      | CIDRs for external managed Postgres when `postgres.mode=external` |
| `networkPolicies.frontendIngressCIDRs`  | `["0.0.0.0/0"]`                                      | Ingress-controller/client CIDRs allowed to reach frontend pods |
| `networkPolicies.admissionIngressCIDRs` | `["0.0.0.0/0"]`                                      | Kubernetes API/control-plane CIDRs allowed to call the webhook |
| `api.replicas`                        | `2`                                                  | Bump for HA                                                     |
| `api.supportBundleSigningKeySecret`  | `""`                                                 | Existing Secret with an Ed25519 PKCS#8 PEM signing key; empty leaves support bundles unsigned |
| `api.supportBundleSigningKeySecretKey` | `private-key.pem`                                  | Data key within that Secret |
| `api.leaderElection.enabled`          | `true`                                               | Only disable with `api.replicas=1`                              |
| `api.metrics.annotations`             | `true`                                               | Drop the `prometheus.io/*` pod annotations                      |
| `api.metrics.serviceMonitor.enabled`  | `false`                                              | Render a Prometheus Operator ServiceMonitor for the `admin` port |
| `api.metrics.serviceMonitor.labels`   | `{}`                                                 | Match your Prometheus `serviceMonitorSelector`                  |
| `api.metrics.serviceMonitor.interval` | `30s`                                                | Scrape cadence                                                  |
| `api.metrics.allowFrom`               | `{}`                                                 | namespaceSelector labels admitted to port 9090 by NetworkPolicy |
| `operator.replicas`                   | `1`                                                  | Raise with leader election on                                   |
| `operator.leaderElection.enabled`     | `true`                                               | Only disable for single-replica debugging                       |
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
| `postgres.mode`                       | `cnpg`                                               | `external` to use an operator-managed DSN (dev/test or managed Postgres) |
| `postgres.dsn`                        | `""`                                                 | DSN string for `external` (alternative to existingSecret)       |
| `postgres.existingSecret`             | `""`                                                 | Reference an externally-managed Postgres Secret (`external`)    |
| `postgres.cloudnativepg.instances`    | `3`                                                  | `1` for dev; HA rendering requires `>=3`                        |
| `postgres.cloudnativepg.imageName`    | `""` (chart pgvector build)                          | Pin a `tag@sha256` or supply your own pgvector operand image    |
| `postgres.cloudnativepg.storage`      | `20Gi`                                               | Per-instance volume size                                        |
| `postgres.cloudnativepg.storageClass` | `""`                                                 | Override the cluster default StorageClass                       |
| `postgres.cloudnativepg.barmanCloud.enabled` | `false`                                       | Archive WAL + base backups through the CNPG-I Barman Cloud plugin |
| `postgres.cloudnativepg.barmanCloud.objectStoreName` | `""`                                  | Externally managed `ObjectStore`; empty uses `backup.objectStore` when enabled |
| `postgres.cloudnativepg.scheduledBackup.enabled` | `false`                                   | Daily base backup (`schedule`, six-field CNPG cron)             |
| `backup.objectStore.enabled`          | `false`                                              | Render the in-cluster RustFS store + ObjectStore + bucket Job (cnpg only) |
| `backup.objectStore.storage`          | `8Gi`                                                | Object store PVC size                                           |
| `backup.objectStore.storageClass`     | `""`                                                 | Override the cluster default StorageClass                       |
| `backup.objectStore.credentialsSecret`| `""` (generated)                                     | Existing Secret with `ACCESS_KEY_ID`/`SECRET_ACCESS_KEY`        |
| `backup.objectStore.bucket`           | `constellation-recovery`                             | Bucket created by the Job and used as `destinationPath`         |
| `backup.objectStore.retentionPolicy`  | `7d`                                                 | Barman retention                                                |
| `backup.objectStore.image`            | digest-pinned `rustfs/rustfs:1.0.3`                  | Mirror or upgrade RustFS                                        |
| `backup.objectStore.bucketJobImage`   | digest-pinned `amazon/aws-cli:2.32.6`                | Mirror the bucket-creation helper                               |
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
| `auditArchiver.sign.mode`             | `static-key`                                         | Required trusted signing: `static-key` or `keyless`              |
| `auditArchiver.sign.keySecretName`    | `""`                                                 | Secret containing the private and trusted public signing keys   |
| `auditArchiver.batchSize`             | `1000`                                               | Maximum rows per catch-up run (1–10,000)                         |
| `ai.enabled`                          | `false`                                              | Enable Abbot GenAI integration                                  |
| `fips.enabled`                        | `false`                                              | Switch to FIPS-validated base images for every role             |

Release images use `v`-prefixed application versions, such as `api:v0.3.0`.
An explicit `image.tag` or per-role tag is used verbatim; per-role digest pins
still take precedence. The CNPG default is
`<image.registry>/postgres:16.15-v<Chart.appVersion>` and follows the chart version
independently of the application `image.tag`. Set `postgres.cloudnativepg.imageName`
to a version-bearing `tag@sha256:...` reference for a pinned database rollout.


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

## Federation transport and proxy trust

Federation `join-remote` requires an absolute HTTPS master URL. Join tokens are
never replayed through redirects. Configure a certificate trusted by the API
container; use a TLS test server for local federation testing. The joining API
no longer fabricates `X-Forwarded-Proto` to make an HTTP connection appear secure.

The chart routes `/api` directly from the Ingress/Gateway to the API service.
This preserves the terminator's TLS/client-IP evidence instead of passing through
the frontend's plain-HTTP proxy. The frontend still serves `/` and uses `/static/`
for compiled assets, leaving `/assets` available to the application router.
With NetworkPolicies enabled, `networkPolicies.frontendIngressCIDRs` also admits
the Ingress/Gateway peers to this direct API path. Narrow it to the actual proxy
networks; do not assume a pod source address is the same as a node source address.

Set `api.env.CONSTELLATION_TRUSTED_PROXIES` to the actual trusted proxy IPs/CIDRs
in the forwarding chain. The middleware records direct-peer trust before
rewriting the client IP. For a trusted socket peer, it reads `X-Forwarded-For`
from right to left and stops at the first untrusted IP. The proxy must append
its actual client address or overwrite the header with a verified chain.
`True-Client-IP` and `X-Real-IP` are ignored; proxies providing only those headers
must also supply `X-Forwarded-For`. Missing headers, malformed trusted suffixes
and chains exceeding 64 hops or 8192 bytes retain the socket address. These
requests share the proxy's rate-limit bucket. Do not include client networks in
the trusted proxy list. Federation honors
forwarded TLS and a configured forwarded client-certificate header only for that
explicitly configured trusted peer. The terminator must overwrite incoming forwarding/certificate
headers and perform the client TLS handshake. A forwarded public certificate
alone does not prove possession of its private key. The compatibility default
uses private/loopback ranges for client-IP rewriting only; it does not attest
federation TLS or client certificates. Explicit narrow CIDRs are required for
forwarded federation transport proof.

Federation admin proxy requests reject redirects, including same-host redirects
that could escape a reader's path allowlist. Redirect Location/Set-Cookie headers
are not relayed to the browser. Configure the final member endpoint directly.
Live ingress/mTLS and multi-cluster acceptance are still required before release.


### Minimal API runtime

The API image uses a digest-pinned Distroless static runtime. It retains the API
and operator CLI, system CA roots, UID/GID 10001 and `/home/constellation`; both Go
binaries embed timezone data, including legacy schedule aliases. It contains no
shell, package manager, or native dynamic linker. Kubernetes HTTP probes and the
`constellation-api -check-schema` init command work directly. Use `kubectl logs`,
the HTTP health/readiness endpoints, and an approved ephemeral debug container
when diagnosing it; `kubectl exec ... -- sh` is no longer available.

Run `bash scripts/test-api-runtime.sh IMAGE` after building. Browser CI runs this
check before its fresh-database API suite. The check verifies application identity,
home ownership, CA roots, timezone aliases, embedded timezone build tags, static
ELF executables, writable temporary storage, and API/CLI startup under a read-only
filesystem with all capabilities dropped. Refresh the runtime digest deliberately,
verify its upstream signature, and compare exact-image scans using the same dated
vulnerability database. Scanner and native runtime-agent images have separate
runtime dependencies and are not converted by this change.

### Shared enforcement protection

Set `systemProtection.protectedNamespaces` (default `[]`) to dedicated dependency
namespaces, for example `[cnpg-system]`. The chart adds these to admission namespace
exclusions and runtime/network-policy enforcement protection. The release namespace,
`kube-system`, `kube-public`, and `kube-node-lease` cannot be removed. Existing
`runtimeAgent.enforcement.protectedNamespaces` and
`networkPolicyApplier.protectedNamespaces` remain additive for their components.
This excludes all workloads in those namespaces from these enforcement paths;
scanning and finding visibility are independent. It does not prevent an application
policy from disconnecting that application from a protected service.

## Off-host backups and secrets backup

`backup.objectStore` is a same-cluster WAL archive. `backup.offhost` adds the
second failure domain the runtime hardening stream ran by hand:

```yaml
backup:
  objectStore: { enabled: true, bucket: constellation-recovery }
  offhost:
    enabled: true
    endpointURL: http://backup-host:9000       # any S3 API (RustFS, MinIO, Ceph RGW, AWS)
    bucket: constellation-recovery-offhost
    credentialsSecret: offhost-credentials     # keys ACCESS_KEY_ID / SECRET_ACCESS_KEY
    sync: { schedule: "*/15 * * * *" }
    recovery: { enabled: true }
networkPolicies:
  offhostCIDRs: ["100.86.167.87/32"]
```

This renders a second Barman `ObjectStore` (`<archive>-offhost`), the
`archive-offhost-sync` CronJob (rclone from the toolbox image, credentials via
`RCLONE_CONFIG_*` env — no config file) and a `<archive>-offhost-recovery`
ObjectStore to point `postgres.cloudnativepg.barmanCloud.recovery.objectStoreName`
at for a PITR drill. **Switch WAL twice before a drill**
(`SELECT pg_switch_wal();` ×2 on the primary) so the target time is archived
on both stores; see `docs/cnpg-recovery.md`.

`backup.secrets` backs up the namespace's Kubernetes Secrets (TLS material,
tokens, the age key) daily, encrypted to `backup.secrets.ageRecipient`, to the
same kind of S3 remote. Keep the matching age identity off the cluster;
restore with `age -d -i identity.txt secrets-<ts>.tar.gz.age | tar xz`.

## Monitoring with the Prometheus Operator

`metrics.serviceMonitor.enabled=true` renders ServiceMonitors for the API
(admin port), scanner and admission and PodMonitors for the operator, the
runtime agent and the CNPG instances; `metrics.prometheusRule.enabled=true`
ships the alert rules (`constellation.components`, CNPG archiving/backup,
and — `includeClusterRules` — node/pod/PVC capacity). Component heartbeat
age, scanner engine-DB age (trivy, trivy-java-db, grype) and CVE-feed age are
served by the API itself (`constellation_component_heartbeat_age_seconds`,
`constellation_scanner_engine_db_age_seconds`, `constellation_cve_feed_age_seconds`),
so no postgres-exporter is required. `metrics.postgresRole.enabled` still
renders a read-only `constellation_metrics` role (CNPG `managed.roles`,
grants owned by migration 186) for an optional exporter. With
`networkPolicies.enabled`, `networkPolicies.monitoring.namespace` is admitted
to every metrics port.

## Local accounts and recovery administrator

Local accounts are a normal sign-in method, enabled by default. Set
`auth.local.enabled`, `auth.oidc.enabled`, or both. Configure presentation with
`auth.local.display: all|local|sso`. When the preferred method is unavailable,
the login page retains the other enabled method and a recovery link.

The chart creates a retained `<release>-local-admin` Secret containing a generated
40-character password and a base32 `totp-secret`. Set
`auth.local.bootstrap.existingSecret` to supply those keys yourself. The initial
email defaults to `admin@constellation.local`; set `auth.local.bootstrap.email` to
change it. Retrieve both values privately using the commands in the chart's NOTES,
and enroll the seed in an authenticator (SHA1, six digits, 30 seconds). They are
never logged by the API or returned by user-list/settings endpoints. This Secret
only creates the initial administrator; it never resets an existing account.

On a new installation the initial administrator is also the one recovery account.
On an upgrade, migration 188 preserves the previous break-glass administrator and
its password/TOTP; the bootstrap administrator is then a separate normal account.
Existing `auth.breakGlass.*` Secret values are used only to import that identity;
subsequent credential changes use Users or the CLI, not chart env rotation.

Settings → Users creates accounts (supplied or generated passwords), assigns a
product role, disables access and resets passwords or TOTP. Creation and resets
show enrollment material once for private delivery to the account owner. There
is no email-delivery dependency. Use another administrator or the operator CLI to
reset your own credentials; the UI prevents losing one-time enrollment material
when the current session is revoked. Settings → Sign-in methods controls local login,
OIDC, the visible choices, password length, session lifetime and TOTP policy.
TOTP is required for everyone by default; `admins` always requires it for the
three administrator roles and recovery. The offline NCSC top-100k list is embedded
in the API; password checks make no network request. The API defaults GOMAXPROCS to the CPU limit (rounded up), avoiding the runtime’s
two-thread floor and quota throttling during password verification. An explicit
`api.env.GOMAXPROCS` overrides it. Argon2 parameters remain 64 MiB / three passes /
four lanes. The default minimum is 16
characters (configurable 12–128), with a 4096-byte input bound.

Normal local sessions default to one hour (configurable 60–86400 seconds).
Disabling local sign-in immediately prevents new normal local logins and revokes
normal local sessions; the recovery administrator continues to work when SSO is
unconfigured or unavailable. Recovery always requires TOTP and lasts five minutes
by default (at most ten, `auth.breakGlass.sessionTTL`). Every accepted TOTP step
is consumed once across replicas. Default limits are 20 attempts per IP per minute
and exponential account backoff after five failures, from one second to five
minutes. `Retry-After` reports the actual cooldown. Counters are shared in Postgres.

Sessions have no refresh. The bounded session index checks expiry on every
request; cross-replica revocations normally propagate within 250ms, and a failed
database freshness check closes access within one second. Database notifications
wake refreshes immediately; a login response waits until all live replicas have
acknowledged its session, so the next request can land on any replica. Migration
189 adds this acknowledgement barrier and one dedicated notification connection
per API replica. No per-request network
or database call is needed for opaque-session verification. OIDC discovery runs
independently, so an issuer outage cannot starve session synchronization.

Recovery success and critical `auth.login.break-glass` audit commit together.
`constellation_break_glass_logins_total` records outcomes and
`ConstellationBreakGlassUsed` alerts on use (`metrics.prometheusRule.enabled`).
Investigate each use and rotate the recovery credentials through Users or CLI.
The recovery identity cannot be disabled, deleted or downgraded.

Operators use an administrator API token or opaque session in the existing CLI
configuration (`constellationctl login --server …` reads the token from stdin):

```sh
constellationctl users list
constellationctl users create --email analyst@example.com --name Analyst --role Analyst
constellationctl users create --email analyst@example.com --role Analyst --password-stdin
constellationctl users disable <user-id>
constellationctl users reset-password <user-id> --password-stdin
constellationctl users reset-totp <user-id>
```

Creation and resets print setup credentials once; redirect them to protected files.
A missing password generates a strong one. Disabling access, resetting credentials
and assigning a role revoke existing sessions and emit audit events. Take a CNPG
backup before applying forward-only migration 188; deploy the API and UI together.

## Pod Security Admission and the k3s host profile

Every chart pod is `restricted`-clean; the runtime agent is the documented
exception (hostNetwork/hostPID). `deploy/k3s/psa-admission.yaml` is the
AdmissionConfiguration that exempts it (through the DaemonSet controller and
its ServiceAccount) and `deploy/k3s/config.yaml` carries the kubelet
eviction/image-GC thresholds a single-node k3s host needs. See
`docs/k3s-profile.md`. The admission webhook's own built-in rules skip
`admission.exemptNamespaces` and namespaces labelled
`constellation.alphabravo.io/admission=ignore`.

## API high availability with packet evidence

`api.replicas > 1` with `api.pcapStorage.enabled` requires a ReadWriteMany
claim; `validate.yaml` rejects RWO because captures are files written by
every replica. `examples/values-api-ha-rwx.yaml` is the supported profile
(RWX PVC created first, `accessMode: ReadWriteMany`). Without RWX storage run
one API replica with packet evidence, or scale the API with packet evidence
disabled.

## Air-gapped installs

`constellationctl bundle build` packs every image (OCI layout), the chart and
a cosign-compatible signed BOM; `bundle verify` checks the signature against
the vendor key compiled into the binary (`--trust-key` to override) before
any payload is read; `bundle load --registry <host:port> --values-out
values-bundle.yaml` pushes the images into the cluster-local registry and
writes a values file that pins every role to the loaded digest with
`global.imageRegistry`. On k3s without a registry, `bundle load --containerd`
imports straight into the node image store (`image.pullPolicy: Never`). The
scanner defaults to `--offline-db` (baked DBs; `CONSTELLATION_SCANNER_OFFLINE_DB=false`
opts into online refresh) and every binary logs one `egress endpoints` line at
start-up naming every out-of-cluster endpoint it may contact.

### Bundle-signing key

Bundles are signed with the AlphaBravo **vendor bundle-signing key**: ECDSA P-256,
PKCS#8 PEM, signatures over SHA-256 of `bom.json` (ASN.1 DER, base64), i.e. the
`cosign sign-blob --key` format. Only the public half is in the source tree
(`internal/bundle/trust/bundle-signing.pub`, compiled into `constellationctl`).

| | |
|---|---|
| Public key | `internal/bundle/trust/bundle-signing.pub` |
| Fingerprint | SHA-256 of the DER SubjectPublicKeyInfo: `b7ca3ba6fe84afb131c20440589dc8c2fa5431647e11b550d2d8c880a6adad91` (`openssl pkey -pubin -in bundle-signing.pub -outform DER \| sha256sum`) |
| Private key | never in git; held by the release owner. On the dev install it is Secret `constellation-system/constellation-bundle-signing` (keys `bundle-signing.key`, `bundle-signing.pub`), which the namespace secrets backup (`backup.secrets`) includes, plus an offline copy (mode 600) |
| Introduced | 0.3.0 (replaces the session-generated development key used during Phase 1) |

Sign: `constellationctl bundle build --sign-key bundle-signing.key ...`.
Verify against something other than the embedded key: `bundle verify --trust-key old.pub`.

**Rotation** (scheduled yearly, immediately on suspected compromise):

1. Generate the new pair offline:
   `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out bundle-signing.key`
   and `openssl pkey -in bundle-signing.key -pubout -out bundle-signing.pub`.
2. Replace `internal/bundle/trust/bundle-signing.pub`, update the fingerprint above and
   note the rotation in `CHANGELOG.md`; cut a release. Bundles signed with the previous key
   are then rejected by the new `constellationctl` unless an operator passes
   `--trust-key <previous>.pub` explicitly (keep the previous public key published next to
   the release notes for one release cycle).
3. Replace the private key wherever it is held (`kubectl -n constellation-system create
   secret generic constellation-bundle-signing --from-file=... --dry-run=client -o yaml |
   kubectl apply -f -`), let the next secrets backup run (or trigger it), then destroy the
   old private key.
4. On compromise: also re-sign and re-publish every supported bundle with the new key, and
   announce the revoked fingerprint.

Moving the private key into cosign KMS/HSM (`cosign sign-blob --key awskms://...`) keeps the
same verification format; only step 1 and the custody row change.

### Private images discovered from the cluster

Set `scanner.registryConfigSecret` to an existing
`kubernetes.io/dockerconfigjson` Secret in the release namespace when discovered
image targets need private registry access. The chart mounts its
`.dockerconfigjson` as a read-only `config.json` and sets `DOCKER_CONFIG` for the
scanner tools. This explicitly grants every scanner replica pull access to the
registries in that Secret. Registry connector jobs continue to use their isolated
per-job credentials, including an empty configuration for anonymous connectors.

The scanner defaults to one concurrent job, a 2 GiB memory request and a 6 GiB
limit: each image job runs Syft, Trivy and Grype as concurrent child processes.
Size the limit from container memory measurements over complete scan cycles;
the worker's Go heap alone does not include its tools or charged file cache.


## Optional bundled single sign-on

Local accounts remain the default and work independently. Enable the shared
identity layer with `identity.enabled: true`; Constellation never requires an
Astronomer installation. The dependency registers a teal Constellation product,
with `security-admin` → `SecurityAdmin` and `analyst` → `Analyst`. Unmapped roles
receive no access. The API reads the issuer, client ID and create-only client
secret from the provisioner's durable product Secret. No client secret belongs
in Helm values.

For a shared public hostname and existing TLS Secret:

```yaml
identity:
  enabled: true
  ingress:
    className: nginx
    tlsSecretName: constellation-tls
  zitadel:
    zitadel:
      configmapConfig:
        ExternalDomain: constellation.example.com
```

The shared chart's internal `zitadel` keys are operator configuration; public
pages, cookies and token claims use product-neutral names. The registered
callback and logo default to that hostname. For a separate issuer hostname,
set `identity.products` to the Constellation registration with an exact product
callback URL and logo URL. The optional database requires the CNPG operator, or
set `identity.database.create: false` and configure the dependency's existing
Postgres host/database/role and password Secret. Back up that database and all
identity Secrets together, including the master key, product credentials and
runtime signing/cookie capabilities. The identity namespace policy selects only
identity Pods. Set `identity.networkPolicy.ingressPeers` and `ingressPorts` for
another ingress controller, plus explicit private upstream allowances as needed.
Registry mirrors may use `identity.imagePullSecrets` and
`identity.zitadel.imagePullSecrets`.

While bundled identity is enabled, it supplies the initial OIDC configuration.
An administrator can select Bundled single sign-on, External OIDC provider, or
Disabled on **Settings → Sign-in methods**, and choose local accounts, SSO, or
both. The bundled option remains available after SSO is disabled; re-enabling it
restores the provisioned credentials without rotating them. Saved settings
survive restarts with unchanged deployment policy. Changing deployment auth
values deliberately replaces saved policy. Disabling normal local accounts
retains the protected recovery administrator and its mandatory TOTP/audit path.

For a customer-managed provider, leave `identity.enabled: false` and configure
`auth.oidc.*` exactly as before. The shared `identity/pkg/rp` verifier performs
local signature/issuer/audience/time checks, ten-minute token-lifetime limits,
ID-token authorized-party checks, last-good JWKS and bounded memoization. The
existing product code flow preserves PKCE, nonce and one-use database state;
client authentication follows the provider's discovery document. Browser
sessions remain opaque product sessions with no token refresh.

The identity chart is pinned at 0.1.3 (restricted Pod Security defaults); the
shared relying-party module and qualified runtime images are 0.1.2.

### Scanner-cache monitoring

The existing `metrics.serviceMonitor.enabled` toggle discovers scanner-local
cache metrics. With the parent PrometheusRule enabled,
`metrics.prometheusRule.scannerCache.enabled` includes eight scoped capacity,
configuration and collection/discovery warnings. Review available-byte and
byte/inode-ratio budgets before activation. See the
[metric contract, values and response guide](scanner-cache-monitoring.md).
Default parent monitoring toggles remain disabled; no cache topology or automatic
eviction policy is selected by these rules.
