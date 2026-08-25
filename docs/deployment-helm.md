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
- vulndb-importer (optional CronJob)
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

Go role images expect the separate `constellation-vulndb` producer checkout as a
BuildKit named context. From the default `constellation-all` layout this works
without extra flags:

```bash
make image-scanner
make images
```

If `constellation-vulndb` lives somewhere else, pass its path explicitly:

```bash
make image-scanner VULNDB_BUILD_CONTEXT=/path/to/constellation-vulndb
```

The Dockerfiles create a temporary Go workspace inside the build container and
replace `github.com/alphabravocompany/constellation-vulndb` with that sibling
context. This keeps the VulnDB producer separate while avoiding private module
fetches inside isolated Docker builds.

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
from the first Secret. It also mounts the configured VulnDB volume read-only and
sets `CONSTELLATION_VULNDB_PATH` so Syft package inventory can be matched by the
local `constellation-vulndb` store. The runtime-agent DaemonSet reads
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

## VulnDB Importer

`constellation-vulndb` remains the producer of vulnerability intelligence.
`vulndbImporter.enabled=true` runs `vulndb-bundle-install` on a schedule to
consume a delivered artifact and atomically update the shared Constellation
store. The source can be an OCI ref, mounted files, HTTPS or presigned S3 URLs,
native `s3://` objects, or a prebuilt bbolt store.

Production installs should disable direct manual API writes and enforce trust
and freshness:

```yaml
vulndb:
  manualUpload:
    enabled: false
  readiness:
    requireBundle: true
    maxAge: 168h
  trust:
    requireSignatures: true
    publicKeySecret: constellation-vulndb-cosign-public-key
    publicKeySecretKey: cosign.pub
  freshness:
    maxAge: 168h
vulndbImporter:
  enabled: true
  installJob:
    enabled: true
  source:
    kind: oci
    ref: ghcr.io/alphabravocompany/constellation-vulndb-bundle:latest
```

The `:latest` ref above is a VulnDB artifact channel, not an application
container image. Production safety comes from `requireSignatures`, freshness
limits, and atomic local store replacement. Pin `vulndbImporter.source.ref` to
an OCI digest when you need exact bundle replay for change-control.
`vulndbImporter.installJob.enabled=true` runs the same importer once during
Helm install/upgrade so the API can become ready without waiting for the next
cron tick.

For large bundles or prebuilt bbolt stores, leave `vulndbImporter.workDir`
empty unless you have a dedicated larger volume. The empty default stores
download, extraction, and validation work files under
`<vulndb.mountPath>/.vulndb-work`, which keeps importer scratch usage on the
shared VulnDB PVC instead of small pod-local ephemeral storage.

When `requireSignatures=true`, OCI sources are verified with `cosign verify`
before pull. File, URL, S3, and prebuilt-store sources use detached cosign
signature bundles beside the artifact (`.sig`) unless explicit signature paths or
URLs are supplied to the installer image.

When `vulndb.readiness.requireBundle=true`, `/readyz` returns `503` until the
API can open the local bbolt store. If `vulndb.readiness.maxAge` is set, the
bundle's `exported_at` metadata must also be within that duration.

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
| `scanner.engines.syft`                | `true`                                               | Keep enabled for package inventory and VulnDB matching          |
| `scanner.engines.vulndb`              | `true`                                               | Canonical vulnerability matching from the local VulnDB store    |
| `scanner.engines.trivy`               | `true`                                               | Disable for VulnDB-only canonical scans; re-enable as evidence  |
| `scanner.engines.grype`               | `true`                                               | Disable for VulnDB-only canonical scans; re-enable as evidence  |
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
| `vulndb.storage.type`                 | `pvc`                                                | Use shared PVC for API, scanner, and importer store access      |
| `vulndb.storage.size`                 | `20Gi`                                              | PVC size for the active store plus importer scratch files and atomic replacement headroom |
| `vulndb.storage.accessModes`          | `[ReadWriteMany]`                                    | Required for multi-replica API/scanner shared-store access      |
| `vulndb.statusFile`                   | `vulndb-import-status.json`                          | Importer status JSON read by `/api/v1/vulndb/status`            |
| `vulndb.manualUpload.enabled`         | `true`                                               | Allow `POST /api/v1/vulndb:import` to write the store directly; set false for importer-only production installs |
| `vulndb.readiness.requireBundle`      | `false`                                              | Make `/readyz` fail until a valid local VulnDB store is loaded  |
| `vulndb.readiness.maxAge`             | `""`                                                 | Make `/readyz` fail when the loaded bundle is older than this Go duration |
| `vulndb.trust.requireSignatures`      | `false`                                              | Require cosign verification before importer installs artifacts  |
| `vulndb.trust.publicKeySecret`        | `""`                                                 | Secret containing `cosign.pub` for static-key verification      |
| `vulndb.trust.certificateIdentity`    | `""`                                                 | Keyless certificate identity regexp when not using a public key |
| `vulndb.trust.certificateOIDCIssuer`  | `""`                                                 | Keyless certificate OIDC issuer regexp                          |
| `vulndb.freshness.maxAge`             | `""`                                                 | Reject artifacts older than this Go duration, for example `168h` |
| `vulndbImporter.installJob.enabled`   | `false`                                             | Run a one-shot importer Job on Helm install/upgrade              |
| `vulndbImporter.workDir`              | `""`                                                | Importer scratch directory; empty defaults to `<vulndb.mountPath>/.vulndb-work` |
| `vulndbImporter.source.kind`          | `oci`                                                | Source mode: `oci`, `bundleDir`, `files`, `urls`, `s3`, `store`, `storeUrl`, or `storeS3` |
| `vulndbImporter.source.ref`           | `ghcr.io/alphabravocompany/constellation-vulndb-bundle:latest` | Signed artifact channel when `source.kind=oci`; pin to digest for exact replay |
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
