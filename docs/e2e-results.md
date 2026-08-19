# Wave E — End-to-End Verification Results

Date: 2026-05-12
Cluster: `k3d-constellation` (k3s v1.30.4, 1 server + 2 agents)
Postgres: 16 with pgvector at `localhost:5433` (28 migrations applied)
Branch: `main` plus the Wave-E fixes documented below.

This run installs the Constellation Helm chart on a fresh k3d cluster, reconciles
a `ConstellationCluster` CR, exercises the golden API + scanner + admission +
runtime/network policy lifecycle paths, and verifies the tamper-evident audit
chain.

## Summary

| # | Golden path | Result | Notes |
|---|-------------|--------|-------|
| 1 | Build six per-role docker images | PASS | Scanner Dockerfile had a `cosign --version` typo (cosign uses `version`); fixed. |
| 2 | Import images into k3d (`k3d image import`) | PASS | All six imports successful. |
| 3 | `helm lint` & `helm install` | PASS | Required a per-role image override capability in the chart; added (see below). |
| 4 | Apply ConstellationCluster CR | PASS | Required CRD schema extension for per-role image fields; added. |
| 5 | All operator-managed pods Running | PASS | api, operator, admission, scanner, runtime-agent (DaemonSet x3). |
| 6 | API `/healthz`, `/readyz`, `/api/v1/dashboard/summary`, `/api/v1/findings` | PASS | See response captures below. |
| 7 | Enqueue scan of `nginx:1.14.2` and complete it end-to-end through the scanner pod | PASS | 109 packages, 217 findings, ~97s wall-clock; required a one-time scanner token (issued via DB). |
| 8 | Admission webhook denies a privileged pod via `/validate` | PASS | Direct POST against the webhook; the cluster-side `ValidatingWebhookConfiguration` is **not** wired (TLS plumbing missing — see SKIPPED below). |
| 9 | Runtime baselining | PARTIAL | In-memory engine in `pkg/runtime/baseline` exercised by its unit tests (3/3 passing). No HTTP endpoint yet — confirmed by inspecting `internal/server/server.go`. |
| 10 | Network policy generation / discover→monitor→protect lifecycle | PASS | `/api/v1/network/policies/lifecycle` and `/api/v1/network/policies/{workload}/preview` return the candidate netpolicy summary, hash, approval status, and rationale. |
| 11 | `constellationctl audit verify` | PASS | After fixing a real chain-integrity bug (see below). Final chain: 33 events, status `verified`. |
| 12 | Frontend smoke | SKIPPED | Frontend image builds (27 MB Wolfi-nginx), but the chart enables a separate `frontend` deployment that wasn't required for any of the API/scanner/admission golden paths. Disabled in `values-e2e.yaml`. |
| 13 | Audit archiver / vulndb importer CronJobs | SKIPPED | Helm CronJobs are created but their schedules wouldn't fire during the run; the operator-managed CronJobs are present (`e2e-audit-archiver`, `e2e-vulndb-importer`). |
| 14 | Cluster-driven admission (`kubectl apply` of a privileged pod blocked via `ValidatingWebhookConfiguration`) | SKIPPED | The admission pod runs in `--insecure` (plain HTTP) mode because no cert plumbing has landed; Kubernetes admission webhooks require HTTPS. The webhook engine itself works (verified by direct POST). |

## Real bugs found and fixed during e2e

All fixes are minimal and live in this PR alongside the e2e artifacts.

### 1. Audit chain is reported as "broken" on a freshly-seeded DB
**Symptom.** `/api/v1/audit/verify` and `constellationctl audit verify` both
return `{"status":"broken","reason":"row hash mismatch","id":1,...}` on a clean
seed.

**Root cause.** `pkg/audit/audit.go` hashes the row with `at.UTC().UnixNano()`,
but `audit_events.at` is a `TIMESTAMPTZ` (microsecond resolution). On write the
in-memory `time.Time` has nanosecond precision, so the hash and the stored row
agree; on `VerifyChain` the value is read back with the µs-truncated `at`,
producing a different hash. Every chain breaks on row 1.

**Fix.** Truncate `at` to `time.Microsecond` at the top of `Logger.Log` so the
hash is computed over the same value that round-trips through Postgres.
`pkg/audit/audit.go:81-95`.

### 2. Scanner Dockerfile fails on `cosign --version`
**Symptom.** `docker build -f deploy/docker/Dockerfile.scanner` aborts in the
tool-validation step with `unknown flag: --version`.

**Root cause.** Cosign's CLI uses `cosign version`, not `cosign --version`.

**Fix.** `deploy/docker/Dockerfile.scanner:63-67`.

### 3. Helm chart cannot point different roles at different images
**Symptom.** Chart uses a single `.Values.image.repository:.tag` for every
component and passes `args: ["constellation-api"]` etc. — but the role
Dockerfiles each produce a single binary with that binary as `ENTRYPOINT`. There
is no role-multiplexing binary, so the chart cannot be used as-is with the
images it claims to deploy.

**Fix.**
- New `constellation.roleImage` helper in `templates/_helpers.tpl` that picks
  `.Values.<role>.image.{repository,tag}` when set and falls back to the
  chart-wide `.Values.image`.
- `api`, `operator`, and `auditArchiver` templates updated to use it.
- `values.yaml` documents the new `image: {}` / `args: []` shape.
- A reproducible override file lives at `deploy/e2e/values-e2e.yaml`.

### 4. Operator passes `--role=<role>` to per-role binaries
**Symptom.** Operator-created scanner / admission / runtime-agent pods crash
on boot with `flag provided but not defined: -role`.

**Root cause.** The reconciler in
`deploy/operator/controllers/constellationcluster_controller.go` was written
assuming a single role-multiplexed entrypoint that doesn't exist in the
shipped Dockerfiles.

**Fix.** Drop the `--role` arg. Add a `roleArgs` helper that returns
`[--insecure]` for admission (since cert plumbing isn't wired) and nothing for
the others. Add a `rolePorts` helper that maps each role to its real listen
port (admission 8443, scanner 8090). Drop the hard-coded readiness probe on
port 8081 (no role serves there). Same file.

### 5. Operator RBAC missing autoscaling, leases, events
**Symptom.** Reconciler logs `Forbidden: cannot list resource
"horizontalpodautoscalers"` when the CR sets `scannerAutoscale.enabled: true`.

**Fix.** Extra rules in `templates/operator.yaml` for the
`autoscaling`, `coordination.k8s.io/leases`, and `""/events` resources.

### 6. CRD schema rejects per-role image fields the Go types accept
**Symptom.** `kubectl apply` of a CR setting `spec.scannerImage` / etc. is
rejected by the API server with `strict decoding error: unknown field`.

**Fix.** Extended the OpenAPI schema in
`deploy/charts/constellation/crds/constellationcluster.yaml` to mirror the
`v1alpha1.ConstellationClusterSpec` Go type
(`scannerImage`, `admissionImage`, `runtimeAgentImage`, `scannerReplicas`,
`admissionReplicas`, `scannerAutoscale`).

## Reproduction

```
# 1. Build images
for f in api operator admission scanner archiver frontend; do
  docker build -t constellation/$f:e2e --build-arg VERSION=e2e \
    -f deploy/docker/Dockerfile.$f .
done

# 2. Import into k3d
k3d image import -c constellation \
  constellation/api:e2e constellation/operator:e2e \
  constellation/admission:e2e constellation/scanner:e2e \
  constellation/archiver:e2e constellation/frontend:e2e

# 3. Seed Postgres
DATABASE_URL='postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable' \
  go run ./cmd/constellation-seed

# 4. Provision Helm secret + install
kubectl -n constellation-system create secret generic constellation-database-url \
  --from-literal=url='postgres://constellation:constellation@host.k3d.internal:5433/constellation?sslmode=disable' \
  --from-literal=DATABASE_URL='postgres://constellation:constellation@host.k3d.internal:5433/constellation?sslmode=disable'
helm install constellation deploy/charts/constellation \
  -n constellation-system -f deploy/e2e/values-e2e.yaml

# 5. Apply the CR
kubectl apply -f deploy/charts/constellation/crds/constellationcluster.yaml
kubectl apply -f deploy/e2e/sample-cr-e2e.yaml
```

## Capture

## Cluster info
```
NAME                         STATUS   ROLES                  AGE   VERSION        INTERNAL-IP   EXTERNAL-IP   OS-IMAGE           KERNEL-VERSION      CONTAINER-RUNTIME
k3d-constellation-agent-0    Ready    <none>                 45m   v1.30.4+k3s1   172.20.0.4    <none>        K3s v1.30.4+k3s1   6.8.0-110-generic   containerd://1.7.20-k3s1
k3d-constellation-agent-1    Ready    <none>                 45m   v1.30.4+k3s1   172.20.0.3    <none>        K3s v1.30.4+k3s1   6.8.0-110-generic   containerd://1.7.20-k3s1
k3d-constellation-server-0   Ready    control-plane,master   45m   v1.30.4+k3s1   172.20.0.2    <none>        K3s v1.30.4+k3s1   6.8.0-110-generic   containerd://1.7.20-k3s1
```

## Pod listing
```
NAME                                          READY   STATUS    RESTARTS   AGE
pod/constellation-api-5cfd679dc4-hxmhj        1/1     Running   0          5m18s
pod/constellation-operator-5d55dd5d58-274m6   1/1     Running   0          14s
pod/e2e-admission-7968c69f85-kf9g5            1/1     Running   0          7m35s
pod/e2e-runtime-agent-5fjq7                   1/1     Running   0          9m2s
pod/e2e-runtime-agent-bc2rl                   1/1     Running   0          9m2s
pod/e2e-runtime-agent-pjfbg                   1/1     Running   0          9m2s
pod/e2e-scanner-79c644dbb-5hhdb               1/1     Running   0          13s

NAME                                     READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/constellation-api        1/1     1            1           11m
deployment.apps/constellation-operator   1/1     1            1           11m
deployment.apps/e2e-admission            1/1     1            1           9m2s
deployment.apps/e2e-scanner              1/1     1            1           9m2s

NAME                               DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
daemonset.apps/e2e-runtime-agent   3         3         3       3            3           <none>          9m2s

NAME                                SCHEDULE      TIMEZONE   SUSPEND   ACTIVE   LAST SCHEDULE   AGE
cronjob.batch/e2e-audit-archiver    0 */6 * * *   <none>     False     0        <none>          11m
cronjob.batch/e2e-vulndb-importer   0 */4 * * *   <none>     False     0        <none>          11m

NAME                        TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
service/constellation-api   ClusterIP   10.43.219.96   <none>        8080/TCP   11m
service/e2e-admission       ClusterIP   10.43.67.37    <none>        443/TCP    11m
```

## Workloads namespace
```
NAME                               READY   STATUS    RESTARTS   AGE
pod/chat-target-7db99f6b69-w7ds4   1/1     Running   0          4m34s
pod/dvwa-target-5f6f6fc944-bx7gj   1/1     Running   0          4m34s

NAME                          READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/chat-target   1/1     1            1           4m34s
deployment.apps/dvwa-target   1/1     1            1           4m34s
```

## Golden API responses

### GET /healthz
```
HTTP/1.1 200 OK
Content-Type: application/json
Vary: Origin
Date: Tue, 12 May 2026 14:15:32 GMT
Content-Length: 16
```

### GET /readyz
```
HTTP/1.1 200 OK
Content-Type: application/json
Vary: Origin
Date: Tue, 12 May 2026 14:15:32 GMT
Content-Length: 19
```

### POST /api/v1/auth/login
```
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJhZGM3YmY0Zi0wOGQ3LTQ0MjctYWI5Zi02YzkxMzhiZGYyMjQiLCJvaWQiOiJmNTRmZTJjMS0zODY4LTQwNjktOThmMi03NDQ4N2MxMmJlODMiLCJlbWFpbCI6ImFkbWluQGRlbW8udGVzdCIsInJvbGVzIjpbIlN1cGVyQWRtaW4iLCJTdXBlckFkbWluIiwiU3VwZXJBZG1pbiIsIlN1cGVyQWRtaW4iXSwiaXNzIjoiY29uc3RlbGxhdGlvbiIsInN1YiI6ImFkYzdiZjRmLTA4ZDctNDQyNy1hYjlmLTZjOTEzOGJkZjIyNCIsImF1ZCI6WyJjb25zdGVsbGF0aW9uLWFwaSJdLCJleHAiOjE3Nzg1OTg5MzIsImlhdCI6MTc3ODU5NTMzMiwianRpIjoiY2MxYTVlYjctOWZlNi00OWFlLWJlNjYtMmE4OTBmMmExMTU4In0.e20vTXDhGdO1nldfVnG2eHP2vyf2EhWG3dGQ2xCFr58",
    "expires_at": "2026-05-12T15:15:32.928873506Z"
}
```

### GET /api/v1/dashboard/summary
```json
{
    "generated_at": "2026-05-12T14:15:32Z",
    "findings_by_severity": {
        "critical": 3,
        "high": 5,
        "medium": 3
    },
    "findings_total": 11,
    "open_findings": 11,
    "accepted_risks": 0,
    "highest_risk": 100,
    "assets_total": 5,
    "scan_queue_depth": 0,
    "recent_activity": [
        {
            "at": "2026-05-12T14:15:32Z",
            "action": "auth.login.local",
            "target_kind": "user",
            "target_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224",
            "actor_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224"
        },
        {
            "at": "2026-05-12T14:15:02Z",
            "action": "scan-job.complete",
            "target_kind": "scan-job",
            "target_id": "e4152aec-c23f-4f9f-b966-3e286496afe1"
        },
        {
            "at": "2026-05-12T14:14:46Z",
            "action": "auth.login.local",
            "target_kind": "user",
            "target_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224",
            "actor_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224"
        },
        {
            "at": "2026-05-12T14:11:03Z",
            "action": "scan-job.enqueue",
            "target_kind": "scan-job",
            "target_id": "e4152aec-c23f-4f9f-b966-3e286496afe1",
            "actor_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224"
        },
        {
            "at": "2026-05-12T14:10:42Z",
            "action": "auth.login.local",
            "target_kind": "user",
            "target_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224",
            "actor_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224"
        },
        {
            "at": "2026-05-12T14:10:36Z",
            "action": "auth.login.local",
            "target_kind": "user",
            "target_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224",
            "actor_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224"
        },
        {
            "at": "2026-05-12T14:10:35Z",
            "action": "policy.create",
            "target_kind": "demo",
            "target_id": "seed",
            "actor_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224"
        },
        {
            "at": "2026-05-12T14:10:35Z",
            "action": "user.invite",
            "target_kind": "demo",
            "target_id": "seed",
            "actor_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224"
        },
        {
            "at": "2026-05-12T14:10:35Z",
            "action": "org.create",
            "target_kind": "demo",
            "target_id": "seed",
            "actor_id": "adc7bf4f-08d7-4427-ab9f-6c9138bdf224"
        }
    ]
}
```

### POST /api/v1/scan-jobs (enqueue nginx:1.14.2)
```json
{
    "jobs": [
        {
            "id": "e4152aec-c23f-4f9f-b966-3e286496afe1",
            "org_id": "f54fe2c1-3868-4069-98f2-74487c12be83",
            "image_ref": "nginx:1.14.2",
            "status": "completed",
            "worker_id": "scanner:e2e:33d9b7a5-8605-423e-b516-2599c4c261b7",
            "package_count": 109,
            "finding_count": 217,
            "requested_at": "2026-05-12T14:11:03.44049Z",
            "claimed_at": "2026-05-12T14:13:25.800126Z",
            "finished_at": "2026-05-12T14:15:02.705301Z"
        }
    ]
}
```

### GET /api/v1/findings?limit=2
```json
{
    "findings": [
        {
            "id": "f7907084-2a87-4a6d-9053-79307017b0c1",
            "kind": "vulnerability",
            "external_id": "CVE-2024-0001",
            "title": "glibc heap overflow",
            "severity": "critical",
            "risk_score": 100,
            "lifecycle": "open",
            "asset_id": "5675104a-ceb7-46f5-a1d8-4d1b60ef778f",
            "attack_techniques": [],
            "first_seen_at": "2026-05-10T14:10:35.701673Z",
            "last_seen_at": "2026-05-12T13:33:35.701673Z",
            "risk_inputs": {
                "cvss_base": 8.8,
                "kev_listed": true,
                "epss_probability": 0.95,
                "asset_criticality": "high",
                "reachable_runtime": true
            }
        },
        {
            "id": "d229a975-39a3-4574-b745-988612814378",
            "kind": "vulnerability",
            "external_id": "CVE-2023-1234",
            "title": "openssl side-channel",
            "severity": "high",
            "risk_score": 77,
            "lifecycle": "open",
            "asset_id": "5675104a-ceb7-46f5-a1d8-4d1b60ef778f",
            "attack_techniques": [],
            "first_seen_at": "2026-05-10T14:10:35.702959Z",
            "last_seen_at": "2026-05-12T13:16:35.702959Z",
            "risk_inputs": {
                "cvss_base": 7.5,
                "kev_listed": false,
                "epss_probability": 0.4,
                "asset_criticality": "high",
                "reachable_runtime": true
```

### POST /api/v1/network/policies/default/frontend/preview
```json
{
    "action": "preview",
    "action_id": "",
    "applies_live": false,
    "idempotency_key": "",
    "idempotent": false,
    "message": "Lifecycle action persisted for audit and staged policy promotion; cluster apply remains gated.",
    "next_mode": "monitor",
    "persists": true,
    "policy": {
        "id": "default/frontend",
        "cluster_id": "95a3589d-50d2-4088-a7fd-fcfa78390fd0",
        "cluster_name": "prod-east",
        "workload": "default/frontend",
        "namespace": "default",
        "current_mode": "monitor",
        "reason": "hold in monitor: out-of-policy traffic observed in the selected cluster",
        "auto_applied": false,
        "evaluated_at": "2026-05-12T14:15:33Z",
        "generated_at": "2026-05-12T14:15:33Z",
        "candidate_hash": "2d4f8e63f14da628",
        "candidate_stale": false,
        "approval_status": "blocked",
        "rollback_available": false,
        "summary": {
            "total_flows": 3,
            "unique_peers": 3,
            "unique_port_protocol": 3,
            "out_of_policy_alerts": 1,
            "new_tuples_last_24h": 3,
```

### GET /api/v1/runtime/overview
```json
{
    "modes": [
        {
            "blocks": false,
            "description": "Observe process, endpoint, and network behavior without alerting.",
            "id": "learn",
            "label": "Learn"
        },
        {
            "blocks": false,
            "description": "Alert on baseline, WAF, DLP, Falco, and network-policy drift without blocking.",
            "id": "monitor",
            "label": "Monitor"
        },
        {
            "blocks": true,
            "description": "Block promoted WAF/DLP/network/process violations and audit every promotion.",
            "id": "enforce",
            "label": "Enforce"
        }
    ],
    "recent_events": [
        {
            "id": "9a09b622-e0e4-4337-8880-99e6e8142654",
            "at": "2026-05-12T14:06:35Z",
```

## Admission webhook test (direct /validate)

### Privileged pod (expected: DENY)
```json
{
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1",
    "response": {
        "uid": "test-001",
        "allowed": false,
        "status": {
            "metadata": {},
            "message": "denied by constellation policy \"block-privileged\": container \"x\" is privileged"
        }
    }
}
```

### Benign pod (expected: ALLOW)
```json
{
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1",
    "response": {
        "uid": "test-002",
        "allowed": true
    }
}
```

## Audit verify (CLI)
```
{"events":33,"genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_hash":"8934aa1bfaec8fd9392fb5b8afd5350b8bd7494416e8676b8e9a22bf7f85f98f","status":"verified","verified_at":"2026-05-12T16:45:00Z"}
```

