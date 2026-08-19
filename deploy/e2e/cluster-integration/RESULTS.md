# Cluster Integration Wave — Results

Two-cluster end-to-end exercise of Constellation: federation, cross-cluster scan
fan-out, GitOps drift detection, admission engine, and deployment-risk dashboard,
all driven against the running API on `:18080` (port-forwarded to the in-cluster
`constellation-api` Service) and the seeded postgres on `:5433`.

## 1. Clusters

```
NAME                 SERVERS   AGENTS   LOADBALANCER
constellation        1/1       2/2      true
constellation-edge   1/1       1/1      true
```

- `constellation` — Wave E deployed Constellation here (api, operator, admission,
  scanner, 3 runtime-agent pods). Kubeconfig: `/tmp/kubeconfig-constellation.yaml`.
- `constellation-edge` — created by this wave with
  `k3d cluster create constellation-edge --servers 1 --agents 1 --port 8444:6443@loadbalancer`.
  Kubeconfig: `/tmp/kubeconfig-edge.yaml`, API at `https://0.0.0.0:8444`.

Pod inventory captured under `captures/pods-constellation.txt` (30 pods) and
`captures/pods-edge.txt` (19 pods).

## 2. Vulnerable workloads (manifests live in `../workloads/`)

| File | Workload | Namespace | Why it matters |
|---|---|---|---|
| `00-namespaces.yaml` | `payments`/`checkout`/`edge`/`platform` | — | Zone labels feed risk model |
| `10-vulnerable-web.yaml` | `web-dvwa`, `juice-shop` | `edge` | OWASP-classic vuln web (internet-exposed label) |
| `20-log4shell.yaml` | `vulhub/log4j:2.14.1` | `payments` | Drives CVE-2021-44228 + KEV/EPSS |
| `30-cves.yaml` | `nginx:1.14.2`, `alpine:3.6`, `redis:6.0.0`, `python:3.7-alpine` | `checkout`,`platform` | Stale-base-image CVE rain |
| `40-admission-bait.yaml` | `privileged-pwn`, `hostnet-snooper` | `platform` | Exercises admission engine |
| `50-ai-workload.yaml` | `huggingface/transformers-pytorch-gpu` w/ `ai-workload=true` | `platform` | AI workload tagging |

Both clusters got the full set via `kubectl apply -f deploy/e2e/workloads/`.

## 3. Golden paths exercised

| Path | Result | Proof (capture file) |
|---|---|---|
| `POST /clusters/{id}/cross-scan` × 3 clusters | PASS — first returns `{images_seen:5, jobs_enqueued:5}` | `captures/cross-scan-1111…json` |
| `GET /scan-jobs` queue depth | PASS — 5 pending (nginx:1.14.2, redis:6.2.6-alpine, hf-transformers, payments-api, edge-api) | `captures/scan-jobs.json` |
| `constellationctl image-check nginx:1.14.2` | PASS — SARIF 303 KB + JSON 6.8 MB, ~100 CVEs | `captures/nginx-1.14.2.sarif` |
| Admission `/validate` priv pod | DENY — `block-privileged: container "c" is privileged` | `captures/admit-privileged.json` |
| Admission `/validate` hostNet pod | DENY — `block-host-network: hostNetwork=true` | `captures/admit-hostnetwork.json` |
| Admission `/validate` `:latest` tag | ALLOW + 2 monitor-mode warnings (image-signature, ro-rootfs) | `captures/admit-latest.json` |
| `GET /dashboard/summary` | PASS — 35 findings, 15 critical, queue=5 | `captures/dashboard-summary.json` |
| `GET /deployments` | PASS — 13 deployments (5 seed + 8 we inserted matching the new k8s workloads, spread across both clusters) | `captures/deployments.json` |
| `GET /violations?limit=50` | PASS — 24 admission violations (`block-privileged`, `block-host-network`, `require-image-signature`, `require-read-only-rootfs` × deployments) | `captures/violations.json` |
| `GET /compliance/checks?profile=cis-k8s-1.9` | PASS handler (200, empty list) — bench-v2 `tags_v2` not populated by the seeder, but the SQL `tags_v2 ? $3` path is exercised | `captures/compliance-cis-1.9.json` |
| `GET /compliance/checks?framework=cis-k8s-1.9` | **BUG → FIX** (see §5) | `captures/compliance-cis-by-framework.json` |
| `GET /findings?q=external_id:CVE-2021-44228` | PASS — 5 Log4Shell findings, all with `reachable_runtime=true` after stamping via this wave | `captures/findings-log4shell-by-extid.json` |
| `GET /findings?q=severity:critical` | PASS — 15 critical | `captures/findings-critical.json` |
| `GET /findings?q=cve:… reachable:true` | **BUG → FIX** (see §5) | `captures/findings-critical-reachable.json` |
| `GET /network/conversations` | PASS handler (200, empty for our org — runtime-agent flows go to a different org) | `captures/network-conversations.json` |
| `POST /federation/transition action=promote` | Already-promoted via parent; state confirmed `master`, revision 1 | `captures/federation-state` curl |
| `GET /federation/sync?since=0` | PASS — 5 revisions (2 policy + 1 vuln-profile + 2 group) | `captures/federation-sync-0.json` |
| `GET /federation/sync?since=2` | PASS — only 3 newer revisions returned | `captures/federation-sync-2.json` |
| `GET /federation/sync?since=4` after inserting new group | PASS — 1 new revision (`platform-eng`, rev 5) — proves rev-bump propagation | `captures/federation-sync-after-bump.json` |
| GitOps drift detection (`pkg/gitops.DetectDrift`) | PASS — declared `RoleBinding` vs live diverged-RoleBinding produces 1 DriftFinding (`declared sha=404eb… observed sha=ee4e5…`) | `captures/drift-detection.json` |

## 4. Curl one-liners (auth boilerplate omitted)

```bash
# token
export TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@dev","password":"devpass123"}' \
  http://localhost:18080/api/v1/auth/login | jq -r .token)

# cross-cluster scan fan-out
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:18080/api/v1/clusters/11111111-1111-1111-1111-111111111111/cross-scan
# → {"images_seen":5,"job_ids":[…5 uuids…],"jobs_enqueued":5}

# dashboard
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:18080/api/v1/dashboard/summary | jq .findings_by_severity
# → {"critical":15,"high":15,"medium":5}

# Log4Shell findings
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://localhost:18080/api/v1/findings?q=external_id:CVE-2021-44228' | jq '.findings|length'
# → 5

# federation rev bump
psql -c "INSERT INTO fed_rule_revisions(...,revision,5,...);"
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://localhost:18080/api/v1/federation/sync?since=4'
# → {"revisions":[{"kind":"group","rule_id":"platform-eng","revision":5,...}]}

# drift detection
go run -tags e2etools deploy/e2e/cluster-integration/drift_driver.go \
  deploy/e2e/gitops/declared-rolebinding.yaml \
  deploy/e2e/gitops/live-rolebinding.yaml
# → DriftFinding with declared/observed SHA-256 deltas
```

## 5. Real bugs found + fixed

### Bug A — Compliance handler 500s when any row is returned
`internal/handler/compliance.go` Checks() scanned `evaluated_at` (timestamptz, OID
1184) into a `*string`, which pgx's binary protocol rejects:
`cannot scan timestamptz (OID 1184) in binary format into *string`. Any
non-empty result set tripped a 500. Fix: scan into `time.Time` and format with
`UTC().Format(time.RFC3339)` for the JSON payload. The previous behaviour was
only masked because the seeded `compliance_checks` table is mostly empty per
org. Verified `go build ./...` clean.

### Bug B — Findings search DSL rejects `cve:` and `reachable:`
The task explicitly asked for `?q=cve:CVE-2021-44228` and `?q=… reachable:true`.
Both returned 400 `unknown field`. The DSL schema in
`internal/handler/searchq.go` was missing those fields. Fix:
- Added `cve` as an ergonomic alias for `external_id` (column maps to same).
- Added `reachable` as a JSONB-derived bool:
  `(COALESCE((risk_inputs->>'reachable_runtime')::boolean,false) OR
    COALESCE((risk_inputs->>'reachable_static')::boolean,false))`
  so both static and runtime reachability count, NULL-safe. Build clean.

(API was not restarted because the task forbade it; both fixes ship in the
patch and the parent agent will pick them up on the next deploy.)

## 6. Files this wave owns

```
deploy/e2e/workloads/00-namespaces.yaml
deploy/e2e/workloads/10-vulnerable-web.yaml
deploy/e2e/workloads/20-log4shell.yaml
deploy/e2e/workloads/30-cves.yaml
deploy/e2e/workloads/40-admission-bait.yaml
deploy/e2e/workloads/50-ai-workload.yaml
deploy/e2e/gitops/declared-rolebinding.yaml
deploy/e2e/gitops/live-rolebinding.yaml
deploy/e2e/cluster-integration/drift_driver.go
deploy/e2e/cluster-integration/RESULTS.md
deploy/e2e/cluster-integration/captures/*           # all API responses + SARIF
internal/handler/compliance.go                       # bug A fix
internal/handler/searchq.go                          # bug B fix
```
