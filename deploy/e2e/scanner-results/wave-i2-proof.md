# Wave I2 — Scanner Processing Proof

Date: 2026-05-12
Operator: Wave I2 agent
Cluster: k3d "constellation"

## Root cause

The in-cluster `e2e-scanner` Deployment (managed by the constellation-operator) was crash-looping on a 401 because the operator's `reconcileScanner()` only injects two env vars — `CONSTELLATION_CONTROL_PLANE_URL` and `CONSTELLATION_ORG_ID` — and never provisions a `CONSTELLATION_SCANNER_TOKEN`. The control plane's `ScannerTokenMiddleware` therefore rejects every claim attempt:

```
{"level":"WARN","msg":"claim job","err":"claim: status 401: scanner bearer token required"}
```

A second latent bug was found while implementing the fix: the `Complete` handler updated `scan_jobs.package_count` / `finding_count` but did **not** insert any rows into the partitioned `findings` table. Even with auth working, completed scans would never produce findings.

## Fix path

Two-part fix, scoped to minimize cluster churn:

1. **`internal/handler/scanjobs.go` — Complete handler now persists findings.**  
   Within the existing transaction, the handler upserts an `assets` row keyed on `(org_id, kind='image', name=image_ref, digest=NULL)` and bulk-inserts each `scanner.Finding` into `findings` (`kind='vulnerability'`, `lifecycle='open'`, severity normalized, risk score backfilled from severity+CVSS+KEV when missing, full engine provenance preserved in `engines` JSONB, package/CVSS/references stored in `detail_json`).

2. **`deploy/e2e/scanner-driver/main.go` — out-of-cluster driver.**  
   The in-cluster scanner image cannot be rotated without a rebuild + operator push. The driver short-circuits that: it connects to Postgres directly, calls the existing `handler.IssueScannerToken` to mint a per-org scanner token, then drives the **existing** `internal/scanner.Aggregator` (syft + trivy + grype) against each pending job and POSTs results to the control plane's `/scan-jobs/claim` + `/scan-jobs/{id}/complete` (or `/fail`) endpoints. Same code path the in-cluster pod uses; same handler middleware; no shortcuts.

This satisfies the task's explicit "simpler short-term path: build a small scanner-driver binary that runs OUTSIDE the cluster" option. The operator fix (inject a token at reconcile time) is a follow-up listed under Deferred.

## Files touched

- `internal/handler/scanjobs.go` — Complete handler now upserts asset + inserts findings; added `severityToScore` fallback.
- `deploy/e2e/scanner-driver/main.go` — new out-of-cluster driver.
- `deploy/e2e/scanner-results/wave-i2-proof.md` — this file.

No frontend, no spec, no progress.md, no other handlers modified.

## Run

```
cd <repo>
go build -o /tmp/scanner-driver ./deploy/e2e/scanner-driver
DATABASE_URL='postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable' \
  API_URL=http://localhost:18080 \
  /tmp/scanner-driver --max 8 --job-timeout 6m
```

## Result

### scan_jobs status

```
  status   | count 
-----------+-------
 completed |     6
 failed    |     3
```

Detail (most recent first):

```
                  id                  |                 image_ref                 |  status   | package_count | finding_count
--------------------------------------+-------------------------------------------+-----------+---------------+---------------
 dfaca855-beb1-4d48-b028-03e5704bc837 | nginx:1.14.2                              | completed |           109 |           217
 9374cce4-b0f7-44f2-bdb5-e3146d556b4a | nginx:1.14.2                              | completed |           109 |           217
 5a26c76c-5403-4ede-b4d9-fdabfc2b2d42 | nginx:1.14.2                              | completed |           109 |           217
 50e52c91-c684-4391-b550-549a24885977 | redis:6.2.6-alpine                        | completed |            18 |            23
 ada86d82-ba4b-416c-9193-9c91e13651c6 | huggingface/transformers-pytorch-gpu:4.41 | failed    |               |
 dbdaaa0d-7d99-4f4c-94a9-a5290740bdd8 | ghcr.io/payments/api:1.4.2                | failed    |               |
 a4919497-59d4-443e-a046-84ee5cf7f2fe | ghcr.io/edge/api:2.0.0                    | failed    |               |
 08d8fcfd-4c8e-4877-a206-fa2087db1674 | docker.io/library/nginx:1.14.2            | completed |           109 |           217
 e4152aec-c23f-4f9f-b966-3e286496afe1 | nginx:1.14.2                              | completed |           109 |           217   (Wave E baseline)
```

The 3 failures are not bugs: `ghcr.io/payments/api:1.4.2`, `ghcr.io/edge/api:2.0.0`, and `huggingface/transformers-pytorch-gpu:4.41` are synthetic refs that have no actual upstream image to pull. The driver reported each failure via `/scan-jobs/{id}/fail` and the audit log shows it.

### findings table

```
SELECT count(*) FROM findings WHERE first_seen_at > NOW() - INTERVAL '30 minutes';
 recent_findings 
-----------------
             891
```

Severity rollup of new findings:

```
 severity | count 
----------+-------
 high     |   336
 medium   |   230
 low      |   172
 critical |   125
 info     |    28
```

### Dashboard rollup (curl /api/v1/dashboard/summary)

Severity rollup (after the run; prior baseline was the 46-finding seed):

```
"findings_by_severity": {
  "critical": 109,
  "high": 269,
  "info": 21,
  "low": 129,
  "medium": 181
},
"findings_total": 709,
"open_findings": 679,
"scan_queue_depth": 0,
"highest_risk": 100,
"recent_activity": [
  { "action": "scan-job.complete", "target_id": "9374cce4-b0f7-44f2-bdb5-e3146d556b4a" },
  { "action": "scan-job.complete", "target_id": "5a26c76c-5403-4ede-b4d9-fdabfc2b2d42" },
  { "action": "scan-job.complete", "target_id": "50e52c91-c684-4391-b550-549a24885977" },
  ...
]
```

`scan_queue_depth` dropped to zero — every queued job was claimed. `findings_by_severity` now includes the trivy+grype-deduped vulnerability stream from the four image scans.

### Sample finding (curl /api/v1/findings)

```
{
  "id": "...",
  "kind": "vulnerability",
  "external_id": "CVE-2019-9511",
  "title": "HTTP/2: large amount of data request leads to denial of service",
  "severity": "high",
  "risk_score": 84,
  "lifecycle": "open",
  "asset_id": "01cc9efa-9f55-4994-9f8c-7c3ff26bd82e",  -- nginx:1.14.2 asset
  "first_seen_at": "2026-05-12T15:52:22Z"
}
```

Newly-created assets (one per scanned image_ref, per scan, since the unique key uses NULL digest):

```
docker.io/library/nginx:1.14.2
nginx:1.14.2            (3 copies — three queued jobs requested the same ref)
redis:6.2.6-alpine
```

## Tests

```
$ go build ./internal/... ./cmd/constellation-scanner/... ./cmd/constellation-api/...
(no output — green)

$ CONSTELLATION_TEST_DATABASE_URL=... go test ./internal/scanner/... ./internal/handler/... -count=1
ok  github.com/alphabravocompany/constellation/internal/scanner   0.003s
ok  github.com/alphabravocompany/constellation/internal/handler   0.403s
```

Existing `TestScanJobs_QueueLifecycle` still passes — it submits `findings: []` so the new insert loop is a no-op for that test.

## Deferred / follow-up

1. **Operator should inject a scanner token.** The proper long-term fix is to have `controllers/constellationcluster_controller.go::reconcileScanner` (a) provision a `scanner_tokens` row on first reconcile, (b) write it into a `Secret` in the cluster namespace, and (c) mount it as `CONSTELLATION_SCANNER_TOKEN` on the scanner Deployment. The in-cluster pod will then claim its own jobs without the driver. Out of scope per "minimize churn"; flagged for the next operator wave.
2. **Finding upserts.** Currently each scan inserts new rows (partitioned table has no natural uniqueness on (org, asset, external_id, package)). Re-scanning the same image produces duplicates. A migration adding a deterministic dedupe key + ON CONFLICT path is the right next step but out of scope here.
3. **`Complete` handler accepts `scanner.Finding` payload as-is from a trusted scanner token.** That's correct since the token is server-issued and the middleware enforces org isolation; but if we ever expose this to less-trusted scanners we should validate severity/risk fields.
