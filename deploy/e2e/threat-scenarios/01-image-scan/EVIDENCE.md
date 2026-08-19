# Scenario 01 — Image vulnerability scan, end-to-end

**Engine:** scanner aggregator (Syft + Trivy + Grype) via
`constellationctl image-check`.

**Result:** PASS

## Attack / probe

A known-vulnerable Debian 9-based nginx image is pulled, SBOM'd, and matched
against the public CVE corpus.

```
/tmp/constellationctl image-check nginx:1.14.2 \
    --sarif captures/nginx-1.14.2.sarif \
    --json  captures/nginx-1.14.2.json
```

## Detection

| Surface | Evidence |
|---|---|
| SARIF (vendor-neutral) | `captures/nginx-1.14.2.sarif` — 217 results across `syft`, `trivy`, `grype`. |
| Aggregate JSON | `captures/nginx-1.14.2.json` — 109 packages, 217 findings (31 critical, 82 high, 54 medium, 43 low). |
| Top-CVE summary | `captures/image-check-summary.txt` |
| API findings | `captures/findings-api.json` — `/api/v1/findings?kind=vulnerability`. |
| Dashboard rollup | `captures/dashboard-summary.json` — `findings_by_severity: {critical:15, high:15, medium:5}` (org-scoped totals after dedupe). |
| Scan-job queue | `captures/scan-job-enqueue.json` — POST `/api/v1/scan-jobs` returns a pending job id. |
| Audit chain | `captures/audit-events.json` — `scan-job.enqueue` row appended. |

## Severity assertions

- SARIF result count ≥ 50 (target): **217** ✓
- CRITICAL count > 10: **31** ✓
- Severity rollup updated on `/dashboard/summary` ✓

## UI surface

The same image lands under `/findings` (severity facet pre-filtered to `critical`)
and the SBOM is fetchable as SPDX/CycloneDX from `/sbom/spdx/<asset_id>`.

## Reproduce

```
./run.sh
```

Inputs: `TOKEN` (env or `/tmp/h3-token`), `API=http://localhost:18080`,
`IMAGE=nginx:1.14.2` (override-able).
