# Constellation Stabilization & NeuVector-Parity Plan

Date: 2026-06-15
Status: Proposed (greenfield — anything may change before first stable release)
Owner: mj@alphabravo.io
Scope: `constellation/` (the product). `constellation-vulndb/` and `neuvector/` are reference/dependency repos and are touched only where called out.

---

## 0. How to read this document

This plan is organized as:

1. **Diagnosis** — what is actually wrong, with confirmed root causes and `file:line` evidence for the three symptoms you reported (confusing layout, wrong findings count, network map with no traffic) plus the underlying stability debt.
2. **Target architecture** — where Constellation needs to land to credibly compete with NeuVector.
3. **Workstreams (WS-A … WS-E)** — the actual work. Every task has: an ID, the problem, evidence, the fix (with code), a **Definition of Done (DoD)**, and **Reasoning**.
4. **Sequencing** — phased milestones so the project feels stable fast, then reaches parity.
5. **Verification needed from a live cluster** — the handful of things that require cluster/login access to confirm vs. fix blind.

Every claim below was verified by reading the code. Where a root cause is environmental (only confirmable on the running cluster), it is marked **[NEEDS CLUSTER]**.

---

## 1. Executive summary

The instinct that the project is "not quite stable" is **only partly borne out by the code**. Build, `go vet`, and the full Go test suite are green (314 source files / 169 test files, ~54% ratio — strong for the size). The instability is not crashes; it is **three correctness/UX defects that make the product look broken**, sitting on top of **architectural debt that will make change risky** as you push for parity.

The three reported symptoms have concrete, mostly-known root causes:

| Symptom | Root cause (confirmed) | Severity | Fix size |
|---|---|---|---|
| "30 findings on the running cluster don't look right" | The deployed VulnDB bundle is a **smoke bundle with no language-ecosystem coverage**: `ghsa=3` (failed: `GITHUB_TOKEN not provided`), `npm/pypi/maven/go ≈ 1` advisory each. Only OS-distro CVEs match → ~30. Compounded by `require-vulndb=false` default (scanner runs "ready" with a missing/empty store) and silent per-package matcher failures. | **High** | Medium |
| "Network map isn't showing traffic flow" | The backend flow pipeline is **fully wired and on by default**, but the **frontend `NetworkMapPage` never passes the active `cluster_id`** — it reads it from `window.location.search` on mount, which is empty on normal nav, so the map query is mis-scoped and renders empty. Compounded by DP observability gaps on eBPF CNIs and no flow retention. | **High** (frontend bug is P0) | Small (frontend) + Medium (DP) |
| "Layout is confusing" | IA sprawl: ~40 routes across 8 nav groups, **5 fully-built pages with no sidebar entry**, **duplicate Response/DLP/WAF surfaces**, label↔route mismatches (Workloads→`deployments`), and the vuln story split across 4 nav locations. NeuVector ships ~7 flat top-level areas. | **Medium** | Medium |
| (Underlying) "feels unstable" | `internal/handler` is a **44.7K-LOC god package** with 508 inlined raw SQL queries; **sqlc and protobuf are configured but generate nothing** (phantom contracts → silent drift); scan/scan-jobs schema is churny; one `panic()` on a live request path. | **Medium** | Large |

**The single highest-leverage fix** is the frontend `cluster_id` bug in the network map (WS-B1) — a few lines that likely turns the empty map back on. **The single most important correctness fix** is producing a real VulnDB bundle with GHSA + language ecosystems (WS-A1) — this is what makes findings credible against NeuVector.

The parity gap with NeuVector is real but addressable: Constellation already has a NeuVector-derived DP/DPI data plane compiled in, the flow ingest path, and a Postgres-backed graph endpoint. What it lacks is NeuVector's **three-tier aggregation, in-memory live graph, conversation/policy-learning model, and group/policy-mode primitives**. WS-E lays that out.

---

## 2. Diagnosis (detailed, with evidence)

### 2.1 Findings: why "30" looks wrong

"30" is **a real count, not a cap.** There is no `LIMIT 30` on vulnerabilities anywhere; the only `LIMIT 30` is on runtime file-threat events (`internal/handler/deployments.go:704`). API findings default to 100/max 1000 (`internal/handler/findings.go:70-71`), the dashboard requests `limit: 1000` (`frontend/src/pages/DashboardPage.tsx:57,61`). So the pipeline genuinely produced ~30 findings, and that is the problem.

**Root cause H1 (strongest) — the VulnDB bundle has no application-language coverage.** The only local bundle (`constellation-vulndb/.local/full-smoke-20260613T200730Z/`) was built with GHSA disabled:

```
ghsa  health=missing  policy=optional  status=failed  seen=0 emitted=0  error="ghsa: GITHUB_TOKEN not provided"
nvd   health=fresh    seen=50  emitted=50
```

Manifest `source_counts` confirms the data is ~99% OS-distro and language ecosystems are empty placeholders:

```
alpine: 50146, wolfi: 57367, ubuntu: 956, rhel: 548, oracle: 560, photon: 376 ...
ghsa: 3,  nvd: 420,
npm: 1, pypi: 1, maven: 1, go: 1, nuget: 1, rubygems: 1   ← placeholders, not real advisories
osv:npm: 39, osv:pypi: 42, osv:maven: 46, osv:go: 61       ← tiny OSV-only language coverage
```

The matcher builds language-namespace queries (`internal/scanner/vulndb.go:147-154`) that return almost nothing because there are almost no language advisories in the store. A typical app image (npm/pip/maven deps) therefore yields only its handful of OS-package CVEs. **This is the direct cause of an implausibly low, OS-only finding count.**

**Root cause H2 — `require-vulndb` defaults to false, so the scanner reports healthy with a broken store.** `cmd/constellation-scanner/main.go:71` defaults `require-vulndb=false`; Helm `values.yaml:312` keeps it false (only `values-prod.yaml` sets true). With it false, `/readyz` returns `ready` even when the bbolt store can't be opened (`main.go:478-480`), and scans proceed using only Trivy/Grype evidence. **[NEEDS CLUSTER]** to confirm whether the store is actually mounted/non-empty on your cluster — check the scanner pod `/readyz` `vulndb.record_count`.

**Root cause H3 — silent partial matcher failures.** `internal/scanner/vulndb.go:60-63` swallows per-query errors and only surfaces an error if *every* query fails AND zero findings result (`vulndb.go:75-77`). A partially-corrupt store or a single failing namespace silently shrinks the count with no operator-visible error. The aggregator similarly treats engine errors as non-fatal unless all engines fail (`internal/scanner/aggregator.go:88-101`).

**Root cause H4 — workload→image correlation gap.** Running-cluster vulns are produced by a read-time JOIN `image_scan_findings → image_scan_results → image_workload_links` (`internal/handler/cve.go:420-464`). If the running pod's image digest differs from the scanned image (mutable `:latest`, retag) or `image_workload_links` isn't populated, the JOIN under-reports. **[NEEDS CLUSTER]**.

**Root cause H5 — possible seed/demo data.** `cmd/constellation-seed/main.go:116-138` inserts exactly 11 findings (`CVE-2024-0001`, `CVE-2023-1234`, …). An E2E capture (`deploy/e2e/threat-scenarios/01-image-scan/captures/dashboard-summary.json:8`) shows `findings_total: 35`. If a seed/E2E rollup is being displayed, "~30" is demo data, not live results. **[NEEDS CLUSTER]** — check `first_seen_at` and whether CVE IDs are the obvious seed ones.

### 2.2 Network map: why no traffic flow

The backend chain is **fully wired and enabled by default** — DP DPI engine (`internal/runtime/dp/supervisor.go:18,326-360`, real C built in `deploy/docker/Dockerfile.runtime-agent:64-76`), DP→agent IPC (`internal/runtime/dp/ipc.go:62-107`), agent flow conversion (`cmd/constellation-runtime-agent/main.go:474-504`, `dp_flow.go:66`), bulk upload (`main.go:362`), ingest+persist (`internal/handler/network_flows_ingest.go:166-178`), and the map/conversations read APIs (`internal/handler/network.go:184-211`, `network_conversations.go:22-67`). Nothing is stubbed.

**Primary root cause — the frontend never scopes to the active cluster.** `NetworkMapPage` is the *only* cluster-scoped page that does not use `useCluster()`. It reads `cluster_id` once from the URL query string on mount and never updates it:

```ts
// frontend/src/pages/NetworkMapPage.tsx:111,119
const initialParams = useMemo(() => new URLSearchParams(window.location.search), []);
const [clusterID] = useState(() => initialParams.get("cluster_id") ?? "");   // <- empty on normal nav
```

When a user clicks "Network Map" in the sidebar they land on `/clusters/:id/network` with **no query string**, so `clusterID === ""` and `network.map({cluster_id: undefined})` (`:143`) is not scoped to the cluster. The `useCluster` contract (`frontend/src/hooks/useCluster.ts:6-9`: "thread the returned `cluster_id` into every data fetch… never query all-clusters data while in cluster mode") is violated only here. This is the most likely cause of the empty map and is a tiny fix (WS-B1).

**Secondary root cause — DP observability gaps [NEEDS CLUSTER].** DP observes via host-side veths matched by name prefix `veth,cali,lxc` (`internal/runtime/dp/podveth.go:62`). On **Cilium in eBPF mode**, pod traffic bypasses the veth/iptables path (`internal/runtime/dp/cnidetect.go:144-147`), so DP launches "ready" but sees little/no traffic. Custom CNIs whose veth names don't match also yield zero taps → zero flows. Even with the frontend fixed, the map can be empty if DP isn't capturing.

**Architectural gaps vs NeuVector (cause of fragility, not emptiness):**
- No agent-side or controller-side rolling graph cache — Constellation aggregates only at SQL read time (`network.go GROUP BY`), relying on every DP event surviving the HTTP→DB round-trip.
- **No flow retention/pruning** — `network_flows` rows accumulate forever in the default partition (opposite of NeuVector's bounded in-memory graph). This degrades the map query over time.
- `rpc StreamFlows` is defined (`proto/constellation/v1/services/runtime.proto:13`) but has **no server implementation**; ingest falls back to batched HTTP, and flows are dropped non-blocking when the channel is full (`main.go:500-503`).

### 2.3 Layout: why it's confusing

- **5 fully-built pages are orphaned** (route exists, no sidebar link, reachable only by typing the URL): `exceptions`, `response`, `runtime-policies`, `runtime-dlp`, `runtime-signatures` (routes `App.tsx:129,132,140,142,144`; absent from `CLUSTER_NAV` `AppShell.tsx:77-130`).
- **Duplicate concepts:** Response v1 (`/response`, `responseRules.*`) vs v2 (`/response-rules`, `responseRulesV2.*`); DLP at two scopes (`DlpSensorsPage` vs `RuntimeDLPPage`); WAF (`WafRulesPage` vs `runtime-signatures`). Users can't tell which surface is authoritative.
- **Label↔route mismatches:** sidebar "Workloads" → route `deployments` → `DeploymentsPage`; "Cluster Health" route `health` renders `ClustersPage`.
- **Vuln story split across 4 nav locations:** Posture→Findings, org Catalog→CVE DB, Runtime→Vuln Profiles, orphaned Exceptions. NeuVector consolidates these under one "Security Risks" area.
- **Overloaded Runtime group:** 8 flat items mixing monitoring (Network Map, Runtime) with policy authoring (WAF/DLP/Response/Vuln Profiles/Groups).
- **Inconsistent empty/error states:** only 39/52 page files handle error/empty; NetworkMapPage has none, so the `cluster_id` bug surfaces as a blank canvas with no explanation.

### 2.4 Architecture/stability debt

- **God package:** `internal/handler` = 44,711 LOC / 99 files (5× the next package), with 508 inlined raw SQL queries. Largest: `file_profiles.go` (2,895), `scanjobs.go` (2,303), `scan_attestations.go` (1,740), `deployments.go` (1,672).
- **Phantom abstractions:** `sqlc.yaml` + `db/queries/*.sql` + `make sqlc` exist but `internal/db/sqlc/` is never generated and `grep sqlc.New` → 0 hits; handlers use raw pgx. `proto/` has 7 services + 9 messages but **zero `.pb.go`** and no gRPC server — wire types are hand-kept Go structs "matching field-for-field." Both look load-bearing but aren't, hiding drift.
- **Schema churn concentrated in scanning:** `image_scan_artifacts` altered 32×, `scan_jobs` 21× across 87 migrations; `064_drop_legacy_host_vulnerabilities.sql` tears out work from 048–053.
- **One request-path panic:** `internal/handler/cluster_init_bundles.go:111` panics on KEK generation failure (crashes the API process instead of returning 500).
- **Untested critical path:** `internal/server` (router, every request) has no tests.

---

### 2.5 Live-cluster confirmation (2026-06-15, k3s `constellation-system`)

The Constellation stack is running in k3s (flannel CNI, single node `constellation-dev-1-mj`). Direct inspection upgraded the hypotheses above from "likely" to **confirmed**:

**Findings — confirmed H1 (language-blind bundle), confirmed H2 (require-vulndb=false).**
- The app DB has **228 vulnerability findings = 30 `high` + 198 `info`**. The "30" you reported is the 30 high-severity ones.
- **All 30 high findings are distro OpenSSL CVEs** — every title is `"Important: openssl security update"` (RHEL-style), `canonical_engine=vulndb`, `target_type=image`, CVE IDs `CVE-2026-34180…45447`. **Zero application-language (npm/pypi/maven) findings.** This is the language-blind smoke bundle producing OS-only matches, exactly as diagnosed.
- The scanner pod has `CONSTELLATION_SCANNER_REQUIRE_VULNDB=false` and a **1.0 GB `vulndb.bbolt` dated Jun 13** (the `ghsa=3` smoke bundle) at `/var/lib/constellation/vulndb.bbolt`. The store is present but language-blind — so the scanner is "ready" and scanning against bad intelligence. (Both fixed: A1 new bundle + A2 require-vulndb=true.)

**Network map — confirmed frontend bug AND a new backend IPC bug; CNI ruled out.**
- `network_flows` table is **empty (0 rows)** — so even with the frontend fix the map would be empty, just with a correct empty state.
- The runtime-agent DP **is capturing**: heartbeat shows `dp_starts=1, dp_taps_added=42, dp_taps_current=18, dp_taps_errors=0`, with `dp tap: added iface vethXXXX` logs. Flannel `veth*` names matched DP's tap prefix — **the Cilium-eBPF blind-spot hypothesis does NOT apply here.**
- But the **DP→agent IPC return path is dead**: `dp_rx_total=0, dp_conn_events=0, flows_uploaded=0`, with `dp_ka_sent=24645, dp_ka_replied=42, dp_ka_errors=24605` and `dp_rx_bad_hdr=0/bad_pl=0/dropped=0` (nothing arrives at all — not malformed). The agent can configure DP (taps added) but never receives DP's connection reports → zero flows. This is a real, previously-unknown bug — see **WS-B6**.

**Bonus bug found:** the runtime-agent logs `dlp sync: fetch failed err="server 401"` every 60s — a DLP-sync auth/token bug between agent and API (low severity, tracked as WS-B7).

---

## 3. Target architecture (to compete with NeuVector)

NeuVector's moat is three things Constellation must match: (1) a **live L7 network conversation map** built bottom-up from DPI, (2) **policy learning** (Discover→Monitor→Protect) that turns observed conversations into segmentation rules, and (3) **credible running-workload vulnerability counts** with fast asset pivots. The supporting primitives are **Groups** (selector-based), **two policy modes per group** (network + process/file), and a **distributed control plane**.

Target shape for Constellation (keeping its Postgres-centric, HTTP-first design rather than copying NeuVector's Consul/gRPC stack):

```
                       ┌──────────────────────────────────────────────┐
   per-node            │            constellation-api                  │
 ┌───────────┐  flows  │  ┌────────────┐   ┌───────────────────────┐   │
 │ runtime-  │────────►│  │ flow ingest│──►│ in-memory Conversation│   │
 │  agent    │  HTTP/  │  │  + resolve │   │   graph (hot cache)   │──►├─► /network/map
 │  + DP/DPI │  gRPC   │  └────────────┘   └──────────┬────────────┘   │   /network/conversations
 └───────────┘ stream  │                    periodic flush │           │
       │               │                  ┌───────────────▼──────────┐ │
       │ vulns         │                  │ network_flows (retained, │ │
       ▼               │                  │  partitioned, pruned)    │ │
 ┌───────────┐         │                  └──────────────────────────┘ │
 │ scanner   │──findings─►  findings / image_scan_findings              │
 │ +VulnDB   │         │   + policy-learning engine (groups→rules)      │
 └───────────┘         └──────────────────────────────────────────────┘
```

Key decisions:
- **Keep DP/DPI** (already compiled) as the L7 source — it is the differentiator vs L3/L4-only (Hubble/Cilium) maps.
- **Add an in-memory conversation graph** in `constellation-api` fed by ingest, flushed to `network_flows` for durability — mirrors NeuVector's hot graph without adopting Consul.
- **Add Groups + policy modes** as first-class primitives, then a learning engine.
- **Decide the contract layer:** either generate sqlc + protobuf for real, or delete them. No phantom contracts.

---

## 4. Workstreams

Priority key: **P0** = ship this week (makes the product look working). **P1** = stabilize. **P2** = parity. Each task: Problem → Fix (code) → DoD → Reasoning.

---

### WS-A — Findings correctness & VulnDB trust

#### A1 (P0) — Produce and ship a real VulnDB bundle (GHSA + language ecosystems)

**Problem.** The deployed bundle has no GHSA and ~zero language-ecosystem advisories (§2.1), so app-container findings are OS-only and implausibly sparse.

**Fix.** Rebuild the bundle with the **production profile + a GitHub token** (the smoke bundle used `-profile dev`, which caps every source and skips GHSA). Full runnable steps are in **Appendix B — VulnDB rebuild runbook**; the short version:
1. `export GITHUB_TOKEN=…` and `export NVD_API_KEY=…`, then run `vulndb-aggregator -profile production` (this enables GHSA and uncaps OSV/NVD/distros), build the bundle, and install the resulting `vulndb.bbolt` into Constellation at `/var/lib/constellation/vulndb.bbolt`.
2. Add a **population gate** that fails the build if language ecosystems are empty. In `constellation-vulndb/internal/population` (or the bundle-population-check command), add minimum thresholds:
   ```go
   // population thresholds — a bundle with near-zero language advisories is not shippable
   var minSourceCounts = map[string]int{
       "ghsa":  5000,   // GHSA carries the bulk of npm/pypi/maven/nuget/go advisories
       "nvd":   100000, // full NVD, not the 50-CVE smoke slice
       "npm":   1000,
       "pypi":  1000,
       "maven": 1000,
   }
   func checkPopulation(counts map[string]int) error {
       var failed []string
       for src, min := range minSourceCounts {
           if counts[src] < min {
               failed = append(failed, fmt.Sprintf("%s=%d (<%d)", src, counts[src], min))
           }
       }
       if len(failed) > 0 {
           return fmt.Errorf("bundle below minimum population: %s", strings.Join(failed, ", "))
       }
       return nil
   }
   ```
3. Re-import into Constellation and re-scan a representative workload.

**DoD.**
- A bundle exists with `ghsa ≥ 5000`, full NVD, and non-placeholder npm/pypi/maven counts; `make vulndb-bundle-verify` passes; the population gate is enforced in CI (`.github/workflows`).
- Scanning a known-vulnerable app image (e.g. an old `node:14` or `python:3.7`) produces language-package CVEs, not just OS CVEs.
- The running-cluster finding count for that workload rises to a plausible number and includes npm/pypi/maven entries.

**Reasoning.** This is the actual cause of "30 findings." Everything else in WS-A is defense-in-depth so a bad bundle can never again look like a working product.

---

#### A2 (P0) — Make a missing/empty VulnDB store fail loudly

**Problem.** `require-vulndb=false` default + readyz passing on a broken store (§2.1 H2) means the scanner silently degrades to OS-only evidence with no operator signal.

**Fix.**
1. Flip the default and the Helm values to require VulnDB in real deployments:
   ```go
   // cmd/constellation-scanner/main.go:71
   requireVulnDB = flag.Bool("require-vulndb",
       envBool("CONSTELLATION_SCANNER_REQUIRE_VULNDB", true), // was false
       "Fail /readyz when the local VulnDB store cannot be opened")
   ```
   ```yaml
   # deploy/charts/constellation/values.yaml:312
   requireVulnDB: true   # was false
   ```
2. Surface a **bundle health banner** in the API/UI. Add `vulndb.record_count` and `bundle_version` to `GET /api/v1/vulndb/status` (the scanner already computes them in `vulnDBStatus()` `main.go:490-521`) and render a warning in the frontend when `record_count` is suspiciously low or `status != ready`.
3. Add a startup log + metric when language-namespace advisory count is ~0:
   ```go
   // internal/scanner/vulndb.go — after opening the store
   if langAdvisories := metadata.LanguageAdvisoryCount; langAdvisories < 1000 {
       log.Warn("vulndb: language-ecosystem advisories look empty; findings will be OS-only",
           "language_advisories", langAdvisories, "bundle_version", metadata.BundleVersion)
   }
   ```
   (Add `LanguageAdvisoryCount` to bundle metadata if not present.)

**DoD.** With no/empty store, the scanner pod is `not-ready` and does not claim jobs; the UI shows a clear "VulnDB unavailable/stale" banner; a metric `constellation_scanner_vulndb_record_count` is exported.

**Reasoning.** A security scanner that silently scans with no vuln DB is worse than one that refuses — it manufactures false confidence. NeuVector treats CVE DB presence as a hard dependency.

---

#### A3 (P1) — Stop swallowing matcher failures

**Problem.** Per-package query errors are dropped unless every query fails (`internal/scanner/vulndb.go:60-63,75-77`); a partial store corruption silently shrinks counts.

**Fix.** Track and surface partial failures as scan-job warnings rather than discarding them:
```go
// internal/scanner/vulndb.go
var queryErrs int
for _, query := range packageQueries(pkg, ref) {
    matches, err := store.ScanPackage(query)
    if err != nil {
        queryErrs++
        if firstQueryErr == nil { firstQueryErr = err }
        continue
    }
    ...
}
// ...after the loop, attach a non-fatal warning to the EngineResult:
result.Warnings = append(result.Warnings,
    fmt.Sprintf("vulndb: %d package queries failed (first: %v)", queryErrs, firstQueryErr))
```
Plumb `Warnings` through `EngineResult` → scan-job completion (`internal/handler/scanjobs.go:819`) → a `scan_jobs.warnings` column → the UI scan-detail view.

**DoD.** A scan against a deliberately truncated store reports the warning count in the scan-job detail and in scanner logs; the finding count is not silently reduced without a visible signal.

**Reasoning.** Observability of degradation is a stability feature; "looks wrong but no error" is exactly the reported experience.

---

#### A4 (P1) — Verify and harden workload→image correlation

**Problem.** Running-cluster vulns depend on `image_workload_links` digest matching (§2.1 H4). Mutable tags / unpopulated links under-report. **[NEEDS CLUSTER]** to confirm.

**Fix.**
1. Add a diagnostic endpoint/CLI: for each running workload, report `image_ref`, resolved digest, whether a matching `image_scan_results` row exists, and the link match strategy used (digest / ref / normalized / repo+tag — `internal/handler/cve.go:441-460`).
2. Emit a metric for **unlinked running images** (images on workloads with no scan result), surfaced as "coverage gaps" in the UI (there is already a `coverage` org page).
3. Ensure the discoverer/runtime-agent always records the **resolved digest** of running pods, not just the tag, so links bind on digest.

**DoD.** A "scan coverage" view lists running workloads whose images are unscanned or unlinked; the count of correlated findings matches `image_scan_findings` for linked images in an E2E test.

**Reasoning.** NeuVector's running-workload counts are trusted because correlation is explicit; Constellation needs the same visibility to avoid "where did my findings go."

---

#### A5 (P2) — Asset-centric vuln index + re-count without rescan

**Problem.** NeuVector keeps a local asset-vuln index (`db/vulasset.db`) and recomputes counts when the CVE DB or vuln profile changes, without rescanning. Constellation recomputes at read time via JOINs and has no fast CVE→assets pivot.

**Fix.** Materialize an `asset_vuln_summary` table (per asset: critical/high/medium/low counts + bundle version) updated on scan completion and on bundle import; back the CVE→affected-assets view (`internal/handler/cve.go`) with it. On bundle import, re-evaluate counts from cached raw findings rather than requeuing scans.

**DoD.** Changing the active bundle version updates per-asset counts within one import cycle with no new scan jobs; CVE→assets pivot is a single indexed query.

**Reasoning.** Parity for the "Security Risks" experience and a prerequisite for fast dashboards at scale.

---

#### A6 (P1) — Fix the single-transaction bbolt store build (confirmed slow on a real bundle)

**Problem.** Confirmed while building the first production-grade bundle (2026-06-15): a real DB (529k advisories, **4.74M package ranges, 48.2M total records**) materializes into `vulndb.bbolt` via a **single `db.Update` transaction** (`constellation-vulndb/pkg/bundledb/store.go:154`). bbolt holds all dirty pages in memory (observed ~4 GB RSS) and rebalances its B+tree on every `Put` (each record writes to row/typed/index buckets — `store.go:553-561,711-750`), so build time degrades super-linearly: **30+ minutes of pegged CPU** with the output file still empty until the final commit. The old smoke bundle (468k records) hid this because it was ~100× smaller.

**Why it matters.** This is on the **production importer path** — Constellation's `vulndb-bundle-install` materializes/installs stores the same way. A 30+ min, 4 GB-RSS build makes routine bundle updates operationally painful and risks OOM on smaller importer pods. It also blocks fast iteration on the cluster.

**Fix.** Chunk the build into bounded transactions instead of one giant `db.Update`:
```go
// store.go — commit every N records so dirty pages flush and memory stays bounded
const buildBatchSize = 50_000
batch := 0
flush := func() error {
    if err := tx.Commit(); err != nil { return err }
    tx, err = db.Begin(true)   // start the next write tx
    return err
}
// ...inside the record loop, after writing each record's row/typed/index puts:
if batch++; batch >= buildBatchSize { if err := flush(); err != nil { return err }; batch = 0 }
```
Also set `bbolt.Options{NoSync: true}` during the build and a single `db.Sync()` at the end (the store is a rebuildable artifact, so per-tx fsync is wasted), and consider pre-sorting keys before insert to keep bbolt's append-mostly path fast.

**DoD.** A full real bundle (≈48M records) materializes in a few minutes with bounded (<1 GB) RSS; `vulndb-bundle-query -counts` matches the source DB; a benchmark/test asserts build time and peak memory stay within budget for a representative large bundle.

**Reasoning.** A vulnerability platform must be able to ship a fresh DB quickly and on modest hardware; a 30-minute single-transaction build is a scalability wall on the most important operational path (keeping intelligence current).

---

#### A7 (P1) — Dedup references in the generation engine (confirmed: 41.8M rows → 610k distinct URLs)

**Problem.** Confirmed building the first production bundle (2026-06-15): `vuln_references` held **41,809,164 rows but only 610,506 distinct URLs** — and it was the single biggest contributor to a 39 GB store. Root cause is a **per-CVE reference fan-out** in the distro sources: for a distro advisory covering N CVEs, the code emits one record per CVE and passes the advisory's *entire* reference list to each (`internal/sources/distros/{suse,oracle,almalinux,azurelinux,rocky}/*.go` → `for _, cve := range cves { v2util.Record(..., d.References) }`). A 30-CVE advisory with 30 refs becomes 900 reference rows. The existing `(advisory_id, url, source)` unique-dedup (`internal/store/store.go:1554`) can't collapse it because each fanned-out CVE is a distinct `advisory_id`. References are **display-only metadata — the package→CVE matcher never queries them.**

**Fix (two parts, both in the generation engine — not a manual truncate).**
1. **Normalize URLs at hydration.** Add a distinct `vuln_reference_urls(id, url, ...)` table and make `vuln_references` a thin link `(advisory_id, url_id, ref_type, source)`. Store each URL string + tags once (≈610k) instead of 41.8M times. Dedup on insert by URL.
   ```sql
   CREATE TABLE IF NOT EXISTS vuln_reference_urls (
       id BIGSERIAL PRIMARY KEY,
       url TEXT NOT NULL UNIQUE
   );
   -- vuln_references.url_id BIGINT REFERENCES vuln_reference_urls(id)
   ```
2. **Exclude references from the matching store.** The bbolt builder (`pkg/bundledb/store.go`) should not materialize the references table into the queryable store (it's never read for matching). Ship references, if needed at all, as a separate optional metadata artifact or serve them from the producer API. This keeps the deployed `vulndb.bbolt` lean independent of reference volume.

   Optionally also fix the fan-out at the source: keep references on the advisory-group record rather than copying onto every per-CVE record.

**DoD.** A full production bundle stores each distinct reference URL once; the matching `vulndb.bbolt` contains no reference bloat; store size is driven by advisories+ranges, not references; `vulndb-bundle-query -counts` shows reference storage proportional to distinct URLs, not advisory×ref fan-out.

**Reasoning.** This is the user-flagged fix: dedup belongs in the hydration/generation engine, not a post-hoc cleanup. It cut the first real bundle's store from 39 GB toward a deployable size and removes a permanent scaling tax on every future bundle.

---

#### A8 (P0) — Shrink the matching store ~50× (confirmed: 20.7 GB vs NeuVector ~100–300 MB)

**Problem.** Confirmed deploying the first real bundle (2026-06-15): the materialized `vulndb.bbolt` is **20.7 GB** even with references excluded. Reference comparators: NeuVector cvedb ~100–300 MB (gzip), Grype ~200–400 MB compressed, Trivy ~1–1.5 GB. Ours is **50–100× too large**, which makes it impractical to ship, `kubectl cp`, mount on modest nodes, or update frequently. Root causes in `constellation-vulndb/pkg/bundledb/store.go`:
1. **Double storage.** `insertRecord` (`store.go:588-621`) writes each record's raw JSON to the `bundle_rows` bucket **and** re-stores the same JSON in the `typed` bucket via `putTyped`, then adds `indexes`. Every advisory/range is persisted ≥2× plus index keys.
2. **Uncompressed payloads + bbolt page overhead.** Verbose JSON stored raw; bbolt 4 KB pages waste space on millions of small values.
3. **Unbounded distro coverage.** Fully-uncapped ingest (ubuntu 2.3M ranges, etc.) — more than a scanner matcher needs.

**Fix (in priority order).**
- **Compress record payloads (primary lever).** Store zstd/gzip-compressed blobs in the typed buckets *and* `bundle_rows`, or **pack many records per bbolt value** (e.g., per-namespace range blocks) to amortize 4 KB-page overhead. JSON compresses ~5–10×. This preserves the existing read contracts (see caveat below) while delivering the bulk of the win. Decompress in `query.go` (`LookupAdvisories`/`LookupPackageRanges`/`RowsByTable`).
- **Drop the redundant `bundle_rows` copy for matchable tables — but mind the contract.** The matcher reads only `typed` + `indexes`; `bundle_rows` is otherwise read solely via the public `Store.RowsByTable` (used by `cmd/vulndb-bundle-query`, `pkg/compat` for `vuln_references`, and `internal/overrides/audit`). Confirmed 2026-06-15: naively skipping the raw write for advisories/ranges/etc. breaks `RowsByTable` for those tables (two store tests assert it) — so EITHER migrate those callers onto the typed path and then drop the raw copy, OR keep `bundle_rows` but compressed. Do not silently drop it.
- **Build only matching indexes** (package-name/PURL → advisory; alias → advisory). Drop any index not used by `LookupPackageRanges`/`LookupAdvisories`.
- **Record-packing (the dominant size lever, lossless).** Store many ranges per gzipped bbolt value keyed by `namespace+package` (the multi-index points at the block; lookup decompresses + version-filters). With 4.7M tiny ~100–300 B rows, bbolt's 4 KB page granularity dwarfs the data — packing amortizes page overhead AND gives gzip large blocks. This is what gets toward NeuVector's hundreds-of-MB range; per-row gzip alone cannot.
- **Release-scoped OS namespaces (size + correctness, the scoping lever).** MEASURED 2026-06-15: the store is 91% distro data; **Ubuntu is 50% alone — 2.37M ranges over 10,358 packages = 228 ranges/package** because data for every Ubuntu release is carried with the release encoded only in the version suffix (`…ubuntu1.3`), `module_stream` empty. Model OS namespaces per release (`ubuntu:22.04`, `debian:12`, `alpine:3.18`) in the distro sources (`constellation-vulndb/internal/sources/distros/*`) so the matcher scopes a container to its own release (FIXES cross-release false matches) and the store can ship only supported releases. Plus **dedup the RHEL-family** (rocky/oracle/almalinux/rhel ≈ 31%, near-identical rebuilds) to a canonical advisory + rebuild mapping.

**Measured baseline (2026-06-15):** per-row gzip alone took the real bundle from **20.7 GB → 12 GB (43%)** with verified match parity (lodash=21, log4j coordinate=23, django=402). Insufficient — the path to <1 GB is packing + release-scoping + RHEL dedup on top of gzip.

**DoD.** A full production bundle materializes to a `vulndb.bbolt` **under ~1 GB** (target NeuVector/Grype range) with identical match results (a fixed corpus of images yields the same findings before/after); store-size and match-parity are asserted in a test/benchmark; the store ships and installs on a node with a few-GB volume.

**Reasoning.** DB size is a first-class competitive property: NeuVector/Grype/Trivy are all sub-1.5 GB. A 20 GB store blocks air-gapped delivery, fast updates, and modest-node deployment — the exact operability story the product sells. This is the highest-leverage store fix after correctness.

---

#### A9 (P0) — Ecosystem package-name normalization (confirmed: Maven silently under-matches)

**Problem.** Confirmed 2026-06-15 against the live cluster's new store: the DB has rich Maven coverage but the scanner under-matched it because advisory sources key Maven by the full `groupId:artifactId` coordinate (GHSA/OSV) while others use the bare artifactId, and the two buckets don't overlap: `log4j-core` → 7 ranges vs `org.apache.logging.log4j:log4j-core` → 23; `guava` → 11 vs `com.google.guava:guava` → 3. The scanner's `packageQueries` (`constellation/internal/scanner/vulndb.go`) only queried the bare name even though Syft supplies the group in the PURL namespace (`parsed.Namespace`). Net effect: great Java DB coverage that doesn't surface. (npm/pypi verified fine: lodash=21, django=402.) This is the decoupled-scanner-+-multi-source-DB normalization tax that NeuVector avoids by co-designing scanner output with its own cvedb, and that Grype solves with a per-ecosystem normalization layer.

**Fix (two parts).**
- **Matcher (DONE this session):** `languagePackageNameCandidates` now queries both the bare name and the ecosystem coordinate — Maven `group:artifact`, Composer `vendor/package` — deduped (`internal/scanner/vulndb.go`). Build/vet/tests green. EXTEND: audit every ecosystem in `languageNamespaces` for naming divergence (nuget casing, golang module paths [ok], swift, pub, etc.) and add a normalization table + unit tests with real Syft PURLs per ecosystem.
- **Producer canonicalization (TODO):** during hydration, reconcile the same package across sources to one canonical key with aliases (so `log4j-core` and `org.apache.logging.log4j:log4j-core` resolve to one entity), rather than pushing the reconciliation onto every consumer.

**DoD.** A Syft SBOM of a known-vulnerable Java image (e.g. log4j-core 2.14.1) surfaces log4shell via the scanner end-to-end; a per-ecosystem matcher test asserts coordinate + bare-name coverage; producer stores one canonical package identity with source aliases.

**Reasoning.** DB coverage is worthless if the matcher can't address it. This is the difference between "we ingested 11.6k Maven ranges" and "we actually find Java CVEs." Highest-priority correctness item after having a good DB.

---

### WS-B — Network traffic map

#### B1 (P0) — Fix `NetworkMapPage` cluster scoping (likely turns the map back on)

**Problem.** The page never threads the active `cluster_id` (§2.2). Empty map on normal navigation.

**Fix.** Replace the URL-search reads with `useCluster()`/`useParams()`, exactly as the sibling runtime pages do (`RuntimePoliciesPage.tsx:54`):
```ts
// frontend/src/pages/NetworkMapPage.tsx
import { useCluster } from "@/hooks/useCluster";

function NetworkMapInner() {
  const queryClient = useQueryClient();
  const { clusterId } = useCluster();              // <- active cluster from /clusters/:id/*
  const clusterID = clusterId ?? "";

  // keep hours/namespace/verdict as real UI state (re-add the dropdowns), not URL-on-mount:
  const [hours, setHours] = useState(24);
  const [namespace, setNamespace] = useState("");
  const [verdict, setVerdict] = useState("");
  ...
  const q = useQuery({
    queryKey: ["network-map", hours, clusterID, namespace, verdict],
    queryFn: () => network.map({ hours, cluster_id: clusterID || undefined,
                                 namespace: namespace || undefined, verdict: verdict || undefined }),
    enabled: !!clusterID,                           // don't fire an unscoped query
    refetchInterval: live ? 10_000 : false,
  });
```
Remove the dead `initialParams`/`useState` URL reads at lines 111–121.

**DoD.** Navigating to a cluster's Network Map fires `GET /network/map?cluster_id=<id>&hours=24`; with flows present, nodes+edges render; with none, an explicit empty state (B2) shows.

**Reasoning.** Smallest possible change with the largest visible impact; restores the headline feature.

---

#### B2 (P0) — Add empty/error/loading states to the network map

**Problem.** No empty/error state (§2.3), so a genuinely flow-less cluster is indistinguishable from a bug.

**Fix.** Render distinct states: loading skeleton; query error; and "No traffic observed in the last N hours" with a diagnostic hint linking to runtime-agent/DP health (does this cluster's CNI support DP tap? is `dp.enabled`? is the agent uploading?).
```tsx
if (q.isLoading) return <NetworkMapSkeleton />;
if (q.isError)  return <ErrorState onRetry={q.refetch} message="Failed to load network flows" />;
if (!workloads.length && !flowsNoSelf.length)
  return <EmptyState title="No traffic observed"
            body={`No network flows in the last ${hours}h for this cluster.`}
            hint="Check that the runtime-agent DaemonSet is running with dp.enabled and that this cluster's CNI supports DP tap (Cilium eBPF requires extra config)."
            action={<Link to={`/clusters/${clusterID}/health`}>View agent health</Link>} />;
```

**DoD.** Each state is visually distinct; the empty state names the likely operational causes.

**Reasoning.** Turns a "broken feature" into an actionable diagnostic and removes a class of false bug reports.

---

#### B3 (P1) — Confirm DP is actually capturing on this cluster [NEEDS CLUSTER]

**Problem.** Even scoped correctly, the map is empty if DP sees no traffic (Cilium eBPF bypass / non-standard veth names, §2.2).

**Fix (investigation + hardening).**
1. On the cluster: confirm the runtime-agent DaemonSet runs with `CONSTELLATION_DP_ENABLED=true`, check agent logs for `kind: dp.connection` events (`main.go:507`), and confirm `POST /api/v1/network-flows:bulk` returns 200 with non-zero rows.
2. If CNI is Cilium eBPF: add a documented fallback flow source. Either (a) consume **Cilium Hubble** flows for L3/L4 edges where DP can't tap, or (b) widen DP veth discovery beyond `veth,cali,lxc` (`internal/runtime/dp/podveth.go:62`) for custom CNIs, behind a config flag.
3. Add a runtime-agent self-report: `network_flow_taps_active`, `flows_emitted_total`, `flows_uploaded_total`, `flow_upload_failures_total` metrics, surfaced in Cluster Health.

**DoD.** Cluster Health shows per-node DP tap status and flow emission/upload counters; on a supported CNI, flows appear within minutes; on Cilium eBPF, either Hubble fallback populates L3/L4 edges or the empty state explains the limitation.

**Reasoning.** This is the real-world reason NeuVector "just works" and a TAP-only competitor doesn't; we must either match capture coverage or be honest about it in-product.

---

#### B4 (P1) — Add flow retention/pruning

**Problem.** `network_flows` rows accumulate forever in the default partition (§2.2), degrading the map query and the DB over time.

**Fix.** Add a retention job (reuse `audit-archiver` pattern) that drops `network_flows` partitions older than a configurable window (default 7–30 days), and ensure time-partitioning is by `at`. Add an index supporting the map query's `at >= NOW() - interval` + `cluster_id` filter.

**DoD.** Old partitions are dropped on schedule; map query latency is bounded; a migration + retention CronJob exist in the chart.

**Reasoning.** NeuVector bounds its in-memory graph; Constellation's durable store needs the equivalent bound or it rots.

---

#### B5 (P2) — In-memory conversation graph + `StreamFlows`

**Problem.** Constellation aggregates only at SQL read time and drops flows when the channel is full; `StreamFlows` is unimplemented (§2.2).

**Fix.** Implement the in-memory ConversationGraph in `constellation-api` (model below in WS-E1), fed by ingest and periodically flushed to `network_flows` for durability. Implement the gRPC `StreamFlows` server (or a streaming HTTP fallback) so the agent stops dropping under load.

**DoD.** Map/conversations served from the hot graph (sub-100ms) with SQL as durable backing; agent no longer drops flows non-blocking; load test sustains N flows/s without loss.

**Reasoning.** This is the structural parity item; it also fixes the "every event must survive an HTTP round-trip" fragility.

---

#### B6 (P0) — Fix the DP→agent IPC return path (confirmed: zero connection events reach the agent)

**Problem.** Confirmed on the live cluster (§2.5): DP taps traffic but the agent never receives DP's messages — `dp_rx_total=0`, `dp_conn_events=0`, `flows_uploaded=0`, with `dp_ka_errors=24605` (only 42 of 24,645 keepalives answered). `network_flows` is therefore empty regardless of the frontend fix. Sockets present: `/tmp/dp_listen.sock` (DP listener), `/tmp/ctrl_listen.sock` (agent listener, mode `srw-------`), `/tmp/dp_client.<agentpid>`.

**Fix.** Root-cause is under investigation in `internal/runtime/dp/{ipc.go,proto.go,supervisor.go,client.go}` and `third_party/neuvector/dp/ctrl.c` (compare against working `neuvector/agent/dp/`). Leading candidates: the agent binds a receive socket DP doesn't send to (ctrl_listen vs the auto-bound `dp_client.<pid>`); a missing register/destination handshake so DP never learns where to reply; or a unixgram address/recvfrom issue. The keepalive error path (24k errors) is the fastest reproducer — fix that and connection reports should follow.

**DoD.** After the fix, the agent heartbeat shows `dp_ka_replied` tracking `dp_ka_sent`, `dp_rx_total > 0`, `dp_conn_events > 0`, and `flows_uploaded > 0`; `network_flows` accumulates `source='dp'` rows; the network map renders edges on the live k3s cluster. A regression test covers the DP↔agent IPC round-trip (keepalive + one synthetic connection report).

**Reasoning.** This is the actual reason the map is empty on a CNI where capture works. It is the highest-value backend fix for the network-map symptom and a prerequisite for the entire conversation-graph parity story (WS-E1).

#### B7 (P2) — Fix runtime-agent DLP sync 401

**Problem.** The agent logs `dlp sync: fetch failed err="server 401"` every 60s (§2.5) — the DLP-rule sync call to the API is unauthorized.

**Fix.** Trace the agent's DLP sync client auth (bootstrap token / service-account header) vs the API's auth middleware for the DLP-sync route; align the credential. Likely a missing or stale bearer token on the agent's sync request.

**DoD.** No recurring 401 in agent logs; DLP rules sync successfully (or the feature is explicitly gated off with no error spam).

**Reasoning.** Low severity but it's continuous error noise that masks real problems and erodes the "stable" feel.

---

### WS-C — Frontend IA / UX overhaul

#### C1 (P1) — Resolve orphaned and duplicate pages

**Problem.** 5 orphaned pages, duplicate Response/DLP/WAF surfaces (§2.3).

**Fix.** Decide one authoritative surface per concept and either link or delete:
- **Response:** keep v2 (`/response-rules`, `responseRulesV2`), delete v1 `ResponsePage` + route `App.tsx:132` + `responseRules.*` client methods.
- **DLP:** pick one of `DlpSensorsPage` / `RuntimeDLPPage`; delete the other; single sidebar entry.
- **WAF:** same for `WafRulesPage` / `runtime-signatures`.
- **Exceptions / runtime-policies:** either add to the sidebar (preferred — they're built) or remove the routes.

**DoD.** No route is reachable-but-unlinked; no two pages manage the same concept; `grep` for the deleted client methods returns 0.

**Reasoning.** Duplicate/orphan surfaces are the literal "confusing layout"; deleting code also reduces the maintenance surface.

---

#### C2 (P1) — Restructure navigation toward NeuVector-style top-level areas

**Problem.** ~40 routes / 8 groups; vuln story split 4 ways; overloaded Runtime group (§2.3).

**Fix.** Collapse the cluster sidebar to ~6 top-level areas mapping to NeuVector's mental model, with sub-nav inside:

| Top-level area | Contains |
|---|---|
| **Dashboard** | overview |
| **Network Activity** | Network Map, runtime threats, learned/observed flows |
| **Assets** | Nodes, Images, Workloads (rename route `deployments`→`workloads`), Serverless, Repositories, Registries |
| **Security Risks** | Findings, CVE DB, Vuln Profiles, Exceptions (the four scattered vuln surfaces, unified) |
| **Policy** | Admission/Network Policies, Groups, Response Rules, WAF, DLP, Process Baselines |
| **Settings/Activity** | Audit Log, Components, Cluster Health, Integrations, Access Control |

**DoD.** Sidebar has ≤6 cluster-mode groups; every vuln surface lives under "Security Risks"; route names match labels (`workloads`, `cluster-health`).

**Reasoning.** Discoverability and a coherent mental model are the difference between "feels like a product" and "feels like a pile of pages." Matching NeuVector's IA also eases competitive evaluation.

---

#### C3 (P2) — Standardize loading/empty/error states + naming

**Problem.** 13/52 pages lack error/empty handling; label↔route mismatches (§2.3).

**Fix.** Extract shared `<LoadingState>`, `<EmptyState>`, `<ErrorState>` components and adopt them across all data pages; rename `deployments`→`workloads` route and the `health`/`ClustersPage` confusion. Add a lint rule or PR checklist requiring the three states on any `useQuery` page.

**DoD.** Every data page renders all three states; route names match nav labels; a shared component is used (no bespoke spinners).

**Reasoning.** Consistency is perceived stability; it also makes the network-map empty state (B2) part of a pattern, not a one-off.

---

### WS-D — Architecture & stability hardening

#### D1 (P1) — Decide the contract layer: adopt or delete sqlc and protobuf

**Problem.** sqlc and protobuf are configured but generate nothing; wire types and queries are hand-maintained "to match" (§2.4). Silent drift.

**Fix.** Choose per layer and make CI enforce it:
- **sqlc:** either run `make sqlc` and migrate the hottest handlers to generated typed queries (directly attacking the god package), or delete `sqlc.yaml` + `db/queries/` + `make sqlc`. Recommended: **adopt**, starting with scan-jobs/findings queries.
- **protobuf:** either wire `buf generate` into CI and serve the defined services (needed anyway for `StreamFlows`, B5), or delete `proto/` and document the Go structs as the source of truth. Recommended: **adopt for the runtime/flow services**, delete the rest.

**DoD.** No configured-but-unused generator remains; CI fails if generated code is stale (`buf generate` / `sqlc generate` + `git diff --exit-code`).

**Reasoning.** Phantom contracts are a stability trap: they imply a safety net (typed queries, schema-checked wire format) that doesn't exist. Either make the net real or stop implying it.

**Decision (resolved).** DELETED both generators rather than adopting. Neither emitted any used code: `internal/db/sqlc/` was never generated (0 `sqlc.New` hits, handlers use raw pgx), and there were zero `.pb.go` files / no gRPC server. Removed `sqlc.yaml`, `buf.yaml`, `buf.gen.yaml`, `buf.lock`, the orphan inputs `db/queries/` and `proto/`, and the `make proto` / `make sqlc` targets. `db/migrations/` is retained as the live schema (goose). Source of truth is now explicit: hand-written Go structs for the wire format and inline pgx + `db/migrations` for queries — comments updated accordingly. No drift-check is wired because there is nothing left to keep in sync; if a generator is reintroduced later, wire its `generate + git diff --exit-code` into CI then.

---

#### D2 (P1) — Split the `internal/handler` god package

**Problem.** 44.7K LOC / 99 files, 508 inlined SQL queries (§2.4).

**Fix.** Split by domain into sub-packages with their own data-access (ideally sqlc-backed from D1): `handler/scanning`, `handler/findings`, `handler/network`, `handler/runtime`, `handler/compliance`, `handler/policy`, `handler/admin`. Move the matching SQL alongside each. Do it incrementally, one domain per PR, with the router (`internal/server`) as the seam.

**DoD.** No single handler package > ~5K LOC; each domain owns its queries; `internal/server` wiring unchanged externally; tests added for the extracted packages (start covering the untested router).

**Reasoning.** The god package is the top maintainability/merge-risk liability and will throttle parity work. Splitting it is the single biggest investment in "feels stable when we change it."

---

#### D3 (P1) — Remove the request-path panic and add router tests

**Problem.** `cluster_init_bundles.go:111` panics on KEK gen failure; `internal/server` has no tests (§2.4).

**Fix.** Return a 500 with a logged error instead of panicking:
```go
// internal/handler/cluster_init_bundles.go:111
kek, err := generateKEK()
if err != nil {
    writeError(rw, http.StatusInternalServerError, "failed to generate init-bundle key")
    log.Error("KEK generation failed", "err", err)
    return
}
```
Add a panic-recovery middleware in `internal/server` (if not present) and a smoke test that exercises every registered route returns non-5xx for healthy inputs.

**DoD.** No `panic()` on any request path; recovery middleware converts unexpected panics to 500 + log; a route-smoke test exists.

**Reasoning.** A single crypto-RNG hiccup taking down the API is exactly the kind of latent instability that erodes trust.

---

#### D4 (P2) — Stabilize the scan/scan-jobs schema; remove dead code

**Problem.** Scan schema churn (32×/21× ALTERs); `internal/tunnel` is an unimplemented stub (§2.4).

**Fix.** Freeze a v1 scan-jobs/scan-artifacts schema (consolidating the accreted ALTERs into a clean baseline migration for greenfield), document it, and gate further changes behind review. Delete `internal/tunnel` (or move to a clearly-marked `experimental/`).

**DoD.** A single documented scan-domain schema baseline; no stub packages in the main tree.

**Reasoning.** The churniest schema overlaps the god-package's biggest files — it's where regressions cluster; freezing it before parity work reduces blast radius.

---

#### D5 (P1) — Close the scale-out/HA gaps (leader election + HA Postgres)

**Problem.** Confirmed on the live cluster (2026-06-15): roles are cleanly split into individual workloads (api, scanner, runtime-agent DaemonSet, admission, operator, discoverer, netpolicy-applier, frontend, postgres) and most are individually scalable — but three gaps prevent "everything individually scalable + HA":
1. **`discoverer` and `netpolicy-applier` run replicas=1 with no leader election.** Scaling either past 1 duplicates work (double inventory writes / double netpolicy application). The operator already does it right (`cmd/constellation-operator/main.go:84` `LeaderElection`, `LeaderElectionID`).
2. **Postgres is a single StatefulSet (SPOF)** — the real horizontal-scale/HA bottleneck; everything is SQL-centric on one instance.
3. **Scanner HPA ships disabled** (`deploy/charts/.../values.yaml` `scanner.autoscaling.enabled: false`).

**Fix.**
- Add controller-runtime/client-go **leader election** to `discoverer` and `netpolicy-applier` (lease-based, same pattern as the operator), so they can run ≥2 replicas active/standby. Then raise their chart replicas and document the HA story.
- Adopt **HA Postgres** (CloudNativePG or Patroni): primary + sync replica, read replicas for heavy read paths (findings/CVE views), connection pooling (PgBouncer). Document RPO/RTO.
- Flip `scanner.autoscaling.enabled: true` with sane CPU/queue-depth targets; consider a **queue-depth external metric** (pending `scan_jobs`) for scan-throughput-driven scaling rather than CPU.

**DoD.** discoverer and netpolicy-applier run ≥2 replicas with exactly one active (verified by killing the leader and watching failover); Postgres survives a primary failure with bounded RPO; scanner scales out under a backlog of pending jobs and back down when drained.

**Reasoning.** "Individually scalable, no SPOF" is a core enterprise expectation NeuVector partially meets via its Raft KV. Constellation's microservice split is already good; closing the leader-election and HA-Postgres gaps makes the scaling story credible for large multi-cluster fleets.

---

### WS-E — NeuVector parity (data model & policy learning)

These are the items that make Constellation a NeuVector competitor rather than a scanner with a map. Sequence after the P0/P1 stabilization.

#### E1 (P2) — Conversation/connection data model + in-memory graph

Replicate NeuVector's aggregation model (`controller/cache/learn.go addConnectToGraph`, `controller/graph/graph.go`):
- **Graph node:** endpoint name + kind (`workload | host | external | addrgrp | ipsvcgrp`), managed flag. Endpoint resolution: managed workload / managed-or-unmanaged host / unmanaged workload IP / external / address-service-FQDN group (scope- and sidecar-aware).
- **Conversation edge:** `from→to` holding entries keyed by `{proto, port, application, clientIP, serverIP}` accumulating `bytes, sessions, max(severity), latest(policyAction, policyID, lastSeen)`, with oldest-entry eviction.
- **Wire format:** model `Connection` on `share.CLUSConnection` (clientWL/serverWL, IPs/ports, IPProto, application, bytes, sessions, first/lastSeen, threatID/severity, policyAction/policyID, ingress, external/local peer, scope, FQDN). Constellation's `dp_flow.go` already carries most of this from DP.

**DoD.** `/network/conversations` serves nodes+edges from the in-memory graph with NeuVector-equivalent fields (apps, ports, bytes/sessions, action, severity); endpoint resolution handles external/host/unmanaged.

**Reasoning.** This is the conversation map that is NeuVector's headline. The DP data is already flowing; the gap is the aggregation/resolution model.

#### E2 (P2) — Groups + dual policy modes (Discover/Monitor/Protect)

- **Group** with selector criteria (image/service/label/namespace/address/node + ops =, regex, prefix, containsAny), `CfgType` lineage (Learned/UserCreated/System), and auto-learned groups per service (`nv.<service>` equivalent).
- **Two independent modes per group:** network `PolicyMode` and process/file `ProfileMode`, each Discover→Monitor→Protect, with action translation (learn → report-only; monitor → violate/log; protect → block) and mixed-mode softening.

**DoD.** Groups are CRUD-able with selectors and membership computation; a group's network mode changes DP enforcement action; modes are surfaced in the Policy area (WS-C2).

**Reasoning.** Groups + modes are the substrate NeuVector's entire policy story sits on; without them, learning and segmentation have nowhere to attach.

#### E3 (P2) — Policy learning: conversations → segmentation rules

Mirror NeuVector's `procLearnedPolicy`: while a group is in Discover, accumulate observed conversations into learned `allow` rules expressed group→group; L7 app rules supersede L4 port rules; collapse port explosion to "any"; debounced flush; compute cluster-wide IP rules and push to DP for enforcement in Protect mode. Constellation already stores `policy_action`/`policy_id` on flows and has a netpolicy-applier — wire the learning engine to them.

**DoD.** A workload in Discover for a period yields learned allow-rules covering its observed conversations; switching to Protect enforces them via DP/netpolicy; a rule's `MatchCntr`/lineage is visible.

**Reasoning.** Zero-trust-by-learning is NeuVector's differentiator over static-policy tools; this closes the loop from the conversation map to enforcement.

---

### WS-F — Runtime security & local container scanning (NeuVector parity; mostly "built but not wired")

Confirmed 2026-06-15 (file:line verified): Constellation already has the hard parts of NeuVector's runtime/local-scan story implemented, but key wires are left `nil`/disconnected — the same phantom-contract pattern as sqlc/proto/DP-IPC. These are high-leverage because they activate existing, tested code.

#### F1 (P0) — Local/running-container scanning: fall back to node-local evidence (fixes the 32 failed cross-scans)

**Problem.** A cross-scan enqueues `discoverer`-sourced **image** jobs that take the registry-pull branch (`cmd/constellation-scanner/main.go:566-577`); locally-built `constellation/*:dev-k3s-*` images aren't in any registry, so `resolveImageDigestRef` fails → `reportFailure` → 32/36 FAILED. Yet Constellation **already** collects those images' packages registry-free on the node — `hostscan.CollectContainerPackages` resolves the container PID via `crictl` over CRI and reads `/proc/<pid>/root` (`internal/runtime/hostscan/container_packages.go:58,251`), driven by `workload_packages_loop.go:54` → `/workload-packages:report` → `scan_evidence`. But that evidence is keyed to `runtime-agent` image targets, while the claim-join only attaches evidence for `st.type IN (...) OR (image AND source_type='runtime-agent')` (`internal/handler/scanjobs.go:754-755`), so `discoverer` jobs never see it. This is NeuVector's enforcer-reads-rootfs model (`neuvector/share/scan/scan_utils.go:191` `GetRunningPackages`, served via `ScanGetFiles`) — already half-built here.

**Fix (status 2026-06-15).**
- **(1) DONE — claim evidence join** now attaches the latest `package-inventory` evidence to *any* image target, matching `target_ref = st.ref` OR `target_ref = st.image_digest`, preferring the target's own evidence (`internal/handler/scanjobs.go` lateral join, ON relaxed to all image types). Build/tests green.
- **(2) DONE — scanner evidence fallback** (`cmd/constellation-scanner/main.go` image branch): runtime-agent targets scan from evidence directly; all other image targets prefer a full registry pull and **fall back to collected package evidence when the pull can't resolve** (node-local images), instead of failing. Registry images keep full scans (no downgrade). Build/tests green.
- **(3) MISSING — the real blocker for the failed dev images: digest resolution.** Verified against the live DB: the runtime-agent keys image evidence by **digest** (`target_ref = sha256:…`), but the discoverer's image targets are keyed by **tag** with **empty `image_digest`** — so the dev images have no key to join on (0 matches; though 25/65 *other* image targets that already have digests are now evidence-scannable). Completing fix: **the discoverer must resolve each running image's digest from the pod `status.containerStatuses[].imageID` and populate `scan_targets.image_digest`** (same digest-resolution gap as A4). Then digest-match connects discoverer targets to runtime-agent evidence and the local-only images scan.

**DoD.** A cross-scan of a cluster running only-local images yields findings (not FAILED) for every running image; the discoverer populates `image_digest` from pod imageIDs; registry images still pull as before; the stale-hash guard is honored. (Parts 1–2 verified this session; part 3 is the remaining work.)

**Reasoning.** Reuses the proven evidence→CVE pipeline; no off-node containerd access. Directly fixes the failure we observed and is core to "scan local/running containers like NeuVector."

#### F2 (P0) — Activate the process-baseline drift detector (it's built but `nil`-wired)

**Problem.** A full baseline engine (`pkg/runtime/baseline/baseline.go:122` `IngestProcess`→`*Alert`), drift classifier (`internal/handler/events_ingest.go:763` — enforce-mode shell exec not in baseline → `severity=high, verdict=alert`), persistence (`internal/handler/baseline.go`, migration `076_process_baseline_lifecycle.sql`), and lifecycle UI all exist. But `NewEventsIngest(...)` is called with `baselineFn = nil` at **both** `internal/server/server.go:508` and `:677` (verified), so `classifyWithFileRules` returns early and **no exec is ever promoted to a drift alert** — every one of the 138k+ captured execs is `verdict=observed`.

**Fix.** Implement `baselineMode(orgID, workloadID)` backed by `process_baseline_states` and pass it at `server.go:508,677`; feed learn/monitor-mode `process_exec` events into `engine.IngestProcess` so baselines populate from live data.

**DoD.** A shell exec in an enforce-mode workload absent from its baseline yields a `severity=high, verdict=alert` finding via the dispatcher + audit log; learn-mode accumulates baselines; a handler test drives a non-nil `baselineMode`.

**Reasoning.** Highest value for least code — turns on already-tested components and directly answers "monitor running containers for new processes outside baselining."

#### F3 (P1) — Broaden runtime detection: image-provenance drift, suspicious processes, privilege escalation

**Problem.** The classifier only scores `shellBinaries` (`events_ingest.go:790`). NeuVector additionally flags any non-image-provenance exec (`IsAllowedShieldProcess`, `agent/probe/process.go:3217`), suspicious binaries (`suspicProcMap`), reverse shells, and privilege escalation (`rootEscalationCheck`). Constellation ships none.

**Fix.** Extend `classifyWithFileRules` to flag execs whose binary isn't in the workload's learned baseline (provenance drift) regardless of name, score a suspicious-binary set, and raise privesc findings from `ProcessEvent.UID`/`PPID` (`internal/runtime/ebpf/types.go:29-39`); map to ATT&CK via existing `techniquesFor`.

**DoD.** A netcat/reverse-shell exec and a UID-0 escalation each produce high-severity ATT&CK-tagged findings; baselined processes don't; unit tests per detector.

**Reasoning.** Closes the qualitative behavioral-detection gap vs NeuVector at the single server-side classification chokepoint.

#### F4 (P1) — File Integrity Monitoring on sensitive paths

**Problem.** The eBPF `file_open` LSM stream is captured and uploaded (`internal/runtime/ebpf/loader_linux.go:101`, consumed `cmd/constellation-runtime-agent/main.go:669-685`) and a `file_open` classifier branch exists (`events_ingest.go:765-784`), but there's no default FIM watch-set, so writes to package DBs, `/etc/passwd`/`shadow`, ssh keys, and system binaries raise nothing. NeuVector ships this (`neuvector/share/fsmon/monitor.go:33-55`).

**Fix.** Ship a default file-profile watch-set (mirroring NeuVector's `ImportantFiles`) via the existing `file_profile_rules_sync.go` path; the `file_open` classifier then emits `file_modified` findings. Optionally enforce `block_access` via `file_profile_enforcer_linux.go`.

**DoD.** A write to `/etc/passwd` or `/var/lib/dpkg/status` in a monitored workload yields a `file_modified` finding with the offending process; default watch-set ships out of the box.

**Reasoning.** Reuses existing capture + rule-sync + classifier; only the default watch-set is new. Completes "and more" beyond process monitoring.

---

### WS-G — Remaining NeuVector-parity gaps (verified 2026-06-17)

Status delta since this plan was written (all verified file:line / live-cluster this session):
- **DONE & shipped:** WS-A VulnDB rebuild (now a **lean 5.1GB matching core** + separate **opt-in CVE-enrichment** artifact; bundle 307MB + 128MB; live on cluster, 358k CVEs), WS-A4 digest resolution path, WS-C IA cleanup (orphans surfaced, dup DLP/WAF/Response nav repointed to canonical pages), WS-E1/E2/E3 (conversation graph enrichment, groups + dual modes with auto-propagation, learned-rule dedup), WS-F1/F2/F3/F4 (local-evidence fallback, baseline drift wired, suspicious/privesc detection, FIM), **admission CVE-count gates** (live deny-validated: refused an image with "2 critical CVEs"), and ingest-side **conditional revalidation** (committed; servers honor 304 but the real win needs the skip-on-304 variant — see G6).
- **The four real remaining gaps** below are what an honest audit (2026-06-17) found still MISSING / STUBBED / BUILT-NOT-WIRED. Ordered by value-per-effort. **G1, G2, G4 are fully independent** (runtime-agent/DP vs operator vs auth) and can run in parallel; **G3** is the largest and touches many handlers; **G5/G6** are independent minors.

**Ultracode run outcome (2026-06-17)** — implemented in parallel isolated worktrees, each adversarially verified:
- **G1 (WAF)** — branch `feat/wsg-G1-waf` — **solid, mergeable.** Took the DELETE path: WAF rule-groups never reached the DP and are redundant with DPI Signatures; removed routes/handler/store/frontend with a grep-guard test; signatures documented authoritative.
- **G2 (net auto-apply)** — **NOT A GAP** (see corrected section below); redundant branch dropped.
- **G3 (federation G3a/b)** — branch `feat/wsg-G3-fedsync` — **solid, mergeable.** Revision write-hook + joint poller.
- **G6 (reval skip-on-304)** — branch `feat/wsg-G6-reval` (vulndb repo) — **solid, mergeable.**
- **G4 (SSO)** — branch `feat/wsg-G4-sso` (commit `e30e909`) — **library layer done + tested, NOT end-to-end.** SAML (`crewjam/saml`) + LDAP (`go-ldap/v3`) auth + role-mapping via a shared `RoleMapping`→existing `signer.Issue`/`role_assignments` path; unit-tested (assertion parse, group→role, DN→CN). **Remaining integration (real work, not just live-validation):** no `/auth/saml/acs` or `/auth/ldap/login` routes in `internal/handler/auth.go`, no SAML/LDAP→user DB link (OIDC uses `oidc_issuer`/`oidc_subject` cols; SAML/LDAP need analogous), no per-org config loading. So G4 is "the hard crypto/mapping is solved; the route+DB plumbing is a follow-up."
**MERGED 2026-06-17** into `feat/neuvector-parity-sweep` (G1/G3/G4) + the vulndb branch (G6) after two ultracode fix rounds closed the adversarial-verify findings (G3 federation divergence: bulk/delete/import hooks + tombstones + migration 092 unique-revision + read-only enforcement + enabled preservation; G6 paginated-source 304 handling: serve-CAS-on-304 for index/pagination drivers, clean-skip only for leaves; G4 SSO: routes+DB+env config wired and the SAML signature-bypass seam unexported). Full integration build green; auth/fed/waf-removal tests pass; frontend tsc clean.
**Outstanding live validation (not code — external setup):** G6 CAS two-run timing proof (in flight); G3 needs migrations 091/092 applied + a 2-cluster master/joint to prove rule sync end-to-end (logic is test-DB-verified); G4 needs a real IdP (Okta SAML / LDAP bind); G1 done (no dead nav, tsc clean). **Honesty flag:** G4's full adversarial re-verify was rate-limited — its critical signature-bypass seam was verified inline + build/tests pass, but the broader SSO logic is unit/handler-tested only, not adversarially swept. Nothing pushed or deployed.

#### G1 (P1) — WAF rule enforcement wiring (STUBBED → DONE). *Parallel with G2, G3, G4.*

**Problem.** `/waf/groups` CRUD + tables exist (`internal/server/server.go:346-349`, `internal/handler/waf_dlp.go`) but there is **no agent sync, no `waf-rules:bundle` endpoint, and no DP enforcement consumer** — confirmed by grep (DLP has all three; WAF has none). WAF rules are authored and persisted but never reach the dataplane — the same phantom-contract pattern as the pre-fix DLP path.

**Fix (mirror the DLP wire, the proven template).**
- Add `GET /api/v1/runtime/waf-rules:bundle` (runtime-agent-token auth) serving compiled WAF rows for a cluster — copy `runtime_dlp.go`'s `AgentBundle`.
- Reuse the agent DLP sync worker shape (`cmd/constellation-runtime-agent/dlp_sync.go`) for `waf_sync.go` (or generalize it with a `category` param) → push to DP via a new `Supervisor.BuildWAFRules()` beside `BuildDLPRules` (same hyperscan path).
- **Decide first (ladder rung 1):** WAF and DPI-signatures may be the same surface — the IA cleanup already repointed `waf-rules` nav at `RuntimeSignaturesPage`. If signatures cover the use-case, **delete `/waf/groups` instead of wiring it**. Only wire if WAF is a distinct ModSecurity-style ruleset.

**DoD.** Either (a) a WAF rule authored in the UI is fetched by the agent and blocks a matching request in the DP, with an agent-audit delivery row; or (b) the redundant WAF surface is removed and signatures documented as the single authoritative DPI ruleset.

**Test.** `waf_sync_test.go` asserting the bundle endpoint returns authored rules under agent-token auth (mirror the DLP test). If deleting: a grep check that no orphan `/waf` routes/pages remain.

**Validation (live).** Author a block rule, send a matching request from a monitored pod, confirm DP blocks + a `runtime_threats` row with the rule id. (≈1 day.)

#### G2 — Network policy auto-apply — **NOT A GAP (corrected 2026-06-17 by ultracode adversarial verify).**

**Correction.** The original "nothing applies them" claim was **wrong** — it grepped only `cmd/constellation-operator`. A dedicated `cmd/constellation-netpolicy-applier` **already exists**, applies native + Cilium/Calico NetworkPolicies via the dynamic client (`internal/netpolicyapply/applier.go:22,126,206`), writes back to `network_policy_apply_status`, **and is deployed** (`deploy/charts/constellation/templates/network-policy-applier-deployment.yaml`). The WS-G implementer's reconciler was a redundant second writer (same status PK + same live object) — **branch dropped**. The only real work here is **live verification** that the applier is enabled and a Protect-mode workload gets a real NetworkPolicy — a validation task, not a build task. Remaining open question: confirm it's triggered by the lifecycle (`target_mode=protect`) and not gated off by default.

**Original (incorrect) problem text, kept for the record:** "Constellation renders manifests and tracks apply-status but nothing applies them; Protect mode requires manual kubectl apply." — superseded by the applier above.

**Fix.** Operator reconciler: for each workload lifecycle row in `target_mode=protect` + `approval_status=approved`, render via the existing `netpolicy` renderer and apply with the typed client (`NetworkingV1().NetworkPolicies(ns).Apply(...)` server-side-apply, constellation field-manager; Cilium/Calico via dynamic client + GVR), then write back `status`/`resource_ref`/`error`. Idempotent SSA; prune on demote. Gate behind a per-cluster `network_enforcement_enabled` flag (default **off**) so it can't surprise-break traffic.

**DoD.** Flipping a workload to Protect (approved) yields a real `NetworkPolicy`/CNP/GNP in the namespace within one reconcile; apply-status shows `applied` + `resource_ref`; demote removes it; flag defaults off.

**Test.** Reconciler unit test against a fake clientset: SSA create/prune for a Protect/approved row, no-op when the flag is off.

**Validation (live).** Approve Protect for a test workload, `kubectl get networkpolicy -n <ns>` shows it, a disallowed egress is dropped, apply-status = `applied`. (≈2-3 days.)

#### G3 (P2) — Federation sync (STUBBED → DONE). *Largest; touches policy/group/response handlers + a poller. G3a/b ∥ G3c/d.*

**Problem.** State machine + member registry work (`pkg/federation/federation.go`, `fed_members`, join/leave), but sync is hollow: **nothing writes `fed_rule_revisions`** (grep: 0 inserts), **no joint poller** pulls `/sync?since=` and applies rules, **no cross-cluster aggregation**, and **no federated network/admission rule types** (NeuVector's `FedAdmCtrlDenyRulesType`/`FedNetworkRulesType` absent). Federation is join/leave only.

**Fix (four sub-tasks).**
- **G3a — revision write hook.** On master-org mutation in `policies.go`/`groups.go`/`response_rules.go`, INSERT into `fed_rule_revisions(kind, rule_id, revision++, payload)` via one shared helper.
- **G3b — joint poller.** Background loop in joints: `GET master /sync?since={last_synced_revision}`, upsert into local tables under `cfg_type=federated` (read-only locally), advance `last_synced_revision`. Reuse the `ReconcileCVEEnrichmentLoop` shape.
- **G3c — federated rule types.** Add `scope` (`local|federated`) to admission/network rule models; master-authored federated rules propagate via G3a/b; precedence fed-deny > local.
- **G3d — cross-cluster visibility.** Master aggregates joints' findings/flows (joints expose a read endpoint master scrapes, or push summaries); serve global `/findings`, `/network/map`.

**DoD.** A policy created on the master appears read-only (`federated` lineage) on a joined cluster within one poll and is enforced there; a federated admission-deny blocks on joints; master dashboard shows aggregate counts across members; `fed_rule_revisions` written on every master mutation.

**Test.** master mutation writes a revision row; poller `since` advances + applies; fed-deny overrides local-allow.

**Validation (live).** Promote A→master, join B; create an admission rule on A; B denies a matching pod and A's dashboard counts B's findings. (≈1-2 weeks — headline multi-cluster story.)

#### G4 (P2) — Enterprise SSO: SAML + LDAP (MISSING). *Parallel with G1, G2, G3.*

**Problem.** Only OIDC exists (`internal/auth/oidc.go`). NeuVector ships SAML + LDAP; their absence blocks enterprise deals that mandate them.

**Fix.** SAML SP via `crewjam/saml` (don't hand-roll XML/signature validation) with IdP-metadata config + assertion→role mapping reusing the RBAC role-assignment path. LDAP bind+search via `go-ldap/ldap/v3` with group→role mapping. Both land beside OIDC behind the existing auth-config selector; no new session model.

**DoD.** A user authenticates via SAML (e.g. Okta) and via LDAP, lands with the RBAC role from assertion/group mapping and an OIDC-identical session; config is per-org.

**Test.** assertion-parse + group-map unit tests against canned SAML responses / LDAP entries (no live IdP).

**Validation.** Test IdP / SAML harness login, confirm role + audit event. (≈1 week; SAML ~60%.)

#### G5 (P3) — Minor integration/parity gaps. *All independent; opportunistic.*

| Item | State | Fix (lazy) | DoD |
|---|---|---|---|
| Syslog / SIEM export | MISSING | `syslog` receiver in `pkg/notify` (RFC5424, stdlib `log/syslog`) + routing-rule type | A finding routes to a syslog collector |
| MS Teams receiver | MISSING | One more `pkg/notify` receiver (Teams MessageCard) | A finding posts a Teams card |
| Event export API | BUILT-NOT-WIRED | `/api/v1/events:export` over existing `pkg/backup/exporter.go` | NDJSON stream of findings/threats by window |
| Trivy IaC scan | STUBBED | Wire `ScanOptions.IncludeIaC` → `trivy --scanners config` + map results | IaC misconfigs appear as findings |
| Custom RBAC roles | MISSING | Role builder over existing `VerbCatalog` (data, not code) | Org-defined role with a verb subset works |
| Docker-bench host | MISSING | Optional host-compliance profile in the collector | Docker-bench controls scored on nodes |

#### G6 (P3) — Finish the ingest revalidation win (skip-on-304). *Independent; vulndb producer only.*

**Problem.** Conditional revalidation is committed and servers **do** 304 (verified: suse OVAL 304/0-bytes vs 200/42.7MB), but the current variant *serves the cached body and re-parses it* — skipping the ~40s download, not the ~11min parse+upsert that dominates. Net: ~no win.

**Fix.** Make `conditionalDo` return a `NotModified` sentinel instead of serving from CAS; each of the 12 distro subsources treats it as a clean per-feed skip (emit nothing — safe: ingest is upsert-only, so skipped rows persist). The only real work is the heterogeneous per-subsource error handling — a uniform `if errors.Is(err, sourceio.ErrNotModified) { return <zero> }` after each `sourceio.Do`.

**DoD / Validation.** Two CAS-enabled runs: run 2's unchanged distros drop from minutes to seconds (suse ~12min → seconds); total distros ingest ~12min → ~2-3min on unchanged days. (≈1 day + 2 re-validation runs.)

---

## 5. Sequencing & milestones

**Milestone 1 — "It looks like it works" (days, P0).**
- B1 (network map cluster scoping) + B2 (empty states).
- A1 (real VulnDB bundle) + A2 (require-vulndb default + health banner).
- Outcome: network map shows traffic; findings counts become plausible and language-aware. Addresses all three reported symptoms' user-visible surface.

**Milestone 2 — "It's stable to change" (1–3 weeks, P1).**
- A3, A4 (matcher observability, correlation coverage).
- B3, B4 (DP capture confirmation, flow retention).
- C1, C2, C3 (IA cleanup, restructure, shared states).
- D1, D2, D3 (contract decision, god-package split start, panic fix + router tests).

**Milestone 3 — "It competes with NeuVector" (parity, P2).**
- A5 (asset-vuln index), B5 (in-memory graph + StreamFlows).
- E1, E2, E3 (conversation model, groups+modes, policy learning). *(E1-E3 done this session.)*
- D4 (schema freeze, dead-code removal).

**Milestone 4 — "Close the parity gaps" (WS-G, 2026-06-17 audit).**
- **Wave 1 (parallel, ~1 week):** G1 (WAF wire-or-delete), G2 (network auto-apply), G4 (SAML+LDAP) — three independent subsystems, three owners. G6 (revalidation skip) as a vulndb-side side-quest.
- **Wave 2 (~1-2 weeks):** G3 (federation sync) — the headline multi-cluster story; start after Wave 1 frees reviewers since it touches many handlers. G3a/b (write-hook + poller) can land before G3c/d (fed rule types + aggregation).
- **Opportunistic:** G5 minors (syslog, Teams, event-export, IaC, custom roles, docker-bench) — pick up between waves.
- **Order rationale:** G2 first if "Protect mode doesn't enforce" is the loudest demo gap; G1 first if the cheapest closed gap matters more; G4 first if a specific enterprise deal needs SSO. Default to running all three Wave-1 items concurrently.

---

## 6. Global Definition of Done

- All three reported symptoms reproduced-then-fixed with an automated test or documented manual verification:
  - Network map renders traffic for a cluster with flows (E2E with seeded/real flows).
  - A scan of a known-vulnerable app image yields language-ecosystem findings; finding counts are explained (no silent degradation).
  - The sidebar has no orphan/duplicate surfaces; vuln features are unified.
- `go build`, `go vet`, `go test ./...`, frontend `tsc`/build, and (new) `buf generate`/`sqlc generate` drift checks all green in CI.
- VulnDB population gate enforced; scanner fails ready on missing store.
- No `panic()` on request paths; panic-recovery middleware present.
- Network flow retention active; map query latency bounded under load.
- Architecture decisions (contract layer, handler split, schema freeze) recorded as ADRs under `constellation/docs/specs/`.
- **WS-G parity gaps closed (each with the per-task DoD above):** no STUBBED/BUILT-NOT-WIRED parity surface remains — WAF either enforces or is deleted (G1); Protect mode applies real NetworkPolicies behind a default-off flag (G2); federation actually syncs rules + aggregates visibility (G3); SAML+LDAP login work (G4). Each verified by its named test + live validation, not by "a table and handler exist."

---

## 7. Verification that needs a live cluster / logins

I can implement every code/UX fix above from the repo. The following are **environmental confirmations** that would let me verify root causes instead of fixing blind — these are where cluster/login access helps most:

1. **Scanner VulnDB health [A1/A2]:** `kubectl exec` the scanner pod → `GET /readyz`, read `vulndb.record_count`, `bundle_version`, `status`. Confirms empty/stale store vs. bundle-coverage gap.
2. **Findings provenance [A4/H5]:** query `findings` for `first_seen_at` + CVE IDs on the running cluster — distinguishes real OS-only scans from seed/demo data (`CVE-2024-0001`/`CVE-2023-1234`).
3. **Network flow capture [B3]:** the cluster's CNI (Cilium eBPF?), runtime-agent logs for `kind: dp.connection`, and whether `network_flows` has recent `source='dp'` rows. Confirms frontend-bug-only vs. also-a-DP-capture-gap.
4. **VulnDB rebuild [A1]:** a `GITHUB_TOKEN` (PAT, public repo / read scope) to rebuild a full bundle with GHSA + language ecosystems.

If you can provide a kubeconfig (read access is enough for 1–3) and a `GITHUB_TOKEN` for 4, I can confirm each hypothesis and adjust the plan's "high" severities to "confirmed" before we start cutting code.

---

## Appendix B — VulnDB rebuild runbook (GitHub token + language ecosystems → bbolt)

This is the exact procedure to replace the broken smoke bundle with a real one that includes GHSA and the language ecosystems, and to get the resulting `vulndb.bbolt` into Constellation. All commands run from `constellation-vulndb/`.

### B.0 Why the current bundle is wrong

The existing bundle was produced by `scripts/local-population-smoke.sh:183` with **`-profile dev`**. The dev profile:
- Does **not** require/use a GitHub token, so GHSA fails (`internal/sources/ghsa/ghsa.go:57` → `ghsa: GITHUB_TOKEN not provided`).
- **Caps** every source: NVD 50–200 records, GHSA 3 pages, OSV 500/ecosystem (`cmd/vulndb-aggregator/main.go:66-71`).

That is why the manifest shows `ghsa:3`, `nvd:420`, and `osv:npm:39 / osv:pypi:42 / osv:maven:46` — placeholder-level language coverage.

### B.1 Where the GitHub token goes

The token is read in one place: `cmd/vulndb-aggregator/main.go:59`
```go
ghsaToken := flag.String("ghsa-token", os.Getenv("GITHUB_TOKEN"), "GitHub token for GHSA")
```
So you provide it **either** as the `GITHUB_TOKEN` env var **or** the `--ghsa-token` flag. In the `production` profile it is mandatory when `ghsa` is in `--sources` (`main.go:134` exits otherwise).

- **Token type/scope:** the GHSA source uses GitHub's public GraphQL Security Advisory API. A **classic PAT with no scopes** (or a fine-grained token with default read) is sufficient — it only needs to authenticate for rate limits, not access private data. `read:packages`/`public_repo` also work. Do **not** grant write scopes.
- **Local/dev:** `export GITHUB_TOKEN=ghp_xxx` in the shell before running the aggregator.
- **CI:** add it as an Actions secret and inject it in `.github/workflows/*` as `GITHUB_TOKEN` (or `--ghsa-token ${{ secrets.GHSA_TOKEN }}`). Note: GitHub's auto-provided `secrets.GITHUB_TOKEN` works for the GraphQL advisory API too, so a CI job can often use it directly.
- **Cluster builds:** put it in a Kubernetes Secret consumed by the aggregator CronJob/Job env.

### B.2 How the "other language repos" are pulled in (you don't add repos — you enable two sources)

The language ecosystems are **already wired**, via two sources. You don't clone npm/pypi/maven repos; their advisories come from:

1. **OSV** (`--osv` flag, default list at `cmd/vulndb-aggregator/main.go:45`) — pulls from osv.dev for every ecosystem:
   ```
   alpine,debian,ubuntu,go,npm,pypi,maven,nuget,rubygems,packagist,crates,hex,pub,
   linux,oss-fuzz,swifturl,android,bitnami,cran,github-actions,hackage,julia,opam,
   redhat,rocky,almalinux,suse,opensuse,wolfi,chainguard,azure-linux,openeuler
   ```
   In `dev` this is capped at 500/ecosystem (`--osv-max-per-ecosystem 500`) — the cause of `osv:npm:39`. The `production` profile sets the cap to `-1` (uncapped) automatically (`main.go:99-101`).
2. **GHSA** (`--ghsa-token`) — GitHub's Security Advisory database, the richest source for npm/PyPI/Maven/NuGet/Composer/RubyGems/Go/Rust/Pub advisories, with curated severity and fixed-version ranges. Capped at 3 pages in dev; `production` raises it to 10,000 pages (`main.go:96-98`).

So "pulling in the language ecosystems" = **(a)** include `osv,ghsa` in `--sources` (they're in the production default `nvd,osv,ghsa,kev,epss,distros`), **(b)** provide `GITHUB_TOKEN`, and **(c)** run `-profile production` (or manually pass `--osv-max-per-ecosystem=-1 --ghsa-pages=10000`). To restrict to specific language ecosystems, narrow `--osv`, e.g. `--osv=npm,pypi,maven,nuget,go,rubygems,crates`.

### B.3 End-to-end rebuild → bbolt → Constellation

```bash
cd constellation-vulndb

# 1. Credentials
export GITHUB_TOKEN=ghp_xxx                 # required for GHSA (B.1)
export NVD_API_KEY=xxxx-xxxx                 # recommended; production requires it for the nvd source
export DATABASE_URL=postgres://…/vulndb      # producer Postgres (see deploy/postgres)

# 2. Aggregate ALL sources into producer Postgres (uncapped, GHSA on, full OSV language ecosystems)
go run ./cmd/vulndb-aggregator \
  -profile production \
  -sources nvd,osv,ghsa,kev,epss,distros \
  -osv npm,pypi,maven,nuget,go,rubygems,crates,hex,pub,packagist,alpine,debian,ubuntu,redhat,rocky,almalinux,suse,wolfi,chainguard
# (omit -sources/-osv to use the production defaults, which already include everything above)

# 3. Build the bundle artifact (bundle.jsonl.gz + manifest.json [+ vulndb.bbolt])
BUNDLE_DIR=.local/full-$(date -u +%Y%m%dT%H%M%SZ)
go run ./cmd/vulndb-bundle -out "$BUNDLE_DIR" -bundle-version "prod-$(date -u +%Y%m%dT%H%M%SZ)"

# 4. Materialize the queryable bbolt store
go run ./cmd/vulndb-bundle-store -dir "$BUNDLE_DIR" -out "$BUNDLE_DIR/vulndb.bbolt" -overwrite

# 5. Sanity-check coverage BEFORE shipping (this is the population gate from A1)
go run ./cmd/vulndb-bundle-query -db "$BUNDLE_DIR/vulndb.bbolt" -counts
#   expect: ghsa in the thousands, full NVD, non-trivial npm/pypi/maven counts
```

Then get the bbolt into Constellation. The scanner reads it from **`/var/lib/constellation/vulndb.bbolt`** by default (`constellation/cmd/constellation-scanner/main.go:1004`; Helm `vulndb.dbFile: vulndb.bbolt`, `values.yaml:586`). Options:

- **Manual / dev:** copy `$BUNDLE_DIR/vulndb.bbolt` to that path on the scanner node/volume and restart the scanner.
- **Production:** publish the store and let Constellation's importer install it (the consumer path: `vulndb-bundle-install --store-url …` / `--store-s3 …` → atomic install into the active bbolt, see `architecture.md` "Importer And Update Flow"). The importer CronJob in `deploy/charts/constellation` should point at the published store/bundle.

### B.4 Confirm Constellation picked it up

```bash
# scanner readiness now reports real coverage (main.go:490-521)
kubectl exec deploy/constellation-scanner -- wget -qO- localhost:<port>/readyz | jq .vulndb
#   expect: status=ready, record_count in the hundreds-of-thousands, recent exported_at
```
With A2 applied (`require-vulndb=true`), the scanner refuses to be ready on a missing/empty store, so this check becomes a hard gate rather than advisory.

---

## 8. Appendix — key evidence index

- Network map frontend bug: `frontend/src/pages/NetworkMapPage.tsx:111,119,143`; contract `frontend/src/hooks/useCluster.ts:6-9`.
- Flow pipeline (working): `internal/runtime/dp/supervisor.go:18,326-360`, `internal/runtime/dp/ipc.go:62-107`, `cmd/constellation-runtime-agent/main.go:362,474-504`, `internal/handler/network_flows_ingest.go:166-178`, `internal/handler/network.go:184-211`, `internal/handler/network_conversations.go:22-67`.
- VulnDB coverage gap: `constellation-vulndb/.local/full-smoke-20260613T200730Z/reports/bundle-population-check.txt` + `manifest.json source_counts` (`ghsa:3`, `npm/pypi/maven/go:1`).
- Scanner gating: `cmd/constellation-scanner/main.go:71,478-521`; `internal/scanner/vulndb.go:50-95,147-154`; `internal/scanner/aggregator.go:88-101,227-328`.
- Findings correlation: `internal/handler/cve.go:420-464`, `internal/handler/deployments.go:604-642,704`, `internal/handler/findings.go:70-71`.
- Seed data: `cmd/constellation-seed/main.go:116-138`.
- IA: `frontend/src/App.tsx:91-171`, `frontend/src/components/AppShell.tsx:77-161`.
- Architecture debt: `internal/handler` (99 files/44.7K LOC), `sqlc.yaml` + `db/queries/` (unused), `proto/` (no `.pb.go`), `internal/handler/cluster_init_bundles.go:111` (panic), 87 migrations.
- NeuVector reference: `neuvector/controller/cache/learn.go` (`addConnectToGraph`), `neuvector/controller/graph/graph.go`, `neuvector/controller/cache/connect.go` (endpoint resolution), `neuvector/share/clus_apis.go` (`CLUSGroup`, `CLUSPolicyRule`), `neuvector/dp/ctrl.c:2633` (`dp_ctrl_connect_report`).
```

---

### WS-D status (merged 2026-06-17 via ultracode)

All five D-items merged into `feat/neuvector-parity-sweep`; full integration build green.
- **D1** — DELETED dead sqlc + protobuf/buf scaffolding (generated nothing, nothing imported them → phantom drift). Lazy-correct over "adopt".
- **D2** — split-plan written to `docs/handler-split-plan.md` + one proof extraction (`internal/handler/network` subpackage) building+testing green; full split is now a mechanical follow-up.
- **D3** — removed the startup `panic()` in `resolveKEK` (crypto-RNG failure now degrades to 503 on the 3 KEK routes via a `kekReady` guard, not a process crash); chi Recoverer confirmed wired + a router-recovery regression test added.
- **D4** — deleted the `internal/tunnel` unimplemented stub (held scope: other zero-importer pkgs have real impls, left alone); scan-schema baseline documented.
- **D5** — leader election via client-go Lease wrapping the singleton background loops, **default OFF** (single-replica behavior identical); chart gains a `postgres.mode` toggle (statefulset|cnpg|external) with the **default empty** so existing cnpg/external values files are NOT flipped to a StatefulSet (a regression the ultracode verifier caught and we fixed + render-verified all modes).

**Outstanding live validation:** D5 leader-election needs a multi-replica deploy to prove only the leader runs the loops; `cnpg` mode needs the CloudNativePG operator installed AND a **pgvector-capable** CNPG image supplied (the chart default is a documented placeholder — stock CNPG postgres lacks the `vector` extension the schema needs). D3's RNG-failure→503 path is code-verified (hard to induce live).

---

### Milestone 3 + G5 status (merged 2026-06-17 via ultracode)

Full integration build green (constellation + vulndb). Merged into `feat/neuvector-parity-sweep`:
- **A5** — per-asset vuln rollup + re-count from stored findings/evidence with NO rescan (`/api/v1/assets/{id}/vulnerabilities`, `source=findings|evidence`); migration 093. **Verifier caught a double-count** (image assets summed image_scan_findings + their promoted generic findings) — fixed to count by asset kind.
- **B5** — in-memory conversation-graph cache + `/network/flows:stream` SSE, layered on the Postgres path, **default OFF** (`CONSTELLATION_LIVEGRAPH`).
- **C2+C3** — nav regrouped toward NeuVector-style top-level areas (all routes kept reachable) + shared `Loading/Empty/ErrorState` components; tsc clean.
- **G5-notify** — syslog (RFC5424) + MS Teams receivers in `pkg/notify` + routing types.
- **G5-scan** — Trivy IaC wiring (opt-in `IncludeIaC`) + Docker-bench host compliance profile.
- **G5 events:export** — `GET /api/v1/events:export?hours=` streaming NDJSON of findings + runtime threats (row_to_json, column-decoupled).

**G5 custom RBAC roles — DONE (2026-06-17, careful inline pass).** custom_roles table (migration 094) + CRUD with a write-time user-grantable filter + `rbac.AuthorizeWithCustom` resolution with defense-in-depth (a custom role can never grant a service-principal verb even if the row is tampered) + per-org TTL cache. Tests cover the authz boundary and the write filter. **The entire plan (WS-A/B/C/D/E/F/G + M3 + G5) is now code-complete.**

**Outstanding live validations (external infra, not code):** multi-cluster federation (G3), real IdP login (G4), CNPG operator + pgvector image + multi-replica leader election (D5), the asset-vuln recount against real data (A5), and the livegraph/SSE under real flow load (B5).
