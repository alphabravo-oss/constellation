# `internal/handler` god-package split plan (WS-D / D2)

Status: **plan + 1 proof-of-pattern extraction landed** (`handler/network`).
Tracking: stabilization plan §D2 (`docs/constellation-stabilization-and-parity-plan.md:573`).

## Why

`internal/handler` is ~62K LOC across ~113 non-test files (the plan's "44.7K / 99
files" snapshot has since grown). It is the single biggest merge-risk and
maintainability liability. The DoD: no single handler package > ~5K LOC, each
domain owns its data access, `internal/server` wiring stays externally
identical, and the extracted packages gain tests.

## The seam is already clean

Every handler is a small struct constructed by a `NewXxx(deps...)` function and
wired exactly once in `internal/server/server.go`. There is **no** monolithic
`Handler` struct — handlers do not call each other's methods. The only thing
binding the files into one package is a handful of **unexported, cross-file
helpers**. So the split is mechanical *once those shared helpers are promoted to
leaf packages*.

### Shared helpers to extract first (the enabling step)

These are the package-level identifiers used across many files. Promote each to
a small dependency-free leaf package that both `handler` and every new
sub-package can import without creating a cycle.

| Helper(s) | Current location | Target leaf package | Notes |
|---|---|---|---|
| `writeJSON` (used by ~86 files) | `auth.go:327` | `handler/httpx` → `WriteJSON` | **done** (proof). Pure stdlib. |
| `splitWorkload`, `stableFlowID` | was `network.go` | `handler/netutil` → `SplitWorkload`, `StableFlowID` | **done** (proof). Pure stdlib. Also used by `network_policies.go`, `groups.go`. |
| `Subject`, `SubjectFrom`, `WithSubject`, `HasTokenScope` | `subject.go` | `handler/authctx` (recommended next) | Auth-context seam every sub-package needs. Only deps: `uuid`, `pkg/rbac`. Promoting it is what lets domain packages stop importing `handler` (see Cycle note). |
| `parseClusterIDParam`, `shiftPlaceholders`, other `sql_helpers.go` funcs | `sql_helpers.go` | `handler/sqlx` | Cluster-scope query plumbing used pervasively. |
| `SafeFilter`, error/response shaping | `auth.go` and scattered | `handler/httpx` | Fold into `httpx` as they surface. |

**Cycle note.** A domain sub-package needs `Subject`/`SubjectFrom`. Until
`subject.go` is promoted to `handler/authctx`, a sub-package must import the
parent `handler` package for it — which means `handler` can **not** import that
sub-package back (import cycle). The proof package (`handler/network`) imports
`handler` for `SubjectFrom`; that is why its shared pure helpers had to go into
`handler/netutil` (a leaf both can import) rather than back into `handler`.
**Recommended ordering: promote `authctx` and `sqlx` *before* the first domain
package, then no domain package imports `handler` at all and the dependency
graph is a clean star: domains → {authctx, httpx, sqlx, netutil} → leaf.**

## Domain grouping (target sub-packages)

Map the files into cohesive domains. Sizes are approximate; any package over
~5K LOC gets a second-level split later.

| Sub-package | Files (representative) |
|---|---|
| `handler/network` *(proof: done)* | `network.go`, `network_conversations.go` (now `conversations.go`) |
| `handler/netpolicy` | `network_policies.go`, `network_flows_ingest.go`, `well_known_ips.go` |
| `handler/scanning` | `scanjobs.go`, `scanjobs_lifecycle.go`, `scan_objects.go`, `scan_evidence.go`, `scan_impacts.go`, `scan_attestations.go`, `scanner_cache.go`, `image_scan_results.go`, `image_acceptances.go`, `workload_packages.go`, `serverless_inventory.go`, `serverless_packages.go` |
| `handler/findings` | `findings.go`, `findings_csv.go`, `findings_reachability.go`, `comments.go`, `cve.go`, `cve_enrichment.go`, `cve_import.go`, `vuln_profiles.go`, `vulnerability_exceptions.go`, `vulndb.go`, `vulndb_rescan.go`, `sbom.go` |
| `handler/runtime` | `runtime_*.go` (detections, dlp, pcap, policies*, signatures, threats*), `events_ingest.go`, `baseline.go`, `process_baselines_bundle.go`, `file_profiles.go`, `quarantine.go`, `forensics.go`, `waf_dlp.go` |
| `handler/compliance` | `compliance.go`, `compliance_exemptions.go`, `compliance_schedules_db.go`, `custom_frameworks.go`, `host_cis.go`, `reports.go`, `connector_coverage.go`, `coverage.go` |
| `handler/policy` | `policies.go`, `policies_admission_profiles.go`, `policies_bulk.go`, `policy_fields.go`, `response_rules.go`, `response_rules_v2.go` |
| `handler/inventory` | `assets.go`, `components_inventory.go`, `repository_inventory.go`, `repository_packages.go`, `repository_retention.go`, `registries.go`, `deployments.go`, `host_facts.go`, `host_containers.go`, `host_packages.go`, `host_processes.go`, `host_vulnerabilities.go`, `platform_facts.go`, `nodes.go`, `heartbeats.go` |
| `handler/clusters` | `clusters_search.go`, `clusters_cross_scan.go`, `cluster_init_bundles.go`, `federation.go`, `fed_sync.go`, `migration_preview.go` |
| `handler/admin` | `access_control.go`, `api_tokens.go`, `auth.go`, `groups.go`, `settings.go`, `audit.go`, `receivers.go`, `integration_deliveries.go`, `backup.go`, `backup_tar.go`, `enterprise.go`, `dashboard.go`, `analytics.go`, `system_health.go`, `ai.go` |
| shared leaf packages | `httpx`, `netutil`, `authctx`, `sqlx`, `subject.go`→authctx |

`openapi.go`/`searchq.go` stay until last; they touch many routes.

## Dependency order (one domain per PR)

1. **Leaf helpers first** — `httpx` *(done)*, `netutil` *(done)*, then `authctx`
   (promote `subject.go`), then `sqlx` (promote `sql_helpers.go`). After this,
   domain packages depend only on leaves.
2. **Leaf domains** — `network` *(done)*, `netpolicy`, `compliance`,
   `policy` (low coupling, mostly self-contained).
3. **Mid domains** — `findings`, `inventory`, `clusters`.
4. **Heavy domains** — `scanning`, `runtime` (biggest; may need a second split).
5. **`admin`** last (auth/settings/audit are referenced widely; move once the
   rest no longer reaches into them).

## Mechanical per-group steps (the recipe, proven by `handler/network`)

For each domain group `G` → `internal/handler/<G>`:

1. `mkdir internal/handler/<G>`.
2. `git mv` each file in the group into it (preserves history).
3. Change `package handler` → `package <G>` in every moved file.
4. For each cross-package reference, repoint to its leaf package:
   `writeJSON(` → `httpx.WriteJSON(`, `splitWorkload(` → `netutil.SplitWorkload(`,
   `SubjectFrom(` → `authctx.SubjectFrom(` (or `handler.SubjectFrom(` until
   authctx exists). Add the corresponding imports; drop now-unused ones.
5. Find any helper the group **defined** that files *outside* the group still
   use (compile error: `undefined: foo`). If it is a pure utility, move it to
   the matching leaf package and repoint both sides (this is the `splitWorkload`
   case). If it is domain-specific, **export** it from `<G>` and have the
   straggler caller import `<G>` — but only if `<G>` does not import `handler`
   (else cycle; that is the signal to finish the `authctx`/`sqlx` promotion
   first).
6. Update the single wiring site in `internal/server/server.go`:
   `handler.NewXxx(...)` → `<G>.NewXxx(...)`, add the import. Watch for a local
   variable shadowing the new package name (e.g. `network := network.NewNetwork`
   → rename the local). Routes/middleware are unchanged: the server contract is
   identical externally.
7. Move the group's `*_test.go` files too. White-box tests keep `package <G>`.
   Test-only helpers that lived in the old package (e.g. `openTestDB` in
   `scanjobs_test.go`) get a tiny per-package copy (`testdb_test.go`) — each Go
   package owns its test helpers; this is idiomatic, not duplication debt.
8. `gofmt -w`, `go build ./...`, `go vet ./internal/handler/<G>/...`,
   `go test ./internal/handler/<G>/...`. Green = the move was mechanical.

## DoD mapping

- *No package > ~5K LOC* — `scanning` and `runtime` will need a second-level
  split (e.g. `scanning/jobs` + `scanning/attestations`); flagged above.
- *Each domain owns its queries* — SQL already lives inline next to each handler;
  it moves with the file. (D1's sqlc adoption can then target one domain at a
  time.)
- *server wiring unchanged externally* — only constructor qualifiers change.
- *tests for extracted packages* — moved tests stay green; new router/smoke
  tests are tracked under D3.

## Proof-of-pattern delivered in this PR

Extracted `handler/network` end-to-end as the reference:

- New leaf packages `internal/handler/httpx` (`WriteJSON`) and
  `internal/handler/netutil` (`SplitWorkload`, `StableFlowID`).
- Moved `network.go` + `network_conversations.go` (→ `conversations.go`) and
  both test files into `internal/handler/network` (`package network`).
- Repointed `internal/server/server.go` wiring; renamed the shadowing local var.
- Repointed the two `handler` stragglers (`network_policies.go`, `groups.go`)
  that used the moved pure helpers to `netutil`.
- `go build ./...` green; `go vet`/`go test` of the new packages green
  (the DB-backed network test passes against the test DB). Pre-existing
  `internal/handler` test failures (stale test-DB schema: `users.display_name`
  NOT NULL, duplicate-key fixtures) are unrelated to this change and reproduce
  on the base branch.
