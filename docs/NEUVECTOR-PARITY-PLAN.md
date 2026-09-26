# Constellation parity and switchability plan

Status: **active canonical plan**
Last reconciled: **2026-09-26**

This is the only active plan for NeuVector behavioral parity, NeuVector migration,
the Astronomer-inspired operator experience, and adoption of AlphaBravo's
[Technology Selection Guide](https://technology-selection-guide.aws.ablabs.io/).
It replaces the dated parity,
switchability, runtime-agent, UI-cleanup, and re-audit plans that previously
overlapped or contradicted one another.

The goal is not a pixel-for-pixel NeuVector clone. A task belongs here when it
helps an operator move from NeuVector, perform the equivalent security workflow,
understand the result, and prove that the control is enforced. Constellation's
stronger multi-tenant, CNI-native, evidence, and correlation features remain
first-class.

## Plan rules

- This file owns status. Audits and assessments are evidence, not task trackers.
- Do not mark a feature complete because a route, table, or form exists. The
  enforcement or delivery side effect, audit record, and operator-visible result
  must also work.
- Do not create inert compatibility objects. Import into an enforced
  Constellation model or report the source object as unsupported with a reason.
- Every mutation is RBAC-gated, audited, and redacts secrets.
- High-volume lists expose pagination or an explicit render cap; no silent
  truncation.
- An export is either round-trip importable or clearly labeled as evidence.
- Backend and chart changes require a deployable artifact and live-cluster smoke.
- New parity work is added here instead of creating another roadmap document.
- Record partial fixes in the implementation review, not as newly checked
  checklist items. Close an existing open item only when its acceptance is met;
  add a new open item when newly discovered work expands the scope.
- Technology Selection Guide requirements are tracked in TSG-1 through TSG-7
  below. Matching some library choices is not evidence of full conformance.
  Record approved deviations explicitly; do not silently treat them as compliant.

## Definition of done

Parity and switchability are release-ready only when:

- Every primary NeuVector workflow has an obvious Constellation entry point.
- Every intended route is reachable through navigation, Settings, the command
  palette, or a documented compatibility route.
- Migration supports preview, actionable unsupported rows, audited idempotent
  apply, history, rollback bundle, and rollback.
- Discover, Monitor, and Protect state is visible and matches actual runtime,
  admission, and network enforcement.
- Counts, filters, exports, and dashboards reconcile with source APIs.
- Security-sensitive error paths have explicit fail-open/fail-closed behavior.
- Source tests, browser tests, and the required CNI/live-cluster matrix pass.
- Documentation describes intentional differences instead of counting them as
  missing features.
- Every applicable Technology Selection Guide requirement has implementation and
  acceptance evidence, or an explicitly reviewed deviation with rationale, owner,
  risk, and review date. Report deviations separately from strict conformance.

## Current baseline

The following foundation is present in the current tree. These are capabilities,
not permanent claims: regressions reopen the relevant workstream.

| Area | Verified baseline |
|---|---|
| Navigation | NeuVector switchboard, compatibility terminology, route aliases, and command-palette discovery |
| Migration | Preview/apply/history/rollback framework; groups, safe network rules, process/file profiles, admission rules, and DLP/WAF conversion |
| Policy | Group detail/usage, network-rule CRUD, process rules, admission state and criteria builder, response-rule precedence and group binding |
| Runtime | NeuVector data plane ingestion, live flows/sessions/threats, process/file enforcement primitives, response-action polling/results, PCAP workflow |
| Network | Map, conversations, sessions, PCAP, rules, threats, group-aware filters, saved views, session kill, CNI-native policy lifecycle |
| Compliance | Kubernetes and host CIS evidence, remediation storage/rendering, cluster/node-safe compliance upsert |
| Vulnerability | Trivy/Grype evidence, KEV/EPSS/CVSS, reachability, risk decomposition, exceptions, CVE catalog |
| Operations | Effective-config read view, component cockpit/diagnostics, support bundle, dashboard rollups, audit and timeline exports |
| Admission | Full PSS baseline/restricted engine plus targeted hardening profiles, dry-run assessment, monitor/protect state |
| UI visibility | Shared persisted platform-component filter for Kubernetes, Constellation, and Astronomer namespaces on network, deployment, and container views |

## P0 — truth, correctness, and release safety

Parity is not credible while a configured security control silently does nothing.
The current [deficiency audit](deficiency-audit.md) is the source list for these
correctness issues; this plan owns their release order.

### Implementation review — 2026-09-26

Unchecked parent items remain open until **all** their acceptance requirements
are met. Code present is not the same as verified or release-ready. The older
deficiency ledger includes findings that already have fixes; do not use its
historical counts as a count of currently open defects.
Acceptance backlog: **101 open**. Since the `800b0ef` baseline of 107 open,
**seven existing items closed** (four OPS-1 items and three SIEM-1 items), and
one new vendor-interoperability item was added. The checklist contains **46 checked
bounded rows** (39 at baseline). Partial scanner and registry fixes are recorded
in the review table, not counted as closures. A checked child does not close its
unchecked parent or replace live deployment evidence.

| Acceptance item closed since `800b0ef` | Closure evidence |
|---|---|
| OPS-1 heartbeat fixtures | API-level tests ingest all 15 required and optional roles and check empty, partial and healthy org/cluster rollups. |
| OPS-1 role aliases, diagnostics and E2E filtering | DB-backed component tests cover controller, runtime-agent/enforcer and scanner role aliases, diagnostics status/checks, redaction and access failures. Existing frontend alias tests pass. A production-build Playwright browser run verifies URL role filters, matching rows, selection and role-specific diagnostics for all three roles using deterministic API fixtures; this closes the test item, not deployed component-health proof. |
| OPS-1 signed support bundles | A Helm-deployed API on disposable k3d ran with a read-only Ed25519 PKCS#8 Secret mount and separate seeded PostgreSQL database. An authenticated admin downloaded a signed bundle (HTTP 200), and the standalone offline verifier accepted it against a fingerprint derived from the deployment key before reading the bundle. The verifier rejected a tampered copy. Source/API/chart tests and Helm rendering also pass. Persisted asynchronous jobs are closed separately below. |
| OPS-1 asynchronous support-bundle jobs | Migration 164 persists queued/running/ready/failed/expired jobs, bounded cursor history, redacted payloads, seven-day expiry and audit links. Per-replica workers claim with `SKIP LOCKED`, recover stale leases and retry completion receipts. Source race tests cover transitions, isolation, audit failure, redaction, pagination and concurrency. A disposable k3d Helm install served API/frontend through nginx: an admin queued a job, observed ready status, downloaded a signed bundle, verified it offline against the independently derived key, and found create/ready/download events in audit history. Production-serving Playwright verified the operator queue, persisted history, ready download and audit drill-down. |

| Slice | Current status | Evidence / remaining work |
|---|---|---|
| P0 audit concurrency | Verified existing fix | `go test -tags=integration -count=2 ./pkg/audit` passed against PostgreSQL: concurrent writers, chain verification, and forbidden mutation. |
| P0 required VulnDB | Verified existing fix | `go test -count=2 ./internal/scanner` passed, including required-matcher failure and empty-SBOM regressions. |
| P0 restore scope/integrity | Source fixes verified; final matrix pending | Archive integrity/format/counts can no longer be waived; restore is atomic, imports reject unresolved cluster/project scopes, and preview now verifies rather than merely parsing. Removed inert UI trust override and gated apply on current-file validation. Backup tests and HTTP trust/RBAC/tenant/audit regression passed twice; UI component tests passed. Browser and deployment evidence still required. |
| P0 CSPM completeness | Source fix verified; deployment evidence open | AWS nested policy/ACL failures, malformed policy documents and inaccessible Public Access Block now return errors; only a typed missing-configuration response is treated as absent. GCP paginates buckets and rejects failed/malformed/oversized evidence. Pagination cycles fail closed. `go test -count=2 ./internal/cspm/...` passed. Cloud-account/live deployment validation remains open. |
| P0 admission compile failure | Source fix verified on fresh DB; deployment evidence open | Malformed enforce-mode CEL/Rego policies now remain in the active engine as fail-closed rules rather than disappearing at compile time; monitor-mode policies warn without blocking. Malformed CEL YAML likewise becomes a fail-closed compile sentinel. Unit tests assert denial, monitor behavior, rule attribution, DenyHook side effect and malformed-YAML loader behavior. Focused package tests passed twice and the affected-package fresh-DB run passed; a live webhook rollout/failurePolicy drill remains open. |
| P0 agent/heartbeat tenant scope | Source fixes and fresh-DB package tests verified; broader attribution audit open | Host facts/packages/processes/containers, host-CIS, workload packages, runtime events/threats/flows, Kubernetes audit, network sessions, platform facts and file-profile watches now use resolved token cluster attribution; file-profile bundle, response-action queue/result and PCAP claim/upload/status reads or writes reject cross-cluster use. The shared resolver rejects conflicting multi-cluster bundle mappings; absent a bundle it retains a legacy fallback only when the token org has exactly one cluster (platform facts requires an explicit bundle). Live flow/threat IP resolution and flow backfill select pod/service metadata only from the reporting cluster. Fresh-DB affected packages passed twice, with targeted valid and negative no-write tests. Remaining scanner-originated writes, per-node binding, legacy single-cluster fallback review and deployed multi-cluster proof remain open. |
| P0 scanner-job/heartbeat tenant scope | Bounded source and DB tests verified; scanner-token cluster binding remains open | Claim, renew, complete and fail reject scan jobs whose target belongs to another org; claim also ignores package evidence linked to a foreign-org target. Scanner-token heartbeat accepts owned clusters by ID or name, rejects foreign clusters and conflicting ID/name pairs. Scanner tokens remain org-scoped and can report any owned cluster; these checks do not prove node identity or deployed multi-cluster behavior. Schema-level composite foreign keys and remaining scanner-originated writes still need audit. |
| P0 scanner read scope | Bounded source and DB tests verified; wider scanner inventory open | Job list, attempts and status exclude rows whose target belongs to another org. Shared queue metrics apply the same target-org check for both scan-job and compliance consumers. Scanner-token package-evidence GET also requires its linked target to share the evidence org. Direct DB tests inject mismatched links and verify no cross-org target metadata, attempt ledger, status bundle, queue metric or evidence payload is surfaced. Schema-level composite foreign keys, other scanner reads/writes and deployment proof remain open. |
| P0 scanner target-link integrity | Bounded source and DB tests verified; parent tenant-scope item open | Package-evidence upsert now selects canonical target metadata from an owned target and writes nothing for a foreign target; latest-evidence lookup also ignores mismatched links. Scan-object evidence/jobs/finding counts/vulnerabilities exclude mismatched links, and enqueue rechecks and locks the owned target. Attestation report, read and verification paths reject or hide foreign-org target/evidence/image-result links. Direct DB tests cover valid and negative paths. Schema-level composite foreign keys, other consumers, transactional verification history and deployed multi-cluster proof remain open. |
| OPS-1 component role fixtures | API and browser tests verified; deployed health open | Heartbeat fixtures cover all 15 declared required and optional component roles, with empty, partial and healthy inventories, org/cluster rollups and instance-scope assertions. Additional DB-backed component tests cover controller, runtime-agent/enforcer and scanner role aliases and healthy/degraded/stale/drift diagnostics, redaction and access failures. A production-build Playwright test verifies URL role filters, matching rows, selection and role-specific diagnostics with deterministic API fixtures. Deployed component health remains open. |
| OPS-1 signed support bundles | Closed; live k3d deployment and offline verification passed | A configured Ed25519 PKCS#8 key signs the redacted sections hash and bundle identity; absent keys remain explicitly unsigned and invalid configured keys fail closed. Source/API tests verify cryptography, tampering, redaction-before-signing and authenticated download. A Helm-deployed API used the existing Secret as a read-only mount; an authenticated download returned a signed bundle that the standalone verifier accepted against a separately derived key fingerprint and rejected after section tampering. Persisted asynchronous jobs are now closed separately. |
| OPS-1 asynchronous support-bundle jobs | Closed; source, live API and production browser passed | PostgreSQL jobs support queued/running/ready/failed/expired states, bounded cursor history, redacted verified payloads, seven-day expiry and per-job audit/download history. Claims use `SKIP LOCKED` across API replicas and stale leases recover after restart. Create/download fail closed on audit outage; worker completion receipts retry before jobs advertise ready. Source race tests passed. A Helm-deployed API/frontend on disposable k3d completed queue/status/signed-download/offline-verification/audit-history smoke, and a production-serving Playwright test verified the System Health operator workflow and audit drill-down. |
| SIEM-1 syslog TLS with CA/client material | Closed; source and deployed collector passed | A Helm-deployed API connected to a strict mTLS collector using configured CA and client material. The collector verified the client certificate and captured a policy event. Replacing the CA or removing the client pair produced no payload; restoring the pair resumed delivery. In-process tests separately cover plaintext rejection and TLS 1.2/1.3. This does not claim interoperability with a branded SIEM. |
| SIEM-1 wire formats and filters | Closed; deployed matrix passed | The same live API emitted RFC5424, JSON and CEF policy events, then a critical finding event. An `info` policy event was excluded by a `high` floor, and a critical finding was excluded by a nonmatching category; switching the category delivered the finding. The collector captured the expected lines and no filtered lines. |
| SIEM-1 named receiver routing and receipts | Closed; source, API and deployed receiver passed | PostgreSQL tests prove named-only dispatch, retry/terminal receipts, org/paused rejection and concurrent pause/send ordering. API tests prove delivery-history visibility and audit linkage, including cross-org isolation. A rebuilt Helm-deployed API sent a test-fire to the first of two named SMTP receivers; only that recipient was reached, its receipt became `delivered`, and the audit event linked its delivery ID. Pausing returned 409 without another send; unpausing restored delivery. A vendor SIEM integration remains a separate open item. |
| REG-1 scanner DB and capacity surfaces | Source and production-browser UI verified; deployed scanner proof open | Scanner heartbeats now report per-engine Trivy/Grype applied revisions from installed DB metadata and download revisions only after a successful explicit refresh; offline preloads report applied but not downloaded. Dashboard, System Health and Scanner & CVE Sources show revisions separately from the host VulnDB bundle and show worker capacity, missing/partial/stale states. Scanner race/unit tests, frontend component/type tests and PostgreSQL-backed overview/cluster health API tests pass. A production-build Playwright test verifies dashboard, System Health and scanner-source rendering with deterministic heartbeat revisions. A deployed scanner refresh and real heartbeat-to-dashboard smoke is still required before closing the existing REG-1 item. Download history is in memory and resets on scanner restart; installed applied revisions are recovered from the local DB. |
| P0 audit/timeline/exemption scope | Source fixes and direct PostgreSQL tests verified; deployed matrix open | Audit, timeline, compliance checks/summary and evidence cluster filters reject clusters outside the subject org; timeline violation attribution cannot join a foreign-org deployment. Exemption create/list/revoke tests cover cross-org/foreign-cluster and no-write behavior. The evidence overlay applies cluster-specific exemptions only to matching-cluster items, falls back to org-wide exemptions and rejects misattributed exemptions; checks/summary exclude misattributed foreign-cluster check and exemption rows. Remaining aggregation and agent-write inventory, route-level cluster-grant RBAC, and deployed multi-cluster paths are open. |
| SIEM-1 TLS material guard | Source and deployed mTLS collector verified | Validation and sender guards refuse TLS material on plaintext transport. In-process tests cover TLS 1.2/1.3, wrong CA, absent/untrusted clients and plaintext rejection. A Helm-deployed API additionally passed strict client-certificate verification and rejected wrong-CA/missing-client attempts before resuming after restoration. Vendor-specific interoperability is separately open. |
| SIEM-1 severity floor | Source and deployed wire/filter matrix verified | An unknown configured minimum level denies all alerts rather than silently shipping; an unknown alert severity falls below an `info` floor. Source tests cover all three formatters and filter-before-dial. A live collector captured RFC5424/JSON/CEF, excluded an info event under a high floor and excluded a critical event under a mismatched category. |
| SIEM-1 named delivery receipts | Source, API and deployed SMTP receiver verified | `DispatchTo` scopes receiver lookup to the event org and rejects paused receivers before queueing. Workers and sweepers terminate queued/retry deliveries paused later. PostgreSQL tests cover named-only send, pending/delivered/retrying/failed/paused receipts, exact retry payload/idempotency and concurrent in-flight pause ordering. API tests cover history, audit linkage and cross-org isolation. A deployed API delivered only to its named SMTP recipient, exposed the delivered receipt and audit link, and returned 409 for a paused test-fire. A named vendor SIEM remains separately open. |

SIEM closure used migration 164 on a disposable PostgreSQL database and a Helm
deployment in disposable k3d. The rebuilt API image was
`sha256:d30da81cea257830d6ba39beb297f45199c317c881f924c1b44f192af335c2d7`.
Captured synthetic collector traffic is in `/tmp/constellation-siem-parity-0926/wire.log`
and `/tmp/constellation-siem-parity-0926/smtp.log`; private test keys are not
retained. Affected Go packages passed `go test -race` and `go vet`; the plan-count
and endpoint-mapping tooling gates passed.
| REG-1 kind validation | Source fix verified; connector matrix open | Registry create rejects unknown kinds with an explicit 400; PATCH rejects any supplied `kind` (including null/empty/non-string) rather than silently ignoring an attempted type change. Unit/HTTP tests cover all 13 accepted kinds, unknown create and immutable update. This does not prove per-kind discovery/auth against real registries or endpoint/credential validation. |
| REG-1 scanner credential isolation | Bounded private-registry source tests verified; live connector proof open | Each scanner job uses a separate Docker config directory with 0700/0600 modes; tests cover simultaneous jobs and cleanup on success, failure and cancellation. Digest resolution, manifest inspection, config-history, file-risk and config-check reads use job credentials with HTTPS and authority checks. Configured-credential fetch, missing credentials, authority or isolated-config failures now fail the job before scanning rather than silently falling back to ambient auth; only explicit `auth_kind=none` is accepted without credentials. The credential endpoint now refuses to disclose a decrypted secret if its audit append fails; DB tests verify a redacted receipt and the no-secret fail path. An opt-in one-shot `--registry-id` path fetches configured credentials, fails before scanning on retrieval/validation errors and passes an isolated config to engines and image metadata reads; its legacy `--ref` path is unchanged. Isolated engine subprocesses drop inherited Trivy/Grype/Syft auth variables. Fake-registry tests cover authenticated metadata, wrong credentials despite ambient Docker config, TLS failure, platform selection and cross-authority blob, bearer-realm or plaintext non-forwarding. Credential issuance is still org-scoped rather than bound to a claimed job; legacy one-shot ambient auth, signature verification, other ambient cloud credentials, live private registries and end-to-end credential lifetime remain open. |
| API-1 CLI recipe smoke | Four GET recipes, nonapplying preview and fixed apply/rollback fixture verified locally; complete runbook smoke open | `scripts/smoke_api_recipes.py` keeps the default four bounded GET recipes and explicit nonapplying preview. New `--apply-rollback-fixture` is loopback-only, opt-in, refuses an existing profile, checks conversion/apply/idempotency/rollback and attempts cleanup on failure without printing tokens or response bodies. Mock tests and an opt-in disposable local API run passed. Other migration families, mutation recipes and deployed-API smoke remain open; the API-1 parent item remains open. |
| P0 E1 response actions | Bounded source behavior verified; full action matrix open | New/updated E1 `tag` rules are rejected because no label side effect exists; legacy runtime, scan, admission, compliance, host-CIS and Kubernetes-audit attempts report unsupported. E1 admission `suppress_log` skips the ordinary deny audit/notify leg while preserving denial and response-action audit; monitor and rule-load failures retain ordinary audit. E1 scan `suppress_log` is rejected for new/updated rules because scan completion emits no security-event log; legacy attempts appear in `unsupported_actions`, are omitted from agent sync, and report `skipped_no_security_event` while operational result/attempt/completion audit persist. Invalid operator CR reconciliation removes known last-applied declarative rows, reports `InvalidSpec` and requeues failed cleanup. Fresh-DB tests pass. Older CRs without last-applied org, a real tag effect, deployed proof and full response-action matrix remain open. |
| Clean database/repeated integration | Verified with explicit skips | `GOWORK=off GOOSE_BIN=/root/go/bin/goose GOTESTSUM_BIN=/tmp/tsg4-bin/gotestsum bash scripts/test-go.sh integration` passed on a fresh disposable pgvector database: migrations through 163, second migration no-op, full integration-tag suite with `-p 1 -race -shuffle=on -count=2`, JUnit/JSON reports. Result: 4,122 tests, 68 skipped, 501.645 seconds. Skips include environment-dependent cases and existing scanner tests requiring seed fixtures; these are not claimed as covered. Per-test DB isolation and elimination of avoidable seed-dependent skips remain open. Final SAML browser-binding checks are a separate follow-up to this snapshot. |
| Full source/release matrix | Partial; broader release matrix remains open | Clean-DB repeated/shuffled integration with races passed (4,122 tests, 68 skipped), followed by 544 seeded handler/scanning tests with races/repetition/shuffle and no skips. Final focused server/security/config/backup tests passed twice with races. `GOWORK=off go vet ./...`, OpenAPI checks, frontend type-check/build, all 83 frontend tests (25 files), 40 tooling tests, actionlint, changed-runner ShellCheck, Helm lint and whitespace checks passed. Four authenticated read-only recipes, a nonapplying preview and ten Playwright tests passed against newly built API/frontend images through production nginx. This is not the full UI, Kubernetes rollout, CNI/kernel/cloud, signed-IdP, FIPS, HA or disconnected-install matrix. |
| TSG-3 browser sessions | Implemented and verified for local/CLI plus container-browser paths | Secure HttpOnly/Strict cookies replace browser localStorage; migration 163 persists hashed rotating refresh secrets, consumed-token replay revokes the tracked family, access tokens are capped at 15 minutes, and origin/header CSRF checks preserve explicit bearer precedence. API/race tests cover tenant scope, password/role revocation, logout, idle/absolute expiry and concurrent replay. Browser tests prove token non-exposure, coalesced cross-tab refresh, cross-tab logout, CSRF denial and replay rejection. The browser regression now verifies cookie rotation and a subsequent forced refresh after two-tab recovery instead of counting a navigation-canceled response event. External IdP/HA coverage and broader security requirements remain open. |
| CFG-1 provenance and validation | Verified bounded implementation, including a deployed change | Per-key default/environment-bootstrap/database provenance persists in JSONB; validation returns field-level errors without submitted secrets; applied revision names only the serving provider. DB tests cover live proxy reload, RBAC, redaction and concurrent PATCH. Container-browser tests change TLS verification, check the applied provider revision, restore the setting and render provenance without restarting the API. Cluster/federation/linked-managed layers, scanner acknowledgements and key-only audit deltas remain open. |
| MIG-1 remaining families | Reviewed subset verified through API, UI and container browser | Safe literal/wildcard vulnerability suppressions and inert-by-default registry metadata support preview/apply/history/idempotency/conflict-safe rollback. Fixture accounts for 16 source objects: 3 convertible, 13 unsupported, plus 2 omission diagnostics. DB/race tests cover isolation, permissions, conflicts, redaction and update restoration. Two production-browser cases cover paste/upload, preview, partial apply, unchanged/update previews, persisted rows/history, rollback bundle and rollback. Scoped/recent/federated profiles, registry selection/schedules/credentials, remaining families and the full mixed-family fixture remain open. |
| TSG-4 blocking gates | Implemented; remaining baseline findings block release | PR and tag-release CI enforce lint/format, history secret scans, gosec, govulncheck/SARIF, dependency audits and race/JUnit runners. Tooling regressions pass. Initial scans found 1,895 lint issues, 256 gosec findings, 18 historical secret detections and ShellCheck/format failures; these need triage, not blanket suppression. Dependency remediation reduced 37 reachable Go vulnerabilities to zero under the actual Go 1.26.8 toolchain, and both npm lockfile audits now report zero. Nine non-reachable imported/module Go advisories remain recorded. Hosted checks/branch protection and source/secret baseline remediation are open. See `security-testing.md`. |
| Security review follow-ups | Source fixes and targeted race tests verified | Foreign-org role-binding subjects/scopes are now rejected and epoch mutations are tenant-scoped. Refresh access is bounded by its absolute family deadline, tracked idle expiry preserves sibling sessions, activity timestamps are monotonic, and stale idle reads cannot delete newly active rows. Browser SAML uses a bounded, expiring, single-use cookie/RelayState binding and rejects unsolicited browser ACS; four new tests include 13 rejection cases and existing SAML tests pass with races/repetition/shuffle. Login/logout clear cached identity data and notify other tabs. Live signed-IdP/multi-replica SAML and exact browser/AuthnRequest assertion-correlation validation remain open. |
| Verification artifacts | Current affected-package fresh-DB and production API/browser gate passed; deployment matrix open | Full-suite JUnit/JSON: `/tmp/constellation-parity-final-integration/`; seeded follow-up JUnit: `/tmp/constellation-parity-seeded.xml`; latest fresh affected-package log: `/tmp/parity-agent-writes-final-fresh.log` (nine packages twice, migration 163 plus second no-op); final PCAP/runtime recheck: `/tmp/parity-runtime-final-fresh.log`; earlier IP/audit logs: `/tmp/parity-ip-scope-fresh.log`, `/tmp/parity-agent-audit-fresh.log`. Current production-image/build/migration/API smoke evidence: `/tmp/parity-agent-writes-browser-current-evidence/`; runner log: `/tmp/parity-agent-writes-browser-current.log` (four live GET recipes, nonapplying preview, opt-in fixed apply/idempotency/rollback and 10 Playwright tests passed). Current API image `sha256:b29668f72e6a20fc150bd30da5857a3250cca4f60e50b60bed604edf78651ff2`; frontend image `sha256:6db10e05f71e7a3fd20c05726098f5ffe5be44476c93b45e7dfd0f6ea6ec395c`. Scanner private-registry tests and 47 tooling tests passed separately; the API image does not contain the scanner worker. Disposable services were cleaned up; no existing Kubernetes deployment was changed. This is local source/container evidence, not live private-registry, CNI/cloud/HA/hosted-CI proof. |

Latest affected-package validation: `GOOSE_BIN=/root/go/bin/goose bash
scripts/test-clean-database.sh ./internal/handler ./internal/handler/compliance
./pkg/admission ./cmd/constellation-admission ./pkg/notify ./internal/syscfg`
passed with two no-op-checked migration runs through 163 and package tests repeated
twice. Log: `/tmp/parity-fresh-affected.log`. The reused local `constellation-test-pg`
remains at migration 161; a SAML browser-session test fails there because
`browser_refresh_tokens` does not exist. That stale-database failure is not
counted as a source regression or successful browser validation.

After the response/registry/SIEM changes, a broader disposable-DB run repeated
tests in 11 affected Go packages (handler, policy, runtime, scanning,
compliance, admission, notify, response-rule, syscfg and operator controller
paths) with migrations through 163 and a second no-op. All packages passed;
log: `/tmp/parity-fresh-expanded.log`. This was not a new full-repository race
or production-browser run.

This continuation repeated tests in handler, compliance, Kubernetes audit,
notify and operator-controller packages against another fresh disposable DB;
migrations reached 163 and the second migration was a no-op. New host
cross-tenant, legacy-tag audit and paused-delivery cases ran without depending
on a seeded org. All five packages passed twice; log:
`/tmp/parity-continuation-fresh.log`. This is affected-package evidence, not a
new full-repository race run.

Admission, scan, policy, response-rule and operator-controller packages then
passed twice against another fresh database through migration 163 with a
second migration no-op. Log: `/tmp/parity-suppress-fresh.log`. This covers the
new `suppress_log` fail paths but is not a full-repository race run.

Policy and response-rule packages passed twice against another fresh database
through migration 163 with a second no-op after legacy scan-rule API/sync
visibility was tightened. Log: `/tmp/parity-scan-unsupported-fresh.log`.

The tenant, scanner-credential and SIEM continuation passed twice against a
fresh disposable database through migration 163 with a second migration no-op:
`./internal/handler`, `./internal/handler/compliance`,
`./cmd/constellation-scanner`, `./pkg/notify` and `./internal/syscfg`.
Log: `/tmp/parity-tenant-siem-fresh.log`. The reused local database still
lacks migration 163 and fails the browser SAML test; fresh-DB verification is
the relevant result. This is not a new production-browser or live-collector run.

After correcting the compliance-evidence cluster overlay, the same five
packages passed twice on another disposable database through migration 163;
log: `/tmp/parity-tenant-evidence-fresh.log`. The final summary negative
assertion was also repeated three times in a focused local database run.

Compliance checks/summary scope and workload-package token binding passed
twice against a fresh disposable database through migration 163, with a
second migration no-op. Log: `/tmp/parity-scope-continuation-fresh.log`.

The runtime-event/DPI-threat/network-flow binding, conflicting-bundle guard,
compliance read scope, workload-package scope and scanner private-registry
continuation passed twice in six affected Go packages on another fresh
disposable database through migration 163, with a second no-op. Log:
`/tmp/parity-agent-registry-fresh.log`. The opt-in fixed CLI apply/rollback
fixture, read-only recipes, preview and ten browser cases passed against
freshly built local production API/frontend images; evidence is in
`/tmp/parity-agent-registry-browser-evidence/`. Neither run is live fleet,
private-registry or deployed SIEM validation.

Flow/threat IP resolution and automatic flow backfill then passed two-cluster
reused-IP tests in seven fresh-DB packages twice; log:
`/tmp/parity-ip-scope-fresh.log`. After removing unused org-wide resolution
entry points and binding Kubernetes audit ingest, handler, network, netpolicy,
runtime and Kubernetes audit packages passed twice on another fresh DB; log:
`/tmp/parity-agent-audit-fresh.log`. Both runs reached migration 163 with a
second no-op. Rebuilt production API/frontend images, four read-only API
recipes, a nonapplying preview, opt-in apply/idempotency/rollback and all ten
Playwright cases passed; evidence: `/tmp/parity-ip-audit-browser-evidence/`.
The scanner private-registry worker is outside that API image; focused race
tests for its credentialed metadata reads passed separately. No live
multi-cluster or private-registry connector claim follows from these tests.

The next agent-write continuation covered session snapshots, platform facts,
file-profile watches and bundles, response-action queue/results and PCAP
claim/upload/status. Nine affected packages passed twice on a fresh database
through migration 163 with a second no-op (`/tmp/parity-agent-writes-final-fresh.log`);
the final PCAP edit passed a separate fresh runtime-package rerun
(`/tmp/parity-runtime-final-fresh.log`). Focused race tests, `go vet ./...`,
endpoint mapping and formatting/whitespace checks passed. A production-browser
attempt exposed a canceled-response counting assertion in the cross-tab refresh
test despite a rotated cookie; the test now verifies a subsequent forced
refresh instead. The final rebuilt API/frontend gate passed four read-only
recipes, preview, apply/idempotency/rollback and 10/10 Playwright cases;
evidence: `/tmp/parity-agent-writes-browser-current-evidence/`. These are
local artifacts, not fleet, live private-registry or CNI proof.

Scanner-job target/evidence org guards, scanner-token heartbeat ID/name
consistency and configured-registry fail-closed behavior passed twice in three
affected packages against another fresh database through migration 163, with a
second migration no-op (`/tmp/parity-postcommit-fresh.log`). Focused race tests
for the new cases passed twice. The earlier production-browser images predate
these API changes; this run is not a rebuilt-browser or live-connector claim.

Opt-in one-shot registry credentials, isolated scan-tool environment and all
declared component-role heartbeat fixtures passed twice in three affected
packages against a further fresh database through migration 163, with a second
migration no-op (`/tmp/parity-oneshot-components-fresh.log`). Focused race tests,
`go vet ./...` and formatting/whitespace checks passed. This does not prove
live private registries, signature-tool isolation or deployed components.

Scanner-job read scope, credential-audit fail-closed behavior and syslog
severity-floor handling then passed twice in handler, scanning, compliance and
notify packages against a fresh database through migration 163, with a second
migration no-op (`/tmp/parity-scanner-read-audit-siem-fresh.log`). This is local
source/DB evidence, not a rebuilt production-browser or deployed SIEM check.

Scanner-token evidence GET target-org validation passed twice in a further
fresh handler-package database run through migration 163, with a second
migration no-op (`/tmp/parity-scan-evidence-get-fresh.log`). Focused scanner,
evidence, credential-audit and syslog cases passed twice with races; `go vet
./...` and whitespace checks passed. The touched `pkg/notify/notify.go` retains
pre-existing whole-file `gofmt` differences outside this bounded change.

The scanner target-link continuation passed twice in handler and scanning
packages against a fresh database through migration 163, with a second
migration no-op (`/tmp/parity-evidence-link-scope-fresh.log`). Focused evidence,
scan-object and attestation cases passed twice with races; `go vet ./...`,
formatting on touched Go files and whitespace checks passed. This is a partial
tenant-scope fix, not a closure of the P0.2 parent or deployed proof.

This table records the current review, not completion of other unchecked
workstreams. Update rows with actual test results as each slice is verified.

### P0.1 Reachability gate for advertised controls

- [ ] Add a feature-reachability test for every advertised response action,
  vulnerability-profile decision, admission decision, runtime policy action,
  backup/restore guarantee, and GitOps reconciler.
- [ ] Remove or visibly mark any option that cannot reach an enforcement or
  delivery side effect.
- [ ] Require one positive side-effect assertion and one fail-path assertion for
  each control before closing its deficiency-audit item.
- [x] Stop accepting new E1 `tag` rules and remove the tag option from
  OpenAPI/operator CRD until it has a persisted label side effect; expose
  legacy unsupported rows without claiming enforcement on runtime, scan or
  admission paths.
- [x] Remove the last applied declarative rule when an existing response-rule
  CR becomes invalid, including legacy `tag`, and requeue a failed cleanup.
  Controller tests cover stale-row removal, repair and delete failure; older
  CRs without `lastAppliedOrgID` still need owner-reviewed cleanup.
- [x] Record legacy E1 `tag` attempts as unsupported in compliance, host-CIS
  and Kubernetes-audit audit events without bypassing `suppress_log` behavior.
  Seed-independent DB tests cover the positive and suppressed paths; a real
  persisted tag/label effect remains unimplemented.
- [x] Apply E1 admission `suppress_log` before ordinary deny audit/notify fan-out
  while keeping the actual denial and response-action audit. Fresh-DB tests
  cover matched, unmatched, monitor, malformed-rule and denial paths.
- [x] Reject new/updated scan `suppress_log` rules because scan completion has
  no security-event log; mark legacy rows unsupported, omit the no-op from
  agent sync and report attempts as skipped without suppressing
  required scan result, attempt history or completion audit. Fresh-DB tests
  cover match and evaluator failure; a distinct suppressible scan alert path
  remains unimplemented.

Current reachability gaps to keep visible: legacy E1 `tag` has no persisted
workload/event label; pre-status tag-bearing operator CRs need owner-reviewed
cleanup; scan completion has no security-event log or generic notification to
suppress, so legacy `suppress_log` is a visible skip rather than runtime-equivalent
suppression; and
the operator GitOps/RBAC, profile-decision, and process-kill chains still need
deployed side-effect and failure assertions. These are not closed by an audit
row saying `enforced`.

### P0.2 Tenant and cluster scope

- [ ] Close all open high-severity org/cluster attribution and restore-scope
  findings before the next parity release claim.
- [ ] Add negative cross-tenant tests for backup restore, host/CIS ingestion,
  audit/event aggregation, exemptions, and agent-originated writes.
- [ ] Derive scope from the authenticated subject and resolved cluster, never an
  uploaded object or an arbitrary first row.
- [x] Reject foreign-org init-bundle/cluster attribution in host facts,
  packages, processes, containers, and CIS ingest through the shared resolver;
  direct DB negative tests confirm no facts/CIS/packages/processes/containers
  snapshot write (and no package scan side effects). Heartbeats
  reject foreign cluster IDs and runtime-agent claims outside their resolved
  cluster binding. Broader agent-originated write inventory remains open.
- [ ] Inventory and test remaining agent-originated writes, audit/event
  aggregation, and exemption scope, including deployed multi-cluster paths.
  Scanner-job claim/renew/complete/fail and scanner-token heartbeat paths have
  bounded source checks below, but remaining scanner-originated writes and
  scanner-token cluster/node binding still need audit. Agent tokens still bind to clusters rather than
  individual nodes; empty session snapshots cannot identify a node to clear.
  The shared resolver still permits a legacy single-cluster fallback for
  tokens without init-bundle mappings; review whether to retire that fallback.
  Do not treat bounded source fixes as deployed multi-cluster proof.
- [x] Reject foreign cluster filters in audit and timeline; prevent foreign-org
  deployment metadata from joining a violation. PostgreSQL tests cover org and
  cluster isolation. Exemption create/list/revoke tests cover cross-org and
  misattributed cluster rows without unauthorized writes. Route-level
  cluster-grant RBAC and deployed multi-cluster evidence remain open.
- [x] Keep cluster-specific compliance exemptions on matching evidence rows,
  with org-wide fallback; reject foreign-cluster evidence filters and ignore
  misattributed exemptions in evidence, checks and summary. Direct DB tests
  cover a two-cluster org and a foreign-cluster reference.
- [x] Reject foreign or missing cluster filters on compliance checks and summary;
  exclude misattributed foreign-cluster checks from org-wide reads. PostgreSQL
  tests cover two owned clusters, org-wide rows, foreign and malformed IDs.
- [x] Bind workload-package evidence and scan jobs to the reporting runtime
  token's resolved cluster; reject same-org mismatches, foreign clusters and
  ambiguous multi-cluster tokens before writes. Local PostgreSQL tests cover
  successful bound ingest and rejected no-write paths. Other agent-originated
  writes remain open in the attribution inventory.
- [x] Bind DPI threat writes to the reporting runtime token's cluster and
  reject foreign-bundle or unbound multi-cluster tokens before writes. Local
  PostgreSQL tests cover valid attribution and negative no-write cases.
- [x] Bind runtime-event and network-flow writes to the reporting token's
  cluster rather than a query argument, workload-name guess or first org row;
  direct DB tests cover valid and rejected no-write paths. The shared resolver
  rejects conflicting multi-cluster bundle mappings. Other agent-originated
  writes remain open.
- [x] Scope flow/threat IP-to-workload lookup and automatic flow backfill to the
  reporting cluster. Direct PostgreSQL tests reuse the same pod/service IP in
  two clusters and verify both correct labels and no cross-cluster relabeling.
  Deployed multi-cluster proof remains open.
- [x] Attribute Kubernetes audit webhook events to the reporting token's
  resolved cluster, not the first org cluster or submitted payload. Fresh-DB
  tests cover bound attribution, spoofed cluster input, invalid bundles,
  ambiguous multi-cluster tokens and no-write rejection. Other agent and
  scanner-originated write paths remain in the inventory.
- [x] Bind network-session snapshot replacement to the reporting token's
  cluster; reject mismatched query/row claims, mixed nodes, foreign/conflicting
  bundles and ambiguous tokens before deletes. Direct DB tests also verify
  the cluster-local session-kill response. Per-node token binding and empty
  snapshot deletion remain open.
- [x] Require an explicit init-bundle token binding for platform-facts reports
  before facts, evidence, scan targets/jobs or cluster state can change.
  PostgreSQL tests cover accepted writes and scanner-token, foreign, ambiguous,
  unbound and same-org-mismatch no-write paths.
- [x] Bind file-profile watch inventory reports to the token's cluster before
  replacement. Direct DB tests cover valid reports and foreign, ambiguous,
  conflicting and same-org-mismatched no-write paths.
- [x] Bind file-profile agent rule bundles to the token's cluster before
  reading rules. Two-cluster DB tests cover valid reads and rejected requests
  without rule leakage.
- [x] Bind response-action pending reads and completion writes to the token's
  cluster. PostgreSQL tests cover valid queue/result side effects and
  same-org cross-cluster, ambiguous and foreign-bundle no-write paths.
- [x] Bind PCAP claim, upload and status endpoints to the token's cluster.
  Direct DB tests cover valid claim/upload/status side effects, cross-cluster
  and ambiguous no-write paths, and absence of rejected upload files.

### P0.3 Fail-path behavior and integrity

- [ ] Close open fail-open findings in admission, CIS, CSPM, required VulnDB,
  notification delivery, signature verification, and restore validation.
- [x] Make the audit hash chain safe under concurrent writers and retain a
  deterministic verification test.
- [x] Add a clean-database migration test and a repeated integration-test run to
  catch uniqueness and stale-fixture failures.

## P1 — switchability and migration

### MIG-1 Complete safe import coverage

- [ ] Convert remaining NeuVector families with safe equivalents:
  vulnerability profiles, compliance profiles, registries without embedded
  secrets, syslog/webhook routing, auth-provider metadata, users/roles and role
  mappings, API-token metadata, and safe federation metadata.
- [x] Mark credentials and token secrets as omitted/reissue-required.
  Covered by remaining-family parser/API redaction tests and both browser import
  cases; registry metadata imports do not copy credentials or enable auto-scans.
- [ ] Publish one complete fixture manifest with source, converted, unsupported,
  applied, and rolled-back object counts.
- [ ] Add browser coverage for paste/upload, preview, dry-run, apply, history,
  rollback-bundle download, rollback, and post-rollback inspection.
- [ ] Confirm imported DLP/WAF objects are visible from Migration, Policy Center,
  DLP Rules, and WAF/DPI Signatures.

### CFG-1 Effective configuration provenance and safe mutation

- [ ] Return per-key provenance: default, environment bootstrap, database,
  cluster, federation, linked-managed, and redacted.
- [ ] Add PATCH only for settings whose consumers already support safe reload:
  scanner refresh/proxy, network proxy, syslog/SIEM, registry TLS/CA, and
  supported retention values.
- [x] Return field-level validation errors with secret-like values redacted.
  Verified by PostgreSQL-backed handler tests, validation unit tests and UI tests;
  unknown field names are also replaced with a safe `$` marker.
- [ ] Increment revision, audit redacted before/after deltas, and show applied
  component revision.
- [x] Validate a settings change in a deployed environment without restart where
  runtime reload is promised.
  Verified for the serving provider through the production-container TLS setting
  change/restore test; this does not claim scanner acknowledgement or fleet-wide
  adoption of every configuration field.

### IAM-1 Identity-provider and RBAC cutover

- [ ] Add bounded, secret-redacted connection tests for LDAP, SAML metadata, and
  OIDC discovery.
- [ ] Add group-resolution and final mapped-role/scope previews.
- [ ] Import NeuVector users, roles, mappings, and token metadata without
  privilege escalation; require token reissue.
- [ ] Add audited local-user unlock and force-reset actions.
- [ ] Complete namespace-scoped row filtering where resources have a namespace.

### API-1 Runbook-compatible contracts

- [ ] Complete OpenAPI request/response schemas for migration, network rules,
  admission assessment, registry sync/cancel, event export, PCAP, support
  bundles, group usage, and DLP/WAF bindings.
- [x] Add a link/route checker for the endpoint mapping document.
  `make check-endpoint-mapping` validates 107 explicit API references and local
  links against OpenAPI, then runs the registered-router/OpenAPI tests; CI gates
  it. Wildcard references prove at least one matching route, not full family
  coverage. Four read-only CLI recipes and nonapplying preview passed locally; complete runbook and
  externally deployed endpoint smoke tests remain open.
- [ ] Smoke-test all applicable CLI recipes against a local API, including
  supported mutation/rollback flows. Four read-only recipes plus a fixed,
  nonapplying vulnerability-profile preview and opt-in fixed apply/rollback
  fixture passed against disposable local APIs; do not count that bounded
  pass as the complete runbook.
- [x] Add a loopback-only, explicit opt-in fixed vulnerability-profile
  apply/idempotency/rollback smoke with preexisting-profile refusal and
  failure cleanup. Mock and disposable-API runs passed; other mutation
  recipes remain open.
- [x] Add a bounded loopback-only, secret-safe recipe runner and mock-server
  positive/failure tests for groups, audit, timeline, scan jobs, and opt-in
  migration preview. The browser gate authenticates and runs the four GET
  recipes plus fixed preview against the freshly built API; arbitrary exports
  remain opt-in and the parent item remains open.
- [ ] Add a new-org cutover script that imports the canonical fixture, checks
  counts and key UI routes, then rolls back.

## P1 — enforcement and runtime fidelity

### RUN-1 Protect mode must mean enforced

- [ ] Maintain a cluster test proving process, file, exec, and zero-drift events
  alert in Monitor and block in Protect.
- [ ] Verify response-rule process kill is delivered, executed, acknowledged,
  and linked to its audit record.
- [ ] Capture bounded argv plus path/hash/parent identity where supported and use
  it in baseline matching; retain basename compatibility only as an explicit
  fallback.
- [ ] Hydrate drift/baseline state after agent restart and report each node's
  last-applied fingerprint.
- [ ] Cover non-exec UID changes and remaining meaningful file mutation classes.

### NET-1 Network enforcement and activity consistency

- [ ] Apply shared filters consistently to map, conversations, sessions, threats,
  policy context, and PCAP where each dimension is meaningful.
- [ ] Finish server-side port/peer/application/time filtering, totals, `has_more`,
  and cursor/offset contracts for row-oriented network APIs.
- [ ] Reconcile counts across tabs for the same filter and large fixture.
- [ ] Live-test Flannel/iptables inline behavior and Cilium/Calico CNI-native
  policy behavior; keep the documented L7-on-Cilium limitation explicit.
- [ ] Validate multi-interface pod attribution and host-network attribution.
- [x] Replace the kube-only visibility chip with a persisted exact-match platform
  filter covering Kubernetes, Constellation, and Astronomer system namespaces.

### CMP-1 Compliance execution

- [ ] Add a true on-demand kube-bench/docker-bench execution path rather than
  only nudging the report renderer.
- [ ] Ship and validate docker-bench scheduling when enabled.
- [ ] Run the same benchmark against two clusters and prove results remain
  cluster/node scoped across repeated executions.

### REG-1 Registry and scanner breadth

- [ ] Prove private-registry credentials are scoped per job and removed after use.
- [x] Verify scanner Docker credential configs are per-job, mode-restricted and
  removed on success, failure and cancellation in local tests. Private-registry
  live connector behavior is not yet proven.
- [x] Use the job's scoped credentials for private-registry digest, manifest
  and config-history reads. Fake-registry tests cover TLS, wrong credentials,
  platform selection and no credential forwarding to redirects, bearer realms
  or plaintext; live connectors remain open.
- [x] Use the same per-job HTTPS/authority-scoped credentials for file-risk and
  config-check image reads. Fake-registry tests cover authenticated metadata,
  wrong credentials despite an ambient Docker config, mismatched authority,
  plaintext rejection and cross-authority blob redirects. Opt-in one-shot
  scans now have a configured-registry path below; signature verification
  still lacks this per-job path.
- [ ] Complete and validate ECR, GCR/Artifact Registry, ACR, Harbor, GitLab,
  JFrog/Nexus, IBM Cloud, and OpenShift discovery/auth flows that are advertised.
- [ ] Add tag/repository selection policies, refreshable cloud tokens, and
  explicit unsupported-kind errors.
- [x] Return an explicit client error for unsupported registry kinds on create
  and attempted kind changes on PATCH; static tests enumerate all 13 accepted
  kinds. Tag/repository selection and live cloud-token refresh remain open.
- [ ] Show scanner database download/apply revision and worker capacity on
  dashboard and health surfaces.

### SIEM-1 Enterprise event delivery

- [x] Support TLS with optional CA/client material for syslog.
- [x] Verify syslog optional CA/client TLS material with an in-process mTLS
  collector, including wrong CA, missing/untrusted client certificates and
  plaintext rejection. A Helm-deployed API also passed strict mTLS collector
  delivery and wrong-CA/missing-client rejection; vendor-specific proof remains open.
- [x] Support RFC5424, JSON, and CEF output plus minimum level/category filters.
- [x] Verify a named receiver receives only its routed events and delivery results
  remain visible and auditable.
- [x] Verify named-only delivery, retry/terminal receipts, cross-org and paused
  rejection in PostgreSQL-backed dispatcher tests. Pausing after queueing
  terminates initial and retry jobs without another send. API visibility/audit,
  concurrent pause/send ordering and deployed named SMTP delivery are verified.
- [ ] Verify end-to-end TLS parsing and event routing against a named deployed
  SIEM product; the strict mTLS collector and SMTP receiver are not vendor-SIEM proof.

## P2 — policy-centered operator workflows

### POL-1 Groups as the policy anchor

- [ ] Finish shared GroupPicker use in remaining runtime/file/response editors.
- [ ] Keep referenced-group update/delete conflict detection deny-by-default;
  any future cascade must be explicit and audited.
- [ ] Add an end-to-end group workflow: create, use in network and DLP/WAF,
  inspect usage, promote mode, attempt unsafe delete.

### POL-2 Policy Center completion

- [ ] Add per-family hit counts and last-hit/last-changed/enforcement health.
- [ ] Add reorder controls only where runtime precedence exists, with RBAC and
  audit tests.
- [ ] Add real family-specific import/export actions; do not link placeholders.
- [ ] Show unsupported migration objects and their remediation beside the
  relevant policy family.

### POL-3 Admission, DLP, WAF, and response depth

- [ ] Finish long-tail structured admission criteria that remain unsupported and
  add OpenShift controller coverage where applicable.
- [ ] Preserve DLP pattern context and make user-authored WAF rules reach the WAF
  dataplane table rather than degrading silently.
- [ ] Include enforcing DLP/WAF policy in backup/restore and defined federation
  scope.
- [ ] Add response-policy export/import and wire specific event categories for
  non-threat ingest sources.

## P2 — Astronomer-inspired operator experience

Use the Astronomer console as a design reference for hierarchy, density, and
progressive disclosure, while retaining Constellation's security vocabulary.

### UI-1 Page and navigation contract

- [ ] One canonical home per feature; aliases redirect instead of rendering a
  duplicate surface.
- [ ] Order scope consistently: Organization, Platform, Integrations, Cluster.
- [ ] Resolve remaining duplicate health/settings/token/attestation entry points.
- [ ] Every primary page opens with one verdict, no more than five KPIs, and one
  primary table or workspace.
- [ ] Use tabs for peer views, drawers for editing, and an Advanced disclosure for
  expert-only fields.

### UI-2 Shared enterprise tables

- [ ] Apply visible pagination, server filters, column selection, density,
  refresh controls, saved views, and CSV export to remaining high-volume pages.
- [ ] Add YAML only where a matching import contract exists.
- [ ] Persist operator choices without making saved state hide active filters.
- [ ] Add detail drawers to repetitive triage tables where full-page navigation
  interrupts the workflow.

### UI-3 Platform-component visibility

- [x] Hide known Kubernetes, Constellation, and Astronomer platform namespaces by
  default in container, deployment, and relevant network views.
- [x] Keep collection, detection, policy, and enforcement active while hidden.
- [x] Persist the preference and migrate older `hide_kube_system` saved views.
- [ ] Move classification to backend `platform_role` metadata using namespace,
  labels, and installation identity so custom install namespaces work like
  NeuVector's `platform_role=core`.
- [ ] Expose the same role in APIs and exports; UI namespace matching remains a
  compatibility fallback.

### UI-4 Dashboard and operational posture

- [ ] Reconcile component health, policy modes, threats, vulnerability posture,
  exposed services, admission, scanner DB, and federation counts with their
  source endpoints.
- [ ] Link every tile to the exact filtered source view.
- [ ] Prefer downloadable HTML/CSV/JSON evidence; add PDF only when it materially
  improves a customer workflow.

## P2 — supportability and scale

### OPS-1 Component cockpit and support bundles

- [x] Complete role-alias and diagnostics component tests plus E2E filtering for
  controller, enforcer/runtime-agent, and scanner roles.
- [x] Add API-level heartbeat fixtures for all 15 declared required and optional
  component roles; assert empty, partial and healthy inventories, org/cluster
  rollups and instance scope. Deployed component health remains open.
- [x] Add persisted asynchronous support-bundle jobs with queued/running/ready/
  failed/expired states, redaction tests, download history, and audit links.
- [x] Sign support bundles when a deployment signing key is configured.

### OPS-2 Scale and test matrix

- [ ] Seed large datasets and prove every high-volume page either pages or labels
  its render cap.
- [ ] Add performance budgets for network rollups, findings, audit/timeline, and
  dashboard summaries.
- [ ] Maintain opt-in real-cluster suites for Flannel, Cilium, and Calico plus
  BPF-LSM-capable and non-capable kernels.
- [ ] Keep FIPS, disconnected install, upgrade, backup/restore, and HA smoke in
  the release matrix.

## Cross-cutting — Technology Selection Guide adoption

**Status: not fully implemented; now tracked here rather than assumed covered by
earlier parity checklists.**
The guide is AlphaBravo's organization-wide Go/TypeScript engineering baseline,
not a list of AWS service integrations. This work supplements, rather than
replaces, the enforcement and migration requirements above.

Source reviewed on **2026-09-26**:
[published guide](https://technology-selection-guide.aws.ablabs.io/) and
[full source](https://technology-selection-guide.aws.ablabs.io/llms-full.txt).
The published version contains May 2026 review/version snapshots. The full-source
SHA-256 at review was
`13ec22a5d0dfa4789b91e2e3101bed4d9e19982db444c8c66ad4173159e6ada0`.
Version snapshots are not instructions to downgrade newer dependencies. Verify
compatibility, supported runtime versions, and upstream changes before pinning.

### Reviewed coverage — baseline evidence, not completion claims

| Guide chapter | Current tree evidence | Status / remaining gap | Owner workstream |
|---|---|---|---|
| [00 Introduction](https://technology-selection-guide.aws.ablabs.io/00-introduction/) | This plan now identifies the source and review snapshot. | Partial: per-requirement applicability, conformance evidence, deviations and quarterly review process remain open. Guide-authoring requirements need applicability decisions, not indiscriminate copying. | TSG-1 |
| [01 Architecture](https://technology-selection-guide.aws.ablabs.io/01-architecture/) | Go binaries under `cmd/`, internal packages, constructors, and an operator exist. | Partial: SQL remains in handlers, downstream packages read env, substantial implementation resides in `pkg/`; audit layer boundaries, mutable globals, composition roots and operator serialization. | TSG-2 |
| [02 Data](https://technology-selection-guide.aws.ablabs.io/02-data/) | PostgreSQL, pgx/v5, Goose SQL migrations, tenant columns and encrypted credentials exist. | Partial: no sqlc query/generated-accessor setup found; migrations use the external Goose image, not an embedded runner; encryption key-version metadata, soft-delete applicability, JSONB contracts and cross-tenant FK enforcement need review. | TSG-2, TSG-3 |
| [03 Surface](https://technology-selection-guide.aws.ablabs.io/03-surface/) | chi REST API, OpenAPI, JWT/RBAC middleware and React/TypeScript SPA exist. Browser cookies, refresh/reuse revocation and a 15-minute access-token cap have API/UI/container-browser regressions. The endpoint-map checker gates explicit API references against OpenAPI/registered routes in CI. | Partial: no Connect/protobuf contract pipeline found; Axios DTOs are hand-maintained, pagination varies, wildcard map references do not prove complete families, and deployed identity/API conformance remains open. | TSG-3, TSG-5 |
| [04 Infrastructure/tooling](https://technology-selection-guide.aws.ablabs.io/04-infra-tooling/) | Makefile, Vite API proxy, multi-stage Dockerfiles, Helm and k3s exist. A golangci-lint v2 config and failing-on-error lint/format, tool installation, runtime pins and shell checks are wired to CI. | Partial: baseline lint/format/ShellCheck findings still block release; no Air development-loop contract has been verified; runtime images contain Debian/package managers and mutable base tags, and deployed toolchain/reproducibility evidence is open. | TSG-4 |
| [05 Observability](https://technology-selection-guide.aws.ablabs.io/05-observability/) | Shared telemetry package, JSON slog, OTLP/HTTP and a separate Prometheus registry exist. | Partial: differs from prescribed zerolog/stderr, OTLP/gRPC and OTel Prometheus exporter; pgx pool has no composite tracer configured; prove propagation, cardinality, shutdown and full local telemetry stack. | TSG-6 |
| [06 Security](https://technology-selection-guide.aws.ablabs.io/06-security/) | jwt/v5, RBAC, audit chain, credential sealing, FIPS-related build paths and release signing exist. Cookie/refresh/reuse controls and blocking per-PR security/secret/dependency gates have been added. | Partial: baseline scan findings, hosted gate enforcement, key rotation metadata/job, threat model and complete deployed identity verification remain open. Source/gate presence does not mean guide compliance. | TSG-3, TSG-4 |
| [07 Testing](https://technology-selection-guide.aws.ablabs.io/07-testing/) | Go/Vitest/Playwright tests, disposable PostgreSQL repeat/race/JUnit gate and production-container browser gate pass locally. Playwright browser auth coverage uses zero PR retries. | Partial: most DB tests lack integration tags and share a DB; no pgtestdb/testcontainers harness found. Seed-dependent skips, CNI/kernel/cloud matrix, hosted CI evidence, and full isolated integration contracts remain open. | TSG-4 |
| [08 Discipline](https://technology-selection-guide.aws.ablabs.io/08-discipline/) | Canonical evidence-driven plan and real DB tests provide a foundation. | Partial: codify ADR/deviation review, root-cause and transport-boundary testing, layer/enum discipline, offline-first acceptance and contributor commands. | TSG-1, TSG-2, TSG-7 |
| [09 Air-gap](https://technology-selection-guide.aws.ablabs.io/09-airgap/) | Scanner DB preload/airgap image support and signed release artifacts exist. | Partial: complete signed offline deployment BOM/loader, local-first OCI resolver, closed-egress first boot and all-feature upgrade/restore proof are not established; release images are deliberately amd64-only versus the guide's dual-architecture requirement. | TSG-7 |
| [10 TypeScript](https://technology-selection-guide.aws.ablabs.io/10-typescript/) | React 19, strict TypeScript, Vite, Tailwind 4, Radix, TanStack Query, lucide, Vitest and Playwright exist. Node is pinned and browser auth/session regressions pass locally. | Partial: no Connect-Web/Zod/react-hook-form stack found; routing uses component auth rather than a root data-loader session contract. Mutation invalidation, inline field errors and version-review obligations need broader acceptance tests. | TSG-5 |
| [11 Multi-language](https://technology-selection-guide.aws.ablabs.io/11-multi-language/) | Go/TypeScript, native/eBPF runtime code, Python test tooling, shell and Helm coexist. Go/Node/Python CI runtimes are pinned, npm lockfiles are audited, and ShellCheck is a blocking gate. | Partial: language ADRs/ownership, native exceptions, ShellCheck baseline findings, Python type/lint coverage, per-language SBOM/signing and cross-language telemetry remain open. | TSG-1, TSG-4, TSG-7 |

### TSG-1 Requirement inventory and deliberate adoption

- [ ] Expand each chapter into stable, chapter/section-linked control IDs for
  every applicable MUST/MUST NOT and SHOULD/SHOULD NOT; record MAY decisions and
  not-applicable requirements with rationale. The chapter matrix is a starting
  review, not an assertion that every individual requirement has been tested.
- [ ] For each control record status (`open`, `implemented/unverified`,
  `verified`, `approved-deviation`, or `not-applicable`), repository evidence,
  positive/failure tests, owner, acceptance command and live evidence where
  required. Only `verified` closes a strict-conformance requirement.
- [ ] Record ADRs for existing REST versus Connect, SQL migration strategy,
  logging/transport choices, privileged/native dataplane images, amd64-only
  release support and any other retained departures; deviations need explicit
  approval, rationale, residual risk, compensating controls and a review date.
- [ ] Resolve guide inconsistencies explicitly: chapters 03/06 disallow browser
  localStorage tokens, while chapter 10 tolerates a transition; use the stronger
  security requirement as the target. Reconcile dated version/router/Helm advice
  rather than treating snapshot predictions as current upstream facts.
- [ ] Establish quarterly source/version/applicability review and a CI evidence
  report; no "fully guide-compliant" release claim while applicable controls
  remain open or mandatory deviations are presented as compliance.

### TSG-2 Architecture and data boundaries — P1

- [ ] Inventory each domain and binary; enforce composition-root configuration
  and dependency construction, handler/service/query boundaries, legitimate
  public `pkg/` APIs, and absence of shared mutable runtime state.
- [ ] Introduce annotated SQL/sqlc generation and checked-in typed accessors;
  migrate hand-written domain/handler SQL with tenant-scoped regression tests,
  or obtain an explicit reviewed migration/deviation decision.
- [ ] Implement or approve the embedded Goose runner contract, advisory-lock
  concurrency, migration-before-serving and failure-before-readiness tests.
- [ ] Audit JSONB validation/schema evolution, user-data soft-delete and purge
  semantics, scope-preserving imports, and schema-level cross-tenant references.
- [ ] Verify per-resource operator serialization and leader-election behavior;
  assess Crossplane/Helm recommendations for applicability without replacing a
  functioning security operator solely to match a reference implementation.

### TSG-3 Identity, secrets and API security — P0

Implementation and cutover contract: [browser sessions](browser-sessions.md).
The implemented cookie/refresh slice does not close the broader identity, key
custody, threat-model or external-provider release matrix.

- [x] Replace browser localStorage access tokens with HttpOnly/Secure/SameSite
  cookies, short-lived access tokens, rotating refresh tokens and reuse-triggered
  session revocation; preserve bearer auth for CLI/agents with explicit precedence.
- [ ] Add CSRF, XSS/token exposure, concurrent refresh, expiration, logout,
  password/role-change revocation, cross-org and namespace-scope tests across
  browser, API and CLI paths. Coordinate this cutover with IAM-1 and API-1.
- [ ] Prove secret-bearing columns use installation-external key custody,
  versioned key/algorithm metadata, a resumable rotation job and old-key-retirement
  verification. Cover backup/restore and unknown-key/algorithm fail paths.
- [ ] Publish a threat model and enforce centralized authentication/authorization,
  audited denies, bounded requests, typed/redacted client errors and protected
  metrics/admin surfaces; remove internal SQL/secrets from error responses.

### TSG-4 Build, CI, development and test contracts — P0/P1

- [ ] Add blocking per-PR gosec, govulncheck/SARIF, full-history secret scanning,
  per-language dependency scanning, dependency update automation and documented
  remediation/suppression SLAs. Release signing alone does not satisfy this.
- [ ] Make lint fail on missing tooling or findings; configure the guide's
  golangci-lint v2 baseline, format verification, shellcheck and applicable
  Python type/lint/lock/audit checks, with reviewed exceptions.
- [ ] Pin Node and every supported language/runtime, align CI/Dockerfiles with
  source-of-truth versions, use immutable production image references, and
  supply required OCI labels plus qualified nonroot/minimal runtime images.
- [ ] Complete canonical Makefile/dev orchestration and per-binary Air configs,
  generated-directory exclusions, shutdown/error handling and reproducible
  environment/bootstrap behavior.
- [ ] Separate unit and DB integration suites with build tags, introduce isolated
  real-backend fixtures, run races without result caching, emit/upload JUnit,
  and prove repeated/shuffled execution without shared-fixture leakage.
- [ ] Run Playwright through production-serving paths with setup-project auth
  state, zero PR retries, configurable base URL and retained failure artifacts;
  wire browser tests and distinct FIPS builds/status checks into CI.

### TSG-5 Typed API and frontend conventions — P1/P2

- [ ] Decide and implement the Connect/protobuf migration boundary (or explicitly
  approve retaining REST/OpenAPI); generate server/client types and categorical
  enums from one contract and gate request/response compatibility in CI.
- [ ] Standardize bounded opaque pagination, route-level error handling and
  session-aware data loaders while preserving API-1's migration/runbook contracts.
- [ ] Adopt schema-driven Zod/react-hook-form validation with inline field errors,
  consistent TanStack query keys/invalidation and deduplicated refresh; migrate
  forms/workspaces incrementally with component and browser tests.
- [ ] Verify React Router Data Mode, accessible Radix-based primitives, static
  production builds, API/WebSocket dev proxies, version stamps and Node/tooling
  pins against the guide, with ADRs for deliberate alternatives.

### TSG-6 Unified telemetry — P1

- [ ] Resolve and implement/approve logger, stderr, OTLP transport and metric
  exporter choices; ensure every long-lived binary participates in the same
  structured logs/metrics/traces and resource identity model.
- [ ] Wire composite pgx query tracing, request/correlation/trace propagation,
  explicit histogram buckets and bounded label cardinality; verify actual emitted
  spans/logs/metrics, not just initialization/configuration.
- [ ] Provision the complete local Prometheus/Tempo/Loki/Grafana stack and prove
  collector-unavailable behavior, bounded queues, partial-init cleanup and
  graceful shutdown without making telemetry a startup dependency.

### TSG-7 Offline and multi-language delivery — P1/release gate

- [ ] Produce a complete signed deployment BOM including charts, all role and
  helper images, scanner databases, tools, language dependencies and trust roots;
  verify trust before extraction and reject missing/invalid/expired signatures.
- [ ] Implement local-first OCI resolution with explicit authenticated fallbacks,
  no implicit public-registry fallback, startup egress inventory and provenance
  logs; document optional connected-only external integrations honestly.
- [ ] Validate local S3-compatible storage, endpoint discovery/caching/overrides,
  external-endpoint presigning and idempotent initialization where applicable.
- [ ] Test first boot, core workflows, scan/DB updates, upgrade and backup/restore
  with out-of-cluster egress blocked. Merely preloading a scanner DB is insufficient.
- [ ] Qualify amd64 and arm64 artifacts, or approve/document an explicit native
  dataplane architecture deviation. Track native/eBPF/Python/shell/Helm support,
  ownership, locks, SBOMs, signing and telemetry parity in the same release matrix.

## Intentional differences and non-goals

- CNI-native NetworkPolicy/CiliumNetworkPolicy/Calico policy is the primary L3/L4
  enforcement model; NeuVector's risky veth port-pair interception is not copied.
- L7 inline WAF/DLP enforcement remains limited to iptables-class CNIs until a
  safe TC-BPF verdict implementation exists.
- Server TLS material and other security-sensitive bootstrap trust may remain
  Secret/env driven and restart-bound; this is not a runtime-config parity gap.
- Constellation OSS does not need NeuVector license-management screens.
- Do not reproduce an NV object model when Constellation has a safer or richer
  enforced model; migration should translate and retain provenance.
- A dedicated PDF renderer is not a parity gate when signed JSON/SARIF/HTML/CSV
  evidence satisfies the workflow.

## Delivery order

1. Close P0 correctness, tenant-scope, and fail-path blockers.
   Include TSG-3 security gaps and TSG-4's blocking security/test gates; perform
   TSG-1's applicability/deviation inventory before claiming guide conformance.
2. Finish the canonical migration fixture and safe import families.
3. Close enforcement/live-cluster validation gaps.
4. Complete effective-config and identity-provider cutover workflows.
5. Finish Policy Center and shared table/navigation consistency.
6. Run the full fixture, CNI, HA, backup/restore, FIPS, and UI release gate.
   Include TSG-2/5/6 implementation evidence and TSG-7's disconnected-delivery
   gate; report guide deviations separately from verified controls.

Independent work may run in parallel, but a dependent workflow is not complete
until the end-to-end acceptance evidence exists.

## Required evidence per merged slice

- Focused unit/component tests.
- Handler/API tests including RBAC, scope, redaction, and audit assertions.
- OpenAPI and documentation updates for contract changes.
- Browser/E2E coverage for the operator workflow.
- `git diff --check`, frontend type-check/build, relevant Go tests, Helm lint and
  rendered-manifest smoke where charts changed.
- Live deployment validation for agent, enforcement, CNI, migration, or chart
  changes.

## Supporting evidence — not active plans

- [NeuVector endpoint mapping](NEUVECTOR-ENDPOINT-MAPPING-2026-08.md)
- [NeuVector capability audit](neuvector-capability-audit.md)
- [Visual and API assessment](nv-vs-constellation-assessment.md)
- [Current deficiency audit](deficiency-audit.md)
- [Network enforcement decision](network-enforcement-model.md)
- [Architecture](architecture.md)

When those documents disagree with the current tree or this plan, verify the
code and update this plan. Do not add status checklists to the evidence files.
