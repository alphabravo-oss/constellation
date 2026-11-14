# Working plan

**Only current working plan. Reconciled 2026-11-14.**

Product assessment baseline: **2026-10-26** against main
[`4aa704a035eaf149eab2ffe55e20e9651956f372`](https://github.com/alphabravo-oss/constellation/commit/4aa704a035eaf149eab2ffe55e20e9651956f372).
This file owns the complete current work queue, including DB-01–23, the 154
historical acceptance entries, hardware qualification, UI follow-ups and release
work. [Architecture decisions](docs/decisions/) govern implementation. Supporting
documents describe contracts and dated evidence; they are not separate plans.
The [archive index](docs/archive/plans/README.md) preserves superseded plans and
links earlier plans already removed from the tree.

On November 14, local main and GitHub main both pointed to `de4ca4090`, the merge
of the October 26 plan update; no subsequent product implementation had landed.
The current consolidation also qualifies pending dependency updates. Repository
synchronization is distinct from deployed qualification. The October test and
live-database observations below retain their original dates.

Update this file whenever a requirement changes state. Give new work a stable ID
under its owning milestone; do not start another backlog, roadmap or todo file.
Archive superseded proposals before replacing their requirements here. Existing
archives must never be treated as instructions to restore retired architecture.

**Assessment:** Constellation is a substantial pre-release security platform with
credible local correctness evidence. Full NeuVector replacement, production
readiness, and superior security, detection accuracy or performance are unproved.
Feature presence, a version number, or a passing unit suite does not establish
those claims. There is no defensible overall completion percentage yet.

## Scope and standing constraints

- Keep **GitHub Actions disabled**. Continue code and local verification only.
  Release publishing, live rollout and live notification qualification remain
  deferred. Off-host recovery and real node-failure testing also remain deferred.
  These are recorded boundaries, not requests to enable workflows or deploy.
- Preserve audit evidence, open findings, referenced scans and recoverable backup
  copies under the [retention decisions](docs/storage-retention-policy.md). No additional
  legal period, legal hold or RPO/RTO target has been supplied. Measure recovery
  performance before proposing service objectives; do not invent an agreed target.
- Follow [ADR 0002](docs/decisions/0002-adopt-guide-stack.md): domain layers, sqlc,
  incremental Connect-RPC/generated clients, react-hook-form/Zod and TanStack
  Router. The retired REST/TanStack Form convergence programme is not reinstated.
- [ADR 0007](docs/decisions/0007-helm-only-deployment.md) controls deployment;
  [ADR 0010](docs/decisions/0010-oidc-relying-party.md) and its local-account successor
  [ADR 0011](docs/decisions/0011-local-accounts.md) control identity. Native LDAP/SAML
  providers are an intentional difference, not a task to restore removed code.

The old `NEUVECTOR-PARITY-PLAN.md` was removed on October 20 during the approved
realignment. Its [last retained version](https://github.com/alphabravo-oss/constellation/blob/388ad8ce861989e4604d1649a27499dc74b8af7c/docs/NEUVECTOR-PARITY-PLAN.md)
contains **66 checked and 88 unchecked entries**. Those are historical counts:
subsequent work completed some requirements, while ADRs superseded others.
The family crosswalk and item inventory below preserve all 154 entries without
restoring obsolete implementation choices. Inventory consolidation is complete;
current evidence revalidation remains M1-01. Historical checkmarks are not fresh
acceptance evidence.

## How progress is counted

| State | Meaning |
| --- | --- |
| Verified, bounded | The named contract passed with recorded source, environment and limits. It does not close its entire parent milestone. |
| Implemented / unverified | Source exists, but the full acceptance criterion lacks current qualifying evidence. |
| Open | Required implementation, investigation or acceptance work remains. |
| Intentional difference | A current ADR or explicit support boundary changes the old requirement. Record the customer impact and migration path. |
| Deferred | The required operational test is outside the current authorized scope. It remains a readiness condition. |
| Blocked | A concrete dependency prevents qualification; record the reason and exit condition without weakening checks. |

Use the stable milestone and subitem IDs below in implementation handoffs. Each
closure must identify source commit, test/profile, positive and failure outcomes,
artifact location, remaining limits and any deferred operational portion. A
milestone closes only when all its applicable criteria are satisfied. Changing a
criterion requires a recorded decision, not a silently removed checkbox.

An implementation batch of ten fixes is **not ten original requirements closed**.
Report bounded results and remaining parent criteria separately. Do not add
overlapping test suites into a unique-test total or count opt-in skips as passes.

## Evidence baseline and limits

| Area | Established evidence | Remaining acceptance boundary |
| --- | --- | --- |
| Historical high-severity defects | [H1–H12](docs/archive/plans/2026-10-23-security-backlog.md) are recorded fixed, including closure by removal/replacement where applicable; most were reverified October 23. | This is closure of a historical list, not a complete vulnerability assessment. Fresh source/dependency/image security qualification remains M5-01. |
| Local code quality | PR #52's final `make check` reported 3,278 tests, 9 skipped; integration reported 5,186 tests, 19 skipped. Lint, vet, formatting, shell and frontend type/build checks passed. | Suites overlap. Native, real-kernel, provider, real-tool and load opt-ins need their own receipts. No fresh security, browser or live acceptance run was performed for this assessment. |
| Frontend | The October 26 assessment run passed 159 files / 2,440 tests. | It emitted 19,820 environment-`act` warnings and 42,277 unwrapped-`act` warnings. These are repeated messages, not 62,097 distinct defects; eliminate the warning causes and qualify real operator flows under M5-02. |
| Scanning | [Scanner evidence](docs/scanner-evidence.md), [job leases](docs/scan-job-leases.md), scoped private-registry credentials and [offline matching](docs/offline-scanning.md) have bounded proofs. Trivy/Grype matched real packages across two network-isolated starts. | Engine count and finding count do not prove accuracy. Complete provider/format coverage, matched-data false-positive/false-negative comparisons, and a full disconnected lifecycle remain open. |
| Runtime and network | Process/file controls, native DP policy distribution, CNI-native policy and scoped Cilium/Calico traffic proofs exist; see [enforcement model](docs/network-enforcement-model.md) and dated [security evidence](docs/security-testing.md). | Configuration must be traced to actual verdict/action, acknowledgement and audit under failure and restart. Cilium inline WAF/DLP is unavailable in this design. No blanket CNI/kernel/platform qualification follows. |
| Evidence and retention | Signed audit, inventory, Kubernetes-audit and runtime-threat exports have independent verification/recovery proofs; The DB-01–23 register below records precise progress. | Scheduled archives, dependencies, immutable remote copies, hold-aware expiry and trusted hot/cold query anchors remain incomplete. The historical audit chain break at row 53 remains unresolved. |
| Delivery | [Event/flow spools and receipt transactions](docs/telemetry-delivery.md) provide bounded raw-data replay protection. | Response callbacks, notifications and other effects lack a transactional delivery outbox. DPI/inventory/session lanes retain best-effort behavior; node/disk loss can destroy unacknowledged local evidence. |
| Efficiency | [Query budgets](docs/efficiency.md) cover 25 hot handlers with 10,000-row fixtures and a 250,000-byte gzip entry budget. Local flow, session and feed qualifications exercised 110,000, 400,000 and 394,803 rows respectively. | These are workload-specific results, not fleet SLOs. The May performance baseline and [scale guide](docs/archive/plans/scale-hardening.md) do not establish production capacity or superiority over NeuVector. |
| Deployment and recovery | The last recorded live database observation, October 23, was one healthy CNPG instance at migration 190 with successful WAL archiving and a completed scheduled backup. | The reviewed source requires migration 198. The live state was not rechecked for this assessment. One instance is not HA, and local recovery is not off-host or node-loss qualification. Actions remained disabled on October 26. |

The three local logs for the first code/frontend rows are retained under
`/root/constellation-next10-20261026/`. They are workstation evidence, not
published release artifacts:

| Log | SHA-256 |
| --- | --- |
| `check-final.log` | `89d8948c0a1c033ecc79baa39ab13b3de1a2b96d9b0cf42018846e31af7d3004` |
| `integration-final.log` | `c34da71f283ca9de44f8272cc2f42ac1d7b8932e608c2be459df271e96e3daf4` |
| `assessment-frontend.log` | `227fbece98ce10a58a66cfe4b6a109e182aba4f9f04f5e5587b89cc06c7c7bde` |

`make check` does **not** include the frontend unit suite, security scans or
browser/live acceptance. [CLAUDE.md](CLAUDE.md) and the [Makefile](Makefile)
define current commands; older entries in the security log may refer to retired
tooling. Preserve those entries as history, not instructions for a new run.

## November 14 consolidation and local qualification

The integration includes dependency PRs **#54, #57, #59–64 and #69–71**, the
TanStack Table 9 wrapper migration, a server-confirmed lock-timeout regression
fix, and the Go 1.27.4 / follow-redirects 1.16.3 security patches. The code baseline
is [`382263946615d73af7a9ca30812f8bc67c21a3ec`](https://github.com/alphabravo-oss/constellation/commit/382263946615d73af7a9ca30812f8bc67c21a3ec);
the remaining consolidation changes are documentation. PR #58 is excluded for
M5-06's compiler/parser incompatibility. Eight superseded documents retain their
original bodies in the archive, and all thirteen earlier source snapshots were
verified in Git history.

Qualification receipts are in
`/root/constellation-consolidation-20261114/`. The October evidence above is
historical; this section records the November run separately.

| Local check | November result |
| --- | --- |
| `make check` | Passed: Go lint/vet/format/shell, frontend lint/type/build and 3,278 Go tests with 9 opt-in skips. Frontend warnings remain below. |
| `make test-integration` | Passed: 5,186 tests, 19 opt-in skips, disposable PostgreSQL, race detection and shuffled execution. The migration lock/repair tests also passed 15 repetitions with the race detector. |
| Frontend | Passed: 159 files / 2,440 tests with `npm test -- --maxWorkers=2`, without raising timeouts or suppressing diagnostics. Production build passed; initial JavaScript is 232,251 gzip bytes against a 250,000-byte gate. |
| Dependencies | Production npm audit: zero advisories. Root-module govulncheck: zero called/imported vulnerabilities, with the module-only finding below. |
| Images/workflows/chart | Scanner-tools image built locally; all five actual binaries report Go 1.27.4 and pass their version smoke checks. Actionlint, pinned action-input checks, Helm lint and chart/PromQL smoke checks passed. This is not qualification of every release image. |
| Planning | 149 local Markdown links/anchors, all stable inventory IDs, eight preserved archive bodies and thirteen immutable historical references verified. `PLAN.md` is the only active plan file. |

Receipt SHA-256 values (files in the directory above):

| Receipt | SHA-256 |
| --- | --- |
| `check-fixed.log` | `bddcea99d6f2cb7c5920dfa900e5392840464f18673d35aa47826840b2ce77a7` |
| `integration-fixed.log` | `4d41da7efb21d4dd11270b0ea92effbcd85d7025361e5552a141c97f7f60cdd1` |
| `frontend-final.log` | `ef5173b87ce3c24ef6bcb0a01a638b597929140d0e5105888ed5289cac2e2298` |
| `govulncheck-fixed.log` | `b5ae54ddcfa4cb39e85f84ad2d9e43556bd817c480eaab2a71bab63bfc29353b` |
| `npm-audit-prod-fixed.json` | `85edd759c9ad715f5c20413cb15817da038064ce6ce107a0f62be1e7acde37bc` |
| `scanner-tools-build-fixed.log` | `52d05bb6e4a5e2f6b400591d1984d49d070b3d61bbee8c7f4b2515192530b5ba` |
| `scanner-tools-go-floor.log` | `e2a5378c8aadf3669c0217b3ac485bead3655ebc0c5056f5b10a797d0e828d1a` |

Remaining security findings are explicit M5-01 work: the full npm audit reports
one development-only [minimatch advisory](https://github.com/advisories/GHSA-g3hv-75wg-m249)
across eight dependency entries. npm proposes an incompatible parser/plugin
downgrade for part of that graph; do not force it or suppress the finding.
Go scanning also records [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)
at module level in `golang.org/x/crypto v0.58.0`; the affected OpenPGP package is
not imported or called by this root module. Review/update these dependencies
under the supported toolchain and include bundled-tool graphs in release scans.

The full frontend run during concurrent cold Go/image compilation had 18 timing
or settling failures. Retain that failed receipt (`frontend-full-fixed.log`);
M5-02 still owns load-sensitive waits, React `act` diagnostics and 129 Fast Refresh
lint warnings. A passing bounded-concurrency run does not close those issues.
No new browser, native/kernel, fleet, signed-release, live alert, off-host or
node-loss evidence is claimed. Actions remains disabled. Previously published
CNPG/Barman images still use Go 1.27.3 and must be rebuilt and qualified before
any future rollout; their existing digest pins were not relabeled.

## Remaining milestones

All five parent milestones are **open**. Work within the current scope can
progress while operational portions stay deferred. Accountable roles below are
review responsibilities, not a claim that an individual has been assigned.

### M1 — Reconcile requirements and supported product scope

Review responsibility: product, architecture and security maintainers.

| ID | State | Completion criterion |
| --- | --- | --- |
| M1-01 | Open | Finish current-source evidence revalidation for NV-001–154 below. The inventory and current milestone mapping are complete; each remaining revalidation needs a source/test receipt or an explicit superseding decision with customer impact. Reconcile Technology Selection Guide controls against current ADRs. Do not infer verification from historical checkmarks. |
| M1-02 | Open | Planning consolidation is complete. Finish reconciling README, architecture, deployment, integrations, security, FIPS, scale and performance instructions against current source. Remove retired VulnDB/production-compose claims, obsolete commands and unsupported superiority/capacity claims. Preserve dated evidence and link the current contract. |
| M1-03 | Open | Publish one supported profile: Kubernetes/CNI/kernel/architecture, policy families, identity modes, scanner tools, storage topology, federation scope and known exclusions. Distinguish supported behavior from experimental paths and design targets. |

**Exit:** every original requirement has an explicit disposition and the supported
profile has consistent operator-facing documentation. An intentional difference
does not silently count as feature parity; its migration impact remains in M4.

### M2 — Prove complete security workflows

Review responsibility: runtime, policy, identity and scanner maintainers.

| ID | State | Completion criterion |
| --- | --- | --- |
| M2-01 | Implemented / unverified | Inventory advertised controls and prove configure → distribute → enforce/act → outcome → audit. Cover admission, process/file/exec, quarantine/kill, DLP/WAF, response actions and group/policy changes, including negative tenant/cluster/namespace scope, unavailable consumers, retries and restarts. Reject unsupported options explicitly. |
| M2-02 | Implemented / unverified; live portion deferred | Prove actual packets, processes and file operations for each supported CNI/kernel profile, including policy precedence, attribution, process identity, baseline recovery and action acknowledgement. Keep Cilium CNI-native results separate from inline DP results. Real-cluster matrices remain deferred; existing local/native harnesses can continue. |
| M2-03 | Open | Build a versioned, labeled scanning corpus with matched image/package data and feed timestamps. Measure false positives, false negatives, unsupported formats, failure reporting and resource use. A NeuVector accuracy/performance comparison must run both products under comparable conditions. |
| M2-04 | Implemented / unverified; live portion deferred | Prove on-demand/scheduled benchmark execution, two-cluster isolation, report provenance and external event routing. Include dependency failures, attempt leases, duplicate reports and receiver errors. Live IdP/cloud/registry/SIEM delivery qualification is separate from local parser/fixture tests. |
| M2-05 | Open | Complete the ADR 0002 domain-by-domain contract work and security proof: generated API/client contracts, configuration provenance/revision/consumer acknowledgement, centralized authorization, secret lifecycle and current local/OIDC/RBAC behavior. Inventory what is already done before implementation; retain a proof for each migrated domain. |
| M2-06 | Open | Review the vendored native engine against current upstream releases/advisories; record relevant changes, local patches and maintenance ownership, then run native regressions for adopted changes. Meet [ADR 0003](docs/decisions/0003-vendored-neuvector-dataplane.md)'s quarterly review/re-vendoring obligation. An older vendor date alone is not evidence of a specific vulnerability. |

**Exit:** each supported security control has a reproducible positive effect and
a defined, tested failure outcome. Unsupported controls are visible as such.
Any outstanding live-profile proof keeps that profile unqualified.

### M3 — Make evidence and response delivery recoverable

Review responsibility: storage, runtime delivery and audit maintainers.

| ID | State | Completion criterion |
| --- | --- | --- |
| M3-01 | Open | Persist required response work atomically with the originating event, with bounded retries, idempotency keys, status and recovery tests for crash-after-commit and ambiguous external success. Inventory other best-effort lanes and specify each loss boundary. Do not promise exactly-once external effects. |
| M3-02 | Open; bounded exports verified | Complete the remaining DB-01–23 code/local criteria: scheduled signed archives, findings/attestation/case/forensics dependency recovery, bounded hold-aware retention, trusted query anchors and capacity/lag signals. Preserve existing evidence/reference/copy-floor protections. Detailed status stays in the DB register below; this plan does not declare the 23 items closed. |
| M3-03 | Open | Record a defensible disposition of the pre-existing row-53 audit discontinuity: affected range, preserved original hashes, trusted verification boundaries and operator-visible limitations. Do not rewrite hashes or bypass verification to obtain a passing chain result. Qualify archives that span the discontinuity. |
| M3-04 | Implemented / unverified; off-host and node-failure portions deferred | Restore current recovery points into an isolated destination and verify data, encrypted credentials and dependencies. Measure RPO/RTO and test failure signals. Independently qualify immutable remote retention, off-host recovery and separate-node availability only if those deferred activities are resumed. |

**Exit:** supported evidence classes can be independently recovered and verified,
response work has an explicit recoverable delivery contract, and DB-01–23 meet
their applicable acceptance criteria. Deferred tests remain unsatisfied criteria.
A local implementation milestone may be recorded separately; it cannot be called
operational completion.

### M4 — Prove a realistic NeuVector cutover

Review responsibility: migration, policy and identity maintainers.

| ID | State | Completion criterion |
| --- | --- | --- |
| M4-01 | Implemented / unverified | Use a representative full export, with a manifest accounting for every source object as converted, unsupported, rejected or deliberately omitted. Cover groups, network, process/file, admission, DLP/WAF, vulnerability profiles, registries and long-tail policy semantics. Existing small fixtures do not establish customer cutover completeness. |
| M4-02 | Open | Supply tested remediation for users/roles/mappings, compliance, routing, authentication, credentials and federation objects currently reported unsupported by the importer. Reissue secrets; define manual or broker-mediated identity migration under ADRs 0010/0011. Do not silently discard unsupported objects or reintroduce retired native IdPs. |
| M4-03 | Implemented / unverified | Exercise preview/dry-run/apply/history/rollback through API, CLI and browser in a fresh organization and cluster. Verify effective enforcement, group references, counters and audit after import, then verify rollback. Define federation family coverage, precedence, conflicts and tombstones rather than inferring completeness from membership APIs. |

**Exit:** a documented supported customer configuration can move across with an
accounted-for policy/identity delta, equivalent promised behavior and a tested
recovery/cutover rollback procedure. Forward-only schema migrations remain in
force; policy rollback is not a database `Down` migration.

### M5 — Qualify one release profile

Review responsibility: release, frontend, security and operations maintainers.

| ID | State | Completion criterion |
| --- | --- | --- |
| M5-01 | Open; hosted/release portion deferred | Run current lint/unit/integration/frontend/native/security gates on a recorded source revision. Scan exact image digests and dependencies, preserve findings and resolve release blockers. Review the November 14 development-only minimatch advisory and non-imported OpenPGP module advisory below. Rebuild and qualify every eventual release/helper image at the Go 1.27.4 floor, including CNPG/Barman, then update signed digest references. Verify source-bound provenance/signatures. Local green checks are not hosted CI or signed-release evidence. |
| M5-02 | Open | Fix frontend asynchronous-test/environment warnings, load-sensitive waits and the remaining Fast Refresh lint warnings without blanket suppression. Define a reproducible worker budget, then run the full suite with a clean diagnostic contract. Verify production-serving browser flows and accessibility for migration, identity, policy, scanning, evidence and recovery. Earlier browser receipts do not qualify the new source automatically. |
| M5-03 | Open; fleet portion deferred | Measure supported load, p95/p99 latency, CPU/memory, database growth, ingest lag/backpressure and recovery under concurrent readers/writers. Retain the 24-hour fleet soak and failure matrix. Define capacity from measurements; 100 clusters / 10,000 nodes / 100M findings is a design target. |
| M5-04 | Open; live portion deferred | Qualify disconnected first boot, core workflows, feed/tool updates, upgrade and full restore with closed egress; qualify each claimed CPU architecture. Go FIPS build/runtime guards do not establish whole-product certification or deployed compliance. |
| M5-05 | Deferred | After an explicit change to the current operating scope, qualify the signed release on the supported deployment profile, including alert delivery, failover, off-host recovery and real node loss. Keep Actions disabled and make no live rollout in the current scope. |
| M5-06 | Blocked on upstream tooling | Upgrade TypeScript only when the supported ESLint/parser toolchain accepts the compiler version, then pass installation, lint, type/build and full frontend regression gates. [PR #58](https://github.com/alphabravo-oss/constellation/pull/58) proposes TypeScript 7.0.2; on November 14 the latest `@typescript-eslint/parser` and plugin (8.72.2) declare TypeScript `>=4.8.4 <6.1.0`. Keep 6.0.3; do not override peer constraints or merge an unsupported compiler. |

**Exit:** a specific version, image set and supported profile have complete
release evidence and stated limitations. Local completion alone does not close
M5 or establish production readiness while M5-05 remains deferred.


## Storage and retention work

These are the current DB-01–23 statuses, consolidated from the October 26 backlog.
DB-06 and DB-20 are completed decisions, not closure of the surrounding lifecycle
requirements. Deployment portions remain deferred under the standing constraint.
The [retention policy](docs/storage-retention-policy.md) is the current policy;
archived recommendations to suppress audit receipts are superseded by DB-06.

| ID | State | Required outcome / implementation evidence | Remaining acceptance criterion |
| --- | --- | --- | --- |
| DB-01 | **Implemented; live rollout open** | Replace `ctid`-only DELETEs from partitioned `events` and `network_flows` (`internal/handler/events_retention.go`, `internal/handler/network/rollup.go`). `ctid` is only unique within a child; a disposable PostgreSQL reproduction selected one expired row and deleted it **and a current row** with the same `ctid` in another partition. | Partitioned two-child test proves an expired row is removed and a current row survives; deploy the fix before relying on pruning. Treat historical event/flow completeness as unverified. |
| DB-02 | **Implemented/local concurrency qualified; live gates deferred** | Refresh failure and watermark lag block raw expiry; late arrivals and refolding share the retention lock/boundary contract. The original prune-after-failure and age-only drop defects are fixed. | Failure/lag regressions and the 110,000-flow partitioned concurrency fixture preserve counts and bytes. Live fold-lag notification remains deferred; historical loss is not repaired. |
| DB-03 | **Implemented/tested; release acceptance deferred** | Fresh-install defaults and seeding now set reviewed nonzero retention. Existing operator choices, including explicit zero holds, remain unchanged. | Fresh/migrated configuration tests pass. Live 3/7/7 policies were preserved; release acceptance remains deferred. |
| DB-04 | **Conservative shared policy implemented; deployment deferred** | Shared retention uses the longest organization window and any zero holds cleanup. The original earliest-org shortcut is superseded. | Config, partition/row maintenance and tenant tests enforce the shared policy; deployment remains deferred. |
| DB-05 | **Local archive recovery/migrations qualified; off-host/failure gates deferred** | A fresh isolated CNPG restore from the local object-store archive reached database readiness in 10m17s; migrations 190–194 preserved recorded counts. Temporary resources were removed. | This is database readiness, not application RTO or marker-based RPO. Off-host recovery, real node failure and live failure notification remain deferred; the pre-existing audit break survived unchanged. |
| DB-06 | **Decision complete: retain all permanent receipts** | Runtime detection and scan completion receipts remain in the append-only audit chain with existing consumers. No suppression or stream migration is authorized by this retention policy. | The [classification decision](docs/storage-retention-policy.md) preserves audit semantics. Archive capacity and query/pruning work remain DB-07–09/23. |
| DB-07 | **Implemented/tested; deployment qualification open** | Version-2 archive segments use bounded ID catch-up, destination-specific locked progress, canonical row replay, signed boundary/checksum metadata and verified S3 read-back. See [archive contract](docs/audit-archive.md). | Local PostgreSQL tests cover missed runs, backdated rows, rollback sequence gaps, replicas and safe replay after upload/read-back/commit failure. Actual destination capacity, compatibility and sustained catch-up remain deployment gates. |
| DB-08 | **Offline complete-chain verification implemented; external durability gates open** | Downloaded segments and complete linked chains verify offline using an independently trusted key and head digest. Bounds, signatures, checksums, IDs, predecessor links and chain hashes are checked. | Local independent replay/tamper/missing-segment tests pass. The historical row-53 discontinuity is not bypassed. Fresh-host recovery, immutable object policy and long-term availability remain unproven. |
| DB-09 | **TRUNCATE protected; hot/cold pruning design open** | Migration 191 closes the TRUNCATE gap; UPDATE/DELETE remain blocked, and demo seeding preserves audit rows. Full source verification still starts at genesis; no pruning or trusted hot/cold query anchor is introduced. | Local PostgreSQL rejects UPDATE/DELETE/TRUNCATE and preserves the chain. After DB-07/08 deployment acceptance, design trusted archive anchors and preserve audit, timeline, support, exception-history and admission-hit queries before pruning. |
| DB-10 | **Per-source health and paged recovery implemented; retention open** | Explicit organization/cluster source configuration detects missing, stale, delayed and unknown-reported timestamps independently. No global latest-event shortcut or fabricated reported timestamp remains for new ingress. | PostgreSQL and PromQL failure/recovery tests pass. Signed export/offline verification and independent-database scoped restore pass local tests. Scheduled archival and hold-aware source retention remain open; live delivery is deferred. |
| DB-11 | **Signed threat/packet recovery locally verified; lifecycle open** | Signed paged runtime-threat export, offline verification and independent packet recovery are implemented. Existing bounded PCAP maintenance requires a verified durable store. | Qualify PCAP failure/recovery, scheduled archival, complete case/forensics dependency recovery and hold-aware retention. No age-only threat or forensic deletion is authorized. See [runtime-threat archives](docs/runtime-threat-archives.md). |
| DB-12 | **Implemented/local tests passed; live gates deferred** | Migration 196 and the [hourly retention contract](docs/flow-rollup-retention.md) provide a separate window, bounded raw-boundary-gated cleanup, monotonic unavailable-history boundary and late-ingest exclusion. | Existing values remain holds; new defaults are 90 days. PostgreSQL and HTTP tests preserve counts and return 410 for expired map/conversation/CSV ranges. Live rollout remains deferred. |
| DB-13 | **Preservation policy set; archive/layout open** | Define lifecycle-aware retention for `findings`. All current findings land in a DEFAULT child despite time partitioning; open findings and triage must not vanish by age alone (`internal/server/database/migrations/004_findings_partitioned.sql`). | Resolved/orphaned findings archive by policy; open/suppressed/accepted decisions remain visible; partitions or another bounded layout avoid default-child bloat. |
| DB-14 | **Reference protection implemented; named-history archive open** | Bounded job/result/repository maintenance locks candidates and rechecks references under READ COMMITTED. Latest/live/referenced records and all findings survive. | Real reference-race and boundary tests pass. Full named-result/job-history archival and dependency-aware restoration remain open; age alone does not authorize evidence removal. |
| DB-15 | **Single-inventory recovery implemented; complete graph lifecycle open** | Signed package-inventory export/offline verification/scoped restore has an independent-database recovery test and atomic audit receipt. It neither deletes source evidence nor archives complete SBOM/result/attestation dependency graphs. | Size/signature/scope/conflict/rollback tests pass for the single-record primitive. Full dependency restoration, durable archive scheduling and payload cleanup remain open. |
| DB-16 | **Cleanup/load/alerts locally qualified; live gates deferred** | Bounded identity/login/network-session cleanup preserves live state and audit receipts. A 400,000-expired-row fixture measures foreground concurrency and WAL; active-worker stall/failure rules avoid idle-follower alarms. | PostgreSQL and PromQL tests pass. Immediate SQL drain is not scheduled capacity: 1,000 rows/family/minute remains the production budget. Live rollout/delivery and fleet sizing remain deferred. |
| DB-17 | **Classification and bounded manual clearing complete; broader lifecycle open** | Per-family ownership/holds are recorded. Existing support payload expiry is bounded; explicit admission-history clearing now has a 1,000-row/five-second budget and atomic audit receipt. | Batch, lock, tenant and commit-failure tests pass. Delivery/compliance/restart archives and bounded retained metadata remain open; no automatic evidence-history expiry was added. |
| DB-18 | **Implemented; real-feed replay locally qualified** | Conditional merged writes and durable checkpoints avoid identical/sparse rewrites. Real KEV/EPSS replay covered 394,803 rows with no replay rewrites or extra WAL; malformed/partial/restart/replica regressions pass. | Production cadence and fleet WAL/dead-tuple growth remain deferred. The local fixture is not fleet capacity proof; see the [feed contract](docs/cve-feed-checkpoints.md). |
| DB-19 | **Historical semantics/backfill implemented; full traversal unqualified** | Sources, aliases and KEV preserve historical observations; EPSS freshness uses its score timestamp. Opt-in resumable NVD bootstrap covers historical modified windows while current updates retain priority. | Withdrawal/sparse-update/replay tests pass. Full real NVD mirror traversal and source deployment remain operational qualification work. |
| DB-20 | **Storage decision complete: retain PostgreSQL** | A restored 412,772-row catalog profile justified targeted indexing, not another database format. The measured default page improved from about 497 ms to 0.258 ms with about 26 MiB additional index allocation. | Local catalog/restore evidence supports the decision; broader workload/fleet capacity is DB-23. Retired VulnDB is not reintroduced. |
| DB-21 | **Topology/health and offline process recovery qualified; live capacity open** | Explicit pod-local/single-PVC topology and diagnostics are implemented. Real Trivy/Grype matching passed twice in fresh network-isolated containers with unchanged private copies of 4,954,046,907 DB bytes; missing databases fail closed. | This proves local package matching across process replacement, not live PVC attachment, full image extraction, refresh overlap headroom or notification delivery. No claim that 8 GiB is sufficient. |
| DB-22 | **Scheduled read-back/local recovery and retention implemented; remote lifecycle open** | Scheduled S3 destinations are consumed and verified by independent read-back. Local cleanup is bounded, locked and opt-in; the protected newest-copy floor requires available safe files. Signed local-file and local-object-store configuration restores into separate databases pass. | Organization backups remain distinct from PostgreSQL PITR and exclude operational evidence/secrets. Remote/failed receipts stay held; off-host recovery, object lifecycle and broader failed-artifact cleanup remain open. |
| DB-23 | **Storage signals and local qualification implemented; fleet/live gates open** | Read-only database/relation/WAL/partition/archive/backup/audit-source signals and active-worker cleanup alarms ship with 21 storage rules and 137 PromQL scenarios. Local catalog, session, scanner and flow concurrency fixtures record measured limits. | Live scrape/notification/Grafana validation, fleet budgets, full event/HTTP ingestion and scanner refresh/extraction headroom remain unqualified. Local burst SQL measurements do not establish production cadence or capacity. |

## Hardware qualification and deferred operational work

The old hardware plan is archived. Preserve these outcomes, not its stale tool
versions, prices, dates or blanket CNI claims. M1-03 must name the supported test
profile before qualification. Live execution remains deferred; local test/harness
preparation can proceed. Numerical targets below are proposed test budgets, not
agreed customer SLOs or permission to provision infrastructure.

| ID | Parent | Current requirement and exit evidence |
| --- | --- | --- |
| HW-E1 | M5-03 | Baseline and agent/enforcement-on measurements for light, heavy and spiky traffic, at least 30 minutes each, plus the 24-hour fleet soak. Record p50/p95/p99 latency, packet loss, CPU/RSS, NFQUEUE state and ingest/replay lag. Exercise DP death, ingest saturation and API disconnection, proving bounded loss/backpressure and recovery. Revalidate the old proposed budgets (light p99 overhead <500 µs; heavy DP <2 cores and lag <5s; spike drain <30s; threat latency <1s) against the supported profile before treating them as gates. |
| HW-E3 | M2-01–02, M5-02 | Inventory all existing threat scenarios; make a reproducible setup/trigger/assert/cleanup runner and prove image/admission/WAF/DLP/process/GitOps/network/audit effects. Cover reverse-shell/miner/lateral-movement/DNS-exfil patterns, WAF RCE, DLP egress, escape attempts and kubelet credential access in disposable fixtures. Record latency and a one-hour benign-traffic false-positive baseline. Do not enable Actions or run live attacks under the current constraint. |
| HW-A4 | M1-03, M2-02 | Qualify detection, appropriate CNI-native or NFQUEUE verdicts, restart/failure behavior and evidence per claimed CNI. Candidate matrix: kindnet, Flannel, Calico, Cilium, Cilium/Calico chaining, EKS VPC CNI, GKE and Azure CNI. Unsupported rows must be excluded visibly; Cilium inline WAF/DLP remains unavailable. Record reproducible cluster specs and per-row limitations. |
| HW-C2 | M2-02 | Prove attribution for host-network pods, ordinary pods, node processes, multiple interfaces and reused identities; verify cgroup/namespace mapping, bounded identity collection and restart behavior. Measure probe/stitcher overhead against the supported load profile; the old <3% CPU budget needs profile validation. Preserve positive, negative and recovery fixtures. |

## Consolidated UI and integration follow-ups

The old UI list predates later redesigns. These are **revalidation tasks**, not
claims that every historical bug still exists. Close each with current route/API
and component/browser evidence, or an explicit product-scope decision. Existing
empty states are not defects merely because a disposable fixture has no data.

| ID | Parent | Work and acceptance criterion |
| --- | --- | --- |
| UI-L01 | M5-02 | Revalidate deployment risk detail routing, entity breadcrumbs/back links, CVE search-to-detail navigation and process-baseline navigation. A deployment must resolve through the deployment contract; labels must identify the entity rather than only its UUID. |
| UI-L02 | M2-05, M5-02 | Revalidate namespace/label facets and URL-scope propagation through dashboard, findings and network queries. Compare filtered API results and counts, not just selected chips. |
| UI-L03 | M5-02 | Revalidate CVE image/deployment/cluster relationships and affected counts against a fixture with each relationship present. |
| UI-L04 | M2-05, M5-02 | Verify authoritative KEV/EPSS, reachability, cluster/namespace dimensions and risk-factor payloads; replace heuristic or synthetic presentation where a supported contract exists, otherwise label unavailable evidence. |
| UI-L05 | M2-01, M5-02 | Verify response-rule event categories in seeded/current data and the canonical audit route; remove or reject empty/unsupported categories. An obsolete `/api/v1/audit-events` URL is not a new API requirement. |
| UI-L06 | M1-03, M5-02 | Resolve the old standalone AI-page request against the current ML/runtime surface. Document the supported location or explicit exclusion; no placeholder route. Validate meaningful empty states for policies and out-of-window flows. |
| INT-01 | M1-03, M2-05 | Decide whether a Bitbucket Pipelines template belongs in the supported integration set; if included, prove its current CLI/policy/report contract with fixtures. |
| INT-02 | M1-03, M2-01 | Decide scope and qualify an Argo CD/GitOps admission integration, including denied/allowed changes and unavailable-controller behavior. |
| INT-03 | M1-03, M2-05, M5-05 | Resolve VS Code source/artifact and support scope: the formerly documented extension directory is absent. If included, implement and qualify the current findings/authentication contract before distribution. Marketplace publication is separate from local correctness and remains outside code/local-only work. |
| INT-04 | M1-03, M2-05 | Review the historical go-github-client proposal against the current GitHub App implementation; adopt only for a demonstrated contract/maintenance benefit, or record it superseded. |
| SYS-01 | M2-01–02 | Finish component-identity protection rather than namespace-only exclusions, image-wide response coverage, separately managed dependency assignments and the audit of every disruptive response path. Preserve system-service communication with scoped positive/negative enforcement proofs. |

## Historical requirement-family crosswalk

These mappings cover the old plan's families, not an item-by-item revalidation.
Old checked states are not promoted to current verified states automatically.

| Original family | Current work | Disposition / evidence boundary |
| --- | --- | --- |
| Image hardening (additional October 19 entry) | M5-01 | Fresh exact-image/security/provenance qualification remains open. |
| P0.1 Control reachability | M2-01, M3-01 | Existing fixes are bounded; complete action/failure matrix and durable effects remain open. |
| P0.2 Scope isolation | M2-01, M2-05 | Historical H1 and attribution fixes exist; full route/agent-write/namespace inventory remains open. |
| P0.3 Fail paths and integrity | M2-01, M3-03, M5-01 | H1–H12 closure does not repair historical audit evidence or qualify all failure paths. |
| MIG-1 Import coverage | M4-01–03 | Partial conversion and scoped cutover tests; full-export accounting and remediation remain open. |
| CFG-1 Configuration | M2-05 | Per-key provenance, safe reload and consumer acknowledgement need current acceptance. |
| IAM-1 Identity and RBAC | M2-05, M4-02 | Native multi-provider LDAP/SAML scope superseded by ADRs 0010/0011; namespace authorization and migration remain requirements. |
| API-1 Runbook contracts | M2-05, M4-03 | Follow ADR 0002 generated contracts; revalidate current CLI and cutover recipes. |
| RUN-1 Runtime fidelity | M2-01–02 | Actual side effects, bounded process identity, drift recovery and remaining mutation classes need complete proofs. |
| NET-1 Network consistency | M2-01–02, M5-03 | Reconcile filters/totals/exports, attribution and real enforcement per supported profile. |
| CMP-1 Compliance | M2-04 | Execution/reporting source exists; full host/cloud/two-cluster and failure acceptance remains incomplete. |
| REG-1 Registry/scanner breadth | M2-03–04 | Scoped credentials and offline matching are bounded proofs; provider/format matrix remains open. |
| SIEM-1 Event delivery | M2-04, M3-01 | Local TLS/routing receipts exist; deployed receiver and recoverable effects are separate gates. |
| POL-1 Group workflows | M2-01, M4-03 | Reference conflicts, binding workflow, enforcement and import/rollback need end-to-end evidence. |
| POL-2 Policy Center | M2-01, M4-03 | Family-specific hit counts/health, precedence, import/export and unsupported-object UX remain acceptance criteria. |
| POL-3 Policy depth | M2-01–02, M3-02, M4-03 | Long-tail admission, DLP context, WAF verdicts, response categories and backup/federation coverage remain explicit. |
| UI-1 Navigation | M5-02 | Historical checked state; requalify current navigation and operator flows. |
| UI-2 Tables | M2-05, M5-02–03 | Historical checked state; verify current paging/filter/export contracts and accessibility. |
| UI-3 Platform visibility | M2-01, M5-02 | Preserve collection/enforcement while hiding platform rows; verify current metadata and exports. |
| UI-4 Operational posture | M5-02–03 | Reconcile dashboards with source data; do not equate presentation with better usability. |
| OPS-1 Supportability | M3-02, M5-02 | Existing cockpit and signed support bundles; current recovery, redaction and payload-retention proofs still apply. |
| OPS-2 Scale/test matrix | M3, M5 | DB-01–23 remain detailed child items; capacity, durable delivery and operational matrix remain incomplete. |
| TSG-1 Requirement inventory | M1-01–03 | Reconcile guide controls against current ADRs, including review ownership and deviations. |
| TSG-2 Architecture/data | M2-05, M3-02 | ADR 0002 governs domain extraction; embedded migrations and isolated DB fixtures exist. Remaining domains/invariants require inventory. |
| TSG-3 Identity/secrets/API | M2-05, M4-02, M5-01 | Current identity replaces old refresh/provider requirements; threat model, authorization and secret recovery still need complete acceptance. |
| TSG-4 Build/test | M5-01–02 | Current Make/toolchain and isolated fixtures replace retired tooling. Hosted Actions remain deferred. |
| TSG-5 API/frontend | M2-05, M5-02 | ADR 0002 supersedes REST/TanStack Form convergence; TanStack Router remains approved. |
| TSG-6 Telemetry | M2-05, M5-03 | Current logging/tracing/dev-stack choices have source; full correlation and operating evidence remain to be reconciled. |
| TSG-7 Offline/multi-language | M2-06, M5-01, M5-04 | ADRs 0003–0005 define native/FIPS exceptions; full BOM, disconnected lifecycle and architecture qualification remain open. |
| D-1 Enforcement model | M1-03, M2-02, M4-01 | Intentional CNI-native primary / NFQUEUE secondary design; Cilium inline WAF/DLP exclusion must remain visible. |


## Complete acceptance inventory

This is the sole item-level inventory: **154 stable NV IDs**, in the order of the
last retained parity checklist. Every entry maps to a current milestone. The
historical source remains linked in the archive index. The old **66 checked / 88
open** split is provenance only; the current evidence work is explicitly stated
below. This is not a new completion percentage or a promise that 154 code changes
are needed. The requirement column retains the original acceptance sentence, with superseded
architecture restated explicitly; dated implementation narratives stay archived.

For carried-over rows, revalidate the requirement under the current ADRs and
supported profile before closure. For restated rows, only the current wording is
required. Attach the source/test receipt directly to this row when closing it.
Local completion and deferred operational portions must remain distinguishable.

| ID | Current milestone | Current evidence task / disposition | Requirement |
| --- | --- | --- | --- |
| NV-001 | M5-01 | Revalidate (historically open) | Reduce vulnerabilities in shipped Constellation and supporting images: inventory exact running digests separately from historical pods/scans; establish per-image OS and embedded-tool baselines with a dated vulnerability database; refresh and pin bases, update bundled scanner tools, and remove unneeded runtime packages; verify native enforcement, TLS, scanning and backup compatibility; retain before/after SBOMs and scans and gate newly introduced fixable critical/high findings. |
| NV-002 | M2-01 / M3-01 | Revalidate (historically open) | Add a feature-reachability test for every advertised response action, vulnerability-profile decision, admission decision, runtime policy action, backup/restore guarantee, and GitOps reconciler. |
| NV-003 | M2-01 / M3-01 | Revalidate (historically open) | Remove or visibly mark any option that cannot reach an enforcement or delivery side effect. |
| NV-004 | M2-01 / M3-01 | Revalidate (historically open) | Require one positive side-effect assertion and one fail-path assertion for each control before closing its deficiency-audit item. |
| NV-005 | M2-01 / M3-01 | Revalidate (historically checked) | Stop accepting new E1 `tag` rules and remove the tag option from OpenAPI/operator CRD until it has a persisted label side effect; expose legacy unsupported rows without claiming enforcement on runtime, scan or admission paths. |
| NV-006 | M2-01 / M3-01 | Revalidate (historically checked) | Remove the last applied declarative rule when an existing response-rule CR becomes invalid, including legacy `tag`, and requeue a failed cleanup. |
| NV-007 | M2-01 / M3-01 | Revalidate (historically checked) | Record legacy E1 `tag` attempts as unsupported in compliance, host-CIS and Kubernetes-audit audit events without bypassing `suppress_log` behavior. |
| NV-008 | M2-01 / M3-01 | Revalidate (historically checked) | Apply E1 admission `suppress_log` before ordinary deny audit/notify fan-out while keeping the actual denial and response-action audit. |
| NV-009 | M2-01 / M3-01 | Revalidate (historically checked) | Reject new/updated scan `suppress_log` rules because scan completion has no security-event log; mark legacy rows unsupported, omit the no-op from agent sync and report attempts as skipped without suppressing required scan result, attempt history or completion audit. |
| NV-010 | M2-01 / M2-05 | Revalidate (historically open) | Close all open high-severity org/cluster attribution and restore-scope findings before the next parity release claim. |
| NV-011 | M2-01 / M2-05 | Revalidate (historically open) | Inventory and remediate legacy DLP/WAF group bindings whose stored org differs from their group's org. |
| NV-012 | M2-01 / M2-05 | Revalidate (historically open) | Add negative cross-tenant tests for backup restore, host/CIS ingestion, audit/event aggregation, exemptions, and agent-originated writes. |
| NV-013 | M2-01 / M2-05 | Revalidate (historically open) | Derive scope from the authenticated subject and resolved cluster, never an uploaded object or an arbitrary first row. |
| NV-014 | M2-01 / M2-05 | Revalidate (historically checked) | Reject foreign-org init-bundle/cluster attribution in host facts, packages, processes, containers, and CIS ingest through the shared resolver; direct DB negative tests confirm no facts/CIS/packages/processes/containers snapshot write (and no package scan side effects). |
| NV-015 | M2-01 / M2-05 | Revalidate (historically open) | Inventory and test remaining agent-originated writes, audit/event aggregation, and exemption scope, including deployed multi-cluster paths. |
| NV-016 | M2-01 / M2-05 | Revalidate (historically checked) | Reject foreign cluster filters in audit and timeline; prevent foreign-org deployment metadata from joining a violation. |
| NV-017 | M2-01 / M2-05 | Revalidate (historically checked) | Keep cluster-specific compliance exemptions on matching evidence rows, with org-wide fallback; reject foreign-cluster evidence filters and ignore misattributed exemptions in evidence, checks and summary. |
| NV-018 | M2-01 / M2-05 | Revalidate (historically checked) | Reject foreign or missing cluster filters on compliance checks and summary; exclude misattributed foreign-cluster checks from org-wide reads. |
| NV-019 | M2-01 / M2-05 | Revalidate (historically checked) | Bind workload-package evidence and scan jobs to the reporting runtime token's resolved cluster; reject same-org mismatches, foreign clusters and ambiguous multi-cluster tokens before writes. |
| NV-020 | M2-01 / M2-05 | Revalidate (historically checked) | Bind DPI threat writes to the reporting runtime token's cluster and reject foreign-bundle or unbound multi-cluster tokens before writes. |
| NV-021 | M2-01 / M2-05 | Revalidate (historically checked) | Bind runtime-event and network-flow writes to the reporting token's cluster rather than a query argument, workload-name guess or first org row; direct DB tests cover valid and rejected no-write paths. |
| NV-022 | M2-01 / M2-05 | Revalidate (historically checked) | Scope flow/threat IP-to-workload lookup and automatic flow backfill to the reporting cluster. |
| NV-023 | M2-01 / M2-05 | Revalidate (historically checked) | Attribute Kubernetes audit webhook events to the reporting token's resolved cluster, not the first org cluster or submitted payload. |
| NV-024 | M2-01 / M2-05 | Revalidate (historically checked) | Bind network-session snapshot replacement to the reporting token's cluster; reject mismatched query/row claims, mixed nodes, foreign/conflicting bundles and ambiguous tokens before deletes. |
| NV-025 | M2-01 / M2-05 | Revalidate (historically checked) | Require an explicit init-bundle token binding for platform-facts reports before facts, evidence, scan targets/jobs or cluster state can change. |
| NV-026 | M2-01 / M2-05 | Revalidate (historically checked) | Bind file-profile watch inventory reports to the token's cluster before replacement. |
| NV-027 | M2-01 / M2-05 | Revalidate (historically checked) | Bind file-profile agent rule bundles to the token's cluster before reading rules. |
| NV-028 | M2-01 / M2-05 | Revalidate (historically checked) | Bind response-action pending reads and completion writes to the token's cluster. |
| NV-029 | M2-01 / M2-05 | Revalidate (historically checked) | Bind PCAP claim, upload and status endpoints to the token's cluster. |
| NV-030 | M2-01 / M3-03 / M5-01 | Revalidate (historically open) | Close open fail-open findings in admission, CIS, CSPM, required scanner matchers, notification delivery, signature verification, and restore validation. |
| NV-031 | M2-01 / M3-03 / M5-01 | Revalidate (historically checked) | Make the audit hash chain safe under concurrent writers and retain a deterministic verification test. |
| NV-032 | M2-01 / M3-03 / M5-01 | Revalidate (historically checked) | Add a clean-database migration test and a repeated integration-test run to catch uniqueness and stale-fixture failures. |
| NV-033 | M4 | Revalidate (historically open) | Convert remaining NeuVector families with safe equivalents: vulnerability profiles, compliance profiles, registries without embedded secrets, syslog/webhook routing, auth-provider metadata, users/roles and role mappings, API-token metadata, and safe federation metadata. |
| NV-034 | M4 | Revalidate (historically checked) | Mark credentials and token secrets as omitted/reissue-required. |
| NV-035 | M4 | Revalidate (historically open) | Publish one complete fixture manifest with source, converted, unsupported, applied, and rolled-back object counts. |
| NV-036 | M4 | Revalidate (historically open) | Add browser coverage for paste/upload, preview, dry-run, apply, history, rollback-bundle download, rollback, and post-rollback inspection. |
| NV-037 | M4 | Revalidate (historically open) | Confirm imported DLP/WAF objects are visible from Migration, Policy Center, DLP Rules, and WAF/DPI Signatures. |
| NV-038 | M2-05 | Revalidate (historically open) | Return per-key provenance: default, environment bootstrap, database, cluster, federation, linked-managed, and redacted. |
| NV-039 | M2-05 | Revalidate (historically open) | Add PATCH only for settings whose consumers already support safe reload: scanner refresh/proxy, network proxy, syslog/SIEM, registry TLS/CA, and supported retention values. |
| NV-040 | M2-05 | Revalidate (historically checked) | Return field-level validation errors with secret-like values redacted. |
| NV-041 | M2-05 | Revalidate (historically open) | Increment revision, audit redacted before/after deltas, and show applied component revision. |
| NV-042 | M2-05 | Revalidate (historically checked) | Validate a settings change in a deployed environment without restart where runtime reload is promised. |
| NV-043 | M2-05 / M4-02 | Restated: ADRs 0010/0011; revalidate | Qualify bounded, secret-redacted connection/issuer failure handling for the current single OIDC relying party and local/TOTP recovery. Native LDAP/SAML provider probes are retired; broker-mediated customer migration remains M4-02. |
| NV-044 | M2-05 / M4-02 | Revalidate (historically open) | Add group-resolution and final mapped-role/scope previews. |
| NV-045 | M2-05 / M4-02 | Revalidate (historically open) | Import NeuVector users, roles, mappings, and token metadata without privilege escalation; require token reissue. |
| NV-046 | M2-05 / M4-02 | Revalidate (historically checked) | Add audited local-user unlock and force-reset actions. |
| NV-047 | M2-05 / M4-02 | Revalidate (historically open) | Complete namespace-scoped row filtering where resources have a namespace. |
| NV-048 | M2-05 / M4-03 | Revalidate (historically open) | Complete OpenAPI request/response schemas for migration, network rules, admission assessment, registry sync/cancel, event export, PCAP, support bundles, group usage, and DLP/WAF bindings. |
| NV-049 | M2-05 / M4-03 | Revalidate (historically checked) | Add a link/route checker for the endpoint mapping document. |
| NV-050 | M2-05 / M4-03 | Revalidate (historically open) | Smoke-test all applicable CLI recipes against a local API, including supported mutation/rollback flows. |
| NV-051 | M2-05 / M4-03 | Revalidate (historically checked) | Add a loopback-only, explicit opt-in fixed vulnerability-profile apply/idempotency/rollback smoke with preexisting-profile refusal and failure cleanup. |
| NV-052 | M2-05 / M4-03 | Revalidate (historically checked) | Add a bounded loopback-only, secret-safe recipe runner and mock-server positive/failure tests for groups, audit, timeline, scan jobs, and opt-in migration preview. |
| NV-053 | M2-05 / M4-03 | Revalidate (historically open) | Add a new-org cutover script that imports the canonical fixture, checks counts and key UI routes, then rolls back. |
| NV-054 | M2-01–02 | Revalidate (historically open) | Maintain a cluster test proving process, file, exec, and zero-drift events alert in Monitor and block in Protect. |
| NV-055 | M2-01–02 | Revalidate (historically open) | Verify response-rule process kill is delivered, executed, acknowledged, and linked to its audit record. |
| NV-056 | M2-01–02 | Revalidate (historically open) | Capture bounded argv plus path/hash/parent identity where supported and use it in baseline matching; retain basename compatibility only as an explicit fallback. |
| NV-057 | M2-01–02 | Revalidate (historically open) | Hydrate drift/baseline state after agent restart and report each node's last-applied fingerprint. |
| NV-058 | M2-01–02 | Revalidate (historically open) | Cover non-exec UID changes and remaining meaningful file mutation classes. |
| NV-059 | M2-02 / M5-03 | Revalidate (historically open) | Apply shared filters consistently to map, conversations, sessions, threats, policy context, and PCAP where each dimension is meaningful. |
| NV-060 | M2-02 / M5-03 | Revalidate (historically open) | Finish server-side port/peer/application/time filtering, totals, `has_more`, and cursor/offset contracts for row-oriented network APIs. |
| NV-061 | M2-02 / M5-03 | Revalidate (historically open) | Reconcile counts across tabs for the same filter and large fixture. |
| NV-062 | M2-02 / M5-03 | Revalidate (historically open) | Live-test Flannel/iptables inline behavior and Cilium/Calico CNI-native policy behavior; keep the documented L7-on-Cilium limitation explicit. |
| NV-063 | M2-02 / M5-03 | Revalidate (historically open) | Validate multi-interface pod attribution and host-network attribution. |
| NV-064 | M2-02 / M5-03 | Revalidate (historically checked) | Replace the kube-only visibility chip with a persisted exact-match platform filter covering Kubernetes, Constellation, and Astronomer system namespaces. |
| NV-065 | M2-04 | Revalidate (historically open) | Add a true on-demand kube-bench/docker-bench execution path rather than only nudging the report renderer. |
| NV-066 | M2-04 | Revalidate (historically open) | Ship and validate docker-bench scheduling when enabled. |
| NV-067 | M2-04 | Revalidate (historically open) | Run the same benchmark against two clusters and prove results remain cluster/node scoped across repeated executions. |
| NV-068 | M2-03–04 | Revalidate (historically checked) | Prove private-registry credentials are scoped per job and removed after use. |
| NV-069 | M2-03–04 | Revalidate (historically checked) | Verify scanner Docker credential configs are per-job, mode-restricted and removed on success, failure and cancellation in local tests. |
| NV-070 | M2-03–04 | Revalidate (historically checked) | Use the job's scoped credentials for private-registry digest, manifest and config-history reads. |
| NV-071 | M2-03–04 | Revalidate (historically checked) | Use the same per-job HTTPS/authority-scoped credentials for file-risk and config-check image reads. |
| NV-072 | M2-03–04 | Revalidate (historically open) | Complete and validate ECR, GCR/Artifact Registry, ACR, Harbor, GitLab, JFrog/Nexus, IBM Cloud, and OpenShift discovery/auth flows that are advertised. |
| NV-073 | M2-03–04 | Revalidate (historically open) | Add tag/repository selection policies, refreshable cloud tokens, and explicit unsupported-kind errors. |
| NV-074 | M2-03–04 | Revalidate (historically checked) | Return an explicit client error for unsupported registry kinds on create and attempted kind changes on PATCH; static tests enumerate all 13 accepted kinds. |
| NV-075 | M2-03–04 | Revalidate (historically checked) | Show scanner database download/apply revision and worker capacity on dashboard and health surfaces. |
| NV-076 | M2-04 / M3-01 | Revalidate (historically checked) | Support TLS with optional CA/client material for syslog. |
| NV-077 | M2-04 / M3-01 | Revalidate (historically checked) | Verify syslog optional CA/client TLS material with an in-process mTLS collector, including wrong CA, missing/untrusted client certificates and plaintext rejection. |
| NV-078 | M2-04 / M3-01 | Revalidate (historically checked) | Support RFC5424, JSON, and CEF output plus minimum level/category filters. |
| NV-079 | M2-04 / M3-01 | Revalidate (historically checked) | Verify a named receiver receives only its routed events and delivery results remain visible and auditable. |
| NV-080 | M2-04 / M3-01 | Revalidate (historically checked) | Verify named-only delivery, retry/terminal receipts, cross-org and paused rejection in PostgreSQL-backed dispatcher tests. |
| NV-081 | M2-04 / M3-01 | Revalidate (historically open) | Verify end-to-end TLS parsing and event routing against a named deployed SIEM product; the strict mTLS collector and SMTP receiver are not vendor-SIEM proof. |
| NV-082 | M2-01 / M4-03 | Revalidate (historically checked) | Use the shared GroupPicker in every editor with a group selector: network, admission, response and DLP/WAF bindings. |
| NV-083 | M2-01 / M4-03 | Revalidate (historically open) | Keep referenced-group update/delete conflict detection deny-by-default; any future cascade must be explicit and audited. |
| NV-084 | M2-01 / M4-03 | Revalidate (historically open) | Complete the now-registered group-edge HTTP workflow: source and deployed API smoke prove RBAC, audit attempts/ordinary receipts, scope rejection, protect-mode expansion and edge deletion. |
| NV-085 | M2-01 / M4-03 | Revalidate (historically open) | Add an end-to-end group workflow: create, use in network and DLP/WAF, inspect usage, promote mode, attempt unsafe delete. |
| NV-086 | M2-01 / M4-03 | Revalidate (historically open) | Add per-family hit counts and last-hit/last-changed/enforcement health. |
| NV-087 | M2-01 / M4-03 | Revalidate (historically open) | Add reorder controls only where runtime precedence exists, with RBAC and audit tests. |
| NV-088 | M2-01 / M4-03 | Revalidate (historically open) | Add real family-specific import/export actions; do not link placeholders. |
| NV-089 | M2-01 / M4-03 | Revalidate (historically open) | Show unsupported migration objects and their remediation beside the relevant policy family. |
| NV-090 | M2-01–02 / M3-02 / M4-03 | Revalidate (historically open) | Finish long-tail structured admission criteria that remain unsupported and add OpenShift controller coverage where applicable. |
| NV-091 | M2-01–02 / M3-02 / M4-03 | Revalidate (historically open) | Preserve DLP pattern context and make user-authored WAF rules reach the WAF dataplane table rather than degrading silently. |
| NV-092 | M2-01–02 / M3-02 / M4-03 | Revalidate (historically open) | Include enforcing DLP/WAF policy in backup/restore and defined federation scope. |
| NV-093 | M2-01–02 / M3-02 / M4-03 | Revalidate (historically open) | Add response-policy export/import and wire specific event categories for non-threat ingest sources. |
| NV-094 | M5-02 | Revalidate (historically checked) | One canonical home per feature; aliases redirect instead of rendering a duplicate surface. |
| NV-095 | M5-02 | Revalidate (historically checked) | Keep Clusters first as the primary workspace, followed by Organization, Platform, and Integrations (updated by the October 12 user decision). |
| NV-096 | M5-02 | Revalidate (historically checked) | Resolve remaining duplicate health/settings/token/attestation entry points. |
| NV-097 | M5-02 | Revalidate (historically checked) | Every primary page opens with one verdict, no more than five KPIs, and one primary table or workspace. |
| NV-098 | M5-02 | Revalidate (historically checked) | Use URL-linked tabs for peer views, dedicated `/new` and `/:id/edit` form pages with Save/Cancel/back navigation, and Advanced disclosure for expert-only fields. |
| NV-099 | M2-05 / M5-02–03 | Revalidate (historically checked) | Apply visible pagination, server filters, column selection, density, refresh controls, saved views, and CSV export to remaining high-volume pages. |
| NV-100 | M2-05 / M5-02–03 | Revalidate (historically checked) | Add YAML only where a matching import contract exists. |
| NV-101 | M2-05 / M5-02–03 | Revalidate (historically checked) | Persist operator choices without making saved state hide active filters. |
| NV-102 | M2-05 / M5-02–03 | Revalidate (historically checked) | Add transient read-only detail peeks where justified for repetitive triage; prefer detail pages and keep every add/edit form on its own URL. |
| NV-103 | M2-01 / M5-02 | Revalidate (historically checked) | Hide known Kubernetes, Constellation, and Astronomer platform namespaces by default in container, deployment, and relevant network views. |
| NV-104 | M2-01 / M5-02 | Revalidate (historically checked) | Keep collection, detection, policy, and enforcement active while hidden. |
| NV-105 | M2-01 / M5-02 | Revalidate (historically checked) | Persist the preference and migrate older `hide_kube_system` saved views. |
| NV-106 | M2-01 / M5-02 | Revalidate (historically checked) | Move classification to backend `platform_role` metadata using namespace, labels, and installation identity so custom install namespaces work like NeuVector's `platform_role=core`. |
| NV-107 | M2-01 / M5-02 | Revalidate (historically checked) | Expose the same role in all relevant APIs and exports; UI namespace matching remains a compatibility fallback. |
| NV-108 | M5-02–03 | Revalidate (historically checked) | Reconcile component health, policy modes, threats, vulnerability posture, exposed services, admission, scanner DB, and federation counts with their source endpoints. |
| NV-109 | M5-02–03 | Revalidate (historically checked) | Link every tile to the exact filtered source view. |
| NV-110 | M5-02–03 | Revalidate (historically checked) | Prefer downloadable HTML/CSV/JSON evidence; add PDF only when it materially improves a customer workflow. |
| NV-111 | M3-02 / M5-02 | Revalidate (historically checked) | Complete role-alias and diagnostics component tests plus E2E filtering for controller, enforcer/runtime-agent, and scanner roles. |
| NV-112 | M3-02 / M5-02 | Revalidate (historically checked) | Add API-level heartbeat fixtures for all 15 declared required and optional component roles; assert empty, partial and healthy inventories, org/cluster rollups and instance scope. |
| NV-113 | M3-02 / M5-02 | Revalidate (historically checked) | Add persisted asynchronous support-bundle jobs with queued/running/ready/ failed/expired states, redaction tests, download history, and audit links. |
| NV-114 | M3-02 / M5-02 | Revalidate (historically checked) | Sign support bundles when a deployment signing key is configured. |
| NV-115 | M3 / M5 | Revalidate (historically checked) | Reclaim physically bloated, empty legacy event/flow DEFAULT partitions after age-based deletion without risking concurrent ingest. |
| NV-116 | M3 / M5 | Revalidate (historically open) | Bound all remaining durable storage growth without silently deleting forensic evidence: export and verify hash-chain continuity before any audit archive/prune, define a reviewed retention horizon for network-flow rollups, and alert on per-table growth, retention lag, failed partition drops, and database/PVC free space. |
| NV-117 | M3 / M5 | Revalidate (historically open) | Seed large datasets and prove every high-volume page either pages or labels its render cap. |
| NV-118 | M3 / M5 | Revalidate (historically open) | Add performance budgets for network rollups, findings, audit/timeline, and dashboard summaries. |
| NV-119 | M3 / M5 | Revalidate (historically open) | Implement durable, bounded per-cluster telemetry delivery and idempotent acceptance. |
| NV-120 | M3 / M5 | Revalidate (historically open) | Qualify independent fleet workload and failure boundaries using the [proposed architecture](docs/architecture.md#proposed-fleet-topology--qualification-work-not-deployed-behavior). |
| NV-121 | M3 / M5 | Revalidate (historically open) | Maintain opt-in real-cluster suites for Flannel, Cilium, and Calico plus BPF-LSM-capable and non-capable kernels. |
| NV-122 | M3 / M5 | Revalidate (historically open) | Keep FIPS, disconnected install, upgrade, backup/restore, and HA smoke in the release matrix. |
| NV-123 | M1 | Revalidate (historically open) | Expand each chapter into stable, chapter/section-linked control IDs for every applicable MUST/MUST NOT and SHOULD/SHOULD NOT; record MAY decisions and not-applicable requirements with rationale. |
| NV-124 | M1 | Revalidate (historically open) | For each control record status (`open`, `implemented/unverified`, `verified`, `approved-deviation`, or `not-applicable`), repository evidence, positive/failure tests, owner, acceptance command and live evidence where required. |
| NV-125 | M1 | Revalidate (historically open) | Record ADRs for existing REST versus Connect, SQL migration strategy, logging/transport choices, privileged/native dataplane images, amd64-only release support and any other retained departures; deviations need explicit approval, rationale, residual risk, compensating controls and a review date. |
| NV-126 | M1 | Revalidate (historically open) | Resolve guide inconsistencies explicitly: chapters 03/06 disallow browser localStorage tokens, while chapter 10 tolerates a transition; use the stronger security requirement as the target. |
| NV-127 | M1 | Revalidate (historically open) | Establish quarterly source/version/applicability review and a CI evidence report; no "fully guide-compliant" release claim while applicable controls remain open or mandatory deviations are presented as compliance. |
| NV-128 | M2-05 / M3-02 | Revalidate (historically open) | Inventory each domain and binary; enforce composition-root configuration and dependency construction, handler/service/query boundaries, legitimate public `pkg/` APIs, and absence of shared mutable runtime state. |
| NV-129 | M2-05 / M3-02 | Revalidate (historically open) | Introduce annotated SQL/sqlc generation and checked-in typed accessors; migrate hand-written domain/handler SQL with tenant-scoped regression tests, or obtain an explicit reviewed migration/deviation decision. |
| NV-130 | M2-05 / M3-02 | Revalidate (historically open) | Implement or approve the embedded Goose runner contract, advisory-lock concurrency, migration-before-serving and failure-before-readiness tests. |
| NV-131 | M2-05 / M3-02 | Revalidate (historically open) | Audit JSONB validation/schema evolution, user-data soft-delete and purge semantics, scope-preserving imports, and schema-level cross-tenant references. |
| NV-132 | M2-05 / M3-02 | Revalidate (historically open) | Verify per-resource operator serialization and leader-election behavior; assess Crossplane/Helm recommendations for applicability without replacing a functioning security operator solely to match a reference implementation. |
| NV-133 | M2-05 / M4-02 / M5-01 | Restated: ADRs 0010/0011; revalidate | Verify HttpOnly/Secure/SameSite browser cookies, hashed opaque database sessions, expiry and revocation, and explicit bearer precedence for machine/CLI callers. The removed browser refresh-token/provider architecture is not reinstated. |
| NV-134 | M2-05 / M4-02 / M5-01 | Restated: ADRs 0010/0011; revalidate | Prove CSRF, XSS/token exposure, expiry/logout, role/password/account-change revocation, cross-org and namespace scope across the current browser/API/CLI flows. Use current single-OIDC and local/TOTP semantics, including replay and provider-outage behavior. |
| NV-135 | M2-05 / M4-02 / M5-01 | Revalidate (historically open) | Prove secret-bearing columns use installation-external key custody, versioned key/algorithm metadata, a resumable rotation job and old-key-retirement verification. |
| NV-136 | M2-05 / M4-02 / M5-01 | Revalidate (historically open) | Publish a threat model and enforce centralized authentication/authorization, audited denies, bounded requests, typed/redacted client errors and protected metrics/admin surfaces; remove internal SQL/secrets from error responses. |
| NV-137 | M5-01–02 | Revalidate (historically open) | Add blocking per-PR gosec, govulncheck/SARIF, full-history secret scanning, per-language dependency scanning, dependency update automation and documented remediation/suppression SLAs. |
| NV-138 | M5-01–02 | Revalidate (historically open) | Make lint fail on missing tooling or findings; configure the guide's golangci-lint v2 baseline, format verification, shellcheck and applicable Python type/lint/lock/audit checks, with reviewed exceptions. |
| NV-139 | M5-01–02 | Revalidate (historically open) | Pin Node and every supported language/runtime, align CI/Dockerfiles with source-of-truth versions, use immutable production image references, and supply required OCI labels plus qualified nonroot/minimal runtime images. |
| NV-140 | M5-01–02 | Revalidate (historically open) | Complete canonical Makefile/dev orchestration and per-binary Air configs, generated-directory exclusions, shutdown/error handling and reproducible environment/bootstrap behavior. |
| NV-141 | M5-01–02 | Revalidate (historically open) | Separate unit and DB integration suites with build tags, introduce isolated real-backend fixtures, run races without result caching, emit/upload JUnit, and prove repeated/shuffled execution without shared-fixture leakage. |
| NV-142 | M5-01–02 | Revalidate (historically checked) | Run Playwright through production-serving paths with setup-project auth state, zero PR retries, configurable base URL and retained failure artifacts; wire browser tests and distinct FIPS builds/status checks into CI. |
| NV-143 | M2-05 / M5-02 | Restated: ADR 0002; revalidate | Adopt generated Connect/protobuf contracts and clients domain by domain, with categorical enums and compatibility/authorization tests. Revalidate remaining REST/OpenAPI consumers until their domain cutover; retire replaced routes rather than maintaining two permanent APIs. |
| NV-144 | M2-05 / M5-02 | Revalidate (historically open) | Standardize bounded opaque pagination, route-level error handling and session-aware data loaders while preserving API-1's migration/runbook contracts. |
| NV-145 | M2-05 / M5-02 | Restated: ADR 0002; revalidate | Migrate forms to react-hook-form and Zod with inline errors, consistent query invalidation and component/browser proof. Retain TanStack Router; the earlier TanStack Form mandate is superseded. |
| NV-146 | M2-05 / M5-02 | Revalidate (historically open) | Migrate to TanStack Router, verify accessible Radix-based primitives, static production builds, API/WebSocket dev proxies, version stamps and Node/tooling pins against the guide, with ADRs for deliberate alternatives. |
| NV-147 | M2-05 / M5-03 | Revalidate (historically open) | Resolve and implement/approve logger, stderr, OTLP transport and metric exporter choices; ensure every long-lived binary participates in the same structured logs/metrics/traces and resource identity model. |
| NV-148 | M2-05 / M5-03 | Revalidate (historically open) | Wire composite pgx query tracing, request/correlation/trace propagation, explicit histogram buckets and bounded label cardinality; verify actual emitted spans/logs/metrics, not just initialization/configuration. |
| NV-149 | M2-05 / M5-03 | Revalidate (historically open) | Provision the complete local Prometheus/Tempo/Loki/Grafana stack and prove collector-unavailable behavior, bounded queues, partial-init cleanup and graceful shutdown without making telemetry a startup dependency. |
| NV-150 | M5-01 / M5-04 | Revalidate (historically open) | Produce a complete signed deployment BOM including charts, all role and helper images, scanner databases, tools, language dependencies and trust roots; verify trust before extraction and reject missing/invalid/expired signatures. |
| NV-151 | M5-01 / M5-04 | Revalidate (historically open) | Implement local-first OCI resolution with explicit authenticated fallbacks, no implicit public-registry fallback, startup egress inventory and provenance logs; document optional connected-only external integrations honestly. |
| NV-152 | M5-01 / M5-04 | Revalidate (historically open) | Validate local S3-compatible storage, endpoint discovery/caching/overrides, external-endpoint presigning and idempotent initialization where applicable. |
| NV-153 | M5-01 / M5-04 | Revalidate (historically open) | Test first boot, core workflows, scan/DB updates, upgrade and backup/restore with out-of-cluster egress blocked. |
| NV-154 | M2-06 / M5-01 / M5-04 | Revalidate (historically open) | Qualify amd64 and arm64 artifacts, or approve/document an explicit native dataplane architecture deviation. |

## Comparison rules and intentional differences

NeuVector's official [5.6 platform documentation](https://open-docs.neuvector.com/basics/requirements/)
lists Cilium, Calico and Flannel support. Its [DLP/WAF documentation](https://open-docs.neuvector.com/policy/dlp/)
describes payload filtering and its overhead. Its [release notes](https://open-docs.neuvector.com/releasenotes/5x/)
include 5.6.3 in October 2026. These sources were reviewed October 26; they define
comparison inputs, not evidence that Constellation matches them or that either
product is defect-free.

- **Enforcement:** CNI-native policy is a deliberate Constellation design choice.
  Do not claim NeuVector lacks Cilium support or network enforcement. Compare
  effective verdicts, policy semantics, failure modes and measured overhead.
- **Native engine:** Constellation vendors NeuVector DP revision
  `4247e24561a9cd225db73a7cfaf5c7b2c99ba0a5`, tagged
  `v5.5.1-rc4-33-g4247e245`, dated May 14 in the [NOTICE](third_party/neuvector/NOTICE).
  This creates an upstream maintenance obligation; it is not an independent
  detection-engine superiority claim.
- **Identity:** local accounts/TOTP and one OIDC provider are supported choices.
  Customers using native LDAP/SAML or multiple providers need a documented broker
  or identity migration. This is a compatibility tradeoff under current ADRs.
- **Migration/federation:** importers and federation primitives exist, but full
  family coverage, precedence and realistic customer cutover remain unqualified.
  Unsupported/manual objects must be counted and visible.
- **Performance and UX:** a modern stack, more tests or more scanner engines do
  not establish lower overhead, better detection or easier operation. Claims need
  comparable workloads, labeled outcomes and observed user workflows.

## Next work and reporting order

1. Finish M1-01's item-level reconciliation and M1-03's supported profile; correct
   contradictory operator instructions under M1-02 as they are encountered.
2. Prioritize M3-01's durable response contract and M2-01's complete security
   action matrix. Review the native-engine maintenance gap under M2-06 in parallel
   with ordinary implementation work when capacity permits.
3. Continue M3-02 using original DB IDs, preserving evidence and distinguishing
   code completion from deferred recovery/retention operations.
4. Qualify the representative cutover under M4 and the local release gates under
   M5, including the frontend warning cleanup. Scope implementation to measured
   gaps; do not rewrite already-qualified paths merely to produce another batch.
5. Leave hosted release/live/off-host/node-failure criteria explicitly deferred
   until the operating constraint changes. Do not call the product done in their
   absence.

For each future update, report: IDs advanced, source/test evidence, criteria
actually closed, next unresolved criterion, and operational deferrals. Update
this plan when an acceptance state changes; keep supporting domain contracts and
dated execution logs separate from the work queue.
