# Product readiness and NeuVector comparison plan

Reviewed **2026-10-26** against main
[`4aa704a035eaf149eab2ffe55e20e9651956f372`](https://github.com/alphabravo-oss/constellation/commit/4aa704a035eaf149eab2ffe55e20e9651956f372).
This is the current acceptance register. The [database lifecycle backlog](database-lifecycle-backlog.md)
owns the detailed DB-01–23 work; [architecture decisions](decisions/) govern the
implementation. Dated test records remain evidence for their stated scope.

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
  copies under the [retention decisions](storage-retention-policy.md). No additional
  legal period, legal hold or RPO/RTO target has been supplied. Measure recovery
  performance before proposing service objectives; do not invent an agreed target.
- Follow [ADR 0002](decisions/0002-adopt-guide-stack.md): domain layers, sqlc,
  incremental Connect-RPC/generated clients, react-hook-form/Zod and TanStack
  Router. The retired REST/TanStack Form convergence programme is not reinstated.
- [ADR 0007](decisions/0007-helm-only-deployment.md) controls deployment;
  [ADR 0010](decisions/0010-oidc-relying-party.md) and its local-account successor
  [ADR 0011](decisions/0011-local-accounts.md) control identity. Native LDAP/SAML
  providers are an intentional difference, not a task to restore removed code.

The old `NEUVECTOR-PARITY-PLAN.md` was removed on October 20 during the approved
realignment. Its [last retained version](https://github.com/alphabravo-oss/constellation/blob/388ad8ce861989e4604d1649a27499dc74b8af7c/docs/NEUVECTOR-PARITY-PLAN.md)
contains **66 checked and 88 unchecked entries**. Those are historical counts:
subsequent work completed some requirements, while ADRs superseded others.
The family crosswalk below preserves traceability without restoring obsolete
implementation choices. Item-by-item reconciliation is still M1-01.

## How progress is counted

| State | Meaning |
| --- | --- |
| Verified, bounded | The named contract passed with recorded source, environment and limits. It does not close its entire parent milestone. |
| Implemented / unverified | Source exists, but the full acceptance criterion lacks current qualifying evidence. |
| Open | Required implementation, investigation or acceptance work remains. |
| Intentional difference | A current ADR or explicit support boundary changes the old requirement. Record the customer impact and migration path. |
| Deferred | The required operational test is outside the current authorized scope. It remains a readiness condition. |

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
| Historical high-severity defects | [H1–H12](SECURITY-BACKLOG.md) are recorded fixed, including closure by removal/replacement where applicable; most were reverified October 23. | This is closure of a historical list, not a complete vulnerability assessment. Fresh source/dependency/image security qualification remains M5-01. |
| Local code quality | PR #52's final `make check` reported 3,278 tests, 9 skipped; integration reported 5,186 tests, 19 skipped. Lint, vet, formatting, shell and frontend type/build checks passed. | Suites overlap. Native, real-kernel, provider, real-tool and load opt-ins need their own receipts. No fresh security, browser or live acceptance run was performed for this assessment. |
| Frontend | The October 26 assessment run passed 159 files / 2,440 tests. | It emitted 19,820 environment-`act` warnings and 42,277 unwrapped-`act` warnings. These are repeated messages, not 62,097 distinct defects; eliminate the warning causes and qualify real operator flows under M5-02. |
| Scanning | [Scanner evidence](scanner-evidence.md), [job leases](scan-job-leases.md), scoped private-registry credentials and [offline matching](offline-scanning.md) have bounded proofs. Trivy/Grype matched real packages across two network-isolated starts. | Engine count and finding count do not prove accuracy. Complete provider/format coverage, matched-data false-positive/false-negative comparisons, and a full disconnected lifecycle remain open. |
| Runtime and network | Process/file controls, native DP policy distribution, CNI-native policy and scoped Cilium/Calico traffic proofs exist; see [enforcement model](network-enforcement-model.md) and dated [security evidence](security-testing.md). | Configuration must be traced to actual verdict/action, acknowledgement and audit under failure and restart. Cilium inline WAF/DLP is unavailable in this design. No blanket CNI/kernel/platform qualification follows. |
| Evidence and retention | Signed audit, inventory, Kubernetes-audit and runtime-threat exports have independent verification/recovery proofs; DB-01–23 records precise progress. | Scheduled archives, dependencies, immutable remote copies, hold-aware expiry and trusted hot/cold query anchors remain incomplete. The historical audit chain break at row 53 remains unresolved. |
| Delivery | [Event/flow spools and receipt transactions](telemetry-delivery.md) provide bounded raw-data replay protection. | Response callbacks, notifications and other effects lack a transactional delivery outbox. DPI/inventory/session lanes retain best-effort behavior; node/disk loss can destroy unacknowledged local evidence. |
| Efficiency | [Query budgets](efficiency.md) cover 25 hot handlers with 10,000-row fixtures and a 250,000-byte gzip entry budget. Local flow, session and feed qualifications exercised 110,000, 400,000 and 394,803 rows respectively. | These are workload-specific results, not fleet SLOs. The May performance baseline and [scale guide](scale-hardening.md) do not establish production capacity or superiority over NeuVector. |
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
browser/live acceptance. [CLAUDE.md](../CLAUDE.md) and the [Makefile](../Makefile)
define current commands; older entries in the security log may refer to retired
tooling. Preserve those entries as history, not instructions for a new run.

## Remaining milestones

All five parent milestones are **open**. Work within the current scope can
progress while operational portions stay deferred. Accountable roles below are
review responsibilities, not a claim that an individual has been assigned.

### M1 — Reconcile requirements and supported product scope

Review responsibility: product, architecture and security maintainers.

| ID | State | Completion criterion |
| --- | --- | --- |
| M1-01 | Open | Give each of the 154 historical entries a stable item-level disposition: current requirement and evidence, superseding decision, or explicit exclusion with impact. Reconcile Technology Selection Guide controls with current ADRs. The family crosswalk alone does not satisfy this item. |
| M1-02 | Open | Reconcile README, architecture, deployment, security, FIPS, scale and performance instructions against current source. Remove retired VulnDB/production-compose claims, obsolete commands and unsupported superiority/capacity claims. Preserve dated evidence and link the current contract. |
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
| M2-06 | Open | Review the vendored native engine against current upstream releases/advisories; record relevant changes, local patches and maintenance ownership, then run native regressions for adopted changes. Meet [ADR 0003](decisions/0003-vendored-neuvector-dataplane.md)'s quarterly review/re-vendoring obligation. An older vendor date alone is not evidence of a specific vulnerability. |

**Exit:** each supported security control has a reproducible positive effect and
a defined, tested failure outcome. Unsupported controls are visible as such.
Any outstanding live-profile proof keeps that profile unqualified.

### M3 — Make evidence and response delivery recoverable

Review responsibility: storage, runtime delivery and audit maintainers.

| ID | State | Completion criterion |
| --- | --- | --- |
| M3-01 | Open | Persist required response work atomically with the originating event, with bounded retries, idempotency keys, status and recovery tests for crash-after-commit and ambiguous external success. Inventory other best-effort lanes and specify each loss boundary. Do not promise exactly-once external effects. |
| M3-02 | Open; bounded exports verified | Complete the remaining DB-01–23 code/local criteria: scheduled signed archives, findings/attestation/case/forensics dependency recovery, bounded hold-aware retention, trusted query anchors and capacity/lag signals. Preserve existing evidence/reference/copy-floor protections. Detailed status stays in the lifecycle backlog; this plan does not declare the 23 items closed. |
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
| M5-01 | Open; hosted/release portion deferred | Run current lint/unit/integration/frontend/native/security gates on a recorded source revision. Scan exact image digests and dependencies, preserve findings and resolve release blockers. Verify source-bound provenance/signatures for any eventual release. Local green checks are not hosted CI or signed-release evidence. |
| M5-02 | Open | Fix frontend asynchronous-test/environment warning causes without blanket suppression, then run the full suite with a clean diagnostic contract. Verify production-serving browser flows and accessibility for migration, identity, policy, scanning, evidence and recovery. Earlier browser receipts do not qualify the new source automatically. |
| M5-03 | Open; fleet portion deferred | Measure supported load, p95/p99 latency, CPU/memory, database growth, ingest lag/backpressure and recovery under concurrent readers/writers. Retain the 24-hour fleet soak and failure matrix. Define capacity from measurements; 100 clusters / 10,000 nodes / 100M findings is a design target. |
| M5-04 | Open; live portion deferred | Qualify disconnected first boot, core workflows, feed/tool updates, upgrade and full restore with closed egress; qualify each claimed CPU architecture. Go FIPS build/runtime guards do not establish whole-product certification or deployed compliance. |
| M5-05 | Deferred | After an explicit change to the current operating scope, qualify the signed release on the supported deployment profile, including alert delivery, failover, off-host recovery and real node loss. Keep Actions disabled and make no live rollout in the current scope. |

**Exit:** a specific version, image set and supported profile have complete
release evidence and stated limitations. Local completion alone does not close
M5 or establish production readiness while M5-05 remains deferred.

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
  `v5.5.1-rc4-33-g4247e245`, dated May 14 in the [NOTICE](../third_party/neuvector/NOTICE).
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
this register and the relevant domain backlog together when an acceptance state
changes; keep dated execution logs separate from the forward-looking plan.
