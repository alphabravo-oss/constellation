# Constellation parity and switchability plan

Status: **active canonical plan**
Last reconciled: **2026-10-18** (selected console scope complete; security and
release-readiness continuation active, qualification evidence remains dated)

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

Exact combined source **2b29b63** passes **2,460** fresh-schema-180
race/shuffle/count-two test executions across four affected packages, with six
explicit native opt-in skips. Vet passes all four packages; four Go binaries,
three thin images and three private raw single-tag archives are verified. All
thirteen image probes are independently absent. Main now runs **Helm 86 / schema
180**, API/scanner/runtime-agent source **2b29b63**, after a fresh completed backup
and successful live payload, storage/lease and API smoke checks. Migration and
frontend remain on 5b82b12. This deploys the notifier, backup, federation and
current-generation readiness follow-ups as well as the inherited c5428cc fixes.

Hosted CI on exact 2b29b63 has nine passing jobs and four failing gates: quality,
gosec, gitleaks and required. Lint is 1,456, gosec 143 and historical-secret
identities remain eleven. Count-aware comparisons against c5428cc remove three
lint and one gosec findings, adding none. Frontend passes 2,344 tests and browser
acceptance passes 279 cases without failures, flakes or skips. No parent acceptance
item is closed. See `docs/security-testing.md` for evidence and boundaries.

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

## October 17 security and release-readiness continuation

The user authorized the broader CI, tenant/fail-path, enforcement, migration and
infrastructure continuation after the selected console scope. Off-host recovery
and deliberate real-node failure remain deferred. The checklist remains **66
checked / 87 open**; bounded fixes below do not close their parent acceptance gates.

Current main development deployment: **Helm 86 / schema 180**, API/scanner/runtime-agent
source **2b29b63**; migration/frontend source **5b82b12**. All seven deployments and
the runtime DaemonSet are ready; StatefulSets match their desired replicas. Four
live Go payloads and inherited native DP/BPF hashes match the reviewed artifacts.
Health/readiness, policy protocol and queue authorization checks pass. Original
retained PCAP storage, mode/ownership, Recreate strategy, API leader lease and
runtime-token secret identity are preserved. Runtime remains in monitor mode,
with enforcement and benchmark workers disabled and execution dry-run enabled.
The fresh CNPG backup retained original UID
`879e1770-4d88-4fb1-82de-023d170cb3b2` and completed at `2026-10-18T17:58:45Z`
before the normal three-image update. All sixteen prior pins and three candidate
pins are verified. The owned smoke forward, listener and disk observer are absent.
Authenticated browser navigation remains unverified under the user's isolated-check
selection. Live policy and response queues are empty; positive enforcement remains
separate dated fixture evidence. The completed deployment manifest is
`/root/constellation-rollout-2b29b63-preparation/DEPLOYMENT-EVIDENCE-MANIFEST.json`.

The deployed catalog correction extends categorical registry errors to
DockerHub, GHCR, Generic V2, Nexus, OpenShift, Quay, Harbor, GitLab and JFrog
catalog requests. Upstream bodies, URLs and parser diagnostics do not enter the
tested API, persisted-status or audit errors; causes remain inspectable through
error unwrapping. Component qualification passes 676 registry and 46 fresh-schema-180
handler executions, vet, and unchanged scoped lint (332 findings, zero additions).
Original-code controls fail 128 intended leaf assertions. ECR SDK and shared V2
diagnostic boundaries are also included in deployed c5428cc, with 768 component
test passes, vet and unchanged scoped lint. These corrections passed combined
artifact validation and deployment; live provider-credential and broader registry
acceptance remain open. See `docs/security-testing.md`; no parent gate closes.

The deployed CIS follow-up requires complete bounded evidence before reporting
module absence or a passing plain SSH setting. Loaded or built-in modules fail;
incomplete inventories skip, available unloaded modules warn, and conditional or
unsupported SSH configuration requires review. Static blacklist text alone does
not establish effective disabling. Final fresh-schema tests pass 876 executions
across hostscan/runtime-agent, with four explicit native/Flannel opt-in skips;
vet passes and scoped lint removes four findings with none added. This correction
is included in the combined c5428cc artifacts and deployment. Benchmark workers
remain disabled; this does not establish benchmark execution or broader CIS
acceptance.

The eight-file notifier delayed-retry, backup terminal-status and federation
response/error follow-ups and three-file runtime-health follow-up are now deployed
in 2b29b63. Their separate source qualifications remain recorded in
`docs/security-testing.md`, followed by the combined 2,460-pass qualification,
artifact verification and Helm 86 deployment. Readiness requires the active DP
generation; historical replies cannot satisfy it after exit or during replacement
startup. The unprivileged search-only fixture uses an inherited directory descriptor
under private temporary-directory ancestors. Fresh tap reconciliation, notifier
shutdown/persistence, unavailable-DB bookkeeping, federation credential/state
atomicity and broader enforcement/recovery acceptance remain open.

Deployed schema180 preserves full unsigned native threat IDs and marks unproven
historical maxima in compact row details. Its full-chain migration checks exact
tenant/cluster tuples, raw-retention/watermark fences, unchanged traffic counters,
lock ordering and guarded downgrade. Qualification passes 2,930 fresh-database
executions and 2,344 frontend tests. Controlled stop/replace completed; 838 main
historical rollups retain an explicit incomplete marker. Live health, queue
authorization, image identities and public frontend assets pass. See
`docs/security-testing.md` for the roll-forward constraints. This bounded
correction does not close a broader acceptance item.

Frozen candidate source **034f2baf49c1** includes:

- Legacy backup list/detail/download reads require exact organization ownership;
  null-owned archives cannot become visible to another tenant. Runtime policy
  bundles require the authenticated agent's resolved cluster, including rejection
  of same-organization sibling-cluster requests.
- Process responses reject missing/mismatched process and container identity;
  conntrack deletion requires explicit protocol, both addresses and both ports.
  These tests use injected operations and do not claim live process enforcement.
- Artifact downloads validate every resolved address at connection time and dial
  only checked numeric addresses. Redirects retain the guard. Configured HTTP and
  HTTPS proxies use numeric CONNECT targets with independently verified proxy
  and destination TLS identities. Download errors and worker logs omit signed
  URL credentials; cancellation identity remains inspectable.
- Audit, signing and compliance artifacts use private directories/files and
  atomic confined writes. File-delivery destinations must remain within the
  operator-configured `REPORT_OUT_DIR`; deployments relying on destinations
  outside that root must change their configuration. Public verification keys
  remain public, and mounted-key read compatibility is preserved.
- Network, DLP and WAF identifiers outside the wire range are refused before
  replacing confirmed enforcement state. Legacy zero network IDs remain valid.
- Compliance delivery failures now fail the persisted run and schedule instead
  of reporting success. Missing SMTP configuration or recipient is an error;
  the rendered artifact remains available and remaining targets are attempted.
- CLI output and response-read failures propagate to callers. Obsolete unused
  evidence collectors were removed; active inventory evidence remains intact.
  Configured formatting was applied to 88 source files. Quality package discovery
  now follows `go list`, as formatting/security checks already do; no module-owned
  packages or tests are excluded and no gate threshold was relaxed.

Bounded validation includes 40 fresh-database tenant/responder executions, 108
artifact/signing executions, 126 CLI executions and 40 delivery executions, all
passing without skips. The runtime-agent package passes 408 repeated race-test
executions with two occurrences of its existing DB-required replay-test skip;
these skips are not claimed as qualification. Scanner proxy tests cover separate
TLS names, proxy authentication isolation, oversized headers, complete large
bodies and misleading CONNECT body framing. The scanner changed-source lint and
vet checks pass without new suppressions. The combined frozen-source fresh-database suite passes **3,370 executions with
zero failures/skips**. That candidate was deployed on the main development cluster
at **Helm76/schema177**: API/scanner use `security-20261017-034f2baf49c1`;
discoverer/operator/runtime-agent use `recovery-20261017-034f2baf49c1`. All seven
application deployments and the runtime-agent DaemonSet are ready. API health and
readiness return 200; the live agent can read its policy bundle, while unknown
cluster and unauthenticated requests return 404/401 without policy disclosure.
The live bundle is empty, so positive policy-content isolation remains database
evidence. The public login renders the expected branding and configured-provider
visibility. Candidate image smoke verifies native libraries, BPF/BTF and build
provenance; previously DB-gated controller tests pass 28 fresh177 executions.
Evidence is under `/tmp/constellation-security-034f2baf49c1/`,
`/tmp/p0-tenant-responder-db/`, `/tmp/security-artifacts-final-fresh-db/`,
`/tmp/quality-cli-output-fresh-db/`, `/tmp/security-smtp-final-fresh-db/` and
`/tmp/scanner-proxy-framing-final.json` on the development host.

The fresh baseline remains non-green: hosted CI at `7ba816e` failed quality,
gosec and historical gitleaks; unit/integration, browser, frontend, FIPS and
vulnerability/dependency checks passed. Local baseline quality reported 2,024
findings (including four downloaded JS-fixture Go files); standalone gosec
reported 256. The frozen candidate reports **1,813 quality findings** and its
standalone gosec reports **224 findings**,
with no Go loading errors. Remaining findings are not waived. Historical secret
remediation still requires external trust/revocation evidence and a reviewed
history-remediation decision. A new read-only main-cluster inventory examined 39
certificate occurrences with zero historical certificate/key matches and zero
errors; this does not establish external trust-store coverage.

Operational recovery found the existing main deployment unschedulable from disk
pressure since October 13. Removing only unused Docker build cache older than 72
hours reclaimed 33.55 GB; kubelet cleared DiskPressure without forced taint
removal. Exact cached API/frontend/scanner/admission/CNPG/Postgres/Barman images
were restored to containerd. API health/readiness, public frontend and schema177
are verified. Three old local-only `0.1.0` images were no longer available;
explicitly versioned discoverer/operator/runtime-agent replacements are now
deployed from the frozen candidate with native runtime dependencies preserved.
The migration image was also restored from its exact cached tag before the
revision76 migration job completed. One old compliance job had never started
and blocked subsequent collection; its metadata was retained, the stalled job
was replaced from the updated CronJob, and the new collector completed 51 rows.
Persistent volumes and database contents were not removed. This incident is not
an off-host recovery or node-failure qualification.

Subsequent source-only changes remove 96 HTTP test-context findings (736 fresh177
executions), simplify tenant/signing helpers (74 executions), and fail configured
signing errors or empty signatures before any delivery (60 executions). Signature
failures retain the local report metadata and produce no webhook, email or file
delivery; an explicitly unconfigured signer retains the documented checksum-only
mode. Runtime policy fields now reject overflowing IDs/directions, invalid actions
and null rules before storage/wire conversion; 84 fresh177 executions pass. These
follow-ups are not included in the deployed `034f2baf49c1` images.

The remaining CLI stream/output/catalog pass is committed in `b40bfad`: eight
production files and their failure-path tests pass 208 fresh177 race/shuffle
executions without skips. Configured CLI lint falls from 96 to 19 findings, with
no new suppressions. The remaining findings are still open. Commit `fe6ca82`
updates deprecated collectors and equivalent parser/selector branches; 814
repeated executions and 14 fresh177 federation executions pass, with 24 focused
DSL executions after the final helper extraction. Exact source manifests and
reports are retained under `/tmp/quality-cli-remaining-frozen-manifest.json`,
`/tmp/quality-cli-remaining-frozen-fresh177.log` and
`/tmp/security-static-routine-manifest.json`.

Hosted run `39006425871` at `7ea6fd5` passes unit/integration, browser, FIPS,
govulncheck and dependency checks, while quality, gosec and historical gitleaks remain failing. Its frontend
suite passes 2,293 tests and fails one response-rule workflow test: the fixture
submits before response options finish loading, when Save is intentionally
disabled. The follow-up test explicitly exercises that blocked state, waits for
Save readiness, and then checks the failed-save draft. Focused tests, lint and
type checks pass. The full Node24 rerun passes all 2,294 tests without skips
(`/tmp/constellation-frontend-20261017-qualified.json`). Hosted source `7ea6fd5`
reports 1,695 quality findings and 218 standalone gosec findings with no Go
loading errors; formatting and ShellCheck reports are empty. The source-only
CLI/parser follow-ups above postdate that hosted scan.

Commit `713f862` makes legacy runtime policy create/update/mode/delete mutations
and their configured audit writes atomic. It also rejects foreign or missing
clusters on create, retains immutable before/after snapshots, and serializes
concurrent partial edits. All 678 runtime-package fresh177 repeated race tests
pass without skips; audit-failure tests prove mutation rollback for every legacy
CRUD path and the system rollback store path. This does not qualify the separate
learned-policy generation path. Evidence: `/tmp/security-legacy-policy-db/` and
`/tmp/security-legacy-policy-manifest.json`.

Commit `3f1181d` propagates cancellation through the remaining 12 contextless
HTTP, socket, SQL and child-process test calls and their shared helpers. The
13-file final snapshot passes 296 fresh177 repeated race executions with no
skips. All 12 `noctx` findings are removed without adding context-check findings;
other pre-existing diagnostics remain. Evidence:
`/tmp/constellation-noctx-remaining-final-db/` and
`/tmp/constellation-noctx-remaining-manifest.json`.

The schema178 exact-process-response candidate is documented in
[security testing](security-testing.md#exact-process-response-candidate-schema-178).
It adds durable intent/result delivery, pidfd and exact kernel identity checks,
protected-workload guards, tenant-scoped receipts and rolling-upgrade isolation.
Its strict kernel and disposable-child checks pass; it does not close RUN1 or
claim a deployed process-kill workflow. Source `ce667d1` images are built. Its
combined fresh178 suite passes 1,648 executions, with four explicit skips for the
opt-in kernel test and child helper across two runs; the separate privileged
kernel suite passes twice without skips. The isolated CNPG recovery drill is
being rerun after correcting fixture queue ordering: the demo seed already has
an older pending scan, so the proof job must explicitly take the first FIFO
position. The exact-job/registry assertion is retained. The retry passes scheduled
backup, WAL/PITR boundary, required extensions, retained session/configuration,
encrypted credential recovery, wrong-key rejection and restored-key recovery,
audit continuity and fresh login. The restored pod restart/reconnect takes 196
seconds (including CNPG's 180-second smart-shutdown window). This isolated
single-node proof is neither off-host recovery nor HA acceptance. The qualified
candidate is deployed as Helm77. Its unchanged bootstrap hook initially waited
for an evicted image; restoring the exact cached bootstrap image completed the
upgrade. Generated compiler cache older than 48 hours was removed to recover
19.7 GB and prevent repeated image eviction. Evidence:
`/tmp/constellation-response-ce667d1/`.

Commit `3f08263` adds DLP/signature cluster ownership checks before reads,
mutations and builtin seeding; agent bundles resolve the authenticated cluster
before seeding and cache by organization plus cluster. Configured audit failure
rolls back CRUD and builtin seeds; signature category authorization uses the
locked row. Fresh177 whole-runtime qualification passes 752 executions; the
final exact-source focused run passes 80 without skips. Owned lint and vet pass.
Evidence: `/tmp/security-dlp-qualified-db/` and
`/tmp/security-dlp-frozen-sha256.json`.

Commit `f41f2f5` separates cluster-bound runner ingest/claim routes from existing
JWT/PAT authoring routes and enforces owned-cluster selectors on user writes.
Organization-wide claims bind to the authenticated cluster atomically with an
audit event. Fresh178 qualification passes 54 executions without skips; HTTP
credential/RBAC, OpenAPI and rendered-runner chart checks pass. Evidence:
`/tmp/compliance-agent-final-db/` and
`/tmp/compliance-agent-frozen-manifest.sha256`. Claims mean accepted, not completed;
execution completion/retry remains unqualified. Ingest/enqueue atomic audit and
claimed benchmark propagation are separate follow-ups.

Commit `590084b` closes the generated/public-learned merge audit gap and makes
edge-generated policy create/update/retraction audits transactional. Row locks
preserve authored/federated rules and existing posture; concurrent first inserts
retry safely, while an edge refuses a newly appeared policy it does not own.
Audits reflect the final edge ownership marks and persisted version. The full
runtime fresh178 suite passes 802 executions without skips. Evidence:
`/tmp/security-generated-qualified-db/`. Commit `ae8cd73` subsequently makes edge
entity and membership completion audits transactional too: HTTP completion-audit
failure returns 503 and rolls back all edge/policy effects, while failed commit
acknowledgements are recorded as unknown. The full runtime suite passes 826
executions; the final receipt refinement passes 150 focused fresh178 executions,
all without skips. Evidence: `/tmp/security-edge-qualified-db/` and
`/tmp/security-edge-final-focused-db/`.

Commit `c04cf85` makes compliance ingest/enqueue audits atomic and holds exact
cluster ownership through all writes. The runner validates claim receipts and
honors the claimed benchmark, including removing a configured pin for automatic
detection; malformed receipts and redirects fail. Fresh178 qualification passes
104 executions without skips. Commit `6c4a1cc` rejects malformed, extra, oversized
and unreadable benchmark request bodies before enqueue/audit, with 40 fresh178
executions. Neither supplies a completion/retry ledger. The current deployment
has no benchmark workers; scheduled one-shot chart jobs do not drain requests.
A separately versioned execution lifecycle and opt-in worker are in progress.

Commit `bf91ead` scopes native policy tables to exact discovered pod UID and
currently registered interface addresses/MACs, fences registration/restart
changes, serializes fragments and scoped removal, and preserves default/action,
nested application attribution and ICMP behavior. Bundles require `protocol=2`;
legacy requests receive 426, requiring coordinated agent replacement and removal
of previously programmed legacy tables. Unit qualification passes 650 executions
with two DB skips, resolved by 26 fresh177 executions without skips. Independent
review caught and corrected native port/IP translation, shared-pod namespace,
keepalive-generation and nested application-rule-ID issues. These are source and
IPC checks, including Go assertions against native matcher semantics. Commit
`d28433e` adds actual unchanged native parser/staging/matcher acceptance: production
Go translation and IPC encoding feed real C control functions and native policy
lookup, with 34 assertions repeated twice, one fixture-generation test, and
malformed-command, wrong-expectation and stale-image negative controls. All
execute without skips in the dedicated harness. Ordinary integration runs skip
two explicit opt-in tests unless this harness is configured. Source/object
provenance and isolated nonroot containers are verified; no vendor source changes
are required. Live CNI interception, packet verdicts, session re-evaluation and
application classification remain unproven. Evidence:
`/tmp/run1-native-proof-hardened/`. Root
OpenAPI contracts pass. Evidence: `/tmp/run1-owned-final-manifest.json` and
`/tmp/run1-fresh177-final/`.

Commit `5c35b82` guards scanner free-capacity overflow and removes four other
unnecessary numeric narrowing conversions. Its 406 unit and 38 fresh178
executions pass without skips; five G115 findings are removed with no new lint
findings. All these post-`ce667d1` changes are combined in frozen candidate
`6c4a1cc`, under qualification at `/tmp/constellation-scope-6c4a1cc/`. Its combined
fresh178 suite passes 2,194 executions without skips. API/runtime image startup
metadata reports the exact source, and native dependencies/conntrack/BPF object
checks pass. Server-side Helm dry run changes only those images and normal hook
revision names. Exact-image isolated backup/PITR/restart qualification passes,
including 195-second restored pod restart, wrong-key rejection and retained-key
recovery. The candidate is deployed at Helm78/schema178; all seven deployments
and the runtime DaemonSet are ready. Live protocol/authentication smoke checks
pass with empty queues/policy bundle and both enforcement flags unchanged off.
The first isolated source database waited for evicted cached dependencies;
restoring their exact local images allowed the drill to proceed. Private drill
evidence: `/tmp/constellation-cnpg-test.sgYbTe/`.

Hosted run `39009181481` at `200f8c4` completed: frontend, unit, integration,
browser, FIPS, vulnerability and dependency jobs pass.
Quality remains red with 1,566 findings (previously 1,695), and gosec remains red
with 205 findings (previously 218). Gitleaks also remains red. Reports:
`/tmp/constellation-ci-39009181481/`. These reductions do not waive any gate.

Commit `1760d26` corrects canonical service linker metadata and passes source
commit/build time through release and Make builds. Six linker recipes and five
actual service binaries (including FIPS mode) report the expected triplet. The
release matrix/push inventory now includes kube-bench-runner, and published
verification uses the PostgreSQL 16.14 tag prefix. Helm source release checks
pass; mocked signature-tool dispatch confirms all 12 role references and runner
failure propagation, without claiming published signature verification. Evidence:
`/tmp/constellation-build-metadata/`.

Commit `5f1fe42` adds schema179 benchmark execution requests, token/cluster-bound
leased attempts, atomic evidence/completion audits, duplicate receipts and
reviewed retries capped at three attempts. The worker journals intent/results,
refuses uncertain reruns and requires persistent private storage. Dedicated
fresh179 qualification passes 208 race/shuffle executions without skips; scoped
lint/vet are clean. Independent review fixes configured-cluster assertion before
claim and post-lock terminal-claim races. The worker remains disabled on main;
actual bundled-image and isolated API queue-drain proof is recorded below. See
[benchmark execution](compliance-benchmark-execution.md) and
`/tmp/bench-v2-reviewed-db/`.

Commit `dd41417` adds the cluster Benchmarks tab, paged history/details and
separate queue/retry forms. Uncertain create receipts retain the same request key;
stale retries require refreshed review; technical IDs/digests remain disclosed
on demand. Focused tests pass 99 executions on Node22. The root's full pinned
Node 24.21.0 suite passes 2,336 tests without skips; typecheck and production build
pass. Evidence: `/tmp/constellation-bench-frontend-full.json`.

Commit `1cb1045` validates runtime PID/count/ring-buffer bounds and preserves
intentional bounded signature indexing. Fifteen scoped G115 findings are removed
without suppressions; configured lint decreases 183 to 168 with no new issue
signatures. Qualification passes 764 unit executions and two fresh178 DB
executions resolving the two opt-in DB skips. Evidence:
`/tmp/quality-runtime-numeric-summary.json`.

These four batches plus prior edge-entity auditing/native tests are combined in
frozen candidate `1cb1045` at `/tmp/constellation-bench-1cb1045/`. The combined
fresh179 suite passes 2,304 executions with eight explicit opt-in native/kernel
fixture skips. Dedicated earlier native/kernel evidence remains separate. All
four API/runtime/migrate/frontend artifacts are built; startup metadata and
native dependencies pass. A fresh178→179 upgrade preserves every legacy request
field and confirms the unchanged legacy claim SQL cannot consume v2 queued work.
Exact-image CNPG/RustFS backup/PITR, authenticated restoration, wrong-key rejection,
retained-key recovery and a 196-second database-pod restart pass. The fresh main
backup completed, followed by a successful Helm79/schema179 rollout. Live health,
readiness and existing agent route-boundary smoke pass; all workloads are ready.

The actual worker image at `610ad3d` bundles upstream kube-bench v0.10.7 and all
204 configuration files. A real check exposed missing `/bin/ps`; the canonical
image now installs procps, with process-discovery probes passing. A controlled
lost-result-acknowledgement fixture confirms same-attempt replay after both
processes restart. A separate real API/schema179/PostgreSQL16.15 fixture proves
user queue→bound agent claim→actual upstream execution→durable receipt, two
source controls (one PASS/one FAIL), two evidence rows and one completion audit.
Recreating API, worker and database while retaining only the owned database and
spool volumes preserves exact receipt/evidence timestamps without another run.
This is two-check container execution and restart persistence, not host/fleet
assessment, backup restoration or airgapped acceptance. All owned fixture
resources are removed. Evidence: `/tmp/constellation-bench-runner-610ad3d/` and
`/tmp/constellation-bench-real-e2e/evidence/summary.json`.

Commit `e184538` rejects new application IDs outside the actual native uint16
range before persistence or alerting and removes signed comparison aliases.
Fresh179 qualification passes 44 race/shuffle executions without skips; vet and
changed-source lint pass with five G115 findings removed and no new findings.
Commit `10018b8` removes two obsolete unused policy helpers. These later source
changes are not in the frozen `1cb1045` deployment candidate. Threat-ID uint32
storage and historical aggregate repair still require a separate migration.
Earlier hosted quality at `21b7c73` reports 1,548 findings; security and quality
remain blocking, with no gate waiver or historical secret rewrite.

### Further qualified source and runtime rollout

Runtime `950ca77` refuses redirects before telemetry bodies can be replayed or
a destination acknowledgement can discard queued data. Its full fresh179 suite
passes 582 executions with four explicit opt-in fixture skips. Exact image
startup metadata and unchanged native/BPF dependency hashes pass. Helm80 deploys
that runtime with the existing execution dry-run flag persisted in Helm; all
other workload specs and schema179 remain unchanged. The node had evicted the
unchanged bootstrap/migration images; reimporting the exact prior qualified
artifacts completed the rollout. Future deployment preflight must check every
regular and hook dependency image, not only changed images. Live health, bundle
protocol and response authorization smoke pass; enforcement remains disabled.

Schema180 source `5b82b12` passes 2,930 combined fresh-database executions without
failures/skips and 2,344 frontend tests on pinned Node 24.21.0. A full migration-chain
179→180 drill preserves every non-target field and traffic counter, repairs only
proven retained cohorts, repeats without changes and rejects unsafe Down without
mutation. API/migration/frontend image payloads and exact build provenance pass.
A fresh main backup completed. Exact-image CNPG scheduled RustFS backup/PITR,
existing session/configuration/encrypted credentials/audit/login, wrong-key
rejection and retained-key recovery pass. High unsigned IDs and incomplete
aggregate metadata remain identical after restore and PostgreSQL pod restart
(201 seconds). Owned namespace and PV cleanup completed normally. This is a single-node,
same-host recovery proof. Controlled main rollout completed at Helm81/schema180.
The original final verifier counted a historical Succeeded frontend Pod and held
the API off after successful Helm completion. Exact deployment UID/template,
active ReplicaSet ownership and OCI identity verification restored the qualified
API; no old binary or schema rollback occurred. Evidence:
`/tmp/constellation-threat180-5b82b12/`.

PCAP source `68e75a6` confines private atomic uploads/downloads/removal and holds
the exact capture row through completion, preventing deletion races and false
success after database failure. Sixty-four fresh179 executions pass; scoped lint
removes four findings with none added. Source `638ca7e` prevents status-only
completion and late failure notifications from downgrading committed uploads;
downloads verify actual size and SHA256 before returning bytes. Sixty-two focused
fresh180 executions pass, plus six API-contract executions. Full runtime
qualification passes 890 executions without skips. An actual isolated RWO PVC
retains a synthetic capture through Recreate API replacement: identical bytes
and SHA256, unchanged PVC UID, private 0700/0600 permissions, same session and
terminal-state rejection. This does not qualify real capture, shared RWX, node
loss or off-host recovery. Evidence: `/tmp/pcap-pvc-proof/result.json`.
Chart support requires
an explicitly owned Bound filesystem claim: one replica/Recreate for RWO, shared
RWX for multiple replicas. No ephemeral-storage durability claim or main PVC
enablement is made. A failed or unknown completion can leave a complete private
orphan for reconciliation; it never returns a false successful receipt.

The isolated Flannel fixture now reaches actual native packet processing. One
explicit monitor allow traversed NFQUEUE and matched native RID11. The strict
24-probe acceptance then failed: unmatched monitor traffic produced OPEN/RID0
with TmpOpen=true instead of the required violation. This exposes native
unknown-peer grace beyond the earlier matcher proof; protect/other-scope/restart
acceptance is not claimed. All owned resources were removed, and main enforcement
remains disabled. Scoped default-rule translation is committed as `6a8057c`; arbitrary
policy-address membership and a global strict-mode toggle are rejected because
they change scope or direction semantics. Immutable evidence:
`/tmp/constellation-flannel-policy-reviewed/attempt-native-temporary-open-confirmed-20261017/summary.json`.

Hosted `21b7c73` security triage reports 190 gosec findings and 11 gitleaks
occurrences (nine confirmed benign fixtures/prose/storage keys and two historical
operational credentials). Full-history remediation and external trust coverage
remain unresolved. No allowlist or history rewrite was applied. That run was
subsequently cancelled by a newer push; latest-head checks remain separate.

Native fix `6a8057c` appends finite-order, endpoint/direction-scoped terminal
rules after authored rules and ICMP normalization. It preserves default RID0
and avoids unknown-peer temporary-open grace without changing vendor code,
global strict mode or peer membership. Expanded tables are capped at 65,536
rules before allocation/IPC; rejected candidates preserve prior confirmed source
and report uncertainty. Agent/DP race qualification passes 796 executions; two
DB-gated skips are separately resolved by fresh180 replay tests. Real native
full-wrapper/keyed acceptance passes 70 assertions twice, including negative
controls. These controlled tuple tests precede the actual Flannel results below.
Evidence: `/tmp/constellation-terminal-default-638ca7e/`.

PCAP persistence review found no existing main capture records/files, but expiry
metadata had no production cleanup caller. Durable storage enablement is held
for bounded, fair, cancelable retention qualification and explicit shared-root
configuration. A 2Gi local-path request is not a hard quota. Existing isolated
synthetic capture persistence proof does not establish aggregate capacity bounds.

Hosted run `39013221479` at `5b82b12` completes unit, integration, frontend,
browser, FIPS and dependency/vulnerability checks successfully, while quality
(1,535 findings), gosec (179) and historical gitleaks (11) remain blocking.
The import-format issue is corrected in `c9b6a66`; unsigned smoke counter narrowing
is corrected in `5642dca`. Later source requires new hosted checks. No gate waiver,
blanket suppression or historical rewrite is applied.

Further source fixes are committed through `7d54c3d`, not yet deployed:

- SAML `69a1db9` query-escapes opaque RelayState before the library builds/signs
  its redirect. The unpatched negative control injects query fields/fragments;
  all 188 auth executions pass after correction. A narrow G710 annotation records
  the reviewed administrator-configured IdP destination boundary. Test helper
  cleanup `c42d85b` leaves no new auth lint findings; no broad suppression is used.
- Federation `8e50edf` binds the configured deployment token to its exact normalized
  configured master URL. Alternate destinations require an explicit caller token.
  The actual hostile TLS receiver receives no implicit credential; 34 fresh180
  and 28 focused executions pass with no added lint findings.
- Registry `7d54c3d` rejects Harbor/GitLab page read/close errors and overflow,
  including failures after valid-looking JSON or on a later page. Invalid request
  errors omit endpoint credentials/query data. Ninety executions pass; two lint
  findings are removed. Follow-up `b862c65` checks twelve remaining enumeration/authentication
  reads across ten primary connectors and six auth flows. Its 240 race/shuffle
  executions pass without skips; 48 unpatched negative controls fail as expected.
  Failed tokens are not cached; GitLab tags/JFrog per-repository fallback is preserved.
  Scoped registry lint drops from 30 to 19 with no additions.
- Retention `8e67508` adds explicit chart-gated, leader-cancelable cleanup on a
  pinned durable root: 100 candidates per cycle, fair UUID cursor, exact expired
  row locking and removal-failure retry. Missing/replaced roots retain receipts;
  no arbitrary orphan scan is added. Eighty-eight fresh180 and 21 chart tests pass.
  This is not a byte quota or an off-host storage claim.
- Broader runtime/server qualification at `8e67508` exposed a shared-port-slice
  normalization race: 1,345 passes, one race failure, no skips (server436 passes).
  `5328083` copies the port list before validation. The new regression fails on
  original source; the fixed whole netpolicy package passes ten race/shuffle
  repetitions. Existing caller normalization/audit behavior is preserved. The
  combined `7d54c3d` candidate passes 2,926 fresh180 executions without skips
  across runtime/server/handler/auth/registry/netpolicy. The exact API/CLI image
  passes actual PVC replacement and leader-driven expiry acceptance: identical
  uploaded bytes/hash survive a changed API Pod on the same claim; the elected
  one-minute background loop removes two expired receipts and the expired file
  while preserving unexpired evidence. Private permissions and same-session
  access pass. Owned namespace/PVC/PV/tunnel cleanup is complete. Evidence:
  `/tmp/pcap-retention-pvc-proof/evidence-manifest.json`. Main enablement awaits
  a reviewed rollout; this does not qualify real capture, RWX or node failure.

The first real Flannel run with exact `6a8057c` passes four baseline and all four
monitor probes, including unmatched violation/RID0 without temporary-open grace.
It then fails at protect-a named allow: the exact request reaches the server and
NFQUEUE advances, but no fresh matching native event is received under the strict
barrier. No protect-mode pass or wrong-action conclusion is claimed. Native
aggregate timestamp and clock-phase semantics are under investigation; bounded
diagnostic work does not relax acceptance. All owned resources are removed.
Evidence: `/tmp/constellation-flannel-policy-terminal6a8057c/` (54 sealed files).

The diagnostic-only follow-up retains exact `6a8057c` production code and passes
all 24 real packet probes: five denied requests, 19 exact server observations
and 16 fresh native-verdict probes across monitor, protect, scoped policy change
and owned-native-process stopped bypass. The Python verifier initially compared
Go's base64 MAC bytes with a colon-form endpoint string and rejected the proof.
Fix `b4fb38d` decodes exactly six bytes; malformed/foreign MAC, stale timestamp,
wrong source, missing verdict/queue and denied-server controls remain rejected.
Independent revalidation of byte-identical evidence passes; the original exit1
is preserved. All nonce-owned Docker resources are removed. This qualifies only
the disposable single-node Flannel fixture, not other CNIs, BPF, HA or node loss.
The prior missing-event run remains a real failure; this pass does not establish
its cause. Evidence: `/tmp/constellation-flannel-mac-revalidation/` and original
52-file seal `bd7a0c26ce2b4246008f92fcb55976a3f0add9152ff98de398a2c6e2543da9cb`.


Hosted run `39016297844` at `f309982` reports 172 gosec findings. The quality
job stops before lint because the new chart test imports undeclared PyYAML.
`e4a8d7f` installs PyYAML 6.0.3 and Helm 3.21.0 explicitly and audits the Python
test dependency. All 110 tooling tests pass in an isolated local Python 3.14.4
environment. Hosted `39016927220` then passes the pinned Python 3.12.14 tooling,
endpoint/plan, format, shell and workflow checks. Quality reaches the lint gate
and reports 1,515 findings; gosec remains 172. Main stays on Helm81; these source
checks do not establish release completion.

A local-only history candidate from `e4a8d7f` preserves 585 commits/44 local refs
outside four exact redacted credential blobs and one explicitly removed invalidated
signature. Eight synthetic tests and all-object secret-removal checks pass; private
original backups are separate. Unmodified full-history gitleaks remains nonzero
with 19 classified benign/redacted-context findings. No published refs or trust
material were changed. External key-use information and an explicit reviewed
public-history decision remain outstanding; this stale snapshot cannot replace
later branch work. Evidence: `/tmp/constellation-history-local-20261017-3115588e/`.

Source `5b417c0` additionally rejects incomplete, oversized, malformed or null
session-control responses and preserves the applied weak-TLS setting when the
server omits it. Explicit true/false still apply. Seventy repeated race-test
executions pass without skips; eight unpatched negative-control executions fail
as expected. Runtime package lint remains 107 findings with none added; existing
upload-loop complexity decreases from 31 to 30. This is not yet deployed.

Source `16956f6` makes quarantine snapshot output private and atomic through the
shared securefiles streaming writer. Producer, sync, stat, close and publication
errors propagate; root substitution cannot return a misleading artifact path.
Forty-two core and 176 fresh180 consumer executions pass without skips; scoped
lint falls from ten to four with none added. Restore and best-effort collection
semantics remain unchanged. Snapshot collection is currently a library path,
not an active production integration.

Source `faf627d` initializes the actual native connection lookup key and sets its
application identifier before lookup. The reporter regression passes 97 assertions
under both standard and deterministic initialization flags; the unpatched control
reproduces duplicate connection buckets. Existing matcher assertions pass 70×2.
Declared vendor patches and sync/restore handling now have 14 shell/Python tests.
The initial native proof explicitly reused seven verified objects; a full native
rebuild is in progress and no new runtime image is deployed. Evidence manifests:
`/tmp/constellation-native-connect-package6a8057c/review-manifest.json`,
`/tmp/constellation-quarantine-private-1304c6f/frozen-manifest.json` and
`/tmp/constellation-session-control-review/qualification-summary.json`.

Hosted `39016927220` has completed: unit/integration, browser, frontend, FIPS
and all dependency checks pass. Quality, gosec and historical gitleaks remain
blocking failures. No broad scanner exclusion or lowered threshold was added.

Source `fcfe91b` also fixes the server side of session controls: an operational
threat-setting read error returns a categorical 500 before consuming pending
kills, while the committed snapshot remains retryable. Missing settings still
deliberately default false. The full network package passes 214 fresh180 repeated
race tests without skips; the unpatched permission-denied fixture fails twice
with a false-disable response and lost pending command. Scoped lint adds nothing.

Combined exact `5b417c0` passes 3,700 fresh180 repeated race executions with zero
failures. Four explicit harness skips remain: native-generator and isolated
Flannel tests, each twice. They are not excluded or counted as packet proof.
The separate canonical full native rebuild at `faf627d` passes all matcher and
reporter assertions without object reuse. A canonical optimized production DP
build at `5b417c0` compiles 51 C units; all 23 linked runtime dependency files
match the qualified base byte-for-byte. New agent/native binaries are assembled
with unchanged BPF/base layers and verified hashes/modes in candidate
`controls-20261017-5b417c0-r2`; its actual packet acceptance fails as detailed below.
An initial private assembly had agent mode0700 from the host umask; its image is
preserved and explicit0755 COPY fixes the candidate. Neither image is deployed.
Evidence: `/tmp/constellation-combined-5b417c0-db/evidence-manifest.json`,
`/tmp/constellation-native-full-faf627d/review-manifest.json`,
`/tmp/constellation-native-prod-5b417c0/review-manifest.json` and
`/tmp/constellation-runtime-combined-5b417c0/image-manifest.json`.

The combined runtime's first isolated attempt stopped before traffic because an
inner test still pinned the previous image. A second attempt corrected only two
test image literals and retained every strict acceptance condition. Four baseline
and four Monitor probes pass, including four fresh native verdicts. The first
Protect allow reaches the expected server and advances its queue from 20 to 30,
but no fresh matching native verdict arrives within 35 seconds. Acceptance fails;
Protect and denial behavior are unqualified for this image. The cause remains
under investigation. All nine owned resources are verified absent; both failed
runs remain preserved. This does not invalidate or extend the separate earlier
24-probe proof for `6a8057c`. Current failure evidence:
`/tmp/constellation-flannel-policy-controls5b417c0-attempt2/actual-packet-evidence-manifest.json`
(SHA256 `0cd69c8d0dbd6a9d7368963e2c2238075a9b537793ee2c4bef451c77701e0615`).

Main is now **Helm82/schema180**, with API source `7d54c3d` on its retained
RWO capture volume and leader-driven retention enabled. Runtime remains
`950ca77`; migration/frontend remain `5b82b12`; other roles and hooks are unchanged.
The fresh CNPG backup completed at 08:56:55 UTC before the controlled API replacement.
Exact API/CLI binaries, volume identity and Retain policy, 0700 capture permissions,
new leader ownership, health/readiness and protocol/tenant boundary reads pass.
Live queues are empty, so positive execution remains separate fixture evidence.
The 2Gi local-path request is not a quota; real traffic capture, node loss and
off-host recovery are not established by this rollout.

The initial storage attempt stopped before API shutdown because admission
rejected the provisioner helper's stale scan. A reviewed single-operation helper
used the deployed API's official target upsert and atomic audit transaction to
queue the exact immutable image, without impersonating a user or altering policy.
Its disposable schema180 checks pass 22 repeated race executions plus seven
wrapper guards. The real scanner completed at 09:25:00 UTC: exact digest and
linux/amd64, successful Syft/Trivy/Grype, one busybox 1.37.0 package, two medium
and four low findings, none with fixes. The original PVC then actually bound
under the unchanged policy. Recovery preserved the failed receipt and exact
resource identities. A second check stopped on an inherited setgid bit; clearing
only that bit changed the same empty directory from 2700 to 0700. The verified PV
was set to Retain and only the owned bootstrap Pod removed before the upgrade.
Original failures, scan results and successful deployment are sealed in
`/tmp/constellation-pcap-main-7d54c3d/evidence/deployment-manifest.json`
(SHA256 `eeaf02b7d276c9c0679fca7151a557e6628cbdfafa638bb11753adefe81f9f13`).

Source `4e5b62c` makes API/scheduled backup filenames unique to their existing job
IDs and publishes completed private archives atomically. CLI output paths and
regular-file overwrite remain supported without changing caller directory modes.
Explicit directory configuration failures no longer silently fall back. Legacy
external download paths remain usable with checked file identity and safe headers;
retention preserves artifacts referenced by another catalog row, including foreign
or null-owned rows. This does not provide a filesystem/database transaction,
repair old overwritten files, or fix the separate CLI S3 naming paths.

Backup qualification passes 366 fresh180 repeated race executions with no test
skips, plus 32 preparation unit executions. Both CLI consumers compile; the
standalone backup command has no test files. Original writer and scheduler
negative controls each fail twice as expected. Vet passes; scoped lint decreases
447 to 443 with no new findings. One test-only G306 annotation deliberately keeps
an existing 0644 hardlink fixture to prove private replacement without changing
the original. No production suppression or scanner configuration changed. These
backup and later session-server fixes are not in the deployed `7d54c3d` image.
Evidence: `/tmp/constellation-backup-artifacts-fcfe91b/frozen-manifest.json`
(SHA256 `8223867e0cc9634214d2967c4ed33304802147115bd2743e4d686a0dc0d85f85`).

Hosted `39020011292` at `29a11dd` has completed: unit/integration, browser,
frontend, FIPS and dependency/vulnerability checks pass. Lint1509, gosec166 and
historical gitleaks remain failed. These are blocking results, not a baseline
waiver. No overall parity acceptance row is closed by these bounded corrections.

Source `46df2d6` closes a remaining proxy-header rate-limit bypass. The trusted
socket peer is checked before client-IP resolution; only `X-Forwarded-For` is
used, walking trusted hops from right to left until the first untrusted address.
Client-controlled prefixes, `True-Client-IP` and `X-Real-IP` cannot override that
address. Missing/invalid trusted suffixes and excessive chains retain the socket
address. Explicit federation transport trust is unchanged. Broad private-network
defaults remain a documented compatibility assumption; operators must configure
actual proxy ranges and append or overwrite verified forwarding evidence.

The full server package passes 494 fresh180 repeated race/shuffle executions,
with zero skips. All three spoofing paths defeat the original limiter twice;
the candidate rejects request11 and preserves the caller's request. Vet passes.
Compared with hosted39020011292, scoped server lint decreases74→73 with no added
findings; the remaining73 still fail the unchanged gate. No scanner settings or
production suppressions changed, and this source is not yet deployed. Evidence:
`/tmp/constellation-client-ip-a6b20a2/evidence-manifest.json`
(SHA256 `d6f355dc918af69ee6c9c52365e5078d74a4fd234f3f46330bd929a49d96a14b`).

Hosted `39022267072` at `a6b20a2` has completed. Unit/integration, browser,
frontend, FIPS, dependency and govulncheck jobs pass. Lint1505, gosec 163 and
historical gitleaks remain blocking; the required gate fails. These counts
precede `46df2d6`; they do not qualify later signing or CLI changes.

Source `76c3262` validates backup signing requests before job, audit or artifact
creation. A bounded 64KiB single JSON object rejects malformed/trailing documents,
duplicate or unknown fields, null/non-string modes and unknown enum values.
One-off empty bodies/omitted modes still mean `none`; schedule omission still
means `static-key`. Both workers validate again, preventing an unknown mode from
silently producing an unsigned successful archive. Valid modes with unavailable
signing infrastructure fail asynchronously without publishing an unsigned archive.

Qualification passes 88 unit and 266 selected fresh180 repeated race/shuffle
executions with zero skips, plus vet. Scoped lint remains340 with no added
findings or suppressions. Eight failed original-worker test executions confirm
the prior false-success behavior; the initial unused-import compilation failure
is preserved separately. All three owned database fixtures are verified removed.
This source is not yet deployed; CLI flag/transport work remains separate.
Evidence: `/tmp/constellation-backup-signing-4e5b62c/evidence/frozen-manifest.json`
(SHA256 `3b12d66aa6e9f45533f9f1c2cb54c93b4945fa426ccdd5c3e6e8bb8822fe680d`).

The strict diagnostic run of the unchanged `5b417c0` runtime candidate records
18 probes, of which 17 complete all criteria (13 fresh native verdicts and four
qualified denials); it does not pass the required 24 probes. Probe18 reaches the
exact server endpoint and advances its queue46→56. Its post-cursor native Allow
record has the expected endpoint, IPs, TCP port18081, application1001 and RID11,
but reports FirstSeenAt/LastSeenAt1792232195 against StartedAt1792232196. A later
end record repeats that timestamp. Raw receipt times prove the report arrived;
the freshness predicate, rather than missing export, rejects this observed case.
The native coarse clock is a supported cause of this one-second discrepancy;
causes of prior runs without raw records remain unproven. The diagnostic leaves
the strict matcher, 35-second deadline and 24-probe matrix unchanged. All nine
owned fixture resources are absent. Root verification matches all 76 evidence
sizes/hashes. No runtime rollout or acceptance row follows from this failed run.
Evidence:
`/tmp/constellation-flannel-policy-clock-diagnostic5b417c0/actual-packet-evidence-manifest.json`
(SHA256 `2c5828967f4d96c1c3040bb117caf5ea626152134bc690b92d3989737ac77b2e`).

The additive OpenAPI correction `f3cc8c5` documents the signing contract and
actual one-off202 asynchronous receipt / schedule200 response. Static checks
cover 48 positive/negative instances, 891 local references and unchanged other
operations/existing schemas. Hosted run 39024761342 at ef0d7a9 also passes
TestGenerateOpenAPI, TestOpenAPICompleteness and TestOpenAPINoNewStubs. This
qualifies the contract checks, not deployment. Static evidence:
`/tmp/constellation-backup-signing-contract-76c3262.l30cb6p5/evidence/frozen-manifest.json`
(SHA256 `9b1d26bdb72e3fc6affe830528c9388e5b5ba5c0a74341b0a7e7c024312f77c7`).

Hosted `39024761342` at `ef0d7a9` has completed: Go unit/integration, browser,
FIPS, dependency and govulncheck jobs pass. Frontend fails one timing-sensitive
compliance sorting test; quality reports 1504 findings, gosec 163, and historical
gitleaks remains failed. The required gate fails; no thresholds or exits changed.
Completed CI and the bound OpenAPI/lint/security checkpoint are recorded in
`/tmp/security-triage-39024761342/completed-manifest.json`
(SHA256 `c6fe1fa6ae88aae26fb8dd0984de7ae14c39c32799a24e9d22aef38e06a7c99c`).

Test-only correction `730e531` holds the sort response until the loading state is
observed, then waits for the rendered ascending header before asserting history
navigation. This removes the request-versus-render race while retaining server
sorting and row assertions. All 15 focused tests and all 2344 frontend tests across
158 files pass on Node 24.21.0. The other 598 frontend blobs match ef0d7a9; no product
code or warning suppression changed. This local result does not rewrite the
failed hosted run. Evidence:
`/tmp/constellation-compliance-sort-ef0d7a9/evidence-manifest.json`
(SHA256 `f84cd7428cdc606fe8350c721aeed32c30bec112878359d322dd0305aa71aa29`).

Source `be15c7c` requires complete discovery/token HTTP responses before OIDC
identity acceptance. Decoded bodies are capped at 1 MiB; read and Close errors,
invalid documents and unsuccessful provider responses produce categorical
errors. The browser callback returns 401 without provider response/URL details.
Normal signature, issuer/audience, nonce, PKCE, roles and valid-session behavior
remain; JWKS response policy and provider redirects are separate unchanged work.

Qualification passes 482 fresh180 repeated race/shuffle test executions without
skips, plus 78 focused unit executions and vet. Scoped lint decreases 333→331 with
no added findings or suppressions. Original signed-token controls fail eight
expected executions; malformed-token controls still reject. Ten original browser
failures include four concrete truncated/oversized response cases that issued a
303 response, one session and two cookies. The candidate rejects those responses
without issuing sessions/cookies and records the failure audit. Both owned
PostgreSQL fixtures are absent. This source is committed but not deployed.
Evidence: `/tmp/constellation-oidc-response-ef0d7a9/evidence/frozen-manifest.json`
(SHA256 `b95a28d4c62fe3e1b6138d701a09cc357616ed275e7c73581e7edf64395c088c`).

Source `7d51fa8` completes the CLI artifact boundary: job-unique S3 names, private
workspaces, checked completion/catalog receipts, pinned upload files and strict
signing flags. pg_dump receives a private libpq service profile instead of a DSN
in its arguments; password remains in the child environment. Bounded complete
service reads reject a valid truncated prefix before it can choose a target.
Help/parse failures no longer expose inherited database/endpoint defaults.
Signature inspection caps all decompressed bytes at 512 MiB, including framing and
trailing data, and validates the gzip trailer. Actual S3 service acceptance and
full disaster recovery remain unqualified.

The original CLI snapshot passes 208 top-level /402 including-subtest fresh180
race/shuffle executions without skips, vet and builds. A network-none real PG16
fixture checks URI/keyword/multihost export, authentication/TLS failures, private
modes, redaction and readable dump contents; eight owned containers are absent.
The two-file bounded-reader follow-up separately passes 30 standalone repeated
race/shuffle executions, tagged vet, a fresh build and actual help. Its negative
control reproduces the exact original valid-prefix/omitted-target failure.
The original full DB/PG16 proof is retained as ancestor evidence, not relabelled
as an exact-source follow-up integration run. Scoped original lint decreases
48→42; follow-up standalone lint remains6. Reviewed new gosec findings remain
open, with no production suppression or gate waiver. No main rollout occurred.
Combined source/evidence seal:
`/tmp/constellation-backup-cli-service-bound/FINAL-SEAL.json`
(SHA256 `b1859c18e464706cf9a3563c09f4f0d51a9aba273c546f8adfb1b85a619c99ab`).

Source `0f33141` makes standalone scanner output truthful: --sarif writes the
shared SARIF 2.1.0 representation, and JSON/SARIF publication must finish before
scan completion is logged. Output flags require --ref; conflicting destinations
are rejected. The existing pinned-root private atomic writer preserves prior
reports on encoding/write/cancellation failure. Parents must already exist and
retain their permissions; publication is per file, so an earlier complete report
remains when a later output fails.

The scanner, shared writer and SARIF packages pass204 repeated race/shuffle test
executions with no skips. Vet passes. Scoped lint 44→43 removes the permissive
output-file finding; existing main statement complexity moves 67→68 and nested
complexity 7→6. No new issue location remains. One test-only G204 annotation
explains execution of the current os.Executable test binary with fixed arguments;
no production suppression was added. Original lint attempts are retained.
The source is committed but not deployed. Evidence:
`/tmp/constellation-scanner-output-ef0d7a9/evidence-manifest.json`
(SHA256 `f2e3da18c458a0c7c64e4074a8a5cb2798ad7f4d99bc5aed79d781a5a0541a15`).

Source `ad0a3a1` uses checked wall time for native connection reports while
preserving the existing coarse timer used for expiry and rate accounting. The
reported timestamp subtracts the existing Idle duration; nonzero Idle remains
an approximation of historical last activity. Failed, negative, overflowing or
underflowing time values are rejected before connection-map/counter mutation.
The strict packet matcher, 35-second deadline and 24-probe matrix are unchanged.

Fresh native tests pass both reporter variants with 97 existing plus 66 new
assertions each. Reversing the clock patch reproduces the exact one-second
mismatch; the existing application-key negative remains. The generator and two
race/shuffle parser/matcher executions pass without skips, including 70 matcher
assertions per execution. Seven vendor-sync tests pass, and the imported shell
scripts pass ShellCheck. The normal production daemon compiles all 51 C units
with canonical -Os flags, required libraries/rpath and no test time wrapper.
Its 23 linked library hashes and package inventory match the qualified parent.
DP SHA256: `e00f06c52439f109c8e95c225eec94e94766b643ff1b697124c6a14934a84eb3`.

Qualification preserves the failed builder-format preflight, raw-index FROM
attempt and subsequent make failure. The production recipe was corrected to
use the locally verified tag, canonical serial make without command-line linker
overrides, and visible compiler failures. The hidden make error from the earlier
attempt remains unproven; the final corrected build and verification pass.
Evidence binds the ten-file overlay on f3cc8c5 through local-only synthetic
snapshot e0e3fa775a59; it is not a published release identity. The new integrated
Go runtime and strict packet run are still required before runtime rollout.
Final 90-file evidence seal:
`/tmp/constellation-native-report-clock-f3cc8c5/qualification-final-evidence-manifest.json`
(SHA256 `3ef9ba77742f7289e550d9913397b4b15c98331abecc261a0fb86406339e7a87`).

Hosted `39026348360` at `c309a21` completes frontend (2344 tests/158 files),
browser (279 cases), Go unit/integration, FIPS, dependency audits and govulncheck
successfully. Unit/integration report 732/14 skips. Quality remains1504, gosec163
and redacted historical gitleaks11; the required gate fails. Formatting, shell
lint, actionlint, tooling, endpoint mapping and parity-plan checks pass. Normalized
lint identities match the prior ef0d7a9 run. This qualifies the sorting-test
correction without changing the previous failed result; later backend commits
are outside this hosted run. All22 evidence artifacts are independently verified:
`/tmp/security-triage-39026348360/completed-manifest.json`
(SHA256 `174ab5baf6da151fa1496382c256747a4d7e66f759d3c63fa54356b30cf6ebd8`).

Combined exact source `314afad` passes 4586 fresh180 repeated race/shuffle test
executions across14 packages, with zero failures and four explicit opt-in skips
(native fixture generator and Flannel acceptance, twice each). Both migrations
and seeding complete; all2596 tracked source blobs remain unchanged and the
owned PostgreSQL container is absent. This includes the final bounded-service
backup CLI source together with OIDC, scanner, backup, server and runtime changes.

The first launcher incorrectly inherited umask077, producing four permission
fixture failures before being stopped with exit143. Those results are preserved.
The two affected tests pass four executions with child umask022, then the entire
combined run passes with that same mask. No product change or weakened assertion
was needed; evidence remains private. This is combined backend qualification,
not strict packet acceptance or deployment. Evidence:
`/tmp/constellation-integrated-314afad/combined-db-evidence-manifest.json`
(SHA256 `024399a77d511e9f94136c81c6db78c8d76140a887ce2b53f23c4258f81cc760`).

Exact `314afad` now has five fresh Go1.26.9 linux/amd64 binaries and three
qualified local image assemblies (API/CLI, scanner and runtime). The runtime
packages the fresh integrated Go agent and the normal production DP above;
all95 native vendor files match the qualified source. Base layers/configuration
and BPF remain verified. Images pass nonroot payload readability and0755 modes;
API/CLI/scanner also execute --help successfully. The runtime has no CLI help
mode; that extra smoke invocation timed out and was removed, with no runtime
help pass claimed. This was local artifact assembly over qualified bases, not
a fresh full Docker/native/BPF pipeline rebuild. The52-artifact image seal is
`/tmp/constellation-integrated-314afad/image-qualification-manifest.json`
(SHA256 `8bdc02411d6cff62b667e2c1ac95750a86d46c29f416ed1066bb9abbe052b717`).

The actual strict Flannel run on runtime index9df9ce866d0d passes all24 probes:
five denied,19 server observations and16 fresh native verdict checks, including
policy changes and DP-stopped bypass. Independent verification uses the unchanged
matcher/deadline/matrix and byte-identical actual inputs. All26 raw post-cursor
records remain available; every accepted native payload appears in that capture
and has FirstSeenAt equal to the probe start, including the previously failing
change-a/server-a/18081 case. Nonzero Idle remains an approximation outside
these observed cases. All23 actual linked-library hashes match the qualified
production build. All nine owned resources are absent by recorded identities;
all250 artifacts from four previous failed runs remain unchanged. This qualifies
the disposable single-node Flannel fixture, not BPF, other CNIs, off-host recovery,
real node failure or main-cluster enforcement. Main rollout remains separate.
The119-artifact completed seal is
`/tmp/constellation-flannel-policy-clock314afad/actual-packet-evidence-manifest.json`
(SHA256 `a524f229aefd20ed7d54fb4be81055b8cad119ac394a6b37bf26222a9d225327`).

Hosted `39028433987` at exact `314afad` is completed. Frontend passes2344 tests
across158 files; browser passes279 cases. Go unit/integration, FIPS, govulncheck
and all dependency jobs pass. Gotestsum reports3642 unit tests including737 skips
and8302 integration tests including14 skips; these totals are not zero-skip
qualification. Configured lint decreases1504→1495 and standalone gosec163→156;
historical gitleaks and the required gate still fail. Four added standalone
occurrences remain at reviewed CLI local-file/subprocess boundaries; the net
decrease does not imply no added findings. Previous checkpoints and report/ZIP
hashes are preserved. No gate waiver or overall release-complete claim follows.
Completed evidence:
`/tmp/security-triage-39028433987/COMPLETED-MANIFEST.json`
(SHA256 `7731efd3a798b8fed77c90092b6e3eeb69b89d373eca33eb681ad8193aecf889`).





## October 12 implementation continuation

The user selected **Astronomer-style console behavior and workflows** as the
current delivery scope. Broader NeuVector security, infrastructure and provider
qualification requirements remain tracked separately in this canonical plan.

The main development deployment now uses **PostgreSQL 16.14 on CNPG**, schema
**172**, under Helm revision **20** (cutover at revision 19). Its frozen-source transfer matched all
**138 public root-table counts** and the audit head before changing the DSN.
The old StatefulSet is stopped with its PVC/credentials retained. Fresh browser
login and authenticated cluster, scan, settings and registry checks pass;
continuous WAL archiving and daily Barman/RustFS backup are configured. The first
main backup and a separate-cluster restore passed session, login, settings,
encrypted-credential and original audit-anchor checks. A follow-up chart fix
preserves admission CA trust across upgrades with hooks disabled; revision 20
passed both unknown-image denial and scanned-image allow dry runs. See the
[main cutover evidence](cnpg-recovery.md#main-development-cutover). Earlier dated
StatefulSet/schema-167 observations below describe the pre-cutover deployment.

Login now follows Astronomer's configured-provider behavior: unavailable SSO
buttons, divider and copy are hidden. Public provider discovery exposes only
OIDC/SAML availability; disabled live providers do not fall back to old environment
configuration. **149 frontend tests**, production build, focused race/API tests,
real-browser verification and changed-code lint pass. No checklist item is closed
by this bounded login or single-node database increment.

The registry credential continuation is deployed at Helm revision **21** with
`constellation/api:registry-leases-20261012` and
`constellation/scanner:registry-leases-20261012`. Credential release now requires
the same-org image target, its configured registry, an active job lease, and the
claiming scanner token/instance. Claims include `registry_id`; requests include
`job_id`; issuance is audited without secrets and responses prohibit caching.
Cosign uses the same isolated per-job Docker config as the scan engines, and
explicitly anonymous registry jobs cannot inherit ambient Docker credentials.
Credential requests reject redirects and oversized responses. One-shot
configured-registry scans require the claimed `--job-id` and matching instance.

Validation: **2,046 seeded, repeated race-test executions**, zero skips, **98
tooling tests**, focused scanner/signature/OpenAPI tests and changed-code lint
pass. The live API and fresh scanner image scanned a temporary authenticated TLS
registry image with Syft, Trivy and Grype; cosign verified its public-key signature.
Pending, other-instance, expired and completed jobs could not obtain credentials.
Successful and wrong-password scans removed their temporary credential configs;
local tests also cover cancellation. Three redacted issuance receipts and the
completed result `e04bfa00-b3ff-4529-96a3-c969637913ba` were persisted. Authenticated
result, signature, package and layer endpoints return the evidence. Temporary
registry, token and job fixtures were removed, and both deployments are ready.
Collaborative browser DOM inspection verifies the stored signature, package,
layer and config-check evidence; screenshot capture was unavailable. Private cloud-provider
connectors, refreshable tokens and the broader tenant-scope gates remain open.

The scan-evidence continuation is deployed at Helm revision **23**. Image-result
list/detail APIs now expose normalized `engine_status` with OpenAPI schemas.
The image detail page follows the Astronomer-style page contract: one verdict,
five metrics, and URL-linked vulnerability, evidence, workload and identity/export
tabs. Missing or failed engine outcomes cannot appear as successful coverage.
Zero-count layer, filesystem and config reports are fetched and their failures
are visible instead of being described as missing historical evidence. Retired
VulnDB fields only render when historical provenance is present. Digest-pinned
images no longer receive the mutable-tag warning.

Validation: **988 seeded, repeated race-test executions**, followed by two focused
executions after test refactoring, **154 frontend tests**, scanner race tests,
OpenAPI checks, production frontend build and changed-code Go/frontend lint pass.
Live API results expose all three successful engines. Collaborative-browser DOM
checks verify five metrics, the default vulnerability view, `?tab=evidence`,
trusted signatures, digest pinning and explicit zero-count inspection failures.
The signed private-image
proof was rerun with the new scanner and verified layer/filesystem/config reads,
the corrected digest control, lease denials, audit receipts and credential cleanup.
This is a bounded P0/UI-1 truthfulness improvement; the broader page and scanner
fleet acceptance items remain open.

The registry form continuation is deployed at Helm revision **24**. Add and
edit now use dedicated `/registries/new` and `/registries/:id/edit` pages with
back navigation, explicit Save/Cancel and collapsed advanced settings. Testing a
connection is a separate action on the saved registry; the former form test could
silently create/update it. Blank credential edits preserve the saved sealed set;
selecting anonymous authentication clears it. The form exposes all 13 connector
kinds accepted by the API without claiming live provider qualification. The list
has a verdict and labels the 200-image-job queue sample.

Validation: **160 frontend tests**, production build and changed-file lint pass.
Collaborative-browser checks cover create-once, loaded edit, save, cancel without
changes, advanced disclosure and hard reload of the edit URL. The temporary manual
registry was removed. UI-1 stays open pending the remaining page/form audit.

The scan-console continuation is deployed at Helm revision **26** with frontend
`scan-console-final-20261012`. Scanner operations have five metrics and URL-linked
jobs, workers/capacity, database-refresh and CVE-source tabs. Failed requests and
unreported paused counts are explicit; configured feeds no longer claim verified
live delivery. The image list has a coverage-aware verdict, a collapsed selected
image summary and no fabricated missing VulnDB provenance. Registry inventory
shows failed or missing-registry requests instead of a false empty result.

Validation: **166 frontend tests**, production build, changed-file lint and
endpoint/plan checks pass. Shared-browser DOM checks cover tab changes, hard reload
of `?tab=workers`, live engine revisions/capacity, image metrics and disclosure,
and the deleted-registry error state. The existing production-browser navigation
spec was updated for the tabs; its full runner was not rerun in this continuation.
Matching live revision/capacity evidence on the dashboard, health and scanner
surfaces closes that bounded REG-1 item; the broader UI gates remain open.

The cluster-workflow continuation removes the competing registration modal.
The cluster list now navigates to the canonical registration page, with distribution,
region and expiry preserved under Advanced settings. Overview and registration
bundles are URL-linked tabs. Rotation has a dedicated confirmation/result page;
it no longer discards the returned replacement bundle. Successful registration
refreshes cluster and bundle lists, and navigation protects a pending request or
an unsaved one-time result. Raw results are not persisted in browser storage.

Validation: **168 frontend tests**, production build, changed-file lint and
endpoint/plan checks pass. Component tests cover cancel-without-create and explicit
rotation with retained results even when the old bundle disappears from the list.
Live shared-browser checks cover list tabs, dedicated registration, advanced
settings, Cancel and hard reload. Live credential rotation was not exercised.
This advances UI-1; the full console audit and its acceptance items remain open.

The policy-console continuation is deployed at Helm revision **29**. Runtime
policy editors wait for a successful same-cluster load, preserve string-encoded
rules, and keep drafts across background refreshes and refresh failures. Required
fields and JSON-array validation prevent invalid form submissions; overlapping
save/simulate/generate requests are disabled, stale simulation evidence clears when
rules change, and transport failures are shown without raw error text. Request
previews use collapsed disclosure; generated YAML format is URL-linked. The list
has a verdict, shared table preferences/export and explicit action failures.
Promotion waits for its match preview and exposes preview retry/failure states.

Policy Center separates families, migration diagnostics and mode guidance into
URL-linked tabs. Fixed example modes no longer appear as live family status.
Validation: **175 frontend tests**, production build, changed-file lint and
endpoint/plan checks pass. Regression tests cover failed and cross-cluster editor
loads, draft preservation, string rules, failed saves/demotion, unavailable promotion
previews and migration diagnostic scope/pagination under the new tabs. Live browser
checks cover a temporary monitor-only policy create/edit, required fields,
collapsed preview, Policy Center tabs and direct-link reload. The fixture was
removed; no live enforcement mode was changed. UI-1 and the broader console audit
remain open.

The network-rule and navigation continuation is deployed at Helm revision **31**.
Clusters is the first, persistent sidebar entry on both cluster and organization
routes; the selected cluster's navigation sits directly beneath it. Network rules
have dedicated edit routes that resolve the saved source/destination pair within
the selected cluster, including disambiguation of display-ID collisions. Legacy
query-based edit links load saved values instead of trusting copied form fields.
Failed, missing, and cross-cluster loads cannot open a blank editor. Drafts survive
background refresh and failed saves. Advanced status/priority controls retain
existing values; the API defaults only omitted priority to 1000, preserving explicit
zero and negative precedence. Learned ports/applications remain read-only because
they are derived from observed traffic. The list exposes disabled status, shared
table preferences/export, and explicit load/action failures.

Validation: **185 frontend tests**, repeated race-enabled network-handler tests
against a freshly migrated/seeded PostgreSQL database, focused OpenAPI tests,
production builds, changed-file lint and endpoint/plan checks pass. Live browser
checks confirm primary Clusters navigation on landing/settings/cluster routes,
dedicated edit links and direct reload, server values overriding stale URL fields,
save/cancel returning to the same cluster, and an explicit deleted-rule error.
A temporary disabled rule retained priority -10 after editing, Cancel left its saved
comment unchanged, and the fixture was removed. No active traffic rule was changed.
UI-1 and the broader console audit remain open; acceptance totals remain 56/97.

The admission/response console continuation is deployed at Helm revision **32**.
Admission opens with five summary metrics and the rules table. Assessment, criteria,
and webhook status use URL-linked tabs. Settings and organization-wide profile
imports have dedicated pages. Admission settings and policy mode/YAML changes now
wait for Save; Cancel performs no write. Admission rules link to the shared policy
editor and return to Admission Control. Failed/missing policy and response loads
cannot open blank editors, and background refresh cannot overwrite loaded drafts.
Rule creation validates required criterion values; errors preserve inputs without
exposing raw transport details. Profile import requires a fresh preview after each
option change and explicitly describes its organization-wide scope. Response lists
use a verdict, shared table controls/export, and explicit failures.

Clusters-first ordering now also applies to the command palette and Settings hub;
old scope-order prose and browser fixtures have been updated. Validation: **196
frontend tests**, production build, changed-file lint, endpoint mapping, plan and
whitespace checks pass. Live shared-browser checks cover admission default rules,
criteria tab selection and reload, dedicated settings Cancel with the server state
unchanged, profile preview gating, and matching sidebar/Settings/palette order.
A temporary disabled response rule passed edit/save/cancel with disabled status and
namespace retained; it was removed, then its direct link showed a non-editable error.
No profile import or live enforcement change was performed. The updated full
browser specs were not rerun; these checks do not close UI-1 or broader acceptance.

The group/DPI/file-monitor console continuation is deployed at Helm revision **34**.
Groups and new-service defaults now use dedicated forms; the dashboard links to
those canonical workflows instead of saving default modes inline. DLP/WAF group
scope has dedicated add pages. Rule editors validate loaded identity/scope and
preserve structured patterns and failed-save drafts. File-monitor forms require a
resolved workload and cluster. Lists use shared preferences/CSV, explicit errors,
and configuration language that does not imply confirmed detector deployment.
Admission profile catalog/bundle import and installed-policy comparison now share
one dedicated page; the old Policies profile tab redirects there. Import requires a
preview matching its inputs. The policy catalog no longer slices to 100 rows before
shared-table pagination.

The dashboard opens with a verdict and five server-derived metrics, with posture,
network, operations and trends behind URL-linked tabs. Sampled findings are labeled;
unknown summaries do not become zero-risk verdicts. Exposure CSV now includes the
server platform role, and the executive report states its organization-wide scope.
Shared table density/column preferences are partitioned by organization and user;
identity changes remount table state, legacy ownerless entries are not adopted, and
stale column IDs are pruned. The header reads Constellation with by Alphabravo below.

Live scope-form verification caught a successful empty API response containing
`bindings: null`. The client now normalizes that collection to an empty array so
new scope forms can load; two transport-level regression tests cover null and
populated responses. The focused DPI/transport suite passes **28 tests**.

Validation: **288 frontend tests**, production type-check/build, changed-file lint,
endpoint mapping and whitespace checks pass. Live browser checks confirm the brand,
five dashboard metrics, Network tab reload, canonical profile-import redirect and
preview gating. Editing a temporary disabled DLP rule preserved disabled mode;
Cancel retained its saved description, and the fixture was deleted. Group settings
Cancel left server defaults unchanged. No admission profile or scope binding was
imported/applied during verification. These bounded checks do not close UI-1/2/3/4:
remaining legacy forms, separately stored saved views, source pagination/exact
links, and the complete API/export/live-install matrix remain open.

The vulnerability-profile/response-catalog/compliance continuation adds dedicated
create/edit pages with scoped loading, explicit failures and preserved drafts.
Vulnerability profiles retain ordered rules and unknown saved scope fields, default
to inactive, and pause saves when the selected cluster becomes unavailable. The
response catalog explicitly describes organization-wide overrides and requires a
preview matching the current inputs. Compliance separates controls, evidence and
schedules into URL-linked workspaces; exemptions validate reason and future expiry.
A control exemption covers all matching evidence for that control in the selected
cluster, including multiple workload targets. Scheduled delivery remains intent
until run history confirms an outcome.

CVE search now uses server pagination with a one-row lookahead, URL-linked filters,
sort and page, keyboard-accessible filter chips and explicitly page-scoped CSV.
Saved views and Findings density now follow organization/user identity; ownerless
legacy preferences are not adopted, while the previously user-owned Network Map
views migrate once. Empty saved group criteria remain empty when edited. Removed
the orphan generic CRUD component and corrected configured-protection and sampled
risk labels. Publication-window vulnerability rules still require publication dates
that current scan-completion findings do not provide; this remains a backend gap.

Validation: the continuation is deployed at Helm revision **36** using
`constellation/frontend:console-workflows-verified-20261012`. All **391 frontend
tests**, production type-check/build, changed-source lint, endpoint mapping and
plan/whitespace checks pass. Live browser checks confirm CVE page 2 requests
`offset=50` and survives reload; response override Save becomes available after
its matching preview; compliance schedule Cancel returns to its tab; and singleton
and five-evidence-row exemption forms validate without creating exemptions.
An inactive vulnerability profile passed create/edit/reload/Cancel, stayed inactive
with its saved description, and was deleted after verification. Final rollout
rechecked profile hydration and the corrected multi-evidence exemption form.
Updated browser specs were discovered but the full browser runner was not rerun.
Remaining table geometry, integration forms, Findings server filtering/export and
other UI-1/2/3/4 acceptance remain open; these checks do not imply full parity.

The shared-table visual continuation fixes a browser layout defect in the common
row hover decoration: a `tr::before` generated an anonymous cell and shifted body
values one column away from the headers. Shared tables now use matching explicit
header/body alignment, a single measured column layout, and an Astronomer-derived
semantic sizing model. Names and descriptions can grow; statuses, counts, dates and
actions remain bounded. Header labels reserve room for sort icons. Legacy tables
retain native width handling while adopting the alignment fix. Overflow stays
inside each table, and clipped values remain available on hover or keyboard focus.
Version lists and compliance evidence wrap fully. Table guidance now lives in
`frontend/CLAUDE.md` so future pages use these shared rules rather than local CSS.

Primary cluster, deployment, Findings, image, CVE, compliance, response, group,
vulnerability-profile, node, registry and file-monitor tables now declare semantic
columns. Network session/PCAP/threat inventories, scanner worker/cache/queue tables,
image evidence, effective configuration/revision tables and compliance run history
use the canonical DataTable. Some compact read-only matrices remain semantic HTML;
this increment does not claim every UI-2 feature or every detail surface is complete.

Validation: deployed at Helm revision **39** with
`constellation/frontend:table-layout-final-20261012`; all seven deployments are
ready. The final source passes **408 frontend tests**, production type-check/build,
changed-source lint, endpoint mapping and plan/whitespace checks. The shared-browser
response catalog has matching header/body positions at 1440px/cozy,
1024px/compact and 640px/comfy, with no action clipping or document overflow.
CVE, Nodes and Findings also have matching column positions and numeric alignment.
Findings column hide/restore preserves alignment; full version lists wrap without
spilling; node timestamps fit; nested clipped vector text exposes its complete
value through the focusable tooltip. The viewport and changed column/density
preferences were restored. A readonly browser geometry regression was added and
successfully discovered, but the full browser runner was not executed for this
increment. Remaining compact detail matrices and broader UI-2 workflows stay open.

The integration/table continuation replaces inline routing and SMTP settings with
URL-addressable form pages and explicit Save/Cancel. Child route edits bind their
index to the loaded revision, preserve advanced YAML and external receiver names,
and save immediately. Complete YAML editing retains nested trees verbatim. Routing
writes now support atomic `If-Match` revision checks, including concurrent first
saves; stale edits return HTTP 412 without changing the document. SMTP saves use
the existing system-config revision check and preserve redacted passwords.
Receiver forms load an exact, settled record, retain drafts on refresh/failure,
and patch changed fields only. Email edits merge the latest loaded configuration;
unchanged custom event filters remain intact. Receiver detail results are bound to
the requested receiver, pending rotations block selection changes, and clipboard
failures never claim success. No live notifications or secret rotations were sent.

All inventory tables now use the shared DataTable; the remaining raw HTML table
is Dashboard's four-row risk summary matrix. Compact network inventories retain
bounded scrolling through an explicit pagination opt-out. Runtime, Audit,
repository, serverless, container, registry-image and integration tables now
use semantic column widths. Secondary diagnostic/policy tables still need explicit
column metadata, and broader UI-2 filtering/export/preferences acceptance is open.

Validation: Helm revision **41** runs frontend
`constellation/frontend:integration-console-final-20261012` and API
`constellation/api:integration-revisions-20261012`; all seven deployments are ready.
All **476 frontend tests**, production build/type-check, changed-source lint,
OpenAPI, endpoint mapping and plan/whitespace checks pass. Fresh seeded PostgreSQL
routing tests pass twice with race detection/shuffling and no skips, covering
concurrent create/update, stale/invalid/cross-organization revisions and legacy
clients. Live checks cover form navigation/reload/Cancel, required route-label
validation, refusal of unversioned route-edit links and complete YAML editor
loading. Configuration fingerprints confirm routing, SMTP and receivers stayed
unchanged. Runtime's three tables and Audit have matching header/body positions
at 1280px and 640px, without document overflow; the viewport was restored.
Five integration browser cases were discovered, including two new readonly
regressions; the full browser runner was not executed for this increment.
Cluster-filtered Audit loading took tens of seconds while the unfiltered latest
event request completed in 0.02 seconds; query diagnosis remains open alongside
Findings server filtering/export, group scope gates and broader UI-1/2/3/4 work.

The inventory/query continuation completes semantic column metadata across the
remaining policy, diagnostic and detail tables. All production inventory columns
now delegate sizing and alignment to DataTable and global CSS; the compact
Dashboard risk matrix remains the only raw table. Server-sorted tables can preserve
the API order while requesting a new sort, without locally reordering one page.

Findings now applies query, kind, lifecycle, cluster and fixability on the server,
with matching instance totals, lifecycle counts, stable ordering and CSV filters.
Search accepts bare text, field terms, negation and colon-containing package URLs;
ordinary substring terms treat SQL wildcard characters literally. Legacy string
KEV evidence agrees between instance and CVE views. URL state retains filters,
view, grouping, page and sort. Selection and grouped exports are explicitly scoped
to the current server page; filtered instance export states its 100,000-row cap.
CVE fixability retains unfixed instances in a matching CVE's blast radius. Its
filtered total already existed; this increment wires consistent search and paging.

Audit migration **173** adds a concurrent organization/target/event index. Cluster
pages probe their distinct target IDs and merge matching events rather than scan
the entire audit log. Interrupted or unrecorded index builds can be retried. Group
authoring requires settled, exact cluster scope, retains drafts through failed
refreshes, and rechecks scope before saving. Components inventory, detail and
support bundles now score the original heartbeat rows without pairing them with a
collapsed/reordered health summary; SystemHealth retains its summary behavior.
Components API failures display an error and retry rather than false zero counts.

Validation: Helm revision **42** runs frontend/API
`query-console-20261012` and migration image `audit-lookup-20261012`; all seven
deployments are ready. **552 frontend tests** pass, together with production
build/type-check, changed-file lint, OpenAPI, endpoint mapping, plan and whitespace
checks. Fresh PostgreSQL applies migration 173 and a second no-op; **140 selected
backend tests** pass with race detection/shuffling and no skips, including retry
of invalid/unrecorded index builds, sparse custom/generic query plans, Components
status association and shared Findings list/CSV predicates beyond row 500.

Live migration finished in 7.55 seconds; the index is ready/valid and the recorded
pre-migration audit head is unchanged. The cluster Audit request returns 17 rows
in 2.269 seconds, versus tens of seconds before. Components returns real inventory
in 0.02 seconds. A critical-vulnerability filter returns 224 matching instances;
CSV agrees with the list IDs and order, and the CVE view reports 27 matching CVEs.
Browser checks verify page 2 shows rows 101–200 of 224 and survives URL reload.
Components' two tables, Findings, and scanner queue/jobs have matching header/body
geometry at 1280px and 640px with no document overflow or clipped actions. The
viewport was restored. These checks do not close remaining UI-1/2/3/4 acceptance.

The action/workload continuation adds dedicated finding accept-risk, suppression
and comment pages plus Network Map isolation, admission quarantine, peer-IP block
and policy-approval forms. Editors require settled exact scope, preserve drafts
through refresh failures, and recheck current targets before submission. Policy
approval verifies both cached and freshly fetched candidate hashes and preserves
idempotency for an unchanged draft. Enforcement/quarantine writes resolve and lock
existing cluster-owned workloads; single-IP blocking is Cilium-only because no
Calico manifest generator is implemented. Queued policy, admission quarantine and
approval are described separately from confirmed traffic enforcement.

Deployment search, namespace/platform filters and classification now run before
pagination. A repeatable-read snapshot supplies the page, full filtered totals and
risk summary; CSV streams all matching permitted rows in the same stable order.
URL filters/pages survive navigation; text changes replace history while explicit
selections/pages push it. The shared DataTable supplies density and column controls.

Exceptions is one shared inventory with URL filters and explicit selection, scoped
to the active cluster. Missing audit evidence remains missing: no invented actors,
timestamps, acceptance reasons, controls or revokers. Image audit events match the
exact acceptance ID, and shared digest associations retain their observed clusters.
Finding scope uses the recorded finding cluster, consistent with detail/list APIs.
Legacy review metadata is explicitly advisory; the legacy approved status denotes
a recorded active acceptance, not proof of an independent approval workflow.

Validation: Helm revision **43** runs frontend/API `action-console-20261012`, with
migration image `audit-lookup-20261012` and schema 173 unchanged. All seven deployments
are ready. **675 frontend tests**, production build/type-check, changed-file lint,
OpenAPI, endpoint mapping, plan and whitespace checks pass. Fresh seeded PostgreSQL
runs **52 selected backend test executions** with race detection/shuffling and no
skips, covering more than 500 deployment rows, SQL/Go platform-classification parity,
namespace restrictions, target ownership, missing audit evidence and exact revokers.
Thirteen affected browser cases were discovered; the full browser runner was not run.

Live readonly checks confirm deployment totals and full CSV agree: 17 overall,
6 customer and 11 platform workloads; a qualified-name query finds its matching
rows. Dedicated finding forms and all four network action pages load by URL;
Cancel preserves network tab context, empty reasons disable submit, and Flannel
correctly blocks the Cilium-only action. The approval page reports no proposed mode
change for the inspected workload and remains disabled. No live finding or network
mutations were submitted. Deployment header/body geometry matches at 1280px and
640px without document overflow or clipped actions; the empty Exceptions table also
stays contained, but has no live rows for a body-alignment assertion. Missing linked
exceptions stay explicit, and the viewport was restored. Remaining UI-1/2/3/4 work
includes Runtime/Components scope/error/disclosure cleanup and Dashboard Operations.

The cockpit continuation puts Runtime live events and Components inventory first,
with URL-linked secondary workspaces and at most five top-line metrics. Components
requires an exact cluster/instance/diagnostic match, keeps confirmed previews and
queued bundle feedback during source polls, and labels support bundles as
organization-wide. Runtime distinguishes its latest-100 historical feed from
selected-window totals and bounded recent-event/workload samples; catalog readiness
is not represented as proof of deployed enforcement. Source failures show Retry
and withhold failed evidence instead of rendering healthy zeroes.

Dashboard Operations is full width. Its package table and export include every
returned package, and scanner/federation scope is explicit. Scan submission checks
current cluster and platform evidence again at mutation time and distinguishes
queued, unqueued and failed requests. No live scan or support-bundle request was
submitted during verification. Timeline filters, dates, pages and exact selection
now persist in the URL; invalid windows and missing selections remain explicit.
Its unused local scope picker is removed. Shared tabs now push browser history
while preserving unrelated filters/fragments. Shared headers wrap actions and the
new global `StatGrid` responds to content width rather than forcing equal columns
at viewport breakpoints. Components, Runtime, Dashboard, Timeline and Exceptions
use it; broader metric-row adoption remains part of consistency acceptance.

Validation: Helm revision **45** runs frontend `cockpit-layout-20261012`, retaining
API `action-console-20261012`, migration `audit-lookup-20261012` and schema 173.
All seven deployments are ready. **751 frontend tests** across 79 files, production
build/typecheck, changed-file lint, endpoint mapping and parity-plan checks pass.
The 41 browser cases in four affected files were discovered, not run as a full
suite. Live read-only checks verify Components inventory/version tables, Runtime
live/evidence tables and Dashboard's ten returned packages; measured header/body
geometry matches and tables stay contained at desktop/narrow widths. Components
metrics were corrected after a narrow screenshot exposed squeezed labels, then
verified at 640px (two columns) and 1280px (five columns), without card overflow.
Timeline page 2 and missing explicit event links load without substituting another
event. Automated cases cover reload/history, deferred polls, stale scope and source
failures. These changes do not close UI-1/2/3/4: remaining selected console work
includes risk-detail scoping, saved-view authoring/persistence, broader shared
layout/export acceptance and route consistency. Broader security/infrastructure
acceptance remains tracked separately.

The workflow/layout continuation extends shared `StatGrid` adoption to 44 more
page files (48 metric rows), plus Findings, risk, Network and remaining Dashboard
rows. Entity headers wrap their metrics/actions, and shared page titles now wrap
long identifiers instead of overlapping actions. Deployment and migration pages
keep at most five primary metrics and disclose secondary counts. Semantic table
column sizing/alignment and typography remain centralized in the shared table
primitives and global CSS; pages declare content kinds rather than equal widths.

Risk workspaces resolve the exact cluster/entity before querying or displaying
related evidence. Asset responses now expose their cluster identity. Generic
asset findings use exact server predicates, stable pagination and matching counts;
canonical image evidence stays separately labeled. Fabricated factors and
substring-related activity are removed. Unsupported workload mappings are explicit.
Source limits remain visible: deployment findings 100, runtime events 50, network
flows 50, node vulnerabilities 2,000 and generic asset CSV up to 10,000.

Findings and Timeline saved views now have dedicated `/views/new` pages with
Save/Cancel, Advanced filter details and preserved return URLs/fragments. Writes
complete before navigation, remain scoped to organization/user, and report browser
storage failures or rejected malformed records. Held callbacks cannot write after
identity/inventory changes. Timeline timestamps retain offsets and milliseconds.
Network saved-view payloads preserve exact conversation endpoints and honor write
outcomes. The later detail-workflow continuation migrates its authoring to dedicated pages.

Dashboard network links now request exact directed pairs and their original 24h
or 168h window. A server-side blocked cohort includes deny/denied/block/blocked
before counting and pagination; count/page reads share one snapshot. Network
filters, tabs, pair detail and conversation pages retain URL/history context.
Exact pair detail uses returned streams independently of the map's 300-flow sample,
and labels its own 200-stream cap. Network status describes 10–15s automatic
refresh instead of falsely claiming an active stream. Livegraph streaming remains
disabled; enabling it requires explicit cluster scoping and connection-state work.

Validation: Helm revision **48** runs frontend `workflow-canvas-20261012` and
API `workflow-console-20261012`, with migration `audit-lookup-20261012` and schema
173. All seven deployments are ready. The combined frontend run passed **847
tests across 84 files**; the final header/polling-label/row-selection refinements
passed 42 relevant tests and a rebuilt production bundle/typecheck. Changed-file
lint, generated OpenAPI/endpoint mapping, parity-plan checks, graph race tests and
handler vet pass. Fresh migrated PostgreSQL runs passed **26 test executions**
with race/shuffle and no skips: 20 conversation and six asset-scope executions.
They cover exact pairs beyond the first page, literal wildcard identities,
deny/block aliases, count/page agreement, durable-cache bypass and tenant scope.
The four affected dashboard browser cases were discovered, not rerun as a suite.

Live read-only API checks confirm exact pair/missing pair/blocked filtering and
asset cluster identity. Browser checks cover risk asset/deployment/node evidence,
exact conversation stream selection and reload, and saved-view direct routes,
required-name gates and Cancel context (including timestamp offsets/milliseconds).
Risk and conversation/stream table geometry matches at desktop/narrow widths;
metrics wrap without overflow, and a long-digest screenshot prompted the shared
header correction, verified at 640px and 1280px. The map canvas received an
explicit responsive height after the scrolling layout exposed a zero-height
ReactFlow surface; its rendered canvas was rechecked. Assets also uses the responsive
shared metrics. These are bounded checks, not full mobile/accessibility or all-page
acceptance. No live security actions or saved-view writes were submitted.
UI-1/2/3/4 remain open for the remaining canonical-page, form, table/export,
platform-role and destination-matrix acceptance; broader infrastructure/security
gates stay separate.

The detail-workflow continuation gives Asset and Deployment pages verdicts,
bounded primary metrics and URL-linked evidence workspaces. Shared semantic tables
expose all returned rows, explicit source caps, preferences and loaded-evidence
CSV. Asset generic findings remain capped at 100 plus returned digest-scan findings;
deployment network/runtime samples are 50, findings 100, compliance controls 50,
package reports 20 and combined threat pivots 60. Missing selected evidence is
explicit instead of silently substituting another record.

Asset image acceptance and revocation now use dedicated review pages. Each sends
the reviewed digest and cluster; the API locks asset/image identity through the
write, rejects changed scope, and confirms the committed identity in its response.
Legacy callers may omit both preconditions. Deployment policy transitions,
quarantine lifting, process/file modes, file exceptions, deletions and bundle import
also have dedicated forms, while approval/quarantine and file-rule authoring reuse
existing canonical forms. Forms preserve drafts on failures, recheck current
evidence and distinguish configuration or queued actions from deployed enforcement.

Network Save/Import views and packet capture now use dedicated pages with preserved
scope/filter/return context. Imports preview accepted/rejected records before the
browser write. Threat detail links to the same capture form with its exact traffic
tuple; no second inline capture editor remains. Capture requests validate limits
without silent clamping, recheck exact workload scope and block repeat submission.
The capture list exposes all 200 returned rows through the shared table; invalid
filters, mismatched scope and failed refreshes cannot appear as broader or current
evidence. Missing packet/size measurements remain explicit.

Validation: Helm revision **51** runs frontend `detail-metrics-20261012` and
API `detail-workflows-20261012`, retaining migration `audit-lookup-20261012` and
schema 173. All seven deployments are ready. The full frontend run passed **1,039
tests across 94 files**; final shared metadata typography changes passed 77
focused deployment/risk tests, production build/typecheck and changed-file lint.
Generated OpenAPI/endpoint mapping, handler vet and parity-plan checks pass.
Fresh migrated PostgreSQL runs passed **26 image-acceptance test executions**
with race/shuffle and no skips, including scope changes, tenant isolation,
confirmed response identity and concurrent asset/image updates. Eight affected
browser cases were discovered; the full browser runner was not rerun.

Live read-only browser checks verify Asset findings/acceptance review and
Deployment network/files evidence, exact form scope and Cancel destinations.
Network Save-view/Cancel/Back/Forward retains local filters, exact conversation
pairs, page, inspection and fragments; packet-capture review retains its workload
and traffic tuple and rejects invalid duration without submitting. Desktop and
640px checks show matching table header/body geometry, contained horizontal
scrolling and no clipped actions. A screenshot exposed oversized timestamp
metrics; the shared `StatCard` now has explicit compact text-value typography,
verified at 88px card height on desktop and without narrow-card overflow.
No live security actions, captures, acceptance changes or saved-view writes were
submitted. The eight remaining selected-console families below stay open;
these checks do not close UI-1/2/3/4 or broader infrastructure/security gates.

The inventory/workspace continuation moves process baseline rule and mode authoring
to dedicated review pages. Inventory and detail workspaces retain URL context,
configured rules and mode history use shared tables, and failed reads no longer
look like empty profiles. Rule APIs resolve exact cluster/workload identity,
reject ambiguous unscoped names, and offer atomic create/update/delete and mode
preconditions. Responses are checked before navigation; uncertain writes cannot
be blindly repeated. New audit records include resolved cluster identity. These
changes configure policy and do not claim agent receipt or enforcement.

Repository, image and serverless scan inventories now expose server continuation
using 100 displayed rows plus a one-row continuation probe. Supported search
predicates run on the server; local severity/status/posture filters, sorting and
CSV are explicitly page-scoped. URL state preserves filters, page and exact
selection. Containers, connector coverage and federation expose read/refresh
errors instead of healthy/empty/zero fallbacks. Organization-wide repository,
serverless, connector and federation evidence is labeled accordingly.

Node, serverless and CVE details use exact entity/scope gates, URL workspaces and
shared evidence tables with preferences and bounded exports. Node scan requests
recheck their exact current scan target. Asset inventory, Audit, Registry Images,
Access Control, API Tokens and Attestation Trust adopt shared table preferences
and accurate CSV values. Asset links follow the actual selection, unknown
signatures remain unknown, and exports retain full audit identities and account
lock/reset state. Audit and registry pagination live in the URL without a second
internal pager. Attestation trust uses one responsive table and distinguishes
verification configuration from admission enforcement.

Effective Config and Cluster Health now use full-width URL workspaces.
Configuration values, provenance, component revision reports and JSON are
separate views; all returned revision reports are reachable through the shared
table instead of a silent 12-row slice. Cluster components, gates, platform
facts and registration are separately linked, with missing evidence kept
distinct from zero. Shared text-value metric typography is used for metadata.

Source limits remain explicit: container inventory 3,000; node CVEs 2,000;
serverless findings 100 and jobs 25; CVE affected images 500 and workload links
1,000; component inventory 1,000; baseline observations/counts derive from the
latest 1,000 retained events. These bounds do not establish full-fleet totals.
Scan list APIs expose offset/limit without total counts. Cloud function evidence
has no cluster association. Baseline inventory/rules/history are uncapped, but
per-workload inventory reads still require scale qualification.


Validation: Helm revision **53** runs frontend `inventory-layout-20261012`
and API `inventory-console-20261012`, retaining migration
`audit-lookup-20261012` and schema 173; all seven deployments are ready.
The full frontend suite passed **1,194 tests across 100 files**. Final baseline
column/header refinement passed 33 focused tests, production build/typecheck and
changed-source lint. Generated OpenAPI, 107 endpoint mappings and runtime handler
vet pass. Fresh schema-173 PostgreSQL passed **506 runtime test executions**
with race/shuffle and no skips, including baseline scope and atomic write conflicts.
The default local test database was stale at schema 161; the fresh migrated run
also passes the unrelated foreign-key test that failed against that old schema.
Four affected browser cases were discovered; the full browser runner was not rerun.

Live read-only checks cover exact baseline rule form scope, closed Advanced fields
and Cancel; Effective Config report/provenance tabs and Back context; Cluster Health
gates/platform/registration workspaces; changed asset selection and its actual
native detail navigation; Audit empty-page recovery; image scan empty-page recovery;
and CVE metadata with explicitly empty bounded affected evidence. Baseline workload
width increased from 169px to 375px at 1280px while numeric columns remain compact.
Desktop and 640px checks show matching table header/body geometry, contained
horizontal scrolling and no clipped actions in the tested populated tables.
The live environment has no node/serverless/registry inventory, so positive paths
for those surfaces are component-test evidence rather than live data acceptance.
No live scans, policy mutations, acceptance changes or saved-view writes were made.
These bounded checks do not close UI-1/2/3/4 or infrastructure/security acceptance.

The workspace/evidence continuation resolves Posture's explicit cluster scope,
owner-scoped source reads, per-source unavailable/retry states and URL workspaces.
Its 24-hour audit/runtime/scan metrics are separate bounded samples (100/50/200),
not a deduplicated activity total. Organization evidence remains labeled; links to
cluster-only destinations explicitly say Browse cluster or require selection.

Migration now separates import, readiness, report and history with URL-linked
evidence families. Previews bind to the exact source/export/target draft, and
stale or mismatched responses cannot authorize Apply. Scanner refresh intervals
use a dedicated revision-checked Save/Cancel page, preserve drafts, verify response
values and prevent late navigation or blind repeat writes after uncertain results.
Scanner attempt history is a shared table with exact-job evidence, Retry and
loaded-ledger CSV. Jobs remain a latest-200 sample and migration history loads
25 records per server page.

Image scan details expose every returned layer-linked package, secret and file-risk
record through shared paginated tables and URL evidence tabs instead of silent
four/six-row previews. Failed artifact reads or refreshes hide stale evidence;
responses must identify the requested scan. Workload links use stable workload
identity. Findings preserve zero CVSS, exclude unavailable fix versions, and explain
that full-scan CSV is independent of the local Fixable-only filter. Package
provenance remains layer-linked; full Inventory includes unattributed packages.

Admission's assessment-history CSV now retains the displayed scalar evidence,
and rule inventory exports omit controls. Registry and Backup inventories have
shared preferences and metadata CSV; backup history explicitly covers the latest
50 records. Compliance schedule-run history exposes its returned 25-record sample;
System Health gains preferences while retaining its existing scalar CSV.
Shared density buttons expose their selected state to assistive technology.

Network policy review moves remaining lifecycle actions into dedicated forms;
weak-TLS settings use explicit Save/Cancel and evidence-removal acknowledgment.
The API validates owned cluster scope, requires an explicit desired boolean,
supports an optional reviewed-value precondition, and commits the setting and
weak-TLS evidence cleanup atomically. Concurrent stale reviews conflict; failed
cleanup rolls back. Configuration success does not claim agent adoption.
Dashboard fixability now matches the linked Findings predicate, and vulnerable
workload rows carry exact deployment IDs. Unsupported cohorts have honest browse
destinations. The source/destination matrix states differing units and scope;
the remaining hand-written dashboard table uses the shared component.


Network lifecycle evidence uses a fixed seven-day source window; map hours and
verdict filters remain return context, not lifecycle evidence filters. The tuple
preview explicitly limits its sample to twelve records. Legacy manifest previews
fall back to the returned YAML when the manifest dictionary is empty.

Workspace/evidence validation passed **1,292 frontend tests across 104 files**;
the subsequent two Network guards passed 73 focused tests, and the Posture
responsive filter adjustment passed 27. Final production build/typecheck and
changed-source lint pass. Fresh schema-173 PostgreSQL passed four Dashboard
destination executions and two DPI transaction executions with race/shuffle and
no skips. Generated OpenAPI, 107 endpoint mappings, handler vet and plan checks
pass. Forty-three affected browser cases were discovered across six specs;
the full browser runner was not rerun.

Helm revision **56** runs frontend `workspace-final-20261012` and API
`workspace-evidence-20261012`, retaining migration `audit-lookup-20261012` and
schema 173. Final narrow-screen review corrected the Posture filter groups to
stack within their container and gave long status badges an explicit semantic
column minimum. These changes continue to use the shared table and global CSS.
All seven deployments are ready. At 640px both filters end at x=595 inside the
content area, and status cells retain a 180px minimum with contained scrolling.

Read-only live checks confirm Posture cluster/organization tabs and Back preserve
context and fragments; selected scope resolves correctly, and shared density
buttons report their selected state. Scanner rejects a negative interval and
Cancel restores its exact return URL. Migration readiness/history tabs preserve
URL history and explicitly describe partial evidence. Weak-TLS starts from the
reported configuration with unchanged Save disabled; Cancel submits no mutation.
The inspected image scan accurately reports missing layer attribution and failed
config inspection; positive multi-page artifact cases use component fixtures.
The Dashboard source matrix exposes its actual cohorts and limits, and following
its fixable link shows the same **2,205** records in Findings. Its six vulnerable
workload links contain exact deployment IDs. Posture and Dashboard populated
tables have matching header/body geometry and no clipped actions at 1280px and
640px, with horizontal scrolling contained within the tables. No live security,
scan, migration, acceptance or saved-view writes were submitted. These checks do
not close the remaining all-page, scale, accessibility or infrastructure gates.

The next shared-table acceptance increment keeps one column-sizing/alignment
implementation and adds controlled URL/history sorting, visible disclosure and
recovery for a hidden sort column, stale-column repair, a full preference reset,
and a visible retry when browser storage cannot save. Select-all preserves
selections on other pages; partial selection exposes its mixed state. Named,
keyboard-focusable scroll regions retain contained horizontal scrolling. The
shared preference namespace remains scoped to organization, user and table.

The frozen frontend passed **1,341 tests across 105 files**, production build,
typecheck and changed-source lint. Fresh schema-173 databases passed **58 focused
race/shuffle executions with no skips**: eight Dashboard cohort, 28 platform-role
and 22 scan-inventory/metadata cases. The 656-execution Network/runtime suite
passed before the final small role contract correction; the frozen-source focused
role rerun qualifies that correction. Handler vet, generated OpenAPI and 107
endpoint mappings pass.

Image, repository and serverless scan inventories now filter and sort on the
server before pagination. Matching totals, aggregate metrics and rows share one
read-only repeatable-read snapshot; deterministic ID ties prevent unstable pages.
Their matching CSV routes use the same query predicates and ordering across pages,
with an explicit 100,000-record cap and total/truncation headers. The separate
page CSV follows visible columns. Search is literal and case-insensitive, invalid
filter/sort/raw query values fail explicitly, and serverless posture uses ASCII
whitespace trimming and case normalization consistently across filters, rows, metrics and exports. Package metadata is a
fallback only when package evidence is absent, preserving authoritative zeroes.

Dashboard image/host vulnerability tiles now link to exact target-type Findings
cohorts, and privileged/root/exposure tiles link to exact deployment risk-fact
key-presence cohorts. These predicates apply to list/count/CSV; target-type also
applies to CVE rollups and saved views. Risk-fact presence includes false, zero and
null stored values because that is the source metric's predicate. CVE rollups
retain unnamed host instances while excluding null image names from string arrays.
Policy-mode labels distinguish distinct open CVE IDs from exposed workloads.

Network flow/recent-entry, threat and capture reads now carry platform roles from
exact organization/cluster/workload evidence. Ambiguous owners and IP endpoints
remain unclassified; modern responses use an explicit empty role to suppress
legacy namespace guesses. Default lifecycle/stream/threat/capture tables and
visible-column CSV carry the role. User-hidden columns remain hidden in page CSV.
Classification does not alter collection or enforcement, and optional live
streaming remains disabled pending its separate scope/connection acceptance.

Helm revision **57** deploys frontend and API `table-contract-20261012`, with
migration `audit-lookup-20261012`, schema 173 and all seven deployments ready.
Read-only live checks show image-list matching total **27**, two nonoverlapping
continuation pages and **27 CSV records**; critical severity selects **12** in the
UI, source count and matching CSV. The browser reports all twelve exported.
Repository/serverless live inventories and CSV are empty; nonempty continuation,
malformed metadata and cap contracts remain fixture-qualified. Offset continuation
reflects current data across requests, not an immutable multi-request snapshot.

Live Dashboard source/destination totals agree for **5,186 image-workload** and
**641 host** open vulnerability records, and **1 privileged**, **1 root**, and
**17 network-exposure** risk-fact deployments. The Host CVEs tile opens the exact
641-instance Findings view; the exposure destination displays its key-presence
semantics and 17 matching rows. Current network reads include role fields on
294 aggregate flows and 50 recent entries; custom-install and ambiguity positives
remain database-qualified rather than live-install acceptance.

At 1280px and 640px the populated Images, Findings and Deployments tables have
matching header/body boundaries, correct numeric alignment, no clipped actions
and contained horizontal overflow. Image filters stay within the content width.
Hiding the active Image sort preserves ordering and displays its caption; Show
sort column restores it. Ascending sort changes server order, and browser Back
restores descending state and its fragment. Keyboard menu navigation activates
Reset table preferences and restores columns/cozy density. The scroll region is
focusable; full keyboard-scrolling and broader accessibility acceptance remain
open. Temporary table preferences were restored. No live policy, scan, migration,
acceptance, capture or saved-view writes were submitted.

The next Dashboard destination increment preserves the source predicates in the
linked inventory. Runtime alerts use the exact inclusive 24-hour lower timestamp
and alert/block/quarantine verdicts; the high/critical event chart uses its exact
exclusive 14-day lower timestamp. Both deliberately retain the source's lack of
an upper bound. Event-only Timeline reads return matching totals from the same
snapshot as rows, and matching CSV states its 10,000-record cap. Window/verdict
filters survive URL history and scoped saved views.

Policy-mode vulnerability IDs and exposed workloads share one strongest-mode
resolver keyed by organization, cluster and workload. This prevents same-named
workloads in sibling clusters from merging. The all-ID Findings rollup includes
advisory identifiers because the Dashboard source counts every non-null external
identifier, while the ordinary CVE view retains its CVE-only default. Workloads
without group membership remain outside the mode cohorts.

Compliance now exposes graded records across all frameworks, with server filters,
stable sorting, continuation, aggregate metadata and a matching 100,000-record
CSV export. Summary and inventory reuse effective-status logic, excluding active
exemptions from graded failures. Exact control lookup removes the exemption
form's first-500-row lookup limit. Dashboard recent activity links to the returned
organization audit IDs, so newer activity cannot replace the selected records;
missing or inaccessible records stay missing and an empty selection stays empty.
Organization Audit Log has persistent navigation and a lossless record-ID column.
All destination tables use the shared DataTable and global sizing/alignment rules.

Frozen frontend validation passed **1,408 tests across 108 files**, production
build/typecheck and changed-source lint. **80 focused fresh PostgreSQL
race/shuffle executions** passed with no skips: six Audit, ten policy-mode,
14 Timeline and 50 Compliance. A further two policy-mode executions verify the
final fixture cleanup correction. Handler vet, OpenAPI contract tests, generated
specification and all 107 endpoint mappings pass. These qualify the changed
workflows, not the full repository's independent release gates.

Helm revision **58** runs frontend/API `dashboard-cohorts-20261012`, migration
`audit-lookup-20261012`, schema 173 and all seven deployments ready. Read-only live
API checks reconcile **20 selected audit IDs**, **80 discover-mode vulnerability
IDs**, **17 discover-mode exposed workloads**, and **52 graded compliance rows**
(0 passing, 52 failing) with their source counts. Monitor/protect cohorts are
empty live and nonempty in database fixtures. Runtime source/destination/CSV agree
at **8,455** records; the 14-day source/destination agree at **25,654**, with CSV
correctly reporting **10,000 exported and truncation**. Both event inventories
have nonoverlapping continuation pages in the bounded live check.

Browser checks follow Dashboard links to all-framework graded Compliance,
selected organization audit, runtime verdicts, high/critical event Timeline and
discover-mode vulnerability IDs. Compliance displays and exports all 52 matches;
Audit retains all 20 selected IDs through refresh. Timeline preserves the precise
lower bound, severity and exclusive predicate through Next and Back, and displays
its matching-export cap explicitly. Counts can change between requests as live
events arrive or expire: pinned bounds are not immutable dataset snapshots.

Populated Compliance, Audit and Findings tables have matching header/body
boundaries and semantic widths at desktop; Compliance and Audit also pass 640px
checks with no document overflow or clipped actions. Timeline keeps its
chronological event list and responsive shared controls; its narrow layout and
filters stay contained. The viewport is restored to 1280px. No live policy,
exemption, scan, migration, acceptance, capture or saved-view writes were submitted.
All-page, larger-dataset, saved-state and accessibility acceptance remains open.

The next shared-table increment adds bounded pointer/keyboard column resizing,
column order, left/right pinning and explicit layout reset to the reusable
DataTable. Header, body and page CSV use the same visible order; pin offsets use
measured column widths and suspend when a narrow viewport cannot retain a usable
center. Scoped preferences sanitize stale columns and invalid sizes. Focused
scroll regions support Left/Right/Home/End without intercepting child controls.
Runtime live, Integration deliveries and Network streams now use an initial
compact density, so their visible density controls can actually change it.

Assets now applies search, the existing query DSL, kind, criticality and AI-workload
filters before server sorting/paging. Matching summaries and up to 100,000 CSV
records share the inventory predicate and a repeatable-read snapshot per request.
Components now exposes server filters/sort/pages and matching CSV across its
24-hour heartbeat source. Health summaries, role counts and version capacity use
the complete selected scope rather than the current page. Restart scoring counts
all last-hour events by organization, cluster, component and hostname; list and
detail use the same owned heartbeat population and report source read failures.
Components still loads the organization heartbeat population to preserve the
complete drift baseline, and its multiple source reads are not a single snapshot.

Runtime events, runtime overview and Timeline workload evidence now carry exact
platform-role metadata, including their relevant CSV/NDJSON exports. Ambiguous
organization-wide rollups remain explicitly unclassified. Events NDJSON export
uses the actual threat `at` column, bounded keyset pages and one read-only snapshot;
a failed stream ends with a valid JSON error record instead of implying success.
Both threat timestamps are producer-reported, not an ingestion-time guarantee.
Session/conversation ownership resolution, capture-start role enrichment and an
actual custom-installation live proof remain open. Containers still filters a
bounded loaded sample and needs the next server-inventory continuation.

Validation: **1,463 frontend tests across 114 files** pass, followed by **50
Assets tests** after the final identity-column width refinement. Production
build/typecheck, frontend lint, affected Go vet, generated OpenAPI contracts,
107 endpoint mappings and plan checks pass. **56 focused fresh PostgreSQL
race/shuffle executions** pass with no skips: six Assets, 24 Components and 26
Runtime/Timeline/export cases. Fixtures exercise more than 1,000 components,
1,205 workload assets and multi-page uncapped NDJSON, with tenant/sibling scope,
restart evidence beyond the former 200-event sample, read failures and stream
error frames. Shared arrangement tests cover order/CSV agreement, stale state,
identity isolation, measured pins, pointer/keyboard bounds and reset.

Helm revision **60** runs frontend `inventory-controls-fit-20261012`, API
`inventory-controls-20261012`, migration `audit-lookup-20261012`, schema 173 and
all seven deployments ready. Live reads reconcile **804 assets** and **357
images** with full matching CSV, and **12 components** with **one scanner**.
Two-row continuation reads do not overlap. Filtering Components preserves the
full-scope summary. Runtime events, overview and Timeline return role fields;
this live workload sample is unclassified. A one-hour NDJSON export returns
**1,030 findings**, no threats and no error frames; positive threat-role and
failure cases are fixture-qualified.

The collaborative browser verifies populated Assets/Components header/body
alignment at 1280px and 640px, with no document overflow or clipped actions.
Assets identity now retains at least 280px while compact metadata yields space.
Keyboard resizing and scroll Home/End, saved pin reload, narrow pin suspension,
layout reset and scanner-role deep links are verified in the live console.
Actual pointer dragging remains component-test qualified. Temporary table
preferences and the 1280px viewport were restored. No live policy, scan,
acceptance, capture, migration or saved-view writes were submitted.

The next bounded inventory slices are Containers (3,000-row source cap before
local filters) and Nodes (filters/sort over loaded pages, local selection and
stale evidence on failed refresh). Further gaps include registry-image global
sorting/export, scan-job continuation, CVE affected-evidence caps, Compliance
raw-evidence continuation and network/runtime history exports. Named saved views
and the full accessibility/cross-dataset matrix remain open; these checks do not
close the parent UI-2/3/4 rows.

The image-identity correction replaces raw SHA names with reported repository/tag
references in Assets, its preview, asset detail, risk workspace and acceptance
review. Raw identity is preserved; the backend exposes `display_name` and uses
it for name sorting and literal search. Full CSV retains raw Name/Digest and adds
Display name. Digests in inventory/preview/image metadata/acceptance review are
collapsed behind **Show digest**; asset labels are also collapsed so references
containing SHA values do not leak into the default preview. Missing name metadata
is shown as Unnamed image rather than making a digest the primary name.

Helm revision **61** deploys frontend/API `asset-identity-20261012` from the isolated
image-identity commits, retaining migration `audit-lookup-20261012` and schema173;
all seven deployments are ready. **1,472 frontend tests /115 files**, build,
typecheck, lint, affected vet and OpenAPI contracts pass. **10 focused fresh
PostgreSQL race/shuffle executions** pass without skips, including named/raw
identity, detail/list/export agreement, stable name ordering, full-reference
search and existing asset scope/count checks. Live API verifies 100 sorted image
names and two matching search/CSV records. The collaborative browser displays
`docker.io/pgvector/pgvector:pg16` instead of its SHA, finds no SHA in the default
image inventory view, and reveals the exact digest when Show digest is opened.
Containers/Nodes and network/capture role work remains uncommitted and is not
included in this image-identity release.

The node/container continuation removes the container 3,000-entry pre-filter
cap and loaded-page node filtering. Both inventories now apply server filters,
stable sorting, pagination, complete matching summaries and matching CSV through
the shared inventory contract. Each request reads count/summary/rows in one
repeatable-read snapshot; successive pages remain current-state reads. CSV is
explicitly bounded at 100,000 records. URL filters/sort/history and exact cluster
scope are preserved; missing node selections never substitute another node,
failed refreshes hide stale evidence, and unknown timestamps say Not collected.
Container image SHA values use the shared closed-by-default Show digest control.

Containers include only running entries in latest per-node snapshots. Workload
risk/facts retain advisory pod-prefix attribution and can repeat per container;
they are not per-container settings. Platform classification is independent:
exact tenant/cluster/namespace pod ownership must resolve unambiguously, while
known platform namespaces retain classification except IP endpoints. Prefix-only,
conflicting, foreign and sibling owners cannot borrow custom-installation labels.
Session/conversation roles now use the same exact ownership rules. Multi-cluster
organization conversations remain unclassified when their merged endpoint has no
unique cluster. Capture action responses include roles; lookup failure rolls
back Start/Claim or rejects Upload/Status before their mutation.

The inventory source passes **1,520 frontend tests /119 files**, followed by **89
focused tests** for container width refinement; build/typecheck, lint, affected
vet, generated OpenAPI/contracts, 107 endpoint mappings and plan checks pass.
**78 fresh PostgreSQL race/shuffle executions** pass without skips: Nodes14,
Containers4, network/capture60. Fixtures cover inventories beyond the old caps,
literal filters, exact ownership, tenant/sibling isolation, export agreement,
malformed responses and real role-lookup failure rollback. Six affected browser
cases are discovered across two specs; the standalone runner was not executed.

The user-requested status cleanup changes the shared VerdictBanner across its
68 page/workflow consumers: the colored box and default explanatory paragraph
become a compact status row. A keyboard-accessible Details button controls the
supporting context. Status titles and actions stay visible; essential action
consequences, TLS-off warnings and stale-edit instructions opt into inline detail.
Normal inventory caveats remain available without dominating the page. This
continuation passes **1,523 frontend tests /120 files**, including disclosure,
independent actions and inline consequences, plus full lint and production build.

Helm revision **63** runs frontend `compact-status-20261012`, API
`node-container-inventory-20261012`, migration `audit-lookup-20261012` and
schema173; all seven deployments are ready. Revision62 first deployed the
inventory/role batch; revision63 adds compact summaries and container width
refinement. Final live reads reconcile **22 containers**, **16 platform rows**,
**six visible when platform is hidden**, and **one node** with full matching CSV.
One-row container continuation does not overlap; node source-cluster host-CVE
filter returns the same one node. Search/CSV agree. Large continuations and
custom ownership positives remain fixture-qualified. Network session and
conversation reads succeed; no live capture or security mutations were submitted.

The collaborative browser verifies Nodes/Containers alignment at 1280px and
640px, with contained scrolling and no clipped actions. Container search retains
332px at desktop and 318px at the narrow viewport; identity columns keep useful
minimum widths. SHA is hidden until Show digest is clicked. Missing node
selection survives sort and browser Back without substitution. The quoted Nodes
status is **32px instead of80px** on desktop, and40px on the narrow viewport;
its paragraph is hidden by default and mouse/Enter toggles work. Viewport was
restored to1280px, with Nodes open and Details closed.

The registry/job continuation adds server filtering, stable sorting, complete
matching summaries and matching CSV to Registry Images and Scan Jobs. Count,
summary and rows share one read snapshot; later pages read current state. CSV
uses the same predicates and reports its 100,000-row cap. Registry scan evidence
correlates the latest organization-wide exact repository, not a particular
registry, tag or digest. Critical/high summary values count findings; scanned
values count repositories. Both scan-job screens use the same response validation
and URL/history contract; stale, foreign or malformed evidence cannot enable
job actions. Digests remain behind Show digest, and page CSV retains raw identity.

Registry queue KPIs now count all organization image jobs, including manual
jobs. Each visible registry's row and Stop action use all jobs linked to that
registry, matching the backend cancellation scope. These per-registry summaries
are independent current-state reads, fetched only for mounted rows. Metadata
CSV marks unfetched off-page counters Not loaded. Queue metrics returned with
scan-job inventory remain organization-wide and independent of list filters.

Network Map and Exposure now resolve exact actual-cluster ownership and emit
explicit unknown roles for ambiguous workload identities and IP endpoints.
Merged graph nodes cannot borrow one source cluster's installation labels.
Exposure aggregates observed sessions before workload enrichment, preventing
same-name workload kinds from multiplying session counts. Embedded deployment
runtime/network evidence now includes actual cluster and role fields; Deployment
and Risk tables/CSV retain them and withhold explicitly foreign-cluster rows.
Unknown deployment cluster no longer matches other clusters. The existing
50-row embedded-evidence and per-direction Exposure bounds remain unchanged.

The frozen source passes **1,628 frontend tests /126 files**, production
build/typecheck and full lint. The initial unconstrained concurrent run had one
Nodes timing failure; Nodes passed separately and the complete final run passed
with two workers. A shared Pager fix now shows0–0 on empty continuation pages.
**170 fresh PostgreSQL race/shuffle executions** pass without skips: Registry2,
ScanJobs4, Network154, embedded Deployment evidence10. Fixtures exercise source
caps, literal filtering, exact scope, summaries/CSV, ambiguous roles and lookup
failure paths. Affected vet, generated OpenAPI/contracts, 107 endpoint mappings
and plan checks pass. Five connector browser cases were discovered after their
selectors were updated; the standalone browser runner was not executed.

Helm revision **65** runs frontend `scan-jobs-fit-20261012`, API
`registry-jobs-roles-20261012`, migration `audit-lookup-20261012` and schema173;
all seven deployments are ready. Revision64 deployed the inventory/role batch;
revision65 refines target width and dates. Those final UI refinements pass **152
focused tests**, build/typecheck and changed-source lint after the full suite.
Live reads reconcile **14,406 scan jobs** with matching CSV, **seven** matches
for an exact target/status search and **14,397** source-cluster jobs. Missing
registry scope returns404. Map returns **121 workloads /300 flows**, Exposure
**four egress rows**, and **17 deployment details /850 embedded network rows**
carry exact cluster and explicit role fields. Runtime-event positives and
registry-image/queue positives remain fixture-qualified because these live
sources are empty. Counts are observations of current state, not durable totals.

The collaborative browser reaches the third scan-job page, verifies sort/reset
and Back restoration, and exports all **four** matches for a live image query.
Both job tables align at1280px and640px with contained scrolling and no clipped
actions. Scanner target width is260px rather than160px; both ledgers use compact
relative times with exact timestamp tooltips and raw ISO values in CSV. Digests
remain hidden by default. No live scan, policy, capture or acceptance mutations
were submitted. Full accessibility and cross-dataset acceptance remain open.

The detail-evidence continuation replaces the Asset Findings and Node CVE
page-local inventories with full server filtering, stable paging, complete
matching summaries and matching CSV. Asset evidence keeps exact-cluster asset
findings separate from the latest organization-owned exact-digest scan; these
are evidence records, not unique vulnerabilities. Node evidence preserves the
source-cluster OR effective-target-cluster attribution rule. Historical finding
instances retain the composite UUID/timestamp identity instead of collapsing
repeated UUIDs. Existing bounded detail payloads remain compatibility surfaces;
the new primary tables do not derive full counts from them.

Asset metadata reads now distinguish missing records from database failures,
and propagate failures in scan findings, image metadata, software inventories
and acceptance history. Account changes isolate the parent asset cache and reset
risk-decision context. Pending/failed/malformed inventory reads hide finding
counts and exports. The shared matching-CSV control captures the clicked download
callback and rejects a changed, unavailable or unmounted scope before dispatch.

CVE affected Images, Workloads, Clusters and Packages each read a full server
inventory; package and cluster totals no longer derive from capped image or
workload pages. Canonical finding IDs remain deduplicated per workload
association, whose identity includes cluster, deployment, workload ID, namespace,
name and kind. Exact image-link tuples are retained together in UI disclosure
and structured CSV, so separately aggregated repository/tag/digest fields cannot
invent an image identity. A known image digest requires an exact scan digest;
mutable tag/reference fallback applies only when the digest is absent. This fixes
inherited cases where a different image could supply apparently clean evidence.
Counts of findings across workloads are association counts,
not globally unique vulnerabilities. Raw compliance normalizes all source scopes
and expands framework mappings and active exemptions before filtering, summary,
paging or export. Embedded deployment compliance supplies its exact target set
before the collector limit, preventing unrelated workloads from consuming it.

The full frontend suite passes **1,715 tests across 132 files**. The initial run
had one scanner-source test that inspected the table before refresh completed;
waiting for the rendered table resolves it without a product change. The final
malformed-response guard passes **67 focused compliance tests** after that run.
Production build/typecheck, full lint, affected Go vet, generated OpenAPI/contracts,
107 endpoint mappings and plan checks pass. **50 fresh PostgreSQL race/shuffle
executions pass without skips**: Asset 6, Node 30, CVE 4, Compliance/deployment 10.
Fixtures include inventories beyond legacy caps, tenant and cluster exclusions,
historical composite finding IDs, mutable-tag digest replacement, stable paging,
full matching CSV and malformed/unavailable evidence. These are changed-domain
checks; the pre-existing default test database is schema 161, so an unrelated full
server run against it is not claimed green.

Helm revision **66** deploys API/frontend `evidence-inventory-20261012`, retaining
migration `audit-lookup-20261012` and schema173; all seven deployments are ready.
Live list/CSV reads reconcile five assets with **1,606 /510 /906 /83 /160** records,
**641** host finding instances (**537** unique advisory IDs), and **794** source
compliance rows. One live CVE has **3 images /2 workload associations /1 cluster
/4 package records**, each agreeing with matching CSV. Filtered exports also agree
and a missing asset returns404. Asset records include both attributed findings
and canonical scan evidence; totals are not unique-CVE counts. Later compliance
browser reads observe 778 rows, reflecting changing source state.

The collaborative browser verifies Asset page 2, Compliance paging and Back
restoration, all four CVE tabs, hidden digests, and desktop/640px alignment with
contained table scrolling and no clipped actions. The exact host warning quoted
by the user is a **32px** compact row with its explanatory text collapsed behind
Details. No live scan, policy, capture or acceptance mutations were submitted.

Final browser-driven refinements hide internal Node finding IDs by default,
remove duplicated advisory text and collapse inventory context. Asset titles are
limited to two lines with full-text tooltips; Asset Observed and CVE Last seen
sorts expose the shared hidden-sort indicator and column reveal. CVE names receive
more width, preserve digest disclosure and show a truthful missing-title fallback.
Compliance source evidence uses a short count line, with semantics in its existing
disclosure; Controls KPIs and verdict no longer appear over the Source evidence
or Schedules tabs. These final refinements pass **210 focused tests** (Asset 45,
Node 34, CVE 62, Compliance 69), production build/typecheck and full lint.
Helm revision **67** runs frontend `evidence-layout-20261012` with the same API,
migration and schema; all seven deployments are ready. Live checks confirm the
short source-evidence caption, Controls-only metrics, title fallback, expanded
image-name width and hidden Last seen sort indicator. Saved column preferences
remain honored; Reset table preferences restores the new defaults.

The network/history continuation gives Conversations, Sessions, DPI Threats and
Runtime event history full matching summaries, stable server sorting, URL paging
and matching CSV independent of the displayed page. Platform filtering is applied
before network counts, pages and exports; roles use exact tenant/cluster ownership
and keep ambiguous endpoints unclassified. Conversation inventories and CSV use
durable hourly rollups; legacy unpaged hot-graph responses explicitly identify a
bounded live snapshot. Sessions retain the five-minute agent snapshot cohort.
Runtime history covers retained matching records independently of its separate
window dashboard. These cohorts do not establish collection or enforcement coverage.

Each inventory checks returned scope, filters, ordering, counts and row identities
before showing totals or enabling exports. Sessions use cluster/node/session IDs;
partitioned runtime events use UUID/timestamp pairs. History selection preserves
that physical identity. A queued session action cannot proceed after its scope or
fresh inventory changes. Matching CSV is capped at 100,000 with explicit total,
limit and truncation headers. Page CSV retains exact numeric values, all application
labels and source timestamps. The network toolbar now shows only controls applicable
to the active workspace, and each table reports its own update time. Shared table
preferences, semantic column widths and compact status disclosures remain in use.

Backend validation for this increment passes **98 fresh PostgreSQL race/shuffle
executions**, without skips: Conversations 30, Sessions 30, runtime threat and
role regressions 30, Runtime event inventory/export 8. These are executions across
four focused runs, with some shared network tests exercised in both runs. Fixtures
include 6,007 conversation pairs, 657 live sessions, 1,206 matching threats,
partitioned event UUID/timestamp collisions, exact ownership/tenant isolation and
100,000-row CSV caps. Threat regression coverage includes existing ingestion and
category/group filtering. Separate affected-domain results do not establish a full
server-suite pass against the obsolete default schema161 database.

Frontend validation passes **1,816 tests across 134 files**, followed by the final
**25-case** Network integration run that adds named-group restoration coverage.
The full run included the preceding 24-case version of that file. The 51 inventory
validator cases cover malformed rows, mismatched filter echoes, unknown roles and
scope metadata. Production build/typecheck, full frontend lint, affected Go vet,
OpenAPI regeneration, **29 server contract checks**, 107 endpoint mappings and
parity-plan counts pass. Two enterprise browser cases were discovered, not run;
that discovery is not live browser acceptance.

Live verification at Helm **68** reconciles **296** conversation pairs (**13**
with platform traffic hidden), **168** sessions and empty DPI threat cohorts with
matching CSV. A bounded Runtime history read before 22:00 UTC reconciles
**2,025,049** events with a correctly reported **100,000-row** truncated export.
These are point-in-time counts; live ingestion and retention change later totals.
The browser verifies conversation page 2, sort reset and Back restoration, session
page 2, matching downloads, explicit empty threat state and desktop/640px alignment
without document overflow or clipped actions. Status disclosures remain 32px.

That live volume exposed the old one-million-offset ceiling. The follow-up uses a
shared signed-32-bit offset bound across the four inventories and matching UI page
limits. Other inventory-route callers retain their existing bound. Blank workload
identities are excluded from Runtime history's renamed **Identified workloads**
KPI. Session endpoint and byte columns have distinct labels. Follow-up fresh DB
qualification passes **22 executions**: network 14, threat 2, Runtime 6; existing
CSV-cap behavior is unchanged. The high-page fixtures verify offsets beyond two
million, invalid boundary rejection and full summaries on empty deep pages.

Final verification passes **1,824 frontend tests across 134 files**, production
build/typecheck, full lint and the updated server contracts. Helm **69** runs
API/frontend `network-history-depth-20261012`, retaining migration
`audit-lookup-20261012` and schema173; all seven deployments are ready. The live API
returns 100 records at offset **2,000,000** from a **2,045,875-record** cohort, with
zero identified workloads when identities are absent. The browser independently
loads page **20,001**, advances to 20,002 and restores 20,001 with Back, preserving
aligned tables at desktop/640px widths. Counts vary between these reads. Deep
history requests measured approximately **8–10 seconds** on this development
cluster; this does not qualify fleet-scale latency. No live policy, scan, session
termination, capture or acceptance writes were submitted.

The profile-inventory continuation adds independent, read-only Process Baseline
and File Monitor inventories. Server filtering, stable sorting, paging, full
matching summaries, namespace facets and matching CSV replace per-workload lazy
reads in the primary views. Both exports cap at 100,000 profiles and report
truncation. Shared namespace/name profiles are deduplicated across workload kinds;
ambiguous owners remain explicit and cannot be selected arbitrarily for writes.
Exact owned pod references can contribute evidence; guessed names cannot.

Process summaries cover all retained process events; the separate detail view
still labels its latest-1,000-event sample. Agent bundles and cached allowed sets
preserve older retained process identities, hash and parent constraints across
restart, detail reads and mode changes. File summaries likewise aggregate all
retained matching events. Configured modes and retained observations do not
establish collection completeness or active enforcement. Lifecycle cards are
explicitly scoped to the current server page.

Both primary pages use shared table geometry, preferences, pagination and compact
Details disclosures. URL filters/sort/pages survive navigation; unavailable,
malformed, invalidated or changed-owner evidence withholds rows and exports.
File-rule forms preserve drafts and compare refreshed configuration before review;
update/delete can atomically require the reviewed timestamp and return 409 for a
conflict. Legacy clients may omit that optional revision. A conflict performs no
rule write, audit entry or federation tombstone; legacy state hydration may still
run before the comparison.

Asset and Finding lists, detail evidence and matching CSV now expose the same
backend-evaluated platform role. Exact workload ownership is required; image,
repository, cloud, node, ambiguous and unsupported identities remain unclassified.
Role columns are available through shared column preferences and hidden by default.
A common route-error page also provides explicit reload and Clusters recovery for
failed lazy imports or render errors, preserves the current URL on reload, and
keeps internal error details out of the interface.

Validation passes **1,887 frontend tests across 137 files**, full frontend lint,
production typecheck/build, affected Go vet, generated OpenAPI and server contract
checks. The broader runtime package passes **568 fresh PostgreSQL race/shuffle
executions**, count 2, without failures or skips; **36 separate Asset/Finding role
executions** also pass. Profile fixtures cover over 600 profiles, over 1,000
retained events, truly older cached identities, duplicate owners, revision
conflicts, full matching counts/CSV and malformed or stale frontend evidence.
Evidence: `/tmp/profile-runtime-regression-db/`,
`/tmp/asset-finding-roles-final-db/`, `/tmp/profile-full-frontend.log`.

Helm **70** deploys API/frontend `profile-inventory-20261012`, retaining migration
`audit-lookup-20261012` and schema173; all seven deployments are ready. Read-only
live profile API/CSV checks agree on **17** profiles in each inventory and **6**
when platform profiles are hidden; empty filters and offset **2,000,000** preserve
correct totals. This live cohort has no retained process/file events, so positive
event/count behavior is fixture-qualified. Baseline reads measured roughly
0.3–2.9 seconds; file reads were roughly 0.02–0.04 seconds in these bounded checks.
Sampled Asset/Finding detail roles agree with their list records, and matching
CSVs include the role field. See `/tmp/profile-inventories-live-results.json` and
`/tmp/profile-evidence-role-live-results.json`.

Native browser checks verify profile sorting/filtering, lifecycle and rule tabs,
Back restoration, empty-page recovery, matching downloads and file-rule
Advanced/Cancel navigation without submitting authoring changes. Header/body
alignment matches at desktop and 640px widths, with no document overflow or
clipped actions; collapsed status disclosures remain **32px**. Existing saved
column selections are preserved; Reset columns restores the new baseline defaults.
The live file profile has no custom rules, so concurrent edit/delete acceptance
remains covered by the fresh database and frontend fixtures, not a live mutation.

The deployment-findings continuation adds an independent direct-workload
inventory shared by Deployment Detail and Risk Findings. Exact owned cluster and
deployment scope, full matching summaries, stable server sorting, literal search,
lifecycle/severity/fixability filters and continuation replace the primary
100-record sample. Matching CSV covers up to 100,000 physical observations and
reports truncation; page CSV follows visible columns. UUID plus the full original
timestamp identifies each observation, including repeated UUIDs and legacy
lifecycle values. Canonical namespace/name ownership ambiguity remains explicit;
pod attribution requires a unique exact owned link. Source and effective target
clusters are preserved separately, with conservative backend platform roles.

Both parent views use the shared table, URL state and compact Details disclosure.
A read-only detail peek preserves the exact observation and closes on scope or
freshness changes. Technical IDs stay under Source details. The Risk Overview
retains an explicitly labeled top-five preview from the legacy bounded payload
and links to the full inventory. Historical finding authoring still needs exact
UUID/timestamp identity and concurrency checks across detail, bulk actions,
comments, audits and notifications; UUID-only actions are not exposed from this
new inventory.

Deployment image and file-risk evidence now require an exact, case-sensitive
match when an image digest is known. Mutable reference/tag fallback applies only
when the link has no digest. Scan selection has a deterministic tie-breaker and
owned deployment/cluster and child-organization checks. Reused tags cannot borrow
another digest's evidence. The file-risk artifact preview remains capped at 20.

Matching exports using the shared inventory control now recheck scope immediately
before browser download dispatch, after the HTTP response arrives. The callback
is propagated through all 19 API seams used by that control. Unmounting, changing
context or temporarily disabling stale evidence invalidates the pending request,
even if the original context becomes active again. Existing exact-cache
preflights also run after the response where present. This does not qualify
independent export controls that do not use the shared inventory component.

Qualification covers **1,960 frontend cases across 139 files**: 1,957 passed in
the full run; three old callback-signature expectations were corrected, then all
73 cases in that file passed. No production edit followed that run. Full lint,
production build/typecheck, affected Go vet, OpenAPI/contracts and endpoint-map
checks pass. The combined Deployment backend passes **42 fresh PostgreSQL
race/shuffle executions**, count 2, with no failures or skips. Fixtures cover
over 1,300 findings, repeated UUID observations, legacy lifecycle values and
100,005 matches producing a correctly labeled 100,000-row CSV. Image/file-risk
fixtures cover exact and missing digests, reused tags, cross-tenant children,
cross-cluster links and tied scan timestamps.

Helm **71** deploys API/frontend `deployment-findings-20261013`, retaining migration
`audit-lookup-20261012` and schema173; all seven deployments are ready. The live
ingress workload returns **83** direct findings; list and CSV agree for all,
fixable, literal-search and empty filters. Two-row pages do not overlap; offset
2,000,000 preserves totals on the empty page, and matching CSV ignores page offset.
Missing, malformed, duplicated and foreign scope checks return the expected
errors. Bounded inventory reads measured **0.03–0.15 seconds** in this sample;
the existing aggregate deployment detail remains slower and is not qualified
for fleet-scale latency (9.8 seconds in the image-identity check). Both linked
images match their selected scan's exact digest in the live API. See
`/tmp/deployment-findings-live-results.json` and
`/tmp/deployment-image-identity-live.json`.

Native browser checks pass in both Deployment and Risk Findings: exact-record
inspection, Source details disclosure, Escape/focus return, literal search,
matching downloads, sort/Back restoration and empty-page recovery. Tables align
at desktop and 640px widths with no document overflow or clipped actions. The
compact status is 32px on desktop and wraps to 40px in the narrow workload view;
the original Nodes status is 32px with its explanatory paragraph hidden until
Details is opened. No live authoring or scan actions were submitted. Positive
continuation beyond 100 records remains fixture-qualified for this small live
workload cohort.

The October 13 browser acceptance continuation resolves the obsolete fixture,
route, disclosure and label expectations in the existing suite without deleting
or skipping cases. The **entire 202-case run passes** against isolated PostgreSQL
16/schema173 and the exact Helm-71 API/frontend images, with one worker and no
retries. Production login throttling remains enabled: UI and API login helpers
honor only 429 Retry-After cooldowns, while cookie secrecy, two-tab refresh,
CSRF and refresh-reuse assertions remain intact. Per-run authentication files
avoid concurrent-run collisions; teardown removed its state while preserving an
unrelated sentinel in the configured directory.

Updated high-volume fixtures filter before paging and supply current totals,
summary, scope and ordering contracts. Matching Assets CSV preserves explicit
cluster/search/kind/criticality/order filters, excludes negative cohorts and
omits page bounds; 100,005 matches produce 100,000 ordered exported records.
Image engine outcomes agree with the fixture's completeness summary. Network
fixtures distinguish the organization notification preview from exact-cluster
primary inventory. Finding risk-acceptance checks submit and verify rationale
and expiry through the dedicated form.

Four additional browser cases pass for shared table preferences (five including
setup): Assets, Nodes and Components preserve keyboard resizing, ordering,
pinning, density and visibility across reloads, return focus after menu actions,
retain header/cell geometry at desktop and 640px, support keyboard horizontal
scrolling without document overflow, and reset visibly without changing the URL.
The identity fixture separately verifies user/organization preference isolation,
stale-column removal, width clamping and reset without hiding active URL filters.
Assets/Components use seeded API evidence; Nodes uses an explicit valid host row
because the selected seeded cluster has no host observations. This qualifies
these adopters, not the complete all-page accessibility or named-view matrix.
All 26 changed/new browser source files pass explicit e2e lint and strict
standalone TypeScript checks. Evidence: `/tmp/parity-browser-full.log`,
`/tmp/parity-browser-tables-qualified.log` and the corresponding HTML reports.
Generated screenshots are archived outside the tracked source.

Hosted CI on `1cee666` passes frontend, Go unit/integration and dependency/FIPS
checks. Its browser job still uses the earlier test files and reports 42 failed,
159 passed and one not run; the passing local suite above qualifies their
replacement, not an already-green hosted run. Existing quality/gosec/gitleaks
gates remain open. This acceptance increment changes tests/documentation only;
Helm 71 remains the deployed build. The exact Nodes status cited by the user was
rechecked live: 32px collapsed at 1280px, 40px at 640px, with explanation hidden
until Details is activated and no narrow document overflow.

The October 13 secondary-inventory continuation adds full retained conversation
stream and packet-capture request inventories, independent matching summaries,
stable server filtering/paging and capped matching CSV. Stream rows identify
aggregate tuples; capture rows preserve physical request IDs and distinguish
unknown measurements from zero. Exact owned cluster scope is required, platform
exclusion happens before counting, and CSV never exposes private capture paths.
The capture ledger keeps confirmed rows visible during polling, pauses polling
when requested and reports its own source status independently of the map.

Effective Config now pages the full retained component inventory and exports
explicitly reported system-config revisions. Missing revisions stay unknown and
do not establish fleet adoption. Node Detail and Node Risk share the full host
finding inventory instead of reusing a bounded preview. Shared export guards
invalidate pending downloads on context changes, unmounts, refresh failures or
cache replacement, even if the same scope becomes available again before React
renders. Page CSV checks the reviewed data again at dispatch.

Findings and Timeline use a shared keyboard-accessible saved-view menu with
focus return after deletion. Browser cases cover save/cancel, exact URL and
filter restoration, reload/history, user/organization isolation and storage
failure; Network cases additionally cover import validation and all saved
workspaces. These are bounded adopter checks, not complete accessibility parity.

The production source passes **2,061 frontend tests in 142 files**, global lint
and production typecheck/build. Fresh PostgreSQL 16/schema173 qualification
passes **452 race/shuffle/count 2 executions** across server, inventory-list,
component-revision and secondary-network suites with no skips. Fixtures cover
more than 1,000 records, both 100,001-row CSV caps, tenant/sibling isolation,
nullable measurements and strict query validation. Go vet, generated
OpenAPI/server contracts and all 111 endpoint mappings pass. Evidence:
`/tmp/secondary-frontend-tests-qualified.log`,
`/tmp/secondary-server-db/integration.json`,
`/tmp/network-secondary-final-db/integration.json` and
`/tmp/component-revision-csv-release-db.log`.

The final production images pass the **entire 216-case browser run**, with one
worker, no retries and no skips, against isolated PostgreSQL 16/schema173.
Two new secondary-inventory cases also pass on those images, bringing the
qualified discovered coverage to 218 cases. The focused nine-case Network
saved-view/role/secondary run passes as well. Browser lint and strict standalone
TypeScript checks pass; generated screenshots are archived outside source.
Evidence: `/tmp/secondary-full-qualified-browser.log`,
`/tmp/network-secondary-browser.log` and
`/tmp/network-secondary-final-browser.log`, with their corresponding reports.

Helm **72** deploys API/frontend `secondary-inventory-20261013`, retaining
migration `audit-lookup-20261012` and schema173; all seven deployments are ready.
Live list/CSV checks agree for the sampled retained stream, its platform-hidden
and no-match cohorts, and all 12 component reports. None of those reports claims
an explicit config revision. The live capture ledger is empty, so positive
capture continuation remains fixture-qualified. Invalid/foreign cluster and
query bounds reject correctly; bounded reads took 0.015–0.048 seconds. Native
browser checks render the capture ledger, component revision reports and the
641-record host finding inventory, with details collapsed and no desktop
document overflow. Evidence: `/tmp/secondary-inventories-live-results.json` and
`/tmp/secondary-inventory-deploy.log`.

A genuine isolated chart installation in `orbit-install-proof` now qualifies
custom-namespace discovery: the real Ready frontend pod, UID/image ID and
Pod→ReplicaSet→Deployment chain were recorded. Scoped API/CSV show two core
workloads and one core container; hiding platform components returns zero while
observation timestamps continue advancing. Native browser hide/show restores
both workloads. This frontend-only fixture does not establish component
heartbeats or the complete role/export matrix. Its default helper image was
rejected by existing admission enforcement; using the deployed frontend image
for the directory-creation step allowed installation without policy changes.
The temporary release was uninstalled after verification. Evidence:
`/tmp/custom-install-proof/verification.json` and accompanying JSON/CSV.

Hosted CI on `0c6790f` now passes frontend, browser, Go unit/integration and
dependency/FIPS checks. This confirms the provider-discovery Retry-After handling
and the Runtime settled-query correction from the preceding run. Existing
quality/gosec/gitleaks gates remain open; the aggregate required gate is not green.

### Exact finding observations and finite navigation acceptance — October 13

Schema **174** binds finding detail, actions, comments, exception evidence and
audit attribution to the physical `(id, first_seen_at)` observation. Exact routes
require a reviewed decimal-string revision for writes and return conflicts when
evidence changed. UUID-only callers resolve only a unique retained observation;
ambiguous IDs require a choice. The narrow standalone `id:<UUID>` chooser includes
owned workload recurrences without changing ordinary global vulnerability totals.
Old UUID-only comments remain separately disclosed; no migration guesses which
observation they belonged to. Scanner updates preserve the exact selected row.

Console links, selections, bulk operations and cache keys preserve microseconds.
Stale forms retain drafts, pause Save and provide explicit Refresh observation.
Unconfirmed late responses prevent blind repeat writes. Generic asset findings
carry exact identity; canonical image-scan evidence stays separate. Federation
passes exact selectors/revisions without broadening custom read allowlists.

The final build passes **2,091 frontend tests in 143 files**, lint and production
typecheck/build. **228 fresh PostgreSQL 16/schema174 executions** pass with race,
shuffle, count 2 and no skips across finding, scanner, server and affected handler
contracts; focused asset/federation and occurrence suites also pass. OpenAPI,
affected Go vet and **118 endpoint mappings** pass. Evidence:
`/tmp/finding-instance-frontend-qualified-tests.log`,
`/tmp/finding-instances-broad-db/integration.json` and
`/tmp/finding-instance-endpoint-mapping.log`.

The full **248-case browser suite** passes on frozen API/frontend/migration
`finding-instances-20261013` images, with one worker and no retries/skips.
The finite alias matrix covers all **96 declared redirects** and **49 supported
detail/form suffixes**, plus true soft navigation, history, repeated filters,
fragments, sibling scope and empty-cluster fallback. A source guard detects
unlisted new aliases. Evidence: `/tmp/finding-instance-full-browser.log` and its
report/results; generated screenshots are archived separately from source.

Helm **73** deploys these images and schema174; all seven deployments are ready.
Live read-only checks sample five of 6,123 finding rows and verify three exact
detail/comment/chooser/CSV cohorts, malformed selectors and foreign scope.
Details and forms preserve the raw observation timestamp; Cancel returns to the
same observation. Status rows remain 32px with details collapsed and no document
overflow at 1280px. Positive recurrence, comments and mutations are disposable
fixture evidence; no live finding state was changed. Evidence:
`/tmp/finding-instances-live-results.json` and `/tmp/finding-instance-deploy.log`.

Seven deterministic Dashboard browser cases pass, including four additional
cases beyond the full suite (**252 discovered cases**). They reconcile strongest
mode vulnerability IDs/exposure, host/platform rollups, runtime/chart temporal
boundaries, exact selected organization audit IDs, graded cross-framework
compliance, and image/host/fixable/privileged/root/exposure tile counts through
pages, exports, history and reload. Missing audit records remain missing after
newer events arrive. Zero, null and false exposure facts preserve source units.
Together with existing severity/acceptance, component/deny-link, backend and live
evidence, this closes exact tile destinations. Operational source-count
reconciliation is a separate acceptance item. Evidence:
`/tmp/dashboard-evidence-final-browser.log` (7 passed).

The finite remaining console audit identifies runtime-policy review guards,
Network Rules server filtering/continuation beyond its old 3,000-row cap,
Audit filters/matching CSV, global CVE matching CSV and stale summary handling,
remaining saved-view adopters, and shared preference/accessibility acceptance.
Small follow-ups expose observation times in the ambiguity chooser, link
workload-finding peeks to exact detail, and return roles in network peer diagnostics.
Dormant SSE and fleet-scale export latency remain unqualified; correctness at a
100,000-row cap is not a performance claim. Broader infrastructure/security
acceptance remains separate from the selected console scope.

The reviewed-inventory continuation (October 13, Helm **74**) deploys frozen
`reviewed-inventories-20261013` API/frontend/migration images and schema **176**.
All seven deployments are ready. Runtime-policy changes use reviewed decimal-string
versions and exact cluster ownership; migration175 makes legacy renames invalidate
review. Network peer diagnostics return role, scope and source-cap metadata. The
additive Network Rules inventory filters and sorts before pagination, uses exact
endpoint-pair identities and exports the complete matching cohort up to 100,000.
Audit and global CVE catalog matching exports use the same predicates as their
lists, with explicit lookahead caps. Export guards recheck the current operator,
scope and evidence before download. Audit chain hashes and other added technical
metadata migrate behind Columns; the exact Findings chooser reveals observation
times without erasing ordinary table preferences.

Validation: **2,162 frontend tests / 147 files**, global lint and production build
pass. **136 fresh PostgreSQL executions** across runtime revisions (16), network
rule/peer/portability (58), Audit CSV (28) and CVE CSV (34) pass. Schema/OpenAPI
contracts, affected Go vet and all 118 endpoint mappings pass. The corrected full
browser run passes **265/265**, one worker with no retries/skips, against the frozen
production images; its first attempt was invalid because the login helper pointed
to a different API and was stopped before this corrected run. Evidence:
`/tmp/reviewed-inventory-qualified-browser.log`,
`/tmp/reviewed-inventory-frontend-full-tests.log` and the per-domain database logs.
Live read-only checks reconcile 1,712 Network Rules and 43 platform-hidden matches
with their complete CSVs, exact Audit event scalars and positive/empty CVE filters.
Live runtime and peer samples were empty; their positive cases remain isolated
fixture/database evidence. The native live Audit status is 32px with Details closed
and chain hashes absent from default columns. Evidence:
`/tmp/reviewed-inventories-live-results.json` and
`/tmp/reviewed-inventory-deploy.log`. No live policy writes were performed.

### Final selected-console acceptance — October 13

**Selected console scope complete — Helm75/schema177 deployed and verified.**
The seven remaining UI-1/2/3/4 rows close against frozen production artifacts,
source/database qualification, the finite browser matrix and live read-only
verification. API/frontend/migration use `console-parity-20261013`; migration177
succeeded and all seven deployments are ready. This does not close the broader
security, fleet enforcement or infrastructure release.

Live checks validate exact organization/cluster receipts for executive and
compliance HTML (13 retained compliance checks, untruncated), reject invalid and
foreign report scope, and confirm identity/roles on six dashboard workload rows
(two core). Backup inventory and matching CSV agree on zero owned runs; there is
no successful owned backup, so positive history/latest-success claims remain
isolated database/browser evidence. Network Rules reconcile 1,712 all matches,
43 platform-hidden matches and zero search matches with their complete CSVs;
Audit and positive/empty CVE matching exports pass. Native live Backup has two
32px collapsed status rows, hidden SHA columns and no document overflow; Network
Rules displays 100 of 1,712 with server controls and no overflow. No live policy
or backup writes were performed. Evidence: `/tmp/console-parity-final-deploy.log`,
`/tmp/console-parity-final-live.log` and
`/tmp/console-parity-final-inventories-live.log`.

The preceding frozen console source passes **2,284 frontend tests in 153 files**,
lint and production typecheck/build. The final Backup export-receipt/CORS follow-up
subsequently passed 74 focused frontend tests, lint and typecheck, and is included
in the deployed console-parity frontend/API artifacts; the larger predecessor
suite is not counted as a rerun of that follow-up. The schema177 parent
production-image browser suite passes **275 cases**, one worker, without retries/skips. The final artifact adds
**three Backup cases** and **four reviewed runtime/peer cases**, all passing;
the runtime run requalifies three existing cases plus the new disabled-policy
re-enable case, so these counts are not added as distinct suite totals. The
fresh seeded PostgreSQL 16/schema177 affected-handler suite passes **1,346
race/shuffle/count 2 executions**, supplemented by **four Backup inventory
executions** on a separate fresh database. Evidence:
`/tmp/console-parity-frontend-tests.log`,
`/tmp/evidence-workflow-qualified-browser.log`,
`/tmp/backup-inventory-browser-frozen.log`,
`/tmp/parity-browser-runtime-enable.log`,
`/tmp/evidence-workflow-full-handler-db.log` and
`/tmp/backup-inventory-fresh-db.log`. Browser cases use isolated production
stacks or deterministic API fixtures; they do not perform live security writes.

The finite source audit covers **110 lazy-routed page sources**: 68 directly use
the shared verdict, 41 are dedicated or delegated forms, and one is the Settings
navigation directory. No primary undisclosed `StatGrid` exceeds five metrics;
no page declares a competing native inventory table. Shared URL tabs, dedicated
forms and Advanced disclosure provide one primary workspace at a time. The
Switchboard is now a compact verdict, three metrics and navigation workspace;
its expert guidance is collapsed and cluster transitions update every link.
The accepted exceptions are dedicated forms without fabricated metric rows,
the Settings directory, URL-bound read-only entity peeks and local nested
inspector tabs within the URL-bound Network workspace. Runtime promotion is a
confirmation without authoring inputs. Scanner, Timeline and workload finding
peeks are read-only; they are not duplicate editors. Source evidence:
`/tmp/console-page-contract-final177.jsonl` and `frontend/CLAUDE.md`.

High-volume console lists now qualify server continuation, matching cohort
filters/sort/summary/CSV, visible caps and unavailable evidence. The last Backup
history consumer no longer stops at 50: its inventory pages, filters and sorts
all owned retained runs, distinguishes matching CSV from current-page CSV, and
gets latest successful backup evidence independently of the page/filter. Shared
tables qualify column geometry, keyboard layout controls, hidden-column sorts,
operator-scoped preferences, stale-column migration and explicit reset. Saved
views preserve active URL filters, history and scope; storage failures retain
drafts. Export dispatch rechecks the reviewed operator, source and cache
identity, including pending-response scope changes and invalidate-to-ready
cycles. Live SSE, latency budgets and fleet-scale performance remain separate
unqualified work, not implied by correctness at an explicit 100,000-row cap.

The finite role matrix includes workload/container, asset/generic finding,
node/deployment evidence, runtime/threat, baseline/file profiles, Network
map/exposure/session/conversation/stream/PCAP/peer/rule/lifecycle evidence,
Dashboard workload rows, report workload context and retained finding NDJSON.
Ambiguous ownership, foreign-cluster identity and IP-only/external peers keep
explicit unknown roles. JSON, shown/matching CSV and report source evidence
agree where those formats apply. The genuine custom-namespace chart proof above
establishes continued discovery while hidden; fresh database and browser cases
qualify the other role-bearing surfaces. Package/image artifacts, binary PCAP
and portable authored policy YAML are not invented workload-role inventories.

Dashboard downloads prefer scoped HTML, with organization/cluster receipts
validated before Blob dispatch; absent or mismatched receipts fail closed.
Scheduled report forms default to HTML/JSON, retaining optional PDF. Schema177
records the actual immutable artifact format, MIME and filename, including HTML
fallback when the optional PDF renderer is missing. Legacy artifacts remain
unknown instead of borrowing a schedule's current format. Compliance reports
use full retained effective-exemption summaries and graded pass/fail units;
executive reports label retained findings, actual names/roles and the separate
organization-wide MTTR source. CSV uses `encoding/csv`. Command tests generate
real HTML/CSV artifacts from more than 5,000 checks. There is **no deployed
compliance-scheduler chart workload proven here**: scheduler command-level
artifact qualification does not establish scheduled live collection/delivery.
Existing Network policy writers also do not gain new reviewed-revision CAS from
this console acceptance.

Hosted commit `ddde1e8`, run **38342409331**, passes browser, integration, Go unit,
frontend, FIPS and govulncheck jobs. Quality, gosec and gitleaks remain **FAIL**;
the overall required release gate is not green. This selected-console closure
does not close broader security, CNI/dataplane enforcement, infrastructure,
provider, migration, scheduler operation or release requirements.

The admission-engine continuation adds migration **172** and persists normalized
engine outcomes atomically with image scan completion. The built-in vulnerability
profiles now require successful Trivy and Grype results rather than retired
VulnDB provenance. Missing, failed and conflicting engine reports fail closed;
re-scans replace prior outcomes, and raw engine errors are excluded from this
map. Existing saved policies are unchanged and require explicit conversion after
the API and admission controller are upgraded. See the
[deployment order](admission-profiles.md#successful-vulnerability-engines).

The resumed verification passed **518 seeded, repeated race-test executions**
without skips (`/tmp/constellation-resume-engine-tests/`) and **96 tooling tests**.
The interrupted session's final production-image smoke finished successfully:
**seven browser tests**, authenticated CLI/API recipes, parent statistics and
session cleanup (`/tmp/constellation-engine-browser-final/`). Changed-code lint
has zero findings. The API image is
`constellation-browser-58c8017f4908-api:latest`, index
`sha256:8382addded7cd3d9d2e74410772f6b64342189a0f82e88ea74abe6e19ded867b`.
These checks do not close the remaining parity or live cutover acceptance gates.

**Parity is not release-complete.** The feature checklist has 66 checked
and 87 open items. The selected-console closure and live schema177 evidence are
recorded above. Counts describe acceptance items, not a percentage of code implemented. The complete scope and remaining gates are retained below; do not
convert partially implemented items into checked boxes.

The owner subsequently authorized main-cluster migration/CNPG cutover and
**deferred off-host recovery and real node-failure testing**. Those external
acceptance requirements remain deferred, not checked. The stronger local
PostgreSQL 16.14 rehearsal passes encrypted-credential recovery, wrong-key
rejection, audit-anchor/chain verification and pod restart (315 seconds through
authenticated recovery). It qualifies the recorded schema-171 image, not later
source changes. The [runbook](cnpg-recovery.md#october-12-credential-and-process-recovery-qualification)
records the proof and a newly confirmed pre-existing row-53 audit-chain break in
both the live source and independent existing-data restore. Do not label that
history clean or rewrite it to satisfy verification. The main cutover is now
verified as recorded above; full fleet qualification, historical audit integrity
and the deferred failure-domain checks remain open.

The subsequent security/recovery increment confines serverless ZIP extraction
with `os.Root`, private permissions, exclusive file creation and entry/byte
budgets; fixes wrapped-error handling; and removes unused implementations and
fixtures. It does not close the separate serverless DNS-rebinding gap. Short
private Unix-socket fixtures now work independently of the compiler scratch path.
The final full seeded PostgreSQL suite passed **5,662 repeated, shuffled race-test
executions**, with no test skips or failures, including the removed-code cleanup
(`/tmp/constellation-security-final-full/`). **84 tooling tests**, formatting,
ShellCheck and plan/endpoint checks passed. Full lint remains blocking at **1,654
findings** (unused and errorlint categories are zero); standalone gosec remains
blocking at **256 findings**, with zero package-load errors and no new exclusions.

The [CNPG/RustFS recovery repeat](cnpg-recovery.md) passed at schema 171 using the
session/schema image built for `103bf74`, including source and restored API schema
gates. This is local single-host recovery evidence, not later-build or production
HA qualification. The exposed admission test Secret capture is removed and fresh
test private keys are no longer captured. The owner is unsure of external use;
the two accessible clusters have no matching historical certificate or webhook
CA in the checked scope. [Inventory limitations and outstanding revocation](../deploy/e2e/threat-scenarios/04-admission-tls/EVIDENCE.md#october-12-credential-remediation)
remain recorded; historical secret findings are not suppressed.

CLI recovery fixes now transmit `--on-conflict` in server-mode restores, enforce
the existing 30-minute deadline and reject redirects instead of replaying the
archive. Local signature-verification flags are rejected in server mode because
the API owns verification policy. Operator login, backup listing, cluster and
package-report calls propagate command cancellation; login/mutation bodies do
not follow redirects, malformed or empty login tokens are not persisted, and a
rejected backup-list request returns an error. Both binaries build; **62 seeded
PostgreSQL/race test executions** pass with no skips, and changed-code lint has
zero findings (`/tmp/constellation-cli-context-seeded/`,
`/tmp/constellation-cli-new-lint-fixed.json`). CLI live-recipe acceptance stays open.

Artifact and notification endpoint DNS preflight now inherits request cancellation
and has a five-second bound. Receiver create/patch uses the context-aware API;
the older notification helper remains compatible. **1,176 seeded race-test
executions** pass with no skips and zero new lint findings
(`/tmp/constellation-dns-context-seeded/`). This bounds DNS work; it does not
establish a serverless dial-time DNS-rebinding defense.

Native policy generation now rejects out-of-range ports and unsupported protocols
with an error and no partial allow-list; it can no longer wrap port 65536 to the
zero/any-port wildcard or translate SCTP/unknown protocols to any protocol.
Explicit port zero remains supported. Group-edge create/expand validates both
submitted and transaction-locked state and returns HTTP 400 for unsupported
native rules. SCTP remains available only where a separate CNI workflow supports
it; native group-edge SCTP enforcement is not advertised. A read-only main-cluster
inventory found zero group edges, so no legacy rows were changed.

Qualification: **1,084 seeded race-test executions** across native policy,
runtime handlers, migration and registered server routes passed; the subsequent
error-handler cleanup passed **704 executions**, all without skips. **Six
production-image browser tests** passed without retries, including real API
rejection/no-write checks, group lifecycle and network workflows. The final API
image is `constellation-browser-4a502b1b2b82-api:latest`, index
`sha256:e1a17de6c80a09ab9ded2cdfcb2b3e7ae7fd59e212495c0ae0a6ca6791d6026c`.
Evidence: `/tmp/constellation-native-policy-{final,cleanup-tests,browser-final}/`
and `/tmp/constellation-native-policy-legacy-inventory.log`. Frontend lint passes.
Full lint now has **1,639 findings**; standalone gosec has **253 findings** and
zero package-load errors. Both remain blocking. No exceptions were added.

A second current-feature CNPG/RustFS rehearsal also passed at schema 171 in
`recovery-94263fc4`, using the native-validation image before the error-handler
cleanup; the [recovery runbook](cnpg-recovery.md) records its exact image and
scope. Main deployment remains unchanged. These fixes do not close the broader
live dataplane, legacy-policy ownership or production recovery gates.

Partitioned-parent statistics now have bounded maintenance for flows, events and
findings: one stale parent per pass, database coordination across replicas,
explicit ownership/lock checks, statement/context budgets and fixed-cardinality
metrics. Helm can disable it for externally managed statistics. The independent
restored copy's row counts are unchanged after analysis, and the flow-organization
cardinality estimate now matches its measured single organization. See the
[statistics contract and measurements](database-lifecycle-backlog.md#october-12-partitioned-parent-statistics-maintenance).
**342 seeded race-test executions**, **85 tooling tests**, changed-code lint,
ShellCheck and **six production browser tests** pass. The production smoke also
requires a completed parent refresh, corresponding PostgreSQL statistics and a
successful session-cleanup pass. API image
`constellation-browser-dd0f7f69b304-api:latest`, index
`sha256:3a6569c2c020c40fff1e5d143863c1ea3faa299a0df50341f4aa7d1a60b70d48`,
is qualified by `/tmp/constellation-parent-stats-browser/`. This is a measured
maintenance improvement, not deployed tuning, fleet capacity or completed DB-23.


Historical admission TLS remediation remains open because use outside local
development is unknown. The expanded read-only inventory found no historical
certificate **or public-key** matches and no errors across 20 certificate
occurrences in the main local cluster and 45 in the isolated CNPG cluster. It
covers named certificate fields in Secrets of all types, ConfigMaps and admission
webhook CA bundles. A wider local-history scan also found the matching CA private
key, whose publication status is unconfirmed; affected deployments need both CA
and server-key replacement. The [remediation record](../deploy/e2e/threat-scenarios/04-admission-tls/EVIDENCE.md#october-12-credential-remediation)
provides the repeatable inventory and its limits. No global revocation, scanner
exception or additional parity acceptance is claimed.

The latest session-lifecycle increment adds migration 171, bounded leader-owned
cleanup for expired browser/session records and five-minute network snapshots and
kill requests. It preserves unexpired refresh reuse evidence, legacy unknown
session deadlines and audit receipts. The API now refuses an older schema before
service initialization; Helm runs the same image's `--check-schema` gate instead
of checking only the old signing-key table. See the [session cleanup contract](browser-sessions.md#operational-cleanup)
and [database backlog](database-lifecycle-backlog.md).

Qualification: **642 repeated race-test executions** across database, lifecycle,
auth, server, network and API packages; **13 production-image browser tests** for
authentication, two-tab refresh/reuse and network workflows; **143 frontend unit
tests**, TypeScript, **81 tooling tests**, formatting, ShellCheck and plan/endpoint
checks passed. Changed Go code has zero new lint findings. The production API
image's schema command accepts the restored migration-171 database and rejects a
migration-169 fixture. The restored-volume 171 down/up rehearsal preserves all
four flow/rollup/event/audit counts. Evidence is under
`/tmp/constellation-session-schema-{tests,browser}/`,
`/tmp/constellation-session-static-checks.log`, and
`/tmp/constellation-schema-check-{restored171,old_fixture169}.log`.

Hosted run [38201453229](https://github.com/alphabravo-oss/constellation/actions/runs/38201453229)
for `659104c` passed Go unit/integration, browser, frontend, FIPS and dependency
checks; lint, gosec and historical secret findings failed. The subsequent
read-only trust-inventory increment passes all **91 tooling tests** locally and
has no application source changes. Main deployment remains schema 167 on its existing
StatefulSet; this increment does not close the CNPG/live, fleet-capacity, durable
action-delivery or full security acceptance gates.

The separately requested [ClickHouse plan](CLICKHOUSE-PLAN.md) defines evaluation,
transactional export, tenancy, schema, duplicate-safe aggregates, retention/holds,
RustFS test recovery, benchmark targets, canary and rollback. It is subordinate
to OPS-2; ClickHouse is neither deployed nor required for initial streaming.

This implementation adds migration 169 and durable ordered event/flow upload:
private bounded node spools, stable producer/sequence, receipt+data in the same
transaction, matching acknowledgement, restart replay, 429/Retry-After, bounded
per-cluster concurrent ingestion, batched PostgreSQL inserts, and transactional
rule-hit counters. Legacy upload callers remain compatible. API/migration must
roll out before agents; an older API cannot acknowledge/dequeue the new spool.
See [telemetry delivery](telemetry-delivery.md) for limits and remaining work.

CI remains a release blocker. The October 11 run reported 2,299 lint findings,
263 standalone gosec findings, 10 historical secret-scanner findings, formatting,
shell lint, reachable dependency vulnerabilities, and browser login throttling.
The SARIF normalizer, login setup honoring Retry-After, and shell fixes address
specific failures. The production browser auth/session/migration batch now passes
all 11 tests, and shell lint and 13 security-tooling tests pass. Go is updated to
1.26.9 with the identified x/net/x/text and OpenTelemetry fixes. A new full
govulncheck run reports zero reachable vulnerabilities (two imported-package and
three required-module advisories remain reported without reachable calls), and all
Go packages compile.
The rebuilt API/frontend production-container harness also passed all 11 selected
browser tests with migration 169 applied. Seven affected packages passed twice
against a fresh disposable database, with focused race and vet checks passing.
The lost-acknowledgement/restart test verifies exactly one raw flow, late aggregate
and rule-hit contribution. Source is pushed to draft PR #2; live remains migration
167, and the broader hosted release gates remain pending/failing as recorded.

The next source review formatted the Go tree and bound 460 test HTTP requests
in total to their test lifetimes. Strict lint findings fell from 2,299 to 1,747;
body-closure, formatting and ineffectual-assignment findings are cleared, while
security/error handling/context/complexity findings remain blocking. All Go packages passed twice on a fresh database
through migration 169. The first complete production browser run found an nginx
`/assets/` collision with the Assets application routes: compiled files now live
under `/static/`, redirects preserve the public origin, and both Docker and Helm
serve SPA deep links. Browser setup now extends its timeout only for an actual
server-mandated login cooldown; production throttling remains enabled. The next
full run passed 190/191, exposing one ambiguous Name/Namespace test locator, now
corrected. The final rebuilt production-container suite passes **193/193** with
zero retries; all **141 frontend unit/component tests** also pass. CI now invokes
the whole browser suite by default and enables the isolated migration
apply/idempotency/rollback recipe. These are local results; hosted and live-cluster
qualification remain open.

The NVD settings editor now uses the shared TanStack Form/Zod layer, accessible
text/password fields and labelled switches. It preserves unsaved drafts across
query refresh/conflicts, omits blank replacement keys, sanitizes save errors and
blocks accidental navigation. Eight component cases and two production browser
cases cover validation, secret handling, save and explicit discard.

The configuration API now accepts a quoted revision in `If-Match`. Conditional
NVD/retention saves reject stale or concurrently superseded drafts with HTTP 412;
rejected writes do not advance revisions or emit success audit events. Older
clients without the header retain compatible merge/retry behavior. Both editors
preserve drafts during conflicts and background refresh failures, and require an
explicit reload to discard them. OpenAPI and CORS describe/support the header.
The accepted [stack ADR](decisions/0001-astronomer-console-stack.md) records the
user's Router/Form/REST direction and its limits; it does not close all of TSG-1.

Additional security fixes in this continuation:

- Stored Argon2 hashes are validated before deriving a key: format, decoding,
  memory, passes, lanes and key/salt sizes are bounded. All locally issued hashes
  retain their existing parameters; imported hashes above the verification budget
  now fail format validation and need a separately reviewed reset/import path.
- Kafka header parsing respects the declared frame boundary, preserves signed
  correlation IDs and rejects invalid client lengths/UTF-8. Plugin example HTTP
  servers now have explicit header/read/write/idle deadlines.
- Compliance email validates header inputs and mailbox syntax, and uses MIME
  encoding for Unicode subjects, attachment names and base64 line wrapping.
  Injection and MIME round-trip tests pass with races.
- Federation proxy requests cannot follow cross-host or same-host redirects;
  join-remote requires HTTPS and does not fabricate transport evidence or replay
  join tokens through redirects. Forwarded TLS/certificate evidence requires a
  explicitly configured trusted direct peer recorded before client-IP rewriting. Direct TLS, trusted
  and untrusted forwarding, redirect and credential tests pass with races.
  The Ingress/Gateway routes `/api` directly to the API, with matching network
  admission; exact deployed mTLS/ingress qualification remains open.
- HTTP/1 inspection decodes chunk framing, respects message body boundaries,
  and reports incomplete/over-budget observations. Request/response framing,
  pipeline separation and bounded-body tests pass with races. This is Go-parser
  evidence, not live C data-plane or CNI qualification.
- A distinct required FIPS job builds API/scanner/operator/runtime-agent with
  the pinned Go module and checks enabled, disabled and unpinned runtime cases.
  All three runtime cases and four builds pass locally. The tagged startup guard
  and crypto-module logs now exist; [FIPS documentation](fips.md) removes earlier
  unsupported whole-product, CLI and native-library claims. Workflow validation
  and the hosted FIPS job pass; deployed cryptographic qualification remains open.

Latest local evidence supersedes the earlier small samples: the immutable
`3944e02` full seeded Go suite passed **5,572 executions** with repetition,
shuffle, races and zero skips/failures. The following conditional-save/auth/DPI
slice passed **586 executions** across four affected packages; the extracted
CVE fixture helper then passed **40 findings-package executions**. The frontend
suite passes **143 tests**, and changed Go code since `3b2f2aa` has zero new lint
issues. Migration 170 also passes 170 → 169 → 170 with CVE data preserved.

The security/format runners now use the module's package list so ignored local
reference checkouts do not enter the scan. Gosec uses two workers, a 2 GiB runtime
soft budget and owned disk scratch; the full 120-package run completes in 15.64
seconds with 284,376 KiB measured peak RSS, and still blocks on **261 findings**.
The unrelated scratch left by the interrupted recursive scan was removed. These
resource fixes do not add scanner exclusions or change native failure statuses.
Hosted run 38191094639 passed Go unit/integration, frontend, FIPS and dependency
audits, but failed quality, gosec, historical secrets and one Accept Risk browser
race. That test now waits for the filtered result and matching finding. All eight
focused production-browser cases pass, including real-API stale retention edits.
The final full production-container suite passes **194/194**, zero retries, with
the migration apply/idempotency/rollback recipe enabled. All **78 tooling tests**,
module formatting, ShellCheck and endpoint/plan checks pass. Evidence:
`/tmp/constellation-resource-fixed-full-browser/`,
`/tmp/constellation-resource-fixed-full-browser.log`,
`/tmp/constellation-fixed-packages/` and
`/tmp/constellation-fixed-tooling-final.log`. New hosted acceptance remains pending.

These fixes do not establish green CI. Historical secret findings need
classification/remediation and any genuine credentials revoked; do not broadly
allowlist them or rewrite shared history without a reviewed recovery plan.

Still required before claiming OPS-2 or full parity: durable response-action
outbox, remaining telemetry lanes, producer-registration budgets/lifecycle,
cluster-fair scheduling and rate/byte budgets, independent rollup progress,
regional ownership/transfer, simultaneous ingest/read/prune/backup failure and
capacity tests, live deployment smoke, and the complete A–K acceptance matrix.
Unchanged CVE import rows now skip UPDATE after comparing the fully merged row;
a real PostgreSQL test verifies unchanged/sparse input preserves xmin and changed
input still updates. Migration 170 now adds bounded persistent KEV/EPSS and NVD
checkpoints, cross-replica serialization and completed-window resume. Repeated
real-PostgreSQL tests cover restart, failure, correction, catch-up and rollback.
A 1,200-row unconditional replay rewrote 1,200 tuples and generated about 1.35 MB
WAL; three checkpointed repeats rewrote no tuples/checkpoints and measured zero
additional WAL in both runs. See [feed checkpoint contract](cve-feed-checkpoints.md).
DB-18 source/local qualification is implemented; real-feed/live measurement stays
open, as do DB-19 catalog semantics/bootstrap and DB-23 freshness alerts.

The existing global rollup lock and global control-audit chain remain scaling
constraints; this change does not claim to remove them.

Local evidence for this continuation: `/tmp/constellation-parity-browser-expanded/`
contains image IDs, migration/API logs and generated screenshots;
`/tmp/constellation-nvd-full-unit.log` records 141 passing tests;
`/tmp/constellation-parity-fips/fips/` records the four builds and three runtime
cases. The expanded seeded database gate passes **5,556 test executions**, twice
and shuffled with the race detector, with **zero skips and failures**. Evidence:
`/tmp/constellation-parity-seeded-race/integration.xml` and `integration.json`.
The previous unseeded run exposed legacy skips; the harness now seeds only its
new disposable database, and new federation redirect tests own their fixtures.
All 69 tooling tests, endpoint/plan checks, repository formatting, ShellCheck,
actionlint, frontend lint, Helm lint and HA/template smoke pass locally.

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

## October 11 reconciliation and next-work plan

This section sets the execution order for the existing acceptance checklist.
It does not create a second backlog or count an installed dependency as a
completed workflow. The source baseline is Constellation `711a881`; Astronomer
was fast-forwarded from `f87b189f` to `3b378ef16141b9eaac35a1e5fe292e061b69f5f1`
and its checkout matches `origin/main`. The comparison uses that source, not
an assertion that every Astronomer capability is deployed or release-qualified.

The Constellation branch is pushed through `711a881`, 38 commits ahead of
`origin/main`, with no PR or branch Actions run found during this review.
CI triggers on PRs/main/manual invocation, so absence of a branch run is not
evidence that CI is missing. This documentation update is subsequent work.
Old stashed UI edits, historical local branches and untracked smoke artifacts
need separate disposition; do not replay them blindly into the current code.

The published checklist at the October 11 snapshot was **53 checked / 100 open**. No acceptance row
was newly closed by this review; two fleet-scale acceptance items were added
after comparing ingestion and failure boundaries with NeuVector. Many open parents contain source fixes and
focused tests already recorded in the September implementation review. Their
remaining integration, negative-path or deployment tests are the work; do not
restart implementation from the older July/August gap lists. The 23 DB detail
items are decomposition of OPS-2, not 23 additional top-level items. These
counts mix correctness, NV switchability, UX and guide conformance and must
not be presented as a feature-completion percentage.

### October 11 implementation review

The baseline comparison below describes `711a881`, before this implementation.
The following source changes supersede its Router/Form, retention and backup
gaps; broad acceptance items remain open until their remaining gates pass.

- **Package A:** partition-safe `(id, at)` row deletion, failure/watermark-gated
  flow expiry, transactional late-flow aggregation and replay protection after
  pruning are implemented. Migration 168 records the conservative raw-history
  boundary. Shared retention uses the longest organization window, with any
  explicit zero holding deletion; fresh installs use flow/event/job defaults of
  14/30/7 days. Legacy absent values remain holds. Actual PostgreSQL collision,
  failure, lag, late-arrival, refold, partition and tenant tests passed with the
  race detector and two repetitions. Main-cluster deployment, fold-lag alerts
  and throughput/lock-contention qualification remain open.
- **Package B:** chart support for Barman Cloud ObjectStore WAL archiving,
  scheduled backups and recovery into a separate CNPG cluster is implemented.
  Four chart contract tests and Helm lint pass. A full copy of the existing
  database was independently restored and upgraded through migration 168,
  preserving exact counts: 2,723,972 raw flows; 153,178 rollups; 3,020,985 events;
  1,905,903 audit events. Secrets were preserved separately under restricted
  access. The user approved local RustFS for the initial CNPG rehearsal; see
  [recovery evidence and reproduction](cnpg-recovery.md). The repeatable RustFS
  script passed scheduled backup, WAL/PITR boundaries, required extensions and
  test-API DSN cutover with existing-session/configuration and fresh-login checks.
  The existing
  StatefulSet remains the live database. Off-host recovery, HA, alert failure
  drills and encrypted-credential/audit-chain verification remain open.
- **Package I / TSG-5:** TanStack Router 1.170.35 replaces React Router throughout
  the console, using a registered code-based route tree. Alias redirects,
  repeated query parameters, hashes, auth return paths and history have focused
  tests. TanStack Form 1.33.5 and Zod 4.6.1 now drive Data Retention through a
  shared form layer, with validation, pending state, conflict handling and dirty
  navigation protection. `tailwind-merge` is 3.6.0. Frontend lint, production
  build and 133 tests pass; 35 production-browser navigation/alias checks and a
  separate 11-test auth/session/retention run pass against the rebuilt image.
  The combined browser suite encountered the API login rate limit and is not a
  green full-release gate. Generated file routes, per-domain typed search,
  remaining form migrations, enterprise table/Virtual adoption and complete
  browser/accessibility qualification remain open. Table is still 8.21.3.

Local image digests for this verification: API
`sha256:1d28702d34e8f738f2740bffc7325d3db7991a602f30147168c0751e435a8914`;
frontend `sha256:3521f62bc6a1edfd9eb58f0aa7a977b1d42195a1cf836986c166220923afc25c`.
These are local artifacts, not published release attestations. Browser batches
were separated by restarting only the disposable API to clear its in-memory
login quota; the production limiter was not weakened.

No top-level checkbox is closed by this bounded implementation slice. Continue
with production artifact qualification and the remaining A/B acceptance, then
the contracts and table/form work in D/I, while retaining the NV enforcement and
migration work in C/E/F/G/H/J/K. Do not equate stack adoption with NeuVector parity.

### October 11 database qualification and release status

The 23:42–23:46 UTC read-only live assessment measured **8.37 GiB** of database
storage (about 8.99 decimal GB), with roughly 2.93 million events, 2.78 million
raw flows, 1.91 million audit rows and 404,000 CVEs. Cleanup is active and its
observed expired-row backlog is small, but the live service remains on migration
**167**, a single PostgreSQL StatefulSet with WAL archiving disabled. The new
safety fixes and the separate RustFS recovery proof do not establish live
cleanup correctness, high availability or fleet-scale capacity.

The [database lifecycle register](database-lifecycle-backlog.md#october-11-live-measurement-and-assessment)
now contains the measured sizes/counts, active retention/partition/vacuum state,
storage headroom, query/statistics limitations and ordered completion gates.
The highest priorities are safe deployment, CVE repeated-write reduction,
evidence-preserving retention for all growing histories, growth/lag/backup
alerts, and combined ingest/read/prune/backup performance qualification. Parent
statistics, global audit/rollup lock contention, stale Kubernetes audit and the
cross-tenant effects of a retention hold are explicit parts of that work.
The initial 1x/10x workload profiles and latency/lag budgets in the register are
test targets, not measured capacity or customer SLAs. The database's current
size alone is not a reason to replace PostgreSQL or declare it scale-qualified.

Hosted CI for [PR #2](https://github.com/alphabravo-oss/constellation/pull/2),
at implementation head `e51a69a`, has now completed: Go unit/integration,
frontend and dependency checks passed, but quality, the security matrix,
browser and aggregate required checks failed
([run 38182357075](https://github.com/alphabravo-oss/constellation/actions/runs/38182357075)).
Local focused passes do not override that release gate. Triage and resolve the
failed checks before deployment or merge; keep the PR draft and the acceptance
items open. The canonical plan is reconciled; full implementation/acceptance is
**not complete**. The subsequent fleet review brings its count to
**53 checked / 100 open** without changing any completed-item status.

### October 11 fleet architecture review

NeuVector keeps cluster-local controllers/state and federates policy, summaries
and selected scan results. Its bounded console history plus external logging
has different storage guarantees from Constellation's centralized searchable
history and integrity chain. The [architecture document](architecture.md) now
describes the active scanner pipeline, current ingest limitations and a proposed
bounded regional deployment model; it replaces the retired VulnDB architecture.
This is a qualification direction, not a claim of implemented regional routing.

Add two explicit OPS-2 gates below: durable/idempotent bounded cluster delivery,
and independent workload/progress/failure boundaries. Current agent batching
and retry counters, time partitions, CNPG replicas and federation APIs do not
close those gaps. Keep PostgreSQL/CNPG, qualify one deployment's capacity first,
and expand to independently operated groups of clusters at measured capacity,
latency or isolation thresholds. Global audit/rollup serialization and shared
retention holds need deliberate contracts before claiming fleet scalability.
Distinguish delivery from storage: durable spool/replay/idempotency is required
work; an external broker and analytical database are conditional technology
choices. Keep transactional authority in PostgreSQL and benchmark the expected
fleet's telemetry workload before selecting a separate store. The architecture
document records triggers, ownership and consistency/restore acceptance for a
possible analytical tier; adding ClickHouse or a streaming broker is not yet an
approved deployment or an acceptance shortcut.

### Stack baseline and approved convergence target

**Product decision — October 11:** converge on Astronomer's technology stack,
including **TanStack Router and TanStack Form**. This supersedes the earlier
proposal to retain React Router. The target also includes the shared TanStack
Table/Query/Virtual patterns, Tailwind v4-compatible primitives, generated
REST/OpenAPI contracts, sqlc and CNPG recovery practices described below.
Implement convergence in bounded migrations; preserve Constellation's security
domain, APIs and enforcement behavior. Astronomer-specific product subsystems
are not prerequisites. Record departures from the Technology Selection Guide
as deliberate product choices, not strict guide conformance. The user's stack
decision is settled; implementation and acceptance evidence remain open.

Versions below come from each repository's committed frontend lockfile, not
semver ranges, installed node_modules, or claims about the newest upstream release.
Source anchors are relative to the named repository.

| Area | Constellation now | Latest pulled Astronomer | Work to schedule |
|---|---|---|---|
| PostgreSQL/CNPG | Chart supports `statefulset`, `cnpg`, external; existing live release uses a single PG16/pgvector StatefulSet. No CNPG CRDs/operator were found. | Chart has bundled/external/CNPG modes, a PG17 operand, Barman plugin backup/recovery, WAL storage and synchronous-replication settings. | OPS-2: qualify a Constellation pgvector-compatible operand, modern backup/recovery contract and migration. Keep PG major upgrade separate from operator migration. |
| React/Tailwind | React 19.2.6; Tailwind and Vite plugin 4.3.1, actually imported by Vite and `src/index.css`. | React 19.3.0; Tailwind/plugin 4.3.3. | Already adopted. Maintain compatible pins; this is not a Tailwind-v4 migration project. |
| Class merging | `tailwind-merge` 2.6.1 is called by `src/lib/cn.ts`. | 3.6.0. | TSG-5/UI-2: move to a Tailwind-v4-compatible release and test theme, arbitrary values and state variants. The upstream README associates v2.6 with Tailwind v3. |
| TanStack Query | 5.100.10; provider in `src/main.tsx`. | 5.102.8 plus canonical query/cancellation/live-state helpers. | Keep Query; standardize keys, cancellation, session refresh and invalidation. Measure request duplication before adding pacing. |
| TanStack Table | 8.21.3 in the actual shared `src/components/ui/data-table.tsx`; 49 TSX files reference `<DataTable` in this source snapshot. Density, visibility, selection, sorting, CSV and bounded local paging exist. | 9.2.4; explicit feature graph, controlled server pagination/filter/sort, resizing/order/pinning, grouping, keyboard navigation, URL state and user-backed saved views. | UI-2/OPS-2: finish the table contract and page adoption. Qualify any v9 adapter change independently; library version alone does not give workflow parity. |
| Virtualization | No `@tanstack/react-virtual` dependency. | 3.14.11 and a virtualized body with a separate semantic/server-paged path. | Use for measured large loaded datasets. Preserve server paging for large remote datasets and test accessibility. |
| Router | React Router DOM 7.18.2, currently `BrowserRouter`, not a verified Data Router setup. | TanStack Router 1.170.35 and generated routes. | TSG-5: migrate to TanStack Router with typed routes/search, shared Query context, session guards and generated route checks. Preserve deep links, auth, scope and error behavior; remove React Router after cutover. |
| Forms | No TanStack Form, react-hook-form or Zod dependency. | TanStack Form 1.33.5 through `src/lib/form.ts`; Zod 4.6.1 is in the lockfile. | TSG-5: adopt TanStack Form through one shared form layer with schema validation, field/server errors and accessible pending/error states. Do not introduce react-hook-form. Record the guide departure. |
| Frontend tools | Vite 8.0.16, TypeScript 5.9.3, Vitest 4.1.11, Playwright 1.60.0; Radix primitives. | Vite 8.3.0, TypeScript 6.0.3, Vitest 5.0.0, Playwright 1.63.0; Radix and axe browser checks. | TSG-4/5: scoped compatibility upgrades, production-browser accessibility and bundle budgets. Avoid combining all major upgrades with feature work. |
| SQL/API contracts | pgx, external Goose migration job, hand-written SQL and Axios DTOs; OpenAPI/checkers exist. | sqlc queries/generated accessors, generated OpenAPI client/types and transport-boundary checks. | TSG-2/5/API-1: converge on Astronomer's generated REST/OpenAPI and sqlc approach; document the guide departure and migrate by domain while preserving transactions/audit. |
| CI/operations | Quality, unit/integration, security and release workflows exist; full green/hosted acceptance remains open. OTel infrastructure exists. | Lockfile-pinned Local CI, contract/complexity/cancellation checks, release/upgrade/DR/accessibility/scale workflows. | TSG-4/6/7: adopt useful gates and recovery evidence patterns. Workflow files do not prove a green release; do not add Redis, Flux or Charlie merely to copy Astronomer. |

Evidence: both `frontend/package-lock.json` files; Constellation
`frontend/vite.config.ts`, `frontend/src/main.tsx`,
`frontend/src/components/ui/data-table.tsx`, `deploy/charts/constellation/values.yaml`,
`deploy/charts/constellation/templates/postgres-cnpg-*.yaml`; Astronomer
`frontend/src/components/ui/data-table-{types,features}.ts`,
`frontend/src/components/ui/use-data-table-view-sync.ts`,
`internal/handler/table_views.go`, `sqlc.yaml`, `deploy/chart/values.yaml`,
`deploy/chart/templates/postgres-cnpg*.yaml`, and `AGENTS.md`.
The Astronomer reference is pinned at
[3b378ef1](https://github.com/alphabravo-oss/astronomer/tree/3b378ef16141b9eaac35a1e5fe292e061b69f5f1).
Upstream compatibility references:
[tailwind-merge](https://github.com/dcastil/tailwind-merge) and
[CNPG backup](https://cloudnative-pg.io/docs/1.28/backup/).

### What is already done and should be retained

| Existing slice | Evidence boundary | Remaining parent work |
|---|---|---|
| Agent/token scope guards, audit concurrency, restore validation and fail-closed admission fixes | Source and focused DB tests recorded below | Complete the remaining write/read inventory and deployed multi-cluster/failure matrix (P0.1–P0.3). |
| Migration preview/apply/history/rollback framework and supported converters | Code and subset fixtures; not a complete NV cutover | Remaining families, unsupported inventory, complete fixture and deployed rollback (MIG-1/API-1). |
| Registry per-job Docker configs and authenticated metadata reads | Focused isolation/failure tests | Claimed-job credential binding, residual ambient credentials and live provider matrix (REG-1). |
| Signed asynchronous support bundles and component fixtures | Four OPS-1 rows already closed with the recorded source/browser/k3d evidence | Preserve these gates; live fleet health and release validation remain broader OPS-2 work. |
| SIEM TLS, formats/filters and named receiver receipts | Five bounded rows closed, including deployed collector evidence | Named vendor parsing/interoperability (SIEM-1). |
| Local-user recovery, platform-role classification, scope ordering, aliases and YAML contract discipline | Bounded API/browser evidence below | Full IdP cutover, role-bearing exports, canonical page audit and shared-table completeness. |
| Empty DEFAULT-partition reclaim and development retention | Recorded September deployment/reclaim evidence | The distinct unsafe row pruners and rollup expiry remain open; reclaim is not a fix for them. |
| Syft inventory plus Trivy/Grype matching and CVE intelligence | Active source path in `internal/scanner/aggregator.go` | Remove misleading retired-bundle documentation/config references and prove live/offline freshness. Do not restore the retired VulnDB producer. |

### Live infrastructure boundary — observed October 11

Read-only inspection found one node (`constellation-dev-1-mj`), Helm release
`constellation` revision 18 in `constellation-system`, a ready single
`constellation-postgres` StatefulSet, a 60 GiB DB PVC and an 8 GiB scanner-cache
PVC. CNPG resource types are absent. The only CronJob in this namespace is
`constellation-k8s-compliance`; no DB-backup CronJob is present. External backup
coverage was not verified. PVC capacities are not current utilization readings.

API/frontend tags are `parity-0927-retention` / `parity-0927-preview`, while
several other role tags are `0.1.0`. Ready pods and tag names do not establish
that every running role contains `711a881`; record image digests/build revisions
before a deployed parity claim. No authenticated browser, backup restore,
failover or CNI test was rerun in this review. September database-size, DNS and
browser observations below remain historical until remeasured.

The current source still contains `ctid`-only DELETEs on partitioned events and
flows, and rollup `runOnce` continues to the prune stage after refresh errors.
These observations reconfirm DB-01/02 as open; this review did not rerun the
destructive reproduction on the live database.

### Ordered delivery packages

All package IDs below map to existing checklist parents. Each implementation
change should record owner, exact source/image identities, focused test output,
negative-path behavior and deployment evidence. Assign the accountable owner
when scheduling a package; do not mark a proposed role as an assigned person.
Packages are sized as reviewable outcomes rather than calendar promises.

| Package / priority | Existing parents | Deliverable and remaining work | Dependencies and exit evidence |
|---|---|---|---|
| A — P0 data safety | P0.3, OPS-2; DB-01–05 | Fix partition row identity, gate row pruning and partition expiry on successful folding/watermarks, define late/refold grace, choose retention scope and safe fresh-install defaults. Establish backup/recovery coverage before destructive maintenance. | First implementation slice. Disposable two-child collision test, refresh-failure/lag/late-arrival cases, fresh/upgrade and tenant tests; deploy only a verified artifact and confirm no unsafe pruning. |
| B — P0 recoverability / P1 CNPG | OPS-2, TSG-2/7; DB-05,21–23 | Produce a full DB+key recovery runbook; qualify pgvector operand, CNPG operator and backup plugin/ObjectStore contract, scheduled backups, WAL/PITR, retention and alerts. Rehearse StatefulSet-to-new-CNPG-cluster transfer and DSN cutover with rollback. Preserve external-DB option. | A's safety fixes and an independently verified recovery copy before live cutover. Single-instance dev rehearsal; three-node failure-domain test for HA. Restore encrypted credentials, audit continuity and application workflows; measure RPO/RTO. Existing chart templates alone do not close this. |
| C — P0 security correctness | P0.1/2/3, TSG-3 | Finish advertised-control reachability, remaining agent/scanner/restore scope audit, legacy DLP/WAF binding repair plan, namespace row filtering, fail-path matrix, secret key custody/rotation and cookie/CSRF/concurrent-session cases. | Can be developed beside A; release waits on both. Positive enforcement/delivery and deny/no-write assertions, cross-tenant/cluster tests, live malformed-policy and restore/agent isolation drills. |
| D — P0/P1 reproducible gates and contracts | API-1, TSG-1/2/4/5 | Keep existing security CI; fix baseline findings, isolated DB/test fixtures and full Playwright reliability. Record architecture/guide decisions; introduce generated API contracts, domain SQL typing, migration safeguards and dependency boundaries incrementally. Add a reproducible local preflight and hosted required-check evidence. | Baseline before further large migrations; continue per package. Fresh/repeated DB migrations, complete no-skip required browser suite, contract regeneration clean, security/quality gates green at the submitted revision. Decisions remain open until recorded. |
| E — P1 NV cutover and identity | MIG-1, CFG-1, IAM-1, API-1 | Complete import families and canonical source/converted/unsupported manifest; idempotent audited apply/history/export/rollback; effective-config provenance/revision/reload; external IdP connectivity, actual group resolution and final scopes; metadata-only user/token migration. | C scope/fail-path contracts and D test infrastructure. New-org fixture cutover through API/CLI/browser, duplicate/rejected import and rollback tests, real supported LDAP/SAML/OIDC cases. Preserve explicit unsupported/private-provider boundaries. |
| F — P1 runtime/network enforcement | RUN-1, NET-1 | Prove process/file/exec/zero-drift Protect, delivered/acknowledged process kill, identity/argv capture, restart hydration and mutation coverage. Finish shared filters/counts/export semantics and multi-interface/host attribution. | C and reproducible role builds. Flannel inline plus Cilium/Calico CNI policy matrix with actual allowed/blocked traffic, mode changes, restart and failure behavior. Decide whether Cilium inline L7 is a required new subsystem or documented unsupported mode. |
| G — P1 scanning, compliance and delivery | REG-1, CMP-1, SIEM-1 | Finish private/cloud registry auth/token/enumeration matrix, scanner capacity/freshness and offline updates; true on-demand/scheduled kube/docker benchmark execution with two-cluster isolation; named SIEM vendor interoperability. | C credentials/scope and D fixtures. Real private provider scans with cleanup/failure proof, installed DB refresh to dashboard, benchmark execution/evidence, vendor acceptance of routed TLS/CEF/JSON events. |
| H — P2 policy workflows | POL-1/2/3 | Complete referenced-group conflict and group-edge workflow; per-family hit/health evidence, real runtime precedence, portable imports/exports, unsupported migration remediation; long-tail admission criteria, DLP context/WAF path, backup/federation and response categories. | E conversion semantics, F enforcement and G event paths. Operator creates/imports group and policies, observes real hit/enforcement, exports/restores, verifies precedence and denied conflicting deletes. Existing CRUD is retained. |
| I — P2 Astronomer-quality console | UI-1/2/3/4, TSG-5; OPS-2 scale | Fix class-merger compatibility; consolidate table state/server pagination/filter/sort; add scoped saved views, URL state, measured virtualization, resizing/pinning and keyboard/accessibility behavior. Complete navigation/page contracts, backend platform-role exports and exact dashboard drilldowns. Migrate to the approved TanStack Router/Form stack through the sequence below. | D contracts and API fixes alongside UI work. Large dataset includes records beyond old 100/500 caps; API/table/count/export agree; saved-view tenant/user isolation and history/reset tests; production mobile/keyboard/axe and visual checks. No component-only closure for API truncation. |
| J — P1/P2 durable lifecycle and observability | OPS-2, TSG-6; DB-06–23 | Finish evidence classification, contiguous signed archive/catch-up and checkpoint-aware verification before audit pruning; bound rollups/history/evidence and scanner caches; reduce redundant CVE writes and define freshness/catalog semantics. Add DB/WAL/partition/fold/archive/cache/backup alerts and trace/request propagation. | A/B; archival deletion waits on independent restore proof. Missed-run and tamper/gap tests, no-loss reconciliation, failure alarms and measured storage/request budgets. Preserve durable evidence advantages over NV. |
| K — release qualification | OPS-2, TSG-4/7 and all applicable open parents | Build a signed immutable BOM with all role/helper images, scanner DBs, trust and architecture declarations; verify HA, upgrades, DR, disconnected first boot/update, FIPS scope and amd64/arm64 or explicit limitations. Run full browser/CNI/scale/release matrix and reconcile docs. | All release-blocking work and decisions. Exact candidate source/digests, hosted checks, archived evidence and honest unsupported/deviation list. No blanket "NV parity complete" while required workflows lack proof. |

### Concrete first changes

1. **DB-01:** replace partition-ambiguous row deletion in
   `internal/handler/events_retention.go` and `internal/handler/network/rollup.go`.
   Use partition-aware identity or a stable logical key; test an expired/current
   collision across two child partitions plus bounded/concurrent deletion.
2. **DB-02:** make fold failure/lag block both raw row pruning and partition
   expiry (`internal/handler/partition_manager.go`); define late-arrival and
   refold retention before choosing the cutoff. Prove counts survive failures.
3. **Recovery/CNPG preparation:** capture sanitized deployment identities,
   validate a full backup with necessary decryption/signing-key recovery,
   implement/qualify backup-plugin and restore configuration, and restore to an
   isolated target. Prepare a reviewable cutover/rollback runbook before touching
   the live DB service or PVC. Single-node development remains non-HA.
4. **Small UI compatibility slice:** upgrade the class merger for existing
   Tailwind v4, with shared component/theme regressions. Inventory table pages
   and API limits before selecting the next table contract migration.
5. **Baseline qualification:** run D's full source/API/browser gates on the
   candidate, triage failures with owners, and then submit bounded reviewable
   changes. Keep the existing 38-commit implementation baseline distinct from
   new fixes so reviewers can identify what was previously tested.

Approved stack direction: converge on Astronomer, including TanStack Router
and Form, with CNPG for managed production DBs and external PostgreSQL still
supported. Production RPO/RTO, evidence retention/holds, failure-domain capacity
and the Cilium L7 support boundary still need concrete deployment decisions.
They do not block implementing DB-01/02 or the frontend migration foundation.

### Stack convergence sequence and acceptance

This decomposes packages D/I and their existing TSG-2/5 and UI parents; it adds
no completion claims or duplicate checklist totals.

1. **Contract inventory:** enumerate current routes, aliases, search parameters,
   auth/scope guards, forms and table consumers. Pin the compared Astronomer
   revision and compatible dependency set. Record the chosen Router/Form and
   REST/OpenAPI direction against the guide; this documents the decision rather
   than reopening it. Preserve links, browser history and API compatibility.
2. **Shared foundation:** align Tailwind/class merging, Radix primitives and
   Query keys/cancellation/error handling; introduce Astronomer-style form
   context, schema adapters and accessible field/error components. Verify
   keyboard/focus behavior and server validation without exposing secrets.
3. **Router migration:** establish TanStack Router and generated typed routes,
   route/search validation, Query context and authenticated layout guards.
   Migrate the shell and route families in a dedicated migration branch with
   all existing URLs and compatibility redirects preserved. Verify deep-link
   reload, unauthorized access, scope changes, session expiry/refresh, back/
   forward navigation, not-found/error boundaries and lazy-loading behavior.
   Remove `BrowserRouter` and `react-router-dom` at cutover; do not ship two
   independent navigation/auth authorities.
4. **Form migration:** move identity/provider, registry, policy and settings
   editors onto TanStack Form in bounded slices. Preserve server authority for
   RBAC and validation, secret omission, dirty-state protection, field-level
   errors, duplicate-submit prevention, reset and mutation invalidation. Cover
   success and rejection through the actual API and production browser.
5. **Table convergence:** migrate the shared adapter to the qualified Astronomer
   TanStack Table generation and feature contracts, add Virtual where measured,
   and connect saved views/typed URL state to the new router. Keep server-side
   pagination/filter/sort authoritative. Prove selection, export scope, counts,
   resizing/pinning, keyboard behavior and saved-view isolation on large data.
6. **Backend/tooling convergence:** generate REST/OpenAPI clients/types and sqlc
   queries incrementally, preserve transactional audit/scope checks, and adopt
   local preflight, accessibility and contract-regeneration gates. CNPG proceeds
   through package B's separate recovery/migration qualification, not a frontend
   dependency. Full production-browser/API tests and removal of superseded
   router/form/table code are required before calling convergence complete.

DB safety remains the first delivery priority. Router/Form implementation may
proceed independently once the baseline contracts are captured; it must not
delay the urgent retention fixes or combine with the live DB cutover.

## P0 — truth, correctness, and release safety

Parity is not credible while a configured security control silently does nothing.
The current [deficiency audit](deficiency-audit.md) is the source list for these
correctness issues; this plan owns their release order.

### Implementation review — 2026-09-26

Unchecked parent items remain open until **all** their acceptance requirements
are met. Code present is not the same as verified or release-ready. The older
deficiency ledger includes findings that already have fixes; do not use its
historical counts as a count of currently open defects.
Acceptance backlog: **87 open** (selected console scope qualified and deployed
on schema177 above). Lease-scoped private-registry proof and
live scanner revision/capacity visibility close two REG-1 items. The October 12 browser/FIPS CI gate closes one
bounded item with local and hosted evidence. The September reconciliation reached 98;
the October 11 fleet review adds two explicit ingestion/isolation gates.
Since the `800b0ef` baseline of 107 open,
**twenty-five existing items closed** (four OPS-1 items, three SIEM-1 items, one
POL-1 item, one IAM-1 item, five UI-1 items, four UI-2 items, two UI-3 items,
three UI-4 items and two REG-1 items), and four new items were added: vendor interoperability, legacy
DPI binding tenant validation, registration/proof of the unreachable
group-edge HTTP workflow, and durable storage-growth controls.
The checklist contains **66 checked bounded rows** (39 at baseline); one new
bounded OPS-2 database-reclaim item was added as complete. Earlier
rounds added bounded POL-1, POL-2 and API-1 fixes without closing their parent
acceptance item. Those rounds added an eight-object cutover fixture and opt-in
runner, network precedence guards, and YAML API contracts. A subsequent round added
atomic network-import and response-reorder audit receipts, a tenant-safe
snapshot history export, and DLP/WAF visibility browser fixtures. Source tests,
deterministic browser tests, and a disposable local API/UI smoke are not a
complete NeuVector fixture or deployed cutover. This round closes local-user
recovery and backend platform-role classification, and adds bounded response-rule
YAML portability without closing its composite POL-3 item. Session and
conversation APIs/CSV use backend platform roles; the final finite role/export
matrix now closes UI-3. Selected non-threat ingest sources emit specific response
categories without closing the separate composite POL-3 requirement.
Partial scanner, registry and POL-1 fixes are recorded in the review table, not counted as
closures. A checked child does not close its unchecked parent or replace live
deployment evidence.
Audited local-user recovery and backend platform-role classification now close
their own bounded rows; IAM provider cutover remains open. Complete relevant
console role/API/export coverage is qualified in the final UI-3 matrix above.

| Acceptance item closed since `800b0ef` | Closure evidence |
|---|---|
| OPS-1 heartbeat fixtures | API-level tests ingest all 15 required and optional roles and check empty, partial and healthy org/cluster rollups. |
| OPS-1 role aliases, diagnostics and E2E filtering | DB-backed component tests cover controller, runtime-agent/enforcer and scanner role aliases, diagnostics status/checks, redaction and access failures. Existing frontend alias tests pass. A production-build Playwright browser run verifies URL role filters, matching rows, selection and role-specific diagnostics for all three roles using deterministic API fixtures; this closes the test item, not deployed component-health proof. |
| OPS-1 signed support bundles | A Helm-deployed API on disposable k3d ran with a read-only Ed25519 PKCS#8 Secret mount and separate seeded PostgreSQL database. An authenticated admin downloaded a signed bundle (HTTP 200), and the standalone offline verifier accepted it against a fingerprint derived from the deployment key before reading the bundle. The verifier rejected a tampered copy. Source/API/chart tests and Helm rendering also pass. Persisted asynchronous jobs are closed separately below. |
| OPS-1 asynchronous support-bundle jobs | Migration 164 persists queued/running/ready/failed/expired jobs, bounded cursor history, redacted payloads, seven-day expiry and audit links. Per-replica workers claim with `SKIP LOCKED`, recover stale leases and retry completion receipts. Source race tests cover transitions, isolation, audit failure, redaction, pagination and concurrency. A disposable k3d Helm install served API/frontend through nginx: an admin queued a job, observed ready status, downloaded a signed bundle, verified it offline against the independently derived key, and found create/ready/download events in audit history. Production-serving Playwright verified the operator queue, persisted history, ready download and audit drill-down. |
| SIEM-1 syslog TLS with CA/client material | A Helm-deployed API delivered to a strict mTLS collector and rejected wrong-CA and missing-client configurations; source tests cover TLS and plaintext rejection. |
| SIEM-1 wire formats and filters | The deployed collector captured RFC5424, JSON and CEF policy events and verified severity/category exclusions. |
| SIEM-1 named receiver routing and receipts | A deployed API sent to only the selected SMTP receiver, surfaced a delivered receipt and audit link, and refused paused sends; source tests cover retries and isolation. |
| POL-1 shared GroupPicker coverage | Editor audit and a response-rule save-path test prove shared group selection; full enforcement remains a separate open item. |
| IAM-1 local-user recovery | PostgreSQL/router tests prove scoped unlock and force reset with atomic audit receipts; a deterministic production-browser test exercises the local-only operator controls. Other IAM-1 items remain open. |
| UI-3 platform-role classification | Source API tests, production-browser tests and a genuine isolated custom-namespace chart installation prove `core` classification, visibility and continued discovery. The complete relevant console API/export matrix is qualified in the final UI-3 continuation above. |
| UI-2 YAML contract discipline | The six enterprise-table YAML controls (network, DLP, signatures, response, groups, vulnerability profiles) each pair export with a registered import route and typed client call. Generated cluster-init and Kubernetes policy YAML are deployment artifacts, not table configuration imports. The response-rule control has deterministic production-browser coverage; the other families have existing import tests. This closes only the YAML discipline row, not shared-table completeness. |
| UI-1 scope order | The October 12 user decision makes Clusters the first persistent entry, followed by Organization, Platform and Integrations, across the sidebar, command palette and Settings hub. Navigation fixtures now follow that order, and live browser checks confirm sidebar, Settings and palette agreement. Prior deterministic browser evidence covers canonical route targets, keyboard navigation and cluster context; the revised full production-browser suite also passes. The final UI-1 source/workflow matrix is recorded above. |
| UI-1 duplicate entry points | Generic health and system-health aliases now redirect to platform health, while cluster sensor/registration health remains intentionally distinct at its cluster URL. Token, attestation, access-control, integration and Settings aliases preserve deep paths, filters and fragments. Cluster health selection follows its URL rather than silently displaying the first cluster; three API-backed cluster browser cases and deterministic alias/settings cases pass. The finite canonical-home and final page/workflow acceptance matrices are recorded above. |
| UI-1 primary page contract | The finite 110-source router audit finds no primary undisclosed metric row above five or competing native inventory table. Frozen production-browser navigation/smoke plus targeted workspace cases qualify the page families; Settings directory and dedicated-form exceptions are explicit. Final deployment and live checks are recorded above. |
| UI-1 URL workspaces and dedicated forms | Production-browser cases qualify peer tabs/history, exact scoped forms, Save/Cancel/back, retained failed drafts and Advanced disclosure; read-only peeks and confirmations do not become editing drawers. |
| UI-2 full inventory controls | Server continuation/filter/sort/summary/matching CSV and visible source caps replace the selected console's secondary bounded consumers, including final Backup history. Shared table controls retain all rows and operator scope. |
| UI-2 operator preferences and saved views | Browser cases cover URL/history restoration, tenant/user isolation, hidden active filters, stale-column migration, keyboard layout controls, reset and failed-storage draft retention. |
| UI-2 read-only peeks | `DeploymentFindingsInventory` observation peeks, Timeline event drawers, Scanner job drawers and Network flow/workload inspectors support repetitive inspection without editing. Exact selection is URL-bound; authoring navigates dedicated forms and missing records do not substitute another row. |
| UI-3 relevant API/export role agreement | The finite endpoint/consumer matrix qualifies actual roles across JSON, applicable CSV/NDJSON and reports, with explicit unknown identity and genuine custom-install discovery/hide-show proof. |
| UI-4 readable report downloads | HTML/CSV/JSON are preferred; optional PDF keeps actual MIME/filename and fallback. Exact scope receipts, effective source summaries, immutable artifacts and real command-generated reports are qualified. Scheduled runtime deployment is not claimed. |

Historical bounded continuation (superseded for selected UI-1/2/3/4 acceptance by
the final source/browser matrix above): network sessions and
conversations now return tenant/cluster-scoped platform roles, conversation
detail carries roles for matching flows, and session/conversation CSV exports
include roles. Source race tests and deterministic browser tests cover a custom
namespace; other exports and a live custom install remain open. Process
anomalies, setuid and FIM now map to
incident, file-profile hits/blocks to violation, and DPI threat IDs to DLP/WAF
response categories. Focused race and PostgreSQL tests pass; other ingest
sources, full rule-category behavior and deployed enforcement remain open.
Saved-provider probes now exercise public LDAPS TLS/optional bind, local SAML
metadata parsing and public HTTPS OIDC discovery with scoped authorization,
redacted responses and audit tests. Private/air-gapped IdPs and live SAML
connectivity are not supported by these probes, so IAM-1 stays open. A
production-build browser test against an isolated migration-166 API/DB created
a saved SAML provider, exercised its check and removed it; this proves the
local metadata path, not external IdP connectivity.
Legacy DLP/WAF and common feature aliases now redirect to canonical routes
while preserving deep paths, filters and fragments; deterministic browser
coverage exercises representative aliases. Token, attestation, access-control
and integration aliases now also redirect to Settings, and the cluster picker
links directly to canonical system health. Cluster health remains a distinct
sensor/registration surface; the duplicate-entry-point row is now closed, while
the canonical-home audit and page-contract rows remain open.

2026-09-27 continuation: an isolated PostgreSQL database migrated through 166
and seeded for a locally running API passed seven existing API-backed browser
tests across Access Control, network, and response workflows. A separate live
browser test created, checked and removed a saved SAML provider. These are
local API/browser proofs, not deployed IdP or network enforcement evidence.
The network conversation table CSV now includes endpoint roles, with a
cluster-scoped browser test; other role-bearing exports remain under review.
Dashboard link tests cover metric destinations and supported filters, but
the destination matrix remains incomplete. Findings now applies severity and
accepted-lifecycle URL filters in the instance view with browser-history tests;
its list is capped at 500 rows, and the CVE rollup has no severity-aware total.
Deployments now applies a visible URL-backed name filter to rows, counts and
CSV, but its API returns only the default first 100 rows. Host CVEs now opens
a cluster-scoped, paged node view filtered to open host vulnerability findings;
it labels loaded-only search, sort, and CSV. The tile counts findings, whereas
the node list counts distinct named hosts, so these are not identical totals.
The October 12 workflow continuation below supersedes these network limitations
with exact endpoint/window predicates and a combined deny/block cohort. Broader
destination and source-total acceptance still leaves UI-4 unchecked.
An attempted 164-case full Playwright run on another isolated migration-166
database was stopped after 38 cases: 24 failures were HTTP 429 from the
intentional 10-per-minute per-IP login guard, not verified feature regressions.
The focused API-backed and deterministic browser gates remain valid. A
worker-local helper alone still hit 429 after a worker restart; a Playwright
setup project now persists validated bearer/browser state outside test output,
shares it across workers, re-authenticates after revocation, and cleans it up
afterward without weakening the guard. A 16-case API-backed browser sample
then passed 15 cases without 429; the remaining repeat image-acceptance case
exposed a database uniqueness defect. Migration 167 permits re-acceptance
after revocation while preserving history; its focused PostgreSQL test and a
three-case browser rerun pass. A subsequent isolated-API full Playwright run
reached 133 of 182 cases: 119 passed before it was stopped after stale
accordion-navigation tests, an obsolete migration-preview assertion, one
intermittent cross-tab refresh failure and one blank asset-detail render.
The navigation and migration assertions were corrected; a 35-pass focused
browser run and a four-pass targeted rerun verified the fixes, including asset
detail and cross-tab recovery. The full suite and cross-tab race remain open.
For browser-only disposable stacks, the session cap is raised to 32 so direct
login tests do not evict the shared setup state; the login rate guard is intact.
This is test infrastructure, not a production session-cap change.

The current code batch also adds stable, explicit asset-list continuation and
loaded-only UI/CSV labeling; bounded network map/conversation/session/threat
filters, totals and paging; and a saved LDAP/SAML/OIDC role/scope preview for
already-extracted group values. The 251-row asset fixture, 250–350-row network
fixtures and scoped provider preview tests pass locally. These are partial
OPS-2, NET-1 and IAM-1 progress, not closures: other high-volume pages and
source counts, exact rollup peer matching/application behavior, cross-tab
reconciliation and live IdP group retrieval remain open.

Local k3s maintenance and deployment on 2026-09-27: both legacy DEFAULT
partitions were proven to contain zero live rows and safely truncated, reducing
the existing database from 33 GB to 18 GB without touching identity or audit
tables. A validated 244 MB non-telemetry backup was taken before Helm upgrade.
Dev telemetry retention was changed from 30 to 7 days for events and from 14
to 3 days for raw network flows by a direct DBA configuration update; this is
not evidence of an audited Settings PATCH. The upgraded API dropped 23 expired
event partitions and 11 expired flow partitions, reducing the database to
6.8 GB. Revision 18 deployed API/frontend and migration 167 in the existing
namespace; API, frontend and runtime-agent pods were ready. The ingress host,
TLS certificate fingerprint and admin password hash/state matched pre-upgrade
baselines; local TLS and an unauthenticated production-browser login-route
smoke passed. The current k3s UI also responds through a local port-forward at
`http://127.0.0.1:5182`. A focused 19-test browser gate against a disposable
local API passed for assets, network activity, provider-role preview,
high-volume caps and clusters.
Authenticated browser smoke against k3s remains open because the bootstrap
Secret does not contain the current admin password. Public DNS currently points
to a different IP than this k3s node, so external URL reachability needs a DNS
change or another routing path; the in-cluster ingress URL and cert are intact.
The partition manager now reclaims an empty, bloated DEFAULT partition only
after a locked recheck; focused PostgreSQL tests cover nonempty, detached and
concurrent-ingest cases. This closes only the bounded reclaim item below.

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
| POL-1 shared GroupPicker coverage | Closed; editor audit and save-path test passed | Network-rule, admission-rule and response-rule editors use `GroupPicker`; DLP/WAF group bindings use `GroupPickerView`. The remaining runtime-policy and file-monitor editors select workloads rather than groups, so replacing those selectors would change their meaning. A response-rule form integration test selects a real group option and verifies the saved `workload_match.group`; all 92 frontend tests and the production build pass. The full group enforcement/browser workflow remains open separately. |
| REG-1 scanner DB and capacity surfaces | Source and production-browser UI verified; deployed scanner proof open | Scanner heartbeats now report per-engine Trivy/Grype applied revisions from installed DB metadata and download revisions only after a successful explicit refresh; offline preloads report applied but not downloaded. Dashboard, System Health and Scanner & CVE Sources show revisions separately from the host VulnDB bundle and show worker capacity, missing/partial/stale states. Scanner race/unit tests, frontend component/type tests and PostgreSQL-backed overview/cluster health API tests pass. A production-build Playwright test verifies dashboard, System Health and scanner-source rendering with deterministic heartbeat revisions. A deployed scanner refresh and real heartbeat-to-dashboard smoke is still required before closing the existing REG-1 item. Download history is in memory and resets on scanner restart; installed applied revisions are recovered from the local DB. |
| P0 audit/timeline/exemption scope | Source fixes and direct PostgreSQL tests verified; deployed matrix open | Audit, timeline, compliance checks/summary and evidence cluster filters reject clusters outside the subject org; timeline violation attribution cannot join a foreign-org deployment. Exemption create/list/revoke tests cover cross-org/foreign-cluster and no-write behavior. The evidence overlay applies cluster-specific exemptions only to matching-cluster items, falls back to org-wide exemptions and rejects misattributed exemptions; checks/summary exclude misattributed foreign-cluster check and exemption rows. The group-edge routes now honor cluster grants in focused API tests; remaining route-level cluster-grant RBAC, aggregation and agent-write inventory, and deployed multi-cluster paths are open. |
| SIEM-1 TLS material guard | Source and deployed mTLS collector verified | Validation and sender guards refuse TLS material on plaintext transport. In-process tests cover TLS 1.2/1.3, wrong CA, absent/untrusted clients and plaintext rejection. A Helm-deployed API additionally passed strict client-certificate verification and rejected wrong-CA/missing-client attempts before resuming after restoration. Vendor-specific interoperability is separately open. |
| SIEM-1 severity floor | Source and deployed wire/filter matrix verified | An unknown configured minimum level denies all alerts rather than silently shipping; an unknown alert severity falls below an `info` floor. Source tests cover all three formatters and filter-before-dial. A live collector captured RFC5424/JSON/CEF, excluded an info event under a high floor and excluded a critical event under a mismatched category. |
| SIEM-1 named delivery receipts | Source, API and deployed SMTP receiver verified | `DispatchTo` scopes receiver lookup to the event org and rejects paused receivers before queueing. Workers and sweepers terminate queued/retry deliveries paused later. PostgreSQL tests cover named-only send, pending/delivered/retrying/failed/paused receipts, exact retry payload/idempotency and concurrent in-flight pause ordering. API tests cover history, audit linkage and cross-org isolation. A deployed API delivered only to its named SMTP recipient, exposed the delivered receipt and audit link, and returned 409 for a paused test-fire. A named vendor SIEM remains separately open. |
| POL-1 reference scope guard | Source races and deployed API concurrency smoke verified; writer integrity open | An org-wide group could be updated under a `cluster_id` filter while its network/response/admission references existed in another cluster. Update now counts blocking references across the org, matching delete; the usage view shows all explicit blockers even with a cluster filter, while derived member profiles remain scoped to that filter. A prior PostgreSQL regression and Helm-deployed API smoke prove cross-cluster visibility, 409 unsafe update/delete, allowed update after unlink and audit. Update/delete lock the org row first, acquire all four reference-table locks with `NOWAIT` and retry in fresh transactions so a blocked table does not hold partial locks against concurrent deletes; they then lock the group and count references. A fresh PostgreSQL `-race` matrix covers each uncommitted reference writer, org deletion, and release of partial locks. A rebuilt Helm-deployed API waited 1.7 seconds for an in-flight network-edge insert, then returned 409; unlinking allowed 204. Some raw group and reference writers still bypass validated paths, so referent integrity remains open. |
| POL-1 name-based writer guard | Bounded source and deployed API smoke verified; raw-writer inventory open | `GroupEdgeStore.Upsert` validates both endpoint group names in the same org/cluster transaction and permits only the built-in `external`/`nodes` names without a group row; PostgreSQL races cover rename/delete and org deletion. The structured admission-rule builder and response-rule-v2 create/update validate nonempty group selectors in the same transaction as their writes; tests cover tenant, cluster and org-wide scope, including rejection of cluster-only groups from org-wide rules, plus rename interleavings. The migration-166 Helm API returned 400 for org-wide rules targeting cluster-only groups, 201 for valid org-wide and cluster-scoped selectors, and 409 for referenced-group delete. Generic raw admission-policy create/update now validate every parsed `spec.match.groups` selector against the resulting policy scope in the same transaction; source races cover rename/delete. Portable group import now locks existing groups and all reference tables before changing reference-sensitive fields, rejects cross-cluster updates and waits for in-flight edge writes; a repeated PostgreSQL race test covers the import outcomes. A subsequent Helm API rejected missing edge groups and raw-policy selectors, expanded a protect edge into five enforcing runtime policies, rejected a referenced-group delete and a sensitive portable import, and listed/deleted the edge. Federation group sync, migration apply/rollback, and learned-group refresh now guard reference-sensitive group changes and scoped edge/admission writes with transactional locking; focused PostgreSQL races and the serial affected-package race suite pass. Direct SQL/other raw-writer inventory and deployed federation/migration/learned-path proof remain open; no name-based referential FK exists. The parent POL-1 conflict item stays open. |
| POL-1 live membership transition | Fresh migration-166 source/race verified; multi-family and deployed proof open | The deployment-driven reconciler now locks the org, reference tables and current group. A cluster-scoped group referenced only by network edges replaces its cached members, retracts fully edge-owned policies, propagates joined-member profile mode without lowering an existing stronger baseline, and re-expands the edges in one transaction. Tests cover discovered deployments, joining/departing members, enforcing policies, ambiguous ownership, forced later-policy failure rollback, mixed reference families, org-wide fail-closed behavior and in-flight edge insertion. DPI/response/admission references and org-wide groups still refuse member changes; departed-member baseline de-propagation, durable system audit receipts, deployment and packet/DPI proof remain open. This bounded network-edge transition does not close POL-1. |
| POL-1 group profile propagation | Source and deployed create rollback verified; org-wide behavior open | Bulk profile-mode promotion/demotion, ordinary group create/update and per-group portable import now update group rows and member process-baseline states in one transaction rather than persisting the group first and ignoring a propagation failure. PostgreSQL check-constraint tests force later member writes to fail and verify no partial group or baseline-state change survives; portable import records the per-group failure without counting it as created/updated. A Helm API returned 500 under a forced later-member ordinary-create failure with zero created groups and the prior baseline unchanged, then 201 after constraint removal with three enforcing default-namespace baselines. Portable-import transactional propagation has source proof only; org-wide propagation remains undefined. This does not close POL-1. |
| POL-1 operator group writer | Bounded PostgreSQL races verified; safe membership transition open | Direct operator group writes now lock the org, reference tables and group row; they reject reference-sensitive updates/deletes, imperative-owner or cluster-scope collisions, and scoped edge endpoints outside the org/cluster. Operator edge mode/port changes and deletes refuse existing expanded policies rather than silently leaving stale enforcement. Tests cover all four group-reference families, scope collisions, expanded-policy conflict and an in-flight edge insert. The operator does not expand/retract policies itself; safe future-member propagation and deployed CR reconciliation proof remain open. |
| POL-1 admission bulk writer | Bounded PostgreSQL races verified; wider policy inventory open | Bulk admission-policy create/update/enable now validate resulting group selectors inside the batch transaction with org/cluster scope and row/table locks; a failed operation rolls back earlier writes. Tests cover foreign/missing groups, org-wide versus cluster scope, foreign clusters, and concurrent rename/delete. Single-policy create now checks cluster ownership in the same transaction even when no group selector is present. Other raw/import writers and deployed negatives remain open. |
| POL-1 group-edge HTTP workflow | Registered, documented and deployed control-plane path; legacy cleanup and dataplane proof open | The route requires read-findings for list and manage-policies for upsert/expand/delete, checks org-owned clusters and scoped groups, and requires durable audit *attempts* before mutations. Source tests cover RBAC, cross-org/cluster rejection, protect expansion and audit-outage no-write; the OpenAPI operation-stub ratchet passes. A Helm API created, listed, re-expanded and deleted an edge with normal audit receipts. Expansion writes runtime policies in one transaction; a forced later-policy failure left zero partial policies, then retry produced six flows and five enforcing policies. Create-with-expand uses one edge/policy transaction; a later Helm API returned 500 with zero edges and policies under injected failure, then 201 with six flows and five enforcing policies on retry. New expansions mark generated rules with the edge ID; PostgreSQL tests prove deletion atomically retracts only fully edge-owned policies and returns 409 without mutation for mixed authored rules, edited posture or unmarked legacy policies. A deployed API also returned 409 for a pre-marker edge, then created an edge with five marked policies and deleted it with zero edge/policy rows left. Legacy/mixed-policy resolution, reliable completion receipts, deployed edge-edit proof, live network dataplane proof and broader cluster-grant RBAC remain open. Group-edge list/create/expand/delete now authorize against the targeted cluster; fresh-DB HTTP tests prove same-cluster grants work and sibling-cluster grants cannot read or mutate. The checklist item stays open. |
| POL-1 expanded edge edit guard | Atomic transition source/race verified; deployed transition open | Mode/port edits to an expanded edge now verify ownership, retract prior policies, update the edge and re-expand within one transaction; ambiguous legacy or mixed policies still return 409 without mutation. Fresh migration-166 PostgreSQL tests cover standalone upsert and create-with-expand, mode/port replacement, ownership denial and forced later-policy failure rollback with a successful retry. The earlier Helm API returned 409 for protect-to-monitor and port changes under the previous guard, 201 for a comment-only edit, and retracted five policies on delete. That deployment predates this transition; deployed edit and dataplane proof remain open. |
| POL-1 DPI binding tenant guard | Source, deployed API and validated-schema upgrade verified; real legacy inventory open | A DLP/WAF binding previously accepted a foreign-org `group_id` because its FK checked only the group ID. Bind now inserts only from a group row in the authenticated org and refuses a conflicting stale binding owned by another org. PostgreSQL HTTP and Helm API negatives return 400/zero rows for foreign groups, while same-org binding returns 201. Migration 165 adds a composite `(org_id, group_id)` FK marked `NOT VALID` and rejects new invalid writes. The read-only preflight reports legacy mismatches; migration 166 validates the FK and stops without deleting rows when a mismatch exists. A genuine 164→165→166 fixture preserved its invalid row and stayed at version 165 until explicit repair, after which preflight and validation passed. The [upgrade runbook](group-dpi-binding-upgrade.md) requires audited API repair. Actual installation inventories, audited repair receipts, and broader import-writer proof remain open. |
| API-1 group/DPI/edge OpenAPI contracts | Source schemas and focused tests verified; parent open | Group usage now documents response/admission counters, org-wide direct references, and error responses. DLP/WAF binding list/create/delete document typed requests, responses and actual status codes. Group-edge list/upsert/expand/delete now use typed row, port and expansion schemas with cluster-grant/transactional-edit semantics and a focused spec test. Other API-1 endpoint families and live contract smoke remain open. |
| API-1 migration OpenAPI contracts | Fresh migration-166 PostgreSQL and focused contract tests verified; parent open | Migration preview, saved-import history, apply, rollback and rollback-bundle operations document typed contracts. History accepts bounded limit/offset and keyset cursor pages so newer inserts do not shift older pages; preview and history expose a validated target-cluster ID for new imports, while legacy records retain unknown target scope. A new org-scoped NDJSON export streams metadata-only history from one repeatable-read snapshot in stable order with a required final count record; PostgreSQL/API tests cover over 100 rows, redaction, tenant isolation, snapshot insertion and RBAC. Raw previews, unsupported reason/source text, errors and rollback bundles are deliberately excluded; interrupted streams require restart. Complete runbook and deployed contract smoke remain open. |
| API-1 network/admission OpenAPI contracts | Focused source contract tests passed; parent open | Network-rule list, mutation, deletion and move-top contracts and admission assessment/dry-run history have typed schemas reflecting handler response statuses. YAML export/import bundles, validated media type/version/kind, and per-rule outcomes are documented and source-tested. Import refuses foreign clusters and unavailable audit before writing; savepoints retain per-row errors while successful writes and the completion receipt commit atomically. Focused PostgreSQL race tests cover audit failure and concurrent imports. Partial success still returns 200; full endpoint-family review and deployed contract smoke remain open. |
| API-1 registry/events/PCAP/support contracts | Focused source contract tests passed; parent open | Registry sync/cancel, event export, PCAP lifecycle and support-bundle generation/job/download operations now document their concrete request and response shapes, status codes and agent security where applicable. Source-dependent NDJSON and support-bundle sections remain open-ended; deployed contract smoke and full endpoint-family review remain open. |
| POL-2 saved migration diagnostics | Source API and frontend component/build verified; deployed UI proof open | Policy Center shows saved NeuVector unsupported reasons and suggestions beside mapped families; ambiguous/unknown kinds stay general. New previews persist validated target-cluster metadata, while legacy or unspecified targets remain explicitly unknown. The history API serves bounded keyset pages with Load more so newer inserts do not shift older pages, and Migration Imports labels target scope. A same-origin download now exposes the full, metadata-only NDJSON snapshot export and distinguishes it from the table's loaded-row CSV; the final completion count must be checked. Policy Center separates selected-cluster, other-cluster and unknown-target records. This is import-time diagnostic history, not current enforcement health. Fixed-snapshot paging across all writes, full diagnostic-content export, deployed browser proof and historical target backfill remain open, so the checklist item stays unchecked. |
| POL-2 listed change/match metadata | Frontend component tests verified; full family health open | Policy Center uses existing DLP, signature, group and vulnerability-profile list timestamps to show a clearly scoped latest *listed* change, with unavailable/empty states. It also sums listed network-rule match counters and shows their last listed match, rejecting invalid counters/timestamps and explicitly not treating matches as enforcement health. Focused component tests and TypeScript pass. Network/admission/response and other families, authoritative all-item last-changed, broader hit/last-hit coverage, enforcement health and deployed proof remain open. |
| POL-2 precedence entry points | Source/race, registered-route RBAC and deterministic browser tests verified; deployment open | Policy Center links to move-to-top and response up/down controls only for families with runtime ordering. The network table initially preserves server evaluation order, shows priority, and does not mistake the first filtered row for the global top. Network move-to-top verifies the owned cluster and existing rule, serializes concurrent moves, preserves negative priorities, and commits its completion receipt atomically; injected audit failure rolls the priority change back. Response reorder now verifies owned cluster scope, logs the before/after order, and commits its completion receipt atomically; injected audit failure leaves priorities unchanged. Registered-router tests verify network same/sibling-cluster grants and deny auditor mutations; the org-wide response route denies cluster-only grants. Focused PostgreSQL race/audit-chain tests, 108 frontend tests, production build and two Chromium tests with mocked APIs pass. Other network-rule writers do not share move serialization; live backend browser and deployed enforcement proof remain open. |
| MIG-1 bounded cutover fixture | Eight-object PostgreSQL, mock and disposable local API smoke; complete canonical fixture open | A manifest enumerates two groups, one network edge, one vulnerability profile, one DLP rule, one WAF rule and two group bindings with source, converted, unsupported, applied and rolled-back counts. A fresh migration-166 PostgreSQL handler test verifies preview semantics, target rows, apply and rollback. The opt-in loopback-only runner refuses nonempty import history or preexisting targets, checks counts and HTML availability for Migration and Policy Center routes, and attempts rollback cleanup on failure; 11 mock tests pass. Against a disposable local API and separate production-build UI HTML server, preflight, eight-create preview, apply/target reads and eight-delete rollback all passed. A production-build Chromium case with deterministic API fixtures shows DLP/WAF preview/apply, Policy Center links and imported origin/group scope on DLP and WAF/DPI pages; it does not render against the real importing API. The local smoke used a seeded org rather than a genuine new-org cutover, and remaining families are absent, so neither the full fixture nor new-org cutover acceptance item is closed. |
| POL-1 group workflow | API and production-browser control plane verified; enforcement open | A PostgreSQL-backed server test creates groups, previews/applies a NeuVector fixture containing a network edge and DLP/WAF bindings, checks usage and mode promotion, verifies RBAC/audit, and rejects unsafe delete without losing the group or references. A Chromium Playwright run against both an isolated production stack and a Helm-deployed API with a production frontend build creates a group, uses it in a network rule and DLP/WAF bindings, inspects usage, promotes mode, gets 409 on unsafe delete and cleans up. The UI-authored network rule is a network override, not a `group_rule_edges` row, so the usage blocker count is two (DLP/WAF). Live network and DPI enforcement remain unproven; the item stays open. |
| IAM-1 local-user recovery | Closed bounded action; other IAM-1 items open | Unlock and force-password-reset routes require manage-users RBAC and scope the target to the caller org. Mutations and audit receipts commit together or roll back on audit failure. Access-control overview exposes local-password, lockout and reset-required state; production-build Chromium verifies local-only controls and the recovery route calls with deterministic API fixtures. Focused handler, router/RBAC, audit and OpenAPI tests pass. LDAP/SAML/OIDC connection tests, role previews, NeuVector identity import and namespace filtering remain open. |
| UI-3 platform-role classification | Closed backend classification; finite relevant API/export matrix qualified and deployed | Exact platform namespaces plus workload labels and Helm installation identity classify custom platform install namespaces as `core` in deployment list/detail, container inventory, network map, exposure and policy lifecycle. Frontend inventories and map prefer the backend role and retain exact-namespace fallback for legacy responses. Source tests and production-browser inventory/export tests pass. A genuine custom installation proves workload/container API/CSV roles, hide/show and continued discovery while hidden. The final role/export matrix qualifies the relevant console surface; schema177 report/tuple/NDJSON deployment is verified above. |
| POL-3 response-rule YAML portability | Bounded control-plane slice; composite POL-3 row open | Org-wide or exact-cluster YAML export/import validates version, scope, media type, size, selectors and conflict policy; import records an attempt before mutation and commits completion audit with successful rows. Unsupported action params fail closed, receiver IDs normalize to names on export, and import requires a matching target-org receiver name. OpenAPI, scoped RBAC, PostgreSQL/race and deterministic production-browser controls are covered. Non-threat event-category wiring plus deployed response-enforcement proof remain open. |

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

SIEM closure used migration 164 on a disposable PostgreSQL database and a Helm
deployment in disposable k3d. The rebuilt API image was
`sha256:d30da81cea257830d6ba39beb297f45199c317c881f924c1b44f192af335c2d7`.
Captured synthetic collector traffic is in `/tmp/constellation-siem-parity-0926/wire.log`
and `/tmp/constellation-siem-parity-0926/smtp.log`; private test keys are not
retained. Affected Go packages passed `go test -race` and `go vet`; the plan-count
and endpoint-mapping tooling gates passed.

POL-1 scope smoke used migration 164 and Helm-deployed API image
`sha256:4c11072fb93ff451759d3799df1b903f93f7a30dc02e980b29d8d650f2cf7902`
on disposable k3d. A filtered group-usage GET surfaced another cluster's
network edge; unsafe update and delete returned 409, removal enabled update,
and the audit API recorded it. Focused handler/server races and the frontend
suite/build passed; this did not exercise the data plane.

POL-1 concurrent-writer smoke used migration 164 and rebuilt Helm API image
`sha256:3101f5f372b5109db415d080b7d529e1d0576245f3d36ba64c588bcc70407302`
on disposable k3d. An authenticated API delete waited 1,695 ms for an
uncommitted network-edge insert, then returned 409 with one blocker; after
unlink it returned 204. A separate deployed update/delete check returned 409
for an existing edge and 204 after unlink. Fresh PostgreSQL race tests cover
in-flight writes in network, DPI, response and admission for both update and
delete. This does not prove later writer referent validation or live enforcement.
The same disposable deployment was then upgraded to API image
`sha256:3de39492d30f042bea5409e37adb3f97cc1f33d1f1678ec4032c425831265f0d`;
an authenticated foreign-org DLP binding returned 400 with no row, while a
same-org binding returned 201 and was cleaned up. Production-build Chromium
passed the group control-plane workflow against the prior Helm image and an
isolated production stack; neither run exercised live network/DPI enforcement.
Migration 165 subsequently added a `NOT VALID` composite tenant FK for group
DPI bindings. On a fresh database, migration 165 and a direct-SQL negative FK
test pass. A downgrade/reapply test with a legacy foreign-org row preserved that
row, left the constraint unvalidated and rejected a new foreign-org insert.
The migrated database also served a Helm API: same-org binding returned 201,
foreign-org binding returned 400 with no row. Existing invalid rows still need
inventory/remediation and `VALIDATE CONSTRAINT`; the full tenant-scope checklist
stays open.
Migration 166 and `scripts/check_group_dpi_binding_scope.sql` now provide a
fail-closed upgrade path, documented in [the binding upgrade runbook](group-dpi-binding-upgrade.md).
A genuine migration-164 legacy fixture with a cross-org row applied 165 but
failed preflight and 166, leaving the row and version 165 intact. Explicit test
repair allowed preflight and 166 to pass with `convalidated=true`. The fixture
repair used direct SQL solely in a disposable database; production remediation
must use an authorized, audited API operation. Real installation inventory and
repair receipts remain open.
An initial seeded shared-DB race run exposed lock-order inversion between group
mutation's table locks and org deletion's FK cascade. Group mutation now locks
the org row first. A later full-suite run exposed another inversion with user
deletion; reference-table locks now use `NOWAIT` and rollback/retry so they do
not retain partial locks. Deterministic org-delete, partial-lock release and
eight reference-writer interleavings pass; handler/policy/runtime/server races
pass on a freshly seeded migration-166 database. The earlier Helm
API image `sha256:16b6a3f21b737557ce02192a1ae61d668612c62d027ba5efcaef9dc1a2f290bd`
ran against migration 165: a DLP binding blocked group delete with 409; after
unbind, an in-flight network-edge insert delayed another delete by 1,309 ms
and returned 409 with one blocker; unlink enabled 204. This is control-plane
proof, not live network/DPI enforcement or legacy FK validation. A new API image
`sha256:a227a4d7d30f08ec1a573eedf7d27984a3de1929188031a5f984025c90161b17e`
ran on a disposable k3d/Helm deployment against migration 166: missing group
selectors returned 400 from response-v2 and admission-builder APIs; valid
selectors returned 201; deleting their referenced group returned 409 with two
blockers. This proves those deployed control-plane paths only. The group-edge
store's hardened writer is not reachable through the server router, and no
live network/DPI dataplane enforcement was exercised.
The final rebuilt image after the org-wide scope correction is
`sha256:8363348e98cdd767050e8d86cce1842573347fe1506dabb3cc870ba077ba5b9c`.
On a second disposable Helm deployment, org-wide response/admission rules
targeting a cluster-only group returned 400; org-wide rules targeting an
org-wide group and cluster rules targeting the cluster group returned 201;
referenced-group deletion returned 409. The migration-166 FK was validated.
That earlier image did not prove the then-unregistered edge HTTP path or
dataplane effects.
The next rebuilt API image,
`sha256:5a344f7101095629f1ac80302d7b6ac84634b61825abeff1df2c9e4f7fc61e3d`,
registered and documented the edge path. A disposable migration-166 Helm API
rejected an absent group (400), saved and expanded a protect edge (201), listed
and re-expanded it (200), rejected deletion of its referenced group (409),
rejected an invalid raw admission selector (400) and a reference-sensitive
portable import (per-group error), and deleted/listed the edge (204/200).
The expansion produced six flows and five persisted `enforce` runtime
policies; ordinary upsert, expand and delete audit receipts were present, and
the composite DPI binding FK remained validated. Edge deletion did not retract
the policies. This is control-plane proof only, not a packet-level enforcement
drill or atomic expansion/cleanup guarantee.

The next API image,
`sha256:b7961739d5f71967e063e6edfbbea47814010d27e081212ada55e502b413d10e`,
ran on a second disposable migration-166 Helm deployment. A protect edge
between three front and two data workloads was saved without expansion. A
temporary PostgreSQL constraint forced the second runtime-policy insert to
fail: expand returned 500 and no policies for that edge persisted. After
removing the constraint, retry returned six flows and five persisted `enforce`
policies. The constraint was removed. This proves atomic runtime-policy writes
for this failure path, not atomic edge creation, policy retraction, completion
audit delivery, or network dataplane enforcement. Federation, migration and
learned-group writer guards passed the serial affected-package race suite on
the same migrated database (`/tmp/parity_group_writers_serial_race.log`); their
deployed HTTP/sync paths were not exercised.
The subsequent source change makes create-with-expand transactional across the
edge and policies. Fresh migration-166 PostgreSQL `-race -count=2` tests force a
later policy insert failure and verify neither a new edge nor an update to an
existing edge survives, with no partial policies. An HTTP handler test also
returns 500 with zero edges and policies after the same injected failure. The
expand audit attempt now precedes either write. API image
`sha256:92099ebb446336ea33234d9c306819eecc17092550df0c4b888d668ffb1d2bec`
ran in a disposable migration-166 Helm release. A temporary constraint forced
the second policy insert during create-with-expand: HTTP returned 500 and both
edge and policy counts remained zero. After removing the constraint, the same
request returned 201 with six flows and five persisted `enforce` policies.
The release reached deployed status and the disposable constraint was removed.
This is control-plane rollback proof, not packet-level enforcement proof.
The membership reconciler now atomically updates cluster-scoped groups that
have only network-edge references: it retracts fully owned prior policies,
updates members, propagates joined-member profile mode without lowering an
existing stronger baseline, and expands replacement edge policies. Forced
re-expansion failure rolls back the member and baseline changes too. Mixed or
legacy policy ownership, DPI/response/admission references and org-wide groups
remain fail-closed. Departed-member profile de-propagation, durable system audit
receipts and deployed enforcement proof remain open.
The current migration-166 fresh-database race run passed
`./internal/groupprofile ./internal/handler ./internal/handler/runtime
./internal/server` serially; its log is `/tmp/parity-membership-broad-final.log`.
The Policy Center update passed 96 frontend tests and a production build.
Bulk profile-mode changes, ordinary group create/update and each portable
import group now use a transaction for the group change and its member
process-baseline states; forced later-member failures roll back both. Portable
import has fresh-DB source proof, while org-wide propagation is not defined.
The operator's direct SQL group and edge paths and the bulk admission-policy
endpoint now guard tenant/scope and referenced mutations in source tests. A
single admission-policy create also rejects foreign-org clusters even without
group selectors. These do not prove deployed operator reconciliation or every
raw writer.
API image
`sha256:5091072f176c1f0ba46a9fb788f2de1f0b9d0d21b721c8dc73daf73fa10b0022`
was deployed by Helm against migration 166. It returned 409 when deleting a
pre-marker edge whose five enforcing policies were unmarked. A newly created
protect edge yielded six flows and five policies with its `edge_id`; deleting
it returned 204, leaving zero edge and policy rows. A separate forced
second-member baseline failure returned 500 on group create with zero new group
rows and the existing baseline unchanged; retry returned 201 with three
enforcing member baselines. The temporary constraint was removed.
New group-edge expansions now mark learned rules with the owning edge ID.
Deletion atomically removes policies only when all their rules and policy-level
posture still belong to that edge; otherwise it returns 409 with no mutation.
PostgreSQL tests cover tenant isolation, mixed user/federated rules, edited
posture, unmarked legacy rules and rollback after a blocked policy delete.
The deployed check covers fully owned and pre-marker paths, not mixed-policy
deletion. Legacy/mixed policies need an
explicit audited resolution path rather than unsafe automatic cleanup.
Mode/port edits to an already-expanded edge now verify complete policy
ownership, retract old policies, update the edge and re-expand in one transaction.
Mixed/legacy ownership remains a 409/no-write conflict. Fresh migration-166
PostgreSQL race tests cover mode/port replacement, standalone and expanded
upsert, and forced re-expansion failure rollback/retry. Comment-only edits remain
allowed. A deployed edit transition and packet-level effect remain open.
API image
`sha256:71bfacdfd3ab91d1ea59da5b9053dcb51523b41d45f5efdc7e4d0dba7ffc10e4`
verified the former edit guard on a disposable Helm release: mode and port changes
returned 409, comment-only returned 201, the protect/5432 edge remained intact,
and delete returned 204. This predates the atomic edit transition and is not a
packet-level enforcement drill.

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
- [ ] Inventory and remediate legacy DLP/WAF group bindings whose stored org
  differs from their group's org. The read-only preflight and migration 166
  fail closed on a dirty upgrade fixture and validate a repaired fixture;
  actual installations still need inventory, audited repair receipts, and a
  verified post-upgrade constraint before this item closes.
  Main development was inventoried read-only on October 17 at schema 180:
  zero group DPI bindings, zero orphan or wrong-organization rows, and the
  validated `(org_id, group_id)` foreign key to groups. No repair was needed.
  This covers the managed development installation only; other installations
  and the broader binding acceptance remain open. The identity-checked receipt
  is `/tmp/constellation-main-binding-inventory-fed732e/inventory-review.json`.
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

- [ ] Close open fail-open findings in admission, CIS, CSPM, required scanner matchers,
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
  applied, and rolled-back object counts. An eight-object subset has a counted
  manifest, PostgreSQL apply/rollback proof and disposable local API smoke;
  remaining families and the
  complete mixed-family fixture are still open.
- [ ] Add browser coverage for paste/upload, preview, dry-run, apply, history,
  rollback-bundle download, rollback, and post-rollback inspection.
- [ ] Confirm imported DLP/WAF objects are visible from Migration, Policy Center,
  DLP Rules, and WAF/DPI Signatures. A deterministic production-browser fixture
  verifies those four surfaces, imported origin and group scope; a browser run
  against the real migration API and deployed dataplane proof remain open.

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
  OIDC discovery. Saved-provider API/UI probes cover public LDAPS TLS/optional
  bind, local SAML metadata parsing and public HTTPS OIDC discovery with
  scoped authorization, audit and sanitized results. A live API-backed browser
  test verifies saved SAML metadata and cleanup. Private or air-gapped
  LDAP/OIDC endpoints and live SAML connectivity remain open.
- [ ] Add group-resolution and final mapped-role/scope previews.
  Saved LDAP/SAML/OIDC providers now preview final organization, cluster and
  namespace grants for bounded supplied group values without echoing values or
  secrets. Live group extraction/lookup and provider-backed cutover proof remain.
- [ ] Import NeuVector users, roles, mappings, and token metadata without
  privilege escalation; require token reissue.
- [x] Add audited local-user unlock and force-reset actions. The scoped routes
  commit audit receipts with successful mutations, expose lock/reset state in
  Access Control, and have focused source and deterministic browser tests.
- [ ] Complete namespace-scoped row filtering where resources have a namespace.

### API-1 Runbook-compatible contracts

- [ ] Complete OpenAPI request/response schemas for migration, network rules,
  admission assessment, registry sync/cancel, event export, PCAP, support
  bundles, group usage, and DLP/WAF bindings. Migration preview/history/apply/
  rollback/bundle, network-rule, admission-assessment, group-edge, group-usage
  and DLP/WAF binding schemas are typed with focused contract tests. Registry
  sync/cancel, event export, PCAP and support-bundle contracts now have typed
  bounded operations too. Source-dependent NDJSON and bundle sections,
  network-rule YAML export/import bundles and per-rule outcomes are also typed.
  Import validates media type, version/kind and owned cluster; durable audit
  attempts precede writes and the completion receipt commits with successful
  rows. Partial success still returns 200 with per-row errors. A metadata-only
  all-history NDJSON export has snapshot and final-count source tests; full
  endpoint-family review and deployed contract proof remain open.
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
  counts and key UI routes, then rolls back. A loopback-only opt-in runner covers
  an eight-object subset, HTML route availability, 11 mock tests and a disposable
  local API apply/rollback smoke. Full canonical-fixture coverage, a genuine new
  org, browser-rendered UI and deployed proof remain.

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
  and cursor/offset contracts for row-oriented network APIs. Map,
  conversations, sessions and DPI threats now expose applicable filters and
  bounded page metadata with database fixtures; rollup peer-IP matching uses
  stored minimum addresses, named applications do not filter DPI threats, and
  remaining network rows/export contracts need review.
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

- [x] Prove private-registry credentials are scoped per job and removed after use.
  October 12: lease-bound API authorization, isolated engine/cosign configs,
  live signed generic-v2 fixture and success/failure cleanup; cancellation is
  covered in local tests. Provider-specific connector validation remains below.
- [x] Verify scanner Docker credential configs are per-job, mode-restricted and
  removed on success, failure and cancellation in local tests. October 12 adds
  a live generic-v2 registry proof; other connectors remain unqualified.
- [x] Use the job's scoped credentials for private-registry digest, manifest
  and config-history reads. Fake-registry tests cover TLS, wrong credentials,
  platform selection and no credential forwarding to redirects, bearer realms
  or plaintext; live connectors remain open.
- [x] Use the same per-job HTTPS/authority-scoped credentials for file-risk and
  config-check image reads. Fake-registry tests cover authenticated metadata,
  wrong credentials despite an ambient Docker config, mismatched authority,
  plaintext rejection and cross-authority blob redirects. Opt-in one-shot
  scans and signature verification now share this per-job path; the October 12
  live generic-v2 fixture also proves private cosign verification.
- [ ] Complete and validate ECR, GCR/Artifact Registry, ACR, Harbor, GitLab,
  JFrog/Nexus, IBM Cloud, and OpenShift discovery/auth flows that are advertised.
- [ ] Add tag/repository selection policies, refreshable cloud tokens, and
  explicit unsupported-kind errors.
- [x] Return an explicit client error for unsupported registry kinds on create
  and attempted kind changes on PATCH; static tests enumerate all 13 accepted
  kinds. Tag/repository selection and live cloud-token refresh remain open.
- [x] Show scanner database download/apply revision and worker capacity on
  dashboard and health surfaces. October 12 live DOM checks show matching Trivy
  and Grype download/applied revisions and worker slots on the cluster dashboard,
  platform health and scanner page. Component tests cover partial/stale reports,
  missing fields, unavailable data and actual zero capacity.

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

- [x] Use the shared GroupPicker in every editor with a group selector: network,
  admission, response and DLP/WAF bindings. Runtime-policy and file-monitor
  editors select workloads, not groups; a response-rule save-path test passes.
- [ ] Keep referenced-group update/delete conflict detection deny-by-default;
  any future cascade must be explicit and audited. Filtered updates/usage now
  see org-wide blockers. Transactional table locks and PostgreSQL race tests
  protect against in-flight writes in all four reference families. Structured
  admission, response-v2, raw admission policies and the group-edge store now
  validate group selectors atomically; portable import blocks referenced
  changes. Federation sync, migration apply/rollback and learned-group refresh
  now guard sensitive writes, with PostgreSQL race coverage. The live membership
  reconciler now transitions cluster-scoped, edge-only member changes with
  owned-policy retraction, profile-mode propagation and re-expansion in one
  transaction; other reference families and org-wide groups remain blocked.
  The operator writer still refuses referenced member changes, while bulk
  admission-policy writes validate selectors atomically. Complete the raw
  writer inventory, deployed writer-path checks and live network/DPI
  enforcement before closing this item.
- [ ] Complete the now-registered group-edge HTTP workflow: source and deployed
  API smoke prove RBAC, audit attempts/ordinary receipts, scope rejection,
  protect-mode expansion and edge deletion. Runtime-policy expansion is now
  transactional, including a deployed mid-expansion failure/retry check;
  create-with-expand edge/policy rollback is source- and Helm-verified.
  Source tests and deployed API smoke verify deletion of fully edge-owned
  policies and 409/no-write for legacy ownership; define an
  audited resolution for ambiguous rows. Require reliable completion receipts,
  and prove the operator result and actual network dataplane effect before closing.
  Mode/port edits now replace fully owned policies transactionally in source
  tests; deployed edit proof remains open. Group-edge routes honor cluster grants
  in source tests; the broader route-level RBAC inventory remains open.
- [ ] Add an end-to-end group workflow: create, use in network and DLP/WAF,
  inspect usage, promote mode, attempt unsafe delete. Source API tests cover
  persisted configuration; production-browser control-plane proof passes against
  a Helm API. Live network and DPI enforcement proof remains.

### POL-2 Policy Center completion

- [ ] Add per-family hit counts and last-hit/last-changed/enforcement health.
  Policy Center now shows the latest *listed* change for DLP, signatures,
  groups and vulnerability profiles, plus listed network-rule match counts and
  last match. It does not invent missing hit or enforcement data. Other families,
  complete pagination and live health proof remain open.
- [ ] Add reorder controls only where runtime precedence exists, with RBAC and
  audit tests. Policy Center now links only the existing network move-to-top
  and response up/down controls. Network list order, filtered top detection,
  owned-cluster/rule checks, concurrent move serialization, negative priorities
  and durable audit attempts/completions have source tests. Response reorder
  now validates cluster scope and commits its completion receipt with priority
  updates; registered-route tests cover both controls' authorization. Two
  deterministic production-browser cases verify links and view-only sorting/
  move refetch; other writers, live backend browser and deployed enforcement
  proof remain open.
- [ ] Add real family-specific import/export actions; do not link placeholders.
  Policy Center retains five working portable YAML contracts and removes generic
  family Import links/badges that only opened Migration. Frontend tests verify
  both the real controls and absence of misleading links. Other family-specific
  contracts and deployed browser verification remain open.
- [ ] Show unsupported migration objects and their remediation beside the
  relevant policy family. Policy Center now shows reason and suggestion from
  saved NeuVector imports beside mapped families, with unknown/ambiguous kinds
  in a general area. New imports persist validated target-cluster scope and
  history supports explicit bounded keyset pages with Load more; legacy/missing targets
  stay labeled unknown, other-cluster imports remain separately visible, and
  diagnostics are not presented as current enforcement. A metadata-only
  all-history NDJSON snapshot export is now available separately from loaded-row
  CSV, with an explicit completion count. Fixed-snapshot paging across all
  writes, full diagnostic-content export, deployed browser proof and historical
  target backfill remain open.

### POL-3 Admission, DLP, WAF, and response depth

- [ ] Finish long-tail structured admission criteria that remain unsupported and
  add OpenShift controller coverage where applicable.
- [ ] Preserve DLP pattern context and make user-authored WAF rules reach the WAF
  dataplane table rather than degrading silently.
- [ ] Include enforcing DLP/WAF policy in backup/restore and defined federation
  scope.
- [ ] Add response-policy export/import and wire specific event categories for
  non-threat ingest sources. A bounded, versioned YAML export/import now covers
  exact cluster or org-wide response rules with audited atomic mutation, strict
  validation, receiver-name normalization and fail-closed unsupported action
  params. Process anomalies, setuid and FIM emit incident, file-profile
  hits/blocks emit violation, and DPI threat IDs emit DLP/WAF response
  categories with focused tests. Other non-threat sources, full category
  behavior and deployed enforcement remain open.

## P2 — Astronomer-inspired operator experience

Use the Astronomer console as a design reference for hierarchy, density, and
progressive disclosure, while retaining Constellation's security vocabulary.

### UI-1 Page and navigation contract

- [x] One canonical home per feature; aliases redirect instead of rendering a
  duplicate surface. A finite source audit and 24 browser cases cover all 96
  declared redirects plus 49 supported detail/form suffixes. Filters, repeated
  query values, fragments, explicit sibling scope, soft navigation and history
  survive redirects. Organization/cluster Audit and CVE detail remain legitimate
  scoped homes; dedicated new/edit forms are separate workflows. The matrix has
  a source coverage guard so future aliases cannot silently escape qualification.
- [x] Keep Clusters first as the primary workspace, followed by Organization,
  Platform, and Integrations (updated by the October 12 user decision). Sidebar,
  command palette, and Settings hub agree. Clusters remains a direct link;
  secondary scopes use accordions. Navigation fixtures follow this order.
- [x] Resolve remaining duplicate health/settings/token/attestation entry points.
  Generic health resolves to platform health; cluster health remains the distinct
  sensor/registration surface and follows its URL-scoped cluster. Token,
  attestation, access-control, integration and Settings aliases preserve deep
  paths, filters and fragments with production-build browser coverage. `/tokens`
  is the browser alias because `/api` is reserved by the server.
- [x] Every primary page opens with one verdict, no more than five KPIs, and one
  primary table or workspace. The finite 110-source audit and production-browser
  family matrix qualify shared compact verdicts, responsive metric rows and one
  primary workspace. Dedicated forms do not invent KPIs; Settings is a navigation
  directory. Final schema177 deployment is verified above.
- [x] Use URL-linked tabs for peer views, dedicated `/new` and `/:id/edit` form
  pages with Save/Cancel/back navigation, and Advanced disclosure for expert-only
  fields. Browser cases cover scope/history, failed drafts and review conflicts.
  Transient read-only peeks and nested Network inspector tabs are accepted only
  within exact URL-bound selection/workspaces; confirmations have no authoring
  inputs. Editing drawers are absent from the routed authoring workflows.

The finite family matrix combines source layout verification with production
browser workflow evidence: navigation/deep-ui for route breadth; Assets,
Deployments, host-CVE and exact Finding observation cases for entity evidence;
high-volume inventories and secondary Network cases for continuation; groups,
reviewed runtime/peer, response, compliance, integration and vulnerability-profile
cases for dedicated forms and review; migration/connector cases for peer
workspaces; retention/NVD and canonical settings cases for settings forms.
`switchboard-scope.spec.ts` qualifies collapsed guidance and cluster-changing
links. Source audit: `/tmp/console-page-contract-final177.jsonl`; full/final
browser logs are recorded in the final selected-console continuation above.
This closes the selected page contract, not every broader feature's side-effect
or infrastructure acceptance.


| Primary family | Source contract and production-browser evidence |
|---|---|
| Clusters, component/coverage/health and Dashboard | `ClustersLandingPage`, `ComponentsPage`, `CoveragePage`, `SystemHealthPage`, `DashboardPage`; `clusters.spec.ts`, `cluster-scope.spec.ts`, `coverage.spec.ts`, `dashboard-operations-reconciliation.spec.ts`, `dashboard-report-download.spec.ts`. |
| Workloads, nodes, risk and finding/CVE detail | `AssetsPage`, `DeploymentDetailPage`, `NodeDetailPage`, `RiskDetailPage`, `FindingsPage`, `CVEDetailPage`; `assets.spec.ts`, `host-cves-drilldown.spec.ts`, `finding-instances.spec.ts`, `high-volume-page-caps.spec.ts`, `deep-ui.spec.ts`. |
| Image/repository/serverless scans, registry and scanner/connectors | Shared scan inventories, evidence tabs and dedicated source forms; `high-volume-page-caps.spec.ts`, `connector_coverage.spec.ts`, `navigation.spec.ts`. |
| Network, groups, runtime, baseline and file profiles | `NetworkMapPage`, `GroupsPage`, `RuntimePoliciesPage`, `BaselinesPage`, `FileMonitorPage`; `network-secondary-inventories.spec.ts`, `network-saved-views.spec.ts`, `network-rule-inventory.spec.ts`, `groups-workflow.spec.ts`, `reviewed-runtime-peer-preferences.spec.ts`, `baselines.spec.ts`, plus `FileMonitorWorkflows.test.tsx` for reviewed-draft transitions. |
| Policy/admission, DLP/WAF/signatures, response and compliance | Dedicated catalog/rule/profile/exemption/schedule forms and peer workspaces; `policy-precedence.spec.ts`, `migration-dpi-visibility.spec.ts`, `vulnerability-profile-workflow.spec.ts`, `response.spec.ts`, `response-rules-portability.spec.ts`, `compliance_policies.spec.ts`, `compliance_schedules.spec.ts`. |
| Audit/Timeline, access/tokens/auth, settings and system configuration | `AuditPage`, `TimelinePage`, `AccessControlPage`, `ApiTokensPage`, `EffectiveConfigPage`; `audit-timeline-pagination.spec.ts`, `access_control.spec.ts`, `settings-entry-points.spec.ts`, `retention-form.spec.ts`, `nvd-form.spec.ts`, auth-provider cases. |
| Integration, migration, federation/backup and navigation directories | Shared URL workspaces and dedicated receiver/routing/SMTP/restoration forms; `integrations.spec.ts`, `migration-remaining.spec.ts`, `migration-dpi-visibility.spec.ts`, `backup-inventory.spec.ts`, `switchboard-scope.spec.ts`, plus `navigation.spec.ts`/`deep-ui.spec.ts` route breadth. |

These references distinguish source layout breadth from workflow assertions;
heading-only smoke does not by itself prove every form, count or side effect.

### UI-2 Shared enterprise tables

- [x] Apply visible pagination, server filters, column selection, density,
  refresh controls, saved views, and CSV export to remaining high-volume pages.
  The finite inventory matrix covers full matching summaries/exports, stable
  continuation, explicit caps and failed-refresh evidence. Final Backup history
  pages beyond 50 and preserves independent latest-success evidence; browser
  and fresh database cases pass. Page CSV remains distinct from matching CSV.
- [x] Add YAML only where a matching import contract exists. Audited the six
  enterprise-table YAML control families against registered import routes and
  client methods; generated deployment artifacts are outside this table rule.
- [x] Persist operator choices without making saved state hide active filters.
  Browser cases qualify shared density/visibility/layout, keyboard controls,
  reset, stale-column migration and operator-scoped saved URL views. Tenant/user
  changes, reload/history and storage failures preserve truthful scope/drafts.
  Hidden-column sorts stay visible with a Clear sort action.
- [x] Add transient read-only detail peeks where justified for repetitive triage;
  prefer detail pages and keep every add/edit form on its own URL.
  `DeploymentFindingsInventory` observation peeks, Timeline event drawers,
  Scanner job drawers and Network workload/flow inspectors remain read-only;
  off-page or missing selections do not substitute another record. Forms retain scope and
  reviewed revisions through failed writes and Cancel/back.

### UI-3 Platform-component visibility

- [x] Hide known Kubernetes, Constellation, and Astronomer platform namespaces by
  default in container, deployment, and relevant network views.
- [x] Keep collection, detection, policy, and enforcement active while hidden.
- [x] Persist the preference and migrate older `hide_kube_system` saved views.
- [x] Move classification to backend `platform_role` metadata using namespace,
  labels, and installation identity so custom install namespaces work like
  NeuVector's `platform_role=core`. Source API and deterministic browser tests
  cover custom namespaces. A genuine isolated chart installation additionally
  qualifies workload/container discovery, API/CSV roles and browser hide/show.
- [x] Expose the same role in all relevant APIs and exports; UI namespace matching
  remains a compatibility fallback. The finite matrix includes workload/container,
  asset/generic finding, node/deployment evidence, runtime/threat, baseline/file,
  Network map/exposure/session/conversation/stream/PCAP/peer/rule/lifecycle,
  Dashboard workload rows, readable report workloads and finding NDJSON.
  Applicable matching/page CSV agrees with JSON; ambiguity, IP/external and
  foreign identity stay explicitly unknown. Shared exact-role database cases,
  production-browser export/visibility cases and the genuine custom-install
  proof qualify the matrix. Artifact-only/binary exports do not invent workload
  roles. Schema177 report/tuple/NDJSON additions are deployed above.

### UI-4 Dashboard and operational posture

- [x] Reconcile component health, policy modes, threats, vulnerability posture,
  exposed services, admission, scanner DB, and federation counts with their
  source endpoints. The finite dashboard browser matrix covers source units,
  scope, filtering, missing evidence and exact destination cohorts. Four further
  operational cases passed against the schema-174 production frontend: component
  ratios, cluster versus organization scanner capacity, queue counts and DB
  version precedence, federation master/joint/standalone states, configured group
  modes and admission states. Unavailable sources withhold healthy counts and
  recover through Retry. Evidence: `/tmp/dashboard-operations-browser.log`;
  typecheck and lint passed. These checks qualify displayed posture, not broader
  enforcement or infrastructure acceptance.
- [x] Link every tile to the exact filtered source view. Browser tests now cover
  dashboard metric destinations and supported component/network filters.
  Findings filters and server pages now preserve URL state and use matching
  instance totals; CVE rollups retain their filtered total and share the search DSL.
  Deployment search and platform/namespace filters now run before server
  pagination, with matching totals and full filtered CSV. Image and host CVE
  tiles now select the exact Findings target type, including unnamed instances;
  privileged/root/exposure tiles use the exact deployment risk-fact predicate. Network
  pair and exposure drill-downs now preserve exact directed endpoints, source
  windows and visible platform context. The conversation header requests a combined
  deny/block cohort before server pagination. Top-vulnerable deployment links and
  the source/destination matrix now use exact deployment IDs and explicit cohort
  units. Fixable findings share the source predicate. Exact destinations also cover
  24-hour runtime alert verdicts, cross-framework graded compliance, the returned
  organization audit IDs, strongest-policy-mode vulnerability-ID/exposure groups,
  and the 14-day high/critical event chart. Source bounds, effective exemption
  status and distinct-ID units remain explicit. The finite source/destination
  browser matrix now reconciles positive multi-page cohorts, matching exports,
  temporal boundaries, missing/pinned audit records, history and reload. Backend
  and recorded live checks supplement those fixtures. Operational health/source
  reconciliation is qualified in the separate item above.
- [x] Prefer downloadable HTML/CSV/JSON evidence; add PDF only when it materially
  improves a customer workflow. Dashboard prefers exact scoped HTML and validates
  organization/cluster receipts before saving; report schedules default to HTML
  and JSON. Actual immutable artifact metadata preserves PDF-to-HTML fallback;
  legacy metadata remains unknown. Effective exemptions, full retained source
  units, real names/roles and CSV escaping have database/command/browser proof.
  Scheduler command artifact generation is qualified; deployed scheduled
  collection/delivery is not claimed. Final schema177 deployment is verified above.

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

- [x] Reclaim physically bloated, empty legacy event/flow DEFAULT partitions
  after age-based deletion without risking concurrent ingest. The partition
  manager checks attachment and size, verifies emptiness before and under a
  bounded non-waiting exclusive lock, and truncates only an empty child.
  Focused PostgreSQL tests passed twice. On the existing k3s database, exact
  zero-row checks preceded a one-time manual truncate that reclaimed 15 GB;
  the 7-day event and 3-day raw-flow dev retention settings then dropped 34
  expired daily partitions after the Helm rollout. This does not prove
  fleet-wide retention policy or audit-log archival.
- [ ] Bound all remaining durable storage growth without silently deleting
  forensic evidence: export and verify hash-chain continuity before any audit
  archive/prune, define a reviewed retention horizon for network-flow rollups,
  and alert on per-table growth, retention lag, failed partition drops, and
  database/PVC free space. On 2026-09-27 the local database was 6.8 GB, with
  `audit_events` at 1.6 GB, `cve_records` at 1.1 GB, and
  `network_flow_rollups` at 79 MB (oldest bucket in June). The audit archiver
  exists but is disabled on k3s and exports only a rolling window; it neither
  catches up missed history nor prunes after verification. Recent audit growth
  is dominated by runtime alerts and scan completions, not control-plane
  mutations. The [storage lifecycle review](storage-lifecycle-review.md)
  compares the local NeuVector code and proposes a safe split. The active
  scanner uses Syft, Trivy and Grype, not the retired `constellation-vulndb`
  bundle; `cve_records` is fed by KEV/EPSS and optional NVD. The event and
  raw-flow windows are bounded locally but do not close this item. The
  [23-item database lifecycle register](database-lifecycle-backlog.md) tracks
  the concrete fixes and policy decisions, including a confirmed
  cross-partition `ctid` deletion defect that must be fixed urgently.
  October 11 live inspection still finds migration 167, while DB-01/02 source
  fixes are tested in PR #2. The live namespace has no CNPG operator or
  DB-backup CronJob. Package B above owns qualifying
  the existing CNPG chart path, plugin-based WAL/backup/PITR, isolated restore
  and a rollback-capable StatefulSet cutover. CNPG supports plugin backups;
  the legacy native Barman integration is deprecated in the referenced upstream
  documentation. Keep extension/image compatibility and PG major upgrades
  explicit. A single-node dev migration does not prove HA or off-host recovery.
- [ ] Seed large datasets and prove every high-volume page either pages or labels
  its render cap. Audit and Timeline now label their loaded 100-row page ranges,
  distinguish current-page CSV, and clear stale rows on page/scope changes;
  deterministic browser tests cover page two and cluster-scoped requests.
  Shared tables now render 100-row pages and label known server fetch limits;
  grouped findings and network lists are bounded. CSV retains all matching
  loaded rows and labels that scope. Deterministic 250–500-row browser fixtures
  pass. Assets now has a stable `has_more`/offset API, a load-more control,
  loaded-only summary/CSV labels and a two-page live-API test. Network activity
  has bounded server pages and 250–350-row database fixtures. A comprehensive
  API-backed large-dataset run, complete detail previews and backend
  pagination for the other capped families remain open.
- [ ] Add performance budgets for network rollups, findings, audit/timeline, and
  dashboard summaries.
- [ ] Implement durable, bounded per-cluster telemetry delivery and idempotent
  acceptance. October 12 source implements bounded durable event/flow spools,
  producer/sequence replay protection, transaction-bound durable ACKs, batched
  writes and Retry-After handling. Restart/lost-ACK/conflict/late-flow tests pass.
  Remaining lanes are best effort; require a durable response-action outbox,
  producer lifecycle/budgets, fair byte/row quotas and priority/overflow
  visibility. Per-process concurrency caps do not establish fleet fairness. Test WAN
  and API loss, process restart, lost acknowledgement after DB commit, duplicate
  and reordered batches, full spool and one noisy cluster without silently
  losing critical receipts or double-counting flow aggregates. Preserve local
  enforcement under disconnection; verify last-valid policy, freshness and
  restart behavior separately for each enforcement backend.
- [ ] Qualify independent fleet workload and failure boundaries using the
  [proposed architecture](architecture.md#proposed-fleet-topology--qualification-work-not-deployed-behavior).
  Publish one deployment's measured capacity and expansion thresholds before
  assigning groups of clusters to multiple deployments. Require fair worker
  scheduling, bounded connections, scoped rollup ownership/watermarks, explicit
  tenant-hold budgets, and a versioned design for any audit-chain split.
  Regional assignment, history/replay-preserving cluster movement and fleet
  policy/query routing must preserve scope, report stale/partial results, and
  tolerate one deployment's outage. CNPG standbys do not shard writes, and
  existing federation APIs do not prove this isolation. Benchmark skewed active
  clusters with concurrent ingest/read/prune/backup; registration counts alone
  do not establish fleet capacity.
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
| [04 Infrastructure/tooling](https://technology-selection-guide.aws.ablabs.io/04-infra-tooling/) | Makefile, Vite API proxy, multi-stage Dockerfiles, Helm and k3s exist. A golangci-lint v2 config and failing-on-error lint/format, tool installation, runtime pins and shell checks are wired to CI. | Partial: baseline lint findings still block release; repository formatting and ShellCheck now pass locally; no Air development-loop contract has been verified; runtime images contain Debian/package managers and mutable base tags, and deployed toolchain/reproducibility evidence is open. | TSG-4 |
| [05 Observability](https://technology-selection-guide.aws.ablabs.io/05-observability/) | Shared telemetry package, JSON slog, OTLP/HTTP and a separate Prometheus registry exist. | Partial: differs from prescribed zerolog/stderr, OTLP/gRPC and OTel Prometheus exporter; pgx pool has no composite tracer configured; prove propagation, cardinality, shutdown and full local telemetry stack. | TSG-6 |
| [06 Security](https://technology-selection-guide.aws.ablabs.io/06-security/) | jwt/v5, RBAC, audit chain, credential sealing, FIPS-related build paths and release signing exist. Cookie/refresh/reuse controls and blocking per-PR security/secret/dependency gates have been added. | Partial: baseline scan findings, hosted gate enforcement, key rotation metadata/job, threat model and complete deployed identity verification remain open. Source/gate presence does not mean guide compliance. | TSG-3, TSG-4 |
| [07 Testing](https://technology-selection-guide.aws.ablabs.io/07-testing/) | Go/Vitest/Playwright tests, disposable PostgreSQL repeat/race/JUnit gate and production-container browser gate pass locally. Playwright browser auth coverage uses zero PR retries. | Partial: most DB tests lack integration tags and share a DB; no pgtestdb/testcontainers harness found. Seed-dependent skips, CNI/kernel/cloud matrix, hosted CI evidence, and full isolated integration contracts remain open. | TSG-4 |
| [08 Discipline](https://technology-selection-guide.aws.ablabs.io/08-discipline/) | Canonical evidence-driven plan and real DB tests provide a foundation. | Partial: codify ADR/deviation review, root-cause and transport-boundary testing, layer/enum discipline, offline-first acceptance and contributor commands. | TSG-1, TSG-2, TSG-7 |
| [09 Air-gap](https://technology-selection-guide.aws.ablabs.io/09-airgap/) | Scanner DB preload/airgap image support and signed release artifacts exist. | Partial: complete signed offline deployment BOM/loader, local-first OCI resolver, closed-egress first boot and all-feature upgrade/restore proof are not established; release images are deliberately amd64-only versus the guide's dual-architecture requirement. | TSG-7 |
| [10 TypeScript](https://technology-selection-guide.aws.ablabs.io/10-typescript/) | React 19, strict TypeScript, Vite, Tailwind 4, Radix, TanStack Query, lucide, Vitest and Playwright exist. Node is pinned and browser auth/session regressions pass locally. | Partial: TanStack Router owns routing and the shared TanStack Form/Zod layer is used by Data Retention and NVD configuration. The user chose these Astronomer-aligned alternatives to the guide's router/form choices; ADR 0001 records the deviation. No Connect-Web pipeline or root session-loader contract is established. Mutation invalidation, inline field errors and version-review obligations need broader acceptance tests. | TSG-5 |
| [11 Multi-language](https://technology-selection-guide.aws.ablabs.io/11-multi-language/) | Go/TypeScript, native/eBPF runtime code, Python test tooling, shell and Helm coexist. Go/Node/Python CI runtimes are pinned, npm lockfiles are audited, and ShellCheck is a blocking gate. | Partial: language ADRs/ownership, native exceptions, Python type/lint coverage, per-language SBOM/signing and cross-language telemetry remain open. | TSG-1, TSG-4, TSG-7 |

### TSG-1 Requirement inventory and deliberate adoption

- [ ] Expand each chapter into stable, chapter/section-linked control IDs for
  every applicable MUST/MUST NOT and SHOULD/SHOULD NOT; record MAY decisions and
  not-applicable requirements with rationale. The
  [102-family guide inventory](technology-guide-control-matrix.md) pins the
  published source hash and records provisional applicability, but grouped
  clauses need a completeness review before this item closes.
- [ ] For each control record status (`open`, `implemented/unverified`,
  `verified`, `approved-deviation`, or `not-applicable`), repository evidence,
  positive/failure tests, owner, acceptance command and live evidence where
  required. Only `verified` closes a strict-conformance requirement.
- [ ] Record ADRs for existing REST versus Connect, SQL migration strategy,
  logging/transport choices, privileged/native dataplane images, amd64-only
  release support and any other retained departures; deviations need explicit
  approval, rationale, residual risk, compensating controls and a review date.
  The [accepted console-stack ADR](decisions/0001-astronomer-console-stack.md)
  now records the user's Router/Form/REST direction and review date. Other
  departures remain individually open; this is not a blanket waiver.
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
- [x] Run Playwright through production-serving paths with setup-project auth
  state, zero PR retries, configurable base URL and retained failure artifacts;
  wire browser tests and distinct FIPS builds/status checks into CI. A fresh
  164-case local suite attempt hit the intentional 10/minute per-IP login guard
  after 38 cases (24 HTTP 429 failures). A later 173-case attempt using only
  worker-local cookies still hit 429 after test 20. Setup-project auth now
  shares validated state across worker restarts; a 16-case API-backed sample
  had no 429s, and the one asset repeat-workflow failure passed after migration
  167. October 12 adds actual Retry-After timeout budgeting and fixes production
  nginx Assets deep links. A subsequent full run passed 190/191; the remaining
  ambiguous field locator is fixed and the final rebuilt suite passes 193/193.
  The full suite and migration apply/rollback fixture are now the CI default.
  The distinct FIPS build/runtime job passes locally and in hosted CI. Hosted
  [run 38190053858](https://github.com/alphabravo-oss/constellation/actions/runs/38190053858)
  passes both browser and FIPS jobs. Later run 38191094639 exposed an Accept Risk
  filter/click race; the repaired full local suite passes 194/194 with zero
  retries, with updated hosted proof pending. This closes the bounded CI wiring
  item based on the recorded successful run;
  overall CI remains blocked by quality/gosec/history-secret findings, and the
  separate deployed FIPS qualification remains open. Production rate limiting
  remains enabled in browser tests.

### TSG-5 Typed API and frontend conventions — P1/P2

- [ ] Implement the approved Astronomer-aligned REST/OpenAPI contract pipeline;
  generate server/client types and categorical enums from one contract and gate
  request/response compatibility in CI. Record the Connect/protobuf departure
  under TSG-1 without presenting it as strict guide conformance.
- [ ] Standardize bounded opaque pagination, route-level error handling and
  session-aware data loaders while preserving API-1's migration/runbook contracts.
- [ ] Adopt schema-driven TanStack Form validation with inline field errors,
  consistent TanStack query keys/invalidation and deduplicated refresh; migrate
  forms/workspaces incrementally with component and browser tests.
  October 11 user decision: converge on Astronomer's TanStack Form layer with
  schema validation (Zod where appropriate). Record the guide's react-hook-form
  departure in TSG-1; do not introduce a second form library. Data Retention now
  uses the shared Form/Zod layer, as does NVD configuration. Both have component
  and production browser coverage; other editors remain open.
- [ ] Migrate to TanStack Router, verify accessible Radix-based primitives, static
  production builds, API/WebSocket dev proxies, version stamps and Node/tooling
  pins against the guide, with ADRs for deliberate alternatives.
  TanStack Router now owns the entry point and all route consumers. Record this
  guide departure in ADR 0001; complete generated route checks, domain-typed search and
  release-wide session/scope/browser acceptance beyond the focused tests.
  Tailwind v4 and TanStack Table are already wired;
  remaining frontend alignment is compatibility and workflow depth, including
  API-aware enterprise-table behavior. The Tailwind v4 class merger is upgraded.

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

The October 11 packages A–K above make this order concrete without replacing
the acceptance checklist. Begin with DB-01/02 and recoverability; carry the
existing completed slices and their regression evidence forward.

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


### Main deployment of the qualified 314afad candidate

Main development now runs **Helm 83 / schema 180**. API, scanner and runtime-agent
use exact source `314afad`; the API image also contains its qualified CLI.
Migration/frontend remain at `5b82b12`. A fresh CNPG plugin backup completed at
2026-10-17 11:56:36 UTC before the normal Helm upgrade. All three candidate images
were imported and pinned by exact OCI identity, preserving every existing pin.
The reviewed render changes only those three images and the API migration-wait
init image. Normal migration/bootstrap hooks completed; all seven deployments
and the runtime DaemonSet are ready.

Live checks verify all six Go/native/BPF payload hashes, health/readiness 200,
protocol-v2 policy reads, legacy 426, unknown-cluster 404, anonymous 401,
foreign-cluster 403 and duplicate-node 400. The live policy and response queues
are empty; positive enforcement remains the separate strict Flannel fixture.
The original retained PCAP PVC/PV, private 0700:10001:10001 directory, Recreate
strategy and new API leader ownership are preserved. Enforcement remains off,
execution dry-run true and benchmark workers off. Public browser login shows
“Constellation” / “by AlphaBravo”, email/password and no unconfigured SSO option.
Authenticated browser navigation remains unverified without a user session;
preview preload diagnostics and unauthenticated 401 responses are retained.

The initial read-only payload wrapper used `runtime` where the rollout receipt
uses `runtimeAgent`; its KeyError is preserved. The corrected role mapping passes
all payload checks. No workload or acceptance change was needed. The frozen
preparation README describes its earlier unexecuted state; the completed phase
receipts and deployment status supersede it. Evidence binds 135 files:
`/tmp/constellation-rollout-314afad/deployment-evidence-manifest.json`
(SHA256 `c50be2f8a698f1dacadb17bb9811187973c6b032e0696eacafd4a977b732cd29`).

This rollout includes the previously source-only API, OIDC, proxy, backup,
signing, scanner and native report-clock fixes through 314afad. It does not deploy
the separately built standalone backup binary or the later private registry/spool
preparations. Hosted quality 1,495, gosec 156 and historical gitleaks still block the
required gate. Overall acceptance remains 66 checked / 87 open; broader CNI, HA,
disconnected and recovery boundaries remain unchanged.


### Telemetry spool ownership and lifecycle qualification

The disk queue now pins its private directory and checks directory/lock identity.
A lifetime directory-inode flock closes the reviewed in-flight lock-file
replacement race; the existing file flock retains ordinary legacy exclusion.
Close serializes with active operations, and closed or identity-lost queues cannot
resume delivery mutations. Atomic private writes retain directory fsync; state
and batch reads reject symlinks and nonregular files. Existing queue metadata and
batch formats remain compatible. This is advisory exclusion among cooperating
updated queues, not protection from privileged writers or an old process ignoring
the directory lock after lock-file replacement.

Final queue/shared-writer qualification passes 60 repeated race/shuffle executions
without skips. Fresh schema-180 runtime callers pass 66 more, including lost-ack
replay; their evidence precedes only production import grouping, whose exact
import set and remaining bytes are unchanged. Both old-behavior controls fail by
intended assertions: four in-flight ownership failures and six closed/root/state
identity failures. Vet passes; scoped configured lint falls from 15 to zero,
without suppressions or configuration changes. The owned database is absent.
Initial lint findings and two Python-only evidence-packaging errors are preserved.
The reviewed final seal binds three source files and 88 evidence files:
`/tmp/constellation-telemetryspool-7831c59/evidence/FINAL-SEAL.json`
(SHA256 `b57feaf1a093bf957af4e8fb7bde1a432ef937b6a9237fa117b67be4bf50ab20`).
This follow-up is included in the combined qualification and deployed 877a1c2
artifact set recorded below. Fleet delivery and overall release acceptance remain
open.


### Registry V2 response completion qualification

Manifest, digest, tag and token responses now require complete bounded reads and
successful closure before exposing successful data. Manifest/tag limits remain
8 MiB / 4 MiB; token responses gain a 1 MiB bound and single-document parsing.
HEAD closes before returning a digest or issuing GET. The missing-digest GET drain
is bounded and checked. Initial challenge retry, child-token reuse, platform
selection order, metadata overlays and partial-repository behavior are preserved.
Redirect/auth-destination policy and broader cloud-provider acceptance are separate.

The full registry package passes 390 repeated race/shuffle executions with zero
skips. Eight old-code regression functions fail by intended assertions. A final
test-only extraction preserves the exact assertions; its two repeated executions
and vet pass, with production and all other tests unchanged. Configured lint falls
from 19 to 11, removing eight targeted diagnostics and adding none; the remaining
cloud-auth/IBM/test findings stay open. The initial test-complexity warning and
its correction remain in evidence. Root independently verified the 85-file seal:
`/tmp/constellation-registry-v2-a274245/FINAL-MANIFEST.json`
(SHA256 `40f78898ac267f3c225279bad1a5a3ff324b89c3f71d8ebdc3808238c4c56da1`).
This follow-up is included in the combined qualification and deployed 877a1c2
artifact set recorded below. No release gate or provider acceptance is waived by
this bounded correction.


### AWS Lambda package download qualification

Lambda package downloads now publish a private file atomically only after bounded
copy, successful response closure, cancellation checks and pinned-directory
identity checks. Failed reads, response closure, overflow or file finalization
preserve a previous complete package and leave no partial first download. The
response is closed exactly once on success and failure paths. Categorized errors
keep presigned URLs and transport credentials out of job summaries while retaining
errors.Is/As causes. Existing size defaults and accepted HTTP statuses remain;
an unrepresentable overflow-check limit fails before dispatch. Redirect policy,
archive extraction and cloud SDK behavior are unchanged.

The final AWS/shared-writer suite passes 112 repeated race/shuffle test executions
with zero skips. Nine public-path old-code functions fail by intended assertions;
the compatibility shim does not replace the old public downloader. Vet passes,
and scoped configured lint falls from nine to six with no new finding signatures
or suppressions. Response-ownership helper changes and test fixture extractions
were followed by the full scoped suite and fresh negative controls. Original
preparation and all attempt logs are preserved. Root independently checked the
62-file seal and all three imported source hashes:
`/tmp/constellation-lambda-download-a557389/evidence/qualified-manifest.json`
(SHA256 `98e78e3c23c118cdc0f4f061362886588a2dd9b82b35ad8c4f96ccb011e10b08`).

This qualifies atomic visibility, not power-loss directory durability. A detected
postpublication directory change may leave a complete artifact while returning
failure, which prevents catalog/report advancement. Tests use injected transports
and no cloud credentials. This follow-up is included in combined qualification
and deployed 877a1c2, recorded below. Broader serverless acceptance and release
gates remain open.


### Cloud registry credential-cache isolation qualification

Shared cloud tokens now require trusted organization and registry identity plus
the effective credentials and authentication target. The two owned-row handler
paths supply that scope; payload credential fields cannot supply it. Direct or
legacy callers without complete scope still authenticate but bypass shared
caching. GCP binds the private key; static ACR binds its client secret; managed
ACR resolves its current identity token before lookup. ECR captures the actual SDK
credentials and uses the same snapshot for minting. Incomplete explicit ECR
credentials fail before ambient or anonymous fallback; fully ambient mode remains
supported. Length-prefixed hashed keys and 256-entry / 8-MiB bounds limit retained
rotations without exposing raw credentials in cache keys.

The full registry ancestor passes 476 repeated race/shuffle executions. Its five
production files are byte-identical to the final candidate; affected test-fixture
cleanup passes 92 repeated executions. Actual connection Test and SyncOnce paths
pass six repeated executions against fresh schema180, proving valid reuse, wrong
and rotated credential handling, sibling organization/registry isolation, ignored
payload scope spoofing and uncached legacy authentication. The corresponding old
caller control records six failure events: four failing workflow executions and
their parent tests. Six direct old-cache regression functions also fail as intended. Vet passes and
configured registry/handler lint remains 332 with identical diagnostic identities.
No skips, suppressions or configuration exceptions were introduced.

Initial test-fixture lint findings and an insufficient old anonymous-fallback
control that attempted reserved .example DNS are retained. Corrected controls
intercept that path; final caller tests terminate cloud traffic at an owned local
proxy. Root verified all 215 sealed records, eleven imported source hashes, full-
suite production lineage and absence of all four owned caller-test databases.
Evidence: `/tmp/constellation-registry-cache-51abb25/FINAL-MANIFEST.json`
(SHA256 `65578c941d2a92a6a766668c271253ef9152aa94afbb8351a66c71ed0f76351a`).

This source qualification does not establish real cloud-credential acceptance.
Combined qualification and deployment of 877a1c2 are recorded below.
ECR AuthToken currently has no non-test repository caller; its exported capability
and the live list/digest credential checks have distinct reachability. Existing
authentication destinations/redirects and broader provider acceptance are unchanged.
The cloud/IBM error-message correction is qualified in the following section.
This correction is included in the deployed 877a1c2 artifact set.


### Cloud registry error redaction qualification

Cloud authentication, IBM registry requests, and Google/Azure catalog failures now
expose a categorical stage and HTTP status without upstream bodies, URLs or parse
values. Wrapped causes remain available through errors.Is/As. Successful responses,
bounds, response closing and cache behavior are unchanged. Real handler tests cover
connection Test, SyncNow, persisted LastSyncError, owning List/Get, foreign-owner
isolation and walker audit records, including successful control requests.

Qualification passes 572 registry and 16 fresh-schema180 handler executions with
race/shuffle/count2 and no skips. Original-code controls produce 22 intended
assertion failures. Vet passes; configured lint remains 332 with no added or
removed diagnostics. Root verified all 77 sealed records, seven imported sources,
unchanged production lineage and absence of all three disposable databases. The
initial test-only compile failure is preserved; its sole correction renamed a
fixture response variable. Evidence:
`/tmp/constellation-registry-errors-376f4b8/evidence/FINAL-SEAL.json`
(SHA256 `aec15eb17c95fb2d860cd10c0d9e328f4f3be11c3f23ba1a7d5fd0ba6fccd221`).

This prevents new disclosures in those paths; it does not rewrite historical audit
or log data. DockerHub/GHCR, other catalog connectors, generic V2/Nexus/OpenShift,
V2 challenge/manifest/tag errors and ECR SDK errors remain separate review work.
Combined qualification, image verification and deployment of this correction in
877a1c2 are recorded below. No release gate is closed here.


### Combined qualification and hosted checks for 877a1c2

Exact source `877a1c2` combines the telemetry ownership, complete registry V2
response, private Lambda download, cloud credential-cache isolation and cloud/IBM
error-redaction fixes above. A fresh owned PostgreSQL 16 database was migrated to
schema 180 twice and seeded. Sixteen packages pass 5,064 repeated race/shuffle test
executions, with zero failures and four explicit native/Flannel opt-in fixture
skips. Vet passes for all sixteen packages. All five Go1.26.9 linux/amd64 binaries
build successfully; all 2,609 frozen source blobs remain unchanged. The owned
database was removed and independently confirmed absent.

Root verified all 48 qualification records and the five binary hashes and modes.
Evidence: `/tmp/constellation-integrated-next-preparation/evidence/combined-qualification-summary.json`
(SHA256 `a2c4f49f61fadd7e7fb2e478ac6042067928c08bd4dcaaa736c677e34333bd9b`).
The qualification manifest is
`/tmp/constellation-integrated-next-preparation/evidence/qualification-evidence-manifest.json`
(SHA256 `a1d5fba6ca32778432cfec1790d8968d60f5ba2460887c2decfa2cf19bf8733d`).

Three images copy only the new Go payloads over the exact qualified 314afad
parents. Parent layers and runtime configuration are preserved apart from reviewed
version labels. Supported nonroot help checks pass; native DP, BPF and 23 native
library hashes and dependency mappings remain unchanged. All thirteen temporary
verification containers are independently absent. This is a verified thin image
assembly, not a fresh native/BPF pipeline build or a new 877 packet acceptance run.
The strict 24-probe Flannel evidence above remains specific to source 314afad.
Assembly receipt:
`/tmp/constellation-images-877a1c2-preparation/execution/ASSEMBLY-RECEIPT.json`
(SHA256 `12ead4cb43276e797b1569a95784d0a1324acc1239e9ccfdead3a1d8f49bb275`).

Hosted [run 39035438259](https://github.com/alphabravo-oss/constellation/actions/runs/39035438259)
completed for exact source 877a1c2: nine jobs pass and four fail. Frontend passes
2,344 tests and browser acceptance passes 279 cases with no failures, retries
classified as flaky, or skips. Go unit records 3,124 passes and 739 skips;
integration records 8,742 passes and fourteen skips. These hosted totals are
separate from the owned-database qualification above. FIPS and dependency and
vulnerability checks pass. Overall CI remains failed: configured lint is 1,469,
standalone gosec 153, historical gitleaks eleven, and the required gate fails.
Normalized comparison against the prior 314afad run removes 26 lint and three
gosec findings with none added; this is not a claim of zero additions against the
original PR baseline. No gate, suppression or configuration was relaxed. Root
verified the completed reports and sealed thirty evidence files:
`/tmp/security-triage-39035438259/COMPLETED-MANIFEST.json`
(SHA256 `8a0733816c3343de5592bab1d8e322b95b0836691cb769b58cf71b4180242a35`).

The separately prepared CIS and remaining catalog-error corrections are outside
this source and artifact set. Real provider credentials, broader enforcement,
other CNIs, HA, disconnected delivery and remaining recovery acceptance are still
open. Off-host recovery and deliberate real-node failure remain deferred. No
parent acceptance checkbox is closed by this qualification.


### Main deployment of the qualified 877a1c2 candidate

Main development now runs **Helm 84 / schema 180**. API, scanner and runtime-agent
use exact source `877a1c2`, including the five follow-ups above. The API image also
contains the matching CLI. Migration and frontend remain on `5b82b12`; the freshly
built standalone backup binary is not part of this workload update.

The normal Helm upgrade followed a new completed CNPG backup (UID
`aa4a7208-4056-4ed6-9ff9-6c94daaad0d3`, completed `2026-10-17T13:56:05Z`). The server
dry-run and installed manifest differ only in the three role images and matching
API init-container image; hook revision names advance normally. All seven
deployments and the runtime DaemonSet are ready. All thirteen image dependencies
and original pins remain verified, with three new image pins added. Six live
payload hashes match the qualified API, CLI, scanner, runtime, native DP and BPF.
The retained PCAP PVC/PV, private directory mode, Recreate strategy and elected
API lease ownership are preserved. Enforcement remains disabled, monitor mode and
execution dry-run remain enabled, and benchmark workers remain disabled.

Post-upgrade health/readiness return 200. Policy protocol 2 succeeds, the unsafe
legacy protocol returns 426, and an unknown cluster returns 404. Response protocol
2 succeeds; anonymous, foreign-cluster and duplicate-node requests return 401,
403 and 400 respectively. Live policy and response queues remain empty, so these
checks do not establish positive enforcement. The exact owned smoke port-forward
was terminated and its process and listener independently confirmed absent.
Public login recheck confirms “Constellation” / “by AlphaBravo” and no SSO button;
authenticated navigation remains unverified without a valid user session.

Root verified 210 deployment evidence files. Evidence:
`/tmp/constellation-rollout-877a1c2-preparation/deployment-evidence-manifest.json`
(SHA256 `05a0e2ca8471ffbfd4f449c35f201052e4510c914fb2ff5d48fb0cc90932f7f6`).
The prepared inputs, failed bytecode-only seal attempt and subsequent reviewed
seal are retained; no cluster mutation occurred during that failed seal attempt.
No quality/security gate or broader acceptance row is closed by this deployment.


### Continuation evidence (2026-10-18)

The user selected continued isolated checks. Authenticated browser acceptance
remains unverified. Use of the historical admission TLS key outside disposable
test clusters is unknown; local non-matches do not establish external non-use.
Replacement/revocation scope and the public-history decision remain open.
The exact 414887a combined database qualification and completed hosted run are
recorded in `docs/security-testing.md`; neither closes a broader acceptance row.


### Qualified follow-up source and documentation-head CI (2026-10-18)

The notifier/backup/federation eight-file qualification records fifteen new
top-level regressions passing twice and 1,584 full affected-package race/shuffle
passes with zero skips. Adapted notifier/backup controls fail 4/5 expected events;
literal old `fed_join.go` alone fails 16 expected events with two passing database
controls. Detailed classifications, source inventories and the sealed manifest
are recorded in `docs/security-testing.md`. This records the earlier source
qualification checkpoint; the combined 2b29b63 qualification and Helm 86 deployment
supersede its pending status. Notifier shutdown/persistence, unavailable-DB
bookkeeping, federation credential/state atomicity and external acceptance remain
open; runtime-health qualification is recorded separately in
`docs/security-testing.md`.

Completed [CI 39143874523](https://github.com/alphabravo-oss/constellation/actions/runs/39143874523)
on documentation source 8daad55 has nine passing/four failing jobs and unchanged
lint 1,459/gosec 144/history-secret 11 identities against c5428cc. It predates the
eight-file follow-up. The checklist remains **66 checked / 87 open**; no parent
acceptance gate closes.


### Completed combined 2b29b63 continuation (2026-10-18)

The eleven-file follow-up is now built, deployed and smoke-checked as Helm 86 /
schema 180 after its fresh original-UID backup. Combined isolated qualification
passes 2,460 tests with six explicit native opt-in skips and four-package vet.
Four Go binaries, three thin images, thirteen owned image probes and three raw
single-tag archives are verified. Six live payload hashes, all controllers,
storage/lease/privacy/runtime flags, nineteen image pins and expected API smoke
statuses pass; all release probe containers, forwards and observer processes
are absent.

Exact-source hosted run 39148334138 completes with nine passing/four failing
jobs: unit 3,411 passes/745 skips, integration 9,368 passes/14 skips, frontend
2,344 passes and browser 279 cases without failures, flakes or skips. Quality
1,456, gosec 143, historical-secret eleven and the required gate still fail;
no gate or diagnostic is waived. Detailed source, artifact, CI and deployment
receipts are in `docs/security-testing.md`. The checklist remains **66 checked /
87 open**. The new scheduler-delivery and namespace-restoration candidates are
separate, unqualified preparations and are not included in deployed 2b29b63.
