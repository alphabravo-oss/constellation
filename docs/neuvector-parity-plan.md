# Constellation vs NeuVector — Parity Review & Work Plan

Date: 2026-06-22
Status: Current (supersedes the two docs now in `docs/archive/`)
Scope: `constellation/` (the product). `constellation-vulndb/` and `neuvector/` are
reference/dependency repos, touched only where called out.
Method: 8-domain multi-agent code review (22 agents), every P0/P1 finding
independently re-verified against the code. Corrections from that verification
pass are folded in below; see [§7](#7-what-the-verification-pass-changed).

> **Implementation status (2026-06-22):** **Milestone 1 + Tranche 2 implemented and validated**
> on branch `feat/neuvector-parity-sweep`. M1: all P0/P1 done (RT-1 eBPF code-complete, needs a
> `clang` BPF recompile + on-kernel verify). Tranche 2 (capability gaps): RT-3 live cordon, RT-5
> distroless/FIM, CMP-3 multi-distro CIS **done**; RT-4 process-tree and NET-3 Hubble **core done**
> with their deferred halves (agent-side socket/ruid emit; Hubble relay gRPC client) documented.
> Tranche 3 (federation + detection): ENT-2, ENT-3, RT-4-FINISH **done**.
> Tranche 4 (named criteria + quality): ADM-2 (CVE-score + env-secret gates), ADM-3 (typed cosign
> decode), VLN-3 (distroless OS match), CMP-4 (data-driven framework mapping, 7→26 CIS controls),
> NET-4 (persisted policy-learning state) **all done**.
> Gates each run: `go build ./...` ✓, `go vet` ✓, `tsc` ✓, no deps added, all new tests ✓.
> ARC-1 handler god-package split is **complete** (7/7 domains, ~150→82 files).
> See [§8](#8-implementation-log). Remaining NeuVector distance: [§3 P2/P3](#3-prioritized-work-plan)
> — chiefly the cluster/toolchain-blocked RT-1 BPF recompile + Hubble relay client, VulnDB store
> size (sibling repo), federation's other 6 rule types, and a test-isolation cleanup pass.

---

## 1. Executive summary

Constellation is **structurally a NeuVector competitor, not a scanner with a map**.
It has rebuilt NeuVector's component split (controller/enforcer/scanner/manager) on a
**Postgres + HTTP** stack instead of NeuVector's **Consul + Raft KV + gRPC**, and it
**vendors NeuVector's actual `dp` DPI binary** rather than reimplementing it. On
several axes it is genuinely *ahead* (supply-chain attestation, multi-engine vuln
reconciliation, tamper-evident audit, signed scheduled compliance reports).

The gap to NeuVector is **mostly wiring and data quality, not missing systems**. The
recurring failure mode across every domain is the same: **substantial, tested code
that is built but never connected** — a live conversation graph the UI never queries,
Rego/CEL admission engines the webhook never instantiates, a response/quarantine
engine no ingest path calls, SSO group→role mappings the auth handler discards. These
are high-leverage precisely because the hard part is already done.

**The one true correctness bug** (verified P0): the eBPF `file_open` hook emits only a
file *basename*, so the entire live FIM / file-profile detection path can never match
its absolute-path rules. Everything else is P1/P2.

### Verdict by domain

| Domain | Parity | Headline gap |
|---|---|---|
| Vuln scanning + VulnDB | **partial** | `require-vulndb` gates only `/readyz`, not the scan path → silent evidence-only scans; 6.4 GB store vs NeuVector ~100–300 MB |
| Network map / conversation graph / learning | **partial** | Live conversation graph + SSE stream built but UI never consumes them; blind on Cilium eBPF (detected + disclosed) |
| Runtime security | **partial** | **P0:** eBPF emits basename not path → FIM dead; response/quarantine engine never wired to ingest |
| Admission + supply chain | **partial** (ahead on depth) | Rego/CEL engines not instantiated; *(simulation gap was refuted — it exists)* |
| Compliance / evidence | **partial** (ahead on reporting) | No in-cluster kube-bench/docker-bench runner (push-only); host CIS = 11 checks |
| Enterprise governance | **partial** (ahead on audit) | SSO group→role mapping computed then discarded; federation syncs only 2 of ~10 rule types |
| Frontend IA / UX | **at-parity** | 3 orphaned routes; nav defined in 3 drifting lists |
| Core architecture / stability | **improving** | handler god-package now split into 7 domain sub-packages (~150→82 files); inline SQL remains per-domain (phantom contracts already deleted — *ahead* of prior baseline) |

---

## 2. Where Constellation is ahead of NeuVector

Keep these; they are differentiators, not debt. Document them in sales/eval material.

- **Supply-chain depth.** Cosign keyless+key verification, in-toto/SLSA provenance
  gates, attestation predicate/identity/issuer trust policies, VulnDB-bundle
  provenance gates. NeuVector's controller has *zero* SBOM/in-toto/SLSA/attestation
  handling — it stops at an `imageSigned` bool. (`pkg/sigverify`, `pkg/attest/slsa.go`,
  `internal/admissionevidence/evidence.go`)
- **Multi-engine vuln reconciliation.** VulnDB canonical + Trivy/Grype as evidence with
  per-field disagreement tracking and provenance. NeuVector does a single CVEDB lookup.
  (`internal/scanner/aggregator.go:232-333`)
- **Cross-ecosystem name normalization.** Maven `groupId:artifactId`, scoped npm, PEP 503,
  Go module paths — the most common false-negative class. (`internal/scanner/vulndb.go:199-270`)
- **Tamper-evident audit.** sha256 hash-chain + Postgres append-only triggers + `VerifyChain`.
  NeuVector stores audit events in Consul KV with no integrity chain. (`pkg/audit/audit.go`,
  `db/migrations/007`)
- **Signed, scheduled, multi-format compliance reports** (PDF/HTML/JSON/CSV/SARIF, cosign-signed,
  email/S3/webhook delivery) and an **audited, time-bound exemption workflow** (approver, reason,
  expiry, revoke). NeuVector has neither.
- **Broader, finer-grained cross-framework control mapping** (CIS → 17 frameworks incl. NIST/PCI/SOC2,
  with per-control `CoreMappings`). NeuVector also ships regulatory mapping (it tags checks to
  HIPAA/PCI/GDPR/NIST/PCIv4/DISA), so the advantage is **breadth and per-control granularity**, not
  the existence of regulatory mapping. *(Under-populated — see P2 below; note we currently lack a GDPR framework that NeuVector tags.)*
- **Incident-response quarantine deny-list at admission**, which the engine fails closed on a stale
  snapshot. (This is the quarantine deny-list's own behavior; the webhook itself defaults to
  `failurePolicy: Ignore` = fail-open — see admission notes. Do not generalize this to "admission is fail-closed.")
- **DP/DPI data plane** is the vendored NeuVector binary, fully supervised with real IPC decode —
  the strongest part of the parity story.

---

## 3. Prioritized work plan

Ordered by leverage. Effort: S ≈ <1 day, M ≈ days, L ≈ 1–2+ weeks.

### P0 — correctness bug, fix first

**[RT-1] eBPF `file_open` emits basename, not absolute path → live FIM never matches.** `M` — ✅ **DONE (verifier-proven); live-fire needs `lsm=…,bpf` boot param**
*Recompiled `runtime.bpf.o` with clang 21 + libbpf — which exposed a real compile bug in the prior fix (`bpf_d_path` rejected the `const` `f_path` under `-Werror`; would have broken the runtime-agent Docker image build). Fixed with a const cast. On a `CONFIG_BPF_LSM=y` kernel the object compiles, the **verifier accepts `bpf_d_path` on `lsm/file_open`**, and `AttachLSM` succeeds. Live `file_open` events fire only when the kernel is booted with `lsm=…,bpf` (this host's active LSM list lacks `bpf`) — a deployment boot-param, not a code gap.*
The LSM hook reads `q.name` (dentry leaf, e.g. `"shadow"`) but the server matchers
(`matchDefaultFIM`, file-profile `filePathMatches`) require a leading-slash absolute
path, so **every live file event is silently dropped**. Only the static crictl
inventory walk produces real paths. Fix: reconstruct the full path in BPF (`bpf_d_path`
on the file's `f_path`, or walk `d_parent` to the mount root) and emit it.
Evidence: `internal/runtime/ebpf/bpf/runtime.bpf.c:99-117`, `loader_linux.go:254-270`,
`internal/handler/runtime_detections.go:223-244`. NV ref: `neuvector/share/fsmon/monitor.go:33-55`.

### P1 — close the loop on built-but-unwired systems

> **All six P1 items below are ✅ DONE** (implemented, built, tested) on
> `feat/neuvector-parity-sweep`. Details per item retained for the record.

**[VLN-1] `require-vulndb` only gates `/readyz`, not the scan path.** `M` — ✅ **DONE**
A scan whose VulnDB store is missing/corrupt still reports **success** with Trivy/Grype
evidence only and no canonical findings, overwriting a prior good scan. Fix: when
`requireVulnDB` is set and the matcher errors, `reportFailure` the job, or stamp a
`vulndb_degraded=true` flag the control plane refuses to promote.
Evidence: `cmd/constellation-scanner/main.go:71,478-492`, `internal/scanner/aggregator.go:120-167`.

**[NET-1] UI never consumes the conversation graph or SSE flow stream.** `M` — ✅ **DONE**
`GET /network/conversations` (folded service graph with `node_kinds`, the NeuVector
`conver2REST` parity feature) and `/network/flows:stream` are routed and working but
**dead server code** — `NetworkMapPage` only polls `network.map()` every 10 s. Fix:
point the map (or a new conversation view) at `/network/conversations` and subscribe to
the SSE stream. Evidence: `frontend/src/pages/NetworkMapPage.tsx:148-153`,
`internal/server/server.go:421,425`, `internal/handler/network/conversations.go:83`.

**[RT-2] Response/quarantine engine never wired into the ingest path.** `M` — ✅ **DONE**
`pkg/response` (Quarantine/Isolate actions + Runtime bridge) is built and tested but
`response.NewEngine` is called only in tests; high/critical events fan out
**notify-only**. Detection → response is an open loop. Fix: construct the engine in the
API server with a Runtime bridge that writes an auto-origin `quarantine_entries` row
and/or applies the cordon NetworkPolicy, and call it from `EventsIngest.Bulk`.
Evidence: `pkg/response/response.go:233-343`, `internal/handler/events_ingest.go:340-361`.

**[ADM-1] Rego (OPA) and K8s CEL admission engines are never instantiated.** `M` — ✅ **DONE**
Both are complete, unit-tested `Engine` implementations, but the webhook binary only
constructs `PolicyEngine`; policy rows with `engine='opa'`/`'cel'` are **silently never
evaluated** (fail-open). Fix: chain a composite engine in `main.go` that loads those
rows and compiles via `NewRegoEngine`/`NewCELEngine`.
Evidence: `pkg/admission/rego.go:45-65`, `pkg/admission/cel.go:40-78`,
`cmd/constellation-admission/main.go:71`, `policy_reload.go:29`.

**[ENT-1] SSO group→role mapping is computed then discarded.** `M` — ✅ **DONE**
SAML/LDAP/OIDC compute `id.Roles` from IdP group mappings, but `issueLinkedSession`
ignores them and 403s any IdP user not manually pre-provisioned — the entire
`RoleMapping` feature is inert for authorization. Fix: JIT-provision a shadow user from
`id.Roles` on first login and reconcile `role_assignments` each login, behind a per-org
`jit-provisioning` flag. Evidence: `internal/auth/sso.go:24`, `saml.go:142`, `ldap.go:141`,
`internal/handler/auth.go:254-264`. NV ref: `controller/rest/auth.go:901` `lookupShadowUser`.

**[CMP-1] No in-cluster kube-bench/docker-bench runner — CIS ingest is push-only.** `M` — ✅ **DONE**
The parsers exist but nothing executes the upstream benchmark and POSTs results, so CIS
K8s/Docker evidence only appears if an external system pushes it. (The existing
compliance CronJob collects K8s *object* posture, not CIS benchmarks.) Fix: ship a
kube-bench CronJob (or collector subcommand) that runs `--json` and POSTs to
`/compliance/ingest`. Evidence: `pkg/compliance/kubebench.go`, `dockerbench.go`,
`internal/handler/compliance.go:281-295`. NV ref: `agent/bench.go:239-260` `BenchLoop`.

**[ARC-1] `internal/handler` god-package split.** `L` — ✅ **DONE** (7 of 7 domains extracted)
All seven domains now live in sub-packages — `network`, `findings`, `netpolicy`, `policy`,
`scanning`, `runtime`, `compliance` — each importing the parent only for shared seams.
The flat package dropped from ~150 top-level files to **82**; `server.go` wiring stayed
byte-identical throughout; no new dependencies. Shared cross-package helpers were relocated
to parent-retained seam files (`scan_seam.go`, `metadata_seam.go`, `runtime_agent_token_seam.go`,
`runtime_detail_seam.go`, `network_flow_resolve.go`, `vulndbmeta`) rather than promoting
`authctx`/`sqlx` (deferred — would touch 100+ files). **Follow-ups:** the parent still hosts
`scan_evidence`/`image_scan_results`/`image_acceptances` (asset seam coupling) and a few
shared SQL helpers; promoting `authctx`/`sqlx` leaves would let sub-packages drop the
parent import entirely.
*(Phantom sqlc/proto contracts were already deleted — no longer a drift risk, only flatness.)*

### P2 — coverage, robustness, footprint

| ID | Item | Effort |
|---|---|---|
| **VLN-2** | VulnDB store 6.4 GB (slim) vs NeuVector ~100–300 MB. Drop `not_affected`/`withdrawn` ranges at build time, prune scan-facing advisory fields, consider OS-namespace partitioning. *Lives in `constellation-vulndb/pkg/bundledb`, not this repo.* | L |
| **VLN-3** ✅ **DONE** | OS-CVE matching now threads a Syft os-release-derived distro version (`Package.OSReleaseVersion`) as the namespace-version fallback, so distroless/scratch images no longer drop OS CVEs; no derivable version → unchanged. | M |
| **VLN-4** | N+1 bbolt lookups per package×spelling×range on large SBOMs. Cache namespaces on open, memoize advisory/alias/risk fetches per scan. | M |
| **VLN-5** | Running-workload CVE correlation is a per-asset recompute, not a persisted CVE→workload index; "which workloads have CVE-X" is slow at fleet scale. | M |
| **NET-2** | In-memory conversation graph (`pkg/livegraph`) is off-by-default and read by nothing. Either make it the default-on hot path the UI reads, or delete it. | M |
| **NET-3** ✅ **DONE (code); e2e needs Cilium cluster** | Hubble `source='hubble'` ingest + converter + read-path precedence + agent stream seam, **plus the concrete relay gRPC client** (`hubbleRelayClient` dials `observer.GetFlows(Follow:true)`, maps `*flow.Flow`→`hubbleFlow`, wired into the agent). Added `cilium/cilium` dep (verified benign incl. the `cilium/ebpf` bump). Live dial exercisable only on a real Cilium cluster. | L |
| **NET-4** ✅ **DONE** | `Evaluate()` now seeds workload mode/`mode_since` from persisted `network_policy_lifecycle_states` (migration 097 adds `mode_since`, advances only on real transitions), so Monitor→Protect evaluates real time-in-monitor; no-state workloads still default to Discover. | M |
| **RT-3** ✅ **DONE** | Live network-isolation wired: `Isolate` enqueues a deny-all NetworkPolicy via the existing netpolicy-applier seam (running-workload quarantine only; image/admission unaffected). Live `kubectl apply` is the applier's existing cluster-tested path. Forensics snapshot still pending. | L |
| **RT-4** ✅ **DONE** | Cross-batch priv-esc (pid cache + ancestor walk); **reverse-shell** (stdio→socket) and **real-uid escalation** (ruid≠0, euid=0) now detected via agent-side `/proc/<pid>/fd` + `/proc/<pid>/status` emit. Only sudo-group authority + userns offsets remain (documented ceiling). | M |
| **RT-5** ✅ **DONE** | dpkg reader now walks distroless `status.d/`; FIM watch-set adds `/lib` + `/lib64` recursive rules (libc/ld.so/libpthread tamper). | S |
| **ADM-2** ✅ **DONE** | Added CVE-score gate (count of findings with `cvss_base ≥ threshold`) and env-var-secret gate (literal container env scanned for AWS/PEM/token shapes) — matches NeuVector `CriteriaKeyCVEScoreCount`/`CriteriaKeyEnvVarSecrets`; YAML-wired. | M |
| **ADM-3** ✅ **DONE** | `sigverify` now decodes `cosign verify --output json` into a typed struct and trusts if *any* signature's identity+issuer satisfies policy (was first-match regex); malformed → untrusted, no panic. | S |
| **CMP-2** | Host CIS scanner = 11 hardcoded checks. Expand toward full CIS Distro-Independent Linux set or vendor a runner. | L |
| **CMP-3** ✅ **DONE** | Runner selects/passes the kube-bench `--benchmark` id; parser tags results with the report's benchmark version (`cis-eks-1.4.0`, `cis-gke-…`, etc.), `cis-k8s-1.9` fallback preserved. (Friendly framework names in `/compliance/frameworks` still need `AllFrameworks()` entries — noted ceiling.) | L |
| **CMP-4** ✅ **DONE** | CIS-K8s→internal-control mapping is now data-driven from `CoreMappings` (reverse index, collision-guarded); coverage grew 7→26 controls, each expanding into NIST/PCI/SOC2/etc. via the existing path. | M |
| **ENT-2** ✅ **DONE** | Federation applies **policy, group, response_rule, admission_policy** end-to-end (upsert + tombstone + fed-read-only). The remaining 6 NeuVector fed types are an **intentional divergence, not a gap** (see note below) — Constellation federates org-level master-authored config; NeuVector's other fed types map to per-cluster *learned* state that structurally cannot replicate. | L |
| **ENT-3** ✅ **DONE** | Master stamps `last_sync_at` + flips pending→active on each joint poll; `ListMembers` derives active/stale/offline; `DELETE /federation/members/{id}` kicks a joint (status=`kicked`, future polls 403, audited). Active-ping (NeuVector `InstantPingFedJoints`) remains the upgrade path. | M |
| **FE-1** ✅ **DONE** | 3 orphaned routes (`response`, `dlp-sensors`, `runtime-policies` — incl. a 27 KB CRUD UI) reachable only by URL. Wired into the Policy nav group + command palette (`dlp-sensors` confirmed distinct from `runtime-dlp`, so kept). | S |
| **FE-2** | Nav defined in 3 hardcoded lists (cluster nav, org nav, command palette) that drift; Cmd+K covers ~8 of ~24 pages. Extract one route manifest. | M |
| **FE-3** | Shared `LoadingState`/`ErrorState` adopted by ~5 of ~50 pages; rest roll bespoke spinners. | M |
| **ARC-2** | 267 ignored DB `Exec` error returns (`_ =`) on write paths can mask partial-failure data bugs. Audit during D2 extraction. | M |

### P3 — minor / document-and-move-on
Custom RBAC roles are coarser than NeuVector's per-namespace read/write bitmasks
(`pkg/rbac/rbac.go:122`) — document as intentional unless namespace-granular RBAC is a
hard requirement. Conversation-graph fold loses per-class (DLP/WAF/threat) severity
detail vs NeuVector's `recalcConversation` — only matters once the conversation view ships.

---

## 4. Suggested sequencing

1. **Milestone 1 — "detection actually fires" (P0 + the unwired-loop P1s).** ✅ **DONE** (2026-06-22)
   VLN-1, NET-1, RT-2, ADM-1, ENT-1 complete + tested; RT-1 code-complete (BPF recompile pending);
   CMP-1 and FE-1 pulled forward into this batch too. See [§8](#8-implementation-log).
2. **Milestone 2 — "compliance & policy are self-driving."** ARC-1 (handler split) begun;
   CMP-1 already landed in M1.
3. **Milestone 3 — "competes at scale."** VLN-2/5, NET-2/3/4, ENT-2/3, CMP-2/3, the
   remaining runtime depth (RT-3/4).
4. **Continuous.** ARC-1 (handler split) one domain per PR; FE-2/3 hygiene.

**Remaining to truly "finish" Milestone 1:** recompile `runtime.bpf.o` with `clang` and
verify RT-1 on a BPF-LSM kernel (toolchain absent in this env) — the only open item.

---

## 5. Architecture snapshot (what's running)

Live cluster `constellation-system` (all healthy, 7–9 day uptime):
`api`, `frontend`, `discoverer`, `scanner`, `admission`, `operator`,
`network-policy-applier`, `runtime-agent` (DaemonSet), `postgres` (StatefulSet),
`k8s-compliance` (CronJob, every 6 h). Maps cleanly onto NeuVector's
controller/manager/scanner/enforcer + operator.

LOC: NeuVector core (controller+agent+share+dp) ≈ 250 K Go; Constellation ≈ 136 K Go +
33 K TS — comparable surface with less code, partly because the DP/DPI engine is reused.

---

## 6. Per-domain reference

Full file:line evidence for every finding lives in this review's run output. Each
finding above carries its primary citation inline. NeuVector reference anchors:
`controller/cache/learn.go` (`addConnectToGraph`), `controller/graph/graph.go`,
`controller/cache/connect.go` (`UpdateConnections`, `conver2REST`),
`controller/cache/admission.go`, `controller/rest/auth.go` (`lookupShadowUser`),
`share/clus_apis.go` (`CLUSGroup`, `CLUSPolicyRule`, Fed* rule types),
`share/fsmon/monitor.go` (`ImportantFiles`), `share/scan/scan_utils.go`
(`GetRunningPackages`), `agent/probe/process.go`, `agent/bench.go`.

---

## 7. What the verification pass changed

Every P0/P1 was re-checked against the code by an independent adversarial agent. Net changes:

- **REFUTED — "no admission simulation endpoint."** It exists: `POST /policies/simulate`
  (`internal/handler/policies.go:364`) replays the real `PolicyEngine.Evaluate` against a
  synthesized AdmissionReview and returns per-rule hit/mode/reason/evidence, reusing the
  same `DetailedEvidenceSource` path. Dropped to P3 (docs nit). The original reviewer cited
  only the profile-import preview and missed this.
- **Downgraded P1 → P2:** VulnDB store size (read-only mmap, tolerable on a scanner pod; and
  it lives in the sibling `constellation-vulndb` repo); Cilium blindness (detected + disclosed
  in the UI empty-state, not silent wrong data); host-CIS 11-check coverage (acknowledged MVP
  subset, nothing broken); 3 orphaned routes (UX defect, routes still function).
- **Confirmed at stated severity:** RT-1 (P0), VLN-1, NET-1, RT-2, ADM-1, ENT-1, CMP-1,
  ARC-1 and ARC's inline-SQL finding (both P1).
- **Confirmed-ahead:** phantom sqlc/proto contracts were already deleted and request paths
  are panic-safe — better than the prior baseline assumed.

---

## 8. Implementation log

Milestone 1 implemented on branch `feat/neuvector-parity-sweep` (2026-06-22). Each
item built, has a regression test, and was validated; gates re-run independently after
the batch: `go build ./...` ✓, `go vet` ✓, frontend `tsc --noEmit` ✓.

| Item | Status | Key change | Test |
|---|---|---|---|
| **VLN-1** | ✅ | `RequireVulnDB` on `ScanOptions`; aggregator returns an error (retryable) when the canonical vulndb matcher fails and require-vulndb is set, so `executeJob` fails instead of promoting an evidence-only scan. `cmd/constellation-scanner` sets it on all 3 scan paths. | `internal/scanner/aggregator_test.go::TestAggregator_RequireVulnDB_FailsOnVulnDBMatcherError` |
| **RT-2** | ✅ | `EventsIngest.WithResponseEngine`; new `response_runtime.go` loads `response_rules_v2`, runs `response.Engine` per high/critical event, records `origin='auto'` `quarantine_entries`. Live network cordon deliberately deferred to RT-3. | `response_runtime_test.go` (hook dispatch + DB end-to-end auto-quarantine) |
| **ADM-1** | ✅ | `admission.ChainEngine` evaluates PolicyEngine + Rego(`opa`) + CEL(`cel`); policy reload loads/compiles those rows and hot-swaps them; first deny wins. | `pkg/admission/chain_test.go::TestChainEngine_RegoDenyDenies` (with negative control) |
| **ENT-1** | ✅ | JIT provisioning: `id.Roles` threaded into `issueLinkedSession`; auto-provision + per-login role reconcile gated by `orgs.jit_provisioning` (migration `095`, default false → behavior unchanged). | `auth_sso_test.go::TestAuth_SAMLACSJITProvisioning` (disabled→403, enabled→mapped session) |
| **CMP-1** | ✅ | New `cmd/constellation-kube-bench-runner` execs kube-bench `--json` and POSTs to `/compliance/ingest`; opt-in Helm CronJob + Dockerfile + Makefile target. | `main_test.go` (payload shaping + server-error surfacing via httptest) |
| **NET-1** | ✅ | API client `network.conversations()` + `network.streamFlows()` (fetch+ReadableStream SSE, since auth is bearer-only); map page consumes `node_kinds` + live edges, 10 s poll kept as fallback. | `api/network-stream.test.ts` (SSE frame parsing/filtering) |
| **FE-1** | ✅ | 3 orphaned routes wired into Policy nav group + command palette; `dlp-sensors` verified distinct from `runtime-dlp` (different backend/data model) so kept. | `AppShell.nav.test.ts` (nav contains the 3 paths) |
| **RT-1** | 🟡 | BPF source uses `bpf_d_path(&file->f_path, e->path, …)` for absolute paths; Go decode unchanged (buffer stays 256 B). **Blocked:** needs `clang`/`llvm-strip` to rebuild `runtime.bpf.o` + on-kernel BTF/BPF-LSM verification — neither available here. | `ebpf/decode_linux_test.go::TestDecodeRecordFileAbsolutePath` |

### Tranche 2 — capability gaps (2026-06-22)

Same approach (sequential, each built + tested). Gates re-run independently: `go build ./...` ✓,
`go vet` ✓, `tsc` ✓, `go mod tidy` no-change (no deps added). All new tests pass.

| Item | Status | Key change | Test |
|---|---|---|---|
| **RT-5** | ✅ | dpkg reader walks `var/lib/dpkg/status.d/` (distroless); `defaultFIMRules` adds `/lib` + `/lib64` recursive watches. | `packages_test.go::TestReadDpkg_StatusDir`, `runtime_detections_fim_test.go::TestMatchDefaultFIM_SharedLibraries` |
| **CMP-3** | ✅ | Runner passes `--benchmark <id>` + `?benchmark=`; `ParseKubeBench` tags rows from the report's per-control version (`cis-<distro>-<ver>`), `cis-k8s-1.9` fallback; `IngestKubeBenchProfile` honors an explicit override. | `compliance_test.go::TestIngestKubeBench_TagsBenchmarkVersionFromReport` |
| **RT-3** | ✅ | `quarantineRuntime.Isolate` now upserts a `network_policy_lifecycle_states` row (`protect`/`applied`) with a pure deny-all native NetworkPolicy (`RenderDenyAllYAML`) that the existing applier reconciles live; gated to running-workload quarantine only. | `response_runtime_test.go::TestQuarantineRuntime_IsolateEnqueuesDenyAll` |
| **RT-4** | ✅ | Bounded (4096-entry, 5 min TTL) per-(cluster,node) pid→{uid,ppid,comm} cache + 10-deep ancestor walk → cross-batch priv-esc flagged. (Reverse-shell + real-uid completed in Tranche 3 — see below.) | `runtime_proctree_test.go` (cross-batch priv-esc, TTL + size eviction) |
| **NET-3** | 🟡 | Ingest accepts `source='hubble'`; read precedence `dp > hubble > bpf > declared > synthetic`; pure Hubble→`network_flows` converter; runtime-agent stream loop + Cilium/relay-addr gate. Live relay gRPC client deferred (heavy `cilium/cilium` dep, Cilium-cluster e2e). | `hubble_flow_test.go` (converter + gate + loop), `network_flows_ingest_test.go::TestNetworkFlowsIngest_HubbleSource` |

### Tranche 3 — federation + runtime detection (2026-06-22)

Sequential, each built + tested. Gates re-run independently: `go build ./...` ✓, `go vet` ✓,
`tsc` ✓, `go mod tidy` no-change. All new tests pass.

| Item | Status | Key change | Test |
|---|---|---|---|
| **ENT-2** | ✅ | `applyFedRevision` now materializes `response_rule` (→ `response_rule_overrides` cfg_type=fed) and `admission_policy` (→ `policies` cfg_type=fed) with tombstone-delete + read-only guards; migration `096` adds `response_rule_overrides.cfg_type`. | `fed_sync_ent2_test.go::TestFedSync_ENT2_ResponseRuleAndAdmissionPolicy` |
| **ENT-3** | ✅ | Joint poll = heartbeat (`last_sync_at`, pending→active, `WHERE status<>'kicked'`); `DeriveStatus` → active/stale/offline; `federation.Kick` + `DELETE /federation/members/{id}` (audited, future polls 403). | `federation_test.go::TestFederationMemberLifecycle`, `federation_kick_test.go` |
| **RT-4-FINISH** | ✅ | Agent reads `/proc/<pid>/fd` (stdio→socket) + `/proc/<pid>/status` (ruid), emits optional `StdioSocket`/`Ruid` fields; server adds `reverseShell()` + `realUIDEscalation()` classifiers. Backward-compatible (absent → current behavior). | `events_ingest_test.go::TestEventsIngest_ReverseShellAndRealUIDEscalation`, `proc_enrich_test.go` |

### Tranche 4 — named criteria + quality gaps (2026-06-22)

Sequential, each built + tested. Gates re-run independently: `go build ./...` ✓, `go vet` ✓,
`tsc` ✓, `go mod tidy` no-change. All new tests pass.

| Item | Status | Key change | Test |
|---|---|---|---|
| **ADM-2** | ✅ | `EvidenceGate.MaxCVEsAtOrAboveScore`/`MinCVEScore` (counts `detail_json->cvss_base ≥ threshold`) + `RuleConditions.DenyEnvVarSecrets` (literal env scanned for AWS/PEM/GitHub/Slack/Stripe shapes); YAML-wired. | `env_secret_gate_test.go`, `evidence_test.go::TestAdmissionEvidenceCVEScoreGateFromPostgres` |
| **ADM-3** | ✅ | Typed `cosign verify --output json` decode; trusts if *any* signature's identity+issuer matches policy (was first-match regex); malformed → untrusted. | `sigverify_test.go::TestPickTrustedIdentityMultiSigSecondMatches` (+ malformed cases) |
| **VLN-3** | ✅ | `Package.OSReleaseVersion` (Syft doc distro) threaded as OS-namespace version fallback so distroless/scratch images match OS CVEs; no version → unchanged. | `vulndb_test.go::TestPackageQueriesUseOSReleaseVersionFallback` |
| **CMP-4** | ✅ | `internalIDForKBControl` now data-driven from a collision-guarded reverse index of `CoreMappings`; CIS-K8s coverage 7→26 controls, auto-expanding cross-framework. | `compliance_test.go::TestIngestKubeBench_DataDrivenCISMapping` |
| **NET-4** | ✅ | Migration 097 adds `mode_since` (advances only on real transitions); `Evaluate()` seeds workload mode/`mode_since` from persisted lifecycle state so Monitor→Protect uses real time-in-mode. | `network_policies_test.go::TestNetworkPolicies_EvaluatesPersistedMonitorTimeInMode` |

### Tranche 5 — ARC-1 handler split, domain 1 (2026-06-22)

| Item | Status | Key change | Test |
|---|---|---|---|
| **ARC-1 (`handler/findings`)** | 🟡 1 domain | Extracted 12 files (`findings`/`cve*`/`vulndb*`/`sbom`/`vuln_profiles`/`vulnerability_exceptions`/`comments`) into `internal/handler/findings`; parent −3.66 K LOC non-test; new `httpx.WriteRawSBOM` + `vulndbmeta` leaf seams; `server.go`/`leaderelection.go` repointed, routes byte-identical; parent no longer references findings. | `go build ./...` ✓, `go vet` ✓, findings pkg 13/14 (1 = pre-existing stale-DB `TestVulnDBRescan…`, byte-identical helper) |

Verified independently: build/vet green, **all 4 prior tranches' tests still pass** after the
extraction (no entanglement — findings files were untouched by tranches 1–4 by design).

### Tranche 6 — ARC-1 domains 2 & 3 (2026-06-22)

| Item | Status | Key change | Test |
|---|---|---|---|
| **ARC-1 (`handler/netpolicy`)** | 🟡 | `network_policies.go` + `network_flows_ingest.go` → `internal/handler/netpolicy`. Broke two parent→domain edges via parent seams: shared IP/cluster resolver split into `network_flow_resolve.go`; `Deployments` takes the lifecycle read-path via injected `WithNetworkPolicyLookup`. | netpolicy 14/15 (1 = pre-existing `TestNetworkPolicies_ActionPersistsStateAndAudit` overlay) |
| **ARC-1 (`handler/policy`)** | 🟡 | `policies*.go` + `response_rules*.go` → `internal/handler/policy`; `recordFedRevision`/`fed_sync.go` stay in parent with new exported fed seams; parent test cycles rewritten (expectations unchanged). | policy pkg fully green |

Verified independently: `go build ./...`, `go vet`, frontend `tsc` green; all prior-tranche
handler tests still pass; no new failures vs the known pre-existing stale-DB set.

### Tranche 8 — ARC-1 final domains, split complete (2026-06-22)

| Item | Status | Key change |
|---|---|---|
| **ARC-1 (`handler/scanning`)** | ✅ | scanjobs/scan_objects/scan_attestations/scanner_cache/workload_packages/serverless_* → `internal/handler/scanning`; shared scan infra → parent `scan_seam.go`; `scan_evidence`/`image_scan_results`/`image_acceptances` kept in parent (asset seam). |
| **ARC-1 (`handler/compliance`)** | ✅ | compliance/exemptions/schedules/custom_frameworks/host_cis/reports/connector_coverage/coverage → `internal/handler/compliance`; metadata accessors → parent `metadata_seam.go`; scheduler cmd repointed. |
| **ARC-1 (`handler/runtime`)** | ✅ | events_ingest/runtime_*/response_runtime/baseline/file_profiles/quarantine/forensics/proctree/threats/waf_dlp → `internal/handler/runtime`; agent-token auth + deployment-detail DTOs → parent seam files; `NeuVectorThreatName` re-homed to parent. |

**ARC-1 complete: 7/7 domains, parent ~150→82 files.** Build/vet/tsc green, no deps; relocated
tranche tests pass in their new packages. Remaining handler-test failures are the known
test-isolation set (scanjobs lease/409, AutoRollback dup-key, ConnectorCoverage count,
NetworkPolicies overlay) — not regressions.

### Tranche 7 — correctness fixes surfaced by reviewing prior work (2026-06-22)

Auditing the "pre-existing stale-DB" failures I'd been dismissing turned up **real bugs**,
not environment noise:

| Fix | What was wrong | Resolution |
|---|---|---|
| **NOT-NULL test fixtures** | 6 user inserts omitted `users.display_name` (NOT NULL since mig 002) and 2 event inserts omitted `events.node_id` (NOT NULL since mig 005). Masked because these tests skip when no test DB is present (CI default) — hence the "stale DB" misdiagnosis. | Added the missing values; ~6 tests now pass (`baseline`, `file_profiles`, `scan_objects`, `platform_facts`, `deployments`, findings `VulnDBRescan`). |
| **Production bug: deployment detail endpoint** | `deployments.deploymentImages` (reached from the detail GET route) selected `critical_count`/`high_count`/`max_risk_score` from `image_scan_results` — columns **no migration ever defined** — so the query errored at plan time for any deployment with linked images. | Compute the rollups in the LATERAL from `image_scan_findings` (the source of truth). No schema/scanner change. |
| **ARC-1 test-seam regression** | The netpolicy extraction moved the deployment network-policy lifecycle behind an injected `WithNetworkPolicyLookup` seam (wired in `server.go`) but `deployments_test` wasn't updated to inject it — it was producing `nil` (masked by the NOT-NULL failure above it). | Test now injects the lookup seam and verifies surfacing. |

**Still open — test isolation (not product bugs):** ~10 handler tests (`scanjobs` ×5,
`TestAutoRollback…`, `TestConnectorCoverage…`, `host_packages`/`workload_packages`,
`TestNetworkPolicies_ActionPersistsStateAndAudit`) fail against the **shared, accumulating**
`constellation_test` DB: they use fixed natural keys / "claim the pending job" / count
assertions and depend on prior runs' cleanup completing. Leftover rows (partly from this
session's interrupted runs) cause dup-key / lease-409 / count mismatches. Fix is a dedicated
test-isolation pass (truncate-per-test or unique scoping or per-test txn) — a coherent
separate task, not a code defect.

### Tranche 9 — test-isolation + authctx/sqlx leaf promotion + green suite (2026-06-22)

| Item | Status | Key change |
|---|---|---|
| **Test isolation** | ✅ | The 9 shared-DB handler tests made deterministic: scanning suites clear the org's claimable queue before enqueuing; AutoRollback deletes its leftover natural-key row; 3 stale expectations corrected to real product behavior (verified, not bar-lowering). |
| **authctx/sqlx leaf promotion** | ✅ | `Subject`/`WithSubject`/`SubjectFrom` → `internal/handler/authctx`; `ParseClusterIDParam`/`ShiftPlaceholders` → `internal/handler/sqlx` (neither imports parent — no cycle). `handler/network` is now **fully decoupled** from the parent; parent keeps thin delegating aliases to avoid churning unrelated `Subject` refs. |
| **ARC-1 regressions fixed** | ✅ | Two bugs from earlier extraction commits surfaced once the suite went green: scanning's rewritten claim-guards read `sj.inventory_hash` (column is on `scan_targets`, not `scan_jobs`) → fixed to `st.inventory_hash`; `TestWAFGroupsHandlerRemoved` pointed at the moved `waf_dlp.go` → repointed to `runtime/`. |

**The full handler tree + `internal/server` test suite now passes** (`go test -p 1
./internal/handler/... ./internal/server/...` — all 9 packages green). The "~10 pre-existing
stale-DB failures" caveat that shadowed every prior validation is **resolved**.

### Tranche 10 — federation scope decision + netpolicy coverage (2026-06-25)

- **`netpolicy.LifecycleForWorkload` test** ✅ — restored the unit coverage ARC-1 dropped
  (`TestLifecycleForWorkload_ReturnsPersistedMonitorState`, passes under `-count=2`).
- **Federation: federate ZERO additional types** (deliberate, after scoping NeuVector's 6
  remaining `Fed*Type`s against real Constellation stores). This is the governing distinction:
  Constellation federation ships **org-level, master-authored config** that a joint upserts
  into its own rows under `cfg_type='fed'` (read-only). Every remaining NeuVector fed type
  maps to one of three Constellation realities that block that:
  - **Per-(org,cluster,workload) learned/runtime state** — `network_policy_lifecycle_states`,
    `process_baseline_states`, `file_profile_rules`, `runtime_dlp_rules`. `cluster_id`-keyed and
    learned independently per cluster; cannot replicate to a joint with different clusters.
    (FedNetworkRules, FedProcessProfiles, FedFileMonitorProfiles, FedDlpSensorGrp authoritative store.)
  - **Deleted/orphan features** — `waf_groups` CRUD was removed (WS-G G1); `dlp_sensors` has a
    reserved `cfg_type='federal'` slot but is cluster-scoped and dataplane-orphaned. (FedWafSensorGrp.)
  - **Speculative config surface** — `org_settings` is org-level but a free-form JSONB bag with no
    declared federated key subset; federating it wholesale would clobber joint-local config. (FedSystemConfig.)
  Implementing these would mean **inventing product surface**, not closing a gap — so they are
  documented as intentional divergence. Revisit only if a concrete need (e.g. an org-global DLP
  sensor store wired to the dataplane, or a defined federated-settings subset) arises.

### Tranche 11 — toolchain/cluster-blocked items unblocked (2026-06-25)

| Item | Status | Key change |
|---|---|---|
| **RT-1 BPF recompile** | ✅ (verifier-proven) | Installed clang 21 + libbpf, recompiled the object — caught a **real compile bug** in the prior fix (`const f_path` rejected by `bpf_d_path` under `-Werror`; would have broken the runtime-agent image build). Fixed via const cast. Verifier accepts `bpf_d_path` on `lsm/file_open`; `AttachLSM` succeeds. Live events need `lsm=…,bpf` at boot (host LSM list lacks `bpf`). |
| **NET-3 Hubble client** | ✅ (code) | Concrete `hubbleRelayClient` over `observer.GetFlows` + `flow.Flow`→`hubbleFlow` mapping (unit-tested) wired into the agent. Added `cilium/cilium` dep; the incidental `cilium/ebpf` 0.17→0.20 bump is verified benign (BPF load test still passes). Live relay dial needs a Cilium cluster. |

Both items are now **code-complete and validated to the limit of this environment**; the only
remaining gaps are a kernel boot parameter (RT-1 live-fire) and a real Cilium cluster (NET-3
live dial) — neither a code deficiency.

### Known gaps / follow-ups
- **RT-1 live-fire** needs the deployment kernel booted with `lsm=…,bpf` (the BPF object itself
  is now correct and verifier-accepted). **NET-3 live dial** needs a Cilium cluster with the
  Hubble relay reachable at `CONSTELLATION_HUBBLE_RELAY_ADDR`.
- **`netpolicy.LifecycleForWorkload`** moved with the ARC-1 netpolicy extraction but has no
  dedicated unit test yet (the deployments integration test now stubs the seam); add a
  netpolicy-package DB test to restore end-to-end coverage of that computation.
- **ARC-1 continues:** 5 handler domains remain (`netpolicy`, `scanning`, `runtime`,
  `compliance`, `policy`); promoting `authctx`/`sqlx` leaves next removes the parent-import seam.
- **RT-4 / NET-3 deferred halves** need agent-side data emit (per-exec socket-fd + ruid) and the
  Hubble relay gRPC client respectively — both documented in-code with the one-line wiring to finish.
- **RT-3 / CMP-3 / NET-3 live behavior** (deny-all actually applied by the applier, kube-bench exec
  on a managed distro, real Hubble stream) can only be exercised on a running cluster.
- **Migration 095** applies cleanly standalone; the shared dev test DB's goose version table
  is out of sync at `091` (pre-existing, unrelated) — reconcile before a clean `goose up`.
- **Pre-existing `internal/handler` integration-test failures** (scanjobs/users/platform_facts/
  runtime_policies) are stale shared-DB pollution in files this batch did not touch — confirmed
  by reproducing `TestScanJobs_QueueLifecycle` failing independently. Not regressions; worth a
  separate test-isolation cleanup (each test should use a fresh schema/txn).
- **NET-1 / CMP-1 / RT-2** end-to-end behavior (live SSE push, real kube-bench exec, pod
  resolution for cordon) can only be exercised on a running cluster, not this sandbox.
