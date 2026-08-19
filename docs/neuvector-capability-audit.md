# Constellation vs NeuVector — Capability & Security Audit

_Adversarially-verified comparison across 10 security dimensions._
_Date: 2026-06-23_

---

## 1. Executive Summary

**Are we as good as or better than NeuVector in every aspect? No — not yet.**

Constellation is genuinely strong, and in several places architecturally cleaner than NeuVector (Postgres-backed durable state, a readable pure-Go DPI/policy stack, per-verb token-scope RBAC, a cryptographic tamper-evident audit chain, machine-readable OpenAPI, signed offsite backups, broader compliance framework breadth). But it is **not strictly better in every dimension**, and in one dimension — **federation / multi-cluster — it is clearly behind** NeuVector.

The blunt verdict by dimension:

- **Behind / weakest:** Federation & multi-cluster. We have no cross-cluster admin forwarding, a weak static-bearer trust model with no per-joint mTLS, no scan-result federation, no proxy/TLS-skip support, and no fed-rule cleanup on leave. This is the one dimension where NeuVector is materially ahead.
- **Mixed (real, material gaps to close):** Runtime security, admission control, network segmentation, vuln scanning, compliance/CSPM, API surface, authn/authz/RBAC, configuration surface, API security exposure. In each, we have credible advantages **and** confirmed gaps — several of them high severity.

The most urgent theme the user specifically asked about — **configuration surface and API security exposure** — is where our highest-severity, highest-leverage gaps cluster:

- **API security exposure is the single most concerning area.** We have **no brute-force/account-lockout protection**, **no HTTP rate limiting anywhere**, **stateless JWTs that cannot be revoked** (logout is a no-op), the **`authMiddleware` does not re-check `users.disabled`**, and — newly found — **disabled users' Personal Access Tokens keep working forever** because `AuthenticateAPIToken` never filters on `u.disabled` and PATs can be minted with no expiry. That last one is a durable backdoor.
- **Configuration surface is deploy-time-only.** Almost nothing is runtime-mutable (no `/system/config`), policy is not expressible as CRDs (GitOps gap), and auth providers are single-instance and configured at process start.

**Count of HIGH-severity gaps: 17** (across runtime-security, admission-control, network-segmentation, federation, authn/authz, config-surface, and api-security-exposure).

**Top 5 things to fix to move toward "better in every aspect":**

1. **Close the PAT/JWT revocation hole (API security).** Add `AND u.disabled = FALSE` to `AuthenticateAPIToken`, re-check `users.disabled` in `authMiddleware`, add a DB-backed `session_epoch`/token-version so logout/disable/password-change/role-change invalidate live JWTs and PATs (cross-replica consistent), and cap PAT lifetime.
2. **Add brute-force lockout + HTTP rate limiting (API security).** Per-user + per-IP failed-login counter with temporary lockout, `httprate` on `/auth/*`, and a concurrent-session cap. We have **zero** compensating controls today; NeuVector has all three.
3. **Build a runtime-mutable, RBAC-gated `/api/v1/system/config` + DB-backed auth-provider CRUD (config surface).** Today every operational knob (proxy, CA bundle/TLS-verify, syslog/SIEM target, scanner autoscale, IdP config) requires a Deployment edit and pod restart.
4. **Harden federation trust + add cross-cluster forwarding (federation).** Replace the single static `CONSTELLATION_FED_MASTER_TOKEN` with a real join-token handshake + per-joint secret (ideally per-joint mTLS), add a master-side reverse-proxy for single-pane control, and clean up `cfg_type='fed'` rows on leave/demote/kick.
5. **Implement the Kubernetes Pod Security Standards admission engine (admission control).** Our `baseline`/`restricted` profiles are misleadingly named — they enforce ~3-5 of ~15 PSS controls. Add capabilities allowlists, hostPath/hostPort, AppArmor/SELinux/seccomp/procMount/sysctls, `allowPrivilegeEscalation`, runAsRoot — plus PVC/controller-kind validation and identity/RBAC (`saBindRiskyRole`) criteria.

---

## 2. Scorecard

| Dimension | Verdict | High | Med | Low |
|---|---|---:|---:|---:|
| Runtime security | mixed | 1 | 3 | 4 |
| Admission control | mixed | 3 | 4 | 5 |
| Network segmentation | mixed | 1 | 5 | 3 |
| Vuln scanning | mixed | 0 | 4 | 4 |
| Compliance / CSPM | mixed | 0 | 3 | 5 |
| Federation / multi-cluster | **constellation_worse** | 3 | 6 | 5 |
| API surface | mixed | 1 | 4 | 4 |
| Authn / authz / RBAC | mixed | 4 | 3 | 5 |
| Configuration surface | mixed | 2 | 3 | 1 |
| API security exposure | mixed | 4 | 4 | 4 |
| **Totals** | | **19*** | **39** | **40** |

\* Counts include both confirmed and newly-found gaps. The prioritized backlog (§5) de-duplicates the cross-cutting auth/session items that recur across the authn-authz, config-surface, and api-security-exposure dimensions; the unique-issue HIGH count is **17**.

---

## 3. Per-Dimension Findings

### 3.1 Runtime Security — _mixed_

**Our advantages**
- Open-flag-derived write-intent FIM (`isFileWrite` reads `O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND`) with a credential/package-DB/binary/lib watch-set (`defaultFIMRules`).
- exec record already carries `ppid` (from `task->real_parent`), so partial process-tree data exists.
- Server-side suspicious-binary / download-cradle / priv-esc / reverse-shell heuristics (`runtime_detections.go`, `proc_enrich.go`).
- kill-on-exec + fanotify open-deny primitives at parity with NeuVector's ProcessProfile/FileAccessRule on the kill/deny axis.
- Readable pure-Go DPI engine feeding DLP/WAF.

**Confirmed gaps**
- **[HIGH] No automated event-driven response-rule / webhook engine.** Zero hits for ResponseRule/webhook/notifier/slack/alertmanager. NeuVector's `CLUSResponseRule` (Event/Conditions/Actions[]/Webhooks[]) is real; our quarantine is an imperative call with no declarative rule/condition/action/webhook model. _Single most material gap._ → Add a server-side response-rule resource (event + condition + ordered actions [quarantine|suppress-log|webhook|tag]) evaluated against runtime streams, persisted in Postgres, synced to agents via the existing `:sync` pull pattern.
- **[MED] No process-exit/fork tracking in eBPF.** Only `tp/sched/sched_process_exec` + `lsm/file_open`. → Add `sched_process_exit` (and optionally `sched_process_fork`) tracepoints so the agent can build full trees, catch short-lived fork-exec-exit malware, and confirm a baseline-killed PID died.
- **[MED] FIM is open-centric; cannot see delete/rename/chmod/mmap-write/post-open-fd write.** NeuVector uses `FAN_CLOSE_WRITE | FAN_MODIFY` + an inotify path; its filter model supports Regex/Recursive. → Add `FAN_CLOSE_WRITE/FAN_MODIFY` to the mark mask and `FAN_CREATE/FAN_DELETE/FAN_MOVE` on FID-capable kernels; add regex/recursive filters.
- **[MED] Process-baseline matches only basename/comm — no lineage, exe-hash, or zero-drift.** Trivially evaded by renaming a binary to a baselined basename. → Use the existing `ppid` for parent-lineage matching + a zero-drift mode; optionally exe-hash.
- **[LOW] No HA / cross-node policy-state consensus at runtime tier.** Acceptable architectural trade-off. → Harden observability: per-node last-applied-fingerprint/sync-status report; alert on stale agents.

**Newly-found gaps**
- **[MED] NeuVector ships a fanotify-based file-access BLOCKING engine with behavior (monitor|block) + Regex + Recursive filters.** Ours is `FAN_OPEN_PERM`-only with flat prefix paths and one behavior. → Model file-profile rules with behavior + regex + recursive matching.
- **[LOW] No parent→child risk propagation** (NeuVector `riskyChild`/`CheckApp`). We cover the static side but lack propagation because we have no live process tree. → Add once exit/fork eBPF events exist.
- **[LOW] `pkg/runtime/falco` is not wired into the agent.** → Either wire it in or stop counting it as an active control.

**Overclaims to stop making**
- The Go DPI engine is a packet **source** for DLP/WAF, not a redundant parallel L7 path NeuVector "lacks."
- Don't say ppid is missing from the exec event — it's present; the missing piece is the matcher using it plus exit/fork events.
- Don't frame FIM as "open-only, no write detection" — we derive write-intent at open; the real, narrower gap is non-open mutation classes.
- Process-enforcement is parity on the kill/deny **primitive**, not on the **rule model** (NeuVector adds zero-drift, exe-hash, block-behavior, regex/recursive).

---

### 3.2 Admission Control — _mixed_

**Our advantages**
- Pluggable OPA/Rego + CEL for arbitrary expression flexibility.
- Policy-simulation endpoint (dry-run over enabled policies).
- Fail-closed first-deny-wins ChainEngine _within the webhook process_.

**Confirmed gaps**
- **[HIGH] Only Pods are validated.** Controller kinds (Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob/RC) and PVCs are not webhook-validated; non-Pod requests early-return Allowed. NeuVector registers 9 kinds incl. PVC + `storageClassName`. → Register apps/batch controllers + PVCs, extract `spec.template.spec` (reuse `Simulate`'s `collectPodSpec`), add a storageClassName/PVC gate.
- **[HIGH] No Kubernetes-identity / RBAC criteria.** No user/groups regex match, no `saBindRiskyRole` (5 risky roles resolved from the pod's SA RoleBindings). `userInfo` only reaches deny audit + hand-written CEL. → Add structured user/groups matching + a `saBindRiskyRole` built-in profile.
- **[MED] No resource-request/limit criteria** (cpu/memory request & limit). → Add per-container threshold conditions.
- **[MED] No Allow/Exception rule type.** Only "deny"; chain short-circuits on first deny; no whitelist path. → Add an exception/allow category evaluated before deny rules.
- **[MED] Built-in engine lacks hostIPC and mounted-volume matching.** The "block hostIPC" inventory claim is backed only by a compliance check, not the admission engine. → Add HostIPC + mountVolumes/hostPath conditions; correct the inventory.
- **[MED] No global admission state API or decision stats.** No global `defaultAction`, no runtime `failurePolicy` toggle, no admission Prometheus counters. → Add a decision CounterVec + runtime global-mode/defaultAction/failurePolicy switch + stats endpoint.
- **[LOW] No federation / multi-cluster rule promotion** (`/promote`, Fed*AdmCtrl). → Add an org-level shared/federated admission scope.
- **[LOW] Missing image-state criteria** (`baseImage`, `imageNoOS`, `modules`, named-CVE deny). → Add baseImage allow/deny, cveNames, optionally imageNoOS/installed-package.

**Newly-found gaps**
- **[HIGH] BIGGEST MISS: no real Kubernetes Pod Security Standards engine.** Zero of: capabilities allowlists, hostPath, hostPort, AppArmor, SELinux, seccomp, procMount, sysctls, allowPrivilegeEscalation, runAsRoot. Our `baseline`/`restricted` profiles bundle only privileged/hostNetwork/hostPID/readOnlyRootFS/runAsNonRoot (~3-5 of ~15 controls) and are **misleadingly named**. → Implement a real PSS baseline/restricted check and either back the profiles with it or rename them.
- **[MED] No `allowPrivilegeEscalation` criterion.** A priv-esc pod that isn't `privileged: true` passes. → Add `allowPrivilegeEscalation=false` enforcement.
- **[LOW] No general `envVars` key/value matching** (manifest + image env). We only have the boolean `DenyEnvVarSecrets`. → Add envVars contains/regex matching.
- **[LOW] No standalone `imageScanned` (deny unscanned) criterion.** `RequireKnownScanResult` is close but only inside an EvidenceGate. → Confirm/expose it standalone.

**Overclaims to stop making**
- Don't call admission "categorically fail-closed." The default `ValidatingWebhookConfiguration` ships `failurePolicy: Ignore` → fail-**OPEN** if the webhook is unreachable. NeuVector exposes a runtime-configurable failurePolicy.
- `Simulate` runs only over **enabled** policies; NeuVector's assess evaluates **all** rules incl. disabled — ours is slightly less capable.
- OPA/Rego+CEL flexibility is partly a **labor shift**: NeuVector ships PSS/RBAC/resource-limit/customPath criteria out of the box that we'd require customers to hand-author.

---

### 3.3 Network Segmentation — _mixed_

**Our advantages**
- Readable pure-Go DPI with app identification.
- Clean Go-side `EvaluateFlow` allow/deny preview.
- Cilium/native export path.

**Confirmed gaps**
- **[HIGH] No end-to-end FQDN-based network policy.** `dp.PolicyRule.Fqdn` is inert; no resolver, fqdnMap, wildcard handling, and `BuildDPRules` never populates Fqdn. → Implement an FQDN resolver fed by the existing `dpi/dns.go` parser, emit Fqdn-anchored allow rules, push `KindIPFqdnStorageUpdate`, emit real `toFQDNs` egress in the Cilium generator.
- **[MED] Auto-generated policies never carry L7 app whitelists.** `buildAllowRule` emits L4-only and drops `Apps[]`; Cilium L7 is a "future enhancement." → Attach `dp.PolicyApp` keyed by observed L7 app id; emit real Cilium L7 toPorts.
- **[MED] Groups are not usable as policy rule endpoints; non-container group kinds missing.** Only Learned/Ground/Federated kinds; no address/ip_service/external/node. → Add those group kinds + From/To rule targeting; unlocks host-to-workload and node-scoped segmentation.
- **[MED] No CRD-based declarative network policy.** Only the install CRD exists. → Offer a SecurityRule CRD (or accept native/Cilium/Calico CRDs) with a validating webhook.
- **[LOW] No per-rule match observability** (hit counter / last-match timestamp). → Add per-rule counters surfaced via the dp event channel; flag dead rules.

**Newly-found gaps**
- **[MED] No operator-controllable rule priority/ordering.** Order is an artifact of the sort, not an authoring control. → Add a `Priority` field + sort push/eval order by it.
- **[MED] WAF/DLP group-bound L7 inspection is absent/removed.** `/waf/groups` CRUD was removed ("never enforced"); WAF is "learn mode, requires NFQUEUE for GA"; DLP sensors aren't group-policy-bound. → Wire DLP/WAF sensor sets to groups + a real dp consumer, or stop counting WAF/DLP as enforced segmentation.
- **[LOW] No per-rule disable** (enable/disable without delete). → Add a per-rule disabled flag honored by PushPolicy and the evaluator.
- **[LOW] Naive learned-rule consolidation.** Only exact-tuple dedupe; no port-any collapse, app/port merge, or stale pruning → kernel-table bloat. → Add consolidation + pruning.

**Overclaims to stop making**
- The "atomic fragmented 8120-byte policy push" is a **direct port** of NeuVector's identical mechanism (NeuVector also fragments subnet **and** FQDN-IP storage). This is parity at best — move to parity_items.
- The Cilium "toFQDNs DNS proxy" / "native L7 HTTP promotion" are **not** present as enforced controls — only a DNS pinhole; export calls Cilium L7 a "future enhancement."
- NeuVector **does** have a policy simulator (`agent/policy/iprulesimulate.go`); the "not present in NeuVector" framing is wrong.
- NeuVector's Go path **does** carry app IDs into the policy table; ours is a readability edge but NeuVector's L7-to-policy path is actually more complete (it feeds Apps into rules; our auto-gen does not).

---

### 3.4 Vuln Scanning — _mixed_

**Our advantages**
- Standardized SBOM (PURL/CPE) export via Syft.
- Broad registry connector set (ECR/GHCR/DockerHub/ArtifactRegistry/ACR/Quay/Harbor/GitLab/JFrog + generic v2).
- We **do** extract & traverse layer blobs for file-risk (setuid/setgid/world-writable).

**Confirmed gaps**
- **[MED] No reachability/call-graph confirmation for Go binaries.** `Reachable *bool` is a permanently-unfilled placeholder; zero `govulncheck` hits. → Implement an opt-in govulncheck binary-mode pass (30s cap) to set `Reachable` and deprioritize unreachable Go matches. The data model already has the field.
- **[MED] No per-layer vuln attribution / Dockerfile-instruction-per-layer.** `ImageLayer` has no Cmds/CreatedBy/history or per-layer Vuls. → Capture OCI config history into `ImageLayer` and join `PackageLocation.LayerDigest` into per-layer rollups (manifest+config JSON, no blob extraction needed).
- **[LOW] Base-image vs app-layer attribution is heuristic; `InBaseImage` left nil with no layer evidence.** → Propagate attribution along layer ancestry or offer opt-in deep mode. (Note: NeuVector's `InBase` mechanism is a closed-source protobuf field — do not overstate it as proven FS-diff.)
- **[LOW] Missing IBM Cloud + OpenShift integrated-registry connectors.** → Add them.
- **[LOW] CIS/image-hardening compliance not joined into the image ScanResult.** → Surface Trivy config-scanner image-hardening checks as a section inside ScanResult.

**Newly-found gaps**
- **[MED] No AWS Lambda / serverless function package scanning.** The `serverless` target does no zip/function extraction — it only consumes pre-collected runtime-agent evidence. → Add a serverless artifact scanner (download + unzip + Syft) independent of a deployed agent.
- **[MED] Registry image selection has no repo/tag filtering or schedule modes.** Only a global `WALKER_INTERVAL`. → Add per-registry repo/tag filter patterns + schedule modes (manual/auto/periodic).
- **[LOW] No user-configurable custom secret-detection patterns.** Fixed to Trivy built-ins. → Expose a custom secret-pattern config.

**Overclaims to stop making**
- Don't claim NeuVector sets `InBase` via "extracted layer FS diffs" — that computation is not in the open-source tree (proprietary scanner).
- Don't say we "deliberately never extract blobs" — `file_risk.go` opens and walks every layer; we just don't reuse that for per-layer vuln/InBase. The per-layer and base-image gaps are closer to closeable than the "no blob extraction" framing implies.
- The SBOM advantage is **narrow** (standardized export format, not detection breadth); Go reachability (govulncheck) actually favors NeuVector.
- "Multi-target scanning beyond images" is partly aspirational — host/workload/platform/serverless/repository all route to the same evidence-based path and require pre-collected agent evidence.

---

### 3.5 Compliance / CSPM — _mixed_

**Our advantages**
- 16 frameworks with per-control `CoreMappings` — genuinely broader and finer-grained than NeuVector.
- Server-side kube-bench parsing; durable, queryable evidence.
- Image-derived compliance evidence (`container.image-secrets-absent`, `container.image-file-risks-absent`) mapped to framework controls.

**Confirmed gaps**
- **[MED] No on-demand per-asset benchmark execution.** Our runner is a one-shot CronJob exec→read→POST; `RunNow` only nudges a REPORT schedule's `next_run_at`. NeuVector triggers `RunDockerBench/RunKubernetesBench` against a named host immediately. → Add a host/cluster-targeted trigger API + a control-plane signal the runner watches.
- **[MED] Custom checks cannot carry user-defined executable logic.** Ours only reference pre-existing `CoreMappings` IDs; no script/rego/CEL path. → Allow user-supplied evaluation logic (exec on collector, or rego/CEL/OPA over collected K8s objects).
- **[LOW] No live compliance-event stream filtered by domain/namespace effective tags.** Namespace filtering is collection-time only. → Add domain/namespace effective-tag filtering if a live stream is exposed.
- **[LOW] No dedicated 'image' compliance evidence scope / registry-image CIS-Docker benchmark.** (Downgraded — image evidence IS produced via `kind+'/image'`.) → Add an explicit image scope + registry-image CIS benchmark, or document current coverage. **Do not claim image compliance is entirely absent.**

**Newly-found gaps**
- **[MED] NeuVector DOES have regulatory mapping** (HIPAA/PCI/GDPR/NIST/PCIv4/DISA per-check tags). Our breadth is richer but the "benchmark-only / no regulatory mapping" framing is wrong. → Reframe the advantage as "broader framework coverage and finer per-control mapping."
- **[LOW] GDPR coverage gap.** We have 16 frameworks but **no GDPR** framework; NeuVector tags checks to GDPR. → Add a GDPR framework / GDPR control mappings.
- **[LOW] No unified cross-asset compliance rollup** (NeuVector's per-check "failing on these N nodes + M workloads + K images"). → Consider a compliance-asset rollup API.
- **[LOW] No runtime container-filesystem secret/setuid evidence.** Ours is image-scan-time, not live in-container FS walks. → Document the difference; add a runtime check if customers need post-deploy detection.

**Overclaims to stop making**
- The old "Gap 4" (setuid/secret detection has "no compliance linkage") is **factually wrong** — that evidence IS emitted and mapped (NIST 800-190 4.2.4, NIST 800-53 CM-7, PCI-DSS 2.2.5, SOC2 CC6.8, FedRAMP, CSA CCM). Remove it.
- "NeuVector has no regulatory mapping" is inaccurate.
- "No image entries in compliance evidence scopes" is true only at the scope-constant level; image-derived evidence IS produced.

---

### 3.6 Federation / Multi-Cluster — _constellation_worse_

**This is the dimension where we are clearly behind.**

**Our advantages**
- Durable, queryable Postgres-backed fed state with a monotonic revision log.
- Idempotent `ON CONFLICT` upserts + tombstones.
- Leader-election-gated singleton sync loop (prevents duplicate polling in HA).
- Org-wide fleet-risk rollup over locally-registered clusters.

**Confirmed gaps**
- **[HIGH] No cross-cluster admin forwarding / reverse-proxy.** No forward routes — only `/federation/{state,members,sync}` + local `cross-scan`. No single-pane operator control of joints. → Add a master-side reverse-proxy (`ANY /api/v1/federation/clusters/{id}/*`) that resolves the endpoint, attaches a per-cluster fed token, forwards, and enforces a read-only allowlist for non-admins.
- **[HIGH] Weak federation trust model.** `/federation/sync` is guarded by an ordinary `VerbReadFindings` JWT (any read-findings principal can pull the entire fed rule log); the joint authenticates with a single static `CONSTELLATION_FED_MASTER_TOKEN`. No join-token issuance, TTL, per-cluster secret, or version handshake. → Add a fed handshake: master mints a short-lived signed join token, joint exchanges it for a per-cluster secret, scope `/sync` to a fed-only credential, validate a per-joint signed ticket on every poll.
- **[MED] No scan-data / registry-result federation.** Joints can't reuse master scan results by digest. → Add a fed scan-result channel keyed on `image_digest`.
- **[MED] No proxy or TLS-skip support for cluster-to-cluster comms.** Bare `http.Client` with default TLS, no proxy. → Honor `HTTPS_PROXY/HTTP_PROXY/NO_PROXY` + add `CONSTELLATION_FED_MASTER_CA`/skip-verify.
- **[MED] Liveness is one-directional (joint→master poll only).** Status derived purely from `last_sync_at` age. → Add a master-side reconcile that GETs each joint `/health`.
- **[MED] Narrower rule replication scope.** Only policy/group/admission/response_rule. NeuVector replicates DLP/WAF/file-monitor/process-profiles/network/system-config too. → Extend the kind enum + `applyFedRevision`.
- **[MED] No federated-rule cleanup on leave/demote/kick.** Stale read-only `cfg_type='fed'` rows remain and can't be edited. → DELETE `WHERE cfg_type='fed'` on Leave/Demote/kicked-403 and reset fed_sync_state.
- **[LOW] No full-vs-incremental polling toggle or master push.** Single fixed timer. → Add a master→joint notify + force-resync (`since=0`).
- **[LOW] No CSP / cloud usage detection or version-compat coordination.** → Add joint→master CSP report + `fed_kv_version` compatibility check at join.

**Newly-found gaps**
- **[HIGH] No per-joint mTLS channel.** NeuVector issues a CA cert + per-joint client cert/key at join. We have no cluster-identity certificates at all — fed traffic is a plain bearer over an unpinned TLS connection, so a leaked token alone impersonates a joint. → Issue a per-joint client cert (or at minimum pin the master CA) at join.
- **[MED] No remote diagnostic/console forwarding** (pcap, sniffer, file export/import, config push). → If single-pane ops is a goal, pass through export/diagnostic endpoints with header preservation, fed-admin gated.
- **[LOW] No compression on fed transfers; hard `LIMIT 500` per `/sync`.** → Add gzip negotiation; verify drain behavior across polls.
- **[LOW] No fixed-join-token / configmap bootstrap for GitOps join.** → Support a pre-shared fixed join token.
- **[LOW] No duplicate-cluster-name guard or same-K8s-UID rejoin handling.** `AddMember` upserts with no name-uniqueness check. → Enforce unique names + detect rejoin by stable cluster identity.

**Overclaims to stop making**
- The "pg_trgm fuzzy search" claim is wrong — it's plain substring `ILIKE` (unindexed → seq scan), and it does **not** federate search across joints the way NeuVector's forward path does for `/v1/vulasset`/`/v1/assetvul`.
- "Crash-safe revision history NeuVector does not have" is wrong — NeuVector persists `CLUSFedRulesRevision`/`CLUSFedScanRevisions` in its replicated KV.
- Our single global per-org revision counter is **coarser** than NeuVector's per-rule-type revision maps (any change bumps the whole-org head → all joints re-evaluate).
- Per-name upsert + tombstones can **leak** fed rows if a tombstone is missed; NeuVector's full replace cannot — and we never clean fed rows on leave/kick.
- The leader-gated sync loop is **parity**, not a differentiator (NeuVector runs its poller on the lead controller).
- The fleet-risk rollup is **single-DB**, not cross-federation.

---

### 3.7 API Surface — _mixed_

**Our advantages**
- A machine-readable OpenAPI 3.1.0 spec exists (NeuVector ships none).
- Per-token RBAC verb binding (`HasTokenScope(verb)` intersects token scopes with role verbs) — a genuine advantage.
- Comprehensive signed backup/restore.

**Confirmed gaps**
- **[HIGH] OpenAPI spec covers ~103 of ~242-284 distinct paths (~60% undocumented).** The completeness CI gate is an unimplemented "Phase 2" deliverable; the 14KB hand-curated spec will drift. → Generate the spec mechanically from the chi router and implement the openapi-diff gate. Until then, drop any "documents all public routes" claim.
- **[MED] No generic uniform query framework** for filtering/sorting across list endpoints. ORDER BY is hardcoded per handler; no client-controllable sort/filter. → Add a shared list-query helper (limit/offset/cursor + typed filter operators + multi-column sort).
- **[MED] No `scope=local|fed|all` query parameter** on read endpoints. → Introduce a scope param/header for federation-merged views.
- **[MED] No granular per-domain config import/export with overwrite/merge semantics.** Only scattered single-domain imports with no merge/replace flag. → Add per-domain export/import with an explicit merge-vs-replace flag (GitOps / config promotion).
- **[LOW] No API versioning strategy.** Only `/api/v1`; any breaking shape change has no migration path. → Establish `/api/v2` or header-based versioning before GA.
- **[LOW] Missing password-policy and EULA/license-acceptance endpoints.** → Add if local Argon2id auth is production-supported.

**Newly-found gaps**
- **[MED] No runtime REST CRUD for auth servers / IdPs.** Providers are wired statically at process start; `RoleMapping` is config/Helm-supplied, not REST-editable. This makes the "auth modes at parity" claim **overstated**. → Add a REST resource for managing LDAP/SAML/OIDC servers + group→role mappings at runtime.
- **[LOW] No namespace/domain-level configuration resource** (NeuVector `/v1/domain`). → Add per-namespace policy-mode/tagging if multi-tenant granularity is a goal.
- **[LOW] No admission-rule 'assess' endpoint and no security-posture scoring endpoint.** → Consider both to match NeuVector's pre-apply validation + scoring.

**Overclaims to stop making**
- "Larger documented REST surface … vs NeuVector's ~340" — the raw counts are essentially equal, and "documented" is misleading given the ~60% spec gap (NeuVector documents scope/behavior inline on ~all routes).
- "Authentication modes at parity" is overstated — NeuVector offers runtime multi-IdP CRUD + per-group role/domain mapping we lack.
- The OpenAPI advantage is oversold (partial, hand-curated, drift-prone, unimplemented CI gate).
- "Comprehensive backup/restore NeuVector lacks" ignores that NeuVector's per-domain export/import is more GitOps-friendly than our all-or-nothing snapshot.

---

### 3.8 Authn / Authz / RBAC — _mixed_

**Our advantages**
- Per-verb token-scope intersection (true least-privilege for **user-attached** PATs).
- Role assignments are re-queried from the DB on every request — so **role-stripping takes effect immediately** mid-session.
- PKCE on the OIDC flow; RS256/ES256 verification of the IdP ID-token.

**Confirmed gaps**
- **[HIGH] No password policy** (complexity, expiration, history). Login accepts any non-empty password. → Add a per-org `password_profile` + `ValidatePassword` on create/change; store recent Argon2id hashes for reuse checks.
- **[HIGH] No failed-login lockout / brute-force throttling, and no rate-limiting middleware anywhere.** → Add `failed_login_count` + `block_login_since` columns, reject while blocked, configurable threshold/window; optionally IP-based rate limiting.
- **[HIGH] Stateless JWT cannot be revoked; native JWT middleware does NOT re-check `users.disabled`; logout is a no-op.** (Role-stripping **does** take effect — only the disabled flag isn't re-checked.) → Re-check `users.disabled` in the JWT middleware; add a token-version / not-before epoch so disabling invalidates outstanding JWTs.
- **[MED] Auth providers wired once at startup; no runtime CRUD, no `AuthOrder`, singletons.** → Add an `auth_servers` table + admin CRUD + hot-reload + `auth_order`.
- **[MED] No forced password reset on first login / bootstrap-credential rotation.** → Add `users.must_change_password`; block non-password-change requests until cleared.
- **[LOW] Coarser read authorization granularity.** `VerbReadFindings` is one broad read verb (can't grant read of one surface while denying another). NeuVector has per-category read/write bits. → Split into per-category read verbs if needed.
- **[LOW] No multi-cluster federation token model** (out of single-cluster scope). → Design early if multi-cluster lands.
- **[LOW] No Rancher SSO** (R_SESS, domain-scoped grants, ExtraPermits overlay). → Add an R_SESS validator if Rancher is a target.

**Newly-found gaps**
- **[HIGH] API-token (PAT) auth ALSO bypasses the disabled flag — and it's worse than the JWT case.** `AuthenticateAPIToken` checks only `revoked_at`/`expires_at`/`status='active'`, never `u.disabled`; nothing cascades to revoke a disabled user's PATs/role_assignments; PATs can be minted with `expires_at = never`. A disabled user's PAT is a **durable backdoor**. → Add `AND u.disabled = FALSE` to the query and cascade-revoke a user's PATs + role_assignments on disable/delete.
- **[MED] No idle/inactivity session timeout and no per-user configurable session timeout.** Only a fixed 1h absolute TTL. → Add a configurable idle window (refresh-token or stateful short-lived session) with per-org/per-user timeout.
- **[LOW] Service-account-attached PATs are minted a synthetic GlobalAdmin assignment.** The token's scopes are the only ceiling — a single-layer defense weaker than the user-PAT case. → Bind service accounts to an explicit least-privilege role row.
- **[LOW] OIDC has no nonce** (only PKCE + state). Parity with NeuVector, but undercuts the "modern hardened flow" framing. → Add nonce binding.

**Overclaims to stop making**
- "JWT key rotation is an advantage over NeuVector's single RSA key" — NeuVector **also** supports rotation (newcert + oldcert). Worse, we sign with **HS256 (symmetric)** so every verifier holds the signing key; NeuVector uses **RSA (asymmetric)** — operationally stronger. This is parity-or-behind, not an advantage.
- "OIDC modern hardened flow" — overstated; it omits the OIDC-spec nonce.
- Don't say "role-stripped user keeps full access" — roles are DB-resolved per request, so that's already immediate.
- "Token-scope intersection always below the minting principal's real grants" doesn't hold for **service** PATs (synthetic GlobalAdmin envelope).

---

### 3.9 Configuration Surface — _mixed_

**(User-flagged area — read closely.)**

**Our advantages**
- Helm/IaC-friendly install; native HPA for scanner autoscale.
- Signed, redacted, offsite (S3) backup.
- Richer ITSM/ChatOps connector breadth (Jira/ServiceNow/PagerDuty).

**Confirmed gaps**
- **[HIGH] No runtime-mutable system configuration.** Auth/DB/observability/intervals are read once from env at process start; changing them requires editing the Deployment and restarting. The only runtime-mutable config is a free-form JSONB `org_settings` blob not wired to operational knobs. NeuVector exposes ~40 live-tunable fields via PATCH `/v1/system/config` (syslog, webhooks, registry proxies, XFF, scanner autoscale, internal subnets, CA certs, TLS-verify toggle, policy modes, atmo auto-transitions). → Introduce a typed, RBAC-gated `/api/v1/system/config` (GET/PATCH) persisted in Postgres + hot-reloaded (LISTEN/NOTIFY): start with registry/scanner egress proxy, global CA bundle/TLS-verify, syslog/SIEM target, scanner autoscale bounds. Env vars become bootstrap defaults the DB overrides.
- **[HIGH] Policy/rules are not expressible as Kubernetes CRDs.** We ship exactly one CRD (`ConstellationCluster`) that only deploys an agent; all security policy lives in Postgres, managed solely via REST. NeuVector exposes a 10-member CRD family (NvSecurityRule, NvClusterSecurityRule, NvGroupDefinition, NvAdmissionControlSecurityRule, NvResponseRuleSecurityRule, NvConfigSecurityRule, NvDlpSecurityRule, NvWafSecurityRule, NvVulnerabilityProfile, NvComplianceProfile) — all kubectl/GitOps-manageable. → Add a declarative policy CRD layer reconciled by `constellation-operator` into DB rows; at minimum provide a documented export of DB policies into kubectl-applyable manifests.
- **[MED] Config-as-code export/import and GitOps push are weaker.** Our backup omits `org_settings`, `users`, roles/custom_roles, `registries`, and `api_tokens`, and there's no YAML config export or push-to-git. → Add those tables to backup (secrets redacted), a YAML config-export/import endpoint, and an optional push-backup-to-git job.
- **[MED] External auth providers are single-instance and deploy-time-only.** No `auth_servers` table or runtime CRUD. → Move auth-provider config into DB records with runtime CRUD + `auth_order`.
- **[LOW] No runtime local-user management or password policy.** → Add user-management endpoints + a configurable password policy, or document SSO-only + break-glass.

**Newly-found gaps**
- **[HIGH] NeuVector has a declarative ConfigMap-driven init layer we entirely missed** (`LoadInitCfg` consumes `/etc/config/{ldap,saml,oidc,sys,role,passwordprofile,user,fed}initcfg.yaml` with per-handler `AlwaysReload`). So NeuVector is config-able **three ways** (ConfigMap YAML / runtime PATCH / CRDs) and **is** GitOps-friendly. We have only env/Helm at boot + a narrow JSONB bag. → Acknowledge NeuVector's ConfigMap init layer; pair our recommended DB-backed config/auth tables with an operator that reconciles them from CRDs or mounted config.
- **[MED] NeuVector exposes network/microsegmentation runtime knobs we lack entirely** (`configured_internal_subnets`, `net_service_policy_mode`/`disable_net_policy`/`detect_unmanaged_wl`/`strict_group_mode`, adaptive-mode D2M/M2P timers). → Add equivalent tunables to the proposed DB-backed system config if segmentation parity is a goal.
- **[LOW] NeuVector has runtime CRUD for individual named webhook targets + a Teams connector.** The delta is connector breadth, not webhook management maturity. → Correct the comparison; keep our ITSM/ChatOps breadth advantage.

**Overclaims to stop making**
- "NeuVector has NO Helm chart and configures imperatively via ~35 CLI flags" is overstated — NeuVector's actual deployment config is declarative (ConfigMaps + CRDs); absence of the chart from this repo clone is not evidence of imperative-only config.
- "runtime-agent alone exposes 50+ env vars" is inflated (~27-31).
- "Scanner HPA superior to NeuVector's autoscaler" is debatable — NeuVector's `scanner_autoscale` is **runtime-mutable** via PATCH; ours needs a redeploy.
- "Signed redacted backup is comparable+ to NeuVector's config export" overstates — ours omits users/roles/registries/org_settings/api_tokens, so it's **narrower**, not a superset.

---

### 3.10 API Security Exposure — _mixed_

**(User-flagged area — this is our most concerning dimension.)**

**Our advantages**
- A cryptographic, tamper-evident hash-chained audit log (`pkg/audit` `VerifyChain`) — NeuVector's `CLUSEventLog` has no tamper detection. **Verified, real advantage.**
- PKCE on OIDC (NeuVector's controller OIDC has none).
- Atomic PAT rotate, PAT-cannot-mint-PAT, fail-closed-on-zero-scopes. **All verified.**
- Per-verb token-scope intersection (cleaner than NeuVector's role-only-with-ExtraPermits).

**Confirmed gaps**
- **[HIGH] No brute-force protection / account lockout / failed-login throttling** on local or LDAP login. Zero attempt counting. NeuVector increments `FailedLoginCount`, sets `BlockLoginSince`, blocks for `BlockMinutes`. → Add per-user (and per-IP) failed-login counter with temporary lockout, enforced before returning the verify result.
- **[HIGH] No rate limiting anywhere on the HTTP surface.** No httprate/throttle/limiter on `/auth/*` or `/api/v1/*`. NeuVector additionally caps concurrent sessions (`MaxPerDomainLoginUsers=32`). → Add `go-chi/httprate` keyed by RealIP on `/auth/*` + a global per-token ceiling and/or concurrent-session cap.
- **[HIGH] Stateless JWTs cannot be revoked.** Logout is a no-op; user-disable/password-change/role-change don't invalidate issued tokens. No jti denylist / token_version / session_epoch. NeuVector keeps a server-side `loginSessions` map with `_logout/_expire/_delete` + `kickLoginSessions` propagated cross-controller over gRPC. → Add `users.session_epoch` (or token_version) bumped on logout/disable/password-change/role-change, checked in `authMiddleware`; reject JWTs with `iat < epoch`.
- **[HIGH] `authMiddleware` doesn't re-check `users.disabled` on the JWT path; `AuthenticateAPIToken` doesn't check it for PATs.** A user disabled after authentication keeps a working JWT **and** working PATs (PATs even synthesize GlobalAdmin). → Add `AND u.disabled = FALSE` to the PAT SQL, re-check in `authMiddleware`, cascade-revoke PATs on disable.
- **[MED] TLS is not terminated or enforced in-process.** `srv.ListenAndServe()` is plain HTTP; no MinVersion/cipher policy/mTLS for the control-plane API (in-process TLS exists only for the admission webhook). NeuVector hardcodes `tls.VersionTLS13` + explicit cipher list. → Support optional in-process `ListenAndServeTLS` with `MinVersion` TLS1.2/1.3 + mTLS for service-to-service callers.
- **[MED] Session JWT uses HS256 (symmetric).** Any verifier holding the key can forge tokens. NeuVector signs with RSA + a transition key for rotation. (We already use RS256/ES256 to verify the IdP ID-token, but our own session token stays HS256.) → Move to RS256/ES256 with scheduled key rotation.
- **[LOW] `AllowCredentials: true` on CORS with no CSRF middleware.** Limited because tokens are Authorization-header bearer. → Keep bearer-in-header (never accept JWT from a cookie), never wildcard origin when AllowCredentials is true, add CSRF if any cookie-auth mutation is introduced.

**Newly-found gaps**
- **[MED] No idle/inactivity session timeout** (only fixed 1h absolute). An idle-but-stolen token stays valid the full hour. → Track last-activity per session/token and expire on inactivity (implement alongside the revocation state).
- **[MED] No cross-replica session revocation primitive.** NeuVector kicks sessions cluster-wide across controllers over gRPC; we run multiple API replicas with no equivalent. → Make revocation DB-backed (`session_epoch`/revocation table) so it's naturally consistent across replicas.
- **[LOW] PATs can be minted with no expiry (`expires_at` empty = never).** → Add a configurable maximum PAT lifetime / reject unbounded expiry.
- **[LOW] NeuVector's `ExtraPermits` is a real fine-grained per-domain read/write layer** — don't dismiss it as a "Rancher bolt-on" when claiming PAT-scope superiority.

**Overclaims to stop making**
- The disabled-user gap should be scoped to **post-issuance revocation**: disabled users **cannot** obtain a new token (`resolveLoginPrincipal` + SSO lookups filter `disabled = FALSE`); the genuine (still-high) issue is that **already-issued** JWTs and PATs keep working.
- NeuVector apikeys are **not** scope-blind — they carry Role + RoleDomains + ExtraPermits. Soften "no scope-narrowing layer" to "lacks Constellation's verb-level intersection model."
- "Neither implements rate limiting (both share this weakness)" understates NeuVector — it has lockout + concurrent-session cap + idle timeout as compensating controls; we have none.

---

## 4. Prioritized Gap Backlog — the work to reach "better in every aspect"

### HIGH severity (do first)

**API security / auth / session (cross-cutting — these recur across api-security-exposure, authn-authz, config-surface):**

1. **PAT/JWT disabled-user + revocation hole** (api-security-exposure, authn-authz) — Add `AND u.disabled = FALSE` to `AuthenticateAPIToken`; re-check `users.disabled` in `authMiddleware`; add DB-backed `users.session_epoch`/token_version bumped on logout/disable/password-change/role-change and checked in middleware (cross-replica consistent); cascade-revoke a disabled user's PATs + role_assignments; cap PAT lifetime.
2. **Brute-force lockout** (api-security-exposure, authn-authz) — `failed_login_count` + `block_login_since` on users, enforced before returning the verify result; configurable threshold/window.
3. **HTTP rate limiting + concurrent-session cap** (api-security-exposure) — `go-chi/httprate` on `/auth/*`, global per-token ceiling, concurrent-session cap.
4. **Password policy** (authn-authz, config-surface) — per-org `password_profile` (length/complexity/expiration/history) + `ValidatePassword`; store recent Argon2id hashes for reuse checks; forced reset on first login.
5. **Move session JWT off HS256** to RS256/ES256 with key rotation (api-security-exposure). _(Med, but bundle with the auth work.)_

**Configuration surface (user-flagged):**

6. **Runtime-mutable, RBAC-gated `/api/v1/system/config`** (config-surface) — typed, Postgres-persisted, hot-reloaded; start with egress proxy, CA bundle/TLS-verify, syslog/SIEM target, scanner autoscale bounds.
7. **Declarative policy CRD layer** reconciled by the operator into DB rows (config-surface) — GitOps-manageable policy; minimum: documented export to kubectl-applyable manifests. Pair with acknowledging NeuVector's ConfigMap init layer.

**Admission control:**

8. **Real Pod Security Standards engine** (admission-control) — capabilities allowlists, hostPath/hostPort, AppArmor/SELinux/seccomp/procMount/sysctls, allowPrivilegeEscalation, runAsRoot; back or rename the misnamed baseline/restricted profiles.
9. **Validate controller kinds + PVCs** (admission-control) — register apps/batch + PVC, extract `spec.template.spec`, add storageClassName gate.
10. **Kubernetes-identity / RBAC admission criteria** (admission-control) — user/groups matching + `saBindRiskyRole` built-in profile.

**Federation (the dimension we're behind in):**

11. **Federation trust handshake** (federation) — short-lived signed join token → per-cluster secret; scope `/sync` to a fed-only credential; validate a per-joint signed ticket on every poll.
12. **Per-joint mTLS** (federation) — issue a per-joint client cert (or at minimum pin the master CA) at join.
13. **Cross-cluster admin reverse-proxy** (federation) — `ANY /api/v1/federation/clusters/{id}/*` with a read-only allowlist for non-admins.

**Runtime security:**

14. **Event-driven response-rule / webhook engine** (runtime-security) — declarative event + condition + ordered actions [quarantine|suppress-log|webhook|tag], persisted in Postgres, synced to agents.

**Network segmentation:**

15. **End-to-end FQDN network policy** (network-segmentation) — resolver fed by `dpi/dns.go`, Fqdn-anchored allow rules, `KindIPFqdnStorageUpdate` push, real Cilium `toFQDNs` egress.

**API surface:**

16. **Mechanically-generated OpenAPI + completeness CI gate** (api-surface) — close the ~60% spec gap; fail the build on undocumented routes.

### MEDIUM severity (next)

- **Runtime:** exit/fork eBPF tracepoints; `FAN_CLOSE_WRITE/FAN_MODIFY` + regex/recursive FIM filters; process-baseline lineage/zero-drift/exe-hash; fanotify file-rule behavior (monitor|block) model.
- **Admission:** resource request/limit criteria; Allow/Exception rule type; hostIPC + mountVolumes/hostPath; global admission-state API + decision stats/Prometheus counters; `allowPrivilegeEscalation` criterion.
- **Network:** L7 app whitelists in auto-gen + Cilium L7; group endpoints (address/ip_service/external/node) + From/To targeting; SecurityRule CRD; rule priority/ordering; WAF/DLP group-bound L7 (or stop counting it).
- **Vuln:** govulncheck reachability (the `Reachable` field already exists); per-layer vuln attribution + Dockerfile history; serverless/Lambda artifact scanner; per-registry repo/tag filters + schedule modes.
- **Compliance:** on-demand per-asset benchmark trigger API; custom checks with user-supplied logic; reframe regulatory-mapping advantage.
- **Federation:** scan-result federation by digest; proxy/TLS-skip support; master-side liveness reconcile; broaden rule-replication scope; fed-rule cleanup on leave/demote/kick; remote diagnostic/export forwarding.
- **API surface:** uniform query/filter/sort framework; `scope=local|fed|all` param; per-domain config import/export with merge/replace; runtime auth-server CRUD.
- **Authn / config / api-security:** runtime auth-provider CRUD + `auth_order`; forced first-login password reset; idle/inactivity session timeout; cross-replica revocation primitive; in-process TLS with MinVersion + mTLS; network/microsegmentation runtime config knobs; config-as-code export incl. org_settings/users/roles/registries.

_(LOW-severity items are enumerated per-dimension in §3 and are tracked but not gating for "better in every aspect.")_

---

## 5. Spotlight: Configuration & API Exposure (user-flagged)

Because the user specifically asked about configuration and API exposure, these are the standout, must-fix findings consolidated:

**API exposure (highest risk):**
- **Disabled users are not fully locked out post-issuance.** Live JWTs keep working (middleware doesn't re-check `disabled`) and **PATs keep working indefinitely** (`AuthenticateAPIToken` never filters `disabled`, PATs can be unexpiring) — a durable backdoor with no cascade revocation.
- **No revocation at all** — logout is a no-op; no token_version/epoch; no cross-replica kick.
- **No brute-force lockout and no rate limiting anywhere** — zero compensating controls; NeuVector has lockout + concurrent-session cap + idle timeout.
- **Plain HTTP in-process** (TLS only at the admission webhook) and **HS256 symmetric session JWTs** (every verifier can forge).
- **No password policy / idle timeout.**

**Configuration exposure:**
- **Nothing operational is runtime-mutable** — no `/system/config`; every knob (proxy, CA/TLS-verify, syslog/SIEM, scanner autoscale, IdP) needs a Deployment edit + restart. NeuVector exposes ~40 live-tunable fields.
- **Policy is not GitOps-able** — one install-only CRD vs NeuVector's 10 policy CRDs + a ConfigMap init layer. NeuVector is meaningfully more declarative than our earlier framing claimed.
- **Auth providers are single-instance, deploy-time-only** — no DB-backed multi-IdP CRUD, no `auth_order`.
- **Backup is not a full config export** — omits users/roles/registries/org_settings/api_tokens; no YAML export or push-to-git.

These two areas, together with federation, are where Constellation is furthest from "as good as or better than NeuVector in every aspect."
