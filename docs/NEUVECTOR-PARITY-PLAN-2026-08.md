# NeuVector Parity — Implementation Plan (2026-08)

> **Status:** DRAFT for review. Nothing here is implemented yet.
> **Goal:** make Constellation *as capable as or better than* NeuVector in every dimension.
> **Source of truth:** this plan supersedes the gap lists in `NEUVECTOR-PARITY-TASKS-2026-07.md` for the items it covers. It was produced by a code-traced, 7-dimension review (2026-08-18) that read both the NeuVector source (`/root/constellation-all/neuvector`) and Constellation's current tree, and re-verified every prior finding.

---

## 0. How to read this plan

Each fix is a self-contained block:

```
### <ID> — <title>            [PRIORITY · DIMENSION · EFFORT]
Problem     — what's wrong / missing, and why it matters.
NeuVector   — how NeuVector does it (file:line in the clone).
Constellation — current behavior (file:line).
Tasks       — [ ] granular, ordered, independently reviewable.
Example     — concrete code/config where it removes ambiguity.
Validation  — [ ] how we prove it works (unit / live / e2e).
Acceptance  — the single condition that means "done".
```

**Legend.** Priority: `HIGH` (blocks "parity as shipped"), `MED` (completeness/hardening), `LOW` (polish/long-tail). Effort: `S` ≤1 day, `M` 2–5 days, `L` >1 week or needs a design decision.

**Golden rule for this whole effort:** almost none of the HIGH gaps are "the feature is absent." They are "the code exists but is gated off, hardcoded open, or half-wired." Prefer *exposing and mode-driving* existing mechanisms over rewriting them.

---

## 1. Executive summary

Constellation meets or exceeds NeuVector at the capability level in **every** dimension, and clearly exceeds on modern ground (dual-engine Trivy+Grype scanning + SBOM + reachability, RS256 DB-backed revocable sessions, hash-chained tamper-evident audit, CEL+Rego admission, 17 compliance frameworks, CNI-native NetworkPolicy generation NeuVector cannot do).

**The one theme that ties the gaps together: enforcement ships gated off.** Inline segmentation, runtime process/file blocking, and quarantine are all implemented and at-or-above NeuVector's mechanisms — but they are default-off, not exposed in the Helm chart, and not driven by a Discover→Monitor→Protect mode. A default install therefore *detects and generates policy but does not block*, where NeuVector's Protect mode blocks on mode alone.

**Dimension scorecard**

| Dimension | Verdict | HIGH gaps |
|---|---|---|
| Vulnerability scanning & registries | Parity+ (exceeds on depth/SBOM/signatures/exports) | 3 — registry creds & breadth |
| Runtime security | Partial (detect-only as shipped) | 3 — enforcement off; no argv; inert kill-response |
| Network security | Partial (observe/generate as shipped; ceiling exceeds) | 3 — inline default-deny inert; no Cilium enforce |
| Admission & compliance | Parity+ (exceeds on CEL/Rego, frameworks, reports) | 1 — multi-cluster CIS clobber |
| Auth / RBAC / federation | Exceeds | 2 — namespace RBAC deny-closed; joint federation |
| Response & platform ops | Exceeds | 1 — plaintext syslog |
| UX / IA | Sound (no restructuring) | 3 — orphaned workspace, dead-ends, stranded pages |

---

## 2. Phasing

- **Phase 1 — "Turn it on."** High value, mostly small. Expose/mode-drive what's already built; fix correctness bugs; wire the UX. This alone moves "detect-only" → "can enforce" and repairs the analyst flow.
- **Phase 2 — Credentials, SIEM, hardening.** Enterprise blockers: private/cloud registry auth, TLS/CEF syslog, argv capture, auth hardening.
- **Phase 3 — Deep enforcement & scale.** Large efforts, some are strategy calls: inline per-workload segmentation, Cilium enforcement, namespace RBAC end-to-end, joint federation.
- **MED backlog** and **LOW backlog** follow, so nothing is dropped.

**Cross-cutting decision to make first (blocks several Phase-3 items):**
> **D-1 — Enforcement model.** Is inline per-workload wire-level segmentation (NeuVector's model) a product goal, or is **CNI-native NetworkPolicy/CiliumNetworkPolicy generation** Constellation's enforcement story? Constellation already does the latter and NeuVector cannot. If CNI-native is the answer, several Phase-3 network items become "document + de-scope the inline dp path" rather than "port the intercept." **Recommendation: CNI-native is the primary enforcement model; keep inline dp for flannel-class clusters as a secondary, clearly-scoped mode.** Decide before Phase 3.

---

# PHASE 1 — Turn it on

## 1A. Runtime enforcement: expose + mode-drive

### RT-ENFORCE-01 — Enforcement is unreachable in a default deploy   [HIGH · Runtime · M]
**Problem.** All runtime block primitives exist and are correct, but each is gated behind a default-OFF env var that is **not templated in the runtime-agent DaemonSet**, and none are driven by the server-side group/baseline mode. Result: a default install is detect-only; NeuVector's Protect mode blocks on mode alone.
**NeuVector.** Group "Protect" mode alone arms enforcement — `neuvector/agent/probe/faccess_linux.go`, `process_linux.go:60`; no per-node opt-in.
**Constellation (verified 2026-08-18).**
- Process kill-on-exec: `cmd/constellation-runtime-agent/process_enforcer.go:108` (`SIGKILL`), gated `CONSTELLATION_PROCESS_ENFORCER` default off (`main.go:564`); honors `row.Mode=="enforce"` (`process_enforcer.go:200`).
- File pre-open block: `file_profile_enforcer_linux.go:290-301` (`FAN_DENY`), gated `CONSTELLATION_FILE_PROFILE_ENFORCER` (off, `main.go:456`), `Mode=="enforce" && Behavior=="block_access"` (line 306).
- Exec pre-block: `file_profile_enforcer_linux.go:766-782`, doubly gated `CONSTELLATION_EXEC_ENFORCER` + `CONSTELLATION_EXEC_ENFORCER_MODE=enforce` (default *monitor*, line 655).
- The DaemonSet `deploy/charts/constellation/templates/runtime-agent-daemonset.yaml` has 14 `CONSTELLATION_*` env vars and **zero** `*_ENFORCER`.

**Tasks.**
- [ ] Add Helm values `runtimeAgent.enforcement.{process,file,exec,zeroDrift}` (bool) and an umbrella `runtimeAgent.enforcement.mode` (`disabled|monitor|protect`).
- [ ] Template the corresponding env vars in `runtime-agent-daemonset.yaml`; default `mode: monitor` (safe: alerts, no blocks) so upgrades don't surprise-block.
- [ ] **Mode-drive it:** when a group/baseline is set to `enforce` server-side, the agent should enforce for that workload **without** a separate global env gate. Change the enforcers to treat `mode=protect` (fleet) OR `row.Mode=="enforce"` (per-workload) as the arming condition; keep the env var only as a global kill-switch (`disabled`).
- [ ] Surface the effective enforcement mode per workload in the UI (RuntimePage / RuntimePoliciesPage) so an operator can see "Monitoring" vs "Protecting".
- [ ] Document the upgrade note: existing installs stay `monitor`; flipping to `protect` is an explicit action.

**Example (chart env).**
```yaml
# values.yaml
runtimeAgent:
  enforcement:
    mode: monitor          # disabled | monitor | protect  (fleet default)
    process: true          # allow per-workload enforce to bite when mode!=disabled
    file: true
    exec: true
    zeroDrift: true
```
```yaml
# runtime-agent-daemonset.yaml (env)
- name: CONSTELLATION_ENFORCE_MODE
  value: {{ .Values.runtimeAgent.enforcement.mode | quote }}
- name: CONSTELLATION_PROCESS_ENFORCER
  value: {{ .Values.runtimeAgent.enforcement.process | quote }}
# … file/exec/zeroDrift …
```

**Validation.**
- [ ] Unit: enforcer arms when `mode=protect` with global env unset; no-ops when `mode=disabled` regardless of per-workload rows.
- [ ] Live: deploy a test Deployment, learn a process baseline, set it to `enforce`, then exec a not-in-baseline binary in the pod → process is SIGKILLed; audit shows `verdict=blocked` (today it only ever shows `observed`/`alert`, `events_ingest.go:1092-1099`).
- [ ] Live: repeat for file (`Behavior=block_access`) and exec-of-drifted-binary.
- [ ] Regression: `mode=monitor` never blocks; only alerts.

**Acceptance.** With chart default `monitor`, flipping a group to Protect (or setting `mode: protect`) blocks a policy violation on a stock install with **no manual DaemonSet edit**.

---

### RT-KILL-02 — Process-kill / kill-session response is inert   [HIGH · Runtime · S]
**Problem.** The agent polls `GET /api/v1/runtime/response-actions:pending` (`response_actions.go:326`) but **the server registers no such route** — a `TODO(matrix)` at `response_actions.go:321`. So the "kill process" response action silently does nothing (network isolate works; process kill does not).
**NeuVector.** Response rules can kill process/session at the enforcer.
**Tasks.**
- [ ] Decide: implement the endpoint, or delete the dead poller and document that process-kill is delivered via the enforcer path (RT-ENFORCE-01), not a response action.
- [ ] If implementing: add `GET /api/v1/runtime/response-actions:pending` (scanner/agent-token auth) that returns queued kill actions for the calling node's workloads, and a `POST …:complete` result sink; producer is the response-rule engine (`pkg/response`).
- [ ] Wire `pkg/response` `isolate`/new `kill` action → enqueue a response-action row.

**Validation.**
- [ ] Live: response rule "on runtime.alert.critical → kill process" fires; target PID is killed; result recorded.
- [ ] Grep: no dangling references to the removed poller if we delete it.

**Acceptance.** A response rule with a kill action either actually kills, or the dead code is gone and docs point to the enforcer path.

---

## 1B. Compliance correctness

### CMP-CLOBBER-03 — Multi-cluster CIS results overwrite each other   [HIGH · Compliance · S]
**Problem.** `Compliance.Ingest` writes only `(org_id, framework, control_id, …)` and upserts on a partial unique index `WHERE cluster_id IS NULL`, so two clusters (or two nodes) in one org **clobber each other's** kube-bench/docker-bench rows. Silent compliance-state corruption for any multi-cluster tenant.
**Evidence.** `internal/handler/compliance/compliance.go:357-369`; index `db/migrations/110_compliance_checks_unique.sql`. The kube-bench runner loads `CONSTELLATION_CLUSTER_ID` but never sends it. The **correct pattern already exists** at `host_cis.go:97-120` (`ResolveAgentClusterID`, dedup on `(org_id, cluster_id, node)`).
**Tasks.**
- [ ] Runner: include `cluster_id` (and `node` where applicable) in the POST body (`cmd/constellation-kube-bench-runner`).
- [ ] `Ingest`: write `cluster_id`/`node`; change the upsert key to `(org_id, cluster_id, node, framework, control_id)`.
- [ ] Migration: replace the `WHERE cluster_id IS NULL` partial unique index with a full composite unique index; backfill existing rows with their cluster (or truncate stale org-wide rows and re-scan).
- [ ] Verify `Checks`/`reports.go`/`CompliancePage` filter by cluster.

**Validation.**
- [ ] Live: run kube-bench on two clusters in one org; both clusters' results coexist and are shown per-cluster (today the second overwrites the first).
- [ ] Unit: ingest of the same control from two clusters yields two rows.

**Acceptance.** Compliance state is per-cluster/per-node; no cross-cluster overwrite.

---

## 1C. Response correctness

### RSP-WEBHOOK-04 — Webhook action ignores its receiver and broadcasts   [MED→ship-in-P1 · Response · S]
**Problem.** E1 `Validate` requires `Params["receiver"]` (`responserule.go:144`) but `fireWebhook` calls `dispatcher.Dispatch` (fan-out to ALL subscribers) instead of `DispatchTo` the named one (`response_rule_defs.go:284-300`). A rule targeting one receiver sprays every subscriber; the validated param is dead.
**NeuVector.** Delivers to the named `rule.Webhooks` (`cache/response.go:368`).
**Tasks.**
- [ ] Resolve `Params["receiver"]` → receiver id (org-scoped) and call `dispatcher.DispatchTo`, mirroring RT-2's `buildReceiverMap`/`dispatchReceiver` (`response_runtime.go:200-273`).
- [ ] Validate the receiver exists at rule-save time.

**Validation.**
- [ ] Live: rule with `receiver: pagerduty-oncall` delivers only to that receiver; a second receiver gets nothing.

**Acceptance.** Webhook actions route to exactly their named receiver.

---

### RSP-AUDIT-05 — Failed logins & lockouts are not audited   [MED→ship-in-P1 · Auth · S]
**Problem.** Successful auth events are audited, but `recordLoginFailure` (`auth.go:324-332`) is a bare counter update — failed logins and lockout trips emit **no** audit event, so brute-force is invisible to `/audit/events` and SIEM.
**NeuVector.** Emits `CLUSEvAuthLoginFailed`.
**Tasks.**
- [ ] Emit `auth.login.failed` (with source IP, username-attempted, reason) from all login paths (local/OIDC/SAML/LDAP) and `auth.login.locked` when lockout trips.
- [ ] Keep the HTTP response generic 401 (no user enumeration); the audit row is server-side only.
- [ ] Also audit the idle-timeout session rejection.

**Validation.**
- [ ] Live: 6 bad logins → 5 `auth.login.failed` + 1 `auth.login.locked` in `/audit/events`; forwarded to syslog.

**Acceptance.** Brute-force activity is visible in the audit log and SIEM.

---

## 1D. UX wiring (repair the analyst flow — no restructuring)

### UX-RISK-06 — The per-entity Risk workspace is orphaned   [HIGH · UX · S]
**Problem.** `RiskDetailPage` (route `clusters/:id/risk/:entityType/:entityId`, `App.tsx:149`) is a rich tabbed drill-down (Overview / Findings / Network / Process / File / Compliance, `RiskDetailPage.tsx:21-26`) with **zero inbound links** — no nav entry, no link from asset/finding rows. A whole "why is this risky" story is invisible.
**Tasks.**
- [ ] Decide canonical entity view: `RiskDetailPage` vs the thinner `AssetDetailPage`. Recommendation: make `RiskDetailPage` canonical for assets/workloads/nodes.
- [ ] Link dashboard heatmap cells, findings rows, and asset/node/deployment rows → `/clusters/:id/risk/<type>/<id>`.
- [ ] Add loading/empty/error states (currently missing).

**Validation.** [ ] From dashboard → click a risky entity → land on its Risk workspace with all tabs populated. **Acceptance.** No dead route; every entity list links into the risk workspace.

### UX-FINDING-07 — Finding detail dead-ends (no asset link)   [HIGH · UX · S]
**Problem.** `FindingDetailPage.tsx` never renders `asset_id` as a link — the deepest view in risk→finding→asset breaks exactly where the chain should continue. (List + dashboard drawer both link it: `FindingsPage.tsx:174`, `DashboardPage.tsx:637`.)
**Tasks.**
- [ ] Add an "Affected asset" field in the `PageHeader`/provenance section linking to `/clusters/:id/assets/:asset_id` (and to the Risk workspace per UX-RISK-06).
**Validation.** [ ] Finding detail → click affected asset → asset/risk page. **Acceptance.** The risk→finding→asset→why loop is navigable end-to-end.

### UX-ORPHAN-08 — Stranded pages reachable only by URL   [HIGH · UX · S]
**Problem.** `VulnDBPage` (`settings/vulndb`) has no nav entry, no Settings link, no palette entry. `AttestationTrustPage`, `ApiTokensPage`, `ConnectorCoveragePage` are body-link-only inside SettingsPage — too buried for supply-chain/token surfaces.
**Tasks.**
- [ ] Give `VulnDBPage` an `ORG_NAV` (Admin) or Settings sub-nav entry.
- [ ] Promote API Tokens + Attestation Trust to a Settings sub-nav (not body-only cards).
- [ ] Add all four to the command palette `NAV_ITEMS` (`CommandPalette.tsx:312-327`).
**Validation.** [ ] Every routed page is reachable from nav or palette (write a test asserting no route lacks an inbound link). **Acceptance.** Zero orphaned routes.

### UX-DASH-09 — Dashboard omits compliance & runtime posture   [MED→ship-in-P1 · UX · S]
**Problem.** `DashboardPage.tsx:14` documents "Compliance donut" but the implemented row (`:277-377`) is Severity/CVE-DB/Trend — no compliance widget, no runtime-threat count. Two platform pillars are absent from "what needs my attention now."
**Tasks.**
- [ ] Add a compliance-posture tile (pass/fail %) and a runtime-threats-today tile to the hero or bottom row.
- [ ] Fix the stale layout comment.
**Validation.** [ ] Dashboard shows compliance % and today's runtime threats, each linking to its page. **Acceptance.** All four pillars (vuln/compliance/runtime/network) are represented on the landing.

### UX-NAV-10 — Nav grouping mislabels runtime & response   [MED→ship-in-P1 · UX · S]
**Problem.** "Runtime Threats" + "Process Baselines" live under **Network Activity** (`AppShell.tsx:85-92`); the **Policy** group mixes detection policy with "Response Rules"/"Response Catalog" (`:117-130`).
**Tasks.**
- [ ] Rename the network group to "Network & Runtime" or split a dedicated **Runtime** group (threats, baselines, file-monitor, DLP, signatures).
- [ ] Split a **Response** group (Response Rules, Response Catalog) out of Policy.
- [ ] Disambiguate "Cluster Health" vs "System Health" labels/scope (M5).
**Validation.** [ ] Nav maps to overview→findings→assets/network→runtime→policy→respond→settings. **Acceptance.** Each analyst stage is its own coherent group.

---

# PHASE 2 — Credentials, SIEM, hardening

## 2A. Registry credentials & breadth

### REG-PRIVAUTH-11 — Scanner can't authenticate to pull private images   [HIGH · Scanning · M]
**Problem.** Scan jobs carry `registry_id` (`internal/handler/scan_seam.go:55`) but `cmd/constellation-scanner` never fetches per-registry creds; all `ScanOptions{}` (main.go:606/632/667/684/803) omit Username/Password; `registryEnv` only exports `DOCKER_USER/PASSWORD` (`syft.go:335-341`) which are **never populated** and are **not** the vars Trivy/Grype/Syft read.
**NeuVector.** Decrypted creds delivered per scan (`image.go:338-352`).
**Tasks.**
- [ ] Add a scanner-token endpoint `GET /api/v1/scanner/registry-credentials?registry_id=…` that unseals `registries.auth_secret` for the job's registry (audited, scoped to the scanner's org).
- [ ] Scanner: fetch creds for a job's `registry_id`, write a temporary docker `config.json` and/or set `TRIVY_USERNAME/TRIVY_PASSWORD`, `GRYPE_REGISTRY_AUTH_*`, `SYFT_REGISTRY_AUTH_*` for the scan subprocess.
- [ ] Ensure creds are per-job and cleaned up (temp dir, no persistence).
**Validation.** [ ] Live: scan a private image from a configured registry succeeds; scan without creds fails clearly. **Acceptance.** Private-registry scan jobs authenticate.

### REG-CLOUDAUTH-12 — Cloud-native registry auth unimplemented   [HIGH · Scanning · M]
**Problem.** `validAuthKinds` advertises `gcp-service-account`/`azure-managed-id` but `BuildConnector` never branches on `authKind`; ACR/artifact-registry need pre-acquired ~1h tokens (`connectors_more.go:38,104`); `NewECR` ignores static keys (`ecr.go:24-33`). Non-manual cadence dies after token expiry.
**Tasks.**
- [ ] GCP: mint OAuth tokens from SA JSON (`_json_key`/`oauth2` token exchange) for GCR/Artifact Registry.
- [ ] Azure: AAD client-credentials for ACR; `azidentity` MSI for managed identity.
- [ ] ECR: honor static access keys (not just the ambient chain) and refresh via `GetAuthorizationToken`.
- [ ] Cache tokens with expiry; refresh before scans.
**Validation.** [ ] Live (or mocked): each cloud registry authenticates and re-authenticates after token TTL. **Acceptance.** Scheduled scans against GCR/ACR/ECR keep working past 1h.

### REG-ENUM-13 — Harbor / GitLab / JFrog repo enumeration broken   [HIGH · Scanning · M]
**Problem.** Harbor uses `/api/v2.0/projects/_default/repositories` (`connectors_more.go:217` — `_default` isn't a real project); GitLab uses `/api/v4/registry/repositories?per_page=100` (`:270` — not a valid list endpoint); JFrog abuses `cfg.Username` as the repo key (`:362`). (Tag enumeration was fixed via `populateTagsViaV2`; repo discovery for these three is still wrong.)
**Tasks.**
- [ ] Harbor: page `/api/v2.0/repositories` across projects.
- [ ] GitLab: enumerate membership projects → per-project `/registry/repositories`.
- [ ] JFrog: `/api/repositories?type=docker` + mode/layout support.
**Validation.** [ ] Live/mocked: each returns the real repo set; scans enqueue per repo. **Acceptance.** These three registries enumerate correctly.

## 2B. SIEM

### SIEM-TLS-14 — Syslog export is plaintext, RFC5424-only   [HIGH · Response · M]
**Problem.** `notify.Syslog` dials plaintext UDP/TCP and emits only RFC5424 (`pkg/notify/notify.go:384-433`); config exposes host/port/protocol only (`syscfg.go:83-87`). Enterprise SIEM over untrusted networks needs TLS + structured formats.
**NeuVector.** TLS (`SyslogServerCert`), JSON (`SyslogInJSON`), category/level filtering, per-CVE (`system.go:522-533`).
**Tasks.**
- [ ] Add `tls` (+ optional CA/cert) transport to `notify.Syslog`.
- [ ] Add a `format` selector: RFC5424 / JSON / CEF (ideally LEEF too).
- [ ] Add level/category filtering (don't ship every event).
- [ ] Surface `tls`, `format`, `min_level`, `categories` in `SyslogTarget` (`syscfg.go`) + Settings UI.
**Validation.** [ ] Live: TLS syslog to a test collector; JSON and CEF parse; level filter drops low events. **Acceptance.** Secure, structured, filtered SIEM export.

## 2C. Runtime detection depth

### RT-ARGV-15 — Argv is never captured   [HIGH · Runtime · M]
**Problem.** The BPF exec tracepoint hard-codes `e->args[0]=0` (`internal/runtime/ebpf/bpf/runtime.bpf.c:94`); `ProcessEvent.Args` is always empty, so every argument-based detection (download-cradles, base64-to-shell) is dead.
**Tasks.**
- [ ] Read argv in the exec tracepoint (bounded loop over `bprm`/user stack) OR best-effort `/proc/<pid>/cmdline` enrichment in userspace for HIGH events.
- [ ] Thread through `ProcessEvent.Args`; update detections (`runtime_detections.go`) to use it.
- [ ] Cap arg count/length to bound overhead.
**Validation.** [ ] Live: `curl … | bash` and `echo <b64> | base64 -d | sh` in a pod raise the corresponding arg-based detections (they don't today). **Acceptance.** Argument-based detections fire.

### RT-MATCH-16 — Basename-only process matching (rename bypass)   [MED · Runtime · M]
**Problem.** Default matching is basename-only (`process_enforcer.go:129-130,218-226`); `mv evil /bin/nginx` bypasses. Granular path+sha256+parent logic exists but the server bundle can't feed it.
**Tasks.**
- [ ] Extend the process-baseline bundle schema to carry `Path`/`Sha256`/`ParentName` (migration + `process_baselines_bundle.go`).
- [ ] Enable `CONSTELLATION_PROCESS_MATCH_GRANULAR` by default once the bundle is rich.
**Validation.** [ ] Live: a baselined binary moved to an allowed name is still blocked. **Acceptance.** Rename-to-allowed-name no longer bypasses.

## 2D. Auth hardening

### AUTH-LOCKOUT-17 — Brute-force lockout not configurable + no unlock   [MED · Auth · S]
**Problem.** Thresholds are package consts (`maxFailedLogins=5`, `loginLockoutWindow=15m`, `auth.go:146-151`); not in `SecurityPolicy`; no unlock endpoint.
**Tasks.**
- [ ] Add `enable_lockout/lockout_threshold/lockout_minutes` to `SecurityPolicy` (`policy.go`) with bounds.
- [ ] Add `POST /users/{id}/unlock` (clears `block_login_since`), gated `VerbManageUsers`.
- [ ] Settings UI control.
**Validation.** [ ] Live: change threshold; lock a user; admin unlock restores login. **Acceptance.** Lockout is admin-tunable and reversible.

### AUTH-OIDC-18 — OIDC group claim hardcoded   [MED · Auth · S]
**Problem.** Group claim hardcoded `raw["groups"]` (`oidc.go:261`); Azure AD (`roles`) / Keycloak yield zero groups → role-less JIT users.
**Tasks.** [ ] Add `GroupClaim` to `ServerConfig`; default `groups`; read the configured claim. **Validation.** [ ] Azure-AD-style `roles` claim maps to roles. **Acceptance.** Group→role works for non-`groups` IdPs.

### AUTH-LDAP-19 — LDAP group-search path missing   [MED · Auth · M]
**Problem.** Groups read only from the user entry's `GroupAttribute` (`ldap.go:167-168`); OpenLDAP `posixGroup`/`memberUid` resolves zero groups.
**Tasks.** [ ] Add `GroupBaseDN` + `GroupMemberAttribute` secondary search (memberUid/member presets). **Validation.** [ ] OpenLDAP posixGroup user resolves its groups. **Acceptance.** Group-object directories map to roles.

### AUTH-USERCRUD-20 — Local-user admin CRUD incomplete   [MED · Auth · M]
**Problem.** Only disable/delete/force-reset over REST (`users.go:39,94,154`); no create/re-enable/edit; disable is one-way.
**Tasks.** [ ] Add `POST /users`, `PATCH /users/{id}`, `POST /users/{id}/enable`, admin password-set; org-scoped; policy-validated; `VerbManageUsers`. [ ] UI in AccessControlPage. **Validation.** [ ] Full user lifecycle via UI/REST. **Acceptance.** Admin can create/edit/enable/disable/delete local users.

---

# PHASE 3 — Deep enforcement & scale

> Gated on decision **D-1** (enforcement model). If CNI-native is chosen as primary, NET-INLINE-21/22 become "secondary mode for flannel-class CNIs + honest docs," not full ports.

## 3A. Network inline enforcement

### NET-INLINE-21 — Inline default-deny is inert   [HIGH · Network · L]
**Problem.** `runtime_policy_sync.go:280` hardcodes `DefAction: dp.PolicyActionAllow` over node-wide `TapMACs()` (line 196); the wire `DefAction` (line 117) is decoded but never consulted; internal-subnet never pushed (repo-wide grep of `ConfigInternalSubnet`/`SetSysConf` = 0 hits) so wildcard/"external" rules are dead; `CONSTELLATION_DP_ENFORCE` isn't templated (`P3-02`).
**Tasks.**
- [ ] Per-workload policy handles keyed to pod→netns→MAC (the `ContainerTapProvider` already knows this mapping) instead of node-wide `TapMACs()`.
- [ ] Honor the wire `DefAction` (drive default-deny from synced policy mode).
- [ ] Push internal/special subnets to dp so wildcard/external rules match (`ConfigInternalSubnet`).
- [ ] Template `CONSTELLATION_DP_ENFORCE` and drive inline selection from group Protect mode.
**Validation.** [ ] Live (flannel-class CNI): a workload in Protect mode drops non-allowed egress at the wire; audit shows a real block. **Acceptance.** Inline segmentation actually enforces per-workload default-deny.

### NET-INLINE-22 — No inline enforcement on Cilium/eBPF CNIs   [HIGH · Network · L]
**Problem.** Only NFQUEUE intercept ported; NeuVector's tc/ovs port-pair L2 intercept absent — Cilium clusters get monitor/tap only (`P3-04`).
**Tasks.**
- [ ] **Decision D-1 applies.** If pursuing inline: port a TC-BPF verdict hook or the port-pair intercept. If not: implement `CiliumNetworkPolicy` enforcement (already generated) as the Cilium story and document that inline dp is flannel-class only.
**Validation.** [ ] Cilium cluster enforces segmentation via the chosen mechanism. **Acceptance.** Cilium clusters have a real enforcement path (inline OR CNI-native), documented.

### NET-QUAR-23 — Quarantine doesn't touch the datapath   [MED · Network/Runtime · M]
**Problem.** `internal/runtime/quarantine/` cordons via deny-all NetworkPolicy only — inert on flannel-class CNIs (exactly where inline works), doesn't drop established conntrack; no un-isolate (`P3-05`, `P3-30`).
**Tasks.** [ ] Add a dp-datapath quarantine flag + session-clear for inline-capable CNIs. [ ] Implement reliable un-isolate on lift/expiry. **Validation.** [ ] Quarantine drops live sessions on inline CNIs; lift restores connectivity. **Acceptance.** Quarantine works CNI-independently and is reversible.

## 3B. RBAC & federation scale

### RBAC-NS-24 — Namespace-scoped RBAC is deny-closed   [HIGH · Auth · L]
**Problem.** Engine/storage/CRUD complete (`scope_namespace` migration 134, clause in `Authorize` `rbac.go:214-218`, loader `server.go:2090-2111`, JIT `auth.go:1079`), but **no handler ever sets `Resource.Namespace`** (all 6 `rbac.Resource{}` sites are org/cluster-only), so every namespace grant is dead (deny-closed = safe but non-functional).
**Tasks.**
- [ ] Derive `Resource.Namespace` in `requireVerb`/handlers from route/body/query where a namespace is in scope.
- [ ] Add row-level list filtering so a namespace-scoped role sees only its namespace's resources.
- [ ] Do the symmetric `ProjectID` derivation if/when a project route family exists.
**Validation.** [ ] Live: a namespace-scoped Auditor sees only that namespace's findings/workloads and is denied elsewhere. **Acceptance.** Namespace multi-tenancy is functional.

### FED-JOIN-25 — Joint-side federation join is unwired   [HIGH · Auth · M]
**Problem.** `PersistJointJoin` (`fed_mtls.go:31`) has **zero non-test callers**; no `join-remote` handler; `constellationctl` has no `federation` command; chart doesn't set `FED_MASTER_URL/TOKEN`. In mTLS mode no joint can present the client cert → mTLS federation unusable.
**NeuVector.** Joint side is wired (`handlerJoinFed`, `neuvector/controller/rest/rest.go:1820`).
**Tasks.** [ ] Add `POST /federation/join-remote` (or `constellationctl federation join`) that calls the master, persists via `PersistJointJoin`, flips local state. [ ] Chart env knobs `FED_MASTER_URL/TOKEN`. **Validation.** [ ] Live: a second cluster joins a master and appears in members; cross-cluster proxy works. **Acceptance.** A joint can actually join, including mTLS mode.

---

# MED BACKLOG (schedule after Phase 1–3 HIGHs)

### Admission
- [ ] **ADM-CRIT-26** [M] Long-tail criteria (`P4-07`): `resourceLimit` (cpu/mem req/limit), `modules`, `imageNoOS`, standalone `allowPrivEscalation`, `shareIpcWithHost`/HostIPC — add to `RuleConditions`/`evalPodRule` (`admission.go:428-505,880-993`).
- [ ] **ADM-META-27** [M] Workload-metadata criteria (`P2-04`): image-name pattern deny, arbitrary pod label/annotation matching, `mountVolumes`, generic `envVars` matching (only `envVarSecrets` today, `admission.go:1083-1116`).
- [ ] **ADM-VWC-28** [M] `failurePolicy`/VWC not runtime-managed (`P4-08`) — shipped VWC is fail-**open** (`admission.go:44-49`); add runtime drift check + failurePolicy toggle.
- [ ] **ADM-CVE-29** [S] CVE admission granularity: add `cveMediumCount` and per-severity with-fix count thresholds (only `RequireFixAvailable` bool today, `admission.go:494`).
- [ ] **ADM-OCP-30** [S] OpenShift `DeploymentConfig` absent from `podTemplateKinds` (`admission.go:1196-1204`) — admission bypass on OCP.

### Compliance
- [ ] **CMP-RUN-31** [M] No on-demand bench run — add control-plane→runner trigger (NV `handlerKubeBenchRun`/`handlerDockerBenchRun`, `bench.go:150,231`); `run-now` currently only nudges the renderer.
- [ ] **CMP-REM-32** [S] CIS remediation text parsed then dropped (`kubebench.go:50` captures it; INSERT omits it `compliance.go:357-369`) — add a `remediation` column + surface it.
- [ ] **CMP-DOCKER-33** [S] Ship a docker-bench CronJob (parser + runner support exist; only kube-bench CronJob shipped).

### Scanning
- [ ] **REG-KINDS-34** [M] Add `generic-v2`, IBM Cloud, OpenShift, Nexus/RedHat registry kinds (`validKinds` unchanged at 9, `registries.go:60-70`; ibmcloud/openshift connectors exist but unreachable).
- [ ] **REG-POLICY-35** [M] Scan-policy expressiveness (`P3-24`): tag regex/patterns, repo/tag count limits, anchored `globMatch` (`registries.go:1139,1238`).
- [ ] **SCAN-PLAT-36** [M] Platform (k8s) CVE matching weak — emit Go-module purls (`pkg:golang/k8s.io/kubernetes@…`) so Grype's GHSA feed matches, or keep a curated platform advisory feed.
- [ ] **SCAN-VEX-37** [S] `pkg/vex` is dead code (zero importers) yet advertised in coverage — add `/vex/{openvex,cyclonedx}/{asset_id}` routes or drop the claim.
- [ ] **SIG-ROOTS-38** [M] No per-org REST-managed sigstore roots-of-trust (NV has full CRUD; Constellation supplies via `--signature-roots` flag only, `main.go:865`).
- [ ] **FED-REG-39** [M] No federated registry propagation (`fed_sync.go` has no registry kind).

### Network (DLP/WAF)
- [ ] **NET-DLPCTX-40** [S] DLP per-pattern context dropped — all forced to `body` (`pcre_pattern.go` `defaultDLPContext`); schema needs `{pattern,op,context}` (`P3-09`).
- [ ] **NET-DLPPREC-41** [M] DLP pattern precision — Luhn/sentinel exclusions; the validated pack is dead code (`P2-02`).
- [ ] **NET-WAFAUTH-42** [M] User-authored WAF rules can't reach dp WAF table — degrade to DLP (`P3-11`).
- [ ] **NET-BIND-43** [M] No group→sensor binding for DLP/WAF (`P3-10`).
- [ ] **NET-BACKUP-44** [S] Backup omits enforcing `runtime_dlp_rules`, backs up dead `dlp_sensors` (`P3-13`) — a restore silently loses live DLP/WAF policy. **(Data-loss risk — consider pulling into Phase 1.)**
- [ ] **NET-FEDDLP-45** [M] Federation doesn't replicate DLP/WAF (`P3-12`).
- [ ] **NET-MULTINIC-46** [M] Multi-interface pods only tap first NIC (`P3-07`) — enforcement bypass on Multus.
- [ ] **NET-ICMP-47** [S] `SetICMPPolicy` never armed (zero prod callers, `P3-01`).

### Runtime
- [ ] **RT-MODE-48** [M] No cluster-global runtime monitor/protect toggle (`P2-06`).
- [ ] **RT-SETUID-49** [M] No setuid-without-exec (UID-change) detection (`P3-16`).
- [ ] **RT-DRIFT-50** [M] Drift classification in-memory; hydration-on-restart gap (`P3-15`).

### Auth/Response
- [ ] **FED-RSP-51** [M] Federated response rules display-only (`P1-17`) — materialize fed rules as real E1 rows evaluated ahead of local.
- [ ] **RSP-CVE-52** [M] CVE-count deny/response conditions thinner than NV — add count-based (with-fix + age) conditions.
- [ ] **SSO-OCP-53** [M] OpenShift/Rancher OAuth login (generic OIDC partially covers).

---

# LOW BACKLOG (polish / long-tail — batch opportunistically)

**Network:** flood-meter knobs no-op (`P2-01`); service-mesh lo-tap default-off/monitor-only (`P3-08`); XFF matching never enabled (`P3-06`); FQDN vhost not on wire (`P4-01`); pcap one-shot/no-rotation (`P4-27`); livegraph default-off (`P4-28`); no conversation-graph reset (`P4-29`); per-rule `apply_dir` dead config (`P3-14`).
**Runtime:** FIM limited to open(2) — no rename/delete/attrib (`P3-17`); un-isolate teardown (`P3-30`); detection-set gaps — ssh family, `/etc/hosts`/`/etc/resolv.conf` (`P4-04/05`); exec-tracepoint attach warn-only, no `/proc` fallback (`P4-06`).
**Compliance:** GDPR framework missing (`P4-15`) — add `FrameworkGDPR` + map existing CoreMappings.
**Scanning:** repo-catalog pagination single-page for ACR/Quay/OpenShift + GHCR org packages invisible (`P3-25`); vulnDB bundle-change rescan revalidation post-vulndb-drop (`P3-26`).
**Platform:** no usage telemetry/version check (NV phones home; Constellation uses Prometheus — arguably a strength for air-gap); `constellationctl` lacks response-rule/receiver CRUD subcommands.
**UX:** bespoke pages skip design system (GroupsPage, VulnProfilePage, FederationPage, RiskDetailPage — no PageHeader/standard states); raw `<table>` outside DataTable (ImageScanDetail, ServerlessFunctionDetail, Compliance, Integrations, ConnectorCoverage); inconsistent Suppress/Accept buttons on FindingDetailPage; notification bell is findings-only (no runtime/response inbox); no fleet/org aggregate dashboard (M2); command palette live-search omits workloads/serverless/repos (M6); no saved-views/bulk-triage; no per-cluster coverage gap view; no reporting/export UI; no guided onboarding.

---

# Appendix A — How we validate enforcement (test harness)

A recurring need across Phase 1/3: prove blocking, not just alerting. Build a small reusable e2e harness:

- [ ] **Test workloads** (`deploy/e2e/parity/`): a Deployment with a known process baseline, a pod that execs a not-in-baseline binary, a pod that writes a protected file, a pod that makes disallowed egress, a pod running a known-vulnerable image, a pod triggering a WAF signature.
- [ ] **Assertions:** for each, assert the *verdict* is `blocked` (not `observed`/`alert`) in `/api/v1/findings` / `/audit/events` when the group is in Protect mode, and `alert` when in Monitor.
- [ ] **CNI matrix:** run on flannel (inline dp path) and Cilium (CNI-native path) to cover both enforcement models (post D-1).
- [ ] **Wire into CI** as an opt-in job (needs a real cluster; the current e2e uses k3s).

# Appendix B — Migrations introduced by this plan (track for the migrate job)

- CMP-CLOBBER-03: replace `110_compliance_checks_unique.sql` partial index with a composite unique index (`+ cluster_id, node`).
- RT-MATCH-16: process-baseline bundle columns (`path`, `sha256`, `parent_name`).
- SIG-ROOTS-38: sigstore roots-of-trust table.
- CMP-REM-32: `compliance_checks.remediation` column.
- Any auth-policy fields (AUTH-LOCKOUT-17) live inside the existing `SecurityPolicy` row (no migration).

> **Deploy note:** this repo deploys with `--no-hooks`, which skips the migrate job. Every migration above MUST be applied via the `constellation-migrate` image (`goose up`) or auth-style drift will recur (see the 2026-08 auth outage). Pin `migrate.image.tag` and run the migrate Job as part of any release carrying these.

---

# Appendix C — Suggested sequencing & rough sizing

| Phase | Items | Rough size |
|---|---|---|
| **1 — Turn it on** | RT-ENFORCE-01, RT-KILL-02, CMP-CLOBBER-03, RSP-WEBHOOK-04, RSP-AUDIT-05, UX-06…10, (pull in NET-BACKUP-44) | ~1–2 wks, low risk |
| **2 — Creds/SIEM/hardening** | REG-11/12/13, SIEM-14, RT-ARGV-15, RT-MATCH-16, AUTH-17/18/19/20 | ~3–4 wks |
| **3 — Deep enforce/scale** | NET-INLINE-21/22, NET-QUAR-23, RBAC-NS-24, FED-JOIN-25 (after D-1) | ~4–8 wks, includes design |
| **MED backlog** | ADM/CMP/REG/NET/RT/FED items 26–53 | ongoing |
| **LOW backlog** | polish/long-tail | opportunistic |

**Do first, always:** decision **D-1** (enforcement model) — it changes the shape of NET-INLINE-21/22 and NET-QUAR-23.
