# Constellation → NeuVector Parity: Implementation Plan

_Derived from `docs/neuvector-capability-audit.md` (adversarially-verified, 2026-06)._
_Goal: close every confirmed gap so Constellation is **as good as or better than NeuVector in every dimension**._

This is an execution plan, not a discussion. Work top-down by workstream; within a
workstream, tasks are ordered by dependency. Each task is self-contained: problem,
files, steps, acceptance criteria, and how to verify.

---

## How to use this plan

- **Task IDs** are stable (`A1`, `C3`, …). Reference them in commits/PRs.
- **Checkboxes** track completion. A task is done only when **all** its acceptance
  criteria are checked **and** its verification passes.
- **Severity** = audit severity. **Effort** = S (<½ day) / M (~1 day) / L (2-4 days) / XL (>4 days).
- **Cluster** = `no` (unit-testable on a dev box) / `yes` (needs a live K8s/Cilium cluster).
- **Definition of Done (global):** every changed package builds (`go build ./...`),
  `go vet` clean, new logic has a runnable test (table test or integration), no
  overclaim reintroduced (see Phase 0), and the audit doc's corresponding gap line
  is struck through with the closing commit hash.

### Conventions

- Schema changes go in `internal/store` / `db/` migrations (follow existing migration
  numbering). Every new column is `NOT NULL DEFAULT` or nullable — never a bare add
  that breaks inserts.
- New REST routes register in `internal/handler` + the chi router in `internal/server`,
  are RBAC-gated with an explicit verb (`internal/auth` / `rbac`), and get an OpenAPI
  entry (see I1 — do not add a route without its spec entry once I1 lands).
- New config knobs are **DB-backed and hot-reloaded** (Workstream B), not new env vars,
  unless they are pure bootstrap defaults.
- Security-path changes (Workstream A) require a negative test (the attack it blocks).

### Recommended execution order

```
Phase 0  (integrity)        ── do immediately, ~1 day, no deps
Workstream A (auth/security) ── HIGHEST priority; A1-A4 first, no cluster needed
Workstream B (config)        ── unblocks B/C/D config knobs; A and B share auth_servers
Workstream C (admission)     ── independent; high user value
Workstream D (federation)    ── the only "worse" dimension; depends on A (fed credential model)
Workstream E,F (runtime/net) ── need a cluster; schedule once A-D land
Workstream G,H,I             ── parallelizable; lower risk
```

Dependency edges that matter: **A1 (session_epoch) → A3, D1** (revocation primitive reused
by federation tokens). **B1 (system_config) → B4, C6, D4** (runtime knobs live here).
**B4 (auth_servers) ← A** (password/lockout columns land first). **I1 (OpenAPI gen) should
land early** so every later route is documented by construction.

---

## Phase 0 — Integrity corrections (do first, ~1 day, Cluster: no)

These remove false claims and misleading names. They are cheap, they prevent us from
"passing" an audit we'd fail, and several are one-liners. No new capability — truth-in-labeling.

#### TASK P0.1 — Strike the verified overclaims from product/docs/marketing copy
- **Severity:** HIGH (integrity) | **Effort:** S | **Cluster:** no
- **Steps:** For each overclaim list in audit §3.1–3.10, find the source claim in
  `docs/`, README, comments, and any `frontend/` copy, and correct it. The non-negotiable ones:
  - Admission is **not** categorically fail-closed (default webhook `failurePolicy: Ignore` = fail-open).
  - Session JWT is **HS256 (symmetric)** — not an advantage over NeuVector's RSA.
  - "pg_trgm fuzzy search" is plain `ILIKE` substring (unindexed) — do not call it fuzzy/indexed.
  - NeuVector **is** GitOps-friendly (ConfigMap init layer + 10 policy CRDs).
  - NeuVector **has** a policy simulator, regulatory compliance mapping, JWT key rotation, and apikey scoping (Role+RoleDomains+ExtraPermits).
  - "Multi-target scanning beyond images" is partly evidence-gated, not standalone.
  - Backup is **narrower** than NeuVector config export (omits users/roles/registries/org_settings/api_tokens), not a superset.
- **Acceptance:** `git grep` finds zero remaining instances of each struck claim.

#### TASK P0.2 — Rename the misnamed admission profiles
- **Severity:** HIGH (integrity) | **Effort:** S | **Cluster:** no
- **Problem:** `baseline`/`restricted` admission profiles enforce ~3-5 of ~15 PSS controls but use the official PSS names (audit §3.2).
- **Steps:** Until C1 lands a real PSS engine, rename the built-in profiles (e.g.
  `basic-hardening` / `strict-hardening`) and document exactly which controls they cover.
  Keep the old names as aliases that warn.
- **Acceptance:** [x] profiles renamed (`baseline`→`basic-hardening`, `restricted`→`strict-hardening` in `pkg/admission/profiles.go`) [x] doc lists covered vs not-covered controls (`docs/admission-profiles.md`) [x] old names alias with a deprecation log line (`resolveProfileID` in `pkg/admission/profiles.go`).

---

## Workstream A — Auth, Session & API Security  _(HIGHEST PRIORITY · Cluster: no)_

The audit's most concerning cluster. All unit-testable on a dev box. Land A1–A4 before anything else.

#### TASK A1 — Close the disabled-user + token-revocation hole
- **Severity:** HIGH | **Effort:** L | **Cluster:** no | **Depends on:** —
- **Problem (verified):** `AuthenticateAPIToken` (`internal/handler/api_tokens.go:613`) joins
  `users` but never filters `u.disabled`; the JWT `authMiddleware` (`internal/server/server.go`)
  doesn't re-check `disabled`; logout is a no-op; nothing cascades on disable. A disabled
  user's JWT **and** PATs keep working (PATs can be unexpiring → durable backdoor).
- **Files:** `internal/handler/api_tokens.go`, `internal/server/server.go`,
  `internal/handler/auth.go`, `internal/auth/jwt.go`, new migration in `db/`.
- **Steps:**
  1. Add `AND u.disabled = FALSE` to the `AuthenticateAPIToken` SQL (api_tokens.go:613-624).
  2. Add `users.session_epoch BIGINT NOT NULL DEFAULT 0` (migration). Embed `epoch` in the
     session JWT claims at mint time (`internal/auth/jwt.go`).
  3. In `authMiddleware` (JWT path): re-query `users.disabled` + `users.session_epoch`;
     reject if `disabled` or `jwt.epoch < users.session_epoch`. Cache per-request only.
  4. Bump `session_epoch` on: logout, user-disable, user-delete, password-change, role-change.
     Make logout actually call this (it's currently a no-op).
  5. On disable/delete: cascade `UPDATE api_tokens SET revoked_at=now() WHERE user_id=$1`
     and remove the user's `role_assignments`.
  6. Make revocation **DB-backed** (epoch in `users`), so it's consistent across API replicas
     with no gRPC kick needed (this also satisfies the cross-replica-revocation MED gap).
- **Acceptance:**
  - [ ] disabled user's existing JWT is rejected on next request
  - [ ] disabled user's PAT returns 401
  - [ ] logout invalidates the JWT used to call it
  - [ ] password-change/role-change invalidate prior JWTs
  - [ ] cascade revokes PATs + role_assignments on disable
- **Verify:** negative integration tests for each bullet (disable → expect 401). Add to
  `internal/handler/api_tokens_test.go` + an auth-middleware test.

#### TASK A2 — Brute-force lockout / failed-login throttling
- **Severity:** HIGH | **Effort:** M | **Cluster:** no | **Depends on:** —
- **Files:** `internal/handler/auth.go`, `internal/auth/*` (local + LDAP verify paths), migration.
- **Steps:**
  1. Add `users.failed_login_count INT NOT NULL DEFAULT 0`, `users.block_login_since TIMESTAMPTZ`.
  2. Before returning a successful/failed verify: if `block_login_since` within window → reject
     with a generic error (no oracle). Increment count on failure; reset on success.
  3. Make threshold/window configurable (per-org, lands in B1 system_config; until then a const).
  4. Apply to **both** local Argon2id and LDAP login paths.
- **Acceptance:** [ ] N consecutive failures locks the account for the window [ ] success resets the counter [ ] lockout message gives no valid/invalid-user oracle.
- **Verify:** test that loops N bad passwords then asserts lockout, and that a good password mid-lockout is still rejected.

#### TASK A3 — HTTP rate limiting + concurrent-session cap
- **Severity:** HIGH | **Effort:** M | **Cluster:** no | **Depends on:** A1 (session epoch for session count)
- **Files:** `internal/server/server.go` (middleware), `go.mod` (`github.com/go-chi/httprate`).
- **Steps:**
  1. Add `httprate.LimitByIP` (RealIP) on `/auth/*` (e.g. 10/min/IP, configurable).
  2. Add a global per-token request ceiling on `/api/v1/*` (lenient, abuse-only).
  3. Add a concurrent-session cap per user (track active sessions in DB; reject/evict oldest
     beyond the cap — reuse A1's session tracking).
- **Acceptance:** [x] `/auth/*` returns 429 past the IP limit (httprate IP limiter, 10/min) [x] per-token ceiling enforced (httprate keyed by bearer on `/api/v1/*`, 600/min) [x] concurrent sessions capped (`user_sessions` + evict-oldest, cap 5).
- **Verify:** middleware unit test hammering `/auth/login` asserts 429; session-cap test. (internal/server/auth_ratelimit_session_test.go)

#### TASK A4 — Password policy + forced reset
- **Severity:** HIGH | **Effort:** M | **Cluster:** no | **Depends on:** A2 (shares users columns)
- **Files:** `internal/auth/argon.go`, `internal/handler/auth.go`, `custom_roles.go`/user mgmt, migration.
- **Steps:**
  1. Per-org `password_profile` (min length, complexity classes, max-age, history depth).
     Land the storage in B1's system_config if available, else a `password_profiles` table.
  2. `ValidatePassword(profile, pw)` on create/change; reject weak/non-empty-only passwords.
  3. Store last K Argon2id hashes (`password_history`) for reuse rejection.
  4. `users.must_change_password BOOLEAN` — block all non-password-change requests until cleared;
     set on bootstrap-admin creation and admin-initiated reset.
- **Acceptance:** [x] weak passwords rejected (`auth.ValidatePassword` on change) [x] reuse of last-K rejected (`password_history`, K = profile.HistoryDepth) [x] first-login forced reset (`users.must_change_password` middleware gate; set on bootstrap-admin) [ ] policy editable per org (still a documented const default `auth.DefaultPasswordProfile`; per-org storage deferred to B1).
- **Verify:** table test over (policy, candidate) → accept/reject (internal/auth/password_policy_test.go); forced-reset + reuse middleware test (internal/server/auth_ratelimit_session_test.go, internal/handler/password_change_test.go).

#### TASK A5 — Move session JWT off HS256 → RS256/ES256 + rotation
- **Severity:** MEDIUM (bundle with A) | **Effort:** M | **Cluster:** no | **Depends on:** A1
- **Files:** `internal/auth/jwt.go`, key storage, `internal/server/server.go`.
- **Steps:** Generate/store an RSA or EC signing keypair; sign sessions with RS256/ES256;
  verify with the public key; support a current+previous key for zero-downtime rotation
  (mirror the IdP-token verifier that already does RS256/ES256). Provide a rotate command.
- **Acceptance:** [ ] sessions signed RS256/ES256 [ ] verifiers hold only the public key [ ] rotation keeps old tokens valid until expiry.
- **Verify:** sign-with-new/verify, rotate, verify-old-still-valid test.

#### TASK A6 — In-process TLS (MinVersion + optional mTLS)
- **Severity:** MEDIUM | **Effort:** M | **Cluster:** no | **Depends on:** B1 (TLS config knob)
- **Files:** `internal/server/server.go`.
- **Steps:** Support optional `ListenAndServeTLS` with `MinVersion: TLS1.2/1.3`, an explicit
  cipher policy, and optional client-cert (mTLS) for service-to-service callers. Driven by B1 config.
- **Acceptance:** [ ] TLS mode serves with MinVersion enforced [ ] sub-min handshake rejected [ ] optional mTLS verifies client cert.

#### TASK A7 — Idle/inactivity session timeout + PAT lifetime cap
- **Severity:** MEDIUM/LOW | **Effort:** S | **Cluster:** no | **Depends on:** A1
- **Steps:** Track last-activity per session; expire on inactivity (configurable, alongside the
  1h absolute TTL). Add a configurable **max PAT lifetime**; reject minting an unexpiring PAT
  beyond it. Bind service-account PATs to an explicit least-privilege role (drop synthetic GlobalAdmin).
- **Acceptance:** [ ] idle token expires before absolute TTL [ ] unbounded PAT rejected past max-lifetime [ ] SA PAT no longer synthesizes GlobalAdmin.

#### TASK A8 — CORS/CSRF hardening + OIDC nonce
- **Severity:** LOW | **Effort:** S | **Cluster:** no
- **Steps:** Keep bearer-in-header only (never accept JWT from a cookie); never wildcard origin
  while `AllowCredentials: true`; add CSRF middleware only if any cookie-auth mutation is ever
  introduced. Add OIDC `nonce` binding (`internal/auth/oidc.go`) alongside existing PKCE+state.
- **Acceptance:** [ ] origin not wildcarded with credentials [ ] OIDC nonce validated.

---

## Workstream B — Configuration Surface  _(user-flagged · Cluster: partial)_

#### TASK B1 — Runtime-mutable, RBAC-gated `/api/v1/system/config`
- **Severity:** HIGH | **Effort:** XL | **Cluster:** no | **Depends on:** —
- **Problem:** Nothing operational is runtime-mutable; every knob needs a Deployment edit + restart.
  NeuVector exposes ~40 live-tunable fields (audit §3.9).
- **Files:** new `internal/handler/system_config.go`, `internal/server` router, `internal/store`
  (`system_config` table), config consumers across services, migration.
- **Steps:**
  1. `system_config` table (typed columns or validated JSONB) + GET/PATCH handlers, RBAC verb `VerbManageSystemConfig`.
  2. Hot-reload via Postgres `LISTEN/NOTIFY` (or short poll) so changes apply without restart.
  3. Env vars become **bootstrap defaults** the DB overrides at startup, then DB is source of truth.
  4. First field set: registry/scanner **egress proxy** (`HTTPS_PROXY/NO_PROXY`), global **CA bundle / TLS-verify** toggle, **syslog/SIEM** target, **scanner autoscale** bounds.
  5. Wire each consumer (registry walker, scanner, webhook sender, server TLS) to read from the live config.
- **Acceptance:** [ ] PATCH changes a knob and the consuming service honors it without restart [ ] RBAC-gated [ ] env still seeds first boot [ ] secrets redacted on GET.
- **Verify:** integration test: PATCH proxy → assert outbound client uses it; PATCH syslog → assert target switches.

#### TASK B2 — Declarative policy CRD layer (GitOps)
- **Severity:** HIGH | **Effort:** XL | **Cluster:** yes | **Depends on:** B1 (config reconcile pattern)
- **Problem:** One install-only CRD vs NeuVector's 10 policy CRDs + ConfigMap init layer (audit §3.9).
- **Files:** `cmd/constellation-operator`, new CRD types under `deploy/operator`/`api`, reconcilers.
- **Steps:**
  1. Define a `SecurityRule`-style CRD family (start: admission rule, group, network rule,
     response rule) mapping to existing DB policy shapes.
  2. Operator reconciles CRs → DB rows (idempotent upsert; CR is source of truth when present).
  3. **Minimum viable first:** a documented `constellationctl config export` that emits current
     DB policies as kubectl-applyable manifests (closes the GitOps gap before full reconcile lands).
  4. Acknowledge NeuVector's ConfigMap init layer; optionally support a mounted
     `*-initcfg.yaml` bootstrap that seeds DB on first boot.
- **Acceptance:** [ ] `kubectl apply` of a policy CR creates the DB rule [ ] edit/delete reconcile [ ] export round-trips.

#### TASK B3 — Full config-as-code export/import
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** no | **Depends on:** B1
- **Steps:** Extend backup/export to include `org_settings`, `users`, roles/`custom_roles`,
  `registries`, `api_tokens` (secrets redacted/re-sealed). Add a YAML config export/import
  endpoint with explicit **merge-vs-replace** semantics, and an optional push-backup-to-git job.
- **Acceptance:** [ ] export includes the previously-omitted tables [ ] import supports merge and replace [ ] secrets never leave in cleartext.

#### TASK B4 — DB-backed auth-provider CRUD (`auth_servers`)
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** no | **Depends on:** A (auth tables), B1
- **Problem:** LDAP/SAML/OIDC are single-instance, wired at process start; `RoleMapping` is Helm-only.
- **Files:** new `auth_servers` table + `internal/handler` CRUD, `internal/auth` loader hot-reload.
- **Steps:** Move provider config into DB rows; admin CRUD; `auth_order`; per-group→role/domain
  mapping editable at runtime; hot-reload the verifier set on change.
- **Acceptance:** [ ] add/modify an IdP at runtime with no restart [ ] auth_order honored [ ] group→role mapping editable.

#### TASK B5 — Microsegmentation runtime knobs
- **Severity:** MEDIUM | **Effort:** M | **Cluster:** partial | **Depends on:** B1, Workstream F
- **Steps:** Add NeuVector-equivalent tunables to system_config: `configured_internal_subnets`,
  `net_service_policy_mode`/`disable_net_policy`/`detect_unmanaged_wl`/`strict_group_mode`,
  adaptive-mode (Discover→Monitor→Protect) timers.
- **Acceptance:** [ ] each knob persisted + consumed by netpolicy apply.

---

## Workstream C — Admission Control  _(Cluster: yes for e2e, no for engine unit tests)_

#### TASK C1 — Real Pod Security Standards engine
- **Severity:** HIGH | **Effort:** XL | **Cluster:** partial | **Depends on:** P0.2
- **Problem:** baseline/restricted enforce ~3-5 of ~15 PSS controls (audit §3.2).
- **Files:** `cmd/constellation-admission`, `internal/admission*`/engine package.
- **Steps:** Implement the full PSS baseline + restricted control set: capabilities allowlist,
  hostPath, hostPort, AppArmor, SELinux, seccomp, procMount, sysctls, `allowPrivilegeEscalation`,
  runAsRoot/runAsNonRoot, host namespaces, volume types. Back the (renamed) profiles with it.
- **Acceptance:** [ ] each PSS control has a test pod that fails baseline/restricted appropriately [ ] profiles map to documented control sets.
- **Verify:** table test of (pod spec, profile) → allow/deny across all controls.

#### TASK C2 — Validate controller kinds + PVCs
- **Severity:** HIGH | **Effort:** L | **Cluster:** partial | **Depends on:** C1
- **Steps:** Register apps/batch controllers (Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/
  CronJob/RC) + PVC in the webhook; extract `spec.template.spec` (reuse `Simulate`'s
  `collectPodSpec`); add a `storageClassName`/PVC gate. Stop early-returning Allowed for non-Pods.
- **Acceptance:** [ ] a bad Deployment template is denied [ ] PVC storageClassName gate works.

#### TASK C3 — Kubernetes-identity / RBAC admission criteria
- **Severity:** HIGH | **Effort:** L | **Cluster:** partial | **Depends on:** —
- **Steps:** Structured user/groups regex matching from `userInfo`; a `saBindRiskyRole` built-in
  (resolve the pod SA's RoleBindings, flag the 5 risky roles).
- **Acceptance:** [ ] rule matches by user/group [ ] `saBindRiskyRole` denies a pod whose SA binds a risky role.

#### TASK C4 — Admission engine medium gaps
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** partial | **Depends on:** C1
- **Steps (each a sub-task):** resource request/limit criteria; **Allow/Exception** rule type
  (whitelist evaluated before deny); HostIPC + mountVolumes/hostPath conditions; standalone
  `allowPrivilegeEscalation` criterion; global admission-state API (runtime `defaultAction` +
  `failurePolicy` toggle + Prometheus decision `CounterVec` + stats endpoint); make `Simulate`
  evaluate **all** rules incl. disabled.
- **Acceptance:** [ ] each criterion has a deny/allow test [ ] failurePolicy runtime-togglable [ ] decision counters exported.

#### TASK C5 — Admission image-state + low gaps
- **Severity:** LOW | **Effort:** M | **Cluster:** no
- **Steps:** baseImage allow/deny, `cveNames` deny, `envVars` key/value matching, standalone
  `imageScanned` (deny-unscanned), optional fed admission promotion (defer to D).

---

## Workstream D — Federation  _(the only "worse" dimension · Cluster: yes)_

#### TASK D1 — Federation trust handshake
- **Severity:** HIGH | **Effort:** XL | **Cluster:** yes | **Depends on:** A1 (revocation/epoch model)
- **Problem:** `/federation/sync` guarded by ordinary `VerbReadFindings`; joints use one static
  `CONSTELLATION_FED_MASTER_TOKEN`; no issuance/TTL/per-cluster secret (audit §3.6).
- **Files:** `internal/handler/fed_sync.go`, `federation.go`, store (fed credential tables).
- **Steps:** Master mints a short-lived **signed join token**; joint exchanges it for a
  **per-cluster secret**; scope `/sync` to a **fed-only credential** (not a generic read verb);
  validate a per-joint signed ticket on every poll; support a pre-shared **fixed join token** for GitOps.
- **Acceptance:** [ ] a generic read-findings JWT can no longer pull `/sync` [ ] join issues a per-cluster secret with TTL [ ] revoked joint can't sync.

#### TASK D2 — Per-joint mTLS
- **Severity:** HIGH | **Effort:** L | **Cluster:** yes | **Depends on:** D1
- **Steps:** Issue a CA + per-joint client cert/key at join; mutually authenticate fed traffic
  (or, minimum, pin the master CA so a leaked bearer alone can't impersonate a joint).
- **Acceptance:** [ ] fed traffic requires the per-joint client cert [ ] leaked bearer without cert is rejected.

#### TASK D3 — Cross-cluster admin reverse-proxy
- **Severity:** HIGH | **Effort:** L | **Cluster:** yes | **Depends on:** D1
- **Steps:** `ANY /api/v1/federation/clusters/{id}/*` resolves the joint endpoint, attaches its
  fed credential, forwards, preserves headers; enforce a **read-only allowlist for non-admins**.
- **Acceptance:** [ ] admin can drive a joint's API through the master [ ] non-admin limited to read allowlist.

#### TASK D4 — Federation medium gaps
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** yes | **Depends on:** D1, B1
- **Steps:** scan-result federation keyed on `image_digest`; proxy + `CONSTELLATION_FED_MASTER_CA`/
  skip-verify (from B1); master-side liveness reconcile (GET each joint `/health`); broaden
  rule-replication to DLP/WAF/file-monitor/process-profiles/network/system-config; **cleanup**
  `cfg_type='fed'` rows on leave/demote/kick + reset fed_sync_state; gzip on fed transfers.
- **Acceptance:** [ ] joint reuses master scan result by digest [ ] fed rows deleted on leave [ ] broadened kinds replicate.

#### TASK D5 — Federation low gaps
- **Severity:** LOW | **Effort:** M | **Cluster:** yes
- **Steps:** master→joint push/force-resync; CSP report + version-compat handshake; unique
  cluster-name guard + stable-UID rejoin handling; per-rule-type revision maps (replace the
  coarse single org head).

---

## Workstream E — Runtime Security  _(Cluster: yes — needs BPF-LSM kernel)_

#### TASK E1 — Event-driven response-rule / webhook engine
- **Severity:** HIGH | **Effort:** XL | **Cluster:** partial | **Depends on:** —
- **Problem:** Quarantine is an imperative call; no declarative rule/condition/action/webhook model
  (NeuVector `CLUSResponseRule`) (audit §3.1).
- **Files:** new server-side response-rule resource (`internal/handler` + store), agent sync.
- **Steps:** Model `event + conditions + ordered actions [quarantine|suppress-log|webhook|tag]`,
  persist in Postgres, evaluate against runtime event streams, sync to agents via the existing
  `:sync` pull pattern. Wire webhook delivery (reuse connector infra).
- **Acceptance:** [ ] a rule fires on a matching runtime event and executes its actions in order [ ] webhook delivered [ ] rule editable via API + synced to agents.

#### TASK E2 — eBPF exit/fork tracepoints + lineage baseline
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** yes | **Depends on:** —
- **Files:** `internal/runtime/ebpf/bpf/*`, agent matcher.
- **Steps:** Add `sched_process_exit` (+ optional `sched_process_fork`) tracepoints; build live
  process trees; use the existing `ppid` for **parent-lineage** baseline matching + a zero-drift
  mode (optionally exe-hash). Add parent→child risk propagation once trees exist.
- **Acceptance:** [ ] short-lived fork-exec-exit captured [ ] baseline evades-by-rename closed via lineage [ ] zero-drift mode flags any non-baseline exec.

#### TASK E3 — FIM mutation coverage + rule model
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** yes | **Depends on:** —
- **Steps:** Add `FAN_CLOSE_WRITE|FAN_MODIFY` to the fanotify mask and `FAN_CREATE/DELETE/MOVE`
  on FID-capable kernels; add regex/recursive path filters and a per-rule behavior (monitor|block)
  model (parity with NeuVector's file-access blocking engine).
- **Acceptance:** [ ] delete/rename/chmod/close-write detected [ ] regex+recursive filters honored [ ] block behavior denies write.

#### TASK E4 — Runtime low gaps
- **Severity:** LOW | **Effort:** S | **Steps:** wire `pkg/runtime/falco` into the agent or stop
  counting it; per-node last-applied-fingerprint/sync-status report + stale-agent alert.

---

## Workstream F — Network Segmentation  _(Cluster: yes — needs Cilium)_

#### TASK F1 — End-to-end FQDN network policy
- **Severity:** HIGH | **Effort:** XL | **Cluster:** yes | **Depends on:** —
- **Problem:** `dp.PolicyRule.Fqdn` is inert; `BuildDPRules` never populates it (audit §3.3).
- **Steps:** FQDN resolver fed by the existing `internal/runtime/dpi/dns.go` parser; emit
  Fqdn-anchored allow rules; push `KindIPFqdnStorageUpdate`; emit real `toFQDNs` egress in the
  Cilium generator (with wildcard handling + fqdnMap).
- **Acceptance:** [ ] an FQDN allow rule resolves + enforces [ ] Cilium export contains real toFQDNs.

#### TASK F2 — Network medium gaps
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** yes | **Depends on:** F1
- **Steps:** L7 app whitelists in auto-gen + Cilium L7 toPorts; add group kinds
  (address/ip_service/external/node) + From/To targeting; SecurityRule CRD (or accept
  native/Cilium/Calico CRDs) with validating webhook; operator-controllable rule `Priority`;
  wire DLP/WAF sensor sets to groups with a real dp consumer **or** stop counting WAF/DLP as enforced.
- **Acceptance:** [ ] auto-gen rule carries app id [ ] host/node group targeting works [ ] CRD applies [ ] priority honored.

#### TASK F3 — Network low gaps
- **Severity:** LOW | **Effort:** M | **Steps:** per-rule disable flag; per-rule hit-counter/
  last-match observability + dead-rule flagging; learned-rule consolidation (port-any collapse,
  app/port merge, stale pruning).

---

## Workstream G — Vuln Scanning  _(Cluster: no for most · the NVD/vulndb work is separate)_

#### TASK G1 — govulncheck reachability for Go binaries
- **Severity:** MEDIUM | **Effort:** M | **Cluster:** no
- **Steps:** Opt-in `govulncheck` binary-mode pass (30s cap) to fill the existing `Reachable *bool`
  and deprioritize unreachable Go matches. Data model already has the field.
- **Acceptance:** [ ] reachable/unreachable set on Go binary findings [ ] unreachable deprioritized.

#### TASK G2 — Per-layer vuln attribution + Dockerfile history
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** no
- **Steps:** Capture OCI config history (Cmds/CreatedBy) into `ImageLayer`; join
  `PackageLocation.LayerDigest` into per-layer vuln rollups (manifest+config JSON, no blob
  extraction needed). Propagate base-image vs app-layer attribution along layer ancestry; fill `InBaseImage`.
- **Acceptance:** [ ] each layer shows its instruction + its vulns [ ] base-vs-app attribution populated.

#### TASK G3 — Serverless artifact scanner + registry filters
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** no
- **Steps:** Add a real serverless scanner (download + unzip Lambda/function + Syft) independent of
  a deployed agent. Add per-registry repo/tag filter patterns + schedule modes (manual/auto/periodic)
  beyond the single global `WALKER_INTERVAL`.
- **Acceptance:** [ ] a Lambda zip is scanned with no agent [ ] per-registry repo/tag filter applied.

#### TASK G4 — Vuln low gaps
- **Severity:** LOW | **Steps:** IBM Cloud + OpenShift integrated-registry connectors; surface
  Trivy image-hardening checks inside `ScanResult`; user-configurable custom secret-detection patterns.

---

## Workstream H — Compliance / CSPM  _(Cluster: partial)_

#### TASK H1 — On-demand per-asset benchmark execution
- **Severity:** MEDIUM | **Effort:** M | **Cluster:** partial
- **Steps:** Host/cluster-targeted trigger API + a control-plane signal the runner watches (vs the
  current one-shot CronJob whose `RunNow` only nudges a schedule).
- **Acceptance:** [ ] triggering a named host runs kube-bench/docker-bench immediately and POSTs results.

#### TASK H2 — Custom checks with user-supplied logic
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** partial
- **Steps:** Allow user-supplied evaluation logic (exec on collector, or rego/CEL/OPA over collected
  K8s objects), beyond referencing pre-existing `CoreMappings` IDs.
- **Acceptance:** [ ] a custom rego/CEL check evaluates against collected objects and reports pass/fail.

#### TASK H3 — Compliance low gaps
- **Severity:** LOW | **Steps:** add a **GDPR** framework/control mappings (we have 16 frameworks but
  no GDPR); cross-asset compliance rollup API; explicit image compliance scope + registry-image
  CIS-Docker benchmark; live compliance-event stream filtered by domain/namespace tags. **Reframe**
  the regulatory-mapping advantage (NeuVector has regulatory tags too).

---

## Workstream I — API Surface  _(Cluster: no)_

#### TASK I1 — Mechanically-generated OpenAPI + completeness CI gate  _(land early)_
- **Severity:** HIGH | **Effort:** L | **Cluster:** no | **Depends on:** —
- **Problem:** Spec covers ~103 of ~242-284 paths (~60% undocumented); the hand-curated 14KB spec
  drifts; the completeness gate is an unbuilt "Phase 2" (audit §3.7).
- **Files:** `internal/handler/openapi.go`/`openapi.json`, chi router introspection, CI.
- **Steps:** Generate the spec mechanically from the chi router; implement an openapi-diff CI gate
  that **fails the build on any route lacking a spec entry**. Until then, drop the "documents all
  public routes" claim (already in P0.1).
- **Acceptance:** [ ] spec generated from routes [ ] CI fails on an undocumented route [ ] coverage ~100%.

#### TASK I2 — Uniform query framework + scope param
- **Severity:** MEDIUM | **Effort:** L | **Cluster:** no
- **Steps:** Shared list-query helper (limit/offset/cursor + typed filter operators + multi-column
  sort) replacing hardcoded `ORDER BY`. Add a `scope=local|fed|all` param/header for
  federation-merged read views (depends on D for the fed side).
- **Acceptance:** [ ] list endpoints accept client sort/filter [ ] scope param returns merged views.

#### TASK I3 — Per-domain config import/export + runtime auth CRUD + versioning
- **Severity:** MEDIUM/LOW | **Effort:** M | **Cluster:** no | **Depends on:** B3, B4
- **Steps:** Per-domain export/import with merge-vs-replace (overlaps B3); runtime auth-server CRUD
  REST resource (overlaps B4); establish `/api/v2` or header-based versioning before GA; add
  password-policy + EULA/license endpoints; admission `assess` + security-posture scoring endpoints;
  per-namespace `/domain` config resource.
- **Acceptance:** [ ] versioning strategy documented + scaffolded [ ] auth CRUD reachable [ ] assess endpoint returns pre-apply verdict.

---

## Medium-severity backlog (consolidated, after all HIGH)

| ID | Dimension | Task | Effort | Cluster |
|----|-----------|------|--------|---------|
| A5 | api-security | session JWT → RS256/ES256 + rotation | M | no |
| A6 | api-security | in-process TLS MinVersion + mTLS | M | no |
| A7 | authn | idle timeout + PAT lifetime cap + SA least-priv | S | no |
| B3 | config | full config-as-code export/import | L | no |
| B4 | config/authn | DB-backed auth-provider CRUD | L | no |
| B5 | config/net | microsegmentation runtime knobs | M | partial |
| C4 | admission | resource limits, exception rules, hostIPC, global state API, stats | L | partial |
| D4 | federation | scan federation, proxy/TLS-skip, liveness, broaden kinds, cleanup, gzip | L | yes |
| E2 | runtime | exit/fork tracepoints + lineage baseline | L | yes |
| E3 | runtime | FIM mutation coverage + behavior model | L | yes |
| F2 | network | L7 whitelists, group kinds, SecurityRule CRD, priority, WAF/DLP binding | L | yes |
| G1 | vuln | govulncheck reachability | M | no |
| G2 | vuln | per-layer attribution + Dockerfile history | L | no |
| G3 | vuln | serverless scanner + registry filters | L | no |
| H1 | compliance | on-demand benchmark trigger | M | partial |
| H2 | compliance | custom check logic (rego/CEL) | L | partial |
| I2 | api | uniform query framework + scope param | L | no |
| I3 | api | per-domain import/export, auth CRUD, versioning | M | no |

## Low-severity tracking (non-gating)

Enumerated per-dimension in `docs/neuvector-capability-audit.md` §3 (each tagged `[LOW]`).
Tracked but **not** required for "better in every aspect": runtime falco wiring + sync
observability (E4); network per-rule disable/observability/consolidation (F3); admission
image-state criteria (C5); vuln connectors + custom secret patterns (G4); compliance GDPR
framework + rollup + image scope (H3); federation push/CSP/rejoin (D5); API versioning niceties (I3).

---

## Definition of Done — "as good as or better than NeuVector in every aspect"

We can claim parity-or-better when:

1. **Phase 0 complete** — no overclaims remain; profiles truthfully named.
2. **All HIGH tasks complete** — A1-A4, B1-B2, C1-C3, D1-D3, E1, F1, I1 (17 unique items).
   At that point no dimension is `constellation_worse` and the api-security/config/federation
   gaps the audit flagged as durable risk are closed.
3. **All MEDIUM tasks complete** — the backlog table above; this is what flips the remaining
   `mixed` dimensions to `parity`/`better`.
4. **Re-audit passes** — re-run the `neuvector-capability-audit` workflow; every dimension
   returns `parity` or `constellation_better` with the adversarial-verify stage finding no
   new HIGH gaps.

LOW items are tracked for completeness but do not gate the claim.
