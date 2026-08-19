# Constellation Deficiency Audit

Adversarially-confirmed deficiencies (medium+ severity that survived a refute pass). Severities use the verifier's `verify_severity`. Near-duplicates have been merged (56 raw confirmed findings → **52 distinct deficiencies**).

## Summary

| Severity | Count |
|----------|-------|
| High     | 12    |
| Medium   | 40    |
| **Total**| **52**|

| Category        | Count |
|-----------------|-------|
| half_wired      | 18    |
| fail_open       | 10    |
| data_integrity  | 10    |
| security        | 7     |
| bug             | 6     |
| dead_code       | 1     |

| Area | Count |
|------|-------|
| compliance | 7 |
| handler-scanning | 3 |
| scanner | 4 |
| operator | 4 |
| admission | 3 |
| netpolicy | 2 |
| runtime-agent | 3 |
| auth-rbac | 3 |
| backup-restore-cli | 3 |
| notify-response-risk | 4 |
| migration-misc-cmd | 3 |
| helm-deploy | 2 |
| hostscan | 2 (merged with xcut host-scan) |
| server | 2 |
| handler-runtime | 2 |
| handler-findings-network | 2 |
| handler-core | 1 |
| frontend | 1 |
| xcut (half-wired/security/data-integrity) | merged into the above |

## Themes (systemic patterns)

1. **Pervasive "half-wired" features (18/52).** The single largest pattern: a control is fully declared, validated, persisted, RBAC-advertised and surfaced in the UI/OpenAPI, but the enforcement leg is never connected. Examples span every subsystem: response-rule `suppress_log`/`tag` actions, `response_rules_v2` notify/ticket, vulnerability-profile suppress/accept/escalate decisions, workload micro-segmentation never pushed to `dp`, FQDN egress (two independent dead ends), the operator's policy-CR reconcilers with no ClusterRole, OIDC group→role mapping, authenticated file downloads, and the StackRox/NeuVector Kyverno emitters. Operators configure security behavior that silently no-ops. **Mitigation pattern:** add a wiring/"feature-reachability" test that asserts each advertised action/decision reaches an enforcement side-effect, and stop advertising actions that aren't enforced.

2. **Recurring fail-open in detection & enforcement (10/52).** Security controls pass/admit on the error path or an unhandled edge instead of failing closed: CEL/Rego eval errors become warnings (pod admitted), synchronous deny-path DB writes time out under `failurePolicy: Ignore` (deny→admit), the admission quarantine DSN crash bypasses the webhook entirely, CIS file-mode uses numeric `<=` so world-readable `/etc/shadow` "passes", AWS IAM wildcard detection matches plain JSON against URL-encoded policy, CSPM swallows partial scanner failure and skips pagination, `RequireVulnDB` is bypassed on empty SBOM, backup restore never verifies the signature, accept-risk takes arbitrary dates, and queue-full notifications are dropped forever. **Mitigation pattern:** default to deny/error on any unverifiable or exceptional path; treat "skipped/absent" the same as "failed" for required gates.

3. **Missing org/cluster scope on multi-tenant paths (data-integrity + cross-tenant).** Scope is repeatedly derived from the wrong source or omitted: backup-restore writes into the org named *in the uploaded tarball* (cross-tenant compromise), host-scan/host-CIS handlers attribute every node to the org's *oldest* cluster (overwrite + NULL-cluster duplicate growth), crashloop detection counts restarts with no `org_id` filter (cross-tenant false alarms), the evidence-collector applies cluster-scoped exemptions org-wide, and the audit hash chain reads a "moving head" row under READ COMMITTED. **Mitigation pattern:** always key writes/reads on the authenticated subject's org/cluster (never on attacker-supplied content or "first row"), and make uniqueness/serialization NULL-safe and contention-safe.

---

## High-severity findings

### H1. Server backup-restore writes into the org named in the uploaded tarball (cross-tenant write / privilege escalation)
- **Severity:** high  **Category:** security  **Area:** backup-restore-cli
- **File:** internal/handler/backup.go:406 (pkg/backup/restorer.go:138,279-318)
- **Failure:** A tenant admin with `VerbManageOrg` in org A POSTs `/api/v1/backups/restore?on_conflict=overwrite&allow_unverified=true` with a crafted tarball whose `tables/orgs.jsonl` names `victim-org`. `upsertOrg` matches/creates that org by name and writes attacker rows (users, role_bindings, policies, registries) under the victim's org_id — full cross-tenant compromise. Also an intra-org privesc: unlike `ApplyConfig`, the restore path doesn't gate identity tables behind `CanManageUsers`.
- **Fix:** Scope restore to the caller — require the archive org to match `subj.OrgID`, pass `subj.OrgID` into `Restore`, and never derive the write-target org from archive content.

### H2. IdP secrets (OIDC client secret, LDAP bind password, SAML SP key) stored unencrypted
- **Severity:** high  **Category:** security  **Area:** auth-rbac
- **File:** internal/auth/authservers.go:215 (and UpdateAuthServer:247)
- **Failure:** `CreateAuthServer`/`UpdateAuthServer` `json.Marshal` `srv.Config` (BindPassword/ClientSecret/SPKeyPEM, all marked `// SECRET`) straight into the `config` JSONB column. Redaction is GET-only. Anyone with DB read (backup, replica, SQLi sink, compromised role) recovers cleartext IdP credentials and can impersonate the SP — while the same deployment seals registry creds and the fed-CA key under the install KEK.
- **Fix:** Seal the secret-bearing fields with the same cipher used by registries/fed-CA before INSERT; `Open()` in `BuildProviders`/`toXConfig`.

### H3. CIS file-permission checks use numeric mode comparison (world-readable /etc/shadow passes)
- **Severity:** high  **Category:** fail_open  **Area:** hostscan
- **File:** internal/runtime/hostscan/cis.go:300
- **Failure:** `checkFileModeMax` does `mode <= maxMode` on raw permission bits — a magnitude test, not a subset test. `/etc/shadow` at `0604` (world-READABLE hashes) = 388 ≤ 416 = `0640` → **pass**; `0606` (world-writable) and `/etc/passwd 0622` likewise pass. Nodes report CIS-compliant while shadow/passwd are world readable/writable.
- **Fix:** Use `mode &^ maxMode.Perm() == 0` so any bit outside the allowed mask fails.

### H4. AWS IAM inline wildcard-policy detection is fail-open (policy is URL-encoded, matcher expects plain JSON)
- **Severity:** high  **Category:** fail_open  **Area:** compliance
- **File:** internal/cspm/aws/aws.go:135 (isWildcardGrant:246-254)
- **Failure:** `GetRolePolicy` returns the document URL-encoded (per the SDK), but `isWildcardGrant` substring-matches `"effect":"allow"`/`"action":"*"`/`"resource":"*"`. The percent-escaped form never matches, so a role with inline `Allow */*` never emits the critical `aws-iam-wildcard` finding; the account is reported clean. The unit test passes only because the fake feeds decoded JSON.
- **Fix:** `url.QueryUnescape` (or `json.Unmarshal` + structural eval) before matching.

### H5. Vulnerability-profile decisions are computed at scan completion but never applied or consumed
- **Severity:** high  **Category:** half_wired  **Area:** handler-scanning
- **File:** internal/handler/scanning/scanjobs.go:824
- **Failure:** `Complete()` evaluates findings against active vuln profiles producing suppress_accept/suppress_defer/escalate, then only stuffs the verdict into `detail_json["vulnerability_profile"]` — read by nothing in production. Lifecycle is hard-coded `'open'` and severity/risk are computed before the decision. Suppress doesn't suppress, escalate doesn't escalate; suppressed CVEs still inflate critical/high rollups and can re-fire response rules.
- **Fix:** Apply the decision in the finding upsert (map to lifecycle `suppressed`/`accepted`, bump severity on escalate) or remove the dead evaluation.

### H6. Workload micro-segmentation policy is never pushed to dp (dp enforces with an empty rule table)
- **Severity:** high  **Category:** half_wired  **Area:** runtime-agent
- **File:** internal/runtime/dp/policy.go:109
- **Failure:** `Supervisor.PushPolicy` is the only path that programs dp's policy engine, and it has **zero** callers — the runtime agent has no policy-sync goroutine (a handler comment even references one that doesn't exist). An operator-created/promoted deny-egress or FQDN-anchored allow is stored, audited and served by the control plane but never reaches dp; dp evaluates every connection against no rules and emits the default action.
- **Fix:** Add the agent-side policy-sync goroutine: fetch the node's runtime_policies, build per-workload `WorkloadPolicy`, call `dpSup.PushPolicy(..., CmdModify)`, and push empty+`CmdDelete` on removal.

### H7. Admission quarantine DSN reads a non-existent Secret key, crashing the webhook (fail-open admission)
- **Severity:** high  **Category:** bug  **Area:** helm-deploy
- **File:** deploy/charts/constellation/templates/admission-deployment.yaml:100
- **Failure:** With quarantine enabled and `dsn` blank (the documented in-cluster default), `CONSTELLATION_QUARANTINE_DSN` is sourced from `secretKeyRef <fullname>-postgres / dsn` with no `optional: true` — but that Secret only has username/password/database; no Secret defines a `dsn` key. Every admission pod is stuck in `CreateContainerConfigError`; with `failurePolicy: Ignore` the API server bypasses the webhook → quarantine deny-list, DB-backed policies and admission audit all silently unenforced.
- **Fix:** Source from `constellation.dsnSecret`/`dsnSecretKey` (the `<fullname>-database-url`/`url` Secret) like the policy/audit DSNs.

### H8. Operator ClusterRole omits all RBAC for the policy CRs it reconciles (GitOps policy reconcile broken)
- **Severity:** high  **Category:** half_wired  **Area:** operator
- **File:** deploy/charts/constellation/templates/operator.yaml:78
- **Failure:** The operator ClusterRole grants verbs only on `constellationclusters`/status. When `--database-url` is set the AdmissionRule/ResponseRule reconcilers start and List/Watch/Update `ConstellationAdmissionRule`/`ConstellationResponseRule` (+ status/finalizers) — but no manifest grants any access. Informers fail with `forbidden: cannot list constellationadmissionrules`; the cache never syncs (can fail the whole manager), no policy CR is reconciled, and applied CRs wedge on delete.
- **Fix:** Add the policy CR kinds (get;list;watch), /status (get;update;patch), /finalizers (update) to the operator ClusterRole, matching the kubebuilder markers.

### H9. Concurrent audit writes silently break the hash chain (false tamper alarms)
- **Severity:** high  **Category:** data_integrity  **Area:** notify-response-risk
- **File:** pkg/audit/audit.go:63
- **Failure:** `Log()` serializes on `SELECT ... ORDER BY id DESC LIMIT 1 FOR UPDATE` under READ COMMITTED. After a `FOR UPDATE` wait, EvalPlanQual re-checks only the locked tuple — the `ORDER BY/LIMIT` is not re-evaluated — so a writer that blocked on row N inserts with the stale prev_hash and doesn't see the committed row N+1. The UNIQUE constraint is on `chain_hash` only, so the divergent row inserts cleanly and `VerifyChain` reports a false `prev_hash mismatch`. Normal concurrent load corrupts the tamper-evidence chain (append-only triggers make it unrepairable).
- **Fix:** Serialize on a fixed object — `pg_advisory_xact_lock(<chain key>)` or `LOCK TABLE ... IN EXCLUSIVE MODE` (or SERIALIZABLE + retry) — then read the head inside the lock.

### H10. SAML/LDAP JIT login mints a session JWT with a stale session_epoch (token dead-on-arrival)
- **Severity:** high  **Category:** bug  **Area:** handler-core
- **File:** internal/handler/auth.go:816
- **Failure:** `issueLinkedSession` reads `sessionEpoch=0` for a new JIT user, then `reconcileJITRoles` bumps `users.session_epoch` to 1 in its own transaction, then `issueSession` issues a JWT with the stale `Epoch=0`. Middleware rejects `claims.Epoch < session_epoch` → every API call returns 401 "session revoked". First SAML/LDAP/OIDC login appears to succeed but is unusable; only a second login (no role change → no bump) works. Same transient breakage hits existing SSO users whenever asserted roles change.
- **Fix:** Have `reconcileJITRoles` return the post-bump epoch (or re-SELECT it) and pass that into `issueSession`.

### H11. kube-bench compliance ingest accumulates duplicate rows every run (Summary/Checks counts drift)
- **Severity:** high  **Category:** data_integrity  **Area:** compliance
- **File:** internal/handler/compliance/compliance.go:326
- **Failure:** `Ingest` INSERTs each check with no DELETE and no `ON CONFLICT`; `compliance_checks` has no unique constraint on (org_id, framework, control_id). The 6-hourly CronJob POSTs each run, so after N runs every control has N rows. Summary `COUNT(*)`s all rows (total inflated N×; status flips counted twice) and Checks `LIMIT 500` truncates real controls behind duplicates. The k8s-object collector dedupes; the kube-bench path is the asymmetric one.
- **Fix:** Add a unique constraint on (org_id, cluster_id, framework, control_id) + `ON CONFLICT DO UPDATE`, or DELETE prior kube-bench rows in the same tx.

### H12. Collapsed external peers ("external", no slash) bypass CIDR-anchoring, breaking real external egress under enforcement
- **Severity:** high  **Category:** half_wired  **Area:** netpolicy
- **File:** internal/handler/netpolicy/network_policies.go:566
- **Failure:** Ingest collapses non-well-known external peers to bare `"external"` (real IP kept in `dst_addr`), but the read path detects externals only via `HasPrefix(dst, "external/")`. For bare `"external"` the prefix never matches: `DstIP` is never set, `tupleInclusion` returns include=true, and generation renders a `app=external` selector (matching no pod) instead of a `toCIDR`. Under protect mode Cilium default-denies the real upstream IP, breaking observed-and-allowed egress. Tests only use the un-collapsed `external/<name>` shape.
- **Fix:** Treat `dst=="external" || HasPrefix(dst,"external/")` as external in the read path and held checks before setting DstIP / clearing DstWorkload.

---

## Medium-severity findings

Grouped by area.

### Admission

#### M. Rego/CEL admission denies bypass audit logging and response-rule enforcement
- **Category:** half_wired — pkg/admission/admission.go:100
- **Failure:** `OnDeny` fires only inside `PolicyEngine.Evaluate`; `ChainEngine.Evaluate` returns a Rego/CEL deny directly without invoking any DenyHook. An enforce-mode OPA/CEL deny correctly rejects the request but writes no `admission.deny` audit row and fires no `EventAdmission` response rule (auto-quarantine/tag never runs).
- **Fix:** Have `ChainEngine` carry/invoke the DenyHook, or wire `OnDeny` into RegoEngine/CELEngine.

#### M. CEL and Rego evaluation errors fail OPEN in enforce mode
- **Category:** fail_open — pkg/admission/cel.go:91 (rego.go:90)
- **Failure:** On `Eval` error both engines append a warning and `continue`, never setting `Allowed=false`. An enforce CEL rule `object.spec.securityContext.runAsNonRoot == true` against a pod with no `securityContext` errors ("no such key") → warning → pod ADMITTED despite violating the policy.
- **Fix:** Treat an eval error on an enforce-mode rule as deny, or add a per-rule failurePolicy mirroring K8s VAP.

#### M. Synchronous OnDeny DB writes on the deny path can turn denies into admits under failurePolicy=Ignore
- **Category:** fail_open — pkg/admission/admission.go:481
- **Failure:** `onDeny` runs synchronously before the deny response (audit INSERT + uncached response-rule SELECT + possible quarantine INSERTs). Under DB latency/contention (or attacker-amplified deny load) the deny path exceeds the 5s webhook timeout; with `failurePolicy: Ignore` the API server admits the pod the rule denied. Only the deny path incurs the DB latency.
- **Fix:** Offload `onDeny` to a buffered goroutine so the verdict returns immediately.

### Auth / RBAC

#### M. OIDC `role_mapping` (group→role) is dead config
- **Category:** half_wired — internal/auth/authservers.go:413
- **Failure:** `toOIDCConfig` drops `RoleMapping`; OIDC claims extract no groups; `OIDCCallback` uses DB role_assignments only (never `MapRoles`/`reconcileJITRoles`/`issueLinkedSession` like SAML/LDAP). Admin-configured OIDC group mappings are silently ignored; IdP group de-provisioning never revokes roles.
- **Fix:** Route OIDC through `issueLinkedSession` with groups from the id_token, or reject `role_mapping` for OIDC rows.

#### M. OIDC id_token `aud` claim is never validated against ClientID
- **Category:** security — internal/auth/oidc.go:190
- **Failure:** `verifyIDToken` passes no `jwt.WithAudience` and never decodes/compares `aud` (OIDC Core 3.1.3.7 MUST). With shared-JWKS IdPs a sibling-app token (same iss/key) passes; the per-login nonce is the only remaining barrier and there's a documented empty-nonce back-compat path that would collapse it.
- **Fix:** `jwt.WithAudience(c.cfg.ClientID)`, validate `azp` for multi-aud, drop the empty-nonce bypass.

### Server

#### M. Per-IP auth rate limiter keyed on spoofable RealIP header (credential-spray bypass)
- **Category:** security — internal/server/server.go:570
- **Failure:** `chimw.RealIP` overwrites `RemoteAddr` from client-controlled `X-Forwarded-For`/`X-Real-IP` with no trusted-proxy allowlist (and uses the leftmost XFF token, so the spoof works even behind an appending ingress). The 10/min `/auth/*` limiter keys on that value; rotating the header per request defeats per-IP credential-spray protection.
- **Fix:** Gate RealIP on a configured trusted-proxy CIDR list, or use RealIP-independent keying; require a header-stripping proxy.

#### M. POST /scan-jobs gated by read-only VerbReadFindings while sibling scan-trigger routes require VerbManagePolicies
- **Category:** security — internal/server/server.go:1118
- **Failure:** `Enqueue` accepts attacker-supplied `target_ref`/`target_type` and inserts a pending scan job workers act on, but is gated only by `VerbReadFindings`. A read-only auditor can make the platform pull/scan an arbitrary external image (scanner load + outbound pulls), bypassing the manage-policies gate the `/scan/workload|host|platform` routes enforce.
- **Fix:** Gate `/scan-jobs` with `VerbManagePolicies` (or a dedicated scan verb) consistently with the trigger routes.

### Handler — scanning

#### M. Image re-scan wipes user triage state (suppressed/accepted/triaged) on promoted image-workload findings
- **Category:** data_integrity — internal/handler/scanning/scanjobs.go:1465
- **Failure:** `promoteImageFindingsToWorkloads` hard-DELETEs prior promotions and re-INSERTs with `gen_random_uuid()` and hard-coded `lifecycle='open'`. Unlike `upsertTargetFinding`/serverless paths (which preserve lifecycle via `CASE WHEN lifecycle='resolved'...`), a rescan silently loses suppression/acceptance, assignee_id, priority, accepted_until; the CVE reappears as open and can re-fire alerts.
- **Fix:** Carry forward lifecycle/assignee/accepted_until via `ON CONFLICT` upsert on a stable promoted key instead of DELETE+reinsert.

#### M. Scan response-rule quarantine audit-logs "skipped" instead of enforcing for registry/repository image scans
- **Category:** half_wired — internal/handler/scanning/scan_response_rules.go:151
- **Failure:** Quarantine is enforced only when `target.ClusterID != nil`; registry/repository image scans (the canonical "scan in registry, block at admission" case) carry `cluster_id NULL`, so the action audit-logs `enforced=skipped` and writes no `quarantine_entries` — the vulnerable image is not blocked even though `image_workload_links` shows the running clusters.
- **Fix:** When ClusterID is nil for an image target, resolve running clusters via `image_workload_links` (as `scanTargetClusters` does) and insert a scope='image' quarantine row per cluster.

### Handler — findings / network

#### M. Reachability ingest updates risk_inputs but never recomputes risk_score (reachability weight dead)
- **Category:** half_wired — internal/handler/findings/findings_reachability.go:95
- **Failure:** `Reachability()` updates only `risk_inputs`/`last_seen_at`, never `risk_score`. The only persisted scorer is `SeverityToScore` (no reachability arg); `risk.Compute` (the 0.15 reachability weight) is never called on the ingest path and no trigger recomputes. A runtime-confirmed CVE never rises in `risk_score DESC` ordering or the `risk:` filter; the Get detail view's on-the-fly breakdown disagrees with the stored score.
- **Fix:** Recompute and persist `risk_score` in the same UPDATE; switch scanjobs to `risk.Compute`.

#### M. Finding-level AcceptRisk accepts arbitrary accepted_until (past or far-future)
- **Category:** fail_open — internal/handler/findings/findings.go:403
- **Failure:** `AcceptRisk` validates only decode error + non-zero date — no future/30-day check (the sibling image-acceptance endpoint enforces both, and a `max-30-day-expiration` "blocking" guardrail is declared). A `VerbAcceptRisk` user accepts a finding for ~75 years or a past date; approver_id/reason are never persisted (separation-of-duties unenforceable).
- **Fix:** Mirror `image_acceptances.go` (reject past / >30d); persist approver_id and enforce requester ≠ approver.

### Handler — runtime

#### M. Response-rule `suppress_log`/`tag` actions are validated and persistable but never enforced
- **Category:** half_wired — pkg/responserule/responserule.go:65 (+ internal/handler/runtime/events_ingest.go:561)
- **Failure:** `ActionSuppressLog`/`ActionTag` pass `Validate()` and are RBAC/OpenAPI-advertised, but all three apply paths (events_ingest, scan, admission audit_hook) switch only on `ActionQuarantine`. Worse, for `suppress_log` the events row is committed, the runtime.alert audit row written, and the notify fan-out fired *before* `dispatchResponseRules` runs — the log/alert it's meant to suppress is already emitted. The documented "agent stream evaluator" / `response-rules:sync` consumer doesn't exist (the agent fetches only baseline/file-profile/dlp bundles).
- **Fix:** Compute the suppress decision before the events/audit/notify side-effects and skip them, or remove `suppress_log`/`tag` from `validActionTypes`.

#### M. runtime-threats category filter mislabels built-in IPS/IDS signatures as 'waf'
- **Category:** bug — internal/handler/runtime/runtime_threats_ingest.go:354
- **Failure:** The `?category=dlp|waf` filter is `CASE WHEN dlp_name_hash>0 THEN 'dlp' ELSE 'waf'`. The catalog is dominated by IPS signatures (PING_DEATH, TCP_SMURF, SQL_INJECTION, threat_id 2000+, hash=0), all bucketed as 'waf', while real custom WAF hits (hash>0) land in 'dlp'. `?category=waf` returns unrelated IPS rows and hides real WAF hits — wrong in both directions. (NeuVector classifies by threat_id range, not the hash.)
- **Fix:** Derive category from sensor/threat classification (threat_id range / DPI sig class), with a distinct IPS bucket.

### Netpolicy

#### M. FQDN toFQDNs egress is dead in the lifecycle/applier path
- **Category:** half_wired — internal/handler/netpolicy/network_policies.go:518
- **Failure:** Ingest persists `fqdn` and `GenerateCilium` supports `toFQDNs`, but the lifecycle catalog query doesn't SELECT `fqdn` and the `policyFlow` literal never sets `Fqdn`. Enforced manifests (persisted to `preview_manifests`, reconciled by the applier) never emit a `toFQDNs` rule; egress is pinned to an observed /32 (or dropped). When the destination rotates IPs, protect-mode silently drops the egress — exactly what toFQDNs prevents.
- **Fix:** Add `COALESCE(fqdn,'')` to the catalog SELECT/GROUP BY and set `policyFlow.Fqdn`, mirroring `runtime_policies_generate.go`.

### Runtime-agent

#### M. FQDN egress resolver is never fed DNS responses or an allow-set (dp's FQDN→IP table stays empty)
- **Category:** half_wired — internal/runtime/dp/fqdn_ctrl.go:67
- **Failure:** `Supervisor.FeedDNS` and `SetAllowedFqdns` (the resolver's only inputs) have zero production callers; no DNS snoop is instantiated in the agent. `reconcileFqdn` always snapshots an empty table, so even if policy were pushed, FQDN rules (matched by resolved IP) can never match. Non-functional end-to-end.
- **Fix:** Wire a DNS snoop into `FeedDNS` and call `SetAllowedFqdns(FqdnAllowSet(...))` on policy change.

#### M. file-profile enforcer denies file opens that do NOT match the rule's path filter (over-block)
- **Category:** bug — cmd/constellation-runtime-agent/file_profile_enforcer_linux.go:353
- **Failure:** The first decision loop skips a rule when the path doesn't match, but the second loop re-evaluates every rule and denies based only on application/exception checks with no path check. Marks cover the whole `scanRoot` dir with `FAN_EVENT_ON_CHILD`, so a rule for `/etc/*shadow*` blocks an unrelated process opening any direct child of `/etc`. Enabled by default. (For containerized workloads the path-less fallback always discards glob granularity since fanotify reports host-overlay paths.)
- **Fix:** Re-check the rule's path filter in the second loop, or only fall through when the event path is empty/unresolvable.

### Hostscan / host-inventory (consolidated cluster-attribution defect)

#### M. Host-scan/host-CIS upserts mis-attribute nodes to the org's oldest cluster and grow unbounded on NULL cluster_id
- **Category:** data_integrity — internal/handler/host_facts.go:146 (also host_processes.go, host_containers.go:100, host_packages.go, compliance/host_cis.go:81)
- **Failure:** These handlers resolve cluster as `SELECT id FROM clusters WHERE org_id=$1 ORDER BY created_at LIMIT 1`, ignoring the reporting node's real cluster (the agent token carries only org_id), then upsert `ON CONFLICT (cluster_id, node)`. In any multi-cluster org all reports collapse onto the oldest cluster; same-named nodes across clusters (e.g. `ip-10-0-0-5`) overwrite each other (silent data loss). When the org has no cluster, `cluster_id` is NULL — NULLS DISTINCT defeats ON CONFLICT, so every periodic report inserts a fresh duplicate row (unbounded growth, duplicate List output).
- **Fix:** Carry an explicit cluster_id in the agent token/payload and make it the conflict target; for the NULL case use a partial/NULL-safe unique index (`COALESCE(cluster_id, ...)`).

### Compliance

#### M. Compliance exemption cross-cluster scope leak in the evidence collector
- **Category:** data_integrity — internal/complianceevidence/evidence.go:736
- **Failure:** `applyExemptions` loads exemptions with `($2 IS NULL OR cluster_id IS NULL OR cluster_id=$2)` — on an org-wide (nil cluster) query the `$2 IS NULL` branch pulls every exemption including cluster-scoped ones, and the apply loop matches only on framework+control_id (never compares cluster_id). A cluster-A-scoped exemption marks a failing control on cluster B as `exempted` (counted pass). The handler SQL paths gate cluster_id correctly; this Go path is the inconsistent one.
- **Fix:** Track each exemption's cluster_id; apply only when NULL or equal to `item.ClusterID`.

#### M. AWS/GCP CSPM Scan swallows partial scanner failure and reports success
- **Category:** fail_open — internal/cspm/aws/aws.go:82 (gcp.go:72)
- **Failure:** `Scan` returns an error only when BOTH sub-scans fail (`ierr != nil && serr != nil`). An `AccessDenied` on `iam:ListRoles` with a successful S3 scan returns S3-only findings and nil error — the pipeline records a clean scan with zero IAM findings; operators conclude IAM is clean when it was never scanned.
- **Fix:** Return a joined error whenever any sub-scan fails, or surface per-source status.

#### M. AWS CSPM enumerations do not paginate (only the first page of roles is scanned)
- **Category:** fail_open — internal/cspm/aws/aws.go:93
- **Failure:** `ScanIAM`/`ScanS3` call `ListRoles`/`ListBuckets`/`ListAttached…`/`ListRolePolicies` once with no `Marker`/`IsTruncated` handling. IAM ListRoles returns ≤100 roles/page; an account with 250 roles silently scans only the first ~100, so a wildcard-grant role on page 2+ produces no finding while the scan presents as complete.
- **Fix:** Use the SDK paginators and loop until `IsTruncated` is false.

#### M. host-cis ingest mis-attributes every node to the oldest cluster
- **Category:** data_integrity — internal/handler/compliance/host_cis.go:81
- **Failure:** `Report` resolves cluster via `ORDER BY created_at LIMIT 1` ignoring the reporting node's cluster, then upserts `ON CONFLICT (cluster_id, node)`. Nodes from cluster B are stored under cluster A; same-named nodes clobber each other. (Same root cause as the consolidated host-scan defect above; the correct cluster is recoverable from the token's init-bundle but ignored.)
- **Fix:** Derive cluster_id from the agent token's cluster, not the oldest cluster row.

### Scanner

#### M. RequireVulnDB guard is bypassed when the SBOM is empty (Syft failure lets Trivy/Grype-only results pass as authoritative)
- **Category:** fail_open — internal/scanner/aggregator.go:121
- **Failure:** The package-matcher loop (only place `vulnDBErr` is set) runs only when `!SBOMOnly && len(out.Packages) > 0`. A non-fatal Syft failure leaves `out.Packages` empty, the loop is skipped, `vulnDBErr` stays nil, the `RequireVulnDB && vulnDBErr != nil` gate never fires, and Trivy/Grype-only findings make `hasUsable` true. The worker records a successful scan with no canonical VulnDB data and an empty inventory, overwriting a prior good result.
- **Fix:** Treat a skipped/absent VulnDB matcher as a require-vulndb failure when `RequireVulnDB` is set.

#### M. Image-signature trust identities/issuers are matched as unanchored regexes (trust widening)
- **Category:** security — pkg/sigverify/sigverify.go:281
- **Failure:** `matchesAny` uses `regexp.MatchString` (unanchored substring) and `joinAlt` wraps patterns in `(?:a|b)` with no `^...$` and no `QuoteMeta`, passed to cosign `--certificate-identity-regexp`. A trusted identity `https://github.com/myorg/myrepo` matches an attacker SAN `…/myrepo-evil/…` (superstring), so an image from a sibling repo is reported `Trusted=true`.
- **Fix:** Anchor patterns (`^(?:...)$`) and `QuoteMeta` literals in both `matchesAny` and the cosign arg construction.

#### M. Go reachability (govulncheck binary mode) is inert for image-target scans
- **Category:** half_wired — internal/scanner/reachability.go:300
- **Failure:** `findingBinaryPaths` derives binary paths from Syft locations, which for an image scan are paths *inside* the image (never extracted to the host). `govulncheck -mode binary <inImagePath>` then errors on every invocation; `Reachable` stays nil for all findings and reorder is a no-op. The opt-in feature only works for serverless `dir:` scans.
- **Fix:** Extract the binary to a host scratch path for image targets (or don't advertise the feature for image targets) and map paths to the extracted location.

#### M. Aggregator dedupe keys on a single vulnerability ID, so VulnDB GHSA/OSV and Trivy/Grype CVE findings for one package aren't merged
- **Category:** data_integrity — internal/scanner/aggregator.go:272
- **Failure:** `dedupe` keys on `canonicalCVE(VulnerabilityID)` (uppercase only, ignores Aliases) + eco/name/version. A VulnDB finding `GHSA-…` (alias `CVE-2024-1234`) and a Trivy `CVE-2024-1234` land in different buckets → two findings for one vuln, the Trivy one not demoted to evidence, double-counting and divergent severity.
- **Fix:** Resolve canonical identity via the alias set (prefer CVE alias / union intersecting ID sets) when bucketing.

### Backup / restore

#### M. Server restore path never verifies the cosign signature (Verify mode hardcoded to None)
- **Category:** fail_open — internal/handler/backup.go:408
- **Failure:** `Backups.Restore` hardcodes `Verify.Mode = SignModeNone` and takes `AllowUnverified` from the `?allow_unverified=true` query param. `backup.Verify` has no production caller; an unsigned/forged tarball is applied with no provenance check even when the org's backups were signed.
- **Fix:** Resolve verifier mode from operator policy / the org's configured public key and call Verify; default fail-closed; don't let the request flip allow_unverified.

#### M. Restore applies table files not covered by the signed manifest (no completeness check)
- **Category:** data_integrity — pkg/backup/restorer.go:236
- **Failure:** `verifyTableDigests` only checks tables listed in the (signed) manifest, never the reverse. Starting from a validly signed backup missing an optional table (e.g. custom_roles), an attacker appends `tables/custom_roles.jsonl` with elevated RBAC rows; the signature over manifest.json still verifies and the restore loop applies the unsigned table — injecting RBAC data into a "verified" restore.
- **Fix:** Assert the set of `tables/*.jsonl` in the archive is a subset of `manifest.Tables`; reject any unlisted file.

### Operator

#### M. Scanner Deployment reconcile unconditionally overwrites replicas, fighting its own HPA
- **Category:** half_wired — deploy/operator/controllers/constellationcluster_controller.go:257
- **Failure:** `ensureDeployment` always sets `Spec.Replicas` while `reconcileScannerHPA` creates an HPA targeting the same Deployment; `Owns(Deployment)` re-triggers reconcile on every HPA scale, resetting replicas back to 2. Capacity flaps; ScannerAutoscale is self-defeating.
- **Fix:** When autoscale is enabled, don't set `Spec.Replicas` (leave it to the HPA).

#### M. Per-role default images are never wired; DefaultAgentImage shadows the per-role fallbacks
- **Category:** dead_code — deploy/operator/controllers/constellationcluster_controller.go:130
- **Failure:** `imageForRole` returns `DefaultAgentImage` before the per-role fallback, but only `DefaultAgentImage` is set (defaulting to `constellation-agent:latest`); `DefaultScannerImage`/`DefaultAdmissionImage`/`DefaultRuntimeAgentImage` have no flags/writers. A CR omitting per-role images runs the combined agent binary (a phantom image with no Dockerfile) for scanner/admission — admission even started with `--insecure` on 8443 against the wrong binary.
- **Fix:** Remove the `DefaultAgentImage` early-return so per-role fallbacks apply, or add per-role flags and wire them.

#### M. Admission webhook Service selector omits the cluster label (cross-routing between ConstellationClusters)
- **Category:** bug — deploy/operator/controllers/constellationcluster_controller.go:383
- **Failure:** The Service selector is only `{name=constellation, component=admission}` while pods also carry `constellation.alphabravo.io/cluster=cc.Name`, and all CRs deploy into one namespace. With two AdmissionEnabled clusters, `cc-a-admission` load-balances across both clusters' admission pods, applying the wrong cluster's/org's policy (each pod is org-scoped via env) — crossing tenant boundaries.
- **Fix:** Add `constellation.alphabravo.io/cluster: cc.Name` to the Service selector.

### Notify / response

#### M. Retried receiver deliveries lose the entire alert payload
- **Category:** half_wired — pkg/notify/dispatcher.go:528
- **Failure:** `persistPending` stores only event_type/severity/idempotency_key; `sweepOnce` reconstructs the retry Event with `Title='(retry) '+kind` and empty Body/Cluster/Workload/URL/Labels/Payload. A retried Slack/PagerDuty/webhook POST is content-free, and the HMAC over the different body won't match a cached original signature.
- **Fix:** Persist the full rendered body (or Event payload as JSONB) on the row and replay it exactly on retry.

#### M. Notifications are permanently dropped (never retried) when the dispatch queue is full
- **Category:** fail_open — pkg/notify/dispatcher.go:192
- **Failure:** On a full queue, `markFailed(..., 'queue_full')` sets `final_state='queue_full'`, `next_retry_at=NULL`; the sweeper only re-enqueues `final_state IS NULL AND next_retry_at IS NOT NULL`, so these rows are never retried — despite the comment claiming they will be. During an alert storm/slow receiver, over-capacity alerts are silently lost exactly when alerting matters most.
- **Fix:** On queue-full set `status='retrying'`, `next_retry_at=NOW()+backoff`, leave `final_state` NULL — or block/spill with a bounded wait.

#### M. Webhook/receiver endpoints accept arbitrary URLs (SSRF to internal services / cloud metadata)
- **Category:** security — internal/handler/receivers.go:258
- **Failure:** `Receivers.Create`/`Patch` validate only non-empty endpoint; the dispatcher POSTs to it with a stock client (no allow/deny list, no loopback/link-local/RFC1918/169.254.169.254 block). A `VerbManagePolicies` user sets `endpoint=http://169.254.169.254/...`; alert traffic hits the internal target and a 512-byte response snippet (status ≥300) is captured into the readable delivery error column — enabling internal port-scan, cloud metadata (node IAM creds), and internal admin endpoints. The fed-proxy path is hardened against exactly this; notify is not.
- **Fix:** Validate at create/patch (require https, reject non-public hosts) and enforce again at dial via a Control hook that blocks private/link-local/loopback resolved IPs (defeats DNS rebind).

### Migration / misc

#### M. StackRox & NeuVector Kyverno emitters produce empty (no-op) validate patterns for unsupported criteria
- **Category:** half_wired — internal/migration/stackrox/stackrox.go:202 (and internal/migration/neuvector/neuvector.go:910)
- **Failure:** `kyvernoMapping`/`canEmitKyverno` accept policies whose only fields are 'Image Tag'/'Read-Only Root Filesystem' (StackRox) or any criterion other than image_name/labels (NeuVector), but `kyvernoPattern`/`emitAdmissionKyverno` fall through to `{spec:{}}` while still setting `validationFailureAction=enforce`. The emitted ClusterPolicy matches everything/enforces nothing; the preview shows engine=kyverno, mode=enforce. NeuVector also only reads `Criteria[0]`. The parity-correct `translateAdmissionProfileRules` path is test-only, not wired to the preview handler.
- **Fix:** Emit real patterns for these criteria, or route unsupported criteria through the constellation-admission/manual-review path instead of a no-op enforce policy.

#### M. StackRox emitKyverno sets validationFailureAction from Disabled only, ignoring the computed monitor/enforce mode
- **Category:** bug — internal/migration/stackrox/stackrox.go:186
- **Failure:** `translatePolicy` computes `mode='monitor'` for a non-disabled policy with no enforcement actions, but `emitKyverno` sets `validationFailureAction = Disabled ? audit : enforce`, never consulting mode. A monitor-only policy gets an embedded spec of `enforce`; applied to a real Kyverno it blocks deployments meant only to alert. (Migration preview is read-only today, capping impact.)
- **Fix:** Derive `validationFailureAction` from the computed mode (enforce→enforce, monitor→audit) and fix the mode ladder so a disabled policy isn't labeled enforce.

### Helm / deploy

#### M. NetworkPolicies are wired for the legacy `postgres.embedded` StatefulSet only and break the DB path in cnpg mode
- **Category:** half_wired — deploy/charts/constellation/templates/_helpers.tpl:184
- **Failure:** The egress helper and the `.embedded`-gated ingress policy assume DB pods carry `component=postgres`, but CNPG-managed instance pods are labelled `cnpg.io/cluster=...` (no `inheritedMetadata`). With the recommended `postgres.mode=cnpg + networkPolicies.enabled=true`, api/migrate egress matches no pod, the ingress policy isn't rendered, and default-deny blocks CNPG replication → DB unreachable / HA can't form. Same gap for `mode=statefulset` with legacy `embedded=false`.
- **Fix:** Gate the ingress policy on `postgresIsStatefulset`; for cnpg add policies selecting `cnpg.io/cluster` + replication, or set `spec.inheritedMetadata.labels` on the CNPG Cluster.

### Frontend

#### M. Authenticated file downloads (SBOM / backup / PCAP) are broken — plain navigation never sends the bearer token
- **Category:** half_wired — frontend/src/pages/BackupPage.tsx:72 (AssetDetailPage.tsx, NetworkMapPage.tsx)
- **Failure:** Downloads use `window.open`/`<a href>` to bearer-only API routes; the JWT lives in localStorage and is attached only by the axios interceptor, so a top-level GET carries no Authorization header → `authMiddleware` 401 "missing bearer token". SBOM export, backup download, and PCAP download are non-functional (the comment claiming the header "flows through" is wrong). A correct `downloadAPIFile` blob helper already exists and is used elsewhere.
- **Fix:** Download via authenticated fetch/axios into a Blob + object URL, or mint short-lived signed one-time URLs server-side.

### Cross-cutting (response / data-integrity)

#### M. response_rules_v2 'notify' and 'ticket' actions are silently dropped (engine built with nil receivers)
- **Category:** half_wired — internal/handler/runtime/response_runtime.go:172
- **Failure:** `NewResponseDispatch` (the only production dispatch) builds `response.NewEngine(nil, ..., nil)` with a nil receivers map and discards the returned warnings. For notify/ticket, the engine's receiver lookup fails, appends `unknown receiver` and continues. A validated/persisted notify rule targeting a specific receiver is a no-op (notify is only partially compensated by kind-based broadcast; ticket is fully dead).
- **Fix:** Pass the real `notify.Receiver` map into the engine, or reject notify/ticket at v2 rule creation; stop discarding warnings.

#### M. Crashloop detection query omits org_id filter (cross-tenant alert contamination)
- **Category:** data_integrity — internal/handler/heartbeats.go:294
- **Failure:** `crashloopFor` counts restarts `WHERE component=$1 AND hostname=$2 AND detected_at > NOW()-1h` with no `org_id` predicate, though rows are written with org_id and every other read is org-scoped. Same component+hostname across tenants (e.g. `constellation-scanner-0`, or the `unknown-<component>` default) collide: org A's restarts trip org B's `>3` threshold, emitting a spurious `component.crashloop` audit + notifier fanout for a tenant that never crashlooped.
- **Fix:** Add `AND org_id = $3` and pass the (already available) orgID, mirroring `LoadRestartEvents`.

#### M. Host inventory upserts accumulate unbounded duplicates when the org has no registered cluster (NULL cluster_id defeats ON CONFLICT)
- **Category:** data_integrity — internal/handler/host_containers.go:100
- **Failure:** On `pgx.ErrNoRows`, `clusterID` stays nil and the handler INSERTs `ON CONFLICT (cluster_id, node)`; with NULLS DISTINCT, `(NULL,'node1')` never conflicts, so every report inserts a new row. Repeated across host_facts/processes/packages/cis. Host-only scanning or pre-registration reporting at 30–60s grows the host_* tables without bound; List returns duplicates. (Same family as the consolidated host-scan defect.)
- **Fix:** Reject ingest when the org has no cluster, or make the unique index NULL-safe (`COALESCE(cluster_id, ...)`) and reference that arbiter.

#### M. Rollback watcher's per-policy deny COUNT over high-volume network_flows has no supporting index
- **Category:** data_integrity — internal/handler/runtime/runtime_policies_rollback.go:159
- **Failure:** Every 30s the watcher runs, per enforce-mode policy, `SELECT COUNT(*) FROM network_flows WHERE org_id=$1 AND cluster_id=$2 AND policy_id=$3 AND verdict='deny' AND at>=…`. No index covers policy_id/cluster_id (and only a single default partition exists, so no `at` pruning), so each query full-scans the org's flows. With N policies on a busy cluster this pressures the pool and delays auto-rollback. A migration comment falsely claims a covering `at` index exists.
- **Fix:** `CREATE INDEX ON network_flows(org_id, cluster_id, policy_id, at DESC) WHERE verdict='deny'`.

#### M. Migration 092 adds UNIQUE(org_id, revision) to fed_rule_revisions without pre-deduping
- **Category:** data_integrity — db/migrations/092_fed_rule_revision_unique.sql:9
- **Failure:** 092 `ADD CONSTRAINT ... UNIQUE (org_id, revision)` with no dedup, on a table whose pre-092 `MAX(revision)+1` race (the very bug 092 fixes) can already have left duplicate rows. On such a deployment the constraint creation fails (`duplicate key value`), goose rolls back, and the deploy is blocked at version 091. (Migrations 061/043 dedup/backfill first; 092 omits this.)
- **Fix:** Dedup colliding revisions (renumber later duplicates via a window function, like migration 061) before the ADD CONSTRAINT.
