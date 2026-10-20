# Security backlog

Archived from the 2026-07 deficiency audit (High severity only) when the
NeuVector parity programme was removed from the tree (2026-10-20). Each row
MUST be re-verified against the current tree before its status changes.

Status values: `open` (not yet verified against HEAD), `verified-open`,
`fixed` (link the commit), `wont-fix` (link the ADR).

| ID | Status | Area | Title | File |
|---|---|---|---|---|
| H1 | open | backup-restore | Server backup-restore writes into the org named in the uploaded tarball (cross-tenant write) | `internal/handler/backup.go` / `pkg/backup/restorer.go` |
| H2 | open | auth | IdP secrets (OIDC client secret, LDAP bind password, SAML SP key) stored unencrypted | `internal/auth/authservers.go` |
| H3 | open | hostscan | CIS file-permission checks use numeric mode comparison (world-readable /etc/shadow passes) | `internal/runtime/hostscan/cis.go` |
| H4 | open | compliance | AWS IAM inline wildcard-policy detection is fail-open (URL-encoded policy never matches) | `internal/cspm/aws/aws.go` |
| H5 | open | scanning | Vulnerability-profile decisions computed at scan completion but never applied | `internal/handler/scanning/scanjobs.go` |
| H6 | open | runtime-agent | Workload micro-segmentation policy never pushed to dp (`Supervisor.PushPolicy` has no callers) | `internal/runtime/dp/policy.go` |
| H7 | open | helm | Admission quarantine DSN reads a non-existent Secret key (fail-open admission) | `deploy/charts/constellation/templates/admission-deployment.yaml` |
| H8 | open | operator | Operator ClusterRole omits RBAC for policy CRs it reconciles | `deploy/charts/constellation/templates/operator.yaml` |
| H9 | open | audit | Concurrent audit writes silently break the hash chain | `pkg/audit/audit.go` |
| H10 | open | auth | SAML/LDAP JIT login mints a session JWT with a stale `session_epoch` | `internal/handler/auth.go` |
| H11 | open | compliance | kube-bench compliance ingest accumulates duplicate rows every run | `internal/handler/compliance/compliance.go` |
| H12 | open | netpolicy | Collapsed external peers (`external`, no slash) bypass CIDR anchoring | `internal/handler/netpolicy/network_policies.go` |

## Details

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
