# 0011: First-class local accounts and independent sign-in methods

Owner direction supersedes ADR 0010's emergency-only local-password policy.
Each installation chooses local accounts (the default), one OIDC provider, or both.
Authorization remains the existing role model and route policy. OIDC identities
remain issuer/subject linked; local creation never links an existing SSO account by email.

`local_users` extends the existing `users` profile, organization, disable state,
last-login timestamp and revocation epoch. Passwords reuse Argon2id (64 MiB,
three passes, four lanes); TOTP reuses the RFC 6238 implementation with atomic
per-account step consumption. Seeds use the existing age ciphertext/key-id/algorithm
triple and participate in key rotation. No second password or session implementation.
The embedded NCSC top-100k corpus rejects breached passwords without network access.

TOTP defaults to everyone. The alternative requires it for GlobalAdmin,
SecurityAdmin and ClusterAdmin; recovery always requires it. Account failures
trigger exponential backoff after five failures by default (1s to 300s). A separate
Postgres IP counter defaults to 20 attempts/minute across replicas. Argon2 verification
is bounded to one concurrent login per replica to cap memory. Session lifetime is
configurable (one hour by default), with no refresh.

One local administrator has `break_glass=true`. Migration imports the previous
Secret-configured administrator without changing credentials or replay protection.
A fresh installation's initial administrator is the recovery administrator. On an
upgrade, the imported recovery administrator stays separate from the normal initial
administrator. Disabling local access revokes normal local sessions, while recovery
continues to work with OIDC configured, unavailable, or not yet configured. Recovery
sessions remain five minutes by default, at most ten, with critical audit, metric
and alert. Database triggers prevent generic user APIs from deleting, disabling,
renaming or removing the recovery administrator's GlobalAdmin grant.

Chart values seed a versioned policy row. UI changes persist across restarts and
unchanged upgrades. A changed deployment-policy fingerprint replaces that row with
the new chart defaults; bootstrap credentials are excluded from policy and never
reset existing users. Admin edits use an optimistic revision, are audited, and
provider secrets are age encrypted. Each replica reloads provider configuration
within two seconds; discovery does not run in the session-refresh worker.

Session checks use a bounded immutable index of at most 10,000 active sessions.
A database revision (triggers on sessions, users and policy) is polled every 250ms;
full snapshots are transferred only after changes. Database notifications wake refreshes
immediately, and successful login waits for acknowledgements from all live replicas
before returning the cookie (migration 189). Each replica uses one dedicated
notification connection; polling remains the fallback. Expiry is checked on every
request. Local identity mutations synchronize the serving replica before returning;
other replicas normally observe revocation within 250ms. Requests fail closed if
the last successful database freshness check is older than one second. This bounded
revocation window replaces request-time Postgres lookups (measured ~360µs), allowing
both first and repeated checks to stay below the plan's 50/75µs budgets. The background
refresh is independent of OIDC discovery, so an issuer outage cannot starve it.
