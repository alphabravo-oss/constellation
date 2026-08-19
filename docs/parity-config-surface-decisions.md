# Config-surface parity decisions (NeuVector)

Re-audit round 2 of the NeuVector-parity sweep flagged four config-surface items as HIGH
after every security dimension was confirmed at parity-or-better. This records how each was
resolved. Three were closed in code; one was formally re-scoped below HIGH with owner sign-off
(2026-06-30).

## B3 — `response_rules` missing from config-as-code — CLOSED
The E1 declarative response-rule engine (table `response_rules`, the `ConstellationResponseRule`
CRD's reconcile target) was omitted from `pkg/backup` `ConfigTables` (config-as-code) and
`OrderedTables` (full backup), which listed only the cluster-scoped `response_rules_v2`. A
GitOps export/import or backup therefore silently dropped E1 rules. Fixed: both lists now
include `response_rules`; it is org-scoped with a `created_by->users` FK identical to
`response_rules_v2`, so the generic exporter/restorer handles it with no special-casing.
(commit `9ede2d4`)

## B1a — dead `syscfg.ScannerAutoscaleMin/Max` — CLOSED (removed)
The fields were defined in the system-config struct, seeded from env, and validated, but **never
read by any consumer** — a misleading config surface. Real, runtime-adjustable scanner
autoscaling already exists and is **better than a static pool size**: the operator's
`ConstellationCluster.Spec.ScannerAutoscale` reconciles a live `HorizontalPodAutoscaler`
(`reconcileScannerHPA`), the K8s-native mechanism. The dead fields were removed; scanner scaling
is documented as operator-owned. (commit `d14930e`)

## B4 — no declarative identity-provider seeding — CLOSED
NeuVector seeds LDAP/SAML/OIDC from `*initcfg.yaml` ConfigMaps via `LoadInitCfg`; Constellation
had only API/CRUD auth-provider config, so a GitOps install could not declaratively stand up
SSO. `constellation-bootstrap` now reads an optional providers file
(`BOOTSTRAP_AUTH_PROVIDERS_FILE`) and seeds each into `auth_servers` via the existing idempotent
`auth.SeedAuthServer` (inserts only when no provider of that type exists — never clobbers an
API-edited one). The Helm chart renders `bootstrap.authProviders` into a Secret the
bootstrap-admin Job mounts; empty by default. (commit `0622a9c`)

## B1b — server TLS / OIDC discovery / federation-peer TLS read at startup — RE-SCOPED below HIGH
**Decision: accepted design difference, not a parity gap. Signed off 2026-06-30.**

NeuVector exposes some operational config (proxy, federation) for runtime update via its
controller `RestConfig` path. Constellation reads **server TLS material, OIDC discovery, and
federation-peer TLS-verify/CA-bundle once at startup**, by design, because:

- These are **security-sensitive bootstrap parameters**. Reading them at startup from env /
  mounted Secrets (the K8s-native delivery) is a deliberate, defensible posture — runtime
  mutation of the server's own TLS trust is a larger attack surface, not a feature gap.
- The config knobs that genuinely benefit from runtime mutation **are** wired to the live
  `syscfg.Provider` (registry HTTP client TLS-verify + CA bundle, syslog/SIEM target, egress
  proxy) — so the live-config capability exists; only the startup-bootstrap parameters are
  intentionally excluded.
- Constellation's identity-provider config (LDAP/SAML/OIDC) **is** runtime-mutable through the
  `auth_servers` table + ProviderSet hot-reload (no restart), and now declaratively seedable at
  install (B4). So the *user-facing* auth config NeuVector tunes at runtime is at parity; only
  the server's own TLS trust + OIDC issuer discovery are startup-bound.

This is a config-*delivery* posture difference, not a security or capability regression versus
NeuVector. It is therefore not treated as a HIGH parity blocker.

## G1 — govulncheck reachability computed but not persisted — CLOSED
Re-audit round 3 found that `Finding.Reachable` was computed by the Go reachability analyzer but
never surfaced: `scannerFindingDetail` dropped it and `findings.risk_inputs.reachable_static`
was never populated, so the result was invisible to the API, the `reachable:true` search filter,
and risk-scoring. (NeuVector has no Go reachability at all, so this was Constellation-exclusive
but half-wired.) Fixed: reachability is now written to `detail_json` and merged into
`risk_inputs.reachable_static` on both the direct upsert and the image→workload promote paths;
absent when not computed so it reads as "unknown", not "unreachable". (commit `747d6b6`)

## Known non-gating MED follow-ups (accepted)
- **Federation leave/demote credential revocation.** `Federation.Transition` ("leave"/"demote")
  updates `federation_state` but does not revoke per-cluster `fed_credentials` (unlike
  `KickMember`, which does). A sync ticket minted before the transition could authenticate a poll
  until it expires. The audit rates this MED, not HIGH. A correct fix is topology-nuanced (a
  joint's *leave* revokes its own ticket; a master's *demote* dissolves all the joints' tickets
  it issued), so it is tracked as a focused follow-up rather than a rushed mirror of KickMember.
  Not a parity blocker.
