# GitOps policy: Constellation CRDs + `export-crds`

This note closes two audit gaps (`docs/neuvector-capability-audit.md`):

- **[HIGH] Policy/rules are not expressible as Kubernetes CRDs** (line 306). We shipped exactly
  one CRD (`ConstellationCluster`) that only deploys an agent; all security policy lived in
  Postgres, managed solely via REST — the GitOps gap.
- **[HIGH] NeuVector has a declarative ConfigMap-driven init layer we entirely missed** (line 312).

## Truth-in-labeling: what NeuVector actually does

Per the audit, NeuVector is config-able **three ways** and is genuinely GitOps-friendly:

1. **A 10-member policy CRD family**, all kubectl/GitOps-manageable: `NvSecurityRule`,
   `NvClusterSecurityRule`, `NvGroupDefinition`, `NvAdmissionControlSecurityRule`,
   `NvResponseRuleSecurityRule`, `NvConfigSecurityRule`, `NvDlpSecurityRule`, `NvWafSecurityRule`,
   `NvVulnerabilityProfile`, `NvComplianceProfile`.
2. **A ConfigMap-driven init layer.** `LoadInitCfg` consumes
   `/etc/config/{ldap,saml,oidc,sys,role,passwordprofile,user,fed}initcfg.yaml`, with per-handler
   `AlwaysReload` semantics, so mounted ConfigMap YAML is reconciled into config at boot.
3. **Runtime PATCH** via the REST API.

We do **not** claim parity with all of that here. This is the audit's stated *minimum*: a declarative
policy CRD layer reconciled by the operator into DB rows, **plus a documented export of DB policies
into kubectl-applyable manifests** (audit recommendation 7, line 371).

## What Constellation ships (Workstream B, task B2)

### CRDs reconciled by `constellation-operator`

| CRD | Backing store | Maps to NeuVector |
| --- | --- | --- |
| `ConstellationAdmissionRule` (`car`) | `policies` row, `category="admission"` (migration 006) | `NvAdmissionControlSecurityRule` |
| `ConstellationResponseRule` (`crr`) | `response_rules` row (migration 103) | `NvResponseRuleSecurityRule` |

Both are **cluster-scoped** (Constellation policy is scoped to a Constellation org, not a k8s
namespace; the org is carried explicitly in `spec.orgID`, which is **immutable** — a CEL validation
on the CRD rejects edits, since changing it would orphan the original row). The operator is the
source of truth: each reconcile upserts the CR's columns (correcting DB drift) and re-asserts itself
on a short interval so out-of-band edits to a declarative row are corrected within bounded time, and
a finalizer (`constellation.alphabravo.io/policy-finalizer`) deletes the backing row when the CR is
removed.

Operator-managed rows are tagged `source='declarative'` — the existing StackRox-inspired provenance
value (migration 027) meaning "committed as YAML and reconciled by the operator". Provenance is
enforced **symmetrically**: the finalizer only deletes `declarative` rows, **and** the upsert's
conflict path is source-guarded (`DO UPDATE … WHERE source='declarative'`). So a REST/UI
(`imperative`) row that shares an `(org, name)` identity is never clobbered, relabelled, or orphaned
— a CR colliding with one is reported `Conflict` on its status and writes nothing. See
`deploy/operator/policydb/store.go` for the full design rationale (why direct DB upsert, not REST).

> **Authorization boundary.** `spec.orgID` is author-asserted; the operator org-scopes every write
> on it but does not itself authorize *which* org a CR may target (it validates only that the org
> exists). Authorization is therefore the **Kubernetes RBAC** boundary on these cluster-scoped CR
> kinds: whoever can create/update a `ConstellationAdmissionRule` / `ConstellationResponseRule` can
> target any existing org. Gate these kinds with RBAC (or front them with an admission webhook that
> pins `spec.orgID`) on multi-tenant clusters.

A `ConstellationNetworkRule` CRD is intentionally **not** defined: `pkg/netpolicy` is a flow-driven
*generator* (it synthesizes NetworkPolicy/Cilium/Calico YAML from observed flows) rather than a
stored, org-scoped policy row, so there is no clean DB shape to mirror as a CRD spec.

CRD manifests ship in the chart: `deploy/charts/constellation/crds/`.

### Export path: `constellationctl policy export-crds`

The inverse of reconcile — read an org's stored policies and emit the equivalent CR documents as a
kubectl-applyable multi-doc YAML stream. This is the minimum-viable GitOps bridge: export the
policy you already have, commit it to git, and `kubectl apply` it back.

```
constellationctl policy export-crds --org <uuid> > policies.yaml
kubectl apply -f policies.yaml
```

Flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--org` (required) | — | Org ID (UUID) whose policies to export |
| `--database-url` | `$CONSTELLATION_DATABASE_URL` / `$DATABASE_URL` | Policy store DSN |
| `--kind` | `all` | `all` \| `admission` \| `response` |
| `--output` | stdout | Write the YAML stream to a file instead |

It reads the DB directly (not REST) for the same reasons the operator does: the REST auth model
derives org from the authenticated subject with no act-as-org affordance, and there is no name-keyed
list/export route to add without tripping the I1 OpenAPI completeness gate.

### Scope of the export, and the round-trip guarantee

The export emits **only operator-owned (`source='declarative'`) policy** — the rows the operator
itself authored. Imperative (REST/UI-authored) policies are deliberately **not** exported: emitting
them as CRs would adopt them into the operator's delete-on-removal lifecycle (and, on re-apply, a CR
colliding with a still-imperative row is refused with `Conflict`), so exporting them would be unsafe
rather than helpful. To bring an imperative policy under GitOps, recreate it as a CR deliberately.

For the declarative rows it does emit, export then apply is **lossless**: a stored row exported to a
CR (`policydb.AdmissionCR` / `policydb.ResponseCR`) and fed back through the reconciler's mapping
(`mapAdmissionRule` / `mapResponseRule`) reproduces the identical row. This is exact precisely
because declarative rows only ever carry the operator-managed columns (admission:
`description, engine, mode, enabled, spec_yaml`; response: `enabled, priority, event_type,
conditions, actions`) — the imperative-only `policies` columns (`cluster_id`, `scopes`,
`exclusions`, `lifecycle_stages`, `mitre_attack_vectors`, `severity`, `enforcement_actions`,
`risk_factors`) are never set on a declarative row, so there is nothing to drop. The struct-mapping
symmetry is enforced by `deploy/operator/controllers/policy_export_roundtrip_test.go`, and the
declarative-only DB read path by `deploy/operator/policydb/store_export_db_test.go`. The re-applied
row matches column-for-column, modulo the DB-assigned `id` (not part of a CR's `(org, name)`
identity).
