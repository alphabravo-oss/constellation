# Compliance audit-log mappings

This document describes how Constellation's audit log maps to industry
compliance frameworks. It is the source-of-truth for ATO worksheets,
SOC 2 evidence packets, PCI DSS audit reports, and ISO 27001 reviews.

## What we claim and what we don't

We map **audit events to controls as evidence of recordkeeping**. Concretely:

- An audit row for `policy.update` *is evidence* that the control
  "CM-3 Configuration Change Control" is being exercised by recording
  authorized policy changes.
- That same row *is not by itself* an attestation that the system as a
  whole is CM-3 compliant — CM-3 also requires change-request workflow,
  rollback procedures, etc. that the audit log alone does not demonstrate.

This distinction matters because audit findings are penalised when
operators overclaim ("we have AC-2 covered, look at the log"). The
correct framing for an auditor is: "audit_events provides the
record-of-action evidence for these controls. Process documentation
covers the remaining elements."

## Frameworks tracked at v1

| ID                    | Framework                                     | Version |
|-----------------------|-----------------------------------------------|---------|
| `nist-sp-800-53-r5`   | NIST Special Publication 800-53               | Rev. 5  |
| `soc2-tsc-2017`       | AICPA SOC 2 Trust Services Criteria           | 2017 (with 2022 revisions) |
| `pci-dss-v4.0`        | Payment Card Industry Data Security Standard  | 4.0     |
| `iso-27001-2022`      | ISO/IEC 27001 — Information Security Management | 2022  |

Framework strings appear verbatim in API responses (`?framework=` query
param, `GET /api/v1/compliance/control-mappings`) and in CSV exports.
They are part of the wire contract — changing them is a breaking change.

## How the mapping works

The mapping table lives in `pkg/audit/compliance.go` and is hand-written
because the judgement call ("does this action genuinely demonstrate the
control?") cannot be automated. The table maps **audit action prefixes**
to a list of **(framework, control_id, title)** tuples.

Lookup is a prefix walk:

```go
mappings := audit.ControlIDsFor("policy.create")
// → [
//   {nist-sp-800-53-r5, AU-2,  Event Logging},
//   {nist-sp-800-53-r5, AU-12, Audit Record Generation},
//   {nist-sp-800-53-r5, CM-3,  Configuration Change Control},
//   {nist-sp-800-53-r5, CM-5,  Access Restrictions for Change},
//   {nist-sp-800-53-r5, CM-6,  Configuration Settings},
//   {pci-dss-v4.0, 6.5,  Changes to system components managed securely},
//   …
// ]
```

The reverse lookup `ActionsFor(framework, control_id)` returns every
action prefix that demonstrates that control — used by the audit query
handler to turn `?framework=…&control=…` into an efficient SQL filter
without scanning the whole audit table.

## API surface

```
GET /api/v1/audit/events?framework=nist-sp-800-53-r5&control=AC-2
   → audit rows where the action demonstrates AC-2 (Account Management).
   → Response includes `control_mapping.matched_prefix` so an operator
     can see which action families were unioned.

GET /api/v1/audit/events?action=policy.create&with_controls=1
   → audit rows for the literal action, each decorated with its
     compliance mappings inline.

GET /api/v1/compliance/control-mappings
GET /api/v1/compliance/control-mappings?framework=pci-dss-v4.0
   → the static mapping table itself, optionally filtered to one
     framework.
```

All three endpoints require the `audit:read` verb (RBAC), so the
information is gated to operators with audit-log read access already.

## Adding a new mapping

When you add a new audit `Action` string, edit `pkg/audit/compliance.go`
to map it to the relevant controls.

`TestRulesCoverEveryDocumentedActionFamily` in `compliance_test.go`
enforces a minimum bar: every documented action prefix must have at
least one mapping. CI fails if you forget. The test does *not* check
that the mappings are *correct* — that's a human judgement call.

When evaluating "is this control a fit?", ask: **could an auditor
reasonably point to a row of this audit_events action and say 'this
demonstrates control X is being exercised'?** If yes, map it. If no
(stretch claim), don't — auditors penalise overclaiming.

## Cross-framework rationale

| Audit family       | Why it maps where                                                                 |
|--------------------|-----------------------------------------------------------------------------------|
| `auth.login.*`     | Direct evidence for IA-2 (identification/auth), AC-7 (failed login limits), AC-2 (account use). PCI 8.2/8.3 require authentication and identification records. ISO A.8.5 (secure authentication). |
| `auth.logout`      | AC-11/AC-12 session termination. PCI 8.2.8 requires session-end records.          |
| `group.*`, `role_binding.*`, `service_account.*` | The full RBAC lifecycle is AC-2 (account mgmt) + AC-5 (separation of duties) + AC-6 (least priv) + IA-5 (authenticator mgmt). SOC 2 CC6.2 (new-user authorization) and CC6.3 (modify/remove). PCI 7.x (access model + enforcement). |
| `finding.*`, `image.accept-risk*` | CA-5 (POA&M — accepted risks must be tracked), RA-5 (vuln monitoring), RA-7 (risk response). SOC 2 CC4.2 (deficiency communication). |
| `policy.*`, `response_rule.*`, `*_profile.*`, `dlp_sensor.*`, `waf_group.*`, `routing.*`, `settings.*` | All represent authorized configuration changes — CM-3/CM-5/CM-6, AU-12. PCI 6.5 (secure change mgmt). |
| `runtime.alert.*`, `admission.deny`, `baseline.transition`, `gitops.drift.detected`, `component.crashloop` | Hot incident-response evidence. SI-4 (monitoring), IR-4 (incident handling), AU-6 (review). PCI 10.4/10.7/12.10. |
| `receiver.*`       | The alerting plumbing itself — IR-6 reporting paths. SOC 2 CC2.3 (responsibility communication). |
| `backup.*`         | CP-9 (backup), CP-10 (recovery). SOC 2 A1.2 (data backup/recovery). ISO A.8.13 (information backup). |
| `registry.*`, `scan-job.*`, `cluster.cross-scan` | RA-5 + SI-2 + SI-3 (vuln/flaw/malware). SR-3 (supply chain) for registry trust events. |
| `compliance.*`     | The framework subsystem itself — CA-2 (control assessments), CA-7 (continuous monitoring), PM-31 (continuous monitoring strategy). |
| `cluster-init-bundle.*` | Bootstrap-token lifecycle — IA-5 (authenticator mgmt), AC-2 (account mgmt). |
| `federation.*`, `fed_member.*` | Cross-tenant data exchange — AC-21 (info sharing), CA-3 (info exchange). |
| `ai.query`, `ai.tool` | AC-3 (access enforcement) + AU-2/AU-12 for record-of-AI-actions. NIST AI RMF mappings are tracked separately at this stage; ISO 42001 is still emerging. |

## Out of scope at v1

- **NIST AI RMF** (AI Risk Management Framework, 2023) and **ISO/IEC 42001**
  (AI management systems, 2023). Both are still rapidly evolving. We log
  the AI-action audit events with conservative NIST 800-53 mappings (AC-3,
  AU-2, AU-12) and will add the AI-specific mappings once the auditor-side
  guidance settles.

- **HIPAA Security Rule § 164.312**. HIPAA bodies map cleanly to a subset
  of NIST 800-53 (the SP 800-66 crosswalk), and we publish the 800-53
  mappings directly. A HIPAA-only customer can derive their answer from
  SP 800-66 without us shipping a separate mapping table that re-encodes
  the same information.

- **FedRAMP-specific overlay controls** beyond the SP 800-53 baseline. FedRAMP
  Moderate is a profile *of* SP 800-53; the audit mappings are identical.

- **Continuous evidence packaging**. The mapping table is the static
  layer; the operator still has to query, export, and package the
  resulting rows for an auditor packet. A future `constellationctl audit
  compliance-export --framework <fw> --window 90d` command would close
  that gap.

## Cryptographic integrity

The mappings are **information about** the audit log, not the audit
log itself. The chain-hash of every audit_events row covers the action
string, the actors, the target, and the before/after JSON — but not the
compliance mappings, which are computed at query time from a static
table.

This is the correct shape for an auditor: the recordkeeping evidence is
tamper-evident (the chain), and the compliance interpretation is a
documented, versioned mapping (this document + `pkg/audit/compliance.go`
under VCS) that the auditor can verify independently of the database.

## Related docs

- `docs/audit.md` — chain hash construction and verification.
- `docs/fips.md` — FIPS 140-3 build of the audit chain HMAC.
- `pkg/audit/compliance.go` — the mapping table itself (source of truth).
- `pkg/audit/compliance_test.go` — invariant tests (action coverage,
  framework string stability, ordering, no duplicates).
