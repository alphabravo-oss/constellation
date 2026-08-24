# NeuVector Switchability Execution Matrix (2026-08-24)

This matrix is the working execution plan for the remaining NeuVector switchability
work. It consolidates the current review evidence from:

- `docs/NEUVECTOR-SWITCHABILITY-IMPLEMENTATION-PLAN-2026-08.md`
- `docs/NEUVECTOR-ENDPOINT-MAPPING-2026-08.md`
- `docs/nv-vs-constellation-assessment.md`
- local NeuVector source at `/root/constellation-all/neuvector`
- current Constellation source and live k3s deployment

The goal is not to clone NeuVector. The goal is to make every NeuVector primary
workflow obvious, importable where safe, enforceable where modeled, audited when
mutated, and visibly better when Constellation has stronger primitives.

## Engineering Rules

- Do not create inert compatibility objects. Imported data must land in an
  enforced Constellation model or be reported as unsupported with source path,
  reason, sample, and suggested manual remediation.
- No silent truncation on operator tables. High-volume APIs must expose `limit`,
  `offset` or cursor, `total` where affordable, and `has_more`.
- Every mutation must be RBAC-gated and audited with redacted before/after state.
- Every export must either round-trip through an import API or be clearly labeled
  as an evidence/report export.
- Every migration apply must be idempotent and rollback-capable.
- Every UI route added for NeuVector users must be reachable from sidebar,
  settings, command palette, or a documented route alias.
- Live deployment validation is required after backend or chart changes.

## Execution Slices

### 1. Migration Import Coverage

Reasoning: switchovers fail if exported NeuVector config can only be previewed or
partially imported. The existing workflow covers groups, safe network allow rules,
admission deny/exception rules, process/file profiles, DLP/WAF rules, and
rollback. Remaining config families need the same reversible treatment.

Granular tasks:
- Convert remaining NeuVector export families that have safe Constellation
  equivalents: vulnerability profiles, compliance profiles, registries without
  embedded secrets, syslog/webhook routing, auth provider metadata, users/roles,
  role mappings, API token metadata, and safe federation metadata.
- Add reissue-required and secret-omitted markers for data that cannot be safely
  imported, such as registry credentials and API token secrets.
- Add a complete fixture manifest with expected source counts, converted counts,
  unsupported counts, and post-apply database counts.
- Add a browser workflow for paste export, preview, apply, history, rollback
  bundle download, rollback, and post-rollback inspection.

Tests:
- Converter unit tests per NV family, including malformed, federated, and
  unsupported cases.
- Handler tests proving preview is read-only, apply is idempotent, rollback
  restores prior rows, and direct handler calls enforce `manage-policies` or the
  relevant admin verb.
- Browser/E2E test for the full import lifecycle with the complete fixture.

Runtime validation:
- In k3s, import the fixture into a disposable org or cluster, compare expected
  counts to live API/database rows, open Policy Center, Migration Imports,
  Groups, DLP, WAF, Admission, Registries, and Access Control, then rollback and
  verify rows are removed or restored.

Acceptance evidence:
- Fixture count manifest passes.
- Audit log contains preview/apply/skipped/failure/rollback events.
- Unsupported rows are actionable and no source family disappears silently.

### 2. Effective Configuration Provenance And Safe Mutation

Reasoning: NeuVector centralizes system configuration. Constellation already has
an effective-config view, redaction, revision metadata, diff, and component
applied state. The remaining gap is exact per-key provenance and a narrow PATCH
surface for settings whose consumers already support runtime reload.

Granular tasks:
- Add backend per-key provenance: default, environment bootstrap, DB override,
  cluster override, federated override, linked-managed, redacted.
- Add PATCH only for already mutable settings: scanner refresh/proxy,
  network proxy, syslog/SIEM mirror, TLS verification/CA bundle, and retention
  values that are polled by runtime consumers.
- Return field-level validation errors with rejected secret-like values redacted.
- Increment config revision and write redacted audit deltas.
- Render provenance and editable state per row in Effective Config.

Tests:
- Handler tests for redaction in GET, validation errors, audit, and support
  bundles.
- Handler tests that PATCH only changes allowed keys and increments revision.
- Component tests for grouped rendering, provenance badges, and redacted JSON.
- Browser test for patch, revision/diff update, and applied-state display.

Runtime validation:
- Patch scanner/proxy/syslog test fields in dev, verify the relevant consumers
  observe the revision without restart where supported, and verify secrets are
  never returned in clear text.

Acceptance evidence:
- Operators can answer what value is active, where it came from, who changed it,
  and whether components applied it.

### 3. Component Cockpit And Diagnostics

Reasoning: NeuVector operators look for controllers, enforcers, and scanners.
Constellation has richer component inventory, but role aliases and diagnostics
must remain obvious and tested.

Granular tasks:
- Finish component unit coverage for role alias rendering.
- Add E2E coverage for controller/enforcer/scanner filters and diagnostics.
- Add heartbeat fixtures for API/controller, runtime-agent/enforcer, scanner,
  admission, discoverer/importer, operator, and optional jobs.

Tests:
- Component unit tests for alias labels, version drift, and diagnostics links.
- Handler tests for admin-only diagnostics and redaction.
- E2E filter/drilldown test for each NV role alias.

Runtime validation:
- Seed heartbeats or inspect live component rows in k3s and confirm rollups,
  version drift, restarts, and diagnostics links render as expected.

Acceptance evidence:
- A NeuVector admin can find controller, enforcer, and scanner equivalents
  without knowing Constellation role names.

### 4. Network Activity Workspace

Reasoning: NeuVector's Network Activity workflow depends on map, conversations,
sessions, sniffers, rules, threats, saved filters, and visible action results.
Constellation has most of the workspace but still needs remaining filter parity
and large-data validation.

Granular tasks:
- Normalize the shared filter model across map, conversations, sessions, PCAP,
  rules, and threats for namespace, group, verdict, application, protocol, port,
  peer, workload, node, and time range.
- Add any remaining server-side filters where the UI already exposes controls.
- Add pagination or explicit `has_more` metadata for every list-like endpoint.
- Add combined E2E for tab switching, filter persistence, PCAP dry-run, and
  session kill in mock mode.
- Add large fixture validation so capped graph views are labeled and table views
  can page.

Tests:
- Unit tests for filter serialization and saved-view import/export.
- Handler tests proving every advertised filter changes SQL results.
- Handler tests for session kill RBAC, audit, and returned target.
- E2E/browser test for filters, saved views, PCAP dry-run, and session kill.

Runtime validation:
- Seed network flows/sessions/threats, compare counts across map,
  conversations, sessions, PCAP, and threats for the same filter.

Acceptance evidence:
- No network list silently hides rows, and operators can save/reload/share the
  same scoped view across tabs.

### 5. Groups As The Policy Centerpiece

Reasoning: NeuVector policy authoring is group-centered. Constellation groups now
have usage, imports, promotion, response-rule and admission-rule binding, and a
shared picker for network/response/admission rules; remaining work is broader
editor coverage and E2E validation.

Granular tasks:
- Finish `GroupPicker` wiring in runtime, file monitor, and remaining
  response-adjacent editors wherever those models reference groups.
- Count modeled group references as blocking: network edges, DLP/WAF bindings,
  response-rule `workload_match.group`, and admission-rule `spec.match.groups`.
- Add E2E create group, use in network rule, view usage, promote/demote mode,
  and verify delete conflict.

Tests:
- Component tests for picker state and search.
- Handler tests for usage references and delete/update conflicts.
- E2E for create-use-view-promote-delete-conflict.

Runtime validation:
- Seed an NV-style group used by network and DLP/WAF bindings, confirm usage
  counts reconcile with source tables and UI links.

Acceptance evidence:
- Groups are the default object for understanding and changing policy.

### 6. Policy Center Completeness

Reasoning: NeuVector users expect one policy home with hit counts, ordering,
mode vocabulary, and import/export affordances. Constellation now has the
landing page and several real portable APIs; remaining work is per-family
completeness.

Granular tasks:
- Add per-rule hit counts where backend match/audit data exists.
- Add reorder controls for families with precedence: response rules, network
  rules, admission rules where order matters, and future file/process rules.
- Add export/import links only for families with real round-trip APIs.
- Add family health badges: importable, ordered, enforced, last hit, last
  changed, unsupported migration rows.
- Add E2E route coverage for every policy family.

Tests:
- Component tests for mode vocabulary, health badges, and action visibility.
- Handler tests for reorder endpoints, RBAC, audit, and stable ordering.
- E2E for every family link and portable export/import where supported.

Runtime validation:
- Static route/link audit plus live API smoke for every visible action.

Acceptance evidence:
- Operators can start from Policy Center and reach every enforcement or
  detection rule without dead links or placeholder actions.

### 7. DLP/WAF Compatibility

Reasoning: NeuVector has sensors, groups, and rules. Constellation's detector
model is cleaner, but imported concepts must remain visible and enforceable.

Granular tasks:
- Add sensor-like grouping UI only if it maps to enforceable detector bundles;
  otherwise keep compatibility labels and provenance.
- Add E2E proving imported DLP/WAF rules appear from Migration, Policy Center,
  DLP Rules, and WAF/DPI Signatures.
- Preserve structured pattern metadata, source path, cfg type, federated status,
  and origin badges on every imported row.

Tests:
- Converter tests for DLP/WAF exports and unsupported patterns.
- Handler tests for apply/rollback and group bindings.
- E2E/browser test for imported visibility across all mapped surfaces.

Runtime validation:
- Import a fixture and verify agent bundle contents or explicit unsupported rows.

Acceptance evidence:
- No fake sensors exist; every imported row is enforced or reported.

### 8. Registry And Image Scan Report Parity

Reasoning: NeuVector's registry and image report views are dense operational
surfaces. Constellation now has scanner queue/capacity, registry policy fields,
config checks, and scan artifacts. Remaining work is fixture reconciliation and
report export/detail polish.

Granular tasks:
- Add E2E for edit scan schedule, sync now, cancel active scans, and failed-job
  drawer.
- Seed registry fixtures and compare list/detail coverage to NeuVector fields.
- Continue image-report parity: findings CSV export, image config metadata,
  base OS/size, per-layer CVE counts, module/CPE rollups, and accepted-CVE
  toggles where exception data exists.
- Keep scanner concurrency bounded and document memory sizing.

Tests:
- Handler tests for registry policy validation, sync/cancel/retry ledger, image
  detail artifact endpoints, and CSV/report exports.
- Component/browser tests for registry images, scan controls, failed drawer, and
  image report downloads.
- Scanner tests for config checks and artifact persistence.

Runtime validation:
- In k3s, sync a registry or scan representative images, open registry images
  and image detail, download evidence artifacts, and verify queue drains without
  OOM or leaked leases.

Acceptance evidence:
- Registry and scanner operations are at least as controllable as NeuVector and
  expose Constellation's deeper SBOM/VEX/provenance evidence.

### 9. Admission Controls

Reasoning: Constellation has strong admission APIs, but NeuVector users expect
state, criteria, dry-run, stats, and imported rule fidelity in one workspace.

Granular tasks:
- Add E2E for create criterion, dry-run pod/image, and switch monitor/protect.
- Compare imported NV admission fixture to rendered Constellation rules.
- Keep dry-run current-vs-protect outcomes and retained history audited.

Tests:
- Unit tests for criteria builder and shortcuts.
- Handler tests for assess criteria, retained history, RBAC, and migration apply.
- E2E for criterion creation, dry-run, and state switch.

Runtime validation:
- Apply an NV admission fixture, run assess against matching and non-matching
  images, and verify UI history and audit.

Acceptance evidence:
- Admission can be operated from dropdowns and dry-run tests, not raw YAML.

### 10. Logs, Timeline, And Reports

Reasoning: NeuVector exposes activity, audit, event, incident, threat,
violation, and security logs. Constellation's unified timeline is stronger but
must reconcile category views and exports.

Granular tasks:
- Add scan/compliance/admission risk report feed where appropriate.
- Ensure exports respect filters and RBAC.
- Reconcile category counts against underlying source tables.
- Preserve rich source-specific fields in detail drawers and CSV exports.

Tests:
- Handler tests for category filters, export filters, RBAC denial, and count
  reconciliation.
- Browser tests for saved views, advanced filters, CSV export, and detail drawer.

Runtime validation:
- Seed source events and compare timeline category counts to audit/runtime/
  network/compliance/admission source queries.

Acceptance evidence:
- Operators can use unified timeline or NeuVector-style category tabs with
  trustworthy counts and exports.

### 11. Access Control And SSO Migration

Reasoning: Switching requires confidence that users, roles, domains, and group
mappings will not overgrant access.

Granular tasks:
- Add LDAP/SAML/OIDC provider test endpoint with timeout and secret redaction.
- Add group-resolution preview and mapped-role/domain/cluster/namespace preview.
- Add default-role, group-domain, and domain-scope mapping UI.
- Add migration preview for NV users, roles, role bindings, and API token
  metadata with secret omission/reissue flags.
- Add unlock and force-reset actions with audit.

Tests:
- Handler tests for provider test redaction and timeout behavior.
- Handler tests that mapping preview cannot grant outside allowed scope.
- Converter tests for NV users/roles without privilege escalation.
- E2E for create provider, test connection, preview mapping.

Runtime validation:
- Run a fixture with multiple NV domains/groups and verify resulting access rows
  match expected least-privilege mappings.

Acceptance evidence:
- Access migration can be reviewed and tested before cutover.

### 12. Enterprise Table And Layout Standardization

Reasoning: High-volume operator tables must scale, preserve state, and export
predictably.

Granular tasks:
- Add server-side pagination contracts to remaining high-volume endpoints.
- Apply shared `DataTable` features: column chooser, CSV export, saved views,
  density, refresh interval, and detail panels where useful.
- Add YAML export only where schemas support import.
- Add large-data tests to catch invisible caps.

Tests:
- Handler tests for total/has_more pagination.
- Component tests for density/refresh persistence and CSV values.
- E2E for save view, reload, page, bulk action, and export.

Runtime validation:
- Seed large datasets and verify every capped response either pages or displays
  `has_more`.

Acceptance evidence:
- No high-volume surface silently truncates or loses operator state.

### 13. Dashboard Operator Posture

Reasoning: NeuVector's first screen emphasizes day-2 health. Constellation should
surface stronger scanner, admission, network, CVE, federation, and component
rollups with links back to source evidence.

Granular tasks:
- Add scanner DB upgrade/apply revision status.
- Add or harden efficient rollups for component health, policy modes, top
  threats, CVE modes, exposed services, admission stats, scanner DB freshness,
  and federation state.
- Link every tile to a filtered source page.
- Add reconciliation tests.

Tests:
- Handler tests for bounded queries and correct rollup fields.
- E2E for tile navigation.

Runtime validation:
- Seed dashboard data and compare each displayed count to its source API.

Acceptance evidence:
- Dashboard answers what needs attention now and every number is explainable.

### 14. Supportability Lifecycle

Reasoning: Redacted support bundles exist. Enterprise support still needs async
jobs, status, retention, signing, and download history.

Granular tasks:
- Add persisted support bundle jobs with queued/running/ready/failed/expired
  states and expiration.
- Sign bundles when a deployment signing key is configured and expose
  verification metadata.
- Add download history and audit correlation.
- Show generation progress on Components and System Health.

Tests:
- Handler tests for non-admin denial, job lifecycle, expiration, and audit.
- Unit tests for redaction and signature metadata.
- Browser tests for create job, poll status, and download.

Runtime validation:
- Generate a live bundle, inspect redaction, verify signature metadata when
  configured, and confirm expired bundles are inaccessible.

Acceptance evidence:
- Support can request diagnostics without shell or direct DB access.

### 15. API Compatibility, Schemas, And Runbook Validation

Reasoning: Switching also means scripts and runbooks can be translated without
source-code archaeology.

Granular tasks:
- Expand detailed OpenAPI schemas for network rules, admission assess, registry
  sync/cancel, event export, PCAP start/list, support bundle, group usage, and
  DLP/WAF bindings.
- Add a docs link checker for endpoint mapping recipes.
- Smoke test CLI recipes against a local dev server where feasible.
- Keep route aliases for NeuVector terms covered by E2E.

Tests:
- OpenAPI generation and completeness tests for every route.
- Link checker test for mapping docs.
- Script smoke tests for documented curl recipes using mock or local server.

Runtime validation:
- Fetch live `/openapi.json`, verify mapped routes exist, and run safe read-only
  recipes against k3s.

Acceptance evidence:
- NeuVector runbooks can be translated from docs and OpenAPI alone.

### 16. Better-Than-NeuVector Onboarding

Reasoning: Parity is not enough. Constellation advantages should be visible
during migration without hiding incomplete work.

Granular tasks:
- Validate the migration report against a live new-org fixture.
- Keep recommended actions linked: SBOM/VEX, repository scans, serverless scans,
  attestation trust, Git/config-as-code, signed compliance artifacts, SIEM, and
  backup.
- Ensure readiness checklist categories distinguish blockers, warnings, and
  informational improvements.

Tests:
- Unit tests for readiness categories.
- E2E for report rendering and action links.

Runtime validation:
- Import a NeuVector fixture into a new org and verify the report shows accurate
  blockers, imported objects, unsupported rows, and next actions.

Acceptance evidence:
- Operators see where Constellation is better while unfinished migration work is
  explicit and actionable.

## Deployment Gate For Each Slice

1. Source checks:
   - Targeted Go tests for changed packages.
   - Frontend unit tests for changed components/helpers.
   - `npm --prefix frontend run type-check -- --pretty false` for frontend
     changes.
   - `npm --prefix frontend run lint` and `npm --prefix frontend run build`
     when UI code changes.

2. API/chart checks:
   - `go test ./internal/server -run 'TestGenerateOpenAPI|TestOpenAPICompleteness|TestOpenAPINoNewStubs'`
   - Regenerate OpenAPI when routes change.
   - `helm lint deploy/charts/constellation`
   - `make helm-template-smoke`

3. Runtime checks:
   - Build/import changed images into k3s.
   - `helm upgrade` or targeted rollout restart.
   - Verify all Constellation pods are `1/1 Running` with no new restarts.
   - Check scanner/API logs for `ERROR`, `WARN`, `OOM`, and `panic`.
   - Smoke `/healthz`, `/readyz`, `/openapi.json`, and changed UI/API routes.
   - For scanner-related slices, verify queue leases do not leak and node
     pressure remains false.

4. Documentation:
   - Update `docs/NEUVECTOR-SWITCHABILITY-IMPLEMENTATION-PLAN-2026-08.md`
     with completed checkboxes and exact validation evidence.
   - Update `docs/NEUVECTOR-ENDPOINT-MAPPING-2026-08.md` when route/API
     coverage changes.
