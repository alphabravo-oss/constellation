# NeuVector Switchability Implementation Plan (2026-08)

Goal: make Constellation easy for NeuVector operators to adopt while preserving
Constellation's stronger architecture. This plan focuses on the product surfaces
called out in the 2026-08 local source review: feature parity, UI configuration,
visibility, layout, migration, and validation.

Source evidence:
- Constellation UI routes: `frontend/src/App.tsx`
- Constellation sidebar: `frontend/src/components/AppShell.tsx`
- Constellation migration UI: `frontend/src/pages/MigrationPage.tsx`
- Constellation component diagnostics: `frontend/src/pages/ComponentsPage.tsx`
- Constellation API client: `frontend/src/api/client.ts`
- Endpoint runbook map: `docs/NEUVECTOR-ENDPOINT-MAPPING-2026-08.md`
- NeuVector API surface: `/root/constellation-all/neuvector/controller/api/apis.yaml`
- NeuVector system config model: `/root/constellation-all/neuvector/controller/api/apis.go`

## Definition of done

The migration is complete only when all items below are implemented, tested, and
validated against both source-level evidence and runtime behavior.

- Every NeuVector primary workflow has a visible Constellation equivalent.
- Every Constellation route intended for NV users is reachable from sidebar,
  settings, or command palette.
- Migration imports have preview, audited apply, rollback, unsupported-object
  reporting, and import history.
- System, scanner, registry, network, syslog, auth, and component state are visible
  in one effective-config/operator view.
- API, UI, and e2e tests cover every new or changed route and mutation.
- A production deployment or deployable artifact is validated after the changes.

## Remaining execution plan

This section turns the remaining review findings into implementation slices. Each
slice must land with source-level tests, browser/API validation, and updated
evidence in this document.

### 1. Group-centered policy workflows

Reasoning: NeuVector operators think in groups first. Constellation already has
groups, learned group synthesis, mode promotion, group-to-group edges, and DLP/WAF
bindings, but the UI still does not consistently show where a group is used or
prevent unsafe edits/deletes.

Granular tasks:
- Add `GET /groups/{id}/usage` returning concrete references: group-to-group
  network edges, DLP/WAF sensor bindings, baseline/profile mode propagation
  targets, response-rule references, admission references when modeled,
  and a coverage summary with unsupported/not-yet-modeled reference families.
- Add group usage panel to `GroupDetailPage` with counts, links, and a warning
  when references make delete/change risky.
- Add shared `GroupPicker` component with empty/loading/error states, member
  count, mode badges, and search by name/criteria/member.
- Replace ad hoc group text fields in network/runtime/DLP/WAF/response editors
  with `GroupPicker` where those editors reference groups; response rules now
  persist and enforce `workload_match.group`.
- Add delete/update conflict detection: deletes are blocked by default when
  concrete references exist; force/cascade is a later explicit audited action.

Tests:
- Handler: usage endpoint returns only current org/cluster references and covers
  group-rule edges plus DLP/WAF bindings.
- Handler: delete rejects referenced groups and emits clear conflict payload.
- Component: `GroupPicker` handles loading, empty, error, selection, and search.
- Browser: group detail shows usage counts and conflict warning; linked policy
  pages open with the relevant filter.

Validation:
- Seed an NV-style group used by network and DLP/WAF bindings; confirm usage
  counts reconcile with source tables.
- Attempt delete of referenced and unreferenced groups and verify behavior/audit.

### 2. DLP/WAF sensor compatibility and migration

Reasoning: NeuVector has DLP sensors, WAF sensors, per-group bindings, and file
export/import routes. Constellation enforces DLP/WAF through runtime DLP rules,
DPI signatures, and `group_dpi_sensor_bindings`; migration must land exported NV
objects in enforceable rows without creating fake sensor objects.

Granular tasks:
- [x] Extend the NeuVector converter for `RESTDlpSensorExport`, `RESTWafSensorExport`,
  `/v1/file/dlp`, and `/v1/file/waf` payload shapes.
- [x] Convert DLP rules to `runtime_dlp_rules` category `dlp`; convert WAF/custom DPI
  patterns to category `waf` or `signature` based on operator/action semantics.
- [x] Convert `dlp_group`/`waf_group` group bindings to `group_dpi_sensor_bindings`
  when the referenced target group exists or is imported by the same preview;
  source sensor names are preserved in preview/report metadata.
- [x] Preserve complete provenance on imported rows: source path, cfg_type/federated status,
  original sensor name, and unsupported pattern details.
- [x] Add migration preview grouping so operators see sensors, rules, bindings, and
  unsupported rows separately.

Tests:
- [x] Unit: NV DLP export converts to runtime DLP rules.
- [x] Unit: NV WAF export converts to DPI/WAF rules.
- [x] Unit: unsupported PCRE/action/context combinations produce structured
  unsupported rows.
- [x] Handler: preview/apply persists converted rules idempotently and
  rollback removes them.
- [ ] Browser: imported DLP/WAF objects are visible from Migration, Policy Center,
  DLP Rules, and WAF/DPI Signatures.

Validation:
- [x] Compare converted object counts against a local NV fixture.
- [x] Confirm every imported row is either enforced by an agent bundle or reported as
  unsupported; no inert "sensor" rows.

Progress 2026-08-23:
- NeuVector DLP/WAF CRD, list, and REST-style sensor exports now preview as
  dedicated DLP/WAF migration rows, require a target cluster only when rules are
  present, and apply into `runtime_dlp_rules` with rollback snapshots.
- WAF imports use category `waf` and are listed by the WAF/DPI Signatures API,
  while DLP imports stay scoped to the DLP Rules API by default.
- Source `dlp_group`/`waf_group` scopes now preview/apply as
  `group_dpi_sensor_bindings` when the matching Constellation group already
  exists; missing groups remain structured unsupported mapping records.
- NeuVector group definitions with supported namespace, service+domain, id,
  cluster, or label selectors now preview/apply/rollback as Constellation groups
  before DLP/WAF group-scope bindings are resolved.
- DLP/WAF rule previews now expose exact NeuVector source paths, sensor/rule
  `cfg_type`, federated status, original sensor names, and source groups; applied
  `runtime_dlp_rules` descriptions retain the source path for auditability.
- Unsupported DLP/WAF pattern entries are no longer silently skipped: unsupported
  keys, empty values, and unsupported operators produce structured
  `dpi_pattern` rows with the original pattern details and source path.

### 3. Network activity filters and session actions

Reasoning: NeuVector's Network Activity workflow depends on stable tabs, saved
filters, server-side filter semantics, and visible action results. Constellation
has the tabs and core data but still needs reliable filter parity and audited
session actions.

Granular tasks:
- Define one serialized filter model for namespace, group, verdict, application,
  port, protocol, peer, and time range.
- Apply the same filters to map, conversations, sessions, PCAP context, rules,
  and threat tabs where each dimension is meaningful.
- Persist saved filters per cluster/user with import/export of filter JSON.
- Make backend list endpoints return `total`, `has_more`, and next cursor/offset.
- Add visible kill-session action results and audit event link.

Tests:
- Unit: filter serialization/deserialization and saved-view persistence.
- Handler: namespace/group/verdict/port/time filters alter SQL results.
- Handler: session kill is RBAC-gated, audited, and reports target/result.
- Browser: apply filters, save/reload view, export CSV, start PCAP dry-run, and
  kill a session in mocked mode.

Validation:
- Large seeded network data confirms no invisible truncation.
- UI counts reconcile between map, conversations, and sessions for same filter.

Progress 2026-08-23:
- Implemented the first saved-filter slice: per-user/per-cluster saved Network
  Activity workspace views with JSON import/export. The snapshot covers the
  currently implemented shared controls: tab, time range, namespace, verdict,
  verdict chips, protocol/application chips, namespace chips, kube-system
  visibility, endpoint-kind visibility, and internal/external scope.
- Verified with unit tests for serialization/import/merge and the shared
  persistence hook, plus a production-preview browser smoke for save, apply,
  import, export, reload, and URL synchronization.
- Added audited session-kill queue results: `DELETE /network/sessions/{id}`
  returns the target tuple, node, requested time, and audit id; the Sessions tab
  and floating live-session card surface the queued result.
- Added server-backed live-session filters for protocol, application, port, peer
  IP, workload, and node; the same filters drive count metadata and saved-view
  restore.
- Added PCAP/sniffer parity slice: `/runtime-pcap/start` now accepts and returns
  the runtime-agent's richer capture options (`bpf_filter`, `interface`,
  `file_count`, `file_size_mb`) and honors a 5-300 second capture window with
  server-side validation. `/runtime-pcap` list filters now support status,
  workload, protocol, source IP, destination IP, and destination port. The
  Network Activity PCAP tab exposes these controls, persists them in saved
  views/import/export, and uses the existing delete API for cancel/remove.
- Verified PCAP slice with runtime handler tests for start/list/claim, agent
  PCAP tests, saved-view tests, TypeScript type-check, lint, production build,
  and OpenAPI route gates.
- Added group-aware Network Activity filtering for the shared server-side
  workflow: map workloads/flows/recent flows, conversation graph, live sessions,
  and Network Activity Rules lifecycle now all accept `group` by id or name and
  return selected-group metadata. The UI group selector uses stable group ids for
  newly selected/saved views while remaining compatible with older name-based URLs
  and saved views.
- Verified group-filter slice with focused network/netpolicy handler tests,
  saved-view tests, TypeScript type-check, lint, production build, OpenAPI route
  gates, diff whitespace check, and a mocked production-preview browser smoke
  confirming `group=<group-id>` reaches map, conversations, sessions, and rules
  lifecycle and round-trips through saved views.
- Extended the same group context to runtime threat lists and PCAP capture lists;
  threat drilldown PCAP capture now defaults to the attributed `workload_id` when
  the runtime threat row has one. Verified with runtime handler tests and a
  mocked production-preview browser smoke covering Threats, PCAP, and the
  threat-to-PCAP workload default.
- Remaining network filter parity is limited to deeper per-row drilldowns that
  do not yet inherit all shared Network Activity filters, plus full E2E coverage
  of the combined PCAP/session/threat workflow.

### 4. Effective configuration provenance and mutability

Reasoning: NV centralizes system configuration. Constellation now shows effective
config, redaction, diff, revision, and applied component state, but provenance and
safe mutation are not complete.

Granular tasks:
- Add per-key provenance in backend responses: default, environment bootstrap,
  DB override, cluster override, federated override, linked-managed, redacted.
- Add PATCH support only for already mutable settings: scanner refresh/proxy,
  network proxy, syslog/SIEM mirror, TLS verification/CA bundle, retention where
  runtime consumers already poll revision.
- Return validation errors per field with redacted rejected values.
- Increment revision and write audit events with before/after redacted deltas.
- Show provenance and mutable/editable state per row in Effective Config UI.

Tests:
- Handler: secrets are redacted in GET, PATCH errors, audit, support bundle.
- Handler: PATCH increments revision and only changes allowed keys.
- Component: grouped rendering and provenance badges.
- Browser: patch a setting, see revision/diff/applied status update.

Validation:
- Dev environment patch for proxy/scanner/syslog fields; verify the relevant
  consumers observe the revision without restart where supported.

### 5. Policy Center completeness

Reasoning: NV users expect one policy home with hit counts, precedence ordering,
mode vocabulary, and import/export affordances. Constellation has the landing page
and mode vocabulary but not all action affordances.

Granular tasks:
- Add per-family hit-count summaries from existing audit/match tables.
- Add reorder controls to rule families with precedence endpoints: response
  rules, network rule edges, admission rules where order matters.
- Add export/import buttons that call real family-specific APIs, not generic
  placeholder links.
- Add family health badges: importable, ordered, enforced by agent/webhook,
  last hit, last changed, unsupported migration rows.
- Remove or avoid dead data fields until corresponding UI/action exists.

Tests:
- Component: mode mapping, family badges, and action visibility.
- Handler: reorder endpoints enforce RBAC and audit changes.
- Browser: every family opens, import/export works where supported, and reorder
  action changes visible order.

Validation:
- Static route/link audit confirms every Policy Center action targets an existing
  route/API.

### 6. Access control and SSO migration

Reasoning: Switching from NV requires trust that users, roles, and group mappings
will not overgrant access. Provider testing and mapping preview are required
before live cutover.

Granular tasks:
- Add provider test endpoint with short timeout and secret redaction for LDAP,
  SAML metadata, and OIDC discovery where safe.
- Add group resolution preview for configured group attributes and sample claims.
- Add mapped-role preview showing final role/domain/cluster/namespace scope.
- Add migration preview for NV users, roles, role mappings, and API token metadata
  with secrets omitted or reissue-required flags.
- Add unlock/force-reset actions with audit for local users.

Tests:
- Handler: provider tests redact secrets and timeout safely.
- Handler: mapping preview cannot grant roles outside allowed scope.
- Unit: NV users/roles convert without privilege escalation.
- Browser: create provider, test connection, preview mapping.

Validation:
- Run a fixture with multiple NV domains/groups and verify resulting access rows
  match expected least-privilege mappings.

### 7. Enterprise table scalability and layout standardization

Reasoning: Several pages now have better table controls, but every high-volume
surface must expose pagination/limits visibly and preserve operator state.

Granular tasks:
- Add `total`, `has_more`, and cursor/offset contracts to high-volume endpoints.
- Apply shared `DataTable` column chooser, CSV export, saved views, density, and
  refresh interval to scanner jobs, registries, components, groups, policies,
  timeline, findings, network sessions, and audit.
- Add YAML export only where the object can round-trip through an import API.
- Add detail panels where row navigation is too slow for repeated triage.

Tests:
- Handler: pagination contracts for each converted endpoint.
- Component: density/refresh persistence and export values.
- Browser: save view, reload, bulk action, export, and page through results.

Validation:
- Seed large datasets and verify no page silently truncates without a pager or
  `has_more` indicator.

### 8. Dashboard and operational posture reconciliation

Reasoning: NV's first screen exposes day-2 health. Constellation has stronger
signals but still needs reconciliation tests and scanner DB upgrade/apply status.

Granular tasks:
- Add scanner DB upgrade/apply revision status to dashboard and health surfaces.
- Add efficient handler rollups for component health, policy modes, top threats,
  CVE modes, exposed services, admission stats, and federation state.
- Link every tile to a filtered source page.
- Add reconciliation tests between dashboard counts and source endpoints.

Tests:
- Handler: dashboard summary uses bounded queries and includes new rollups.
- Browser: dashboard tiles navigate to filtered sources.

Validation:
- Seed dashboard data and compare each linked count to its source page/API.

### 9. Supportability lifecycle

Reasoning: Redacted support bundles are live, but enterprise support needs async
jobs, status, retention, and signed artifact lifecycle comparable to NV.

Granular tasks:
- Add persisted support bundle jobs with queued/running/ready/failed/expired
  states and expiration.
- Sign bundles when a deployment signing key is configured; expose signature
  metadata and verification instructions.
- Add download history and audit correlation.
- Add support bundle generation progress on Components and System Health.

Tests:
- Handler: non-admin denied, jobs audited, expired bundles inaccessible.
- Unit: signature metadata and redaction.
- Browser: create job, poll status, download ready bundle.

Validation:
- Inspect generated bundle and signature; confirm no configured secrets appear.

### 10. API compatibility, schemas, and live fixture validation

Reasoning: Runbook switching depends on documented schemas and a live fixture
showing that imported NV configuration lands in working Constellation surfaces.

Granular tasks:
- Expand OpenAPI request/response schemas for network rules, admission assess,
  registry sync/cancel, event export, PCAP start, support bundle, group usage,
  and DLP/WAF bindings.
- Add link checker for endpoint mapping docs.
- Add CLI recipe smoke tests against local preview/API where feasible.
- Add a complete NV fixture and expected object-count manifest.
- Add a "new org from NV fixture" validation script: preview, apply, inspect
  counts, open key UI routes, rollback.

Tests:
- OpenAPI generation/completeness tests for every new route/schema.
- Script test for docs recipes using mock or local dev server.
- Handler: preview/apply/rollback fixture count assertions.

Validation:
- Local deployable artifact plus browser/API smoke for the fixture cutover path.

## Phase 0 - Discovery and compatibility map

Reasoning: the fastest way to reduce switching friction is to meet operators in
their existing mental model before changing behavior.

Tasks:
- [x] Add a NeuVector switchboard route in cluster context.
- [x] Map NV labels to current Constellation pages: Workloads/Services, Hosts,
  Controllers, Enforcers, Scanners, Groups, Policy, Network Activity, Security
  Risks, Events, Notifications, Settings.
- [x] Add route aliases or command-palette synonyms for NV terms.
- [x] Add sidebar entry for the switchboard near Dashboard.
- [x] Add settings entry for migration/switching.
- [x] Add e2e coverage that the route renders and each primary mapped link exists.

Validation:
- [x] `npm run type-check`
- [x] `npm run build`
- [x] Playwright route smoke: `/clusters/:id/neuvector`
- [x] Static search: every route added to App also has a sidebar, settings, or
  command-palette entry.

Acceptance:
- A NeuVector operator can start from the sidebar or command palette and find the
  equivalent Constellation surface for every major NV navigation area.

## Phase 1 - Migration import apply and rollback

Reasoning: current migration is preview-only, which blocks real switchovers. NV
supports broad config import/export, including local and federated configuration.

Tasks:
- [x] Define `migration_imports` table: id, org_id, source, source_hash,
  status, preview_json, applied_json, rollback_json, unsupported_json,
  created_by, applied_by, created_at, applied_at.
- [x] Add `POST /migration/preview` response IDs so a preview can be applied.
- [x] Add `POST /migration/imports/{id}:apply` with audited live apply for
  converted policies.
- [x] Add `POST /migration/imports/{id}:rollback`.
- [x] Add `GET /migration/imports/{id}/rollback-bundle` for the persisted
  rollback snapshot captured during apply.
- [x] Add import history and status detail in the UI.
- [x] Convert safe NeuVector network allow rules from REST policy exports and
  `NvSecurityRule` ingress/egress CRDs into `group_rule_edges`; preserve deny,
  disabled, L7 application-scoped, malformed, or missing-group rules as
  structured unsupported rows.
- [x] Convert NeuVector file monitor profiles into workload-scoped
  `file_profile_states` and `file_profile_rules` when the referenced group
  resolves to discovered target workloads; unresolved profiles remain structured
  unsupported rows.
- [x] Convert NeuVector process profiles into workload-scoped
  `process_baseline_states` and `process_profile_rules` when the referenced
  group resolves to discovered target workloads; unresolved or unsafe wildcard
  process rules remain structured unsupported rows.
- [ ] Convert remaining NeuVector config sections: vulnerability profiles,
  compliance profiles, registries, auth providers where secrets are available,
  syslog/webhooks, and federation metadata where safe.
- [x] Convert NeuVector group definitions with supported selectors to
  Constellation groups and report unsupported selectors as structured migration
  rows.
- [x] Emit unsupported-object rows with source path, reason, suggested manual fix,
  and data sample.
- [x] Make policy applies idempotent by import status and deterministic names.
- [x] Add audit events for preview, apply, rollback, skipped object, and failure.

Tests:
- [x] Unit: NeuVector group config converts into expected Constellation DTOs.
- [x] Unit: unsupported group criteria produce structured unsupported rows.
- [x] Unit: NeuVector REST and CRD network allow rules convert into group edges;
  unsupported network semantics remain explicit unsupported rows.
- [x] Handler: preview cannot mutate DB.
- [x] Handler: apply creates rows, second apply is idempotent.
- [x] Handler: rollback restores prior state.
- [x] Handler: network rule apply creates group edges and rollback deletes or
  restores them.
- [x] Handler: file-profile apply resolves target group members, writes
  workload file monitor rules, and rollback deletes or restores them.
- [x] Handler: process-profile apply resolves target group members, writes
  workload process baseline states/rules, and rollback deletes or restores them.
- [x] Handler: RBAC denies non-admin apply/rollback.
- [ ] E2E: paste NV export, preview, apply dry-run, live apply, view history.

Validation:
- [x] Compare imported object counts against source config.
- [x] Verify audit log contains import lifecycle events.
- [x] Verify rollback bundle can be downloaded and replayed.

Acceptance:
- A NeuVector export can be imported into Constellation with a persistent,
  audited, reversible workflow.

Progress 2026-08-24:
- NeuVector `RESTPolicyRule` network exports and `NvSecurityRule` ingress/egress
  CRDs now preview as dedicated Network Rules rows in Migration Imports.
- Apply upserts validated `group_rule_edges` after groups are imported, so
  same-export group definitions can satisfy edge references. Rollback deletes
  newly-created edges and restores previous ports/mode/comment for updates.
- Unsupported network semantics are not approximated: deny, disabled,
  application-scoped, malformed port/range, and missing-group rules are reported
  with source metadata and suggested manual remediation.
- NeuVector file monitor profiles now apply to every resolved workload member of
  the source group. Profiles without a selected cluster, missing group, or empty
  group membership remain queued as unsupported rows instead of becoming no-op
  imports.
- Migration apply and rollback now enforce `manage-policies` inside the
  handler, including API-token scope narrowing and custom-role grants, so direct
  handler paths cannot bypass the router RBAC gate.
- Applied imports now expose a durable rollback-bundle download from Import
  History. The bundle is served from persisted `rollback_json`, audited, and
  denied until an apply has captured replayable state.
- Migration preview now includes NeuVector source object counts by family
  (`source_counts`, `source_total`) and flags `unaccounted_source` when converted
  plus unsupported rows do not reconcile with the export.
- NeuVector process profiles now apply to every resolved workload member of the
  source group. Imported allow/deny entries seed Constellation process baseline
  rules, and rollback removes newly-created states/rules or restores prior rows.

## Phase 2 - Effective system configuration

Reasoning: NV centralizes many operator knobs under system config; Constellation
has strong settings pages but the effective runtime state is fragmented.

Tasks:
- [x] Add `/settings/effective-config` UI backed by `systemConfigApi.get`.
- [x] Group config by platform, scanner, registry, network, syslog/SIEM, auth,
  retention, backup, federation, and runtime enforcement.
- [x] Show row-level source classification: default, stored, redacted secret,
  linked/managed, or disabled.
- [ ] Add exact per-key provenance when backend exposes it: environment
  bootstrap, DB override, cluster override, and federated override.
- [x] Show revision, last changed by, last changed at, and audit link.
- [x] Add redacted JSON export view for the current effective config.
- [x] Add computed diff view for current vs previous/default effective config.
- [x] Show per-component applied revision using component diagnostics metadata.
- [ ] Add PATCH support only where backend config is already mutable.
- [x] Redact secrets and secret-like values consistently.

Tests:
- [ ] Component unit: redaction and grouped rendering.
- [ ] Handler: secrets never returned in clear text.
- [x] Handler: GET returns redaction-safe source/revision/update metadata.
- [ ] Handler: PATCH increments revision and audits change.
- [x] Browser smoke: page renders current config, metadata, coverage map, and redacted secrets.
- [x] E2E: page renders component applied status.

Validation:
- [ ] Patch scanner refresh/proxy/syslog test fields in dev and verify consumers
  observe the revision without restart where supported.

Acceptance:
- Operators can answer "what config is active, where did it come from, and which
  components have applied it?" from one page.

## Phase 3 - Operator component cockpit

Reasoning: NV exposes controllers, enforcers, and scanners directly. Constellation
has component inventory and diagnostics; the UI needs NV-oriented grouping.

Tasks:
- [x] Rename/alias component roles: controller/API, enforcer/runtime agent,
  scanner, admission, discoverer/importer.
- [x] Add role filter chips and NV role labels on Components.
- [x] Add support bundle download when backend enables redacted bundle
  collection; true signed artifact lifecycle remains tracked in Phase 14.
- [x] Add version drift matrix by component role.
- [x] Add upgrade/readiness gates and last heartbeat reason.
- [x] Add scanner queue/capacity counters into scanner rollups.
- [x] Link component diagnostics from System Health and cluster health.

Tests:
- [x] Unit: role alias mapping and diagnostics link generation.
- [ ] Component unit: role alias rendering.
- [x] Handler: diagnostics require admin gate.
- [x] E2E: component page exposes NV role filters and version drift matrix.
- [ ] E2E: filter to scanner/enforcer/controller and inspect diagnostics.

Validation:
- [ ] Seed heartbeat fixtures for each role and confirm expected rollups.

Acceptance:
- A NeuVector admin can find the equivalent of controllers, enforcers, and
  scanners and inspect live health without knowing Constellation internals.

## Phase 4 - Network activity workspace

Reasoning: Constellation's Network Map has strong capabilities, but NV users expect
stable tabs for map, conversations, sessions, sniffers/PCAP, rules, and threats.

Tasks:
- [x] Convert Network Map page into tabs: Map, Conversations, Sessions, PCAP,
  Rules, Threats.
- [x] Promote live sessions and kill-session controls from secondary panels into
  the Sessions tab.
- [x] Promote PCAP capture/sniffer controls into a PCAP tab.
- [x] Add saved workspace filters for the implemented Network Activity controls:
  tab, time range, namespace, server verdict, verdict chips, protocol/application
  chips, namespace chips, kube-system visibility, endpoint-kind visibility, and
  internal/external scope.
- [x] Extend live-session saved filters and backend params to protocol,
  application, port, peer IP, workload, and node.
- [x] Extend cross-tab saved filters and backend params to group for map,
  conversations, sessions, runtime threats, PCAP capture list, and Network
  Activity Rules lifecycle.
- [ ] Extend cross-tab saved filters and backend params to remaining port/peer
  and PCAP-specific dimensions where the corresponding server filters are not
  yet consistent.
- [ ] Ensure all server-side filters match UI filters, including threat and PCAP
  pivots.
- [x] Add session kill audit trail and visible queued-action result with target
  tuple, node, requested time, and audit row id.
- [x] Add live-session `total`, `limit`, and `has_more` response metadata and a
  visible truncation banner so capped session lists are not mistaken for complete
  inventory.
- [x] Add CSV export for conversations and sessions.

Tests:
- [x] Unit: filter serialization and saved-view import/export normalization for
  the implemented Network Activity model.
- [x] Unit: saved-view persistence hook reloads safely when storage keys change
  between cluster/user scopes.
- [x] Handler: group filters affect map, conversations, sessions, and Network
  Activity Rules lifecycle results.
- [x] Handler: group filters affect runtime threat and PCAP capture list results.
- [ ] Handler: remaining namespace/verdict/pagination coverage is complete for
  every Network Activity endpoint.
- [x] Handler: session kill queues the agent request, returns target/audit
  details, and writes a hash-chained audit event.
- [x] Handler: live-session response reports `total`, `limit`, and `has_more`
  when a requested page is capped.
- [x] Handler: live-session protocol/application/port/peer/workload/node
  filters affect the same count and row query.
- [x] E2E: Network Activity tab strip exposes map, conversations, sessions,
  PCAP, rules, and threats.
- [x] Browser smoke: save a Network Activity view, mutate filters, apply the
  saved view, import another view, export JSON, reload, and reapply the saved
  view from production preview.
- [x] Browser smoke: Sessions tab queues a mocked session kill and renders the
  queued target/audit result.
- [x] Browser smoke: Sessions tab shows a truncation banner when the API reports
  `has_more`.
- [x] Browser smoke: Sessions tab sends protocol/application/port/peer/workload/
  node filters to the API and restores them from a saved Network Activity view.
- [x] Browser smoke: group selector sends group id to map, conversations,
  sessions, and Network Activity Rules lifecycle, syncs the URL, and restores from
  a saved view.
- [x] Browser smoke: group selector sends group id to Threats and PCAP list
  requests; threat PCAP capture pane pre-fills the attributed workload.
- [ ] E2E: switch tabs, apply filters, start PCAP dry-run, kill session in mock.

Validation:
- [x] `go test ./internal/handler/network -run 'TestNetwork_KillSessionQueuesRequestAndAuditsTarget'`
- [x] `go test ./internal/handler/network -run 'TestNetwork_SessionsReturnsTruncationMetadata'`
- [x] `go test ./internal/handler/network -run 'TestNetwork_SessionsAppliesServerSideFilters'`
- [x] `go test ./internal/handler/network`
- [x] `go test ./internal/server -run 'TestGenerateOpenAPI|TestOpenAPICompleteness|TestOpenAPINoNewStubs'`
- [x] `npm --prefix frontend run test -- network-saved-views useSavedViews`
- [x] `npm --prefix frontend run type-check -- --pretty false`
- [x] `npm --prefix frontend run lint`
- [x] `npm --prefix frontend run build`
- [x] Mocked browser smoke against `http://127.0.0.1:4173/clusters/cluster-1/network`
  using system Chrome verified per-user/per-cluster saved view storage,
  save/apply/import/export, URL synchronization, and reload persistence.
- [x] Mocked browser smoke against `http://127.0.0.1:4173/clusters/cluster-1/network`
  using system Chrome verified session-kill confirm, DELETE call, queued result
  banner, target tuple, audit id rendering, and live-session truncation banner.
- [x] Mocked browser smoke against `http://127.0.0.1:4173/clusters/cluster-1/network`
  using system Chrome verified live-session filter query params and saved-view
  round trip for protocol/application/port/peer/workload/node.
- [x] Mocked browser smoke against `http://127.0.0.1:4173/clusters/<cluster-id>/network`
  using system Chrome verified Network Activity group selector query params for
  map, conversations, sessions, and rules lifecycle plus saved-view round trip and
  compact filter-bar layout.
- [x] Mocked browser smoke against `http://127.0.0.1:4173/clusters/<cluster-id>/network`
  using system Chrome verified Threats and PCAP list group query params plus
  threat-to-PCAP workload defaulting.
- [ ] Large fixture confirms no silent truncation without pager/has_more.

Acceptance:
- The Network workspace matches or exceeds NV's operator layout while retaining
  Constellation's graph and policy-generation advantages.

## Phase 5 - Groups as the central policy object

Reasoning: NeuVector policy authoring revolves around groups. Constellation has
groups, but they must become visible inside every policy editor.

Tasks:
- [ ] Finish group picker coverage for runtime, file monitor, and any remaining
  response-adjacent editors that still reference groups.
- [x] Add shared `GroupPicker` with group search by name/comment/criteria/member,
  mode/member context, external compatibility, and network-rule source/destination
  wiring.
- [x] Add membership preview with criteria, member count, mode, and last matched.
- [x] Add concrete group usage map for stored group-rule edges and DLP/WAF
  bindings, including delete-conflict detection for referenced groups.
- [x] Add group usage map for modeled references: network rules, DLP/WAF
  bindings, process baseline state/rules, file profile state/rules/
  exceptions, response-rule `workload_match.group` references, and admission
  rule `spec.match.groups` references.
- [x] Add response-rule group binding: API create/list/update preserves
  `workload_match.group`, the form uses `GroupPicker`, runtime/threat response
  evaluation resolves cached group members plus pod-owner links before
  suppress-log/action dispatch, and referenced groups block delete/update.
- [x] Add admission-rule group binding: builder payloads persist
  `spec.match.groups`, the rules table exposes group scope, API assess/simulate
  and the live webhook use a DB-backed group resolver, and referenced groups
  block delete/update.
- [x] Add bulk promote/demote workflows for Discover/Monitor/Protect aliases.
- [x] Add conflict detection when deleting or changing a group used by policies.
- [x] Add import/export for group bundles with deterministic authored fields.
- [x] Add NeuVector group import through migration preview/apply/rollback for
  supported selectors.

Tests:
- [x] Component unit: group picker handles empty/loading/error states, search, and
  selection.
- [x] Handler: usage endpoint covers concrete group-rule edges and DLP/WAF
  bindings and delete rejects referenced groups with a conflict payload.
- [x] Handler: usage endpoint covers direct group-rule/DLP-WAF rows and
  member-derived process/file profile rows for current group members.
- [x] Handler/runtime: response-rule group selector matches cached members and
  pod owner links during pre-write suppress-log evaluation.
- [x] Handler: delete and reference-sensitive updates are blocked with conflict
  payloads while policy references exist.
- [ ] E2E: create group, use it in network rule, view usage, promote mode.

Validation:
- [x] Compare NV group export fixture shape to imported Constellation groups for
  REST-style groups and `NvGroupDefinition` selectors.
- [x] `go test ./internal/handler -run 'TestGroupsUsageMapsConcreteReferencesAndBlocksDelete'`
- [x] `go test ./internal/handler -run 'TestGroupsPromoteSupportsExplicitModeChangeAndProfilePropagation|TestGroupsUsageMapsConcreteReferencesAndBlocksDelete|TestGroupsListIncludesMembershipPreview'`
- [x] `go test ./internal/server -run 'TestGenerateOpenAPI|TestOpenAPICompleteness|TestOpenAPINoNewStubs'`
- [x] `npm --prefix frontend run test -- GroupPicker`
- [x] `go test ./internal/migration/neuvector ./internal/handler -run 'TestConvertGroups|TestEnterpriseMigrationApplyNeuVectorGroupsAndDPIBindingsFromSameExport'`
- [x] `npm --prefix frontend run type-check -- --pretty false`
- [x] `npm --prefix frontend run build`
- [x] `npm --prefix frontend run lint`
- [x] Mocked browser smoke: `/clusters/cluster-1/groups/group-1` renders
  policy usage counts, blocking references, concrete network/DLP rows, and
  coverage states.
- [x] Mocked browser smoke: `/clusters/cluster-1/network-rules/new` selects
  groups through `GroupPicker`, submits the expected rule payload, and verifies
  form labels are associated with controls.
- [x] Group list responses include a `membership` preview with criteria count,
  member count, policy/profile modes, and freshest matching deployment evidence;
  Group Detail renders it as a top-level membership preview panel.
- [x] Response Rule form selects groups through `GroupPicker`, submits compact
  `workload_match.group` payloads, and Group Detail usage counts response-rule
  references as blocking.

Acceptance:
- Groups are the default object operators use to understand and change policy.

## Phase 6 - Policy landing and mode vocabulary

Reasoning: Constellation has many policy surfaces, but they are split. NV users
expect one Policy area with ordered rules and clear mode semantics.

Tasks:
- [x] Add `/clusters/:id/policy` landing with tabs/cards for network rules,
  admission, runtime policies, process baselines, file monitor, DLP, WAF/DPI,
  response rules, vulnerability profiles, and groups.
- [x] Add vocabulary bridge: NV Discover/Monitor/Protect equals Constellation
  Learn/Monitor/Enforce where applicable.
- [x] Normalize badges and filters to show both labels where needed.
- [ ] Add per-rule hit counts where backend has data.
- [ ] Add ordered rule editor/reorder controls for rule types with precedence.
- [ ] Add export/import links for each policy family.
- [x] Add direct family-specific YAML import/export actions in Policy Center for
  Groups, DLP Rules, and Vulnerability Profiles using their real APIs.
- [x] Add Network Rules YAML export/import for authored manual rules and learned
  overrides, surfaced on both Network Rules and Policy Center.
- [x] Add WAF/DPI signature YAML export/import on Policy Center using the runtime
  signatures portable API.

Tests:
- [x] Component unit: mode mapping.
- [ ] E2E: every policy family is reachable from policy landing.
- [ ] Handler tests for reorder endpoints as they are added.

Validation:
- [x] Static route/link audit for all policy pages.
- [x] Mocked browser smoke: Policy Center exports/imports Groups YAML via
  `/groups:export` and `/groups:import`, exposes DLP YAML controls on the DLP
  family, and does not show DLP controls on Runtime Policies.
- [x] `go test ./internal/handler/network -run TestNetworkRulesPortableExportImportAuthoredOverrides`
- [x] `npm --prefix frontend run test -- PolicyCenterPage GroupPicker runtime-rule-provenance NeuVectorCompatibilityChips`

Acceptance:
- Operators can start in one Policy area and reach every enforcement or detection
  rule surface.

## Phase 7 - DLP/WAF sensor compatibility

Reasoning: NeuVector has sensors, groups, and rules. Constellation's model is
cleaner, but migration must explicitly map the concepts.

Tasks:
- [x] Add compatibility labels: DLP Sensors -> DLP Rules and bindings; WAF Sensors
  -> WAF/DPI Signatures and bindings.
- [x] Add UI-managed group scope for the shared DLP/DPI detector on DLP Rules
  and DPI Signatures pages, backed by `runtime/dpi-sensor-bindings`.
- [x] Make `sensor_id` optional for `runtime/dpi-sensor-bindings` by defaulting
  to a stable per-kind all-rules sentinel, matching the current agent bundle
  semantics.
- [x] Add migration mapping in switchboard and migration preview.
- [ ] Add sensor-like grouping UI only if needed to represent imported NV sensors.
- [x] Preserve rule provenance: imported, learned, user-created, federated.
- [x] Add import/export for DLP and WAF/DPI bundles.
- [x] Split/convert true NV WAF sensors into category `waf` rows where reset-path
  enforcement is required; current built-in WAF/DPI packs remain category
  `signature` and use the shared detector path.

Tests:
- [x] Unit: NV DLP/WAF config converts to Constellation rules and reports
  group binding candidates.
- [x] Handler: DPI group binding accepts omitted `sensor_id`, remains
  org-scoped, and preserves bind/list/unbind behavior.
- [x] Handler: migration preview/apply/rollback persists converted DLP/WAF rows.
- [x] Handler: migration preview/apply/rollback persists matching DLP/WAF group
  scope bindings, including groups imported by the same migration preview, and
  leaves missing target groups as unsupported rows.
- [ ] E2E: imported rules are visible from switchboard and policy landing.

Validation:
- [x] Confirm there are no fake "sensor" objects that are not enforced.
- [x] `go test ./internal/handler/runtime -run 'TestGroupSensorBindings_HTTP_RoundTrip|TestGroupSensorBindings_BoundGroupDefs|TestResolveSensorMACs'`
- [x] Mocked browser smoke: `/clusters/cluster-1/runtime-dlp` adds/removes a
  DLP/DPI group scope binding and submits no legacy `sensor_id`.
- [x] Policy Center, NeuVector Switchboard, DLP Rules, and WAF/DPI Signatures
  now show explicit `NV DLP Sensors -> DLP Rules` and
  `NV WAF Sensors -> WAF/DPI Signatures` compatibility labels with group-scope
  binding labels.
- [x] DLP YAML export/import is scoped to `category=dlp`; WAF/DPI YAML
  export/import is available from `runtime-signatures` and preserves structured
  pattern `op`/`context` metadata for WAF rows.
- [x] `runtime_dlp_rules` now stores `source`, `cfg_type`, and `source_path`;
  NeuVector migration apply stamps `neuvector/imported|federated`, YAML imports
  default to `import/imported`, built-ins seed as `builtin/predefined`, and DLP
  plus WAF/DPI tables show an Origin badge.

Acceptance:
- NV DLP/WAF exports land in enforceable Constellation objects with clear mapping.

## Phase 8 - Registry and scanner operator controls

Reasoning: NV exposes registry scan scheduling and scanner controls in more detail.

Tasks:
- [x] Surface existing registry policy fields: include/exclude repos, tag
  selection, max image age, rescan interval, and promotion threshold.
- [x] Add registry scan policy fields: rescan_after_db_update, repo_limit,
  tag_limit, custom interval/cron, ignore_proxy, and scan_layers display.
- [x] Surface existing registry-wide test and sync-now actions.
- [x] Add registry-wide stop/cancel active scan action.
- [x] Add registry operator summary for images seen, sync health, active jobs,
  pending jobs, and failed jobs.
- [x] Add live scanner queue counters: pending, retry-delayed, running,
  stale, failed, completed-last-hour, and oldest pending.
- [x] Add scanner worker and cache view under Scanner & CVE Sources.
- [x] Add recent scan job table with status filter and pause, resume, retry,
  and cancel controls.
- [x] Add failed job drawer with full error, retry state/timing summary, target
  metadata, and VulnDB provenance.
- [x] Add persisted per-attempt scan job retry history/ledger and expose it in
  the failed job drawer.
- [x] Add scanner DB freshness to settings.
- [x] Add scanner DB freshness to dashboard with DB version, freshness,
  scanner-worker coverage, queue state, and failed scan count.

Tests:
- [x] Handler: scan policy validation for new fields.
- [x] Handler: stop scan cancels in-flight jobs safely.
- [x] E2E: scanner and registry pages expose operator queue visibility.
- [x] Browser smoke: scanner page exposes queue visibility, failed-job drawer,
  cache inspector, and CSV export.
- [x] Browser smoke: registry row action cancels active scans, refetches job
  state, reports canceled count, and disables when idle.
- [x] Browser smoke: registry edit persists cron cadence, repo/tag limits,
  DB-update rescan, proxy bypass, and scan-layer visibility.
- [x] Handler/API: scan job attempts ledger records retry-scheduled, running,
  and exhausted attempts and exposes `/scan-jobs/{id}/attempts`.
- [x] Browser smoke: failed-job drawer loads persisted attempt history.
- [ ] E2E: edit scan schedule and sync now.

Validation:
- [ ] Seed registry fixtures and compare list/detail against NV field coverage.

Acceptance:
- Registry and scanner operations are no less controllable than NV and expose
  Constellation's deeper scan evidence.

## Phase 9 - Admission parity controls

Reasoning: Constellation has strong admission APIs; NV users need the same visible
state, criteria, stats, and test workflow.

Tasks:
- [x] Surface predefined admission profile templates in the Admission workspace,
  including preview, export, monitor/enforce override, enabled override, and
  audited import.
- [x] Add predefined risky-role shortcuts directly into the custom rule builder.
- [x] Add custom criteria catalog UI from admission options.
- [x] Show monitor/protect state, default action, failure policy, and configured
  webhook state fields.
- [x] Add live webhook liveness/applied-revision state from component health.
- [x] Add rule, criteria, and template stats.
- [x] Add cluster-scoped browser-persistent admission dry-run/test history with
  current-vs-protect outcomes and CSV export.
- [x] Add shared server-side audited admission dry-run history with retained
  org/cluster-scoped rows, clear action, assess/clear audit events, and UI merge
  with local immediate history.
- [x] Add dry-run current-vs-protect outcome diff for prospective images.
- [x] Add migration apply coverage for native NeuVector admission deny and
  exception rules; exception rules become active `action: allow` carve-outs when
  they include enforceable criteria, while scope-only exceptions stay disabled
  manual-review rows to avoid no-op enforcement.

Tests:
- [x] Unit: criteria builder compiles supported rule YAML.
- [x] Unit: admission webhook liveness and dry-run history helpers.
- [x] Unit: retained dry-run metadata overrides local fallback and server/local
  history rows de-duplicate.
- [x] Unit: admission risk shortcut presets map only to supported criteria.
- [x] Handler: assess persists retained dry-run history, exposes list/clear, and
  writes assess/clear audit events.
- [x] Unit: NeuVector native admission `rule_type: deny|exception`, `rule_mode`,
  `disable`, `comment`, and `name` criteria convert into supported
  Constellation admission policies or manual-review rows.
- [x] Handler: migration preview/apply persists native NeuVector admission deny
  and exception rules with audited apply.
- [x] Handler: assess endpoint handles all supported criteria.
- [x] E2E: admission workspace exposes state, rules, criteria catalog, profile
  templates, and dry-run profile preview.
- [x] Browser smoke: admission page exposes webhook liveness, records dry-run
  history, exports history CSV, and clears history.
- [x] Browser smoke: admission page loads retained history, posts scoped assess,
  merges the returned retained row, and sends scoped clear.
- [x] Browser smoke: admission rule builder applies a risk shortcut and posts
  the expected structured criteria.
- [ ] E2E: create criterion, dry-run pod, switch monitor/protect.

Validation evidence:
- [x] `go test ./internal/handler/policy -run 'TestAssessImageMatchesHandlesAdmissionCatalogSupportedCriteria|TestAssessImageMatchesDeniesOnCVEGate|TestBuildAdmissionSpecYAML_NewCriteriaRoundTrip|TestAdmissionCatalogKeysHaveBuilderCases'`

Validation:
- [ ] Compare imported NV admission rule fixture to rendered Constellation rule.

Acceptance:
- Admission control can be operated by dropdowns and dry-run tests, not raw YAML.

## Phase 10 - Logs, timeline, and reports

Reasoning: Constellation's unified timeline is useful, but NV users expect category
views for activity, audit, event, incident, threat, violation, and security logs.

Tasks:
- [x] Add category tabs on Timeline: Activity, Audit, Event, Incident, Threat,
  Violation, Security.
- [x] Preserve unified view as All.
- [x] Add advanced filters and saved views shared with Findings.
- [x] Add CSV export per view.
- [x] Add rich detail drawers for source-specific fields.
- [ ] Add risk reports feed for scan/compliance/admission events.

Tests:
- [x] Handler: category filters map to correct event sources.
- [ ] Handler: export respects filters and RBAC.
- [x] Browser smoke: advanced filters hit backend params, save/reload menu
  state, export CSV, and open source-specific detail drawer.

Validation:
- [ ] Ensure timeline count by category matches underlying source tables.

Acceptance:
- Operators can use either Constellation's unified timeline or NV-style log tabs.

## Phase 11 - Access control and SSO migration

Reasoning: Constellation's RBAC is strong, but NV users need provider testing,
group mapping preview, and migrated users/roles/API token handling.

Tasks:
- [ ] Add auth provider test endpoint for LDAP/SAML/OIDC where safe.
- [ ] Add group resolution preview and mapped-role preview.
- [ ] Add default-role, group-domain, and domain-scope mapping UI.
- [ ] Include users, roles, role bindings, and API token metadata in migration
  preview with secrets omitted or reissued.
- [ ] Add unlock/force-reset actions with audit.

Tests:
- [ ] Handler: provider test redacts secrets and times out safely.
- [ ] Handler: group mapping preview produces expected role/domain bindings.
- [ ] E2E: create provider, test connection, preview group mapping.

Validation:
- [ ] Migration fixture maps NV users/roles without privilege escalation.

Acceptance:
- Access control migration is understandable and testable before cutover.

## Phase 12 - Table and layout standardization

Reasoning: Findings has mature saved views and bulk actions; other enterprise
tables should not silently truncate or lose operator state.

Tasks:
- [x] Extend DataTable with optional column chooser.
- [x] Add saved views as a reusable hook.
- [ ] Add server-side pagination contracts to high-volume tables.
- [x] Add consistent CSV export affordances through the shared DataTable.
- [ ] Add YAML export affordances where object schemas support round-trip import.
- [ ] Add persisted density and refresh interval per page.
- [ ] Add detail side panels for list pages where row navigation is too heavy.

Tests:
- [x] Component unit: DataTable column chooser and table-key density persistence.
- [x] Component unit: DataTable CSV export respects visible columns and stable export values.
- [x] Component unit: saved view persistence reusable hook.
- [ ] Handler: total/has_more pagination for each converted endpoint.
- [ ] E2E: save view, reload page, bulk action, export.

Validation:
- [x] Mocked browser smoke: component inventory, system heartbeat, and cluster component CSV exports download expected files.
- [x] Mocked browser smoke: Findings CVE rollup and instance tables download expected CSV files.
- [ ] Large seeded datasets confirm no invisible cap without UI indication.

Acceptance:
- Every high-volume table is predictable, exportable, and scalable.

## Phase 13 - Dashboard operator posture

Reasoning: NV shows day-2 operational status quickly. Constellation should show
security and platform posture from the first cluster screen.

Tasks:
- [x] Add component health strip: controller/API, agents/enforcers, scanners,
  admission, discoverer/importer.
- [x] Add policy mode distribution.
- [x] Add top violations/threats.
- [x] Add critical CVEs by mode.
- [x] Add top network denies.
- [x] Add exposed services.
- [x] Add admission stats.
- [x] Add scanner DB freshness and version/status.
- [ ] Add scanner DB upgrade/apply revision status.
- [x] Add federation health when cluster participates in federation.

Tests:
- [ ] Handler: dashboard summary includes new rollups efficiently.
- [x] E2E: dashboard operator tiles link to their source pages.

Validation:
- [ ] Seed dashboard data and verify all linked counts reconcile with source pages.

Acceptance:
- The dashboard answers "what needs attention now?" across vuln, runtime, network,
  admission, compliance, and platform operations.

## Phase 14 - Supportability

Reasoning: Enterprise operations require diagnostics and support bundles comparable
to NV.

Tasks:
- [x] Define redacted JSON support bundle format with SHA-256 integrity metadata.
  True cryptographic signing remains pending until a deployment signing key is
  configured.
- [x] Add backend bundle generation for redacted config, component health,
  recent audit metadata, scanner state, policy summaries, versions, and
  environment metadata.
- [ ] Add async bundle job with persisted status and signed artifact lifecycle.
- [x] Add UI download action from Components/System Health.
- [x] Add redaction tests for secrets, tokens, cert private keys, and credentials.

Tests:
- [x] Unit: redactor catches known secret shapes, including struct-backed
  sections.
- [x] Handler: non-admin denied; admin request audited.
- [x] Browser smoke: generate bundle and download metadata from System Health
  and component diagnostics with mocked API routes.

Validation:
- [x] Inspect generated bundle to confirm configured secrets are not in clear
  text.

Acceptance:
- Support can request a bundle without requiring shell access or manual DB dumps.

## Phase 15 - API compatibility and documentation

Reasoning: switching also means scripts, runbooks, and operators can find the
equivalent API quickly.

Tasks:
- [x] Add OpenAPI download/link in Settings.
- [x] Add NV-to-Constellation endpoint mapping document.
- [x] Add CLI recipes for common NV workflows: export/import config, list groups,
  create network rule, scan registry, test admission, export logs.
- [x] Add route aliases where they do not create API ambiguity.
- [x] Add deprecation-safe aliases for terms like workload/service and
  agent/enforcer in UI search.
- [ ] Expand detailed OpenAPI request/response schemas for network-rules,
  admission assess, registry sync, event export, and PCAP start.

Tests:
- [x] OpenAPI generation test includes every registered route.
- [x] E2E: NeuVector route aliases redirect to Constellation destinations.
- [ ] Link checker for endpoint mapping docs.
- [ ] Smoke test CLI recipes against dev server where possible.

Validation:
- [x] Runbook review: each NV primary endpoint family has an equivalent or an
  explicitly documented "not applicable; Constellation does X instead."
- [x] Mocked browser smoke: Cmd+K searches for agent, sniffer, vulndb, and
  service expose the expected Constellation destinations.
- [x] Mocked browser smoke: route aliases for agents, network-activity, events,
  incidents, admission-control, registry, vulnerability-profiles, system-config,
  vulndb, notifications, and sysconfig redirect to the intended pages.

Acceptance:
- Existing NV runbooks can be translated without source-code archaeology.

## Phase 16 - Better-than-NV onboarding

Reasoning: parity is not enough; Constellation's advantages should be visible at
the moment of migration.

Tasks:
- [x] Add migration/onboarding callouts for SBOM/VEX, repository scans, serverless
  scans, attestation trust, Git/config-as-code, signed compliance artifacts,
  stronger federation controls, and command palette.
- [x] Add post-import recommended actions: enable attestation trust, configure
  repo scans, schedule compliance reports, connect SIEM, enable backup.
- [x] Add readiness checklist with blockers/warnings/info categories.
- [x] Add exportable migration report.

Tests:
- [x] E2E: migration report renders and links to each recommended action.
- [x] Unit: readiness categories derive from preview/import history state.

Validation:
- [x] Mocked NeuVector import fixture shows clear next actions, not generic text.
- [ ] New org seeded from NV fixture shows clear next actions against a live API.

Acceptance:
- The product demonstrates where it is better than NV without hiding unfinished
  migration or enforcement work.

## Deployment and validation plan

For every implementation slice:

1. Static checks:
   - `npm run type-check`
   - `npm run lint` when touched files are in lint scope
   - `npm run build`
   - targeted `go test ./...` package runs for changed backend packages

2. UI checks:
   - Playwright smoke for new/changed routes
   - Screenshot check for desktop and mobile when layout changes are material
   - Route/link audit for sidebar, settings, command palette, and legacy redirects

3. API checks:
   - Handler tests for new endpoints and RBAC denial paths
   - OpenAPI regeneration/consistency test for every route
   - Audit-log assertions for every mutation

4. Data checks:
   - Migration fixture counts and unsupported-object reports
   - Idempotency checks for apply and rollback
   - Redaction checks for config/support-bundle exports

5. Deployment:
   - If `.openai/hosting.json` is present, deploy through Sites.
   - Otherwise build the frontend artifact and run the local preview server.
   - For backend/API changes, run the documented Compose or Helm deployment path
     in the target environment and verify `/health`, `/api/v1/system/health`,
     and changed route smoke tests.

6. Release gate:
   - No invisible truncation on changed high-volume pages.
   - No unaudited mutation.
   - No secret in exported config, diagnostics, support bundle, or logs.
   - Every new page has loading, empty, error, and permission-denied states.
