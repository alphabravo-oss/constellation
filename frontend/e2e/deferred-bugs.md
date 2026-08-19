# Deferred UI bugs

Bugs discovered during the Playwright deep-ui walk that were NOT fixed because the
affected file is owned by a parallel UX-overhaul agent (or is out-of-scope for the
deep-ui bug-fix pass). Each entry: file → one-line description.

## Files owned by the parallel UX agent

These should be picked up by the redesign pass:

- **frontend/src/pages/risk/OverviewTab.tsx** — `entityType=deployment` (a perfectly valid third
  RiskDetail entity type) falls through to `/api/v1/assets/<id>` and 404s. Branch only
  handles `finding` vs default-asset; add a `deployment` branch hitting
  `/api/v1/deployments/<id>` so the route `/risk/deployment/:id` actually loads.
- **frontend/src/pages/RiskDetailPage.tsx** — no visible "back to entity" link / breadcrumb
  uses the raw entity uuid in the H1 (`Risk: 401d5ef7-…`). Worth an EntityHeader pass.
- **frontend/src/components/ScopeBar.tsx** — `Namespace` and `Label` chips have empty
  `options=[]` — they only accept free-text Enter. Wire them to the deployments
  endpoint (namespace facets) and the asset labels endpoint so the dropdowns are useful.
- **frontend/src/pages/CVEDetailPage.tsx** — `groupByEntity` only buckets the `images` map
  (asset_id), leaving `Affected Deployments (0)` and `Affected Clusters (0)` always
  empty even when the CVE *is* present in seed data. Needs to join through the
  deployments + clusters endpoints.
- **frontend/src/pages/CVEPage.tsx** (also coupled with CVEDetail) — each CVE search row
  is a plain `<li>` with no link to `/cve/:id`. Wrap the row in `<Link to={`/cve/${r.cve_id}`}>`
  so users can click into the detail page from the catalog.
- **frontend/src/pages/DashboardPage.tsx** + **FindingsPage.tsx** + **NetworkMapPage.tsx**:
  ScopeBar is rendered but the page never reads the scope when issuing queries, so
  selecting a cluster filter changes the URL but not the data on the page (the agent
  redesign will own this).
- **frontend/src/components/AppShell.tsx** — there is no top-nav entry for the "AI"
  page named in the spec brief; `/ai` is not routed anywhere. Confirm whether AI is
  rolled into Runtime → ML signatures or is a missing surface.

## Out-of-scope (backend contract — task says do not touch Go)

- `/api/v1/response-rules-v2` currently returns `"event_type": ""` for the seeded rules.
  The frontend renders this fine (shows the empty string), but a future seed pass should
  populate it with one of the enum values from `RRV2EventType`. Document only.
- `/api/v1/audit-events` returns 404; the audit page hits the correct path
  (`/api/v1/audit/events`), so no fix is needed in the UI. Document only.

## Deferred during the elite UX overhaul

- **Scope-aware queries** — DashboardPage / FindingsPage / NetworkMapPage all
  render the new ScopeBar (URL + localStorage persisted) but the `useScope()`
  hook output is not yet threaded into `findings.list({ cluster, namespace })`
  because the `/api/v1/findings` filter accepts neither today. UI is ready;
  backend filter params need wiring.
- **KEV + EPSS on findings** — `SeverityBadge` accepts a `kev` flag and the
  Findings DSL exposes `kev:true`, but `Finding` payloads don't yet carry the
  KEV flag; the FindingsPage currently uses a `severity=critical && risk>=88`
  heuristic as proxy. Backend should surface `kev_listed` + `epss_probability`
  on `/findings`.
- **Reachability** — `<ReachableBadge>` component is built and ready; awaiting
  backend reachability analysis to populate `reachable` on findings.
- **Heatmap cluster × namespace** — Dashboard's heatmap uses `kind` as the
  column axis because `Finding` payload lacks `cluster_id` / `namespace`.
  Swap when these are surfaced.
- **Dashboard subfactors** — Risk-score tooltip shows synthetic subfactors
  (Exploitability/Impact/Exposure/Asset criticality) derived heuristically.
  When `/findings/:id` returns a `risk.factors[]` block, drop the heuristic.

## Empty by design (not bugs)

- **Policies page** — seed has no policies (the spec only lists vuln profiles, WAF
  groups, and DLP sensors as seeded). The empty state ("No policies yet. Seed one via …")
  renders correctly.
- **Network Map flows** — `/api/v1/network/map` returns `flows=0` / `recent_flows=0`
  for the default 1h window; seed populates flows but they appear to age out before
  the page loads. UI surfaces a "No flows in window" message gracefully.
