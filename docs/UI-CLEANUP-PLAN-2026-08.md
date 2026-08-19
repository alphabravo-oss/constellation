# Constellation UI Cleanup & Progressive-Disclosure Plan — 2026-08

> Status: **DRAFT for review.** No code changes until this is approved.
> Scope: the **platform (org-level) UI** — the pages you hit before entering a cluster.
> Explicitly **out of scope for now:** the in-cluster view (`/clusters/:id/*`). That is a
> separate, larger effort; this plan establishes the **patterns** we will reuse there.

Companion audits (evidence, with file:line citations) are summarized inline below and
were produced 2026-08-19 against `frontend/` + `internal/`.

---

## 0. Why this exists — the three diseases

Nothing here is meaningfully "broken" at the HTTP layer. The problems are:

1. **Density.** Pages dump every data point at one altitude. System Health renders ~10
   sections and 100+ data points with no top-line verdict. Access Control shows six RBAC
   concepts at once.
2. **Redundancy / duplicate homes.** Attestation Trust and API Tokens each appear in
   **three** places. "Coverage" has three names + a second unrelated coverage page. There
   are two health pages (`/health`, `/system-health`).
3. **Fragmented IA + half-finished migrations.** ~50 top-level routes. "Settings" is split
   across a sidebar Admin group and a `/settings` hub that **disagree** on which pages
   exist. The vulndb subsystem is being dropped, but the chart still defaults it **on**, so
   CVE-DB and VulnDB look alive-but-empty.

**North star:** *verdict first, detail on demand; one canonical home per feature; group by
scope.* Every page should answer its one question in the first screen, and reveal the rest
progressively.

---

## 1. The pattern playbook (reused by every phase — and the cluster view)

These are the reusable primitives. Build them once, apply everywhere.

### P1. Verdict-first page skeleton
```
┌─────────────────────────────────────────────────────────────┐
│  ●  <One-line verdict>            [scope/time controls]       │  ← status, derived
│     e.g. "Platform healthy · 12/12 components reporting"      │
├─────────────────────────────────────────────────────────────┤
│  [tile] [tile] [tile] [tile] [tile]                          │  ← 3–5 KPIs, always visible
├─────────────────────────────────────────────────────────────┤
│  ( Tab A ) ( Tab B ) ( Tab C )                                │  ← everything else, tabbed
│  … one focused view per tab …                                │
└─────────────────────────────────────────────────────────────┘
```
Rule: the fold shows **verdict + ≤5 KPIs + one primary table**. Nothing else is visible
without an interaction.

### P2. Disclosure mechanisms (in order of preference)
- **Tabs** for peer sub-views of one entity (Users | Roles | SSO…).
- **Row-expand / `<details>`** for per-item detail (a heartbeat's internals).
- **Drawer / modal** for *editing* (never a permanently-rendered form).
- **"Advanced" collapse** for expert fields (Rekor, predicate types, source globs).
- **Density toggle** for big tables (comfortable ↔ compact).

### P3. One canonical home per feature
Every feature is reachable from exactly **one** place. No teaser-card-that-links +
sidebar-item + own-page triads. Cross-references are links, not duplicate surfaces.

### P4. Consistent card contract
A card is one of: **(a) a live control**, **(b) a summary that links to its page**, or
**(c) a status readout** — and it looks like its kind. Never mix a static essay, an inline
wizard, and a live form as equal-weight peers (today's `/settings`).

### P5. Group by scope
Four scopes, always in this order: **Organization → Platform → Integrations → Cluster.**
Nav and URLs must agree with this grouping.

### Component inventory to build/verify (shared)
- [ ] `<VerdictBanner status="ok|degraded|critical" title detail />`
- [ ] `<Tabs>` (accessible, URL-synced `?tab=`)
- [ ] `<Drawer>` (right-side, focus-trapped) for editors
- [ ] `<Collapse label="Advanced">` / reuse existing `<details>` styling
- [ ] `<SettingsShell>` (left sub-nav + `<Outlet/>`)
- [ ] `<DensityToggle>` for `DataTable`

*(Audit note: some of these likely already exist in `frontend/src/components`; inventory
before building. Match the Astronomer re-skin design system already in place.)*

---

## 2. Information architecture — target route map

**Today:** ~50 flat routes; Org sidebar groups = Fleet / Catalog / Admin(8 flat).
**Target:** collapse to grouped, scope-ordered nav with one home per feature.

```
ORG (fleet) NAV
  Fleet
    • Clusters                     /clusters
  Security
    • Findings (fleet roll-up)     /findings          ← the LIVE Trivy/Grype vuln home
    • CVE Database                 /cve               ← rewired to live catalog (§3.1)
    • Posture (was "Coverage")     /posture           ← renamed, disambiguated (§3.3)
    • Compliance                   /compliance
  Settings  (single shell, left sub-nav — §4)
    Organization
      • Access Control             /settings/access
      • API Tokens                 /settings/api-tokens
      • Attestation Trust          /settings/attestation-trust
    Platform
      • System Health              /settings/health   ← moved under settings
      • Scanner & CVE Sources      /settings/scanner  ← replaces "Vuln DB" (§3.2)
      • Backup                     /settings/backup
    Integrations
      • Integrations & Routing     /settings/integrations
      • Connectors                 /settings/connectors
      • Migration Imports          /settings/migration
```

Deletions/merges (§ details below):
- **DELETE** `/settings/vulndb` (bbolt admin) → replaced by `/settings/scanner`.
- **MERGE** the `/settings` hub's teaser cards into the shell; kill triple-exposure.
- **RENAME** `/coverage` → `/posture`; fold `/settings/connectors` "coverage" naming so
  only one thing is called "coverage."
- **RESOLVE** `/health` vs `/system-health` — keep one (System Health), redirect the other.
- Route count target: **~50 → ~30** org-side.

---

## 3. Phase 1 — Vuln surface (highest confusion, clearest wins)

**Goal:** make **Findings** the single live vuln home, give the **CVE catalog a live data
source**, and delete the dead bbolt subsystem.

### 3.1 CVE-DB → live CVE catalog  *(decision: REWIRE)*
**Problem (audit):** `/cve` (`CVEPage.tsx`) reads `cve_records` via `/cve/stats`,
`/cve/search`, `/cve/bundle/status`. `cve_records` is written **only** by
`findings.ReconcileCVERecordsLoop` importing the dropped **vulndb bbolt bundle**
(`cve_import.go:191` is the sole `INSERT INTO cve_records`). No Trivy/Grype feed. With
vulndb gone → empty tables + `—` tiles. `cve_bundles`/`BundleStatus` is written only by the
dev seed tool (`cmd/constellation-seed/main.go:157`).

**Target:** a real, live CVE-intelligence catalog fed directly from upstream sources.

- [ ] New importer `internal/handler/findings/cve_intel_import.go` (name TBD) that upserts
      `cve_records` from live upstreams:
  - [ ] **NVD** JSON feeds (CVE id, description, CVSS v3.1/v4, CWE, references)
  - [ ] **CISA KEV** (known-exploited flag + date)
  - [ ] **EPSS** (exploit-probability score, updated daily)
  - [ ] **GHSA / OSV** (ecosystem advisories, affected ranges) — optional v2
- [ ] Replace `ReconcileCVERecordsLoop`'s `vulndbMatcher` dependency
      (`leaderelection.go:48`, `server.go:238`) with the new importer; drop the
      `BundleHash()` gate (`cve_import.go:233`).
- [ ] **Offline / air-gapped:** mirror-URL + interval settings, reusing the pattern already
      built for the scanner DB (`syscfg scanner_db_refresh_minutes`,
      `CONSTELLATION_SCANNER_OFFLINE_DB`). A file/S3 mirror of the NVD/KEV/EPSS snapshots.
- [ ] Schema: confirm `cve_records` columns cover KEV flag + EPSS; add migration if not.
- [ ] Remove the bbolt fallback in `cve.Get` (`cve.go:373`) and the seed-only
      `cve_bundles`/`BundleStatus` branch (`cve.go:769`, `CVEPage.tsx:176-181`).
- [ ] UI (`CVEPage.tsx`): apply **P1** — verdict line ("332k CVEs · synced 2h ago · N KEV"),
      keep 4 tiles, put the table behind the search (already the main content). Replace the
      dead "Bundle imported…" line with a live "Sources: NVD ✓ KEV ✓ EPSS ✓ · last sync".
- [ ] **Source-freshness** surfaced on `/settings/scanner` (§3.2), not a separate page.

**Tests/validation:**
- [ ] Importer unit test: given a fixture NVD/KEV/EPSS payload, `cve_records` upserts with
      correct KEV flag + EPSS score.
- [ ] `/cve/stats` returns non-zero against a seeded live import (not the bbolt path).
- [ ] Empty-upstream case degrades to a clear "sources not yet synced" state, not `—`.

### 3.2 VulnDB page → "Scanner & CVE Sources"  *(DELETE the bbolt admin)*
**Problem (audit):** `/settings/vulndb` (`VulnDBPage.tsx`) manages the bbolt bundle
(`/vulndb/status|:import|:rescan`). Once vulndb is retired it renders all `—` / "Not
present." The Grype package matcher (`internal/scanner/grype_matcher.go`) already "fills the
slot vulndb did."

- [ ] **Delete** `VulnDBPage.tsx` + its nav entry + `/vulndb/*` handlers
      (`server.go:1171-1173`) + `internal/handler/findings/vulndb.go` + the vulndb bbolt
      matcher + the importer CronJob.
- [ ] **Flip the defaults** that contradict the drop: `values.yaml:398` `vulndb: true→false`,
      scanner `vulndb-enabled` default (`cmd/constellation-scanner/main.go:68`) `true→false`.
- [ ] **New** `/settings/scanner` page: Trivy/Grype **DB freshness** (last update, source,
      offline mode), the scanner DB refresh interval (moved from the `/settings` Vuln-scanning
      card), and the CVE-intel source status from §3.1. One home for "scanner data health."
- [ ] Keep [[scanner-engine-posture]] intact — this only removes the dead vulndb path.

**Tests:** grep proves no remaining reference to `/vulndb`, `vulndbMatcher`, `bundledb`
outside deleted files; `helm template` renders with `vulndb.enabled=false` by default;
scanner starts clean without the flag.

### 3.3 Coverage → "Posture"  *(KEEP, rename, disambiguate)*
**Problem (audit):** `/coverage` (`CoveragePage.tsx`, titled "Posture Maturity") is live and
healthy, but has **three names** + collides with `ConnectorCoveragePage`
(`/settings/connectors`), and its "CVE Intelligence" row rides dead `cve_records`.

- [ ] Rename route `/coverage → /posture`; title, nav label, and command-palette entry all
      say **"Posture."** (`AppShell.tsx:171,601`, `CoveragePage.tsx:816`.)
- [ ] The connector page keeps "Connectors" only — remove any "coverage" wording so the word
      means one thing.
- [ ] Repoint the CVE-Intelligence row's evidence to the live source from §3.1 (or Trivy/Grype
      freshness) so it stops going red while scanning is live (`CoveragePage.tsx:236-244`).
- [ ] Apply **P1**: the page is already a roll-up; add a single top verdict
      ("Posture: 9/12 capabilities healthy").

### 3.4 Findings = canonical live vuln home
- [ ] No data change (already Trivy/Grype-backed, `server.go:639`). Ensure nav labels/CTAs
      point vuln-seeking users here, and CVE detail cross-links to `/cve/:id`.

---

## 4. Phase 2 — Settings shell (the structural fix)

**Problem (audit):** `/settings` is a flat hub of 8 unlike cards (`SettingsPage.tsx`) that
**disagrees with the sidebar** (Backup + Vuln DB only in sidebar; Connectors only on hub),
triple-exposes features, and embeds a heavy migration wizard inline.

**Target:** a real `SettingsShell` with a left sub-nav grouped by scope (**P5**), one home per
feature (**P3**), consistent card contract (**P4**).

```
/settings
┌───────────────┬─────────────────────────────────────────────┐
│ ORGANIZATION  │   <selected sub-page renders here>            │
│  Access Ctrl  │                                              │
│  API Tokens   │   (each sub-page is verdict-first, P1)        │
│  Attest Trust │                                              │
│ PLATFORM      │                                              │
│  System Health│                                              │
│  Scanner/CVE  │                                              │
│  Backup       │                                              │
│ INTEGRATIONS  │                                              │
│  Integrations │                                              │
│  Connectors   │                                              │
│  Migration    │                                              │
└───────────────┴─────────────────────────────────────────────┘
```

- [ ] Build `<SettingsShell>` (left sub-nav + `<Outlet/>`); move all `/settings/*` under it.
- [ ] Delete the flat hub's teaser cards; each becomes a real sub-page.
- [ ] Remove the duplicate Admin sidebar group — Settings is the single entry.
- [ ] Move the **Migration wizard** out of the hub into `/settings/migration` (summary +
      "Start import"; the code editor/preview lives on that sub-page only).
- [ ] Cut the "AI & residency" essay card to a short status + link (or a real toggle page).
- [ ] Fix the identity/scope mixing: user-scope identity stays top-level; org/platform items
      go to their groups.

**Tests:** every `/settings/*` route resolves inside the shell; nav and routes agree
(automated check that each nav item has a route and vice-versa); no feature reachable from >1
place (lint/list).

---

## 5. Phase 3 — System Health (density → verdict + tabs)

**Problem (audit):** `SystemHealthPage.tsx` renders **two overlapping health models** — live
telemetry (heartbeats/drift/crashloops/license) *and* a legacy static "catalog/signals/
incidents" model kept "for backwards compatibility" (`:37-46`, `:201-302`). ~10 sections,
5-col tiles, a 10-col heartbeat table with an overloaded "Details" cell. No top-line verdict.

**Target (P1 + P2):**
```
●  Platform healthy · 12/12 reporting · license 88d       [30s ↻]
[Healthy 12] [Drift 0] [Degraded 0] [Stale 0] [Crashloop 0]
( Clusters ) ( Components ) ( Crashloops ) ( Incidents & Actions )
  └ default tab: Clusters (per-cluster cards, <details> for versions)
```
- [ ] Add `<VerdictBanner>` derived from `summary` (green/degraded/critical).
- [ ] Keep only the 5 fleet tiles + license banner above the fold.
- [ ] Move heartbeat table → **Components** tab; collapse the "Details" cell into row-expand;
      add density toggle.
- [ ] Move crashloop timeline → **Crashloops** tab; incidents + remediation → **Incidents**
      tab (not a permanent aside).
- [ ] **Delete the legacy catalog/signals/incidents model** (`:201-302`) — it duplicates the
      live telemetry and is the biggest density offender. (Confirm nothing else consumes it.)
- [ ] Resolve `/health` vs `/system-health`: keep System Health, redirect the other.

**Tests:** page renders verdict + ≤5 tiles + one tab above the fold; removing the legacy model
doesn't break the live model; visual regression on the collapsed table.

---

## 6. Phase 4 — Access Control (confusing + read-only)

**Problem (audit):** `AccessControlPage.tsx` puts **six concepts** on one screen (users, roles,
permission matrix, scoped bindings, SSO, service tokens, guardrails); Roles + Permission
Matrix restate the same data; service tokens duplicate `/settings/api-tokens`. It's **100%
read-only** (no `useMutation`) yet the backend has `POST role-bindings` /
`POST service-accounts` (`server.go:906,908`) it never calls — a dashboard mislabeled as a
control surface.

**Target (P1 + P2 + P3):**
```
●  47 users · 6 roles · 2 SSO providers · 3 guardrails
( Users ) ( Roles & Permissions ) ( SSO / Auth ) ( Service Accounts ) ( Guardrails )
```
- [ ] Tabs as above; **merge** Roles cards + Permission Matrix into one "Roles & Permissions"
      tab (one representation, not two).
- [ ] **Remove** the Service Tokens card; consolidate with `/settings/api-tokens` (P3).
- [ ] Decide the page's identity:
  - [ ] **Option A (preferred):** wire the existing create endpoints — "Add user", "Bind
        role", "Create service account" — making it a real control surface.
  - [ ] **Option B:** rename to **"Access Overview"** and keep read-only (honest labeling).
- [ ] Move under the Settings shell at `/settings/access` (§4).

**Tests:** each tab loads independently; if Option A, create flows round-trip against
`server.go:906,908`; tokens exist in exactly one place.

---

## 7. Phase 5 — Attestation Trust (jargon + always-open editor)

**Problem (audit):** `AttestationTrustPage.tsx` is the **most complete/functional** page (real
cosign/SLSA/Rekor trust-policy CRUD, `server.go:1143-1147`), but the label assumes expertise
and it permanently renders a ~15-field `PolicyEditor` even when browsing.

**Target (P2):**
- [ ] Add one plain-language line: *"Verify image signatures/attestations before admission."*
- [ ] Move `PolicyEditor` (`:380-502`) into a **drawer** opened by "New policy"/Edit — not
      permanently rendered.
- [ ] Collapse advanced fields (predicate types, Rekor, source-ref globs) behind
      **"Advanced"**; show Name + Sources + verifier by default. (Keyless/public-key toggle
      already conditional at `:481`.)
- [ ] Single entry point under the Settings shell at `/settings/attestation-trust` (P3).

**Tests:** browsing shows only list + tiles (no editor); drawer opens/saves; advanced fields
hidden by default.

---

## 8. Sequencing & effort

| Phase | Scope | Risk | Backend work? |
|---|---|---|---|
| 1. Vuln surface | CVE rewire + delete vulndb + rename Coverage | Med (importer) | **Yes** (CVE importer) |
| 2. Settings shell | IA + one home per feature | Low | No |
| 3. System Health | verdict + tabs + delete legacy model | Low | No (maybe drop legacy endpoint) |
| 4. Access Control | tabs + wire-up/rename + dedupe | Low–Med | Maybe (create flows) |
| 5. Attestation Trust | drawer + collapse + label | Low | No |

**Recommended order:** 2 → 5 → 3 → 4 → 1. *(Do the pure-frontend IA/disclosure wins first for
fast visible progress and to prove the pattern playbook; land the CVE importer — the only
real backend lift — last, on its own.)*
**Alternative:** 1 first if killing the dead vulndb confusion is the priority.

## 9. Definition of done (every phase)
- [ ] Page opens to **verdict + ≤5 KPIs + one primary view**; the rest is behind
      tabs/drawers/collapse.
- [ ] Feature has **exactly one** home; nav and routes agree.
- [ ] No dead/`—` states from retired subsystems.
- [ ] Matches the Astronomer re-skin design system.
- [ ] `tsc` clean; visual check in the running app at `constellation.dev.alphabravo.io`.

## 10. Out of scope (next effort) — the cluster view
`/clusters/:id/*` (runtime, baselines, DLP, signatures, policies, response, network, timeline,
serverless, …) is the larger, "even worse" surface. It reuses **every pattern in §1**. We
tackle it after these five phases land and the playbook is proven.
