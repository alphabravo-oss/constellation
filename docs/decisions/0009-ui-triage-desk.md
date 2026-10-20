---
status: "accepted"
date: 2026-10-20
deciders: ["AlphaBravoCompany"]
title: "C1 Triage Desk UI on the shared AlphaBravo UI kit"
tags: [frontend, ui, design-system]
---

# C1 Triage Desk UI on the shared AlphaBravo UI kit

## Context

The 2026-10-20 UI audit (34 Constellation pages, light and dark) found the
product reading as a developer tool: every page opened with ~300 px of
verdict + stat-card chrome (the Findings table started at y≈680 on a 900 px
viewport), 10–11 px uppercase labels, severity red/orange used as decoration,
raw UUIDs in breadcrumbs, unstyled native selects, explanatory prose in the UI,
four export/refresh verbs per page, NeuVector terms in primary navigation, a
30-item one-open-accordion sidebar, spinner-and-em-dash loading and a 404
outside the shell. Constellation and Astronomer had drifted apart above a
shared token base (ADR 0001).

The owner chose **A1 Operator Console** for Astronomer and **C1 Triage Desk**
for Constellation, Inter Variable + JetBrains Mono Variable self-hosted, a
copied `src/ui/` kit this round, 3-mode theme, teal as Constellation's only
accent.

## Decision

1. **Shared kit.** `frontend/src/ui/` is a verbatim copy of Astronomer's kit
   (`docs/ui/KIT.md`). Constellation never edits it for product needs; identity
   enters through `ProductConfig` (`src/lib/product-config.tsx`: name, vendor,
   version, teal constellation mark, `loginHero: "starfield"`, router link) and
   the brand/ring slots in `src/index.css`. Kit changes go to Astronomer first
   and are copied back (re-synced to Astronomer `82f6c9a`).
2. **Identity.** Teal (`--brand 175 50% 31%` light / `174 52% 50%` dark,
   derived from the mark) is the only accent: active nav bar, primary button,
   text links (`text-link`), focus ring. The blue→violet `--color-brand*`
   tokens and the hex status set are gone; status and severity come from the
   kit's HSL light/dark pairs. Severity color appears only on severity pills,
   severity numerals and risk dots.
3. **Navigation.** Kit rail + panel. The rail is the organization scope
   (Clusters, CVE database, Posture, Audit log, Settings). Inside a cluster the
   panel shows always-visible groups: Overview · Inventory (Nodes, Workloads,
   Containers, Images, Registries, Serverless) · Vulnerabilities (Findings,
   Vulnerability profiles, Exceptions) · Runtime (Activity, Process baselines,
   File monitor, Signatures) · Network (Map, Rules, Incidents) · Policies ·
   Compliance · Agents — 20 destinations, one security icon each
   (`components/shell/nav-model.ts`).
4. **Hubs.** The four policy surfaces become **Policies** with route tabs
   Admission (admission rules · policy catalog) · Runtime · Network (groups and
   enforcement modes) · Response (response rules · built-in catalog). Sensor
   health + Components become **Agents**; DPI signatures + DLP rules become
   **Signatures**. Existing routes are kept; the hub frame
   (`components/shell/hubs.tsx`) renders the tab strip and demotes the inner
   page header to a section header.
5. **Header.** Cluster scope chip, the **System workloads** scope switch
   (replaces every page-level "Include Constellation system workloads" checkbox
   and "Platform hidden" button; URL `include_system` still overrides),
   breadcrumbs with names only (entity pages register labels through
   `useCrumbLabel`; ids fall back to the entity noun), one search that opens
   the kit palette (`/` and ⌘K), theme, notifications, account. Sign out is
   neutral.
6. **Page anatomy.** `PageHeader` (long prose becomes an info tooltip) → one
   56 px `VerdictBanner` with ≤ 4 inline numbers + Details → the primary view.
   Tables take their toolbar inside `DataTable` (search, ≤ 3 filters, More
   filters, view toggle, one **Export** menu) so the table starts near y≈240 at
   1440×900. Dense tables, logs and the network map are full-bleed.
7. **States and forms.** Kit skeletons, errors with retry + correlation id,
   empty states with one action, 404/403 inside the shell. Product
   `Select`/`Checkbox`/`Switch` keep their old APIs but render the kit's Radix
   controls (a hidden native mirror keeps form submission and programmatic
   change events working).
8. **NeuVector** wording leaves primary navigation: the switchboard, policy
   transfer and import history live under Settings › NeuVector migration and
   the command palette.
9. **Settings** is two layers (sidebar → settings page with its own section
   list); `/settings` redirects to Access control.

## Consequences

- Positive: Constellation and Astronomer share shell, rail/panel model,
  header, palette, PageHeader, tables, forms and states; they differ in accent,
  mark, icon motif, severity language, dashboard composition and login
  texture. Every list page leads with its table in the first screen.
- Positive: one place for scope (header switch) and one export verb.
- Negative: the kit is a copy until the Phase 2 package; drift is controlled by
  re-syncing from Astronomer before each release.
- Negative: theme preference is browser-local until the API exposes per-user
  preferences (backend ask).
- Follow-ups: extract `@alphabravo/ui` (Phase 2); move remaining StatGrid
  tiles on detail pages to the shared StatCard once the kit adds a compact
  variant.
