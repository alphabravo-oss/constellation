# Constellation Frontend — UI rules (C1 "Triage Desk", ADR 0009)

Constellation renders on the shared AlphaBravo UI kit in `src/ui/` (copied
verbatim from Astronomer; see `../docs/ui/KIT.md`). Never edit `src/ui/` for a
Constellation-only need: extend through `ProductConfig`
(`src/lib/product-config.tsx`), product tokens in `src/index.css`, or wrapper
components outside `src/ui/`. A generic kit change goes to Astronomer first and
is copied back.

## Identity (the only things that differ from Astronomer)
- Teal is the single accent: active nav bar, primary buttons, text links
  (`text-link`), focus ring. No blue/violet anywhere.
- Severity color appears only on severity pills, severity numerals and risk
  dots. Never on card borders, backgrounds, bars or decoration. Charts use
  neutral bars with a severity-colored critical segment.
- Security icon set, one distinct icon per sidebar item; star-field login.

## Page anatomy
- `PageHeader` (title + at most one short description line; long prose goes
  into the info tooltip automatically) → one `VerdictBanner` (56 px strip:
  sentence + up to four `numbers` + Details) → the primary view.
- No stat-card stacks on list pages. Table metadata ("rows on this page",
  "selected") is never a KPI. `StatGrid` is only for detail pages.
- Tables: pass the toolbar into `DataTable` (`toolbar`, `toolbarEnd`,
  `exportOptions`): search, up to three filters, `MoreFilters`, a view toggle,
  one `Export` menu. Filter rows never wrap. Dense tables are full-bleed.
- Tabs are URL-synced (`useTabParam` / route tabs). Hubs (Policies, Agents,
  Signatures) are route tabs in `components/shell/hubs.tsx`.

## Naming
- Sentence case for nav, titles, buttons, tabs, filter values. Severity values
  Title case in pills ("Critical"); lifecycle values sentence case.
- One verb per action: Add, Create, Register, Export, Refresh.
- No NeuVector wording in primary navigation (it lives in Settings › Migration).

## Forms and states
- Kit controls only: `Select`/`Checkbox`/`Switch`/`TextInput` from
  `components/ui/form` (they render the kit's Radix controls). No native
  `<select>` or checkbox chrome.
- First load = skeleton (`LoadingState`), error = `ErrorState` with retry and
  correlation id, empty = `EmptyState` with the one action that fixes it.
  404/403 render inside the shell.
- Dedicated create/edit pages (no drawers for forms); advanced fields behind
  `Collapse`.

## Scope and breadcrumbs
- "Include system workloads" is the header switch (`lib/system-scope.ts`);
  pages read `useIncludeSystem(searchParams)`, never their own checkbox.
- Breadcrumbs never show ids: entity pages call `useCrumbLabel(name)` from
  `lib/page-title.ts`.

## Type
- Inter Variable + JetBrains Mono Variable, self-hosted. Nothing below 11 px
  (`text-micro`); stat labels 12/500; no uppercase data labels.
