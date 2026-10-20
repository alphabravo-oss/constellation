# AlphaBravo UI kit (`frontend/src/ui/`)

The shared foundation both Astronomer and Constellation render from. It is
product-agnostic: nothing in `src/ui/` imports product code. A product injects
its identity through one `ProductConfig` (name, mark, login hero texture,
docs URL, router link) and overrides exactly three CSS slots (`--brand`,
`--brand-from`, `--brand-to`). Everything else — neutrals, status colors,
type scale, density, shell geometry, components — is identical in both.

Delivery in this round is a **copied directory**: `src/ui/` is copied
verbatim into Constellation (ADR 0009). Phase 2 extracts it to a package.
Until then: change the kit in Astronomer first, copy, never fork.

## Files

| File | Contents |
| --- | --- |
| `tokens.css` | Every token (neutral, brand, status, severity, elevation, motion, z-index, density, shell geometry, type scale) plus the Tailwind `@theme inline` mapping. |
| `kit.css` | Component layer: base element defaults, the data-table contract, sidebar item, gauge bar, gradient text, reduced-motion. |
| `product.tsx` | `ProductConfig`, `ProductProvider`, `useProduct`, `applyBrandAccent`, `hexToHslTriplet`. |
| `theme.tsx` | `ThemeProvider` (system/light/dark, server-synced through a `ThemeStorage` adapter), `useTheme`, `ThemeToggle`. |
| `primitives.tsx` | `Button`, `Kbd`, `Tooltip`, `Popover*`, `Menu*` (dropdown), `Skeleton`, `SkeletonText`, `StatusDot`. |
| `app-shell.tsx` | `AppShell` (sidebar / header / banners / offline / `<main>` + skip link / overlays), `OfflineBanner`, `ProductFooter`. |
| `sidebar.tsx` | `SidebarFrame` (240 px panel or 64 px rail, brand row, context slot, footer), `SidebarBrand`, `SidebarGroup`, `SidebarItem`, `Rail`, `RailItem`, `RailGroup` (flyout). |
| `header.tsx` | `Header` (56 px: scope · breadcrumbs · one search · actions), `Breadcrumbs` (renders only at depth ≥ 2), `HeaderIconButton`, `SearchTrigger`, `ScopeChip`. |
| `command-palette.tsx` | `CommandPalette` (Radix dialog + cmdk), `CommandGroup`, `CommandItem` (icon · title · description · hotkey). |
| `page-header.tsx` | `PageShell`, `PageHeader` (title · description · metadata · actions · tabs), `PageSection`, `PageEyebrowProvider`. |
| `stat-card.tsx` | `StatCard` (12/500 label, 28 tabular numeral, optional tone/bar/link), `StatGrid`. |
| `data-table/index.tsx` | Table chrome: `TableToolbar`, `TableSearch`, `ToolbarButton`, `FilterChip(s)`, `MoreFilters`, `ExportMenu` (the one export verb), `ColumnMenu`, `DensityToggle`, `SavedViewsMenu`, `Pagination`, `RowActions`, `EntityLink`, `EntityName`. |
| `form/index.tsx` | `Field`, `Input`, `Textarea`, `Select` (Radix), `Combobox` (cmdk), `Checkbox` (Radix), `Switch` (Radix), `ChoiceRow`, `FormShell`, `FormSection`. No native control chrome anywhere. |
| `confirm-dialog.tsx` | `ConfirmDialog`: destructive actions require typing the object's name; optional impact preview. |
| `states.tsx` | `StatePanel`, `EmptyState` (with the action that fixes it), `LoadingState` (skeletons, never spinners), `ErrorState` (retry + correlation id), `NotFoundState`, `ForbiddenState` (both inside the shell). |
| `tabs.tsx` | `Tabs` (WAI-ARIA automatic activation), `TabPanel`, `LinkTabs`, `useUrlTab` (`?tab=` deep links). |
| `verdict-banner.tsx` | `VerdictBanner`: 56 px strip, icon + sentence + ≤ 4 inline numbers + Details. |
| `collapse.tsx` | `Collapse` ("Advanced"), closed by default. |
| `toaster.tsx` | `KitToaster`: sonner bottom-right, 4 s, themed. |
| `cn.ts` | `cn()` = clsx + tailwind-merge, aware of the kit's font-size tokens. |

## Tokens

All colors are HSL triplets consumed as `hsl(var(--x))`; switching `.dark`
on `<html>` re-themes every utility without a rebuild.

**Neutral** — `background, foreground, card, popover, primary, secondary,
muted, muted-foreground (42 % light / 64.9 % dark: AA on 11–12 px),
accent, destructive, border, input, ring, sidebar*`. Light and dark values
are the shadcn/zinc set Astronomer shipped; Constellation's copy drifted at
`muted-foreground` and dark `destructive` and now matches.

**Brand** — `--brand` (accent), `--brand-foreground`, `--brand-from`,
`--brand-to` (gradient for the mark). Default: violet, blue → violet.
Constellation sets all three to teal. An operator branding color goes
through `applyBrandAccent(hex)`, which writes only these slots.

Where brand color may appear: the mark, the active nav indicator (the 2 px
bar in `SidebarItem` / `RailItem`), `Button intent="primary"`. Nowhere else.
Links, selected rows, focus rings and pagination are neutral.

**Status** — `success, warning, error, info, pending, neutral` as light/dark
pairs. Status color appears on pills, dots and numerals, never on borders or
card backgrounds. Every status is dot + label, never color only.

**Severity** — `critical, high, medium, low, info`: Constellation's signature
ramp; Astronomer uses it only inside image-scan views. `--color-status-high`
aliases `severity-high` for Astronomer's legacy `high` tone.

**Elevation** — `elev-1` (hairline), `elev-2` (card hover/popover-lite),
`elev-3` (drawer), `elev-popover` (menus, palette). Tailwind: `shadow-elev-*`.

**Motion** — `--motion-ease: cubic-bezier(.2,.8,.2,1)`, 100 / 160 / 240 ms.
Animations: `animate-fade-in`, `animate-rise`, `animate-pulse-dot`.
Reduced motion disables all three.

**Z-index** — sticky 10 · header 30 · chrome 40 · overlay 50 · popover 60 ·
toast 70 (`z-sticky` … `z-toast`).

**Density** — comfortable (default): `--row-py .75rem` → 44 px table rows,
`--control-h 2.25rem`, `--card-p 1.25rem`, `--gap-section 1.5rem`.
`<html data-density="compact">`: 36 px rows, 32 px controls, tighter
sections. The product persists the choice per user.

**Shell geometry** — `--sidebar-w 15rem`, `--rail-w 4rem`, `--header-h
3.5rem`, `--content-gutter 1.5rem`, `--content-max 100rem` (1600 px).
Contained pages center within `--content-max`; dense tables, logs and
graphs are full-bleed (`AppShell contentLayout="full-bleed"`).

## Type scale

| Token | Size | Use |
| --- | --- | --- |
| `text-page-title` | 24 / 600, tracking −0.02em | Page titles (`PageHeader`) |
| `text-section-title-lg` | 16 / 600 | Major section headings |
| `text-section-title` | 14 / 600 | Section headings, card titles |
| `text-body` | 14 / 400 (tables 450) | Everything |
| `text-meta` | 12 | Metadata, table headers (600, **no uppercase**), stat labels (500) |
| `text-micro` | 11 | Footer, kbd, hints. **Nothing renders below 11 px**: `text-2xs`, `text-9`, `text-10`, `text-11` all resolve to 11 px. |
| `text-13` + `font-mono` | 13 tabular | Identifiers and numbers |
| `text-stat` | 28 / 600 tabular | Stat numerals |

Uppercase is allowed for at most one or two eyebrows per page and never for
data labels, table headers, badges or stat labels.

Fonts: **Inter Variable** and **JetBrains Mono Variable**, self-hosted via
`@fontsource-variable/*`, imported once in `main.tsx`. No Google Fonts.

## Shell contract

- `AppShell`: skip link to `#main`, `<main tabIndex=-1>` focused on route
  change, offline banner under the header, overlays (palette, drawers,
  window manager) rendered as siblings of the frame.
- `Sidebar`: 240 px panel / 64 px rail. Groups with sentence-case 12/600
  headers, one icon per item, **no counts** (they belong in page content).
  Active item: neutral background + 2 px brand bar. Rail groups open a
  flyout (Radix popover, keyboard reachable). Footer: docs link + `Product
  x.y.z · Vendor`.
- `Header`: 56 px. Left: scope chip(s) only when a scope is selected, then
  breadcrumbs **only at depth ≥ 2** (`Breadcrumbs` returns null otherwise).
  Center: one `SearchTrigger` (`/` and `⌘K` open the same palette). Right:
  actions (assistant, theme, notifications, account) as 32 px icon buttons.
  The page title never lives in the header.
- `CommandPalette`: one visual style — 12/600 sentence-case group headings,
  14 px rows, description line, `Kbd` hotkey hints, footer hints.

## Naming conventions and glossary

Sentence case for navigation, page titles, buttons and tabs. Kubernetes kinds
keep their canonical casing (ConfigMaps, DaemonSets, CRDs). Industry
abbreviations are allowed in nav only when they are the term (RBAC, CVE,
CVSS, HPA, CRD); otherwise spell it out ("Access control", "Volume claims").

One verb per action: **Add** (attach an existing thing) · **Create** (new
object) · **Register** (clusters) · **Install** (tools/apps) · **Export**
(one menu: `Export ▾`, CSV scopes inside) · **Refresh**. Destructive actions
use `ConfirmDialog` with typed confirmation.

Shared nouns (identical in both products): Cluster · Node · Namespace ·
Workload · Pod · Image · Registry · Agent · Audit log · Settings · Access
control · API tokens. Product nouns stay: Astronomer — Fleet (delivery),
Sources, Bundles, Targets, Rollouts, Releases, Templates, Overrides, Tools
(installed), Catalog (installable), Applications (Helm releases);
Constellation — Findings, Exceptions, Policies, Compliance, Posture, Runtime,
Network map.

## Component rules

- **Tables** (`.app-data-table`): 44 px rows (36 compact), 14/450 body,
  12/600 headers without uppercase, mono 13 tabular ids/numbers, neutral
  entity links (underline, no color). The selection checkbox column is 32 px
  and hidden until the row is hovered/focused or a selection exists
  (`data-selection="idle" | "active"` on the wrapper). The **Name** column
  (`td[data-kind="name"]`) never truncates: it wraps. Toolbar order: search ·
  up to three filters · `More filters` · chips row · right: Views · Columns ·
  density · `Export ▾`. Pagination copy: "Showing 1–20 of 212".
- **StatCard**: tone colors the numeral only.
- **States**: first load = skeletons; refetch = inline indicator; empty =
  one primary action; error = retry + correlation id; 404/403 inside the
  shell.
- **Forms**: `Field` wraps label/control/helper/error; selects and
  comboboxes are Radix/cmdk; `FormShell` has a sticky footer for actions;
  secondary options go under `Collapse`.
- **Accessibility**: visible 2 px focus rings everywhere, landmarks
  (`<aside>`, `<nav aria-label>`, `<header>`, `<main>`), keyboard-navigable
  sidebar/rail/tables, dot + label status, AA contrast on 12 px text in
  both themes.

## Distinct by design

Astronomer: blue → violet gradient mark (Orbit), infrastructure icons
(Server, Boxes, Rocket, Gauge), fleet-first overview, terminal/YAML/wizard
surfaces, orbit/grid login texture.

Constellation: teal accent, line-art constellation mark, security icons
(Shield variants, Radar, Crosshair, Fingerprint), verdict strip on every
page, severity ramp/KEV/risk visuals, star-field login texture.
