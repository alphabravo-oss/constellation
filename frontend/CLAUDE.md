# Constellation Frontend — UX / Design Principles

These are hard rules for this UI, from direct user feedback (2026-08). Apply them to
EVERY page — the platform pages and, next, the cluster view (`/clusters/:id/*`).
When building or editing any page, conform to all of these.

## Layout & density
- **No cramped 2-column "main + narrow aside" layouts.** They feel dated and cramped.
  Prefer full-width, single-column flow with generous spacing, or an even multi-column
  grid — never a big column + a squished 360px sidebar of little cards.
- **Metrics are a full-width stat row**, not a cluster of tiny cards jammed into the
  PageHeader `actions` slot on one side. Use a proper `StatCard` grid across the top.
- Modern, spacious, breathing room. Bigger touch targets, clear hierarchy.

## Progressive disclosure (verdict-first)
- Every page answers its ONE question in the first screen: a `VerdictBanner` +
  a stat row + the primary view. Everything else is behind tabs / drawers / `Collapse`.
- Keep pushing disclosure further everywhere — if a page shows everything at once, it's wrong.

## Tabs
- **Tabs MUST be deep-linkable** via the URL (`?tab=<value>`). A user must be able to
  link straight to a tab. The shared `ui/tabs.tsx` is URL-synced — use it, don't
  reinvent local-state tabs.

## Forms & actions — NO BARE FORMS
- **Never render a bare/always-open form on a page.** To add something, show a **`+`
  (add)** affordance; to change something, show a **pencil (edit)** affordance. Both
  open a **Drawer** (`ui/drawer.tsx`) containing the form. Browsing a page shows lists/
  cards/verdict only — the form appears on demand.
- Inside a drawer form, hide expert fields behind `Collapse` ("Advanced").
- Give users real actions where the backend allows — e.g. "force update", "upload",
  "refresh now" — don't make a page display-only when an action is possible.

## Clarity — every page explains itself
- The user must never ask "what is this page / what is this for?" Each page has a
  PageHeader `description` in plain language (no unexplained jargon), and sections are
  labeled for what they DO. If a page's purpose isn't obvious, that's a bug.

## Reusable primitives (build on these, keep consistent)
- `ui/verdict-banner.tsx` — the top-line verdict (ok/degraded/critical/info).
- `ui/collapse.tsx` — "Advanced"/detail disclosure.
- `ui/tabs.tsx` — URL-synced tabs.
- `ui/drawer.tsx` — the home for every add/edit form.
- `ui/stat-card.tsx` — the metric tile; use in a full-width grid.
- `components/SettingsShell.tsx` — the grouped settings surface.
- Match the Astronomer-cloned design system (Inter, cool-gray, blue→violet, 8px,
  CSS-var tokens `var(--color-*)`).
