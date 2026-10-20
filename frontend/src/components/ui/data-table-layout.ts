import type { ReactNode } from "react";

export type ColumnKind = "name" | "text" | "status" | "badge" | "count" | "percent" | "date" | "age" | "version" | "id" | "bytes" | "actions";
export type ColumnAlign = "left" | "center" | "right";
export type OverflowPolicy = "truncate" | "wrap-2" | "nowrap" | "middle" | "fixed" | "wrap" | "legacy";

export interface ColumnKindSpec {
  size: number;
  minSize: number;
  maxSize?: number;
  align: ColumnAlign;
  grow?: boolean;
  overflow: OverflowPolicy;
  numeric?: boolean;
  mono?: boolean;
}

// Adapted from Astronomer's semantic table model. Inline Edit/Delete controls
// need more room than its 48px overflow-menu-only action column.
export const COLUMN_KINDS: Readonly<Record<ColumnKind, ColumnKindSpec>> = {
  name: { size: 240, minSize: 160, align: "left", grow: true, overflow: "truncate" },
  text: { size: 200, minSize: 120, maxSize: 480, align: "left", overflow: "wrap-2" },
  status: { size: 120, minSize: 96, maxSize: 180, align: "left", overflow: "nowrap" },
  badge: { size: 120, minSize: 88, maxSize: 200, align: "left", overflow: "nowrap" },
  count: { size: 80, minSize: 64, maxSize: 120, align: "right", overflow: "nowrap", numeric: true },
  percent: { size: 88, minSize: 72, maxSize: 120, align: "right", overflow: "nowrap", numeric: true },
  date: { size: 160, minSize: 128, maxSize: 220, align: "left", overflow: "nowrap" },
  age: { size: 140, minSize: 72, maxSize: 160, align: "left", overflow: "nowrap" },
  version: { size: 112, minSize: 88, maxSize: 180, align: "left", overflow: "nowrap" },
  id: { size: 160, minSize: 112, maxSize: 280, align: "left", overflow: "middle", mono: true },
  bytes: { size: 96, minSize: 72, maxSize: 140, align: "right", overflow: "nowrap", numeric: true },
  actions: { size: 112, minSize: 112, maxSize: 192, align: "right", overflow: "fixed" },
};

export interface ColumnLayoutInput {
  id: string;
  header: ReactNode;
  /** Plain label when a composite header cannot be measured as text. */
  headerLabel?: string;
  kind?: ColumnKind;
  /** Legacy CSS width. px/rem values can also participate in pixel layout. */
  width?: string;
  size?: number;
  minSize?: number;
  maxSize?: number;
  grow?: boolean;
  align?: ColumnAlign;
  overflow?: OverflowPolicy;
  wrap?: boolean;
  sortable?: boolean;
  /** Existing facade flags remain effective without forcing a semantic kind. */
  numeric?: boolean;
  code?: boolean;
}

export interface ResolvedColumnLayout {
  kind?: ColumnKind;
  sized: boolean;
  size?: number;
  minSize: number;
  maxSize?: number;
  grow: boolean;
  align: ColumnAlign;
  overflow: OverflowPolicy;
  numeric: boolean;
  mono: boolean;
  cssWidth?: string;
}

/** Width reserved for the entire label, horizontal padding, and sort control. */
export function headerFloor(col: Pick<ColumnLayoutInput, "id" | "header" | "headerLabel" | "sortable" | "kind">): number {
  if (col.kind === "actions") return 0;
  const label = (col.headerLabel ?? headerText(col.header)).trim();
  if (!label) return 0;
  return Math.ceil(label.length * 7) + 32 + (col.sortable === false ? 0 : 24);
}

/**
 * An entirely legacy table keeps native sizing. For a table adopting semantic
 * layout, callers can resolve unspecified columns with defaultKind: "text".
 * Explicit CSS widths take precedence over preferred pixel sizes. Percentages,
 * calc(), and CSS variables stay opaque hints and require native table layout.
 */
export function resolveColumnLayout(col: ColumnLayoutInput, options: { defaultKind?: ColumnKind } = {}): ResolvedColumnLayout {
  const kind = col.kind ?? options.defaultKind;
  const spec = kind ? COLUMN_KINDS[kind] : undefined;
  const sized = !!spec || col.size !== undefined || col.minSize !== undefined || col.maxSize !== undefined;
  const minSize = Math.max(col.minSize ?? spec?.minSize ?? 0, sized ? headerFloor({ ...col, kind }) : 0);
  const rawMax = col.maxSize ?? spec?.maxSize;
  const maxSize = rawMax === undefined ? undefined : Math.max(rawMax, minSize);
  const preferred = col.width === undefined ? col.size ?? spec?.size : undefined;
  const numeric = col.numeric ?? spec?.numeric ?? false;
  return {
    kind,
    sized,
    size: preferred === undefined ? undefined : clamp(preferred, minSize, maxSize ?? Infinity),
    minSize,
    maxSize,
    grow: col.grow ?? (col.width !== undefined ? false : spec?.grow ?? false),
    align: col.align ?? (numeric ? "right" : spec?.align ?? "left"),
    overflow: col.overflow ?? (col.wrap ? "wrap" : spec?.overflow ?? "legacy"),
    numeric,
    mono: col.code ?? spec?.mono ?? false,
    cssWidth: col.width,
  };
}

/** Parse only nonnegative px/rem widths (or unitless pixels). Never guess %. */
export function parsePx(width: string | undefined): number | undefined {
  if (width === undefined) return undefined;
  const match = /^(\d+(?:\.\d+)?)(px|rem)?$/.exec(width.trim());
  if (!match) return undefined;
  const value = Number(match[1]) * (match[2] === "rem" ? 16 : 1);
  return Number.isFinite(value) ? value : undefined;
}

/**
 * Fixed columns keep their preferred sizes; grow columns share the remaining
 * space, honoring every bound. Fixed columns shrink toward their minimums if
 * necessary. Below the sum of minimums, the table must scroll rather than clip.
 * If there are no grow columns, the returned total can be narrower than the
 * container; callers must not spread that surplus over structural columns.
 * Opaque CSS widths must use native layout instead of this pixel computation.
 */
export function computeColumnWidths(layouts: ReadonlyArray<ResolvedColumnLayout>, containerWidth: number): number[] {
  if (!Number.isFinite(containerWidth) || containerWidth < 0) throw new RangeError("Container width must be a nonnegative finite number");
  const widths = layouts.map((layout) => {
    const cssPixels = parsePx(layout.cssWidth);
    if (layout.cssWidth !== undefined && cssPixels === undefined) throw new RangeError("Use native table layout for percentage or other non-pixel CSS widths");
    if (layout.grow || layout.size === undefined && layout.cssWidth === undefined) return undefined;
    return clamp(cssPixels ?? layout.size ?? layout.minSize, layout.minSize, layout.maxSize ?? Infinity);
  });
  const growIndexes = widths.flatMap((width, i) => width === undefined ? [i] : []);
  const growMinimum = growIndexes.reduce((sum, i) => sum + layouts[i].minSize, 0);
  const preferredTotal = widths.reduce<number>((sum, width) => sum + (width ?? 0), 0);
  const deficit = preferredTotal + growMinimum - containerWidth;
  if (deficit > 0) {
    const slack = widths.map((width, i) => width === undefined ? 0 : Math.max(width - layouts[i].minSize, 0));
    const slackTotal = slack.reduce((sum, width) => sum + width, 0);
    if (slackTotal > 0) {
      const proportion = Math.min(deficit, slackTotal) / slackTotal;
      for (let i = 0; i < widths.length; i++) if (widths[i] !== undefined) widths[i] = widths[i]! - slack[i] * proportion;
    }
  }
  let remaining = Math.max(containerWidth - widths.reduce<number>((sum, width) => sum + (width ?? 0), 0), 0);
  let open = [...growIndexes];
  const result = widths.map((width) => width ?? 0);
  for (let guard = 0; guard <= growIndexes.length && open.length; guard++) {
    const share = remaining / open.length;
    // Settle minimums first. Subtracting a minimum can move other columns
    // below their maximum, so settling minima/maxima together wastes space.
    const belowMinimum = open.filter((i) => share < layouts[i].minSize);
    const aboveMaximum = open.filter((i) => layouts[i].maxSize !== undefined && share > layouts[i].maxSize!);
    const bound = belowMinimum.length ? belowMinimum : aboveMaximum;
    if (!bound.length) { for (const i of open) result[i] = share; break; }
    for (const i of bound) {
      result[i] = clamp(share, layouts[i].minSize, layouts[i].maxSize ?? Infinity);
      remaining -= result[i];
    }
    open = open.filter((i) => !bound.includes(i));
    remaining = Math.max(remaining, 0);
  }
  return result;
}

function clamp(value: number, min: number, max: number): number { return Math.min(Math.max(value, min), max); }

function headerText(header: ReactNode): string {
  if (typeof header === "string" || typeof header === "number") return String(header);
  if (Array.isArray(header)) return header.map(headerText).join("");
  if (header && typeof header === "object" && "props" in header) {
    const props = header.props as { children?: ReactNode };
    return headerText(props.children);
  }
  return "";
}
