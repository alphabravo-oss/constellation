import { parsePx, resolveColumnLayout, type ColumnLayoutInput } from "./data-table-layout";

export interface ColumnPinning { start: string[]; end: string[] }
export interface TableArrangement {
  columnOrder?: string[];
  columnWidths?: Record<string, number>;
  columnPinning?: ColumnPinning;
}

/** Shared by saved preferences and rendering. Unknown/duplicate columns never survive. */
export function sanitizeArrangement(raw: unknown, columns: ReadonlyArray<ColumnLayoutInput & { sort?: unknown }>): TableArrangement {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const value = raw as Record<string, unknown>;
  const known = new Set(columns.map(column => column.id));
  const ids = (list: unknown) => Array.isArray(list) ? [...new Set(list.filter((id): id is string => typeof id === "string" && known.has(id)))] : [];
  const result: TableArrangement = {};
  if (Array.isArray(value.columnOrder)) result.columnOrder = ids(value.columnOrder);
  if (value.columnWidths && typeof value.columnWidths === "object" && !Array.isArray(value.columnWidths)) {
    const widths = value.columnWidths as Record<string, unknown>;
    result.columnWidths = Object.fromEntries(columns.flatMap(column => {
      const width = widths[column.id];
      if (typeof width !== "number" || !Number.isFinite(width) || width <= 0) return [];
      const layout = resolveColumnLayout({ ...column, sortable: column.sortable ?? !!column.sort });
      if (!layout.sized || (layout.cssWidth !== undefined && parsePx(layout.cssWidth) === undefined)) return [];
      return [[column.id, Math.round(Math.max(layout.minSize, Math.min(width, layout.maxSize ?? 4096)))]];
    }));
  }
  if (value.columnPinning && typeof value.columnPinning === "object" && !Array.isArray(value.columnPinning)) {
    const pin = value.columnPinning as Record<string, unknown>;
    const start = ids(pin.start);
    result.columnPinning = { start, end: ids(pin.end).filter(id => !start.includes(id)) };
  }
  return result;
}

/** Same start/center/end placement as Astronomer's reusable table. */
export function arrangeColumns<T extends { id: string }>(columns: readonly T[], order: readonly string[], pin: ColumnPinning): T[] {
  const byID = new Map(columns.map(column => [column.id, column]));
  const orderedIDs = [...new Set([...pin.start, ...order.filter(id => !pin.end.includes(id)), ...columns.map(column => column.id).filter(id => !pin.end.includes(id)), ...pin.end])];
  return orderedIDs.flatMap(id => byID.has(id) ? [byID.get(id)!] : []);
}

export function pinnedOffsets(ids: readonly string[], widths: readonly number[], pin: ColumnPinning, container: number, lead = 0) {
  const byID = new Map(ids.map((id, index) => [id, widths[index]]));
  const pinnedWidth = [...pin.start, ...pin.end].reduce((sum, id) => sum + (byID.get(id) ?? 0), 0);
  // Keep a usable center at narrow widths instead of covering the entire scroll area.
  const hasCenter = ids.some(id => !pin.start.includes(id) && !pin.end.includes(id));
  const suspended = pinnedWidth > 0 && (container <= 0 || pinnedWidth + lead + (hasCenter ? 120 : 0) > container);
  const offsets = new Map<string, { side: "left" | "right"; offset: number }>();
  if (!suspended) {
    let left = lead;
    for (const id of pin.start) if (byID.has(id)) { offsets.set(id, { side: "left", offset: left }); left += byID.get(id)!; }
    let right = 0;
    for (const id of [...pin.end].reverse()) if (byID.has(id)) { offsets.set(id, { side: "right", offset: right }); right += byID.get(id)!; }
  }
  return { offsets, suspended };
}
