import { type ReactNode, type Key, useEffect, useMemo, useRef, useState } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowUpDown, Check, ChevronDown, ChevronUp, Download, RotateCcw, Rows2, Rows3, Rows4, SlidersHorizontal } from "lucide-react";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { cn } from "@/lib/cn";
import { downloadCsv, type CsvCell } from "@/lib/csv";
import { computeColumnWidths, parsePx, resolveColumnLayout, type ColumnKind } from "./data-table-layout";
import { TableCellContent } from "./table-cell-content";
import { arrangeColumns, pinnedOffsets, sanitizeArrangement, type TableArrangement } from "./data-table-arrangement";
import { ColumnResizeHandle } from "./data-table-resize";
import { ColumnLayoutMenu } from "./data-table-layout-menu";

export type Density = "compact" | "cozy" | "comfy";
export type TableSort = { id: string; dir: "asc" | "desc" };
interface StoredTablePreferences extends TableArrangement {
  density?: Density;
  hiddenColumnIds?: string[];
  preferenceMigrations?: string[];
}

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Sort comparator. If omitted, column is not sortable. */
  sort?: (a: T, b: T) => number;
  width?: string;
  /** Shared semantic sizing; explicit dimensions override the kind defaults. */
  kind?: ColumnKind;
  size?: number;
  minSize?: number;
  maxSize?: number;
  grow?: boolean;
  align?: "left" | "center" | "right";
  /** Preserve full multiline content instead of the kind's clipping policy. */
  wrap?: boolean;
  className?: string;
  numeric?: boolean;
  /** Use for image refs, node names, versions, IPs, and other machine identifiers. */
  code?: boolean;
  sticky?: boolean;
  hideable?: boolean;
  exportHeader?: string;
  exportValue?: (row: T) => CsvCell;
  exportable?: boolean;
}

export interface DataTableProps<T> {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => Key;
  onRowClick?: (row: T) => void;
  selectable?: boolean;
  selected?: Set<Key>;
  onSelectedChange?: (s: Set<Key>) => void;
  density?: Density;
  /** Initial density for operator-controlled tables; stored choices take precedence. */
  defaultDensity?: Density;
  onDensityChange?: (d: Density) => void;
  /** Render under the table after selection actions; e.g. row hover quick actions. */
  emptyState?: ReactNode;
  className?: string;
  /** Initial sort */
  defaultSort?: TableSort;
  /** Controlled sort, including URL/history changes. null means no active sort. */
  sort?: TableSort | null;
  /**
   * Notified whenever the sort column/direction changes (header click). Pages that
   * sort SERVER-SIDE (data larger than one page) use this to refetch in the new order;
   * `null` means sort was cleared. Client-side-only tables can ignore it.
   */
  onSortChange?: (sort: { id: string; dir: "asc" | "desc" } | null) => void;
  /** Preserve server ordering while allowing sort controls to request a new page. */
  manualSorting?: boolean;
  /** Show density toggle in header right slot. */
  showDensityToggle?: boolean;
  /** Stable key used to persist density/column visibility for this table. */
  preferencesKey?: string;
  /** Show column visibility menu. Defaults to true when preferencesKey is set. */
  showColumnChooser?: boolean;
  /** Controlled hidden columns for pages that persist table state themselves. */
  hiddenColumnIds?: string[];
  /** Initial hidden columns when no stored preferences exist. */
  defaultHiddenColumnIds?: string[];
  preferenceMigration?: { id: string; hideColumnIds: string[] };
  onHiddenColumnIdsChange?: (ids: string[]) => void;
  /** Enables CSV export for the currently rendered rows and visible columns. */
  exportFileName?: string;
  exportLabel?: string;
  /** Recheck current scope/evidence immediately before page CSV dispatch. */
  canExport?: () => boolean;
  /** data-testid on the wrapper (preserves page/table test hooks after migration). */
  testId?: string;
  /** Accessible name; defaults to the column labels for distinct table regions. */
  ariaLabel?: string;
  /** Per-row data-testid — lets migrated tables keep e2e row selectors. */
  rowTestId?: (row: T) => string;
  /** Arbitrary per-row attributes (e.g. data-* hooks) preserved on each <tr>. */
  rowAttrs?: (row: T) => Record<string, string | number | undefined>;
  /** Upper bound on the server response. Counts, filters, and exports cover loaded rows only. */
  sourceLimit?: number;
  sourceCount?: number;
  /** Disable internal paging for bounded, scrollable detail inventories. */
  pagination?: boolean;
}

const TABLE_PAGE_SIZE = 100;

/**
 * DataTable — the single table primitive for the whole app.
 *
 * Powered by @tanstack/react-table (headless): TanStack owns the row model,
 * sorting, and state; this component renders the one canonical <table> markup
 * and exposes a small `Column<T>` facade so pages never hand-roll a table.
 * Sticky header · semantic alignment · resizing/order/pinning · scoped preferences.
 */
export function DataTable<T>(props: DataTableProps<T>) {
  const identity = useTablePreferencesIdentity();
  const scopedKey = identity && props.preferencesKey
    ? JSON.stringify([identity.org_id, identity.user_id, props.preferencesKey])
    : undefined;
  // Remount table state on identity/table changes so old preferences are never
  // briefly displayed or written into the next user's storage namespace.
  return <DataTableView key={JSON.stringify([identity?.org_id, identity?.user_id, props.preferencesKey])}
    {...props} preferencesKey={scopedKey} showColumnChooser={props.showColumnChooser ?? !!props.preferencesKey} />;
}

function DataTableView<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  selectable,
  selected,
  onSelectedChange,
  density: densityProp,
  defaultDensity = "cozy",
  onDensityChange,
  emptyState,
  className,
  defaultSort,
  sort: controlledSort,
  onSortChange,
  manualSorting = false,
  showDensityToggle = true,
  preferencesKey,
  showColumnChooser,
  hiddenColumnIds,
  defaultHiddenColumnIds,
  preferenceMigration,
  onHiddenColumnIdsChange,
  exportFileName,
  exportLabel = "Export CSV",
  canExport,
  testId,
  ariaLabel,
  rowTestId,
  rowAttrs,
  sourceLimit,
  sourceCount,
  pagination = true,
}: DataTableProps<T>) {
  const [requestedPage, setRequestedPage] = useState(0);
  const storedPreferences = useMemo(() => readStoredTablePreferences(preferencesKey, preferenceMigration), [preferencesKey, preferenceMigration]);
  const [requestedArrangement, setArrangement] = useState<TableArrangement>(() => sanitizeArrangement(storedPreferences, columns));
  const arrangement = useMemo(() => sanitizeArrangement(requestedArrangement, columns), [requestedArrangement, columns]);
  const pinning = useMemo(() => arrangement.columnPinning ?? { start: columns.filter(column => column.sticky).map(column => column.id), end: [] }, [arrangement.columnPinning, columns]);
  const orderedColumns = useMemo(() => arrangeColumns(columns, arrangement.columnOrder ?? [], pinning), [columns, arrangement.columnOrder, pinning]);
  const [internalHiddenColumnIds, setInternalHiddenColumnIds] = useState<Set<string>>(() => {
    const stored = storedPreferences.hiddenColumnIds;
    return new Set(stored ?? defaultHiddenColumnIds ?? []);
  });
  const [internalDensity, setInternalDensity] = useState<Density>(() => densityProp ?? storedPreferences.density ?? defaultDensity);
  const [internalSorting, setSorting] = useState<SortingState>(
    defaultSort ? [{ id: defaultSort.id, desc: defaultSort.dir === "desc" }] : [],
  );
  const sorting = useMemo(() => {
    const requested = controlledSort === undefined ? internalSorting : controlledSort ? [{ id: controlledSort.id, desc: controlledSort.dir === "desc" }] : [];
    return requested.filter(sort => columns.some(column => column.id === sort.id && column.sort));
  }, [controlledSort, internalSorting, columns]);
  const [preferencesUnavailable, setPreferencesUnavailable] = useState(false);
  const [preferencesWriteAttempt, setPreferencesWriteAttempt] = useState(0);
  const handleSortingChange: typeof setSorting = (updater) => {
    setRequestedPage(0);
    const next = typeof updater === "function" ? updater(sorting) : updater;
    setSorting(next);
    const first = next[0];
    onSortChange?.(first ? { id: first.id, dir: first.desc ? "desc" : "asc" } : null);
  };

  const hiddenIds = useMemo(
    () => sanitizeHiddenColumns(hiddenColumnIds ?? Array.from(internalHiddenColumnIds), columns, preferenceMigration?.hideColumnIds),
    [hiddenColumnIds, internalHiddenColumnIds, columns, preferenceMigration?.hideColumnIds],
  );
  const visibleColumns = useMemo(
    () => orderedColumns.filter((c) => !hiddenIds.has(c.id) || c.hideable === false),
    [orderedColumns, hiddenIds],
  );
  const columnVisibility = useMemo(() => Object.fromEntries(columns.map(column => [column.id, !hiddenIds.has(column.id) || column.hideable === false])), [columns, hiddenIds]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState(0);
  useEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const measure = () => setContainerWidth(element.clientWidth);
    measure();
    if (typeof window.ResizeObserver === "undefined") return;
    const observer = new window.ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const baseLayouts = useMemo(() => visibleColumns.map((column) => resolveColumnLayout({
    ...column,
    sortable: !!column.sort,
    align: column.align ?? (column.numeric || /(?:^|\s)text-right(?:\s|$)/.test(column.className ?? "") ? "right" : /(?:^|\s)text-center(?:\s|$)/.test(column.className ?? "") ? "center" : undefined),
  })), [visibleColumns]);
  const layouts = useMemo(() => baseLayouts.map((layout, index) => {
    const width = arrangement.columnWidths?.[visibleColumns[index].id];
    return width === undefined ? layout : { ...layout, size: width, minSize: width, maxSize: width, grow: false, cssWidth: undefined };
  }), [baseLayouts, arrangement.columnWidths, visibleColumns]);
  // Legacy CSS widths keep native layout. Semantic tables share one measured
  // colgroup, so headers and cells cannot independently choose their widths.
  const semanticLayout = layouts.length > 0 && layouts.every((layout) => layout.sized && (!layout.cssWidth || parsePx(layout.cssWidth) !== undefined));
  const selectionWidth = selectable ? 40 : 0;
  const columnWidths = semanticLayout ? computeColumnWidths(layouts, Math.max(0, containerWidth - selectionWidth)) : [];
  const tableWidth = columnWidths.reduce((sum, width) => sum + width, selectionWidth);
  const pinned = semanticLayout ? pinnedOffsets(visibleColumns.map(column => column.id), columnWidths, pinning, containerWidth, selectionWidth) : { offsets: new Map<string, { side: "left" | "right"; offset: number }>(), suspended: false };
  const pinnedStyle = (id: string) => { const placement = pinned.offsets.get(id); return placement ? { position: "sticky" as const, [placement.side]: placement.offset } : {}; };

  useEffect(() => {
    setArrangement(previous => {
      const next = sanitizeArrangement(previous, columns);
      return JSON.stringify(previous) === JSON.stringify(next) ? previous : next;
    });
    setInternalHiddenColumnIds((prev) => {
      const next = sanitizeHiddenColumns(Array.from(prev), columns, preferenceMigration?.hideColumnIds);
      return setsEqual(prev, next) ? prev : next;
    });
  }, [columns, preferenceMigration?.hideColumnIds]);

  useEffect(() => {
    if (!preferencesKey) return;
    const prefs = readStoredTablePreferences(preferencesKey);
    setPreferencesUnavailable(!writeStoredTablePreferences(preferencesKey, {
      ...prefs,
      ...((storedPreferences.preferenceMigrations?.length || prefs.preferenceMigrations?.length) ? { preferenceMigrations: Array.from(new Set([...(storedPreferences.preferenceMigrations ?? []), ...(prefs.preferenceMigrations ?? [])])) } : {}),
      columnWidths: arrangement.columnWidths,
      columnOrder: arrangement.columnOrder,
      columnPinning: arrangement.columnPinning,
      ...(hiddenColumnIds === undefined ? { hiddenColumnIds: Array.from(hiddenIds) } : {}),
      ...(densityProp === undefined ? { density: internalDensity } : {}),
    }));
  }, [preferencesKey, hiddenColumnIds, hiddenIds, densityProp, internalDensity, preferencesWriteAttempt, arrangement, storedPreferences]);

  useEffect(() => {
    if (densityProp) {
      setInternalDensity(densityProp);
    }
  }, [densityProp]);

  const density = densityProp ?? internalDensity;
  const rowH = density === "compact" ? "h-6" : density === "comfy" ? "h-10" : "h-8";
  const cellPad = density === "compact" ? "px-2 py-0.5" : density === "comfy" ? "px-3 py-2" : "px-2.5 py-1.5";

  // Look up the Column facade by id when rendering headers/cells (avoids
  // threading the facade through TanStack column meta typing).
  const colById = useMemo(() => new Map(visibleColumns.map((c) => [c.id, c])), [visibleColumns]);

  const columnDefs = useMemo<ColumnDef<T>[]>(
    () =>
      columns.map((c) => ({
        id: c.id,
        accessorFn: (row: T) => row,
        enableSorting: !!c.sort,
        sortingFn: c.sort ? (a, b) => c.sort!(a.original, b.original) : "auto",
        sortDescFirst: true,
        header: c.id,
        cell: () => null,
      })),
    [columns],
  );

  const table = useReactTable({
    data: rows,
    columns: columnDefs,
    state: { sorting, columnVisibility, columnOrder: orderedColumns.map(column => column.id) },
    onSortingChange: handleSortingChange,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    manualSorting,
    getRowId: (row) => String(rowKey(row)),
    enableSortingRemoval: true,
    enableMultiSort: false,
  });

  const modelRows = table.getRowModel().rows;
  const pageCount = pagination ? Math.max(1, Math.ceil(modelRows.length / TABLE_PAGE_SIZE)) : 1;
  const page = Math.min(requestedPage, pageCount - 1);
  const visibleRows = pagination ? modelRows.slice(page * TABLE_PAGE_SIZE, (page + 1) * TABLE_PAGE_SIZE) : modelRows;
  const headers = table.getHeaderGroups()[0]?.headers ?? [];

  const allKeys = visibleRows.map((row) => rowKey(row.original));
  const allSelected = selectable && selected ? allKeys.length > 0 && allKeys.every((k) => selected.has(k)) : false;
  const partiallySelected = !!selected && !allSelected && allKeys.some(key => selected.has(key));

  function toggleAll() {
    if (!onSelectedChange) return;
    const next = new Set(selected);
    for (const key of allKeys) {
      if (allSelected) next.delete(key); else next.add(key);
    }
    onSelectedChange(next);
  }

  function toggleOne(k: Key) {
    if (!onSelectedChange) return;
    const next = new Set(selected);
    if (next.has(k)) next.delete(k); else next.add(k);
    onSelectedChange(next);
  }

  function setColumnVisible(id: string, visible: boolean) {
    const target = columns.find((c) => c.id === id);
    if (!target || target.hideable === false) return;
    const next = new Set(hiddenIds);
    if (visible) {
      next.delete(id);
    } else {
      if (visibleColumns.length <= 1) return;
      next.add(id);
    }
    setInternalHiddenColumnIds(next);
    onHiddenColumnIdsChange?.(Array.from(next));
  }

  function resetColumns() {
    const next = sanitizeHiddenColumns(defaultHiddenColumnIds ?? [], columns, preferenceMigration?.hideColumnIds);
    setInternalHiddenColumnIds(next);
    onHiddenColumnIdsChange?.(Array.from(next));
  }

  function setDensity(next: Density) {
    if (!densityProp) {
      setInternalDensity(next);
    }
    onDensityChange?.(next);
  }

  function resetPreferences() {
    setArrangement({});
    resetColumns();
    setDensity(defaultDensity);
  }

  function resizeColumn(id: string, width?: number) {
    setArrangement(current => {
      const columnWidths = { ...current.columnWidths };
      if (width === undefined) delete columnWidths[id]; else columnWidths[id] = width;
      return { ...current, columnWidths };
    });
  }

  function pinColumn(id: string, side: "start" | "end" | null) {
    const next = { start: pinning.start.filter(key => key !== id), end: pinning.end.filter(key => key !== id) };
    if (side) next[side].push(id);
    setArrangement(current => ({ ...current, columnPinning: next }));
  }

  function moveColumn(id: string, direction: -1 | 1) {
    const next = orderedColumns.map(column => column.id);
    const slots = next.flatMap((key, index) => !pinning.start.includes(key) && !pinning.end.includes(key) ? [index] : []);
    const slot = slots.findIndex(index => next[index] === id), target = slot + direction;
    if (slot < 0 || target < 0 || target >= slots.length) return;
    [next[slots[slot]], next[slots[target]]] = [next[slots[target]], next[slots[slot]]];
    setArrangement(current => ({ ...current, columnOrder: next }));
  }

  function exportVisibleRows() {
    if (!exportFileName) return;
    const exportColumns = visibleColumns.filter((column) => column.exportable !== false);
    const headers = exportColumns.map((column) => column.exportHeader ?? headerText(column.header, column.id));
    const csvRows = modelRows.map((row) => exportColumns.map((column) => exportCellValue(column, row.original)));
    if (canExport && !canExport()) return;
    downloadCsv(exportFileName, headers, csvRows);
  }

  const shouldShowColumnChooser = (showColumnChooser ?? !!preferencesKey) && columns.length > 1;
  const shouldShowExport = Boolean(exportFileName);
  const canChangeDensity = densityProp === undefined || !!onDensityChange;
  const shouldShowToolbar = (showDensityToggle && canChangeDensity) || shouldShowColumnChooser || shouldShowExport || semanticLayout;
  const tableLabel = ariaLabel ?? `Table: ${columns.slice(0, 3).map(column => headerText(column.header, column.id)).join(", ")}`;

  return (
    <div className={cn("app-data-table min-w-0 max-w-full rounded-md border border-border bg-card overflow-hidden", className)} data-testid={testId}>
      {shouldShowToolbar && (
        <div className="flex flex-wrap items-center justify-end gap-2 border-b border-border px-2 py-1">
          {shouldShowExport && (
            <button
              type="button"
              onClick={exportVisibleRows}
              disabled={canExport ? !canExport() : false}
              aria-label={exportLabel}
              title={exportLabel}
              data-testid={testId ? `${testId}-export-csv` : undefined}
              className="inline-flex h-7 items-center gap-1.5 rounded border border-border bg-card px-2 text-[11px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Download className="h-3.5 w-3.5" />
              <span>{exportLabel}</span>
            </button>
          )}
          {shouldShowColumnChooser && (
            <ColumnChooser
              columns={columns}
              hiddenIds={hiddenIds}
              visibleColumns={visibleColumns.length}
              onVisibleChange={setColumnVisible}
              onReset={resetColumns}
              onResetPreferences={resetPreferences}
              testId={testId}
            />
          )}
          {semanticLayout && <ColumnLayoutMenu columns={orderedColumns.map(column => ({ id: column.id, label: headerText(column.header, column.id) }))}
            pinning={pinning} onMove={moveColumn} onPin={pinColumn} onResetWidth={id => resizeColumn(id)} onReset={() => setArrangement({})} />}
          {showDensityToggle && canChangeDensity && (
            <div className="flex items-center gap-1">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground mr-2">Density</span>
              <DensityBtn current={density} value="compact" onClick={() => setDensity("compact")} icon={Rows4} label="compact" />
              <DensityBtn current={density} value="cozy" onClick={() => setDensity("cozy")} icon={Rows3} label="cozy" />
              <DensityBtn current={density} value="comfy" onClick={() => setDensity("comfy")} icon={Rows2} label="comfy" />
            </div>
          )}
        </div>
      )}
      {pinned.suspended && <p className="border-b border-border px-3 py-2 text-xs text-muted-foreground">Column pinning pauses at this width so every column remains reachable. Your saved pins are retained.</p>}
      {preferencesUnavailable && <div role="status" className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2 text-xs text-muted-foreground"><span>Table preferences could not be saved. Changes apply to this tab.</span><button type="button" className="text-primary underline underline-offset-2" onClick={() => setPreferencesWriteAttempt(attempt => attempt + 1)}>Retry saving preferences</button></div>}
      {sorting[0] && hiddenIds.has(sorting[0].id) && <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2 text-xs">
        <span>Sorted by {headerText(columns.find(column => column.id === sorting[0].id)?.header, sorting[0].id)} ({sorting[0].desc ? "descending" : "ascending"}) · hidden column</span>
        {(hiddenColumnIds === undefined || onHiddenColumnIdsChange) && <button type="button" className="text-primary underline underline-offset-2" onClick={() => setColumnVisible(sorting[0].id, true)}>Show sort column</button>}
        {!manualSorting && <button type="button" className="text-primary underline underline-offset-2" onClick={() => handleSortingChange([])}>Clear sort</button>}
      </div>}
      <div ref={scrollRef} className="app-table-scroll overflow-auto focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary" tabIndex={0} role="region" aria-label={`Scrollable ${tableLabel}`} onKeyDown={event => {
        if (event.target !== event.currentTarget || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
        const element = event.currentTarget;
        if (element.scrollWidth <= element.clientWidth || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        element.scrollLeft = event.key === "Home" ? 0 : event.key === "End" ? element.scrollWidth : element.scrollLeft + (event.key === "ArrowRight" ? 80 : -80);
      }}>
        <table className="w-full text-sm" aria-label={tableLabel} data-layout={semanticLayout ? "semantic" : "auto"}
          style={semanticLayout ? { tableLayout: "fixed", width: tableWidth, minWidth: tableWidth } : undefined}>
          {semanticLayout && <colgroup>
            {selectable && <col style={{ width: selectionWidth }} />}
            {visibleColumns.map((column, index) => <col key={column.id} style={{ width: columnWidths[index] }} />)}
          </colgroup>}
          <thead className="sticky top-0 z-10">
            <tr className="border-b border-border text-xs">
              {selectable && (
                <th scope="col" className={cn("w-8 px-2 py-2 text-left", pinned.offsets.size > 0 && "app-table-pinned")} style={pinned.offsets.size > 0 ? { position: "sticky", left: 0 } : undefined}>
                  <input
                    type="checkbox"
                    checked={allSelected}
                    ref={input => { if (input) input.indeterminate = partiallySelected; }}
                    aria-checked={partiallySelected ? "mixed" : allSelected}
                    onChange={toggleAll}
                    aria-label="Select all"
                    className="accent-[color:var(--color-primary)]"
                  />
                </th>
              )}
              {headers.map((h, index) => {
                const c = colById.get(h.column.id);
                const layout = layouts[index];
                const dir = h.column.getIsSorted();
                return (
                  <th
                    key={h.id}
                    scope="col"
                    data-column-id={h.column.id}
                    data-align={layout.align}
                    aria-sort={dir ? (dir === "asc" ? "ascending" : "descending") : undefined}
                    className={cn(
                      "relative h-10 py-2 font-semibold select-none",
                      cellPad,
                      pinned.offsets.has(h.column.id) && "app-table-pinned",
                      c?.className,
                    )}
                    style={{ textAlign: layout.align, ...pinnedStyle(h.column.id), ...(!semanticLayout && c?.width ? { width: c.width } : {}) }}
                  >
                    {semanticLayout && <ColumnResizeHandle label={headerText(c?.header, h.column.id)} width={columnWidths[index]} min={baseLayouts[index].minSize} max={baseLayouts[index].maxSize ?? 4096}
                      onResize={width => resizeColumn(h.column.id, width)} onReset={() => resizeColumn(h.column.id)} />}
                    {c?.sort ? (
                      <button
                        type="button"
                        onClick={h.column.getToggleSortingHandler()}
                        className={cn(
                          "app-table-header-button hover:text-foreground transition-colors",
                        )}
                      >
                        <span>{c.header}</span>
                        {dir === "desc" ? (
                          <ChevronDown className="h-3 w-3 shrink-0" />
                        ) : dir === "asc" ? (
                          <ChevronUp className="h-3 w-3 shrink-0" />
                        ) : (
                          <ArrowUpDown className="h-3 w-3 shrink-0 opacity-40" />
                        )}
                      </button>
                    ) : (
                      c?.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {visibleRows.map((r) => {
              const row = r.original;
              const k = rowKey(row);
              const isSel = selected?.has(k);
              return (
                <tr
                  key={r.id}
                  data-testid={rowTestId?.(row)}
                  {...(rowAttrs?.(row) ?? {})}
                  data-selected={isSel || undefined}
                  tabIndex={onRowClick ? 0 : undefined}
                  className={cn(
                    "border-b border-border last:border-b-0 transition-colors",
                    onRowClick && "app-data-table-row-clickable cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[color:var(--color-primary)]",
                    !isSel && "hover:bg-[var(--table-row-hover)]",
                    rowH,
                  )}
                  onClick={onRowClick ? (e) => {
                    // Ignore clicks on inputs/buttons/anchors inside the row.
                    const tgt = e.target as HTMLElement;
                    if (tgt.closest("input,button,a,select,textarea,summary,label,[role='button'],[contenteditable='true']")) return;
                    onRowClick(row);
                  } : undefined}
                  onKeyDown={onRowClick ? (event) => {
                    if (event.target !== event.currentTarget || (event.key !== "Enter" && event.key !== " ")) return;
                    event.preventDefault();
                    onRowClick(row);
                  } : undefined}
                >
                  {selectable && (
                    <td className={cn("px-2", pinned.offsets.size > 0 && "app-table-pinned")} style={pinned.offsets.size > 0 ? { position: "sticky", left: 0 } : undefined}>
                      <input
                        type="checkbox"
                        checked={!!isSel}
                        onChange={() => toggleOne(k)}
                        onClick={(e) => e.stopPropagation()}
                        aria-label="Select row"
                        className="accent-[color:var(--color-primary)]"
                      />
                    </td>
                  )}
                      {visibleColumns.map((c, index) => (
                    <td
                      key={c.id}
                      data-column-id={c.id}
                      data-align={layouts[index].align}
                      data-kind={c.kind}
                      style={{ textAlign: layouts[index].align, ...pinnedStyle(c.id) }}
                      className={cn(
                        cellPad,
                        (c.code || layouts[index].mono) && "app-table-code",
                        (c.numeric || layouts[index].numeric) && "app-table-numeric",
                        pinned.offsets.has(c.id) && "app-table-pinned",
                        c.className,
                      )}
                    >
                      <TableCellContent overflow={semanticLayout ? layouts[index].overflow : "legacy"} width={columnWidths[index]}>{c.cell(row)}</TableCellContent>
                    </td>
                  ))}
                </tr>
              );
            })}
            {visibleRows.length === 0 && (
              <tr>
                <td colSpan={visibleColumns.length + (selectable ? 1 : 0)}>
                  {emptyState ?? (
                    <div className="px-6 py-10 text-center text-xs text-muted-foreground">No rows.</div>
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {(pageCount > 1 || sourceLimit !== undefined) && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2 text-xs text-muted-foreground" data-testid={testId ? `${testId}-page-scope` : undefined}>
          <span>
            Showing {visibleRows.length ? page * TABLE_PAGE_SIZE + 1 : 0}–{page * TABLE_PAGE_SIZE + visibleRows.length} of {modelRows.length.toLocaleString()} matching loaded rows.
            {sourceLimit !== undefined && <> Server fetch limit: {sourceLimit.toLocaleString()} rows ({(sourceCount ?? rows.length).toLocaleString()} loaded); filters and totals use loaded rows only.</>}
            {exportFileName && " Table CSV exports all matching loaded rows."}
          </span>
          {pageCount > 1 && (
            <div className="flex items-center gap-2">
              <button type="button" disabled={page === 0} onClick={() => setRequestedPage(page - 1)} className="rounded border border-border px-2 py-1 hover:bg-accent disabled:opacity-40">Previous</button>
              <span>Page {page + 1} of {pageCount}</span>
              <button type="button" disabled={page + 1 >= pageCount} onClick={() => setRequestedPage(page + 1)} className="rounded border border-border px-2 py-1 hover:bg-accent disabled:opacity-40">Next</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ColumnChooser<T>({
  columns,
  hiddenIds,
  visibleColumns,
  onVisibleChange,
  onReset,
  onResetPreferences,
  testId,
}: {
  columns: Column<T>[];
  hiddenIds: Set<string>;
  visibleColumns: number;
  onVisibleChange: (id: string, visible: boolean) => void;
  onReset: () => void;
  onResetPreferences: () => void;
  testId?: string;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          aria-label="Columns"
          title="Columns"
          data-testid={testId ? `${testId}-columns-trigger` : undefined}
          className="inline-flex h-7 w-7 items-center justify-center rounded border border-border bg-card text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        >
          <SlidersHorizontal className="h-3.5 w-3.5" />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          data-testid={testId ? `${testId}-columns-menu` : undefined}
          className="z-50 min-w-52 rounded-md border border-border bg-card p-1 shadow-xl"
        >
          <div className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">Columns</div>
          {columns.map((column) => {
            const checked = !hiddenIds.has(column.id) || column.hideable === false;
            const disabled = column.hideable === false || (checked && visibleColumns <= 1);
            return (
              <DropdownMenu.CheckboxItem
                key={column.id}
                checked={checked}
                disabled={disabled}
                onCheckedChange={(next) => onVisibleChange(column.id, next === true)}
                onSelect={(event) => event.preventDefault()}
                className={cn(
                  "relative flex cursor-pointer select-none items-center gap-2 rounded px-2 py-1.5 pl-7 text-xs outline-none transition-colors focus:bg-accent",
                  disabled && "cursor-not-allowed opacity-50",
                )}
              >
                <DropdownMenu.ItemIndicator className="absolute left-2 inline-flex items-center justify-center">
                  <Check className="h-3.5 w-3.5" />
                </DropdownMenu.ItemIndicator>
                <span className="truncate">{column.header}</span>
              </DropdownMenu.CheckboxItem>
            );
          })}
          <DropdownMenu.Separator className="my-1 h-px bg-border" />
          <DropdownMenu.Item
            onSelect={onReset}
            className="flex cursor-pointer select-none items-center gap-2 rounded px-2 py-1.5 text-xs outline-none transition-colors focus:bg-accent"
          >
            <RotateCcw className="h-3.5 w-3.5 text-muted-foreground" />
            Reset columns
          </DropdownMenu.Item>
          <DropdownMenu.Item onSelect={onResetPreferences} className="flex cursor-pointer select-none items-center gap-2 rounded px-2 py-1.5 text-xs outline-none transition-colors focus:bg-accent">
            <RotateCcw className="h-3.5 w-3.5 text-muted-foreground" />
            Reset table preferences
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function DensityBtn({ current, value, onClick, icon: Icon, label }: { current: Density; value: Density; onClick: () => void; icon: React.ComponentType<{ className?: string }>; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`${label} density`}
      aria-pressed={current === value}
      title={`${label} density`}
      className={cn(
        "rounded p-1 hover:bg-accent transition-colors",
        current === value ? "text-foreground bg-accent" : "text-muted-foreground",
      )}
    >
      <Icon className="h-3.5 w-3.5" />
    </button>
  );
}

function headerText(header: ReactNode, fallback: string) {
  if (typeof header === "string" || typeof header === "number") {
    return String(header);
  }
  return fallback;
}

function exportCellValue<T>(column: Column<T>, row: T): CsvCell {
  if (column.exportValue) {
    return column.exportValue(row);
  }
  const value = column.cell(row);
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value == null) {
    return value;
  }
  return "";
}

function readStoredTablePreferences(key?: string, migration?: { id: string; hideColumnIds: string[] }): StoredTablePreferences {
  if (!key) return {};
  try {
    if (typeof localStorage === "undefined") return {};
    const parsed = JSON.parse(localStorage.getItem(tablePreferencesStorageKey(key)) ?? "{}");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const hiddenColumnIds = Array.isArray(parsed.hiddenColumnIds)
      ? parsed.hiddenColumnIds.filter((id: unknown): id is string => typeof id === "string")
      : undefined;
    const density = parsed.density === "compact" || parsed.density === "cozy" || parsed.density === "comfy"
      ? parsed.density
      : undefined;
    const markers = Array.isArray(parsed.preferenceMigrations) ? parsed.preferenceMigrations.filter((id: unknown): id is string => typeof id === "string") : [];
    if (migration && !markers.includes(migration.id)) {
      return { ...parsed, density, ...(hiddenColumnIds ? { hiddenColumnIds: Array.from(new Set([...hiddenColumnIds, ...migration.hideColumnIds])) } : {}), preferenceMigrations: [...markers, migration.id] };
    }
    return { ...parsed, density, hiddenColumnIds, ...(markers.length ? { preferenceMigrations: markers } : {}) };
  } catch {
    return {};
  }
}

function writeStoredTablePreferences(key: string, preferences: StoredTablePreferences) {
  try {
    if (typeof localStorage === "undefined") return false;
    const storageKey = tablePreferencesStorageKey(key);
    const serialized = JSON.stringify(preferences);
    if (localStorage.getItem(storageKey) !== serialized) localStorage.setItem(storageKey, serialized);
    return true;
  } catch {
    return false;
  }
}

function sanitizeHiddenColumns<T>(ids: string[], columns: Column<T>[], preserve: string[] = []): Set<string> {
  const hideable = new Set(columns.filter(column => column.hideable !== false || preserve.includes(column.id)).map(column => column.id));
  const hidden = new Set(ids.filter(id => hideable.has(id)));
  if (columns.length && columns.every(column => column.hideable !== false && hidden.has(column.id))) hidden.delete(columns[0].id);
  return hidden;
}

function tablePreferencesStorageKey(key: string) {
  return `constellation.table.${key}.v1`;
}

function setsEqual(a: Set<string>, b: Set<string>) {
  if (a.size !== b.size) return false;
  for (const value of a) {
    if (!b.has(value)) return false;
  }
  return true;
}
