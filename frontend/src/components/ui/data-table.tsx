import { type ReactNode, type Key, useEffect, useMemo, useState } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowUpDown, Check, ChevronDown, ChevronUp, Download, RotateCcw, Rows2, Rows3, Rows4, SlidersHorizontal } from "lucide-react";
import { cn } from "@/lib/cn";
import { downloadCsv, type CsvCell } from "@/lib/csv";

export type Density = "compact" | "cozy" | "comfy";
interface StoredTablePreferences {
  density?: Density;
  hiddenColumnIds?: string[];
}

export interface Column<T> {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Sort comparator. If omitted, column is not sortable. */
  sort?: (a: T, b: T) => number;
  width?: string;
  className?: string;
  numeric?: boolean;
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
  onDensityChange?: (d: Density) => void;
  /** Render under the table after selection actions; e.g. row hover quick actions. */
  emptyState?: ReactNode;
  className?: string;
  /** Initial sort */
  defaultSort?: { id: string; dir: "asc" | "desc" };
  /**
   * Notified whenever the sort column/direction changes (header click). Pages that
   * sort SERVER-SIDE (data larger than one page) use this to refetch in the new order;
   * `null` means sort was cleared. Client-side-only tables can ignore it.
   */
  onSortChange?: (sort: { id: string; dir: "asc" | "desc" } | null) => void;
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
  onHiddenColumnIdsChange?: (ids: string[]) => void;
  /** Enables CSV export for the currently rendered rows and visible columns. */
  exportFileName?: string;
  exportLabel?: string;
  /** data-testid on the wrapper (preserves page/table test hooks after migration). */
  testId?: string;
  /** Per-row data-testid — lets migrated tables keep e2e row selectors. */
  rowTestId?: (row: T) => string;
  /** Arbitrary per-row attributes (e.g. data-* hooks) preserved on each <tr>. */
  rowAttrs?: (row: T) => Record<string, string | number | undefined>;
}

/**
 * DataTable — the single table primitive for the whole app.
 *
 * Powered by @tanstack/react-table (headless): TanStack owns the row model,
 * sorting, and state; this component renders the one canonical <table> markup
 * and exposes a small `Column<T>` facade so pages never hand-roll a table.
 * Sticky header · right-align numeric · accent slide-in on row hover · density.
 */
export function DataTable<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  selectable,
  selected,
  onSelectedChange,
  density: densityProp,
  onDensityChange,
  emptyState,
  className,
  defaultSort,
  onSortChange,
  showDensityToggle = true,
  preferencesKey,
  showColumnChooser,
  hiddenColumnIds,
  defaultHiddenColumnIds,
  onHiddenColumnIdsChange,
  exportFileName,
  exportLabel = "Export CSV",
  testId,
  rowTestId,
  rowAttrs,
}: DataTableProps<T>) {
  const storedPreferences = useMemo(() => readStoredTablePreferences(preferencesKey), [preferencesKey]);
  const [internalHiddenColumnIds, setInternalHiddenColumnIds] = useState<Set<string>>(() => {
    const stored = storedPreferences.hiddenColumnIds;
    return new Set(stored ?? defaultHiddenColumnIds ?? []);
  });
  const [internalDensity, setInternalDensity] = useState<Density>(() => densityProp ?? storedPreferences.density ?? "cozy");
  const [sorting, setSorting] = useState<SortingState>(
    defaultSort ? [{ id: defaultSort.id, desc: defaultSort.dir === "desc" }] : [],
  );
  const handleSortingChange: typeof setSorting = (updater) => {
    setSorting((prev) => {
      const next = typeof updater === "function" ? updater(prev) : updater;
      if (onSortChange) {
        const s = next[0];
        onSortChange(s ? { id: s.id, dir: s.desc ? "desc" : "asc" } : null);
      }
      return next;
    });
  };

  const hiddenIds = useMemo(
    () => new Set(hiddenColumnIds ?? Array.from(internalHiddenColumnIds)),
    [hiddenColumnIds, internalHiddenColumnIds],
  );
  const visibleColumns = useMemo(
    () => columns.filter((c) => !hiddenIds.has(c.id) || c.hideable === false),
    [columns, hiddenIds],
  );
  const visibleColumnIds = useMemo(() => new Set(visibleColumns.map((c) => c.id)), [visibleColumns]);

  useEffect(() => {
    const valid = new Set(columns.map((c) => c.id));
    setInternalHiddenColumnIds((prev) => {
      const next = new Set(Array.from(prev).filter((id) => valid.has(id)));
      return setsEqual(prev, next) ? prev : next;
    });
  }, [columns]);

  useEffect(() => {
    if (!preferencesKey || hiddenColumnIds) return;
    const prefs = readStoredTablePreferences(preferencesKey);
    writeStoredTablePreferences(preferencesKey, {
      ...prefs,
      hiddenColumnIds: Array.from(internalHiddenColumnIds),
    });
  }, [preferencesKey, hiddenColumnIds, internalHiddenColumnIds]);

  useEffect(() => {
    if (densityProp) {
      setInternalDensity(densityProp);
    }
  }, [densityProp]);

  useEffect(() => {
    if (!preferencesKey || densityProp) return;
    const prefs = readStoredTablePreferences(preferencesKey);
    writeStoredTablePreferences(preferencesKey, {
      ...prefs,
      density: internalDensity,
    });
  }, [preferencesKey, densityProp, internalDensity]);

  useEffect(() => {
    setSorting((prev) => prev.filter((s) => visibleColumnIds.has(s.id)));
  }, [visibleColumnIds]);

  const density = densityProp ?? internalDensity;
  const rowH = density === "compact" ? "h-6" : density === "comfy" ? "h-10" : "h-8";
  const cellPad = density === "compact" ? "px-2 py-0.5" : density === "comfy" ? "px-3 py-2" : "px-2.5 py-1.5";

  // Look up the Column facade by id when rendering headers/cells (avoids
  // threading the facade through TanStack column meta typing).
  const colById = useMemo(() => new Map(visibleColumns.map((c) => [c.id, c])), [visibleColumns]);

  const columnDefs = useMemo<ColumnDef<T>[]>(
    () =>
      visibleColumns.map((c) => ({
        id: c.id,
        accessorFn: (row: T) => row,
        enableSorting: !!c.sort,
        sortingFn: c.sort ? (a, b) => c.sort!(a.original, b.original) : "auto",
        sortDescFirst: true,
        header: c.id,
        cell: () => null,
      })),
    [visibleColumns],
  );

  const table = useReactTable({
    data: rows,
    columns: columnDefs,
    state: { sorting },
    onSortingChange: handleSortingChange,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (row) => String(rowKey(row)),
    enableSortingRemoval: true,
    enableMultiSort: false,
  });

  const modelRows = table.getRowModel().rows;
  const headers = table.getHeaderGroups()[0]?.headers ?? [];

  const allKeys = useMemo(() => rows.map(rowKey), [rows, rowKey]);
  const allSelected = selectable && selected ? allKeys.length > 0 && allKeys.every((k) => selected.has(k)) : false;

  function toggleAll() {
    if (!onSelectedChange) return;
    onSelectedChange(allSelected ? new Set() : new Set(allKeys));
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
      const visibleHideable = columns.filter((c) => c.hideable !== false && !hiddenIds.has(c.id));
      if (visibleHideable.length <= 1) return;
      next.add(id);
    }
    setInternalHiddenColumnIds(next);
    onHiddenColumnIdsChange?.(Array.from(next));
  }

  function resetColumns() {
    const next = new Set(defaultHiddenColumnIds ?? []);
    setInternalHiddenColumnIds(next);
    onHiddenColumnIdsChange?.(Array.from(next));
  }

  function setDensity(next: Density) {
    if (!densityProp) {
      setInternalDensity(next);
    }
    onDensityChange?.(next);
  }

  function exportVisibleRows() {
    if (!exportFileName) return;
    const exportColumns = visibleColumns.filter((column) => column.exportable !== false);
    const headers = exportColumns.map((column) => column.exportHeader ?? headerText(column.header, column.id));
    const csvRows = modelRows.map((row) => exportColumns.map((column) => exportCellValue(column, row.original)));
    downloadCsv(exportFileName, headers, csvRows);
  }

  const shouldShowColumnChooser = (showColumnChooser ?? !!preferencesKey) && columns.length > 1;
  const shouldShowExport = Boolean(exportFileName);
  const shouldShowToolbar = showDensityToggle || shouldShowColumnChooser || shouldShowExport;

  return (
    <div className={cn("rounded-md border border-border bg-card overflow-hidden", className)} data-testid={testId}>
      {shouldShowToolbar && (
        <div className="flex items-center justify-end gap-2 border-b border-border px-2 py-1">
          {shouldShowExport && (
            <button
              type="button"
              onClick={exportVisibleRows}
              aria-label={exportLabel}
              title={exportLabel}
              data-testid={testId ? `${testId}-export-csv` : undefined}
              className="inline-flex h-7 items-center gap-1.5 rounded border border-border bg-card px-2 text-[11px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
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
              testId={testId}
            />
          )}
          {showDensityToggle && (
            <div className="flex items-center gap-1">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground mr-2">Density</span>
              <DensityBtn current={density} value="compact" onClick={() => setDensity("compact")} icon={Rows4} label="compact" />
              <DensityBtn current={density} value="cozy" onClick={() => setDensity("cozy")} icon={Rows3} label="cozy" />
              <DensityBtn current={density} value="comfy" onClick={() => setDensity("comfy")} icon={Rows2} label="comfy" />
            </div>
          )}
        </div>
      )}
      <div className="overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
            <tr className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
              {selectable && (
                <th className="w-8 px-2 py-2 text-left">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleAll}
                    aria-label="Select all"
                    className="accent-[color:var(--color-primary)]"
                  />
                </th>
              )}
              {headers.map((h) => {
                const c = colById.get(h.column.id);
                const dir = h.column.getIsSorted();
                return (
                  <th
                    key={h.id}
                    scope="col"
                    className={cn(
                      "py-2 font-medium select-none",
                      cellPad,
                      c?.numeric && "text-right",
                      c?.sticky && "sticky left-0 bg-card",
                      c?.className,
                    )}
                    style={c?.width ? { width: c.width } : undefined}
                  >
                    {c?.sort ? (
                      <button
                        type="button"
                        onClick={h.column.getToggleSortingHandler()}
                        className={cn(
                          "inline-flex items-center gap-1 hover:text-foreground transition-colors",
                          c.numeric && "ml-auto",
                        )}
                      >
                        {c.header}
                        {dir === "desc" ? (
                          <ChevronDown className="h-3 w-3" />
                        ) : dir === "asc" ? (
                          <ChevronUp className="h-3 w-3" />
                        ) : (
                          <ArrowUpDown className="h-3 w-3 opacity-40" />
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
            {modelRows.map((r) => {
              const row = r.original;
              const k = rowKey(row);
              const isSel = selected?.has(k);
              return (
                <tr
                  key={r.id}
                  data-testid={rowTestId?.(row)}
                  {...(rowAttrs?.(row) ?? {})}
                  data-selected={isSel || undefined}
                  className={cn(
                    "accent-slide border-b border-border last:border-b-0 transition-colors",
                    onRowClick && "cursor-pointer",
                    isSel ? "bg-[color-mix(in_oklab,var(--color-primary)_8%,transparent)]" : "hover:bg-muted/40",
                    rowH,
                  )}
                  onClick={onRowClick ? (e) => {
                    // Ignore clicks on inputs/buttons/anchors inside the row.
                    const tgt = e.target as HTMLElement;
                    if (tgt.closest("input,button,a,[role='button']")) return;
                    onRowClick(row);
                  } : undefined}
                >
                  {selectable && (
                    <td className="px-2">
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
                  {visibleColumns.map((c) => (
                    <td
                      key={c.id}
                      className={cn(
                        cellPad,
                        c.numeric && "text-right text-mono",
                        c.sticky && "sticky left-0 bg-card",
                        c.className,
                      )}
                    >
                      {c.cell(row)}
                    </td>
                  ))}
                </tr>
              );
            })}
            {modelRows.length === 0 && (
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
    </div>
  );
}

function ColumnChooser<T>({
  columns,
  hiddenIds,
  visibleColumns,
  onVisibleChange,
  onReset,
  testId,
}: {
  columns: Column<T>[];
  hiddenIds: Set<string>;
  visibleColumns: number;
  onVisibleChange: (id: string, visible: boolean) => void;
  onReset: () => void;
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

function readStoredTablePreferences(key?: string): StoredTablePreferences {
  if (!key || typeof localStorage === "undefined") return {};
  try {
    const parsed = JSON.parse(localStorage.getItem(tablePreferencesStorageKey(key)) ?? "{}");
    if (!parsed || typeof parsed !== "object") return {};
    const hiddenColumnIds = Array.isArray(parsed.hiddenColumnIds)
      ? parsed.hiddenColumnIds.filter((id: unknown): id is string => typeof id === "string")
      : undefined;
    const density = parsed.density === "compact" || parsed.density === "cozy" || parsed.density === "comfy"
      ? parsed.density
      : undefined;
    return { density, hiddenColumnIds };
  } catch {
    return {};
  }
}

function writeStoredTablePreferences(key: string, preferences: StoredTablePreferences) {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(tablePreferencesStorageKey(key), JSON.stringify(preferences));
  } catch {
    // Storage can be unavailable in locked-down browsers; table controls should still work.
  }
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
