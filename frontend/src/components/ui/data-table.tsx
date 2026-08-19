import { type ReactNode, type Key, useMemo, useState } from "react";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { ChevronDown, ChevronUp, ArrowUpDown, Rows3, Rows2, Rows4 } from "lucide-react";
import { cn } from "@/lib/cn";

export type Density = "compact" | "cozy" | "comfy";

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
  /** Show density toggle in header right slot. */
  showDensityToggle?: boolean;
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
  density = "cozy",
  onDensityChange,
  emptyState,
  className,
  defaultSort,
  showDensityToggle = true,
  testId,
  rowTestId,
  rowAttrs,
}: DataTableProps<T>) {
  const [sorting, setSorting] = useState<SortingState>(
    defaultSort ? [{ id: defaultSort.id, desc: defaultSort.dir === "desc" }] : [],
  );

  const rowH = density === "compact" ? "h-6" : density === "comfy" ? "h-10" : "h-8";
  const cellPad = density === "compact" ? "px-2 py-0.5" : density === "comfy" ? "px-3 py-2" : "px-2.5 py-1.5";

  // Look up the Column facade by id when rendering headers/cells (avoids
  // threading the facade through TanStack column meta typing).
  const colById = useMemo(() => new Map(columns.map((c) => [c.id, c])), [columns]);

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
    state: { sorting },
    onSortingChange: setSorting,
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

  return (
    <div className={cn("rounded-md border border-border bg-card overflow-hidden", className)} data-testid={testId}>
      {showDensityToggle && (
        <div className="flex items-center justify-end gap-1 border-b border-border px-2 py-1">
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground mr-2">Density</span>
          <DensityBtn current={density} value="compact" onClick={() => onDensityChange?.("compact")} icon={Rows4} label="compact" />
          <DensityBtn current={density} value="cozy"    onClick={() => onDensityChange?.("cozy")} icon={Rows3} label="cozy" />
          <DensityBtn current={density} value="comfy"   onClick={() => onDensityChange?.("comfy")} icon={Rows2} label="comfy" />
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
                  {columns.map((c) => (
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
                <td colSpan={columns.length + (selectable ? 1 : 0)}>
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
