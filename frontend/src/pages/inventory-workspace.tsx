import { useExportGuard } from "@/hooks/useExportGuard";
import { useMutation, useIsFetching, useQueryClient } from "@tanstack/react-query";
import { useCluster } from "@/hooks/useCluster";
import { useDebounced } from "@/hooks/useDebounced";
import { useRouteSearchParams } from "@/lib/route-search";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import type { ScanInventoryDownloadGuard, ScanInventoryExportResult, ScanInventoryMetadata } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Pager } from "@/components/ui/pager";
import { Filter, Info, Search } from "lucide-react";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { ToolbarButton, Tooltip, type ExportOption } from "@/ui";

export const INVENTORY_PAGE_SIZE = 100;
export const INVENTORY_FETCH_SIZE = 101;
// eslint-disable-next-line react-refresh/only-export-components
export function useInventoryScope() {
  const scope = useCluster();
  const identity = useTablePreferencesIdentity();
  const qc = useQueryClient();
  const fetching = useIsFetching({ queryKey: ["clusters"], exact: true }) + useIsFetching({ queryKey: ["cluster", scope.clusterId], exact: true });
  const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
  const detail = qc.getQueryState<{ id: string }>(["cluster", scope.clusterId]);
  const cached = !registry && !detail || (registry?.data?.clusters.find(item => item.id === scope.clusterId) ?? detail?.data)?.id === scope.clusterId;
  const ready = Boolean(scope.clusterId && scope.cluster?.id === scope.clusterId && !scope.isLoading && !scope.error && !fetching && cached && (!registry || registry.status === "success") && (!detail || detail.status !== "error"));
  return { ...scope, owner: `${identity?.org_id}:${identity?.user_id}`, ready, fetching, retry: () => { void qc.invalidateQueries({ queryKey: ["clusters"], exact: true }); void qc.invalidateQueries({ queryKey: ["cluster", scope.clusterId], exact: true }); } };
}
// eslint-disable-next-line react-refresh/only-export-components
export function useInventoryRoute(maxPage = 10000) {
  const [params, setParams] = useRouteSearchParams();
  const query = params.get("q") ?? "";
  const debouncedQuery = useDebounced(query, 250);
  const rawPage = Number(params.get("page"));
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 && rawPage <= maxPage ? rawPage - 1 : 0;
  const update = (changes: Record<string, string | null>, reset = true, replace = false) => setParams(current => {
    const next = new URLSearchParams(current);
    for (const [key, value] of Object.entries(changes)) { if (value === null || value === "") next.delete(key); else next.set(key, value); }
    if (reset) { next.delete("page"); next.delete("selected"); }
    return next;
  }, { replace });
  return { params, query, debouncedQuery, debouncing: query !== debouncedQuery, page, offset: page * INVENTORY_PAGE_SIZE, selectedID: params.get("selected"), update,
    setQuery: (value: string) => update({ q: value }, true, true), setSelectedID: (value: string | null) => update({ selected: value }, false),
    setPage: (value: number) => update({ page: value === 0 ? null : String(value + 1), selected: null }, false) };
}
export function InventoryScopeState({ scope }: { scope: ReturnType<typeof useInventoryScope> }) {
  return scope.isLoading || scope.fetching ? <LoadingState label="Resolving cluster…" /> : <ErrorState title="The active cluster could not be resolved." action={<Button onClick={scope.retry}>Retry cluster</Button>} />;
}
export function InventoryLoadState({ label, query, invalid = false, debouncing = false }: { label: string; query: { isError: boolean; isPending: boolean; isFetching: boolean; refetch: () => unknown }; invalid?: boolean; debouncing?: boolean }) {
  return query.isError || invalid ? <ErrorState title={`${label} are unavailable${invalid ? ": the response does not match the requested scope or page" : " or could not be refreshed"}.`} action={<Button onClick={() => void query.refetch()}>Retry</Button>} />
    : query.isPending || query.isFetching || debouncing ? <LoadingState label={`Loading ${label.toLowerCase()}…`} /> : null;
}
export function ScanInventoryContinuation({ page, rows, hasMore, onPage, matching, total }: { page: number; rows: number; hasMore: boolean; onPage: (page: number) => void; matching: number; total?: number }) {
  const note = total === undefined
    ? <>{rows} loaded records on server page {page + 1}; {matching} match page filters. The server does not report a total. CSV and metrics cover this page only.</>
    : <>{total.toLocaleString()} records match the server filters; {rows} on page {page + 1}. Metrics cover every match. Matching CSV exports up to 100,000 records across pages.</>;
  return <div className="space-y-2" data-testid="scan-inventory-continuation">
    {rows === 0 && page > 0 ? <div className="flex flex-wrap items-center gap-2"><p className="text-sm text-muted-foreground">No records were returned for this page. Return to the first page to recover.</p><Button onClick={() => onPage(0)}>First page</Button><Button onClick={() => onPage(page - 1)}>Previous page</Button></div>
      : <div className="flex items-start gap-1.5"><div className="min-w-0 flex-1"><Pager page={page} pageSize={INVENTORY_PAGE_SIZE} rowsOnPage={rows} total={total} hasMore={hasMore} onPage={onPage} /></div>
        <Tooltip content={<span className="block max-w-xs">{note}</span>}><button type="button" aria-label="About these records" className="mt-3 inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"><Info className="h-4 w-4" aria-hidden /></button></Tooltip></div>}
    <p className="sr-only">{note}</p>
  </div>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function scanInventoryResponseValid(data: (ScanInventoryMetadata & { limit: number; offset: number }) | undefined, rows: number, offset: number, sort: string, order: string, summaryKeys: string[] = []) {
  return !!data && data.offset === offset && data.limit === INVENTORY_PAGE_SIZE && Number.isSafeInteger(data.total) && data.total! >= 0 && typeof data.has_more === "boolean" && data.summary?.total === data.total && summaryKeys.every(key => Number.isSafeInteger(data.summary?.[key]) && data.summary![key] >= 0) && data.sort === sort && data.order === order && rows === Math.min(INVENTORY_PAGE_SIZE, Math.max(0, data.total! - offset)) && data.has_more === (data.total! > offset + rows);
}

/**
 * Server-side "matching rows" export as one option of the table's single
 * Export menu (C1: one export verb). `status` renders the capped/complete
 * receipt and failures next to the table.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useScanInventoryExport({ context, disabled, download, isCurrent, label = "Matching rows", description = "Every page, up to 100,000 records" }: { context: string; disabled: boolean; isCurrent?: ScanInventoryDownloadGuard; download: (shouldDownload: ScanInventoryDownloadGuard) => Promise<ScanInventoryExportResult>; label?: string; description?: string }): { option: ExportOption; status: ReactNode; pending: boolean } {
  const captureExport = useExportGuard(context, disabled, isCurrent);
  const exportCSV = useMutation({ mutationFn: async (request: { context: string; shouldDownload: ScanInventoryDownloadGuard; download: (shouldDownload: ScanInventoryDownloadGuard) => Promise<ScanInventoryExportResult> }) => {
    const shouldDownload = request.shouldDownload;
    if (!shouldDownload()) throw new Error("Refresh the inventory before exporting this scope.");
    const result = await request.download(shouldDownload);
    if (!shouldDownload()) throw new Error("Refresh the inventory before exporting this scope.");
    return { ...result, context: request.context };
  } });
  const result = exportCSV.data?.context === context ? exportCSV.data : undefined;
  const failed = exportCSV.isError && exportCSV.variables?.context === context;
  const status = failed || result ? <div className="text-sm" data-testid="scan-inventory-export-status">
    {failed && <p role="alert" className="text-status-error">Matching CSV could not be exported. Refresh the evidence and try again.</p>}
    {result && <p role={result.truncated ? "alert" : "status"} className="text-muted-foreground">{result.truncated ? `Export capped at ${result.limit.toLocaleString()} of ${result.total.toLocaleString()} matching records. Narrow filters for a complete export.` : `Exported all ${result.exported.toLocaleString()} matching records across pages.`}</p>}
  </div> : null;
  return {
    option: { label: exportCSV.isPending ? "Exporting matching rows…" : label, description, disabled: disabled || exportCSV.isPending, onSelect: () => exportCSV.mutate({ context, shouldDownload: captureExport(), download }) },
    status,
    pending: exportCSV.isPending,
  };
}

/** Standalone matching export (pages without a table toolbar). */
export function ScanInventoryExport({ context, disabled, download, isCurrent }: { context: string; disabled: boolean; isCurrent?: ScanInventoryDownloadGuard; download: (shouldDownload: ScanInventoryDownloadGuard) => Promise<ScanInventoryExportResult> }) {
  const { option, status, pending } = useScanInventoryExport({ context, disabled, download, isCurrent });
  return <div className="space-y-2"><Button disabled={option.disabled} onClick={option.onSelect} aria-label="Export matching CSV">{pending ? "Exporting…" : "Export matching CSV"}</Button>{status}</div>;
}

/** Table search field (kit TableSearch geometry) with an explicit label and test id. */
export function InventorySearch({ value, onChange, label, placeholder, testId, className }: { value: string; onChange: (value: string) => void; label: string; placeholder?: string; testId?: string; className?: string }) {
  return <div className={`relative w-full max-w-72 ${className ?? ""}`}>
    <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
    <input type="search" value={value} onChange={event => onChange(event.target.value)} aria-label={label} placeholder={placeholder ?? label} data-testid={testId} data-table-search=""
      className="h-9 w-full rounded-md border border-border bg-background pl-9 pr-3 text-sm placeholder:text-muted-foreground focus:outline-hidden focus:ring-2 focus:ring-ring" />
  </div>;
}

/**
 * "More filters" for inventory toolbars: kit ToolbarButton + a popover-styled
 * panel that stays mounted (hidden when closed) so URL-driven filter values
 * and their controls survive open/close. Closes on Escape and outside click.
 */
export function InventoryMoreFilters({ count = 0, children }: { count?: number; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (event: MouseEvent) => { const target = event.target as HTMLElement; if (target.closest?.("[data-radix-popper-content-wrapper]")) return; if (ref.current && !ref.current.contains(target)) setOpen(false); };
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey); };
  }, [open]);
  return <div ref={ref} className="relative shrink-0">
    <ToolbarButton active={count > 0} aria-expanded={open} aria-controls={id} onClick={() => setOpen(value => !value)} className="whitespace-nowrap">
      <Filter className="h-3.5 w-3.5" />
      More filters
      {count > 0 ? <span className="ml-0.5 inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-foreground px-1 text-micro text-background">{count}</span> : null}
    </ToolbarButton>
    <div id={id} hidden={!open} role="group" aria-label="More filters" className="absolute left-0 top-full z-popover mt-1.5 w-80 space-y-3 rounded-md border border-border bg-popover p-3 text-popover-foreground shadow-elev-popover">
      {children}
    </div>
  </div>;
}

export function FilterLabel({ label, children }: { label: string; children: ReactNode }) {
  return <label className="block space-y-1.5 text-meta font-medium text-muted-foreground"><span>{label}</span>{children}</label>;
}
