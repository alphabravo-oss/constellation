import { useMutation, useIsFetching, useQueryClient } from "@tanstack/react-query";
import { useCluster } from "@/hooks/useCluster";
import { useDebounced } from "@/hooks/useDebounced";
import { useRouteSearchParams } from "@/lib/route-search";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import type { ScanInventoryExportResult, ScanInventoryMetadata } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Pager } from "@/components/ui/pager";

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
export function useInventoryRoute() {
  const [params, setParams] = useRouteSearchParams();
  const query = params.get("q") ?? "";
  const debouncedQuery = useDebounced(query, 250);
  const rawPage = Number(params.get("page"));
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 && rawPage <= 10000 ? rawPage - 1 : 0;
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
  return <div className="space-y-2" data-testid="scan-inventory-continuation">
    <p className="text-xs text-muted-foreground">{total === undefined ? <>{rows} loaded records on server page {page + 1}; {matching} match page filters. The server does not report a total. CSV and metrics cover this page only.</> : <>{total.toLocaleString()} records match the server filters; {rows} on page {page + 1}. Metrics cover every match. Matching CSV exports up to 100,000 records across pages.</>}</p>
    {rows === 0 && page > 0 ? <div className="space-y-2"><p>No records were returned for this page. Return to the first page to recover.</p><Button onClick={() => onPage(0)}>First page</Button><Button onClick={() => onPage(page - 1)}>Previous page</Button></div>
      : <Pager page={page} pageSize={INVENTORY_PAGE_SIZE} rowsOnPage={rows} total={total} hasMore={hasMore} onPage={onPage} />}
  </div>;
}


// eslint-disable-next-line react-refresh/only-export-components
export function scanInventoryResponseValid(data: (ScanInventoryMetadata & { limit: number; offset: number }) | undefined, rows: number, offset: number, sort: string, order: string, summaryKeys: string[] = []) {
  return !!data && data.offset === offset && data.limit === INVENTORY_PAGE_SIZE && Number.isSafeInteger(data.total) && data.total! >= 0 && typeof data.has_more === "boolean" && data.summary?.total === data.total && summaryKeys.every(key => Number.isSafeInteger(data.summary?.[key]) && data.summary![key] >= 0) && data.sort === sort && data.order === order && rows === Math.min(INVENTORY_PAGE_SIZE, Math.max(0, data.total! - offset)) && data.has_more === (data.total! > offset + rows);
}

export function ScanInventoryExport({ context, disabled, download }: { context: string; disabled: boolean; download: () => Promise<ScanInventoryExportResult> }) {
  const exportCSV = useMutation({ mutationFn: async (requestContext: string) => ({ ...await download(), context: requestContext }) });
  const result = exportCSV.data?.context === context ? exportCSV.data : undefined;
  const failed = exportCSV.isError && exportCSV.variables === context;
  return <div className="space-y-2"><Button disabled={disabled || exportCSV.isPending} onClick={() => exportCSV.mutate(context)}>{exportCSV.isPending ? "Exporting matching CSV…" : "Export matching CSV"}</Button>
    {failed && <p role="alert" className="text-sm text-destructive">Matching CSV could not be exported. Refresh the evidence and try again.</p>}
    {result && <p role={result.truncated ? "alert" : "status"} className="text-sm">{result.truncated ? `Export capped at ${result.limit.toLocaleString()} of ${result.total.toLocaleString()} matching records. Narrow filters for a complete export.` : `Exported all ${result.exported.toLocaleString()} matching records across pages.`}</p>}
  </div>;
}
