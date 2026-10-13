import { fmtRelative } from "@/lib/format";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { assets, type AssetFindingInventoryResponse } from "@/api/client";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Pager } from "@/components/ui/pager";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { useInventoryRoute, ScanInventoryExport, scanInventoryResponseValid } from "./inventory-workspace";
import type { useAssetDetailScope } from "./asset-detail-scope";

const severities = ["critical", "high", "medium", "low", "info", "unknown"];
const lifecycles = ["open", "triaged", "in_progress", "resolved", "suppressed", "accepted"];
const sources = ["asset", "image_scan"];
const sorts = ["finding", "kind", "severity", "risk", "lifecycle", "source", "observed"];
// eslint-disable-next-line react-refresh/only-export-components
export function useAssetFindingsInventory(scope: ReturnType<typeof useAssetDetailScope>) {
  const route = useInventoryRoute();
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const qc = useQueryClient();
  const severity = route.params.get("severity") || "", lifecycle = route.params.get("lifecycle") || "", source = route.params.get("source") || "";
  const sort = route.params.get("sort") || "risk", order = route.params.get("order") || "desc", rawPage = route.params.get("page");
  const invalid = Boolean(severity && !severities.includes(severity) || lifecycle && !lifecycles.includes(lifecycle) || source && !sources.includes(source) || !sorts.includes(sort) || !["asc", "desc"].includes(order) || rawPage !== null && (!/^\d+$/.test(rawPage) || !Number.isSafeInteger(Number(rawPage)) || Number(rawPage) < 1 || Number(rawPage) > 10000));
  const request = { cluster_id: scope.clusterId, q: route.debouncedQuery.trim() || undefined, severity: severity || undefined, lifecycle: lifecycle || undefined, source: source || undefined, sort, order: order as "asc" | "desc", limit: 100, offset: route.offset };
  const key = ["asset-findings", owner, scope.clusterId, scope.aid, request];
  const enabled = Boolean(owner && scope.resolved && scope.aid && scope.q.isSuccess && !scope.q.isFetching && scope.q.data?.asset.id === scope.aid && scope.q.data.asset.cluster_id === scope.clusterId && !invalid && !route.debouncing);
  const valid = (data: AssetFindingInventoryResponse) => !!data && Array.isArray(data.items) && data.items.every(f => !!f && typeof f === "object" && [f.id, f.row_id, f.title, f.external_id, f.kind, f.severity, f.lifecycle, f.source].every(value => typeof value === "string") && Number.isSafeInteger(f.risk_score) && f.risk_score >= 0) && data.asset_id === scope.aid && data.cluster_id === scope.clusterId &&
    data.q === (request.q ?? "") && data.severity === severity && data.lifecycle === lifecycle && data.source === source &&
    scanInventoryResponseValid(data, data.items.length, request.offset, sort, order, ["critical", "high", "open", "asset_findings", "image_scan_findings"]) &&
    data.summary.asset_findings + data.summary.image_scan_findings === data.total && data.summary.critical + data.summary.high <= data.total && data.summary.open <= data.total &&
    new Set(data.items.map(f => f.row_id)).size === data.items.length && data.items.every(f => f.id && (f.source === "asset" ? f.row_id.startsWith(`asset:${f.id}:`) && /^-?\d+(?:\.\d+)?$/.test(f.row_id.slice(`asset:${f.id}:`.length)) : f.row_id === `image:${f.id}`) && sources.includes(f.source) && (f.source === "image_scan" ? !!f.image_scan_result_id : !f.image_scan_result_id) && (!severity || f.severity === severity) && (!lifecycle || f.lifecycle === lifecycle) && (!source || f.source === source));
  const q = useQuery({ queryKey: key, enabled, queryFn: async () => { const data = await assets.findings(scope.aid!, request); if (!valid(data)) throw new Error("Asset findings do not match this scope or page"); return data; } });
  const invalidResponse = q.isSuccess && !q.isFetching && !valid(q.data);
  const available = enabled && q.isSuccess && !q.isFetching && !invalidResponse;
  const recheck = () => { const state = qc.getQueryState<AssetFindingInventoryResponse>(key); return available && !!scope.recheck() && state?.status === "success" && state.fetchStatus === "idle" && !state.isInvalidated && !!state.data && valid(state.data); };
  return { route, request, key, context: JSON.stringify([key, route.query]), invalid, invalidResponse, q, available, recheck, clusterId: scope.clusterId, assetId: scope.aid };
}
type Inventory = ReturnType<typeof useAssetFindingsInventory>;
type Row = AssetFindingInventoryResponse["items"][number];
export function AssetFindingsInventory({ inventory: i }: { inventory: Inventory }) {
  const { route, request, q, available } = i;
  const columns: Column<Row>[] = [
    { id: "finding", header: "Finding", kind: "name", size: 340, minSize: 280, wrap: true, sort: () => 0, exportValue: f => f.title, cell: f => <><div className="line-clamp-2" title={f.title}>{f.source === "asset" ? <a className="font-medium hover:underline" href={`/clusters/${encodeURIComponent(i.clusterId!)}/findings/${encodeURIComponent(f.id)}`}>{f.title}</a> : f.title}</div><div className="text-xs text-muted-foreground">{f.external_id}</div></> },
    { id: "platform-role", header: "Platform role", kind: "status", exportValue: f => f.platform_role ?? "", cell: f => <span className="text-xs">{f.platform_role === "core" ? "Core" : f.platform_role === "" ? "Unclassified" : "Not reported"}</span> },
    { id: "observed", header: "Observed", kind: "date", sort: () => 0, exportValue: f => f.last_seen_at, cell: f => <span title={f.last_seen_at}>{fmtRelative(f.last_seen_at)}</span> },
    { id: "kind", header: "Kind", kind: "status", sort: () => 0, cell: f => f.kind },
    { id: "severity", header: "Severity", kind: "status", sort: () => 0, cell: f => f.severity },
    { id: "risk", header: "Risk", kind: "count", sort: () => 0, cell: f => f.risk_score },
    { id: "lifecycle", header: "Lifecycle", kind: "status", sort: () => 0, cell: f => f.lifecycle },
    { id: "source", header: "Evidence source", kind: "text", sort: () => 0, wrap: true, cell: f => f.source === "image_scan" ? "Digest image scan" : "Asset finding" },
  ];
  return <section className="space-y-3" data-testid="asset-findings">
    <div className="flex flex-wrap gap-2"><input aria-label="Search asset findings" placeholder="Search findings" className="min-w-0 basis-64 flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm" value={route.query} onChange={e => route.setQuery(e.target.value)} />
      <select aria-label="Finding severity" value={request.severity ?? ""} onChange={e => route.update({ severity: e.target.value })} className="rounded-md border border-border bg-background p-2 text-sm"><option value="">All severities</option>{severities.map(s => <option key={s}>{s}</option>)}</select>
      <select aria-label="Finding lifecycle" value={request.lifecycle ?? ""} onChange={e => route.update({ lifecycle: e.target.value })} className="rounded-md border border-border bg-background p-2 text-sm"><option value="">All lifecycles</option>{lifecycles.map(s => <option key={s}>{s}</option>)}</select>
      <select aria-label="Finding source" value={request.source ?? ""} onChange={e => route.update({ source: e.target.value })} className="rounded-md border border-border bg-background p-2 text-sm"><option value="">All evidence sources</option><option value="asset">Asset findings</option><option value="image_scan">Digest image scan</option></select>
      <Button variant="outline" onClick={() => route.update({ q: null, severity: null, lifecycle: null, source: null, sort: null, order: null, page: null })}>Reset filters</Button>
    </div>
    {i.invalid ? <ErrorState title="Choose supported finding filters and sorting." /> : q.isError || i.invalidResponse ? <ErrorState title="Asset findings are unavailable or could not be refreshed." action={<Button onClick={() => void q.refetch()}>Retry findings</Button>} /> : !available || !q.data ? <LoadingState label="Loading asset findings…" /> : <>
      <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-muted-foreground">{q.data.total.toLocaleString()} matching findings · {q.data.summary.asset_findings.toLocaleString()} asset · {q.data.summary.image_scan_findings.toLocaleString()} digest scan</p><ScanInventoryExport context={i.context} disabled={!available} download={shouldDownload => { if (!i.recheck()) return Promise.reject(new Error("Refresh findings before exporting")); return assets.findingsCSV(i.assetId!, request, () => shouldDownload() && i.recheck()); }} /></div>
      <DataTable rows={q.data.items} columns={columns} rowKey={f => f.row_id} preferencesKey="asset-findings" defaultHiddenColumnIds={["observed", "platform-role"]} testId="asset-findings-table" pagination={false} manualSorting sort={{ id: request.sort, dir: request.order }} onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })} exportFileName={`asset-${i.assetId}-findings-page`} exportLabel="Export this page CSV" emptyState={<p className="p-6 text-sm text-muted-foreground">No findings match these filters or page.</p>} />
      {route.page > 0 && !q.data.items.length && <Button onClick={() => route.setPage(0)}>First page</Button>}
      <Pager page={route.page} pageSize={100} total={q.data.total} rowsOnPage={q.data.items.length} onPage={route.setPage} />
    </>}
  </section>;
}
