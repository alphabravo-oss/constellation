import { useSyncExternalStore } from "react";
import type { ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { nodes as nodesApi, type NodeVulnerability, type NodeVulnerabilityParams, type NodeVulnerabilityResponse, type NodeDetail } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useDebounced } from "@/hooks/useDebounced";
import { useRouteSearchParams } from "@/lib/route-search";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { StatusPill as SharedStatusPill } from "@/components/ui/status-pill";
import { Pager } from "@/components/ui/pager";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { ScanInventoryExport, scanInventoryResponseValid } from "./inventory-workspace";
import { Select } from "@/components/ui/form";

function useNodeFindingRoute(prefix: string) {
  const [search, setSearch] = useRouteSearchParams();
  const params = new URLSearchParams();
  for (const [key, value] of search) if (key.startsWith(prefix)) params.append(key.slice(prefix.length), value);
  const query = params.get("q") || "", debouncedQuery = useDebounced(query, 250);
  const pageValue = Number(params.get("page"));
  const page = Number.isSafeInteger(pageValue) && pageValue > 0 && pageValue <= INVENTORY_MAX_PAGE ? pageValue - 1 : 0;
  const update = (changes: Record<string, string | null>, reset = true, replace = false) => setSearch(current => {
    const next = new URLSearchParams(current);
    for (const [key, value] of Object.entries(changes)) { if (!value) next.delete(prefix + key); else next.set(prefix + key, value); }
    if (reset) { next.delete(prefix + "page"); next.delete(prefix + "selected"); }
    return next;
  }, { replace });
  return { params, query, debouncedQuery, debouncing: query !== debouncedQuery, page, offset: page * 100, selectedID: params.get("selected"), update, setQuery: (value: string) => update({ q: value }, true, true), setSelectedID: (value: string | null) => update({ selected: value }, false) };
}

function nodeFindingResponseMatches(data: NodeVulnerabilityResponse | undefined, clusterId: string, nodeName: string, request: NodeVulnerabilityParams) {
  if (!data || data.node !== nodeName || data.cluster_id !== clusterId || !Array.isArray(data.items)) return false;
  if (!scanInventoryResponseValid(data, data.items.length, request.offset || 0, request.sort || "risk", request.order || "desc", ["critical", "high", "fixable", "unique_cves"])) return false;
  if (data.q !== (request.q || "") || data.severity !== (request.severity || "") || data.fixable !== (request.fixable || "") || data.source !== (request.source || "")) return false;
  if (Object.values(data.summary).some(count => count > data.total) || data.summary.critical + data.summary.high > data.total) return false;
  return data.items.every(item => [item.id, item.row_id, item.vuln_id, item.package_name, item.package_version, item.source, item.observed_at, item.first_seen_at].every(value => typeof value === "string") && (item.fixed_version === undefined || typeof item.fixed_version === "string") && (item.summary === undefined || typeof item.summary === "string") && (item.references === undefined || typeof item.references === "string") && (item.aliases === undefined || Array.isArray(item.aliases) && item.aliases.every(value => typeof value === "string")) && item.id && item.row_id?.startsWith(`${item.id}:`) && /^-?\d+(?:\.\d+)?$/.test(item.row_id.slice(item.id.length + 1)) && item.node === nodeName && (item.source_cluster_id === clusterId || item.cluster_id === clusterId)
    && ["critical", "high", "medium", "low", "info", "unknown"].includes(item.severity || "") && Number.isFinite(item.risk_score) && typeof item.fixable === "boolean"
    && (!request.severity || item.severity === request.severity) && (!request.fixable || item.fixable === (request.fixable === "true")) && (!request.source || item.source === request.source))
    && new Set(data.items.map(item => item.row_id)).size === data.items.length;
}

function hostFindingSummary(item: NodeVulnerability) {
  const primary = item.vuln_id.trim().toLowerCase();
  const summary = item.summary?.trim();
  if (summary && summary.toLowerCase() !== primary) return summary;
  return [...new Set((item.aliases || []).map(alias => alias.trim()).filter(alias => alias && alias.toLowerCase() !== primary))].join(", ");
}

export function NodeVulnerabilitiesInventory({ clusterId, nodeName, sourceQueryKey, sourceKind = "detail", sourceReady, nodeRefreshing = false, paramPrefix = "" }: { clusterId: string; nodeName: string; sourceQueryKey: readonly unknown[]; sourceKind?: "detail" | "risk"; sourceReady: boolean; nodeRefreshing?: boolean; paramPrefix?: string }) {
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const cluster = useCluster();
  const qc = useQueryClient();
  const sourceCurrent = () => {
    const state = qc.getQueryState<NodeDetail | { type: string; data: NodeDetail }>(sourceQueryKey);
    if (state?.status !== "success" || !state.data || !sourceReady || !owner || !sourceQueryKey.includes(owner) || cluster.clusterId !== clusterId || cluster.cluster?.id !== clusterId || cluster.isLoading || cluster.error) return false;
    const value = sourceKind === "risk" && "type" in state.data && state.data.type === "node" ? state.data.data : sourceKind === "detail" && "node" in state.data ? state.data : undefined;
    return value?.node.node === nodeName && value.node.cluster_id === clusterId;
  };
  const sourceValid = useSyncExternalStore(notify => qc.getQueryCache().subscribe(notify), sourceCurrent);
  const sourceSettled = () => sourceCurrent() && clusterCacheReady(qc, clusterId) && qc.getQueryState(sourceQueryKey)?.fetchStatus === "idle" && !qc.getQueryState(sourceQueryKey)?.isInvalidated;
  const route = useNodeFindingRoute(paramPrefix);
  const severity = route.params.get("severity") || "";
  const fixable = route.params.get("fixable") || "";
  const source = route.params.get("source")?.trim() || "";
  const sort = route.params.get("sort") || "risk";
  const order = route.params.get("order") || "desc";
  const rawPage = route.params.get("page");
  const invalid = Boolean(["q", "severity", "fixable", "source", "sort", "order", "page", "selected"].some(field => route.params.getAll(field).length > 1) || severity && !["critical", "high", "medium", "low", "info", "unknown"].includes(severity) || fixable && !["true", "false"].includes(fixable) || !["risk", "cve", "package", "version", "severity", "fix", "source", "observed"].includes(sort) || !["asc", "desc"].includes(order) || rawPage !== null && (!/^\d+$/.test(rawPage) || !Number.isSafeInteger(Number(rawPage)) || Number(rawPage) < 1 || Number(rawPage) > INVENTORY_MAX_PAGE));
  const request = { q: route.debouncedQuery.trim() || undefined, severity: severity || undefined, fixable: fixable as "true" | "false" || undefined, source: source || undefined, sort, order: order as "asc" | "desc", limit: 100, offset: route.offset };
  const key = ["node-vulnerabilities", owner, clusterId, nodeName, request];
  const context = JSON.stringify([key, route.query]);
  const matches = (data: NodeVulnerabilityResponse | undefined) => nodeFindingResponseMatches(data, clusterId, nodeName, request);
  const q = useQuery({ queryKey: key, enabled: sourceSettled() && !invalid && !route.debouncing && !nodeRefreshing, queryFn: async () => { const data = await nodesApi.vulnerabilities(clusterId, nodeName, request); if (!matches(data)) throw new Error("Node host finding inventory does not match the requested scope or page."); return data; } });
  const valid = q.data && matches(q.data);
  const available = sourceValid && q.isSuccess && valid && !invalid && !route.debouncing;
  const exportCurrent = () => { const state = qc.getQueryState<NodeVulnerabilityResponse>(key); return sourceSettled() && !nodeRefreshing && state?.status === "success" && state.fetchStatus === "idle" && !state.isInvalidated && state.data === q.data && matches(state.data); };
  const rows = available ? q.data.items : [];
  const selected = rows.find(item => item.row_id === route.selectedID);
  const setPage = (page: number) => route.update({ page: page ? String(page + 1) : null }, false);
  const columns: Column<NodeVulnerability>[] = [
    { id: "cve", header: "CVE / advisory", kind: "name", wrap: true, sort: () => 0, exportValue: item => item.vuln_id, cell: item => <>{item.vuln_id ? <a href={`/clusters/${encodeURIComponent(clusterId)}/cve/${encodeURIComponent(item.vuln_id)}`} className="font-mono text-xs hover:underline">{item.vuln_id}</a> : <span>Not reported</span>}{hostFindingSummary(item) && <div className="mt-1 text-xs text-muted-foreground">{hostFindingSummary(item)}</div>}</> },
    { id: "package", header: "Package", kind: "text", code: true, wrap: true, size: 200, minSize: 144, maxSize: 280, sort: () => 0, cell: item => item.package_name || "Not reported" },
    { id: "version", header: "Version", kind: "version", wrap: true, sort: () => 0, cell: item => item.package_version || "Not reported" },
    { id: "severity", header: "Severity", kind: "status", sort: () => 0, exportValue: item => item.severity || "unknown", cell: item => <SharedStatusPill label={item.severity || "unknown"} tone={item.severity === "critical" ? "error" : item.severity === "high" || item.severity === "medium" ? "warning" : "neutral"} /> },
    { id: "risk", header: "Risk", kind: "count", sort: () => 0, cell: item => item.risk_score },
    { id: "fix", header: "Fixed version", kind: "version", size: 160, minSize: 112, maxSize: 224, wrap: true, sort: () => 0, cell: item => item.fixable ? item.fixed_version || "Reported fix" : "No reported fix" },
    { id: "source", header: "Source", kind: "text", wrap: true, size: 144, maxSize: 240, sort: () => 0, cell: item => item.source },
    { id: "observed", header: "Observed", kind: "date", size: 224, minSize: 208, maxSize: 240, sort: () => 0, exportValue: item => item.observed_at, cell: item => formatDate(item.observed_at) },
    { id: "row_id", header: "Instance row ID", kind: "id", size: 288, maxSize: 432, code: true, wrap: true, cell: item => item.row_id },
    { id: "id", header: "Finding ID", kind: "id", size: 240, maxSize: 360, code: true, wrap: true, cell: item => item.id },
  ];
  return <section className="space-y-3" data-testid="node-vulnerabilities">
    <div><h2 className="text-sm font-semibold">Host vulnerability finding instances</h2><Collapse label="Inventory details"><p className="text-xs text-muted-foreground">Open host findings attributed to this node by their source cluster or effective target cluster. Instances can repeat a CVE across packages or scanners. Filters, totals and sorting cover all matching instances; matching CSV exports up to 100,000 rows.</p></Collapse></div>
    <div className="flex flex-wrap gap-2"><input aria-label="Search node host findings" className="min-w-0 basis-64 flex-1 rounded-md border border-border bg-background p-2 text-sm" placeholder="Search CVE, package, scanner or finding ID" value={route.query} onChange={event => route.setQuery(event.target.value)} /><Select aria-label="Host finding severity" className="rounded-md border border-border bg-background p-2 text-sm" value={severity} onChange={event => route.update({ severity: event.target.value })}><option value="">All severities</option>{["critical", "high", "medium", "low", "info", "unknown"].map(value => <option key={value}>{value}</option>)}</Select><Select aria-label="Host finding fixability" className="rounded-md border border-border bg-background p-2 text-sm" value={fixable} onChange={event => route.update({ fixable: event.target.value })}><option value="">All fix states</option><option value="true">Fix reported</option><option value="false">No reported fix</option></Select><input aria-label="Host finding source" className="rounded-md border border-border bg-background p-2 text-sm" placeholder="Exact scanner source" value={route.params.get("source") || ""} onChange={event => route.update({ source: event.target.value }, true, true)} /><Button variant="outline" onClick={() => route.update({ q: null, severity: null, fixable: null, source: null, sort: null, order: null, page: null })}>Reset host finding filters</Button></div>
    {!sourceValid ? <ErrorState title="Current node evidence is unavailable; refresh this exact node before loading findings." action={<Button onClick={() => void qc.invalidateQueries({ queryKey: sourceQueryKey, exact: true })}>Retry node evidence</Button>} /> : invalid ? <ErrorState title="Choose supported host finding filters, sorting and page." /> : q.isError || q.data && !valid ? <ErrorState title="Host finding inventory could not be loaded or refreshed." action={<Button disabled={!sourceSettled() || invalid || route.debouncing || nodeRefreshing} onClick={() => { if (sourceSettled() && !invalid && !route.debouncing && !nodeRefreshing) void q.refetch(); }}>Retry host findings</Button>} /> : !available ? <LoadingState label="Loading host findings…" /> : <>
      <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-muted-foreground">{q.data.total.toLocaleString()} matching finding instances · {q.data.summary.unique_cves.toLocaleString()} unique CVE / advisory IDs · {q.data.summary.critical.toLocaleString()} critical · {q.data.summary.high.toLocaleString()} high · {q.data.summary.fixable.toLocaleString()} with a reported fix</p><ScanInventoryExport context={context} isCurrent={exportCurrent} disabled={q.isFetching || nodeRefreshing || !exportCurrent()} download={shouldDownload => { if (!exportCurrent()) return Promise.reject(new Error("Refresh host findings before exporting")); return nodesApi.exportVulnerabilitiesCSV(clusterId, nodeName, request, () => shouldDownload() && exportCurrent()); }} /></div>
      {(q.isFetching || nodeRefreshing) && <p role="status" className="text-sm text-muted-foreground">Refreshing host findings; matching export is paused until the request settles.</p>}
      <DataTable rows={rows} columns={columns} canExport={exportCurrent} rowKey={item => item.row_id} preferencesKey="node-host-vulnerabilities" defaultHiddenColumnIds={["row_id", "id"]} testId="node-host-findings-table" pagination={false} manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => route.update({ sort: next?.id || null, order: next?.dir || null })} selected={new Set(selected ? [selected.row_id] : [])} onRowClick={item => route.setSelectedID(item.row_id)} exportFileName={`node-${clusterId}-${encodeURIComponent(nodeName)}-host-findings-page.csv`} exportLabel="Export this page CSV" emptyState={<p className="p-6 text-sm text-muted-foreground">No matching host finding instances returned for this page. This does not establish a successful or complete scan.</p>} />
      {route.page > 0 && rows.length === 0 && <Button onClick={() => setPage(0)}>First page</Button>}<Pager page={route.page} pageSize={100} total={q.data.total} rowsOnPage={rows.length} onPage={setPage} />
      {route.selectedID && <div className="space-y-2"><Button variant="outline" size="sm" onClick={() => route.setSelectedID(null)}>Clear host finding selection</Button>{selected ? <dl className="grid gap-2 rounded-md border border-border p-3 text-sm sm:grid-cols-2"><Field label="Finding ID" value={selected.id} /><Field label="First seen" value={formatDate(selected.first_seen_at)} /><Field label="Source cluster ID" value={selected.source_cluster_id || "Not reported"} /><Field label="Effective target cluster ID" value={selected.cluster_id || "Not reported"} /><Field label="References" value={selected.references || "Not reported"} wide /></dl> : <p role="status" className="text-sm text-muted-foreground">The selected finding instance is outside this page or filter; no other finding has been substituted.</p>}</div>}
    </>}
  </section>;
}

function Field({ label, value, wide }: { label: string; value: ReactNode; wide?: boolean }) {
  return <div className={`grid gap-1 ${wide ? "sm:col-span-2" : ""}`}><dt className="text-micro  text-muted-foreground">{label}</dt><dd className="break-all font-mono text-xs">{value}</dd></div>;
}
function formatDate(value?: string): string { if (!value) return "Not reported"; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString(); }
