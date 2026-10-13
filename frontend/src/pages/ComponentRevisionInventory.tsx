import { useSyncExternalStore } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { clusters, componentsInventory, type ComponentInstance, type ComponentInventoryResponse, type ComponentsInventoryParams } from "@/api/client";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { useDebounced } from "@/hooks/useDebounced";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { NV_COMPONENT_ROLES, nvRoleAlias } from "@/lib/component-roles";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Pager } from "@/components/ui/pager";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { ScanInventoryExport } from "./inventory-workspace";

const statuses = ["healthy", "degraded", "stale", "drift", "crashlooping", "missing", "not-observed"];
const sorts = ["component", "build", "runtime", "status", "hostname", "restarts", "heartbeat"];
type AppliedStatus = "current" | "behind" | "ahead" | "unknown";
export function AppliedStatusPill({ status }: { status: AppliedStatus | "unavailable" }) {
  const cls = status === "current" ? "border-primary/30 bg-primary/10 text-primary" : status === "behind" ? "border-status-warning/30 bg-status-warning/10 text-status-warning" : status === "ahead" ? "border-status-info/30 bg-status-info/10 text-status-info" : "border-border bg-muted text-muted-foreground";
  return <span className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium ${cls}`}>{({ current: "Current", behind: "Behind", ahead: "Ahead", unknown: "Unknown", unavailable: "Unavailable" })[status]}</span>;
}
function reportedRevision(item: ComponentInstance) {
  const value = item.metadata?.system_config_revision;
  const revision = typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value.trim()) ? Number(value.trim()) : NaN;
  return Number.isSafeInteger(revision) && revision >= 0 ? revision : null;
}
function statusFor(item: ComponentInstance, target: number): AppliedStatus { const revision = reportedRevision(item); return revision === null ? "unknown" : revision < target ? "behind" : revision > target ? "ahead" : "current"; }
function responseMatches(data: ComponentInventoryResponse | undefined, request: ComponentsInventoryParams) {
  if (!data || !Array.isArray(data.components) || !Array.isArray(data.rollups) || (data.cluster_id ?? undefined) !== request.cluster_id || data.source_window_hours !== 24 || data.q !== (request.q || "") || data.role !== (request.role || "") || data.status !== (request.status || "") || data.component !== "" || data.limit !== 100 || data.offset !== request.offset || data.sort !== request.sort || data.order !== request.order || !Number.isSafeInteger(data.total) || data.total! < 0 || data.components.length !== Math.min(100, Math.max(0, data.total! - request.offset!)) || data.has_more !== (data.total! > request.offset! + data.components.length)) return false;
  if (!data.summary || !["components", "total_instances", "healthy", "degraded", "stale", "drift", "crashlooping", "missing"].every(key => Number.isSafeInteger(data.summary[key as keyof typeof data.summary]) && Number(data.summary[key as keyof typeof data.summary]) >= 0) || !NV_COMPONENT_ROLES.every(role => Number.isSafeInteger(data.role_counts?.[role.id]) && data.role_counts![role.id] >= 0) || data.role_counts!.all !== data.summary.total_instances || data.role_counts!.all < data.total!) return false;
  const ids = new Set<string>();
  return data.components.every(item => { if (![item.id, item.component, item.display_name, item.role, item.scope, item.kind, item.status, item.hostname, item.last_seen_at].every(value => typeof value === "string") || item.cluster_id != null && typeof item.cluster_id !== "string" || item.cluster_name != null && typeof item.cluster_name !== "string" || !item.id || ids.has(item.id) || request.cluster_id && item.cluster_id !== request.cluster_id || request.role && nvRoleAlias(item).id !== request.role || request.status && item.status !== request.status) return false; ids.add(item.id); return true; });
}
export function ComponentRevisionInventory({ targetRevision, sourceQueryKey, sourceRefreshing }: { targetRevision: number; sourceQueryKey: readonly unknown[]; sourceRefreshing: boolean }) {
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const qc = useQueryClient();
  const [search, setSearch] = useRouteSearchParams();
  const query = search.get("report_q") || "", debounced = useDebounced(query, 250);
  const cluster = search.get("report_cluster") || "", role = search.get("report_role") || "", status = search.get("report_status") || "";
  const sort = search.get("report_sort") || "component", order = search.get("report_order") || "asc", rawPage = search.get("report_page"), pageValue = Number(rawPage || "1");
  const validPage = Number.isSafeInteger(pageValue) && pageValue >= 1 && pageValue <= INVENTORY_MAX_PAGE && (rawPage === null || /^\d+$/.test(rawPage));
  const page = validPage ? pageValue - 1 : 0;
  const invalid = !validPage || ["q", "cluster", "role", "status", "sort", "order", "page"].some(field => search.getAll(`report_${field}`).length > 1) || role !== "" && !NV_COMPONENT_ROLES.some(value => value.id === role && role !== "all") || status !== "" && !statuses.includes(status) || !sorts.includes(sort) || !["asc", "desc"].includes(order);
  const request: ComponentsInventoryParams = { q: debounced.trim() || undefined, cluster_id: cluster || undefined, role: role || undefined, status: status || undefined, sort, order: order as "asc" | "desc", limit: 100, offset: page * 100 };
  const clusterQ = useQuery({ queryKey: ["effective-config-clusters", owner], enabled: !!owner, queryFn: () => clusters.list() });
  const clusterReady = !cluster || clusterQ.isSuccess && clusterQ.data.clusters.some(value => value.id === cluster);
  const sourceCurrent = () => { const state = qc.getQueryState<{ revision: number }>(sourceQueryKey); return !!owner && sourceQueryKey.includes(owner) && state?.status === "success" && state.data?.revision === targetRevision; };
  const sourceValid = useSyncExternalStore(notify => qc.getQueryCache().subscribe(notify), sourceCurrent);
  const key = ["components-inventory", "effective-config", owner, request];
  const q = useQuery({ queryKey: key, enabled: !!owner && sourceValid && clusterReady && !invalid && query === debounced, queryFn: async () => { const data = await componentsInventory.list(request); if (!responseMatches(data, request)) throw new Error("Component reports do not match this scope or page"); return data; } });
  const available = sourceValid && clusterReady && !invalid && query === debounced && q.isSuccess && responseMatches(q.data, request);
  const update = (changes: Record<string, string | null>, reset = true, replace = false) => setSearch(current => { const next = new URLSearchParams(current); for (const [key, value] of Object.entries(changes)) { if (!value) next.delete(`report_${key}`); else next.set(`report_${key}`, value); } if (reset) next.delete("report_page"); return next; }, { replace });
  const exportCurrent = () => { const source = qc.getQueryState(sourceQueryKey), state = qc.getQueryState<ComponentInventoryResponse>(key), registry = qc.getQueryState(["effective-config-clusters", owner]); return available && sourceCurrent() && source?.fetchStatus === "idle" && !source.isInvalidated && state?.status === "success" && state.fetchStatus === "idle" && !state.isInvalidated && state.data === q.data && responseMatches(state.data, request) && (!cluster || registry?.status === "success" && registry.fetchStatus === "idle" && !registry.isInvalidated); };
  const rows = available ? q.data!.components : [];
  const columns: Column<ComponentInstance>[] = [
    { id: "component", header: "Component", kind: "name", wrap: true, sort: () => 0, exportValue: item => `${item.display_name || item.component}; role=${item.role}; cluster=${item.cluster_name || item.cluster_id || "org"}`, cell: item => <><div className="font-medium">{item.display_name || item.component}</div><div className="text-xs text-muted-foreground">{item.role} · {item.cluster_name || item.cluster_id || "Organization"}</div></> },
    { id: "build", header: "Build", kind: "version", wrap: true, sort: () => 0, cell: item => [item.version, item.commit].filter(Boolean).join(" · ") || "Not reported" },
    { id: "runtime", header: "Uptime seconds", kind: "count", sort: () => 0, cell: item => item.uptime_seconds },
    { id: "restarts", header: "Restarts", kind: "count", sort: () => 0, cell: item => item.restart_count },
    { id: "status", header: "Health status", kind: "status", sort: () => 0, cell: item => item.status },
    { id: "hostname", header: "Host", kind: "name", wrap: true, sort: () => 0, cell: item => item.hostname },
    { id: "revision", header: "Reported revision", kind: "text", align: "right", size: 176, minSize: 152, maxSize: 200, exportValue: item => reportedRevision(item) ?? "", cell: item => reportedRevision(item) ?? "Unknown" },
    { id: "comparison", header: "Compared with target", kind: "status", size: 200, exportValue: item => statusFor(item, targetRevision), cell: item => <AppliedStatusPill status={statusFor(item, targetRevision)} /> },
    { id: "heartbeat", header: "Last seen", kind: "date", sort: () => 0, size: 224, minSize: 208, maxSize: 240, exportValue: item => item.last_seen_at, cell: item => new Date(item.last_seen_at).toLocaleString() },
  ];
  return <section className="space-y-3" data-testid="effective-config-applied-revisions">
    <h2 className="text-sm font-semibold">Reported system config revision</h2>
    <div className="flex flex-wrap gap-2"><input aria-label="Search component revision reports" value={query} onChange={event => update({ q: event.target.value }, true, true)} placeholder="Component, host or build" className="min-w-0 basis-64 flex-1 rounded border border-border bg-card p-2 text-sm" /><select aria-label="Report cluster" value={cluster} onChange={event => update({ cluster: event.target.value })} className="rounded border border-border bg-card p-2 text-sm"><option value="">All organization clusters</option>{cluster && !clusterReady && <option value={cluster}>Unavailable cluster: {cluster}</option>}{clusterQ.data?.clusters.map(value => <option key={value.id} value={value.id}>{value.name}</option>)}</select><select aria-label="Report role" value={role} onChange={event => update({ role: event.target.value })} className="rounded border border-border bg-card p-2 text-sm"><option value="">All roles</option>{NV_COMPONENT_ROLES.filter(value => value.id !== "all").map(value => <option key={value.id} value={value.id}>{value.label}</option>)}</select><select aria-label="Report health status" value={status} onChange={event => update({ status: event.target.value })} className="rounded border border-border bg-card p-2 text-sm"><option value="">All health statuses</option>{statuses.map(value => <option key={value}>{value}</option>)}</select><Button disabled={q.isFetching || sourceRefreshing || invalid || !owner || !sourceValid || !clusterReady} onClick={() => { if (!invalid && sourceCurrent() && clusterReady && !sourceRefreshing) void q.refetch(); }}>Refresh inventory</Button></div>
    {clusterQ.isError && <ErrorState title="Cluster filter choices are unavailable." action={<Button onClick={() => void clusterQ.refetch()}>Retry report clusters</Button>} />}
    {invalid ? <ErrorState title="Choose supported report filters, sorting and page." action={<Button onClick={() => update({ q: null, cluster: null, role: null, status: null, sort: null, order: null, page: null })}>Reset report filters and page</Button>} /> : !clusterReady ? <ErrorState title="The requested report cluster is unavailable in this organization." action={<Button onClick={() => void clusterQ.refetch()}>Retry report clusters</Button>} /> : !sourceValid ? <ErrorState title="Current system configuration is unavailable; refresh the configuration before reviewing reports." action={<Button disabled={!sourceQueryKey.includes(owner)} onClick={() => { if (sourceQueryKey.includes(owner)) void qc.invalidateQueries({ queryKey: sourceQueryKey, exact: true }); }}>Retry configuration</Button>} /> : q.isError ? <ErrorState title="Component inventory unavailable" action={<Button disabled={!sourceCurrent() || !clusterReady || invalid || query !== debounced || sourceRefreshing} onClick={() => { if (sourceCurrent() && clusterReady && !invalid && query === debounced && !sourceRefreshing) void q.refetch(); }}>Retry inventory</Button>} /> : !available ? <LoadingState label="Loading component reports…" /> : <>
      <p className="text-xs text-muted-foreground">{q.data!.total!.toLocaleString()} matching component records · {rows.filter(item => reportedRevision(item) !== null).length}/{rows.length} on this page report a revision · target revision {targetRevision}</p>
      <Collapse label="Revision evidence details"><p className="text-xs text-muted-foreground">{cluster ? "Selected-cluster" : "Organization-wide"} heartbeats retained in the current 24-hour inventory source. Full source: {q.data!.summary.total_instances} instances, {q.data!.summary.healthy} healthy. Only explicit system_config_revision metadata is revision evidence. Health and comparison with the displayed target are different statuses. Matching CSV includes reported revisions across pages; the target comparison in page CSV uses revision {targetRevision}. Reports do not establish fleet-wide adoption.</p></Collapse>
      {(q.isFetching || sourceRefreshing) && <p role="status" className="text-xs text-muted-foreground">Refreshing component reports…</p>}
      <ScanInventoryExport context={JSON.stringify([key, query, targetRevision, sourceQueryKey])} isCurrent={exportCurrent} disabled={!exportCurrent() || sourceRefreshing} download={shouldDownload => { if (!exportCurrent()) return Promise.reject(new Error("Refresh reports before exporting")); return componentsInventory.exportCSV(request, () => shouldDownload() && exportCurrent()); }} />
      <DataTable rows={rows} columns={columns} canExport={exportCurrent} rowKey={item => item.id} preferencesKey="effective-config-reports" defaultHiddenColumnIds={["build", "runtime", "restarts", "status"]} testId="effective-config-reports-table" pagination={false} manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => update({ sort: next?.id || null, order: next?.dir || null })} exportFileName={`effective-config-reports-target-${targetRevision}-page.csv`} exportLabel="Export this page CSV" emptyState={<p className="p-4 text-sm text-muted-foreground">No components match these filters or page in the 24-hour source. This is not proof of fleet-wide adoption.</p>} />
      {page > 0 && !rows.length && <Button onClick={() => update({ page: null }, false)}>First page</Button>}<Pager page={page} pageSize={100} total={q.data!.total} rowsOnPage={rows.length} onPage={value => update({ page: value ? String(value + 1) : null }, false)} />
    </>}
  </section>;
}
