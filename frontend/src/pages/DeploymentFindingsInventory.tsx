import { findingHref } from "@/lib/finding-instance";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { deployments, type DeploymentDetail, type DeploymentFindingInventoryRow, type DeploymentFindingsParams, type DeploymentFindingsResponse, type Lifecycle, type Severity } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useDebounced } from "@/hooks/useDebounced";
import { useRouteSearchParams } from "@/lib/route-search";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { Drawer } from "@/components/ui/drawer";
import { Pager } from "@/components/ui/pager";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LifecycleBadge } from "@/components/ui/status-pill";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ScanInventoryExport } from "./inventory-workspace";
import { deploymentFindingsMatch, deploymentFindingLifecycles, deploymentFindingSeverities, deploymentFindingSorts } from "./DeploymentFindingsInventory.validation";
import { Select } from "@/components/ui/form";

type Props = { deployment: DeploymentDetail; sourceQueryKey: QueryKey; sourceKind: "detail" | "risk"; sourceReady: boolean };
const fields = ["q", "severity", "lifecycle", "fixable", "sort", "order", "page"];
export function DeploymentFindingsInventory({ deployment, sourceQueryKey, sourceKind, sourceReady }: Props) {
  const qc = useQueryClient();
  const cluster = useCluster();
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const [params, setParams] = useRouteSearchParams();
  const search = params.get("findings_q") ?? "";
  const debounced = useDebounced(search, 250);
  const rawSeverity = (params.get("findings_severity") ?? "").trim();
  const severity = rawSeverity === "all" ? "" : rawSeverity;
  const lifecycle = (params.get("findings_lifecycle") ?? "").trim() || "open";
  const rawFixable = (params.get("findings_fixable") ?? "").trim();
  const fixable = rawFixable === "all" ? "" : rawFixable;
  const sort = params.get("findings_sort") ?? "risk", order = params.get("findings_order") ?? "desc";
  const rawPage = params.get("findings_page"), pageValue = Number(rawPage ?? "1");
  const validPage = Number.isSafeInteger(pageValue) && pageValue >= 1 && pageValue <= INVENTORY_MAX_PAGE && (rawPage === null || /^\d+$/.test(rawPage));
  const page = validPage ? pageValue - 1 : 0;
  const invalid = !validPage || fields.some(field => params.getAll(`findings_${field}`).length > 1) || !deploymentFindingSorts.includes(sort) || !["asc", "desc"].includes(order) || !["all", ...deploymentFindingLifecycles].includes(lifecycle) || severity !== "" && !deploymentFindingSeverities.includes(severity) || !["", "true", "false"].includes(fixable);
  const request: DeploymentFindingsParams = { cluster_id: deployment.cluster_id ?? "", q: debounced.trim().toLowerCase() || undefined, lifecycle: lifecycle as Lifecycle | "all", severity: severity ? severity as Severity | "unknown" : undefined, fixable: fixable === "" ? undefined : fixable === "true", sort, order: order as "asc" | "desc", limit: 100, offset: page * 100 };
  const workload = `${deployment.namespace}/${deployment.name}`;
  const key = ["deployment-findings-inventory", owner, deployment.cluster_id, deployment.id, workload, request];
  const sourceCurrent = () => {
    const state = qc.getQueryState<DeploymentDetail | { type: string; data: DeploymentDetail }>(sourceQueryKey);
    if (!state || state.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || !state.data || typeof state.data !== "object" || Array.isArray(state.data)) return false;
    const value = sourceKind === "risk" && state.data && "type" in state.data && state.data.type === "deployment" ? state.data.data : sourceKind === "detail" && state.data && "id" in state.data ? state.data : undefined;
    return value?.id === deployment.id && value.cluster_id === deployment.cluster_id && value.namespace === deployment.namespace && value.name === deployment.name && clusterCacheReady(qc, deployment.cluster_id ?? "");
  };
  const sourceFresh = useSyncExternalStore(notify => qc.getQueryCache().subscribe(notify), sourceCurrent);
  const scopeReady = sourceReady && sourceFresh && !!owner && !!deployment.cluster_id && cluster.clusterId === deployment.cluster_id && cluster.cluster?.id === deployment.cluster_id && !cluster.isLoading && !cluster.error;
  const enabled = scopeReady && !invalid && search === debounced;
  const q = useQuery({ queryKey: key, enabled, queryFn: async () => { const data = await deployments.findings(deployment.id, request); if (!deploymentFindingsMatch(data, deployment.id, workload, request)) throw new Error("Deployment finding response does not match this scope or page"); return data; } });
  const inventoryFresh = useSyncExternalStore(notify => qc.getQueryCache().subscribe(notify), () => !qc.getQueryState(key)?.isInvalidated);
  const badResponse = q.isSuccess && !q.isFetching && !deploymentFindingsMatch(q.data, deployment.id, workload, request);
  const available = enabled && inventoryFresh && q.isSuccess && !q.isFetching && !badResponse;
  const data = available ? q.data : undefined;
  const context = JSON.stringify([key, search, sourceQueryKey, sourceKind]);
  const [selected, setSelected] = useState<{ id: string; context: string } | null>(null);
  const selectedRow = data && selected?.context === context ? data.items.find(row => row.row_id === selected.id) : undefined;
  useEffect(() => { if (selected && (!available || selected.context !== context || !selectedRow)) setSelected(null); }, [available, context, selected, selectedRow]);
  const update = (changes: Record<string, string | null>, resetPage = true, replace = false) => setParams(current => {
    const next = new URLSearchParams(current);
    for (const [key, value] of Object.entries(changes)) { if (!value) next.delete(`findings_${key}`); else next.set(`findings_${key}`, value); }
    if (resetPage) next.delete("findings_page");
    return next;
  }, { replace });
  const exportCurrent = () => {
    const state = qc.getQueryState<DeploymentFindingsResponse>(key);
    if (!available || !sourceCurrent() || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || !deploymentFindingsMatch(state.data, deployment.id, workload, request)) return false;
    return true;
  };
  const download = (shouldDownload: () => boolean) => {
    if (!exportCurrent()) return Promise.reject(new Error("Refresh deployment findings before exporting"));
    return deployments.findingsCSV(deployment.id, request, () => shouldDownload() && exportCurrent());
  };
  const returnFocus = useRef<HTMLElement | null>(null);
  const closeRecord = () => { setSelected(null); window.requestAnimationFrame(() => { if (returnFocus.current?.isConnected) returnFocus.current.focus(); }); };
  const inspect = (row: DeploymentFindingInventoryRow, trigger?: HTMLElement) => {
    const state = qc.getQueryState<DeploymentFindingsResponse>(key);
    if (available && sourceCurrent() && state?.status === "success" && state.fetchStatus === "idle" && !state.isInvalidated && deploymentFindingsMatch(state.data, deployment.id, workload, request) && state.data.items.some(item => item.row_id === row.row_id)) { returnFocus.current = trigger ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null); setSelected({ id: row.row_id, context }); }
  };
  const columns: Column<DeploymentFindingInventoryRow>[] = [
    { id: "finding", header: "Finding", kind: "name", wrap: true, sort: () => 0, cell: row => <button className="text-left font-medium hover:underline" onClick={event => inspect(row, event.currentTarget)}>{row.title}</button>, exportValue: row => row.title },
    { id: "cve", header: "External ID", kind: "id", sort: () => 0, cell: row => /^CVE-\d{4}-\d{4,}$/.test(row.external_id) ? <a href={`/cve/${encodeURIComponent(row.external_id)}`} className="hover:underline">{row.external_id}</a> : row.external_id || "Not reported", exportValue: row => row.external_id },
    { id: "severity", header: "Severity", kind: "status", sort: () => 0, cell: row => row.severity === "unknown" ? <span className="text-xs">Unknown</span> : <SeverityBadge severity={row.severity} />, exportValue: row => row.severity },
    { id: "risk", header: "Risk", kind: "count", sort: () => 0, cell: row => row.risk_score, exportValue: row => row.risk_score },
    { id: "lifecycle", header: "Lifecycle", kind: "status", sort: () => 0, cell: row => <LifecycleBadge lifecycle={row.lifecycle} />, exportValue: row => row.lifecycle },
    { id: "kind", header: "Kind", kind: "status", sort: () => 0, cell: row => row.kind, exportValue: row => row.kind },
    { id: "package", header: "Package", kind: "text", wrap: true, sort: () => 0, cell: row => [row.package_name, row.package_version].filter(Boolean).join(" · ") || "Not reported", exportValue: row => `${row.package_name} ${row.package_version}`.trim() },
    { id: "fixed", header: "Fixed version", kind: "version", wrap: true, sort: () => 0, cell: row => row.fixed_version || "Not reported", exportValue: row => row.fixed_version },
    { id: "observed", header: "Last observed", kind: "date", sort: () => 0, cell: row => row.last_seen_at, exportValue: row => row.last_seen_at },
    { id: "first_seen", header: "First observed", kind: "date", sort: () => 0, cell: row => row.first_seen_at, exportValue: row => row.first_seen_at },
    { id: "row_id", header: "Physical record", kind: "id", wrap: true, cell: row => row.row_id, exportValue: row => row.row_id },
    { id: "source_cluster_id", header: "Source cluster", kind: "id", cell: row => row.source_cluster_id ?? "Not reported", exportValue: row => row.source_cluster_id ?? "" },
    { id: "target_cluster_id", header: "Target cluster override", kind: "id", cell: row => row.target_cluster_id ?? "None", exportValue: row => row.target_cluster_id ?? "" },
    { id: "effective_target_cluster_id", header: "Effective target cluster", kind: "id", cell: row => row.effective_target_cluster_id, exportValue: row => row.effective_target_cluster_id },
    { id: "target_ref", header: "Workload target", kind: "text", wrap: true, cell: row => row.target_ref, exportValue: row => row.target_ref },
    { id: "attribution", header: "Attribution", kind: "status", cell: row => row.attribution, exportValue: row => row.attribution },
    { id: "owners", header: "Inventory owners", kind: "count", cell: row => row.owner_count, exportValue: row => row.owner_count },
    { id: "ambiguous", header: "Ambiguous owners", kind: "status", cell: row => row.owner_ambiguous ? "Yes" : "No", exportValue: row => row.owner_ambiguous },
    { id: "platform_role", header: "Platform role", kind: "status", cell: row => row.platform_role || "Unclassified", exportValue: row => row.platform_role },
  ];
  return <section className="space-y-3" data-testid="deployment-findings-inventory">
    <h2 className="text-sm font-semibold">Workload findings</h2>
    <div className="flex flex-wrap gap-2">
      <input aria-label="Search deployment findings" placeholder="Search workload findings" className="min-w-0 basis-64 flex-1 rounded border border-border bg-background px-3 py-2 text-sm" value={search} onChange={e => update({ q: e.target.value }, true, true)} />
      <Select aria-label="Deployment finding lifecycle" value={lifecycle} onChange={e => update({ lifecycle: e.target.value })} className="rounded border border-border bg-background p-2 text-sm"><option value="all">All lifecycles</option>{deploymentFindingLifecycles.map(value => <option key={value}>{value}</option>)}</Select>
      <Select aria-label="Deployment finding severity" value={severity} onChange={e => update({ severity: e.target.value })} className="rounded border border-border bg-background p-2 text-sm"><option value="">All severities</option>{deploymentFindingSeverities.map(value => <option key={value}>{value}</option>)}</Select>
      <Select aria-label="Deployment finding fixability" value={fixable} onChange={e => update({ fixable: e.target.value })} className="rounded border border-border bg-background p-2 text-sm"><option value="">Any fixability</option><option value="true">Fix available</option><option value="false">No fix reported</option></Select>
      <Button variant="outline" onClick={() => update({ q: null, severity: null, lifecycle: null, fixable: null, sort: null, order: null })}>Reset finding filters</Button>
    </div>
    {invalid ? <ErrorState title="Choose supported deployment finding filters, sorting and page." /> : !scopeReady ? <LoadingState label="Resolve and refresh this exact deployment before loading findings…" /> : q.isError || badResponse ? <ErrorState title="Deployment workload findings are unavailable or could not be refreshed." action={<Button onClick={() => void q.refetch()}>Retry findings</Button>} /> : !data ? <LoadingState label="Loading deployment workload findings…" /> : <>
      <div className="flex flex-wrap items-center justify-between gap-2"><VerdictBanner status="info" title={`${data.total.toLocaleString()} matching workload finding records · ${data.items.length} on page ${page + 1}`} detail={<><p>Filters and totals cover direct workload findings for this exact deployment’s effective target cluster, including uniquely owned pod identities. These records are separate from canonical image vulnerability totals reported by deployment inventory. All retained matching records are included; this does not prove complete collection.</p><p>{data.summary.critical.toLocaleString()} critical · {data.summary.high.toLocaleString()} high · {data.summary.fixable.toLocaleString()} fixable · {data.summary.canonical.toLocaleString()} canonical-workload · {data.summary.pod.toLocaleString()} pod-attributed · {data.summary.ambiguous_owners.toLocaleString()} with ambiguous inventory owners. Lifecycle scope: {lifecycle}; {data.summary.other_lifecycle.toLocaleString()} records have other retained status values.</p><p>Matching CSV exports up to 100,000 records across pages; page CSV exports selected visible columns. Inspect each retained observation here. Open the finding to review its history or change its status.</p></>} /><ScanInventoryExport context={context} disabled={!available} download={download} /></div>
      <DataTable rows={data.items} columns={columns} rowKey={row => row.row_id} onRowClick={row => inspect(row)} selected={new Set(selectedRow ? [selectedRow.row_id] : [])} preferencesKey="deployment-workload-findings" defaultHiddenColumnIds={["cve", "kind", "package", "fixed", "observed", "first_seen", "row_id", "source_cluster_id", "target_cluster_id", "effective_target_cluster_id", "target_ref", "attribution", "owners", "ambiguous", "platform_role"]} testId="deployment-findings-table" pagination={false} manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => update({ sort: next?.id ?? null, order: next?.dir ?? null })} exportFileName={`deployment-${deployment.id}-findings-page`} exportLabel="Export this page CSV" emptyState={<p className="p-6 text-sm text-muted-foreground">No workload findings match these filters or page.</p>} />
      {data.items.length === 0 && page > 0 && <Button onClick={() => update({ page: null }, false)}>First page</Button>}
      <Pager page={page} pageSize={100} total={data.total} rowsOnPage={data.items.length} onPage={next => update({ page: next === 0 ? null : String(next + 1) }, false)} />
    </>}
    <Drawer open={!!selectedRow} onOpenChange={open => { if (!open) closeRecord(); }} title={selectedRow?.title} description="Retained workload finding observation · read-only">
      {selectedRow && <div className="space-y-4" data-testid="deployment-finding-record">
        <dl className="space-y-3 text-sm">{[
          ["Severity", selectedRow.severity], ["Lifecycle", selectedRow.lifecycle], ["Reported risk", selectedRow.risk_score], ["Package", selectedRow.package_name || "Not reported"], ["Package version", selectedRow.package_version || "Not reported"], ["Fixed version", selectedRow.fixed_version || "Not reported"], ["Fix available", selectedRow.fixable ? "Yes" : "No"], ["Workload target", selectedRow.target_ref], ["Attribution", selectedRow.attribution === "pod" ? "Exact owned pod" : "Canonical workload name"], ["Inventory owners", `${selectedRow.owner_count}${selectedRow.owner_ambiguous ? " (ambiguous)" : ""}`], ["Platform role", selectedRow.platform_role || "Unclassified"], ["Kind", selectedRow.kind], ["External ID", selectedRow.external_id || "Not reported"],
        ].map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="break-all">{value}</dd></div>)}</dl>
        {selectedRow.source_cluster_id !== selectedRow.effective_target_cluster_id && <p className="text-sm text-muted-foreground">{selectedRow.source_cluster_id ? "Reported from another cluster; this observation targets the selected deployment." : "Source cluster is not reported; this observation targets the selected deployment."}</p>}
        <Collapse label="Source details"><dl className="space-y-3 text-sm">{[
          ["Physical record", selectedRow.row_id], ["Finding UUID", selectedRow.id], ["First observed", selectedRow.first_seen_at], ["Last observed", selectedRow.last_seen_at], ["Source cluster", selectedRow.source_cluster_id ?? "Not reported"], ["Target cluster override", selectedRow.target_cluster_id ?? "None"], ["Effective target cluster", selectedRow.effective_target_cluster_id],
        ].map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="break-all">{value}</dd></div>)}</dl></Collapse>
        <a href={findingHref(selectedRow, selectedRow.effective_target_cluster_id)} className="inline-flex rounded-md border border-border px-3 py-2 text-sm hover:bg-accent" data-testid="deployment-finding-open">Open finding</a>
        <p className="text-xs text-muted-foreground">Open the finding to review its history or change its status.</p>
      </div>}
    </Drawer>
  </section>;
}
