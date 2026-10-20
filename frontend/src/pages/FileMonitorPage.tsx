import { useEffect, useRef, useState } from "react";
import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { PenLine, Plus, Trash2 } from "lucide-react";
import { fileProfiles, type FileProfileDetail, type FileProfileRule, type FileProfileInventoryRow, type FileProfileInventoryResponse, type FileProfileInventoryParams } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { sentenceValue } from "@/components/ui/status-pill";
import { usePlatformComponentVisibility } from "@/hooks/usePlatformComponentVisibility";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { InventorySearch, ScanInventoryContinuation, scanInventoryResponseValid, useInventoryRoute, useScanInventoryExport } from "./inventory-workspace";
import { Select } from "@/components/ui/form";

const SORTS = ["workload", "namespace", "mode", "rules", "paths", "alerts", "blocks", "last_observed"];
const SUMMARY = ["learn", "monitor", "enforce", "rules", "alerts", "blocks", "retained_events", "ambiguous"];
const revision = (rule: FileProfileRule) => JSON.stringify(rule);
function inventoryMatches(data: FileProfileInventoryResponse | undefined, request: FileProfileInventoryParams, org: string) {
  if(!data || !Array.isArray(data.profiles) || !data.profiles.every(p => p && typeof p === "object") || data.org_id !== org || data.cluster_id !== request.cluster_id || data.source !== "retained_file_events" || data.source_complete !== true || data.summary_scope !== "matching_shared_profiles" || !Array.isArray(data.namespaces) || !data.namespaces.every(ns => typeof ns === "string") || !data.filters) return false;
  const expected = { q: request.q ?? "", namespace: request.namespace ?? "", mode: request.mode ?? "", platform_role: request.platform_role ?? "", hide_platform: request.hide_platform ?? false };
  if(Object.entries(expected).some(([key, value]) => data.filters[key as keyof typeof expected] !== value) || !scanInventoryResponseValid(data, data.profiles.length, request.offset!, request.sort!, request.order!, SUMMARY)) return false;
  return new Set(data.profiles.map(p => p.row_id)).size === data.profiles.length && data.profiles.every(p => {
    let id: unknown; try { id = JSON.parse(p.row_id); } catch { return false; }
    return JSON.stringify(id) === JSON.stringify([request.cluster_id, p.workload_id]) && p.cluster_id === request.cluster_id && typeof p.workload_id === "string" && ["learn", "monitor", "enforce"].includes(p.mode) && typeof p.namespace === "string" && typeof p.name === "string" && ["", "core"].includes(p.platform_role) && Number.isSafeInteger(p.owner_count) && p.owner_count >= 0 && p.owner_ambiguous === (p.owner_count > 1) && [p.rule_count, p.learned_paths_count, p.sensitive_path_count, p.monitored_alerts_24h, p.enforced_blocks_24h, p.retained_events].every(n => Number.isSafeInteger(n) && n >= 0) && (!request.hide_platform || p.platform_role !== "core");
  });
}
export function FileMonitorPage() {
  const { clusterId, isLoading: clusterLoading, cluster, error: clusterError } = useCluster();
  const qc = useQueryClient(), navigate = useNavigate(), identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const route = useInventoryRoute(INVENTORY_MAX_PAGE), { params } = route;
  const [rawTab, setTab] = useTabParam("tab", params.has("workload") ? "rules" : "workloads"), tab = rawTab === "rules" ? "rules" : "workloads";
  const clusterFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true }) + useIsFetching({ queryKey: ["clusters"], exact: true });
  const scoped = !!owner && !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError && !clusterFetching && clusterCacheReady(qc, clusterId);
  const [platformHidden] = usePlatformComponentVisibility();
  const sort = params.get("sort") ?? "workload", order = params.get("order") ?? "asc", mode = params.get("mode") ?? "", namespace = (params.get("namespace") ?? "").trim(), platform = params.get("platform_role") ?? "", hide = params.get("hide_platform") ?? String(platformHidden);
  const validFilters = SORTS.includes(sort) && ["asc", "desc"].includes(order) && ["", "learn", "monitor", "enforce"].includes(mode) && ["", "core", "unknown"].includes(platform) && ["true", "false"].includes(hide) && (!params.has("page") || /^\d+$/.test(params.get("page")!) && Number(params.get("page")) >= 1 && Number(params.get("page")) <= INVENTORY_MAX_PAGE);
  const request: FileProfileInventoryParams = { cluster_id: clusterId ?? "", q: route.debouncedQuery.trim(), namespace, mode: mode as FileProfileInventoryParams["mode"], platform_role: platform as FileProfileInventoryParams["platform_role"], hide_platform: hide === "true", sort, order: order as "asc" | "desc", limit: 100, offset: route.offset };
  const key = ["file-monitor-inventory", owner, request], context = JSON.stringify(key);
  const current = useRef({ context, scoped }); current.current = { context, scoped };
  const listQ = useQuery({ queryKey: key, enabled: scoped && validFilters && !route.debouncing, queryFn: async () => { const data = await fileProfiles.inventory(request); if(!inventoryMatches(data, request, identity!.org_id)) throw new Error("File profile scope or totals could not be confirmed"); return data; } });
  const available = scoped && validFilters && !route.debouncing && listQ.isSuccess && !listQ.isFetching && !qc.getQueryState(key)?.isInvalidated && inventoryMatches(listQ.data, request, identity?.org_id ?? "");
  const activeWorkload = params.get("workload"), detailKey = ["file-monitor-detail", clusterId, activeWorkload, owner];
  const detailQ = useQuery({ queryKey: detailKey, enabled: scoped && !!activeWorkload && tab === "rules", queryFn: async () => { const data = await fileProfiles.get(activeWorkload!, { cluster_id: clusterId }); if(data.workload_id !== activeWorkload || data.cluster_id !== clusterId || !Array.isArray(data.rules) || data.rules.some(r => !r.id || typeof r.updated_at !== "string")) throw new Error("Rule scope could not be confirmed"); return data; } });
  const detailReady = scoped && detailQ.isSuccess && !detailQ.isFetching && !qc.getQueryState(detailKey)?.isInvalidated && detailQ.data?.workload_id === activeWorkload && detailQ.data.cluster_id === clusterId;
  const [pendingDelete, setPendingDelete] = useState<{ workload: string; cluster: string; owner: string; rule: FileProfileRule; context: string } | null>(null);
  const mounted = useRef(false); useEffect(() => { mounted.current = true; return () => { mounted.current = false }; }, []);
  const detailContext = JSON.stringify([owner, clusterId, activeWorkload, tab]), currentDetail = useRef(detailContext); currentDetail.current = detailContext;
  const recheckInventory = () => { const state = qc.getQueryState<FileProfileInventoryResponse>(key); if(!mounted.current || current.current.context !== context || !current.current.scoped || !clusterCacheReady(qc, request.cluster_id) || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || !inventoryMatches(state.data, request, identity?.org_id ?? "")) throw new Error("Refresh the inventory before exporting"); };
  const delMut = useMutation({
mutationFn: async (target: NonNullable<typeof pendingDelete>) => {
      const state = qc.getQueryState<FileProfileDetail>(detailKey), rule = state?.data?.rules.find(r => r.id === target.rule.id);
      if(!mounted.current || currentDetail.current !== target.context || !scoped || target.owner !== owner || !clusterCacheReady(qc, target.cluster) || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || state.data?.cluster_id !== target.cluster || state.data.workload_id !== target.workload || !rule || revision(rule) !== revision(target.rule) || !rule.updated_at || Number.isNaN(Date.parse(rule.updated_at))) throw new Error("The reviewed rule changed or is unavailable. Refresh and confirm it again.");
      const result = await fileProfiles.deleteRule(target.workload, rule.id, { reason: "removed via file-monitor console", expected_updated_at: rule.updated_at }, { cluster_id: target.cluster });
      if(result.deleted !== rule.id) throw new Error("The response did not confirm the reviewed rule removal. Refresh before continuing."); return result;
    }, onSuccess: (_, target) => { void qc.invalidateQueries({ queryKey: ["file-monitor-detail", target.cluster, target.workload] }); void qc.invalidateQueries({ queryKey: ["file-monitor-inventory", target.owner] }); void qc.invalidateQueries({ queryKey: ["file-monitor-profiles", target.cluster] }); if(currentDetail.current === target.context) setPendingDelete(null); }
});
  const backTo = `/clusters/${clusterId}/file-monitor`, gotoForm = (segment: string) => void navigate({ href: `${backTo}/${encodeURIComponent(segment)}?workload=${encodeURIComponent(activeWorkload!)}` });
  const select = (workload: string) => { setPendingDelete(null); route.update({ workload, tab: "rules" }, false); };
  const columns: Column<FileProfileInventoryRow>[] = [
    { id: "workload", header: "Workload profile", kind: "name", wrap: true, code: true, hideable: false, sort: () => 0, exportValue: p => p.workload_id, cell: p => <button className="app-table-entity-link text-left" onClick={() => select(p.workload_id)}>{p.workload_id}</button> },
    { id: "namespace", header: "Namespace", kind: "text", sort: () => 0, cell: p => p.namespace },
    { id: "mode", header: "Configured mode", kind: "status", sort: () => 0, cell: p => sentenceValue(p.mode), exportValue: p => p.mode },
    { id: "rules", header: "Rules", kind: "count", sort: () => 0, cell: p => p.rule_count },
    { id: "paths", header: "Path/process pairs", kind: "count", sort: () => 0, cell: p => p.learned_paths_count },
    { id: "alerts", header: "Alerts (24h)", kind: "count", sort: () => 0, cell: p => p.monitored_alerts_24h },
    { id: "blocks", header: "Blocks (24h)", kind: "count", sort: () => 0, cell: p => p.enforced_blocks_24h },
    { id: "platform_role", header: "Platform role", kind: "text", cell: p => p.platform_role || "Not classified", exportValue: p => p.platform_role },
    { id: "owners", header: "Workload owners", kind: "text", wrap: true, cell: p => p.owner_ambiguous ? `Shared by ${p.owner_count} workload kinds; pod evidence excluded` : p.owner_count === 0 ? "No observed owner" : String(p.owner_count), exportValue: p => p.owner_count },
    { id: "last_observed", header: "Last file event", kind: "date", sort: () => 0, cell: p => p.last_observed_at ? new Date(p.last_observed_at).toLocaleString() : "Not reported", exportValue: p => p.last_observed_at },
  ];
  const ruleColumns: Column<FileProfileRule>[] = [
    { id: "filter", header: "Path filter", kind: "name", code: true, wrap: true, hideable: false, sort: (a, b) => a.filter.localeCompare(b.filter), cell: r => r.filter },
    { id: "behavior", header: "Behavior", kind: "status", cell: r => r.behavior === "block_access" ? "Block access" : "Observe changes", exportValue: r => r.behavior },
    { id: "enabled", header: "Rule status", kind: "status", cell: r => r.enabled ? "Enabled" : "Disabled", exportValue: r => r.enabled },
    { id: "recursive", header: "Subdirectories", kind: "status", cell: r => r.recursive ? "Included" : "Excluded", exportValue: r => r.recursive },
    { id: "actions", header: "Actions", kind: "actions", hideable: false, exportable: false, cell: r => <div className="flex justify-end gap-2"><Button variant="ghost" size="sm" disabled={!detailReady || delMut.isPending} aria-label={`Edit rule ${r.filter}`} onClick={() => gotoForm(r.id)}><PenLine className="h-4 w-4" /></Button><Button variant="ghost" size="sm" disabled={!detailReady || delMut.isPending} aria-label={`Delete rule ${r.filter}`} onClick={() => { delMut.reset(); setPendingDelete({ workload: activeWorkload!, cluster: clusterId!, owner, rule: r, context: detailContext }); }}><Trash2 className="h-4 w-4" /></Button></div> },
  ];
  const totals = available ? listQ.data!.summary : undefined;
  const matching = useScanInventoryExport({ context, disabled: !available, download: shouldDownload => { recheckInventory(); return fileProfiles.inventoryCSV(request, () => { if (!shouldDownload()) return false; recheckInventory(); return true; }); } });
  const workloadToolbar = <>
    <InventorySearch value={route.query} onChange={route.setQuery} label="Search workloads" />
    <Select aria-label="Namespace" className="h-9 max-w-48" value={namespace} onChange={e => route.update({ namespace: e.target.value })}><option value="">Any namespace</option>{listQ.data?.namespaces.map(ns => <option key={ns}>{ns}</option>)}{namespace && !listQ.data?.namespaces.includes(namespace) && <option>{namespace}</option>}</Select>
    <Select aria-label="Profile mode" className="h-9" value={mode} onChange={e => route.update({ mode: e.target.value })}><option value="">Any mode</option>{["learn", "monitor", "enforce"].map(m => <option key={m} value={m}>{sentenceValue(m)}</option>)}</Select>
    <Select aria-label="Platform role" className="h-9" value={platform} onChange={e => route.update({ platform_role: e.target.value })}><option value="">Any platform role</option><option value="core">Platform core</option><option value="unknown">Not classified</option></Select>
    {(route.query || namespace || mode || platform) && <Button variant="ghost" onClick={() => route.update({ q: null, namespace: null, mode: null, platform_role: null, hide_platform: null, sort: null, order: null, page: null })}>Reset filters</Button>}
  </>;
  const refresh = () => { void listQ.refetch(); if(activeWorkload) void detailQ.refetch(); };
  return <div className="space-y-5" data-testid="file-monitor-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title="File monitor" description="Workload file profiles and configured path rules." actions={<><Button disabled={!scoped || listQ.isFetching || detailQ.isFetching} onClick={refresh}>Refresh</Button>{tab === "rules" && <Button variant="primary" disabled={!detailReady} onClick={() => gotoForm("new")} data-testid="file-monitor-add-open"><Plus className="h-4 w-4" /> Add rule</Button>}</>} />
    <VerdictBanner status={available ? "info" : "degraded"} title={available ? `${listQ.data!.total.toLocaleString()} matching file profiles` : "File profile evidence unavailable"} numbers={[{ label: "rules", value: totals?.rules ?? "—", title: "Configured rules" }, { label: "alerts (24h)", value: totals?.alerts ?? "—", tone: (totals?.alerts ?? 0) > 0 ? "warning" : "default" }, { label: "blocks (24h)", value: totals?.blocks ?? "—" }]}
      detail={<div className="space-y-1"><p data-testid="file-monitor-summary">Matching profiles {totals?.total ?? "—"} · configured rules {totals?.rules ?? "—"} · alerts, retained 24h {totals?.alerts ?? "—"} · blocks, retained 24h {totals?.blocks ?? "—"}</p><p>Profiles configure behavior; monitoring and blocking require agent evidence. Activity counts cover all retained canonical and unambiguous owned-pod file events; shared ambiguous owners exclude pod evidence. Workload kinds sharing namespace/name share one profile; zero owners means no current workload was observed. Full matching CSV is capped at 100,000 profiles.</p></div>} />
    {!scoped ? clusterLoading || clusterFetching ? <LoadingState label="Resolving cluster…" /> : <ErrorState title="The selected cluster and operator could not be resolved." action={<Button onClick={() => { void qc.invalidateQueries({ queryKey: ["clusters"] }); void qc.invalidateQueries({ queryKey: ["cluster", clusterId] }); }}>Retry cluster</Button>} /> : <>
      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "workloads", label: "Workloads", content: !validFilters ? <ErrorState title="Choose supported file profile filters and page values." /> : !available ? listQ.isFetching || listQ.isPending || route.debouncing ? <LoadingState label="Loading file profiles…" /> : <ErrorState title="Could not load or refresh file profiles for this cluster." action={<Button onClick={() => void listQ.refetch()}>Retry</Button>} /> : <div className="space-y-3">{matching.status}<DataTable toolbar={workloadToolbar} exportOptions={[matching.option]} rows={listQ.data!.profiles} columns={columns} rowKey={p => p.row_id} preferencesKey="file-monitor-workloads" pagination={false} manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })} defaultHiddenColumnIds={["platform_role", "owners", "last_observed"]} exportFileName="file-monitor-profiles-page.csv" exportLabel="This page" testId="file-monitor-workloads-table" emptyState={<EmptyState title="No file profiles match these filters or page" />} /><ScanInventoryContinuation page={route.page} rows={listQ.data!.profiles.length} hasMore={listQ.data!.has_more} matching={listQ.data!.total} total={listQ.data!.total} onPage={route.setPage} /></div> },
        { value: "rules", label: "Rules", content: !activeWorkload ? <EmptyState title="Choose an exact workload profile from Workloads" /> : !detailReady ? detailQ.isFetching || detailQ.isPending ? <LoadingState label="Loading rules…" /> : <ErrorState title="Could not load or refresh rules for this workload." action={<Button onClick={() => void detailQ.refetch()}>Retry</Button>} /> : <div className="space-y-4"><p className="font-mono text-sm">{activeWorkload}</p><DataTable rows={detailQ.data!.rules} columns={ruleColumns} rowKey={r => r.id} preferencesKey="file-monitor-rules" exportFileName="file-monitor-rules.csv" testId="file-monitor-rules-table" emptyState={<EmptyState title="No custom rules" hint="Add a rule to watch a path on this workload." />} />{pendingDelete?.context === detailContext && <div role="alert" className="space-y-3 rounded border border-border p-4"><p>Delete the reviewed rule for <span className="font-mono">{pendingDelete.rule.filter}</span>? This removes its configured file monitoring behavior.</p><Button disabled={!detailReady || delMut.isPending} onClick={() => delMut.mutate(pendingDelete)}>{delMut.isPending ? "Deleting…" : "Delete rule"}</Button><Button disabled={delMut.isPending} onClick={() => setPendingDelete(null)}>Cancel</Button></div>}{delMut.isError && delMut.variables?.context === detailContext && <ErrorState title="Could not delete the reviewed rule. Refresh and confirm it again." />}</div> },
      ]} />
    </>}
  </div>;
}
