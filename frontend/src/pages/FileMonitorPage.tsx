import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Edit3, FileText, FolderTree, ListChecks, Plus, RefreshCw, Trash2 } from "lucide-react";
import { fileProfiles, type FileProfileRule, type FileProfileSummary } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Tabs, useTabParam } from "@/components/ui/tabs";

export function FileMonitorPage() {
  const { clusterId, isLoading: clusterLoading, cluster } = useCluster();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useRouteSearchParams();
  const [rawTab, setTab] = useTabParam("tab", "rules");
  const tab = rawTab === "workloads" ? "workloads" : "rules";
  const [pendingDelete, setPendingDelete] = useState<{ workload: string; cluster: string; rule: FileProfileRule } | null>(null);
  const scoped = !!clusterId && !!cluster && !clusterLoading;
  const listQ = useQuery({
    queryKey: ["file-monitor-profiles", clusterId],
    queryFn: async () => {
      const data = await fileProfiles.list({ cluster_id: clusterId });
      if (data.profiles.some((p) => p.cluster_id && p.cluster_id !== clusterId)) throw new Error("Scope mismatch");
      return data;
    },
    enabled: scoped,
  });
  const profiles = useMemo(() => listQ.data?.profiles ?? [], [listQ.data]);
  const selected = params.get("workload");
  const activeWorkload = selected ?? profiles[0]?.workload_id ?? null;
  const activeProfile = profiles.find((p) => p.workload_id === activeWorkload);
  const detailQ = useQuery({
    queryKey: ["file-monitor-detail", clusterId, activeWorkload],
    queryFn: async () => {
      const data = await fileProfiles.get(activeWorkload!, { cluster_id: clusterId });
      if (data.workload_id !== activeWorkload || (data.cluster_id && data.cluster_id !== clusterId)) throw new Error("Scope mismatch");
      return data;
    },
    enabled: scoped && !!activeProfile,
  });
  const rules = detailQ.data?.rules ?? [];
  const canAuthor = scoped && !!activeProfile && detailQ.isSuccess && !listQ.isError && !detailQ.isFetching;
  const backTo = `/clusters/${clusterId}/file-monitor`;
  const selectWorkload = (workload: string) => {
    setPendingDelete(null);
    setParams((current) => { current.set("workload", workload); return current; });
  };
  const gotoForm = (segment: string) => void navigate({ href: `${backTo}/${encodeURIComponent(segment)}?workload=${encodeURIComponent(activeWorkload!)}` });
  const delMut = useMutation({
    mutationFn: ({ workload, ruleId, targetCluster }: { workload: string; ruleId: string; targetCluster: string }) =>
      fileProfiles.deleteRule(workload, ruleId, { reason: "removed via file-monitor console" }, { cluster_id: targetCluster }),
    onSuccess: (_, target) => {
      setPendingDelete((current) => current?.cluster === target.targetCluster && current.workload === target.workload ? null : current);
      void qc.invalidateQueries({ queryKey: ["file-monitor-detail", target.targetCluster, target.workload] });
      void qc.invalidateQueries({ queryKey: ["file-monitor-profiles", target.targetCluster] });
    },
  });
  const columns: Column<FileProfileRule>[] = [
    { id: "filter", header: "Path filter", kind: "name", cell: (r) => r.filter, code: true, hideable: false, sort: (a, b) => a.filter.localeCompare(b.filter) },
    { id: "behavior", header: "Behavior", kind: "status", size: 152, minSize: 144, maxSize: 176, cell: (r) => r.behavior === "block_access" ? "Block access" : "Observe changes", exportValue: (r) => r.behavior, sort: (a, b) => a.behavior.localeCompare(b.behavior) },
    { id: "enabled", header: "Rule status", kind: "status", cell: (r) => r.enabled ? "Enabled" : "Disabled", exportValue: (r) => r.enabled, sort: (a, b) => Number(a.enabled) - Number(b.enabled) },
    { id: "recursive", header: "Subdirectories", kind: "status", cell: (r) => r.recursive ? "Included" : "Excluded", exportValue: (r) => r.recursive },
    { id: "actions", header: "Actions", kind: "actions", hideable: false, exportable: false, cell: (r) => <div className="flex justify-end gap-2">
      <Button variant="ghost" size="sm" disabled={!canAuthor || delMut.isPending} aria-label={`Edit rule ${r.filter}`} onClick={() => gotoForm(r.id)}><Edit3 className="h-4 w-4" /></Button>
      <Button variant="ghost" size="sm" disabled={!canAuthor || delMut.isPending} aria-label={`Delete rule ${r.filter}`} onClick={() => { delMut.reset(); setPendingDelete({ workload: activeWorkload!, cluster: clusterId!, rule: r }); }}><Trash2 className="h-4 w-4" /></Button>
    </div> },
  ];
  const workloadColumns: Column<FileProfileSummary>[] = [
    { id: "name", header: "Workload", kind: "name", hideable: false, cell: (p) => <button type="button" className="text-primary hover:underline" onClick={() => { setPendingDelete(null); setParams((current) => { current.set("workload", p.workload_id); current.delete("tab"); return current; }); }}>{p.name || p.workload_id}</button>, exportValue: (p) => p.name || p.workload_id, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "namespace", header: "Namespace", kind: "text", size: 176, minSize: 144, maxSize: 240, cell: (p) => p.namespace, sort: (a, b) => a.namespace.localeCompare(b.namespace) },
    { id: "mode", header: "Profile mode", kind: "status", cell: (p) => p.mode, sort: (a, b) => a.mode.localeCompare(b.mode) },
    { id: "rules", header: "Rules", kind: "count", cell: (p) => p.rule_count, numeric: true, sort: (a, b) => a.rule_count - b.rule_count },
  ];
  const refresh = () => { void listQ.refetch(); if (activeProfile) void detailQ.refetch(); };

  if (clusterLoading) return <LoadingState label="Loading cluster…" />;
  return <div className="space-y-6" data-testid="file-monitor-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title="File Monitor" description="Review file monitoring rules for each workload and choose which paths to watch for changes. New rules observe changes by default."
      actions={<><Button variant="secondary" disabled={!scoped || listQ.isFetching || detailQ.isFetching} onClick={refresh}><RefreshCw className="h-4 w-4" /> Refresh</Button><Button variant="primary" disabled={!canAuthor} onClick={() => gotoForm("new")} data-testid="file-monitor-add-open"><Plus className="h-4 w-4" /> Add rule</Button></>} />
    {!scoped ? <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." />
      : listQ.isPending ? <LoadingState label="Loading file profiles…" />
      : !listQ.data ? <ErrorState title="Could not load file profiles for this cluster." action={<Button onClick={() => void listQ.refetch()}>Retry</Button>} />
      : <>
        <VerdictBanner detailMode={listQ.isError ? "inline" : "disclosure"} status={listQ.isError ? "degraded" : "info"} title={listQ.isError ? "File profiles could not be refreshed" : profiles.length ? `${profiles.length} workloads have file profiles` : "No file profiles reported"} detail={listQ.isError ? "Showing the last loaded profiles. Refresh before changing rules." : "Profile configuration and recent activity are shown below. Enabled rules alone do not confirm that monitoring is active on a workload."} />
        <StatGrid>
          <StatCard label="Reported workloads" value={profiles.length} icon={<FolderTree className="h-4 w-4" />} />
          <StatCard label="Configured rules" value={profiles.reduce((n, p) => n + p.rule_count, 0)} icon={<ListChecks className="h-4 w-4" />} />
          <StatCard label="Alerts · last 24h" value={profiles.reduce((n, p) => n + p.monitored_alerts_24h, 0)} icon={<FileText className="h-4 w-4" />} />
          <StatCard label="Blocks · last 24h" value={profiles.reduce((n, p) => n + p.enforced_blocks_24h, 0)} />
        </StatGrid>
        {profiles.length === 0 ? <EmptyState title="No file profiles" hint="No workloads are reporting file monitoring yet." /> : <>
          <label className="block space-y-2 text-sm"><span className="font-medium">Selected workload</span><select className="h-10 w-full rounded-md border border-border bg-card px-3" value={activeWorkload ?? ""} onChange={(e) => selectWorkload(e.target.value)}>
            {selected && !activeProfile && <option value={selected}>Unavailable workload: {selected}</option>}
            {profiles.map((p) => <option key={p.workload_id} value={p.workload_id}>{p.namespace ? `${p.namespace} / ` : ""}{p.name || p.workload_id} · {p.mode}</option>)}
          </select></label>
          <Tabs value={tab} onValueChange={setTab} items={[
            { value: "rules", label: "Rules", content: !activeProfile ? <ErrorState title="This workload is not available in the selected cluster. Choose another workload." />
              : detailQ.isPending ? <LoadingState label="Loading rules…" />
              : !detailQ.data ? <ErrorState title="Could not load rules for this workload." action={<Button onClick={() => void detailQ.refetch()}>Retry</Button>} />
              : <div className="space-y-4">
                {detailQ.isError && <p role="alert" className="text-sm text-status-error">Could not refresh rules. Showing the last loaded rules; refresh before making changes.</p>}
                <DataTable rows={rules} columns={columns} rowKey={(r) => r.id} preferencesKey="file-monitor-rules" exportFileName="file-monitor-rules.csv" testId="file-monitor-rules-table" emptyState={<EmptyState title="No custom rules" hint="Add a rule to watch a path on this workload." />} />
                {pendingDelete?.workload === activeWorkload && pendingDelete.cluster === clusterId && <div role="alert" className="space-y-3 rounded-md border border-border bg-card p-4"><p className="text-sm">Delete the rule for <span className="font-mono">{pendingDelete.rule.filter}</span>? This removes its configured file monitoring behavior.</p><div className="flex gap-2"><Button disabled={!canAuthor || delMut.isPending} onClick={() => delMut.mutate({ workload: activeWorkload!, ruleId: pendingDelete.rule.id, targetCluster: clusterId! })}>{delMut.isPending ? "Deleting…" : "Delete rule"}</Button><Button variant="ghost" disabled={delMut.isPending} onClick={() => setPendingDelete(null)}>Cancel</Button></div></div>}
                {delMut.isError && delMut.variables?.workload === activeWorkload && delMut.variables.targetCluster === clusterId && <p role="alert" className="text-sm text-status-error">Could not delete this rule. Try again.</p>}
              </div> },
            { value: "workloads", label: "Workloads", count: profiles.length, content: <DataTable rows={profiles} columns={workloadColumns} rowKey={(p) => p.workload_id} preferencesKey="file-monitor-workloads" exportFileName="file-monitor-workloads.csv" /> },
          ]} />
        </>}
      </>}
  </div>;
}
