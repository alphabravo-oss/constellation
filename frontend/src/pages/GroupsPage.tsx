import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, ArrowUpDown, Pencil, Plus, RefreshCw, Settings, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { ImportExportButtons } from "@/components/ImportExportButtons";
import { groupsApi, type GroupMode } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { TextInput, Select } from "@/components/ui/form";
import { useRouteSearchParams } from "@/lib/route-search";
import { groupSearchText } from "@/lib/group-picker";

const GROUP_MODES: GroupMode[] = ["discover", "monitor", "protect"];

export function GroupsPage() {
  const { clusterId, isLoading, cluster, error } = useCluster();
  const qc = useQueryClient();
  const [tab, setTab] = useTabParam("tab", "groups");
  const [params, setParams] = useRouteSearchParams();
  const search = params.get("q") ?? "";
  const [transferError, setTransferError] = useState<string | null>(null);
  const [transferResult, setTransferResult] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["groups", clusterId], queryFn: () => groupsApi.list({ cluster_id: clusterId }), enabled: Boolean(clusterId) && !isLoading && !(error && !cluster) });
  const groups = q.data?.groups ?? [];
  const filtered = groups.filter((group) => groupSearchText(group).includes(search.trim().toLowerCase()));
  const listPath = clusterId ? `/clusters/${clusterId}/groups` : "/groups";
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["groups", clusterId] });
    void qc.invalidateQueries({ queryKey: ["group-editor", clusterId] });
    void qc.invalidateQueries({ queryKey: ["group-usage", clusterId] });
    void qc.invalidateQueries({ queryKey: ["dashboard", clusterId] });
  };
  const del = useMutation({ mutationFn: (id: string) => groupsApi.delete(id), onSuccess: () => { toast.success("Group deleted"); invalidate(); } });
  const discovery = groups.filter((group) => group.policy_mode === "discover" || group.profile_mode === "discover").length;
  const protectedCount = groups.filter((group) => group.policy_mode === "protect" && group.profile_mode === "protect").length;
  const conflict = (del.error as { response?: { status?: number } } | null)?.response?.status === 409;
  return <div className="space-y-6" data-testid="groups-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title="Groups" description="Organize matching workloads and choose how their network, process, and file policies are enforced."
      actions={<div className="flex items-center gap-2"><Button variant="outline" disabled={q.isFetching || !clusterId} onClick={() => void q.refetch()}><RefreshCw className="h-4 w-4" /> Refresh</Button>
        {clusterId && <Button asChild variant="outline"><Link to="." href={`${listPath}/settings`}><Settings className="h-4 w-4" /> Settings</Link></Button>}
        {clusterId && <Button asChild variant="primary"><Link to="." href={`${listPath}/new`}><Plus className="h-4 w-4" /> Add group</Link></Button>}</div>} />
    {isLoading ? <LoadingState label="Loading cluster…" />
      : !clusterId || (error && !cluster) ? <ErrorState title="Select an available cluster to manage groups." />
      : q.isPending ? <LoadingState label="Loading groups…" />
      : q.isError ? <ErrorState title="Groups could not be loaded. Existing configuration has not changed." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
      : <>
        <VerdictBanner status={discovery ? "degraded" : groups.length ? "ok" : "info"}
          title={discovery ? `${discovery} group${discovery === 1 ? " is" : "s are"} still learning` : groups.length ? "All groups have moved beyond discovery" : "No workload groups yet"}
          detail="Discover learns behavior, Monitor reports violations, and Protect enforces policy. These configured modes do not confirm deployment. Open a group to review its members and dependencies." />
        <StatGrid>
          <StatCard label="Groups" value={groups.length} />
          <StatCard label="Learning" value={discovery} />
          <StatCard label="Protect configured" value={protectedCount} />
          <StatCard label="Member assignments" value={groups.reduce((count, group) => count + (group.members?.length ?? 0), 0)} />
        </StatGrid>
        <Tabs value={tab === "operations" ? "operations" : "groups"} onValueChange={setTab} items={[
          { value: "groups", label: "Workload groups", count: groups.length, content: <Card title="Workload groups" description="Search selectors, member names, and modes; open a group to inspect its workload coverage.">
            <div className="mb-4"><TextInput aria-label="Search groups" placeholder="Search groups, selectors, or members…" value={search} onChange={(event) => setParams((current) => { if (event.target.value) current.set("q", event.target.value); else current.delete("q"); return current; }, { replace: true })} /></div>
            {del.isError && <p role="alert" className="mb-4 text-sm text-status-error">{conflict ? "This group cannot be deleted while policy references depend on it. Open its Policy usage tab to review blocking references." : "Could not delete this group. Its configuration is preserved; try again."}</p>}
            <DataTable rows={filtered} rowKey={(group) => group.id} preferencesKey="workload-groups" exportFileName="constellation-groups.csv" defaultSort={{ id: "name", dir: "asc" }} testId="groups-table"
              columns={[
                { id: "name", kind: "name", grow: true, minSize: 200, header: "Name", hideable: false, cell: (group) => <Link to="." href={`${listPath}/${group.id}`} className="font-medium text-primary hover:underline">{group.name}</Link>, sort: (a, b) => a.name.localeCompare(b.name), exportValue: (group) => group.name },
                { id: "kind", kind: "status", size: 112, minSize: 96, header: "Kind", cell: (group) => group.kind, sort: (a, b) => a.kind.localeCompare(b.kind) },
                { id: "network", kind: "status", size: 144, minSize: 128, header: "Network mode", cell: (group) => group.policy_mode ?? "monitor", sort: (a, b) => (a.policy_mode ?? "monitor").localeCompare(b.policy_mode ?? "monitor") },
                { id: "process", kind: "status", size: 176, minSize: 144, header: "Process/file mode", cell: (group) => group.profile_mode ?? "monitor", sort: (a, b) => (a.profile_mode ?? "monitor").localeCompare(b.profile_mode ?? "monitor") },
                { id: "criteria", kind: "count", size: 112, minSize: 96, header: "Selectors", numeric: true, cell: (group) => group.criteria?.length ?? 0, sort: (a, b) => (a.criteria?.length ?? 0) - (b.criteria?.length ?? 0) },
                { id: "members", kind: "count", size: 112, minSize: 96, header: "Members", numeric: true, cell: (group) => group.members?.length ?? 0, sort: (a, b) => (a.members?.length ?? 0) - (b.members?.length ?? 0) },
                { id: "actions", kind: "actions", size: 160, minSize: 152, wrap: true, header: "Actions", hideable: false, exportable: false, cell: (group) => group.cfg_type === "fed" ? <span className="text-xs text-muted-foreground">Managed by federation</span> : <div className="flex gap-2"><Button asChild variant="ghost" size="sm"><Link to="." href={`${listPath}/${group.id}/edit`} aria-label={`Edit ${group.name}`}><Pencil className="h-3.5 w-3.5" /> Edit</Link></Button><Button variant="ghost" size="sm" disabled={del.isPending} aria-label={`Delete ${group.name}`} onClick={() => { if (window.confirm(`Delete group “${group.name}”? Policy references can block deletion.`)) del.mutate(group.id); }}><Trash2 className="h-3.5 w-3.5" /></Button></div> },
              ]}
              emptyState={<EmptyState title={search ? "No matching groups" : "No groups yet"} hint={search ? "Try another name, selector, or member." : "Add a group to organize workloads using membership selectors."} />} />
          </Card> },
          { value: "operations", label: "Bulk operations", content: <div className="space-y-5">
            <Card title="Change enforcement modes" description="Apply a mode transition to every matching group in this cluster except groups managed by the learner."><GroupModeBulkActions key={clusterId} clusterId={clusterId} onChanged={invalidate} /></Card>
            <Card title="Import or export group configuration" description="Move workload selectors and modes using a YAML configuration bundle.">
              <div className="flex flex-wrap items-center gap-3"><ImportExportButtons filename="constellation-groups.yaml" label="groups"
                exportYaml={async () => { setTransferError(null); setTransferResult(null); try { return await groupsApi.exportYaml({ cluster_id: clusterId }); } catch (err) { setTransferError("Could not export group configuration. Try again."); throw err; } }}
                importYaml={async (text) => { setTransferError(null); setTransferResult(null); try { const result = await groupsApi.importYaml(text, { cluster_id: clusterId }); const failed = result.results.filter((item) => item.status === "error").length; setTransferResult(`Imported ${result.created} new and ${result.updated} updated groups${failed ? `; ${failed} failed. Check the bundle and retry failed entries.` : "."}`); return result; } catch (err) { setTransferError("Could not import groups. Check the YAML bundle and try again."); throw err; } }} onImported={invalidate} /></div>
              {transferError && <p role="alert" className="mt-3 text-sm text-status-error">{transferError}</p>}
              {transferResult && <p role="status" className="mt-3 text-sm text-muted-foreground">{transferResult}</p>}
            </Card>
          </div> },
        ]} />
      </>}
  </div>;
}

function GroupModeBulkActions({ clusterId, onChanged }: { clusterId: string; onChanged: () => void }) {
  const [dimension, setDimension] = useState<"policy" | "profile">("policy");
  const [from, setFrom] = useState<GroupMode>("discover");
  const [to, setTo] = useState<GroupMode>("monitor");
  const mut = useMutation({
    mutationFn: () => groupsApi.promote({ dimension, from, to }, { cluster_id: clusterId }),
    onSuccess: (res) => { toast.success(res.changed ? `Changed ${res.changed} groups: ${res.from} to ${res.to}` : `No ${res.from} groups changed`); onChanged(); },
  });
  return <div className="space-y-3">
    <div className="flex flex-wrap items-end gap-3">
      <label className="space-y-1 text-xs">Mode dimension<Select aria-label="Mode dimension" className="block h-9 rounded-md border border-border bg-background px-3 text-sm" value={dimension} disabled={mut.isPending} onChange={(event) => setDimension(event.target.value as "policy" | "profile")}><option value="policy">Network</option><option value="profile">Process/File</option></Select></label>
      <label className="space-y-1 text-xs">From mode<Select aria-label="From mode" className="block h-9 rounded-md border border-border bg-background px-3 text-sm" value={from} disabled={mut.isPending} onChange={(event) => setFrom(event.target.value as GroupMode)}>{GROUP_MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}</Select></label>
      <ArrowRight className="mb-2 h-4 w-4 text-muted-foreground" aria-hidden />
      <label className="space-y-1 text-xs">To mode<Select aria-label="To mode" className="block h-9 rounded-md border border-border bg-background px-3 text-sm" value={to} disabled={mut.isPending} onChange={(event) => setTo(event.target.value as GroupMode)}>{GROUP_MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}</Select></label>
      <Button variant="primary" size="lg" disabled={from === to || mut.isPending} onClick={() => { if (window.confirm(`Change every ${from} group in this cluster to ${to} for ${dimension === "policy" ? "network" : "process/file"} enforcement?`)) mut.mutate(); }}><ArrowUpDown className="h-4 w-4" />{mut.isPending ? "Applying…" : "Apply"}</Button>
    </div>
    {mut.isError && <p role="alert" className="text-sm text-status-error">Could not change group modes. Refresh the groups to verify their current modes, then try again.</p>}
    {mut.data && <p role="status" className="text-sm text-muted-foreground">Changed {mut.data.changed} groups from {mut.data.from} to {mut.data.to}.</p>}
  </div>;
}
