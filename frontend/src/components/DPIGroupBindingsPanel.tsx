import { useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { dpiGroupBindings, groupsApi, type DPISensorKind, type DPIGroupBinding, type Group } from "@/api/client";
import { useRouteSearchParams } from "@/lib/route-search";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";

type DPIGroupBindingsPanelProps = {
  clusterId: string;
  kind: DPISensorKind;
  title: string;
  description: string;
  testId?: string;
};
const EMPTY_GROUPS: Group[] = [];
const EMPTY_BINDINGS: DPIGroupBinding[] = [];

export function DPIGroupBindingsPanel({ clusterId, kind, title, description, testId = "dpi-group-bindings" }: DPIGroupBindingsPanelProps) {
  const navigate = useNavigate();
  const [search] = useRouteSearchParams();
  const queryClient = useQueryClient();
  const groupsQ = useQuery({ queryKey: ["groups", clusterId], queryFn: () => groupsApi.list({ cluster_id: clusterId }), enabled: !!clusterId, staleTime: 30_000 });
  const bindingsQ = useQuery({ queryKey: ["dpi-group-bindings"], queryFn: () => dpiGroupBindings.list(), enabled: !!clusterId, staleTime: 30_000 });
  const groups = groupsQ.data?.groups ?? EMPTY_GROUPS;
  const bindings = bindingsQ.data ?? EMPTY_BINDINGS;
  const groupBindingMap = useMemo(() => {
    const out = new Map<string, DPIGroupBinding[]>();
    for (const binding of bindings) {
      if (binding.sensor_kind !== kind) continue;
      out.set(binding.group_id, [...(out.get(binding.group_id) ?? []), binding]);
    }
    return out;
  }, [bindings, kind]);
  const boundGroups = groups.filter((group) => groupBindingMap.has(group.id));
  const loading = groupsQ.isPending || bindingsQ.isPending;
  const error = groupsQ.isError || bindingsQ.isError;
  const loaded = !!groupsQ.data && !!bindingsQ.data;
  const unbind = useMutation({
    mutationFn: async (groupID: string) => {
      const results = await Promise.allSettled((groupBindingMap.get(groupID) ?? []).map((row) => dpiGroupBindings.unbind(row.id)));
      if (results.some((result) => result.status === "rejected")) throw new Error("Group scope was only partially removed");
    },
    onSettled: () => {
      // A multi-binding removal can partially succeed; always reload its actual state.
      void queryClient.invalidateQueries({ queryKey: ["dpi-group-bindings"] });
      void queryClient.invalidateQueries({ queryKey: ["group-usage"] });
    },
  });
  const columns: Column<Group>[] = [
    { id: "name", header: "Group", hideable: false, exportValue: (group) => group.name, cell: (group) => <button type="button" className="font-mono text-sm text-primary hover:underline" onClick={() => navigate({ href: `/clusters/${encodeURIComponent(clusterId)}/groups/${encodeURIComponent(group.id)}${search.size ? `?${search}` : ""}` })}>{group.name}</button>, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "kind", header: "Kind", cell: (group) => group.kind },
    { id: "members", header: "Matching workloads", numeric: true, cell: (group) => (group.members ?? []).length },
    { id: "actions", header: "Actions", hideable: false, exportable: false, cell: (group) => <Button type="button" size="sm" variant="ghost" disabled={error || unbind.isPending} onClick={() => { if (window.confirm(`Remove ${group.name} from this detector's scope?`)) unbind.mutate(group.id); }}><Trash2 className="mr-1 h-3.5 w-3.5" /> Remove</Button> },
  ];
  const listPath = `/clusters/${encodeURIComponent(clusterId)}/${kind === "dlp" ? "runtime-dlp" : "runtime-signatures"}`;
  return <section className="space-y-4 rounded-lg border border-border bg-card p-4" data-testid={testId}>
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div><h2 className="text-sm font-semibold">{title}</h2><p className="mt-1 text-xs text-muted-foreground">{description}</p><p className="mt-1 text-xs text-muted-foreground">{loaded ? `${boundGroups.length} configured groups` : "Group count unavailable"}. Scope configuration does not confirm detector deployment.</p></div>
      <Button size="sm" variant="outline" onClick={() => navigate({ href: `${listPath}/scope/new${search.size ? `?${search}` : ""}` })} data-testid={`${testId}-add`}><Plus className="mr-1 h-3.5 w-3.5" /> Add group</Button>
    </header>
    {loading && <LoadingState label="Loading group scope…" />}
    {error && <ErrorState title="Current group scope could not be loaded." action={<Button onClick={() => { void groupsQ.refetch(); void bindingsQ.refetch(); }}>Retry</Button>} />}
    {unbind.isError && <p role="alert" className="text-sm text-status-error">Could not fully remove the group scope. Review the refreshed list and try again.</p>}
    {loaded && <DataTable rows={boundGroups} columns={columns} rowKey={(group) => group.id} preferencesKey={`dpi-${kind}-group-scope`} testId={`${testId}-rows`} emptyState={<EmptyState title="No scoped groups" hint="Add a group to configure inspection for its matching workloads." />} />}
  </section>;
}
