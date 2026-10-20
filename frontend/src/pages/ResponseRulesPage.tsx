import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Plus, Trash2, ChevronUp, ChevronDown } from "lucide-react";

import { responseRulesV2, type ResponseRuleV2 } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { ImportExportButtons } from "@/components/ImportExportButtons";

export function ResponseRulesPage() {
  const { clusterId, cluster, isLoading } = useCluster();
  if (isLoading) return <LoadingState label="Loading cluster…" />;
  if (!clusterId || !cluster) return <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." />;
  return <ResponseRulesWorkspace key={clusterId} clusterId={clusterId} />;
}

function ResponseRulesWorkspace({ clusterId }: { clusterId: string }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  // Cluster-scoped config: rules created in cluster mode are tagged with the
  // cluster_id on the server; the list query filters to "matches this cluster
  // OR org-wide (NULL)" so the user sees what actually applies here.
  const rulesBase = `/clusters/${clusterId ?? ""}/response-rules`;
  const q = useQuery({
    queryKey: ["response-rules-v2", clusterId],
    queryFn: () => responseRulesV2.list({ cluster_id: clusterId }),
    enabled: !!clusterId,
  });
  const rules = useMemo(() => q.data?.rules ?? [], [q.data]);

  const delMut = useMutation({
    mutationFn: async (id: string) => responseRulesV2.delete(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["response-rules-v2", clusterId] }),
  });
  const reorderMut = useMutation({
    mutationFn: (orderedIds: string[]) => responseRulesV2.reorder(orderedIds, { cluster_id: clusterId }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["response-rules-v2", clusterId] }),
  });
  const busy = delMut.isPending || reorderMut.isPending || q.isError || q.isFetching;
  // Move a rule one slot up/down in the evaluation order and persist the new order.
  const move = (index: number, dir: -1 | 1) => {
    const target = index + dir;
    if (target < 0 || target >= rules.length) return;
    const ids = rules.map((r) => r.id);
    [ids[index], ids[target]] = [ids[target], ids[index]];
    reorderMut.mutate(ids);
  };

  const columns: Column<ResponseRuleV2>[] = [
    {
      id: "order", kind: "count", size: 88, minSize: 88, align: "left", numeric: true,
      exportValue: (r) => rules.findIndex((x) => x.id === r.id) + 1,
      header: "Order",
      cell: (r) => {
        const i = rules.findIndex((x) => x.id === r.id);
        return (
          <div className="flex items-center gap-1">
            <span className="w-5 text-right tabular-nums text-xs text-muted-foreground">{i + 1}</span>
            <div className="flex flex-col">
              <button type="button" title="Move up" disabled={i <= 0 || busy} onClick={() => move(i, -1)} className="rounded p-0.5 hover:bg-accent disabled:opacity-30"><ChevronUp className="h-3 w-3" /></button>
              <button type="button" title="Move down" disabled={i >= rules.length - 1 || busy} onClick={() => move(i, 1)} className="rounded p-0.5 hover:bg-accent disabled:opacity-30"><ChevronDown className="h-3 w-3" /></button>
            </div>
          </div>
        );
      },
    },
    { id: "name", kind: "name", grow: true, minSize: 200, exportValue: (r) => r.name, header: "Name", cell: (r) => <span className="font-medium">{r.name}</span> },
    { id: "event_type", kind: "status", size: 128, minSize: 112, exportValue: (r) => r.event_type, header: "Event type", cell: (r) => <span className="text-xs">{r.event_type}</span> },
    { id: "conditions", kind: "count", size: 128, minSize: 112, exportValue: (r) => r.conditions.map((c) => `${c.type}: ${c.value}`).join("; "), header: "Conditions", cell: (r) => <span className="text-xs text-muted-foreground">{r.conditions.length} clause(s)</span> },
    { id: "actions", kind: "text", size: 176, minSize: 160, wrap: true, exportValue: (r) => r.actions.map((a) => a.kind).join(", "), header: "Actions", cell: (r) => <span className="text-xs text-muted-foreground">{r.actions.map((a) => a.kind).join(", ")}</span> },
    { id: "enabled", kind: "status", exportValue: (r) => r.enabled ? "yes" : "no", header: "Enabled", cell: (r) => <span className="text-xs">{r.enabled ? "yes" : "no"}</span> },
    {
      id: "row-actions", kind: "actions", size: 128, minSize: 120,
      hideable: false, exportable: false,
      header: "",
      cell: (r) => (
        <div className="flex items-center justify-end gap-1">
          <button
            type="button"
            aria-label={`Edit ${r.name}`}
            disabled={busy || q.isFetching}
            onClick={() => navigate({ href: `${rulesBase}/${encodeURIComponent(r.id)}` })}
            className="rounded-md px-2 py-1 text-xs hover:bg-accent"
          >
            Edit
          </button>
          <button
            type="button"
            onClick={() => {
              if (window.confirm(`Delete rule "${r.name}"?`)) delMut.mutate(r.id);
            }}
            className="rounded-md p-1 text-xs hover:bg-accent"
            disabled={busy}
            aria-label={`Delete ${r.name}`}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4" data-testid="response-rules-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Response rules"
        description="Author response rules for this cluster or review applicable organization rules. Match incoming events to automatic actions — notify a channel, open a ticket, or quarantine/isolate a workload — when the conditions you define all hold. Rules evaluate top-to-bottom; use the order arrows to set precedence."
        actions={
          <div className="flex items-center gap-2">
            <fieldset disabled={busy || q.isPending} className="flex gap-2"><ImportExportButtons
              filename="constellation-response-rules.yaml"
              label="cluster response rules"
              exportYaml={() => responseRulesV2.exportYaml(clusterId)}
              importYaml={(text) => responseRulesV2.importYaml(clusterId, text)}
              onImported={() => void qc.invalidateQueries({ queryKey: ["response-rules-v2", clusterId] })}
            /></fieldset>
            <button
              type="button"
              disabled={busy || q.isPending}
              onClick={() => navigate({ href: `${rulesBase}/new` })}
              className="inline-flex h-8 items-center gap-1.5 rounded-md bg-brand px-3 text-meta font-medium text-brand-foreground transition-colors hover:bg-brand/90 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
            >
              <Plus className="h-3.5 w-3.5" /> New rule
            </button>
          </div>
        }
      />

      <VerdictBanner status={q.isError ? "degraded" : "info"} title={q.isError ? "Response rules could not be refreshed" : q.isPending ? "Loading response rules" : `${rules.length} response rules apply to this cluster`}
        detail="Rules run in evaluation order. Enabled rules describe configured automation; delivery and workload actions still depend on their receivers and agents." />
      <p className="text-xs text-muted-foreground">YAML export includes cluster-owned rules only; organization-wide rules remain separate.</p>

      <StatGrid>
        <StatCard label="Rules" value={q.data ? rules.length : "—"} />
        <StatCard label="Enabled" value={q.data ? rules.filter((r) => r.enabled).length : "—"} tone="accent" />
        <StatCard label="Disabled" value={q.data ? rules.filter((r) => !r.enabled).length : "—"} />
      </StatGrid>

      {(delMut.isError || reorderMut.isError) && <p role="alert" className="text-sm text-status-error">Could not update response rules. Try the action again.</p>}
      {q.isError && <ErrorState title="Could not load response rules." action={<button type="button" onClick={() => void q.refetch()}>Retry</button>} />}
      {q.isPending ? <LoadingState label="Loading response rules…" /> : q.data ? <DataTable
        rows={rules}
        columns={columns}
        rowKey={(r) => r.id}
        preferencesKey="response-rules"
        exportFileName="constellation-response-rules"
        emptyState={
          q.isPending ? (
            <div className="py-6" />
          ) : (
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              No response rules yet. Click "New rule" to create your first.
            </div>
          )
        }
      /> : null}
    </div>
  );
}
