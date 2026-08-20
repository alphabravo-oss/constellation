import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Plus, Trash2 } from "lucide-react";

import { responseRulesV2, type ResponseRuleV2 } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";

export function ResponseRulesPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  // Cluster-scoped config: rules created in cluster mode are tagged with the
  // cluster_id on the server; the list query filters to "matches this cluster
  // OR org-wide (NULL)" so the user sees what actually applies here.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const rulesBase = `/clusters/${clusterId ?? ""}/response-rules`;
  const q = useQuery({
    queryKey: ["response-rules-v2", clusterId],
    queryFn: () => responseRulesV2.list({ cluster_id: clusterId }),
  });
  const rules = useMemo(() => q.data?.rules ?? [], [q.data]);

  const delMut = useMutation({
    mutationFn: async (id: string) => responseRulesV2.delete(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["response-rules-v2", clusterId] }),
  });

  const columns: Column<ResponseRuleV2>[] = [
    { id: "name", header: "Name", cell: (r) => <span className="font-medium">{r.name}</span> },
    { id: "event_type", header: "Event type", cell: (r) => <span className="text-xs">{r.event_type}</span> },
    { id: "conditions", header: "Conditions", cell: (r) => <span className="text-xs text-muted-foreground">{r.conditions.length} clause(s)</span> },
    { id: "actions", header: "Actions", cell: (r) => <span className="text-xs text-muted-foreground">{r.actions.map((a) => a.kind).join(", ")}</span> },
    { id: "enabled", header: "Enabled", cell: (r) => <span className="text-xs">{r.enabled ? "yes" : "no"}</span> },
    {
      id: "row-actions",
      header: "",
      cell: (r) => (
        <div className="flex items-center justify-end gap-1">
          <button
            type="button"
            onClick={() => navigate(`${rulesBase}/${r.id}`)}
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
            aria-label="Delete"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ),
    },
  ];

  if (clusterLoading) {
    return <p className="text-sm text-muted-foreground" data-testid="response-rules-loading">Loading cluster…</p>;
  }

  return (
    <div className="space-y-4" data-testid="response-rules-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Response Rules"
        description="Match incoming events to automatic actions — notify a channel, open a ticket, or quarantine/isolate a workload — when the conditions you define all hold."
        actions={
          <button
            type="button"
            onClick={() => navigate(`${rulesBase}/new`)}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
          >
            <Plus className="h-3.5 w-3.5" /> New rule
          </button>
        }
      />

      <section className="grid grid-cols-3 gap-3">
        <StatCard label="Rules" value={rules.length} />
        <StatCard label="Enabled" value={rules.filter((r) => r.enabled).length} tone="accent" />
        <StatCard label="Disabled" value={rules.filter((r) => !r.enabled).length} />
      </section>

      <DataTable
        rows={rules}
        columns={columns}
        rowKey={(r) => r.id}
        showDensityToggle={false}
        emptyState={
          q.isPending ? (
            <div className="py-6" />
          ) : (
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              No response rules yet. Click "New rule" to create your first.
            </div>
          )
        }
      />
    </div>
  );
}
