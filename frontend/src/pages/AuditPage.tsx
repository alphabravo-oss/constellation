import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";

interface AuditEvent {
  id: number;
  actor_id?: string;
  action: string;
  target_kind?: string;
  target_id?: string;
  prev_hash: string;
  chain_hash: string;
  at: string;
}

const auditColumns: Column<AuditEvent>[] = [
  { id: "when", header: "When", cell: (e) => new Date(e.at).toLocaleString(), className: "text-xs text-muted-foreground" },
  { id: "actor", header: "Actor", cell: (e) => e.actor_id?.slice(0, 8) ?? "—", className: "font-mono text-xs" },
  { id: "action", header: "Action", cell: (e) => e.action, className: "font-mono text-xs" },
  { id: "target", header: "Target", cell: (e) => <>{e.target_kind}:{e.target_id?.slice(0, 12) ?? ""}</>, className: "text-xs" },
  { id: "chain", header: "Chain Hash", cell: (e) => <>{e.chain_hash.slice(0, 16)}…</>, className: "truncate font-mono text-xs" },
];

export function AuditPage() {
  // Cluster-scoped: the backend joins target_id against findings/assets/
  // deployments/compliance_checks/policies rows of the active cluster so we only
  // surface events that touched something inside this cluster.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const q = useQuery({
    queryKey: ["audit", clusterId],
    queryFn: () =>
      api
        .get<{ events: AuditEvent[] }>("/audit/events", { params: { limit: 100, cluster_id: clusterId } })
        .then((r) => r.data),
  });

  if (clusterLoading) {
    return <LoadingState label="Loading cluster…" />;
  }

  return (
    <div className="space-y-4" data-testid="audit-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Audit Log"
        description={<>Append-only, hash-chained. Verify integrity with <code className="font-mono">constellationctl audit verify</code>.</>}
      />
      {q.isPending ? (
        <LoadingState label="Loading audit events…" />
      ) : q.isError ? (
        <ErrorState error={q.error} />
      ) : (q.data?.events.length ?? 0) === 0 ? (
        <EmptyState title="No audit events" hint="Actions taken in this cluster will appear here." />
      ) : (
      <DataTable rows={q.data?.events ?? []} columns={auditColumns} rowKey={(e) => e.id} />
      )}
    </div>
  );
}
