import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Pager } from "@/components/ui/pager";

const PAGE = 100;

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
  const [searchParams] = useSearchParams();
  const eventID = searchParams.get("event_id");
  const supportBundleJobID = searchParams.get("support_bundle_job_id");
  const [page, setPage] = useState(0);
  const pageIndex = eventID ? 0 : page;
  const q = useQuery({
    queryKey: ["audit", clusterId, eventID, supportBundleJobID, pageIndex],
    queryFn: () =>
      api
        .get<{ events: AuditEvent[]; has_more: boolean }>("/audit/events", { params: { limit: eventID ? 1 : PAGE, offset: pageIndex * PAGE, cluster_id: eventID || supportBundleJobID ? undefined : clusterId, event_id: eventID || undefined, support_bundle_job_id: supportBundleJobID || undefined } })
        .then((r) => r.data),
  });
  const events = q.data?.events ?? [];

  if (clusterLoading) {
    return <LoadingState label="Loading cluster…" />;
  }

  return (
    <div className="space-y-4" data-testid="audit-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Audit Log"
        description={supportBundleJobID ? <>Audit history for support-bundle job {supportBundleJobID}.</> : eventID ? <>Audit event #{eventID}, scoped to your organization.</> : <>Append-only, hash-chained. Verify integrity with <code className="font-mono">constellationctl audit verify</code>.</>}
      />
      {q.isPending ? (
        <LoadingState label="Loading audit events…" />
      ) : q.isError ? (
        <ErrorState error={q.error} />
      ) : events.length === 0 ? (
        <>
          <EmptyState title={pageIndex > 0 ? "No events on this page" : "No audit events"} hint="Actions taken in this cluster will appear here." />
          {pageIndex > 0 && <button type="button" onClick={() => setPage(pageIndex - 1)} className="text-sm text-primary hover:underline">Previous page</button>}
        </>
      ) : (
        <>
          <DataTable rows={events} columns={auditColumns} rowKey={(e) => e.id} />
          <p className="text-xs text-muted-foreground" data-testid="audit-page-scope">
            Showing audit events {pageIndex * PAGE + 1}–{pageIndex * PAGE + events.length} on page {pageIndex + 1}. {q.data?.has_more ? "More pages available." : "No more pages."}
          </p>
          {!eventID && <Pager page={pageIndex} pageSize={PAGE} hasMore={q.data?.has_more} rowsOnPage={events.length} onPage={setPage} />}
        </>
      )}
    </div>
  );
}
