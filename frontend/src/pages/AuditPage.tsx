import { useQuery } from "@tanstack/react-query";

import { useRouteSearchParams } from "@/lib/route-search";
import { api } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Pager } from "@/components/ui/pager";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Button } from "@/components/ui/button";

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
  { id: "when", header: "When", kind: "date", size: 190, minSize: 160, maxSize: 240, exportValue: (e) => e.at, cell: (e) => new Date(e.at).toLocaleString(), className: "text-xs text-muted-foreground" },
  { id: "actor", header: "Actor", kind: "id", size: 128, minSize: 112, maxSize: 160, exportValue: (e) => e.actor_id ?? "", cell: (e) => e.actor_id ?? "—", className: "font-mono text-xs" },
  { id: "action", header: "Action", kind: "text", code: true, size: 240, minSize: 160, grow: true, wrap: true, exportValue: (e) => e.action, cell: (e) => e.action, className: "font-mono text-xs" },
  { id: "target", header: "Target", kind: "id", size: 220, minSize: 160, maxSize: 320, wrap: true, exportValue: (e) => `${e.target_kind ?? ""}:${e.target_id ?? ""}`, cell: (e) => <>{e.target_kind}:{e.target_id ?? ""}</>, className: "text-xs" },
  { id: "chain", header: "Chain Hash", kind: "id", size: 180, maxSize: 220, exportValue: (e) => e.chain_hash, cell: (e) => e.chain_hash, className: "truncate font-mono text-xs" },
];

export function AuditPage() {
  // Cluster-scoped: the backend joins target_id against findings/assets/
  // deployments/compliance_checks/policies rows of the active cluster so we only
  // surface events that touched something inside this cluster.
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const clusterReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError;
  const [searchParams, setParams] = useRouteSearchParams();
  const eventID = searchParams.get("event_id");
  const supportBundleJobID = searchParams.get("support_bundle_job_id");
  const rawPage = Number(searchParams.get("page"));
  const pageIndex = eventID ? 0 : Number.isSafeInteger(rawPage) && rawPage >= 1 && rawPage <= Math.floor(Number.MAX_SAFE_INTEGER / PAGE) ? rawPage - 1 : 0;
  const setPage = (page: number) => setParams(current => { if (page) current.set("page", String(page + 1)); else current.delete("page"); return current; });
  const orgFilter = !!eventID || !!supportBundleJobID;
  const scopeReady = orgFilter || clusterReady;
  const q = useQuery({
    queryKey: ["audit", clusterId, eventID, supportBundleJobID, pageIndex],
    enabled: scopeReady,
    queryFn: () =>
      api
        .get<{ events: AuditEvent[]; has_more: boolean }>("/audit/events", { params: { limit: eventID ? 1 : PAGE, offset: pageIndex * PAGE, cluster_id: eventID || supportBundleJobID ? undefined : clusterId, event_id: eventID || undefined, support_bundle_job_id: supportBundleJobID || undefined } })
        .then((r) => { if (typeof r.data.has_more !== "boolean" || (eventID && r.data.events.some(event => String(event.id) !== eventID))) throw new Error("Audit evidence does not match the requested page or event"); return r.data; }),
  });
  const ready = scopeReady && q.isSuccess;
  const events = ready ? q.data.events : [];

  if (clusterLoading && !orgFilter) {
    return <LoadingState label="Loading cluster…" />;
  }

  return (
    <div className="space-y-4" data-testid="audit-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Audit Log"
        actions={<Button variant="outline" disabled={!scopeReady || q.isFetching} onClick={() => void q.refetch()}>Refresh</Button>}
        description={supportBundleJobID ? <>Audit history for support-bundle job {supportBundleJobID}.</> : eventID ? <>Audit event #{eventID}, scoped to your organization.</> : <>Append-only, hash-chained. Verify integrity with <code className="font-mono">constellationctl audit verify</code>.</>}
      />
      <VerdictBanner status={!scopeReady || q.isError ? "degraded" : "info"}
        title={!scopeReady ? "Cluster scope unavailable" : q.isError ? "Audit evidence unavailable" : q.isPending ? "Loading audit evidence" : `${events.length} audit events on this page`}
        detail={orgFilter ? "This explicit event or support-bundle lookup is organization-scoped. Displayed hashes do not establish chain integrity." : "Events are resolved to this cluster by their recorded target. Displayed hashes do not establish chain integrity."} />
      <StatGrid><StatCard label="Events (page)" value={ready ? events.length : "—"} /><StatCard label="Page" value={pageIndex + 1} /><StatCard label="More pages" valueKind="text" value={ready ? q.data.has_more ? "Available" : "None reported" : "—"} /></StatGrid>
      {!scopeReady ? <ErrorState title="Resolve the selected cluster before loading audit events" error={clusterError} /> : q.isPending ? (
        <LoadingState label="Loading audit events…" />
      ) : q.isError ? (
        <ErrorState error={q.error} action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
      ) : events.length === 0 ? (
        <>
          <EmptyState title={pageIndex > 0 ? "No events on this page" : "No audit events"} hint="Actions taken in this cluster will appear here." />
          {pageIndex > 0 && <button type="button" onClick={() => setPage(pageIndex - 1)} className="text-sm text-primary hover:underline">Previous page</button>}
        </>
      ) : (
        <>
          <DataTable rows={events} columns={auditColumns} rowKey={(e) => e.id} pagination={false} preferencesKey="audit-events" exportFileName={`audit-events-page-${pageIndex + 1}`} exportLabel="Export this page CSV" />
          <p className="text-xs text-muted-foreground" data-testid="audit-page-scope">
            Showing audit events {pageIndex * PAGE + 1}–{pageIndex * PAGE + events.length} on page {pageIndex + 1}. {q.data?.has_more ? "More pages available." : "No more pages."}
          </p>
          {!eventID && <Pager page={pageIndex} pageSize={PAGE} hasMore={q.data?.has_more} rowsOnPage={events.length} onPage={setPage} />}
        </>
      )}
    </div>
  );
}
