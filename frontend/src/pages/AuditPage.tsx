import { useIsFetching, useQuery, useQueryClient } from "@tanstack/react-query";

import { useRouteSearchParams } from "@/lib/route-search";
import { api } from "@/api/client";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useCluster } from "@/hooks/useCluster";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Pager } from "@/components/ui/pager";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Button } from "@/components/ui/button";
import { LookaheadExport } from "@/components/LookaheadExport";
import { exportQueryReady } from "@/hooks/useExportGuard";
import { clusterCacheReady } from "@/lib/cluster-evidence";

const PAGE = 100;

interface AuditEvent {
  id: number;
  event_id?: string;
  actor_id?: string;
  action: string;
  target_kind?: string;
  target_id?: string;
  prev_hash: string;
  chain_hash: string;
  at: string;
}

function validAuditID(id: unknown): id is string {
  return typeof id === "string" && /^[1-9]\d*$/.test(id) && BigInt(id) <= 9223372036854775807n;
}
function validAuditEvent(value: unknown): value is AuditEvent {
  if (!value || typeof value !== "object") return false;
  const row = value as Partial<AuditEvent>;
  return typeof row.id === "number" && Number.isInteger(row.id) && row.id > 0 &&
    (row.event_id !== undefined ? validAuditID(row.event_id) : Number.isSafeInteger(row.id)) &&
    typeof row.at === "string" && Number.isFinite(Date.parse(row.at)) &&
    typeof row.action === "string" && typeof row.prev_hash === "string" && typeof row.chain_hash === "string" &&
    [row.actor_id, row.target_kind, row.target_id].every(field => field === undefined || typeof field === "string");
}

const auditColumns: Column<AuditEvent>[] = [
  { id: "record", header: "Record ID", kind: "id", size: 112, minSize: 88, exportValue: e => e.event_id ?? String(e.id), cell: e => e.event_id ?? String(e.id) },
  { id: "when", header: "When", kind: "date", size: 190, minSize: 160, maxSize: 240, exportValue: (e) => e.at, cell: (e) => new Date(e.at).toLocaleString(), className: "text-xs text-muted-foreground" },
  { id: "actor", header: "Actor", kind: "id", size: 128, minSize: 112, maxSize: 160, exportValue: (e) => e.actor_id ?? "", cell: (e) => e.actor_id ?? "—", className: "font-mono text-xs" },
  { id: "action", header: "Action", kind: "text", code: true, size: 240, minSize: 160, grow: true, wrap: true, exportValue: (e) => e.action, cell: (e) => e.action, className: "font-mono text-xs" },
  { id: "target", header: "Target", kind: "id", size: 220, minSize: 160, maxSize: 320, wrap: true, exportValue: (e) => `${e.target_kind ?? ""}:${e.target_id ?? ""}`, cell: (e) => <>{e.target_kind}:{e.target_id ?? ""}</>, className: "text-xs" },
  { id: "chain", header: "Chain Hash", kind: "id", size: 180, maxSize: 220, exportValue: (e) => e.chain_hash, cell: (e) => e.chain_hash, className: "truncate font-mono text-xs" },
];

export function AuditPage({ scope = "cluster" }: { scope?: "cluster" | "organization" }) {
  const qc = useQueryClient();
  const identity = useTablePreferencesIdentity();
  // Cluster-scoped: the backend joins target_id against findings/assets/
  // deployments/compliance_checks/policies rows of the active cluster so we only
  // surface events that touched something inside this cluster.
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const detailFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const clusterReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError && !registryFetching && !detailFetching && clusterCacheReady(qc, clusterId);
  const [searchParams, setParams] = useRouteSearchParams();
  const eventID = searchParams.get("event_id");
  const cohortSet = searchParams.has("event_ids");
  const cohortRaw = searchParams.get("event_ids") ?? "";
  const cohortParts = cohortRaw ? cohortRaw.split(",") : [];
  const cohort = Array.from(new Set(cohortParts));
  const invalidCohort = cohortSet && (searchParams.getAll("event_ids").length !== 1 || cohortParts.length > 20 || cohort.some(id => !validAuditID(id)) || ["event_id", "support_bundle_job_id", "cluster_id", "action", "framework", "control"].some(key => !!searchParams.get(key)));
  const supportBundleJobID = searchParams.get("support_bundle_job_id");
  const action = searchParams.get("action") ?? "", framework = searchParams.get("framework") ?? "", control = searchParams.get("control") ?? "";
  const rawPage = Number(searchParams.get("page"));
  const invalidFilters = Boolean(framework.trim()) !== Boolean(control.trim()) || !!eventID && !validAuditID(eventID) || searchParams.has("page") && (!Number.isSafeInteger(rawPage) || rawPage < 1 || rawPage > Math.floor(Number.MAX_SAFE_INTEGER / PAGE)) || ["action", "framework", "control", "page", "event_id", "support_bundle_job_id"].some(key => searchParams.getAll(key).length > 1);
  const pageIndex = eventID || cohortSet ? 0 : Number.isSafeInteger(rawPage) && rawPage >= 1 && rawPage <= Math.floor(Number.MAX_SAFE_INTEGER / PAGE) ? rawPage - 1 : 0;
  const setPage = (page: number) => setParams(current => { if (page) current.set("page", String(page + 1)); else current.delete("page"); return current; });
  const orgFilter = scope === "organization" || cohortSet || !!eventID || !!supportBundleJobID;
  const scopeReady = !!identity?.org_id && !!identity?.user_id && !invalidCohort && !invalidFilters && (orgFilter || clusterReady);
  const filters = { cluster_id: orgFilter ? undefined : clusterId, event_id: eventID || undefined, ...(cohortSet ? { event_ids: cohortRaw } : {}), support_bundle_job_id: supportBundleJobID || undefined, ...(action ? { action } : {}), ...(framework ? { framework } : {}), ...(control ? { control } : {}) };
  const queryKey = ["audit", identity?.org_id, identity?.user_id, scope, clusterId, filters, pageIndex];
  const q = useQuery({
    queryKey,
    enabled: scopeReady,
    queryFn: () =>
      api
        .get<{ events: AuditEvent[]; has_more: boolean }>("/audit/events", { params: { limit: eventID ? 1 : cohortSet ? 20 : PAGE, offset: pageIndex * PAGE, ...filters } })
        .then((r) => { if (!Array.isArray(r.data.events) || !r.data.events.every(validAuditEvent) || new Set(r.data.events.map(event => event.event_id ?? String(event.id))).size !== r.data.events.length || typeof r.data.has_more !== "boolean" || (eventID && r.data.events.some(event => (event.event_id ?? String(event.id)) !== eventID)) || (cohortSet && (r.data.has_more || r.data.events.some(event => !cohort.includes(event.event_id ?? String(event.id)))) )) throw new Error("Audit evidence does not match the requested page or event"); return r.data; }),
  });
  const ready = scopeReady && q.isSuccess && !q.isFetching && exportQueryReady(qc, queryKey, q.data);
  const events = ready ? q.data.events : [];
  const current = () => scopeReady && (orgFilter || !!clusterId && clusterCacheReady(qc, clusterId)) && exportQueryReady(qc, queryKey, q.data);
  const exportContext = JSON.stringify(queryKey);
  const setFilters = (values: Record<string, string>) => setParams(params => { for (const [key, value] of Object.entries(values)) { if (value) params.set(key, value); else params.delete(key); } params.delete("page"); return params; });

  if (clusterLoading && !orgFilter) {
    return <LoadingState label="Loading cluster…" />;
  }

  return (
    <div className="space-y-4" data-testid="audit-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title={orgFilter ? "Organization Audit Log" : "Audit Log"}
        actions={<Button variant="outline" disabled={!scopeReady || q.isFetching} onClick={() => void q.refetch()}>Refresh</Button>}
        description={cohortSet ? "The exact audit records selected from Dashboard activity, across your organization." : scope === "organization" && !eventID && !supportBundleJobID ? "Recorded actions across your organization, including organization settings and all clusters." : supportBundleJobID ? <>Audit history for support-bundle job {supportBundleJobID}.</> : eventID ? <>Audit event #{eventID}, scoped to your organization.</> : <>Append-only, hash-chained. Verify integrity with <code className="font-mono">constellationctl audit verify</code>.</>}
      />
      <VerdictBanner status={!scopeReady || q.isError ? "degraded" : "info"}
        title={invalidCohort ? "Invalid activity selection" : invalidFilters ? "Invalid audit filters" : !scopeReady ? "Audit scope unavailable" : q.isError ? "Audit evidence unavailable" : !ready ? "Loading audit evidence" : `${events.length} audit events on this page`}
        detail={cohortSet ? `Showing ${ready ? events.length : "—"} of ${cohort.length} selected organization records. Missing or inaccessible records are not replaced by newer activity. Displayed hashes do not establish chain integrity.` : orgFilter ? "This view covers organization-scoped audit records. Displayed hashes do not establish chain integrity." : "Events are resolved to this cluster by their recorded target. Displayed hashes do not establish chain integrity."} />
      <StatGrid><StatCard label="Events (page)" value={ready ? events.length : "—"} /><StatCard label="Page" value={pageIndex + 1} /><StatCard label="More pages" valueKind="text" value={ready ? q.data.has_more ? "Available" : "None reported" : "—"} /></StatGrid>
      {!cohortSet && <form key={JSON.stringify([scope, clusterId, action, framework, control])} className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); const data = new FormData(event.currentTarget); setFilters(Object.fromEntries(["action", "framework", "control"].map(key => [key, String(data.get(key) ?? "").trim()]))); }}>
        {[["action", "Exact action", action], ["framework", "Framework", framework], ["control", "Control", control]].map(([name, label, value]) => <label key={name} className="space-y-1 text-xs"><span className="block">{label}</span><input name={name} defaultValue={value} className="rounded border border-border bg-background px-3 py-2 text-sm" /></label>)}
        <Button type="submit" variant="outline">Apply filters</Button><Button type="button" variant="ghost" onClick={() => setFilters({ action: "", framework: "", control: "" })}>Reset filters</Button>
        <p className="basis-full text-xs text-muted-foreground">Supply Framework and Control together. All supplied filters apply together.</p>
      </form>}
      {cohortSet && <a href="/organization/audit" className="text-sm text-primary hover:underline">View full organization audit history</a>}
      {!scopeReady ? <ErrorState title={invalidCohort ? "Select at most 20 valid audit record IDs" : invalidFilters ? "Choose valid audit filters and a positive page; Framework and Control must be paired." : "Resolve the selected scope before loading audit events"} error={clusterError} /> : q.isPending || q.isFetching ? (
        <LoadingState label="Loading audit events…" />
      ) : q.isError ? (
        <ErrorState error={q.error} action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
      ) : events.length === 0 ? (
        <>
          <EmptyState title={pageIndex > 0 ? "No events on this page" : "No audit events"} hint={cohortSet ? "None of the selected records are available in your organization." : orgFilter ? "Recorded organization actions will appear here." : "Actions taken in this cluster will appear here."} />
          {pageIndex > 0 && <button type="button" onClick={() => setPage(pageIndex - 1)} className="text-sm text-primary hover:underline">Previous page</button>}
        </>
      ) : (
        <>
          <LookaheadExport key={exportContext} context={exportContext} disabled={!ready} isCurrent={current} path="/audit/events.csv" params={filters} filename="audit-events.csv" />
          <DataTable rows={events} columns={auditColumns} rowKey={(e) => e.event_id ?? e.id} pagination={false} preferencesKey={orgFilter ? "organization-audit-events" : "audit-events"} defaultHiddenColumnIds={["chain"]} preferenceMigration={{ id: "audit-hidden-hashes-v1", hideColumnIds: ["chain"] }} canExport={current} exportFileName={`audit-events-page-${pageIndex + 1}`} exportLabel="Export this page CSV" />
          <p className="text-xs text-muted-foreground" data-testid="audit-page-scope">
            Showing audit events {pageIndex * PAGE + 1}–{pageIndex * PAGE + events.length} on page {pageIndex + 1}. {q.data?.has_more ? "More pages available." : "No more pages."}
          </p>
          {!eventID && !cohortSet && <Pager page={pageIndex} pageSize={PAGE} hasMore={q.data?.has_more} rowsOnPage={events.length} onPage={setPage} />}
        </>
      )}
    </div>
  );
}
