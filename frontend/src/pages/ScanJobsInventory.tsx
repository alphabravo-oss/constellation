import { useEffect, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scanJobs, scanJobsAdmin, type ScanJob, type ScanJobInventoryResponse } from "@/api/client";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Pager } from "@/components/ui/pager";
import { StatusPill } from "@/components/ui/status-pill";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { useInventoryRoute, ScanInventoryExport } from "./inventory-workspace";
import { scanJobInventoryResponseValid } from "@/lib/scan-job-inventory";
import { fmtRelative } from "@/lib/format";
import { Select } from "@/components/ui/form";

const statuses = ["pending", "running", "paused", "completed", "failed", "canceled"];
const types = ["image", "workload", "host", "platform", "registry", "repository", "serverless"];
const sorts = ["requested", "target", "type", "status", "attempts", "findings", "finished"];
type Action = "pause" | "resume" | "retry" | "cancel";

function actions(status: string): Action[] {
  if (status === "pending") return ["pause", "cancel"];
  if (status === "paused") return ["resume", "cancel"];
  if (status === "running") return ["cancel"];
  return ["failed", "canceled"].includes(status) ? ["retry"] : [];
}

export function ScanJobsInventory() {
  const route = useInventoryRoute();
  const identity = useTablePreferencesIdentity();
  const qc = useQueryClient();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const status = route.params.get("status") || "";
  const type = route.params.get("target_type") || "";
  const sort = route.params.get("sort") || "requested";
  const order = route.params.get("order") || "desc";
  const rawPage = route.params.get("page");
  const invalid = Boolean(
    status && !statuses.includes(status) || type && !types.includes(type) ||
    !sorts.includes(sort) || !["asc", "desc"].includes(order) ||
    rawPage !== null && (!/^\d+$/.test(rawPage) || !Number.isSafeInteger(Number(rawPage)) || Number(rawPage) < 1 || Number(rawPage) > 10000)
  );
  const request = {
    q: route.debouncedQuery.trim() || undefined,
    status: status || undefined,
    target_type: type || undefined,
    cluster_id: route.params.get("cluster_id") || undefined,
    registry_id: route.params.get("registry_id") || undefined,
    sort,
    order: order as "asc" | "desc",
    limit: 100,
    offset: route.offset,
  };
  const key = ["scan-jobs", owner, request];
  const context = JSON.stringify([key, route.query]);
  const currentContext = useRef(context);
  currentContext.current = context;
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const q = useQuery({
    queryKey: key, enabled: Boolean(owner) && !invalid && !route.debouncing, queryFn: async () => {
      const data = await scanJobs.list(request);
      if (!scanJobInventoryResponseValid(data, request, identity?.org_id))
        throw new Error("Scan job response does not match this inventory");
      return data;
    }
  });
  const available = Boolean(owner) && q.isSuccess && !q.isFetching && !invalid && !route.debouncing;
  const rows = available ? q.data.jobs : [];
  const lifecycle = useMutation({
    mutationFn: async ({ id, action, submittedContext }: {
      id: string;
      action: Action;
      submittedContext: string;
      submittedOwner: string;
    }) => {
      const state = qc.getQueryState<ScanJobInventoryResponse>(key);
      const current = state?.data?.jobs.find(j => j.id === id);
      if (!mounted.current || !available || submittedContext !== currentContext.current || state?.isInvalidated || state?.status !== "success" || state.fetchStatus !== "idle" || !current || !actions(current.status).includes(action))
        throw new Error("Refresh the job before changing its state");
      return scanJobsAdmin[action](id);
    },
    onSuccess: (_result, variables) => {
      void qc.invalidateQueries({ queryKey: ["scan-jobs"], predicate: query => query.queryKey.includes(variables.submittedOwner) });
      void qc.invalidateQueries({ queryKey: ["connector-coverage", variables.submittedOwner] });
    },
  });
  const columns: Column<ScanJob>[] = [
    { id: "target", sort: () => 0, header: "Target", kind: "name", minSize: 260, wrap: true, exportValue: j => j.target_ref, cell: j => { const digest = j.target_type === "image" ? j.target_ref.match(/(?:^|@)(sha256:.+)$/)?.[1] : undefined; return <div>{digest ? j.target_ref.replace(/(?:^|@)sha256:.+$/, "") || "Unnamed image" : j.target_ref}<DigestDisclosure digest={digest} /></div>; } },
    { id: "type", sort: () => 0, header: "Type", kind: "status", cell: j => j.target_type },
    { id: "status", sort: () => 0, header: "Status", kind: "status", cell: j => <StatusPill label={j.status} tone={j.status === "failed" ? "error" : j.status === "completed" ? "success" : "neutral"} /> },
    { id: "attempts", sort: () => 0, header: "Attempts", kind: "count", cell: j => `${j.attempt_count}/${j.max_attempts}` },
    { id: "findings", sort: () => 0, header: "Findings", kind: "count", cell: j => j.finding_count ?? 0 },
    { id: "requested", sort: () => 0, header: "Requested", kind: "date", exportValue: j => j.requested_at, cell: j => <span title={new Date(j.requested_at).toLocaleString()}>{fmtRelative(j.requested_at)}</span> },
    { id: "finished", sort: () => 0, header: "Finished", kind: "date", exportValue: j => j.finished_at, cell: j => j.finished_at ? <span title={new Date(j.finished_at).toLocaleString()}>{fmtRelative(j.finished_at)}</span> : "—" },
    { id: "actions", header: "Actions", kind: "actions", minSize: 168, cell: j => <div className="flex flex-wrap gap-1">{actions(j.status).map(action => <Button key={action} size="sm" variant="outline" disabled={!available || lifecycle.isPending} onClick={event => { event.stopPropagation(); lifecycle.mutate({ id: j.id, action, submittedContext: context, submittedOwner: owner }); }}>{action[0].toUpperCase() + action.slice(1)}</Button>)}</div> },
  ];
  const selected = rows.find(j => j.id === route.selectedID);
  return <section className="space-y-3" data-testid="recent-scan-jobs">
    <div className="flex flex-wrap gap-2">
      <input aria-label="Search scan jobs" placeholder="Search target, source, worker or error" className="min-w-0 basis-64 flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm" value={route.query} onChange={e => route.setQuery(e.target.value)} />
      <Select aria-label="Scan job status" value={status} onChange={e => route.update({ status: e.target.value })} className="rounded-md border border-border bg-background p-2 text-sm"><option value="">All statuses</option>{statuses.map(s => <option key={s}>{s}</option>)}</Select>
      <Select aria-label="Scan target type" value={type} onChange={e => route.update({ target_type: e.target.value })} className="rounded-md border border-border bg-background p-2 text-sm"><option value="">All target types</option>{types.map(s => <option key={s}>{s}</option>)}</Select>
      <Button disabled={!owner || q.isFetching || invalid || route.debouncing} onClick={() => void q.refetch()}>Refresh jobs</Button>
      <Button variant="outline" onClick={() => route.update({ q: null, status: null, target_type: null, cluster_id: null, registry_id: null, sort: null, order: null, page: null })}>Reset filters</Button>
    </div>
    {(request.cluster_id || request.registry_id) && <p className="text-xs text-muted-foreground">{request.cluster_id && <>Cluster: {request.cluster_id} </>}{request.registry_id && <>Registry: {request.registry_id}</>}</p>}
    {lifecycle.isError && lifecycle.variables?.submittedContext === context && <ErrorState title="The scan job action failed. Refresh jobs and retry." />}
    {invalid ? <ErrorState title="Choose supported scan job filters and sorting." /> : q.isError ? <ErrorState title="Scan jobs are unavailable or could not be refreshed." action={<Button onClick={() => void q.refetch()}>Retry scan jobs</Button>} /> : !available ? <LoadingState label="Loading scan jobs…" /> : <>
      <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-muted-foreground">{q.data.total!.toLocaleString()} matching jobs · {q.data.summary!.running} running · {q.data.summary!.failed} failed</p><ScanInventoryExport context={context} disabled={!available} download={shouldDownload => scanJobs.exportCSV(request, shouldDownload)} /></div>
      <DataTable rows={rows} columns={columns} rowKey={j => j.id} testId="scan-jobs-table" preferencesKey="connector-scan-jobs" pagination={false} manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })} onRowClick={j => route.setSelectedID(j.id)} selected={new Set(selected ? [selected.id] : [])} exportFileName="constellation-scan-jobs-page.csv" exportLabel="Export this page CSV" emptyState={<p className="p-4 text-sm text-muted-foreground">No scan jobs match these filters or page.</p>} />
      {route.page > 0 && !rows.length && <Button onClick={() => route.setPage(0)}>First page</Button>}
      <Pager page={route.page} pageSize={100} total={q.data.total} rowsOnPage={rows.length} onPage={route.setPage} />
      {route.selectedID && <div className="space-y-2"><Button size="sm" variant="outline" onClick={() => route.setSelectedID(null)}>Clear selection</Button>{selected ? <dl className="grid gap-2 rounded-md border border-border p-3 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Job ID</dt><dd className="break-all">{selected.id}</dd></div><div><dt className="text-muted-foreground">Worker</dt><dd>{selected.worker_id || "Not assigned"}</dd></div><div><dt className="text-muted-foreground">Error</dt><dd className="break-words">{selected.error || "None reported"}</dd></div><div><dt className="text-muted-foreground">Next attempt</dt><dd>{selected.next_attempt_at ? new Date(selected.next_attempt_at).toLocaleString() : "Not scheduled"}</dd></div></dl> : <p role="status" className="text-sm text-muted-foreground">The selected job is outside this page or filter.</p>}</div>}
    </>}
  </section>;
}
