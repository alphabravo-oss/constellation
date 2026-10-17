import { ResourceSavedViewsControl } from "@/components/ResourceSavedViewsControl";
import { useIsFetching, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Clock3, RadioTower, ShieldAlert, Skull } from "lucide-react";
import type { ReactNode } from "react";

import { enterprise, runtimeEvents, type RuntimeEvent, type RuntimeOverview, type RuntimeEventsParams } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { Field as FormField, Select, TextInput } from "@/components/ui/form";
import { Pager } from "@/components/ui/pager";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { useInventoryRoute, ScanInventoryExport } from "./inventory-workspace";
import { EVENT_SEVERITIES, EVENT_VERDICTS, eventCSVFilter, runtimeEventFiltersValid, runtimeEventsResponseValid } from "./runtime-event-inventory";
import { useRouteSearchParams } from "@/lib/route-search";
import { sameTimelineBoundary, timelineAfterParam } from "@/lib/timeline-filters";
import { useCluster } from "@/hooks/useCluster";

const WINDOWS = [1, 6, 24, 72, 168];
const WORKSPACES = ["live", "evidence", "subsystems", "workloads", "rules"];

export function RuntimePage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const detailFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
  const clusterDetail = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
  const cachedClusterMatches = !registry && !clusterDetail || (registry?.data?.clusters.find((item) => item.id === clusterId) ?? clusterDetail?.data)?.id === clusterId;
  const clusterReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError && !registryFetching && !detailFetching && cachedClusterMatches &&
    (!registry || registry.status === "success" && registry.fetchStatus === "idle") && (!clusterDetail || clusterDetail.status !== "error" && clusterDetail.fetchStatus === "idle");
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const route = useInventoryRoute(INVENTORY_MAX_PAGE);
  const [params, setParams] = useRouteSearchParams();
  const [requestedTab, setTab] = useTabParam("tab", "live");
  const tab = WORKSPACES.includes(requestedTab) ? requestedTab : "live";
  const requestedHours = Number(params.get("hours"));
  const hours = WINDOWS.includes(requestedHours) ? requestedHours : 24;
  const selectedEventID = params.get("event");
  const selectedEventAt = params.get("event_at");
  const evidenceKey = (event: RuntimeOverview["recent_events"][number]) => `${event.id}@${event.at}`;
  function selectEvent(id: string, at: string) {
    setParams((previous) => { const next = new URLSearchParams(previous); next.set("event", id); next.set("event_at", at); next.set("tab", "evidence"); return next; });
  }
  const q = useQuery({ queryKey: ["runtime-overview", owner, hours, clusterId], queryFn: () => enterprise.runtime({ hours, cluster_id: clusterId! }), enabled: clusterReady && !!owner });
  const liveSort = params.get("sort") || "at", liveOrder = params.get("order") || "desc";
  const liveFiltersValid = runtimeEventFiltersValid(params);
  const liveRequest: RuntimeEventsParams = { cluster_id: clusterId!, limit: 100, offset: route.offset, sort: liveSort, order: liveOrder as "asc" | "desc", q: route.debouncedQuery.trim() || undefined,
    kind: eventCSVFilter(params.get("kind") || "") || undefined, source: eventCSVFilter(params.get("source") || "") || undefined, verdict: eventCSVFilter(params.get("verdict") || "") || undefined,
    severity: (params.get("severity") || undefined) as RuntimeEventsParams["severity"], workload: params.get("workload")?.trim() || undefined, namespace: params.get("namespace")?.trim() || undefined, node: params.get("node")?.trim() || undefined,
    after: params.get("after") ? timelineAfterParam(params.get("after")!) : undefined, before: params.get("before") ? timelineAfterParam(params.get("before")!) : undefined };
  const liveKey = ["runtime-events-live", owner, clusterId, liveRequest];
  const liveQ = useQuery({ queryKey: liveKey, queryFn: () => runtimeEvents.list(liveRequest), enabled: clusterReady && !!owner && liveFiltersValid && !route.debouncing, refetchInterval: 10_000 });
  const overviewReady = clusterReady && !!owner && q.isSuccess && q.data.summary.window_hours === hours;
  const liveScopeMismatch = (liveQ.data !== undefined || liveQ.isSuccess) && !runtimeEventsResponseValid(liveQ.data, liveRequest);
  const liveReady = clusterReady && !!owner && liveFiltersValid && !route.debouncing && liveQ.isSuccess && !liveScopeMismatch;
  const liveEvents = liveReady ? liveQ.data.events : [];
  const subsystems = overviewReady ? q.data.subsystems : [];
  const rules = overviewReady ? q.data.rules : [];
  const events = overviewReady ? q.data.recent_events.filter((event) => event.cluster_id === clusterId) : [];
  const workloads = overviewReady ? q.data.workloads : [];
  const summary = overviewReady ? q.data.summary : undefined;
  const selectedCandidates = selectedEventID ? events.filter(event => event.id === selectedEventID && (!selectedEventAt || sameTimelineBoundary(event.at, selectedEventAt))) : [];
  const selectedEvent = selectedCandidates.length === 1 ? selectedCandidates[0] : undefined;
  function retryCluster() {
    void qc.invalidateQueries({ queryKey: ["clusters"], exact: true });
    void qc.invalidateQueries({ queryKey: ["cluster", clusterId], exact: true });
  }
  const overviewState = !overviewReady ? q.isError ? <ErrorState title="Runtime evidence could not be loaded or refreshed." error={q.error} action={<Button onClick={() => void q.refetch()}>Retry runtime evidence</Button>} />
    : q.isPending || q.isFetching ? <LoadingState label="Loading runtime evidence…" />
    : <ErrorState title="Runtime evidence does not match the selected time window." action={<Button onClick={() => void q.refetch()}>Retry runtime evidence</Button>} /> : null;
  const withOverview = (content: ReactNode) => overviewState ?? content;
  // Columns for the "Recent runtime events" table. Defined in-component because
  // the Workload cell's select button updates the selected event URL.
  const recentEventColumns: Column<RuntimeOverview["recent_events"][number]>[] = [
    {
      id: "workload",
      header: "Workload",
      kind: "name",
      code: true,
      wrap: true,
      className: "align-top",
      cell: (event) => (
        <>
          <button type="button" className="text-left font-medium hover:underline" onClick={(click) => { click.stopPropagation(); selectEvent(event.id, event.at); }}>
            {event.workload_id}
          </button>
          <div className="mt-1 text-[11px] text-muted-foreground">{event.cluster_name || event.cluster_id}</div>
        </>
      ),
    },
    {id:"platform_role",header:"Platform role",kind:"text",exportHeader:"platform_role",cell:event=>event.platform_role||"Not classified",exportValue:event=>event.platform_role??""},
    {
      id: "signal",
      header: "Signal",
      kind: "text",
      size: 160,
      maxSize: 220,
      className: "align-top text-xs",
      cell: (event) => (
        <>
          <div>{event.source}</div>
          <div className="mt-1 text-muted-foreground">{event.kind} · {event.severity}</div>
        </>
      ),
    },
    {
      id: "verdict",
      header: "Verdict",
      kind: "status",
      className: "align-top",
      cell: (event) => <span className="rounded-md border border-border px-2 py-1 text-xs">{event.verdict}</span>,
    },
    {
      id: "attack",
      header: "ATT&CK",
      kind: "badge",
      size: 180,
      minSize: 120,
      maxSize: 260,
      wrap: true,
      className: "align-top",
      cell: (event) => (
        <div className="flex flex-wrap gap-1">
          {event.attack_techniques.map((technique) => (
            <span key={technique} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {technique}
            </span>
          ))}
        </div>
      ),
    },
    {
      id: "message",
      header: "Message",
      kind: "text",
      size: 280,
      maxSize: 640,
      grow: true,
      wrap: true,
      className: "align-top text-xs text-muted-foreground",
      cell: (event) => (
        <>
          <div>{event.message || new Date(event.at).toLocaleTimeString()}</div>
          {event.rule_name && <div className="mt-1 font-mono text-[11px]">{event.rule_name}</div>}
        </>
      ),
    },
  ];

  if (!clusterReady) return <div className="space-y-6" data-testid="runtime-page">
    <PageHeader title="Runtime" description="Inspect runtime events and enforcement evidence for the selected cluster." />
    {clusterLoading || registryFetching || detailFetching ? <LoadingState label="Resolving runtime cluster…" />
      : <ErrorState title="The selected cluster could not be resolved." error={clusterError} action={<Button onClick={retryCluster}>Retry cluster</Button>} />}
  </div>;

  const liveView = <section className="space-y-3" data-testid="runtime-live-events">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 className="text-sm font-semibold">Runtime event history</h2>
      <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground" data-testid="runtime-live-status">{liveQ.isError || liveScopeMismatch ? "Unavailable" : liveQ.isFetching ? "Refreshing" : "Polling"}</span>
    </div>
    <ResourceSavedViewsControl inventory="runtime" clusterId={clusterId} ready={liveReady && !liveQ.isFetching && !route.debouncing}/>
    <div className="flex flex-wrap items-end gap-3">
      <FormField label="Search events" htmlFor="runtime-event-search" className="min-w-56 flex-1"><TextInput id="runtime-event-search" value={route.query} onChange={event => route.setQuery(event.target.value)} /></FormField>
      <FormField label="Minimum severity" htmlFor="runtime-event-severity"><Select id="runtime-event-severity" value={params.get("severity") || ""} onChange={event => route.update({ severity: event.target.value || null })}><option value="">All severities</option>{EVENT_SEVERITIES.map(value => <option key={value} value={value}>{value} and higher</option>)}</Select></FormField>
      <FormField label="Verdict" htmlFor="runtime-event-verdict"><Select id="runtime-event-verdict" value={params.get("verdict") || ""} onChange={event => route.update({ verdict: event.target.value || null })}><option value="">All verdicts</option>{params.get("verdict")?.includes(",") && <option value={params.get("verdict")!}>{params.get("verdict")}</option>}{EVENT_VERDICTS.map(value => <option key={value} value={value}>{value}</option>)}</Select></FormField>
      <Button disabled={!liveFiltersValid || liveQ.isFetching || route.debouncing || !owner} onClick={() => void liveQ.refetch()}>Refresh events</Button>
    </div>
    <Collapse label="Advanced: event filters and source details">
      <div className="grid gap-3 sm:grid-cols-2">{[["workload", "Workload contains"], ["kind", "Kinds (comma separated)"], ["source", "Sources (comma separated)"], ["namespace", "Exact namespace"], ["node", "Exact node"], ["after", "At or after (RFC3339)"], ["before", "Before (RFC3339)"]].map(([key, label]) => <FormField key={key} label={label} htmlFor={`runtime-event-${key}`}><TextInput id={`runtime-event-${key}`} value={params.get(key) || ""} onChange={event => route.update({ [key]: event.target.value || null }, true, true)} /></FormField>)}</div>
      <p className="mt-3 text-sm text-muted-foreground">History covers all matching records across pages, with no default time bound. It refreshes every 10 seconds and is separate from the evidence time window. Alerting includes alert, block and quarantine verdicts. Identified workloads count distinct nonblank cluster/workload pairs among matching events. Page CSV uses visible columns; matching CSV includes all event fields, up to 100,000 rows. Reported events do not prove agent coverage or enforcement.</p>
    </Collapse>
    {!owner ? <ErrorState title="Resolve the current account before loading runtime events." /> : !liveFiltersValid ? <ErrorState title="The requested runtime event filters or page are invalid." action={<Button onClick={() => route.update({ severity: null, verdict: null, after: null, before: null, sort: null, order: null })}>Reset event filters</Button>} />
      : liveQ.isError ? <ErrorState title="Runtime event history could not be loaded or refreshed." error={liveQ.error} action={<Button onClick={() => void liveQ.refetch()}>Retry latest events</Button>} />
      : liveScopeMismatch ? <ErrorState title="Runtime events do not match the selected scope, filters or page." action={<Button onClick={() => void liveQ.refetch()}>Retry latest events</Button>} />
      : !liveReady ? <LoadingState label="Loading runtime events…" /> : <>
        <p className="text-sm text-muted-foreground">{liveQ.data.total!.toLocaleString()} event records match these filters.</p>
        <ScanInventoryExport context={JSON.stringify(liveKey)} disabled={liveQ.isFetching || !liveReady} download={shouldDownload => runtimeEvents.exportCSV(liveRequest, shouldDownload)} />
        <DataTable rows={liveEvents} rowKey={(event) => event.row_id!} columns={liveColumns} pagination={false} manualSorting sort={{ id: liveSort, dir: liveOrder as "asc" | "desc" }} onSortChange={next => route.update({ sort: next?.id || null, order: next?.dir || null })}
          defaultDensity="compact" preferencesKey="runtime-live-events" exportFileName="runtime-events-page" testId="runtime-live-table"
          emptyState={<p className="px-3 py-6 text-sm text-muted-foreground">No runtime events match these filters.</p>} />
        {route.page > 0 && liveEvents.length === 0 && <Button onClick={() => route.setPage(0)}>First page</Button>}
        <Pager page={route.page} pageSize={100} total={liveQ.data.total} rowsOnPage={liveEvents.length} onPage={route.setPage} />
      </>}
  </section>;
  const evidenceView = withOverview(<div className="space-y-4" data-testid="runtime-event-evidence">
    <div><h2 className="text-sm font-semibold">Runtime evidence · {hours}h</h2><p className="text-xs text-muted-foreground">Latest 20 events in this window, correlated with workloads and rule evidence. Select an event to inspect it.</p></div>
    <DataTable rows={events} sourceLimit={20} sourceCount={events.length} columns={recentEventColumns} rowKey={evidenceKey} rowTestId={() => "runtime-event-row"}
      onRowClick={(event) => selectEvent(event.id, event.at)} selected={selectedEvent ? new Set([evidenceKey(selectedEvent)]) : undefined} preferencesKey="runtime-window-events" exportFileName="runtime-window-events" testId="runtime-evidence-table"
      emptyState={<p className="px-3 py-6 text-sm text-muted-foreground">No runtime events in this window.</p>} />
    {selectedEventID && !selectedEvent && <ErrorState title="The selected event cannot be resolved uniquely in the loaded cluster and time window. No other event has been substituted."
      action={<Button onClick={() => setParams((previous) => { const next = new URLSearchParams(previous); next.delete("event"); next.delete("event_at"); return next; })}>Clear event selection</Button>} />}
    {selectedEvent && <Collapse key={`${clusterId}:${evidenceKey(selectedEvent)}`} label="Selected event details" defaultOpen><RuntimeEventInspector event={selectedEvent} /></Collapse>}
    <Collapse label="Additional window evidence"><dl className="grid gap-3 text-sm sm:grid-cols-2"><Field label="ATT&CK techniques" value={String(summary?.techniques ?? "—")} /><Field label="Window" value={`${hours}h`} /></dl></Collapse>
  </div>);
  const systemsView = withOverview(<div className="space-y-4" data-testid="runtime-subsystems">
    <div><h2 className="text-sm font-semibold">Runtime subsystems</h2><p className="text-xs text-muted-foreground">Capability catalog and prerequisites. A ready feature does not confirm that its agent is deployed or enforcing in this cluster.</p></div>
    <p className="text-sm text-muted-foreground">{subsystems.filter((item) => item.status === "ready" || item.status.startsWith("ready-")).length} ready catalog features · {subsystems.filter((item) => item.status === "gated" || item.status.endsWith("-gated")).length} gated catalog features</p>
    <DataTable rows={subsystems} columns={subsystemColumns} rowKey={(item) => item.id} preferencesKey="runtime-subsystems" exportFileName="runtime-subsystems"
      emptyState={<p className="px-3 py-6 text-sm text-muted-foreground">No runtime subsystems reported.</p>} />
    <Collapse label="Learn, Monitor and Enforce modes"><div className="grid gap-3 md:grid-cols-3">{q.data?.modes.map((mode) => <section key={mode.id} className="rounded-md border border-border p-4"><div className="flex items-center justify-between"><h3 className="text-sm font-semibold">{mode.label}</h3><span className="text-xs text-muted-foreground">{mode.blocks ? "blocks" : "observe"}</span></div><p className="mt-2 text-xs text-muted-foreground">{mode.description}</p></section>)}</div></Collapse>
  </div>);
  const workloadsView = withOverview(<div className="space-y-3" data-testid="runtime-workloads"><h2 className="text-sm font-semibold">Affected workloads · {hours}h</h2><p className="text-xs text-muted-foreground">Top 10 workloads ranked by alerting events; the summary count covers the entire window.</p><DataTable rows={workloads} columns={workloadColumns} sourceLimit={10} sourceCount={workloads.length} rowKey={(item) => item.workload_id} preferencesKey="runtime-workloads" exportFileName="runtime-affected-workloads" emptyState={<p className="px-3 py-6 text-sm text-muted-foreground">No affected workloads in this window.</p>} /></div>);
  const rulesView = withOverview(<div className="space-y-3" data-testid="runtime-rules"><h2 className="text-sm font-semibold">Runtime rule catalog</h2><p className="text-xs text-muted-foreground">Catalog modes describe rule capabilities; event counts and last-triggered evidence apply to the selected {hours}h window.</p><DataTable rows={rules} columns={ruleColumns} rowKey={(item) => item.id} preferencesKey="runtime-rule-catalog" exportFileName="runtime-rule-catalog" emptyState={<p className="px-3 py-6 text-sm text-muted-foreground">No runtime rules reported.</p>} /></div>);
  const historySummary = liveReady ? liveQ.data.summary : undefined;
  const primary = tab === "live" ? historySummary ? { events: historySummary.total, alerts: historySummary.alerting, blocks: historySummary.blocks, quarantines: historySummary.quarantines, affected_workloads: historySummary.affected_workloads } : undefined : summary;
  const incomplete = tab === "live" ? liveQ.isError || liveScopeMismatch || !liveFiltersValid : q.isError;
  const refreshing = tab === "live" ? liveQ.isFetching || route.debouncing : q.isFetching;
  return <div className="space-y-6" data-testid="runtime-page" data-cluster-id={clusterId}>
    <PageHeader title="Runtime" description="Inspect reported runtime activity and enforcement evidence for this cluster." />
    <VerdictBanner status={incomplete ? "degraded" : !primary || refreshing ? "info" : primary.alerts > 0 ? "degraded" : "info"}
      title={incomplete ? "Runtime evidence is unavailable" : !primary || refreshing ? "Runtime evidence is loading or refreshing" : tab === "live" ? primary.events === 0 ? "No runtime events match these filters" : `${primary.alerts} alerting events match these filters` : summary!.events === 0 ? `No runtime events reported in the selected ${hours}h window` : `${summary!.alerts} alerting events in the selected ${hours}h window`}
      detail={tab === "live" ? "Metrics cover all matching event records across pages. Alerting includes alert, block and quarantine verdicts. These reports do not prove agent coverage or enforcement." : "Window totals reflect reported events, not proof of agent coverage. Event history covers available history separately."} />
    {tab !== "live" && summary && clusterId && <p className="text-sm"><a data-testid="runtime-alert-events-link" className="text-primary hover:underline" href={`/clusters/${encodeURIComponent(clusterId)}/timeline?${new URLSearchParams({tab:"event",verdict:"alert,block,quarantine",...(summary.window_start && timelineAfterParam(summary.window_start)?{after:summary.window_start}:{hours:String(hours)})})}`}>Browse all {hours}h alerting event records</a> <span className="text-muted-foreground">Alert, block and quarantine verdicts; full counts and matching export.</span></p>}
    <StatGrid data-testid="runtime-summary">
      <StatCard label="Events" value={primary?.events ?? "—"} icon={<Activity className="h-3.5 w-3.5" />} />
      <StatCard label="Alerts" value={primary?.alerts ?? "—"} tone={(primary?.alerts ?? 0) > 0 ? "medium" : "neutral"} icon={<Skull className="h-3.5 w-3.5" />} />
      <StatCard label="Blocks" value={primary?.blocks ?? "—"} tone={(primary?.blocks ?? 0) > 0 ? "high" : "neutral"} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
      <StatCard label="Quarantines" value={primary?.quarantines ?? "—"} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
      <StatCard label={tab === "live" ? "Identified workloads" : "Affected workloads"} value={primary?.affected_workloads ?? "—"} icon={<RadioTower className="h-3.5 w-3.5" />} />
    </StatGrid>
    {tab !== "live" && <label className="flex flex-wrap items-center gap-2 text-sm"><Clock3 className="h-4 w-4 text-muted-foreground" aria-hidden /> Evidence time window
      <select className="rounded-md border border-border bg-background px-3 py-2" value={hours} data-testid="runtime-window-select" onChange={(event) => setParams((previous) => { const next = new URLSearchParams(previous); next.set("hours", event.target.value); return next; })}>
        {WINDOWS.map((window) => <option key={window} value={window}>{window === 168 ? "7d" : `${window}h`}</option>)}
      </select><span className="text-xs text-muted-foreground">Applies to window totals and secondary evidence, not event history.</span>
    </label>}
    <Tabs value={tab} onValueChange={setTab} items={[
      { value: "live", label: "Live events", content: liveView },
      { value: "evidence", label: "Window evidence", content: evidenceView },
      { value: "subsystems", label: "Subsystems", content: systemsView },
      { value: "workloads", label: "Affected workloads", content: workloadsView },
      { value: "rules", label: "Rule catalog", content: rulesView },
    ]} />
  </div>;
}

// Column definitions for the Wave I4 live runtime events DataTable. Kept module-level so
// the component identity is stable across renders (React would otherwise reset the
// DataTable's internal sort state on every parent re-render).
type RuntimeWorkload = RuntimeOverview["workloads"][number];
const workloadColumns: Column<RuntimeWorkload>[] = [
  {id:"platform_role",header:"Platform role",kind:"text",exportHeader:"platform_role",cell:item=>item.platform_role||"Not classified",exportValue:item=>item.platform_role??""},
  { id: "workload", header: "Workload", kind: "name", code: true, wrap: true, cell: (item) => item.workload_id, sort: (a, b) => a.workload_id.localeCompare(b.workload_id) },
  { id: "events", header: "Events", kind: "count", cell: (item) => item.events, sort: (a, b) => a.events - b.events },
  { id: "alerts", header: "Alerts", kind: "count", cell: (item) => item.alerts, sort: (a, b) => a.alerts - b.alerts },
  { id: "blocks", header: "Blocks", kind: "count", cell: (item) => item.blocks, sort: (a, b) => a.blocks - b.blocks },
  { id: "severity", header: "Highest severity", kind: "status", cell: (item) => item.highest_severity, sort: (a, b) => severityOrder(a.highest_severity) - severityOrder(b.highest_severity) },
  { id: "sources", header: "Sources / ATT&CK", kind: "text", size: 240, minSize: 176, maxSize: 360, wrap: true, cell: (item) => [...item.sources, ...item.techniques].join(", ") },
  { id: "seen", header: "Last seen", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (item) => new Date(item.last_seen_at).toLocaleString(), exportValue: (item) => item.last_seen_at, sort: (a, b) => a.last_seen_at.localeCompare(b.last_seen_at) },
];
type RuntimeRule = RuntimeOverview["rules"][number];
const ruleColumns: Column<RuntimeRule>[] = [
  { id: "name", header: "Rule", kind: "name", wrap: true, cell: (item) => item.name, sort: (a, b) => a.name.localeCompare(b.name) },
  { id: "source", header: "Source", kind: "text", size: 160, minSize: 128, maxSize: 220, cell: (item) => item.source },
  { id: "severity", header: "Severity", kind: "status", cell: (item) => item.severity, sort: (a, b) => severityOrder(a.severity) - severityOrder(b.severity) },
  { id: "mode", header: "Mode", kind: "status", cell: (item) => item.mode },
  { id: "events", header: "Events", kind: "count", cell: (item) => item.event_count, sort: (a, b) => a.event_count - b.event_count },
  { id: "workloads", header: "Workloads", kind: "count", cell: (item) => item.affected_workloads, sort: (a, b) => a.affected_workloads - b.affected_workloads },
  { id: "techniques", header: "ATT&CK", kind: "badge", size: 176, minSize: 120, maxSize: 264, wrap: true, cell: (item) => item.techniques.join(", ") },
  { id: "triggered", header: "Last triggered", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (item) => item.last_triggered_at ? new Date(item.last_triggered_at).toLocaleString() : "Not triggered", exportValue: (item) => item.last_triggered_at ?? "", sort: (a, b) => (a.last_triggered_at ?? "").localeCompare(b.last_triggered_at ?? "") },
];

const liveColumns: Column<RuntimeEvent>[] = [
  {id:"platform_role",header:"Platform role",kind:"text",exportHeader:"platform_role",cell:item=>item.platform_role||"Not classified",exportValue:item=>item.platform_role??""},
  {
    id: "at",
    header: "Time",
    kind: "date",
    size: 224,
    minSize: 208,
    maxSize: 240,
    sort: () => 0,
    exportValue: event => event.at,
    cell: (e) => <span className="font-mono text-[11px]">{new Date(e.at).toLocaleString()}</span>,
  },
  {
    id: "kind",
    header: "Kind",
    kind: "status",
    size: 140,
    wrap: true,
    sort: () => 0,
    cell: (e) => <span className="font-mono text-xs">{e.kind}</span>,
  },
  { id: "source", header: "Source", kind: "text", size: 144, minSize: 112, maxSize: 200, cell: (event) => event.source, sort: () => 0 },
  { id: "verdict", header: "Verdict", kind: "status", cell: (event) => event.verdict, sort: () => 0 },
  {
    id: "workload",
    sort: () => 0,
    exportValue: event => event.workload_id,
    header: "Workload / pod",
    kind: "name",
    wrap: true,
    cell: (e) => {
      const pod = typeof e.payload?.pod === "string" ? (e.payload.pod as string) : "";
      return (
        <div>
          <div className="font-medium">{e.workload_id || pod || "—"}</div>
          {pod && e.workload_id && <div className="mt-0.5 text-xs text-muted-foreground">{pod}</div>}
          {e.container_id && (
            <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{e.container_id.slice(0, 12)}</div>
          )}
        </div>
      );
    },
  },
  { id: "node", header: "Node", kind: "name", wrap: true, sort: () => 0, cell: event => event.node_id, exportValue: event => event.node_id },
  {
    id: "namespace",
    header: "Namespace",
    kind: "id",
    sort: () => 0,
    cell: (e) => <span className="font-mono text-xs">{e.namespace || "—"}</span>,
  },
  {
    id: "attack",
    header: "ATT&CK",
    kind: "badge",
    size: 180,
    minSize: 120,
    maxSize: 260,
    wrap: true,
    cell: (e) => (
      <div className="flex flex-wrap gap-1">
        {e.attack_techniques.length === 0 ? (
          <span className="text-xs text-muted-foreground">—</span>
        ) : (
          e.attack_techniques.map((t) => (
            <span key={t} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {t}
            </span>
          ))
        )}
      </div>
    ),
  },
  {
    id: "severity",
    header: "Severity",
    kind: "status",
    size: 112,
    maxSize: 140,
    sort: () => 0,
    cell: (e) => (
      <span
        className={`rounded-md px-2 py-0.5 text-[10px] font-medium ${
          e.severity === "critical" || e.severity === "high"
            ? "bg-destructive/15 text-destructive"
            : e.severity === "medium"
            ? "bg-status-warning/15 text-status-warning"
            : "bg-muted text-muted-foreground"
        }`}
      >
        {e.severity}
      </span>
    ),
  },
];

// Subsystem status table (left column). Module-level to keep column identity
// stable across renders so DataTable's internal sort state survives.
type RuntimeSubsystem = RuntimeOverview["subsystems"][number];
const subsystemColumns: Column<RuntimeSubsystem>[] = [
  {
    id: "name",
    header: "Subsystem",
    kind: "name",
    cell: (s) => <span className="font-medium">{s.name}</span>,
    sort: (a, b) => a.name.localeCompare(b.name),
  },
  {
    id: "mode",
    header: "Mode",
    kind: "status",
    size: 160,
    wrap: true,
    cell: (s) => <span className="font-mono text-xs">{s.mode}</span>,
    sort: (a, b) => a.mode.localeCompare(b.mode),
  },
  {
    id: "status",
    header: "Status",
    kind: "status",
    size: 160,
    maxSize: 220,
    wrap: true,
    cell: (s) => <span className="rounded-md border border-border px-2 py-1 text-xs">{s.status}</span>,
    sort: (a, b) => a.status.localeCompare(b.status),
  },
  {
    id: "evidence",
    header: "Evidence",
    kind: "text",
    size: 280,
    maxSize: 640,
    grow: true,
    wrap: true,
    cell: (s) => <span className="text-xs text-muted-foreground">{s.evidence}</span>,
  },
];

function severityOrder(s: string): number {
  switch (s) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

function RuntimeEventInspector({ event }: { event: RuntimeOverview["recent_events"][number] }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4" data-testid="runtime-event-inspector">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">Event inspector</h2>
          <p className="mt-1 text-xs text-muted-foreground">{event.source} · {event.kind} · {new Date(event.at).toLocaleString()}</p>
        </div>
        <span className="rounded-md border border-border px-2 py-1 text-xs">{event.verdict}</span>
      </div>
      <dl className="mt-3 grid gap-2 text-xs">
        <Field label="Workload" value={event.workload_id} />
        <Field label="Cluster" value={event.cluster_name || event.cluster_id} />
        <Field label="Rule" value={event.rule_name || event.rule_id || "unmatched"} />
        <Field label="Severity" value={event.severity} />
      </dl>
      <p className="mt-3 text-xs text-muted-foreground">{event.message}</p>
      <div className="mt-3 flex flex-wrap gap-1">
        {event.attack_techniques.map((technique) => (
          <span key={technique} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            {technique}
          </span>
        ))}
      </div>
    </section>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border px-3 py-2">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="mt-1 font-semibold">{value}</dd>
    </div>
  );
}
