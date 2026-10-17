import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { Download, PlayCircle, Plus, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import { compliance, type ComplianceCheck, type ComplianceChecksParams, type ComplianceChecksResponse, type ComplianceExemption, type ComplianceScheduleDB } from "@/api/client";
import { BenchmarksWorkspace } from "./BenchmarksWorkspace";
import { ComplianceEvidenceInventory } from "./ComplianceEvidenceInventory";
import { useEntityClusterScope } from "./entity-detail-scope";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useInventoryRoute, ScanInventoryExport } from "./inventory-workspace";
import { Pager } from "@/components/ui/pager";
import { useRouteSearchParams } from "@/lib/route-search";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { Field, Select } from "@/components/ui/form";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { DataTable, type Column } from "@/components/ui/data-table";
import { exportQueryReady, useExportGuard } from "@/hooks/useExportGuard";

// regLabel shortens a compliance standard id to a compact badge label.
function regLabel(std: string): string {
  const s = std.toLowerCase();
  if (s.includes("pci")) return "PCI";
  if (s.includes("nist")) return "NIST";
  if (s.includes("stig")) return "STIG";
  if (s.includes("nsa") || s.includes("cisa")) return "NSA/CISA";
  if (s.includes("cis")) return "CIS";
  if (s.includes("hipaa")) return "HIPAA";
  if (s.includes("gdpr")) return "GDPR";
  if (s.includes("soc2")) return "SOC2";
  if (s.includes("iso")) return "ISO";
  return std.split(/[-.]/)[0].toUpperCase();
}

export function CompliancePage() {
  const scope = useEntityClusterScope();
  const { clusterId } = scope;
  const scopeReady = scope.ready;
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const navigate = useNavigate(); const qc = useQueryClient();
  const route = useInventoryRoute(); const search = route.params;
  const [requestedTab, setTab] = useTabParam("tab", "controls");
  const tab = ["controls", "evidence", "schedules", "benchmarks"].includes(requestedTab) ? requestedTab : "controls";
  const listPath = `/clusters/${encodeURIComponent(clusterId ?? "")}/compliance`;
  const active = search.get("framework") || "all";
  const status = search.get("status") || "all";
  const sort = search.get("sort") || "framework";
  const order = search.get("order") || "asc";
  const validFilters = ["all", "graded", "ungraded", "pass", "fail", "manual", "not_applicable", "exempted"].includes(status) && ["framework", "control", "title", "status", "severity", "evaluated"].includes(sort) && ["asc", "desc"].includes(order);
  const request: ComplianceChecksParams = { framework: active, cluster_id: clusterId, profile: search.get("profile") || undefined, control_id: search.get("control_id") || undefined, status: status === "all" ? undefined : status, q: route.debouncedQuery || undefined, sort, order: order as "asc" | "desc", limit: 100, offset: route.offset };
  const queryKey = ["compliance", "checks", owner, clusterId, request];
  const context = JSON.stringify(queryKey);
  const currentContext = useRef(context); currentContext.current = context;
  const currentReady = useRef(scopeReady); currentReady.current = scopeReady;
  const fws = useQuery({ queryKey: ["compliance", "frameworks"], queryFn: () => compliance.frameworks(), enabled: scopeReady });
  const summary = useQuery({ queryKey: ["compliance", "summary", clusterId], queryFn: () => compliance.summary(clusterId!), enabled: scopeReady });
  const checks = useQuery({ queryKey, queryFn: () => compliance.checks(request), enabled: scopeReady && validFilters && !route.debouncing });
  const invalid = Boolean(checks.data && !checksResponseMatches(checks.data, request));
  const available = scopeReady && checks.isSuccess && !route.debouncing && validFilters && !invalid;
  const checkRows = available ? checks.data!.checks : [];
  const totals = available ? checks.data!.summary! : undefined;
  const graded = totals ? totals.pass + totals.fail : 0;
  const percentage = totals && graded > 0 ? Math.round(totals.pass * 100 / graded) : undefined;
  const frameworks = useMemo(() => {
    const options = new Map((fws.isSuccess ? fws.data.frameworks : []).map(item => [item.id, item]));
    for (const item of summary.isSuccess ? summary.data.frameworks : []) if (!options.has(item.framework)) options.set(item.framework, { id: item.framework, name: `Reported framework: ${item.framework}`, category: "Reported evidence" });
    return [...options.values()];
  }, [fws.isSuccess, fws.data, summary.isSuccess, summary.data]);
  const validFramework = active === "all" || frameworks.some(item => item.id === active);
  const exemptions = useQuery({ queryKey: ["compliance", "exemptions", active, clusterId], queryFn: () => compliance.listExemptions({ framework: active === "all" ? undefined : active, cluster_id: clusterId! }), enabled: scopeReady && tab === "controls" });

  const invalidate = () => { for (const family of ["summary", "checks", "evidence", "exemptions"]) void qc.invalidateQueries({ queryKey: ["compliance", family] }); };
  const revokeExemption = useMutation({ mutationFn: (id: string) => {
    const state = qc.getQueryState<ComplianceChecksResponse>(queryKey);
    const history = qc.getQueryState<{ exemptions: ComplianceExemption[] }>(["compliance", "exemptions", active, clusterId]);
    const historyCurrent = history?.status === "success" && history.fetchStatus === "idle" && !history.isInvalidated && history.data?.exemptions.some(item => item.id === id && (!item.cluster_id || item.cluster_id === clusterId) && (active === "all" || item.framework === active) && item.status === "active" && Date.parse(item.expires_at) > Date.now());
    if (!currentReady.current || currentContext.current !== context || !scope.recheck() || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || !historyCurrent && !state.data?.checks.some(item => item.exemption?.id === id && item.cluster_id === clusterId && item.effective_status === "exempted")) throw new Error("Refresh this exact control before revoking its exemption.");
    return compliance.revokeExemption(id);
  }, onSuccess: invalidate });
  const selectFramework = (value: string) => route.update({ framework: value, control_id: null });
  const refreshControls = () => { void checks.refetch(); void summary.refetch(); void fws.refetch(); if (tab === "controls") void exemptions.refetch(); };
  const checkColumns: Column<ComplianceCheck>[] = [
    { id: "framework", header: "Framework", kind: "text", wrap: true, size: 200, minSize: 160, sort: () => 0, exportValue: item => item.framework, cell: item => frameworks.find(framework => framework.id === item.framework)?.name || item.framework },
    {
      id: "control", sort: () => 0, kind: "id", size: 160, minSize: 128, wrap: true,
      hideable: false, exportValue: (c) => c.control_id,
      header: "Control",
      cell: (c) => <span className="font-mono text-xs">{c.control_id}</span>,
    },
    {
      id: "title", sort: () => 0, kind: "text", grow: true, minSize: 280, wrap: true,
      exportValue: (c) => c.title,
      header: "Title",
      cell: (c) => (
        <div>
          <div>{c.title}</div>
          {c.evidence && (
            <div className="mt-0.5 text-xs text-muted-foreground" title={c.evidence}>
              {c.evidence}
            </div>
          )}
          {c.remediation && c.effective_status === "fail" && (
            <div className="mt-1 rounded border-l-2 border-[color:var(--color-severity-medium)] bg-muted/40 px-2 py-1 text-[11px] text-muted-foreground">
              <span className="font-medium text-foreground">Remediation: </span>{c.remediation}
            </div>
          )}
          {c.tags_v2 && Object.keys(c.tags_v2).length > 0 && (
            <div className="mt-1 flex flex-wrap items-center gap-1">
              {Object.entries(c.tags_v2).map(([std, meta]) => {
                const ref = meta?.references?.[0];
                return (
                  <span key={std} className="rounded bg-muted px-1.5 py-px text-[9px] font-medium text-muted-foreground" title={meta?.description || std}>
                    {regLabel(std)}{ref ? ` ${ref}` : ""}
                  </span>
                );
              })}
            </div>
          )}
          {c.exemption && (
            <div className="mt-1 text-xs text-muted-foreground">
              Exempt until {formatDateTime(c.exemption.expires_at)} · {c.exemption.reason}
            </div>
          )}
        </div>
      ),
    },
    {
      id: "status", sort: () => 0, kind: "status", size: 120, minSize: 104,
      exportValue: (c) => c.effective_status ?? c.status,
      header: "Status",
      cell: (c) => {
        const effectiveStatus = c.effective_status ?? c.status;
        return (
          <span className={`rounded-md px-1.5 py-0.5 text-xs ${statusClass(effectiveStatus)}`}>
            {effectiveStatus}
          </span>
        );
      },
    },
    {
      id: "severity", sort: () => 0, kind: "badge", size: 112, minSize: 104,
      exportValue: (c) => c.severity,
      header: "Severity",
      cell: (c) => <span className="text-xs text-muted-foreground">{c.severity}</span>,
    },
    { id: "evaluated", header: "Evaluated", kind: "date", size: 224, minSize: 208, maxSize: 240, sort: () => 0, cell: item => formatDateTime(item.evaluated_at), exportValue: item => item.evaluated_at },
    {
      id: "action", kind: "actions", size: 136, minSize: 128,
      hideable: false, exportable: false,
      header: "Action",
      cell: (c) => {
        const effectiveStatus = c.effective_status ?? c.status;
        return effectiveStatus === "exempted" && c.exemption ? (
          <button
            type="button"
            onClick={() => revokeExemption.mutate(c.exemption!.id)}
            disabled={!available || revokeExemption.isPending || checks.isError || checks.isFetching || exemptions.isError || exemptions.isFetching}
            className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
          >
            <Trash2 className="h-3 w-3" aria-hidden />
            Revoke
          </button>
        ) : c.status === "fail" ? (
          <button
            type="button"
            onClick={() => {
              const next = new URLSearchParams(search); next.set("framework", c.framework); next.set("control_id", c.control_id); next.set("tab", "controls");
              navigate({ href: `${listPath}/exemptions/new?${next}` });
            }}
            disabled={!available || checks.isFetching}
            className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent"
          >
            <ShieldAlert className="h-3 w-3" aria-hidden />
            Exempt
          </button>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        );
      },
    },
  ];

  return <div className="space-y-6" data-testid="compliance-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title="Compliance" description="Review persisted control evidence across frameworks, inspect supporting sources and configure recurring reports for this cluster." />
    {!scopeReady ? scope.loading ? <LoadingState label="Loading cluster…" /> : <ErrorState title="The selected cluster could not be resolved. Review its registration and retry." action={<Button onClick={scope.retry}>Retry cluster</Button>} /> : <>
      {tab === "controls" && <>
      <VerdictBanner status={!validFilters || checks.isError || invalid ? "degraded" : !available || percentage === undefined ? "info" : totals!.fail > 0 ? "degraded" : "ok"}
        title={!validFilters ? "The requested compliance filter or sort is invalid" : checks.isError || invalid ? "Compliance evidence is unavailable" : !available ? "Loading compliance evidence" : !totals!.total ? "No evidence rows match these filters" : totals!.fail > 0 ? `${totals!.fail} failing evidence rows need review` : graded > 0 ? "Graded evidence has no active failures" : "No graded controls in this cohort"}
        detail="Graded pass percentage is passing / (passing + failing). Active exemptions, manual review, not applicable and unrecognized statuses are excluded. Evidence rows and framework mappings are counted separately; these counts do not deduplicate controls." />
      <StatGrid data-testid="compliance-summary">
        <StatCard label="Graded pass" value={!totals ? "—" : percentage === undefined ? "—" : `${percentage}%`} icon={<ShieldCheck className="h-3.5 w-3.5" />} />
        <StatCard label="Passing" value={totals?.pass ?? "—"} />
        <StatCard label="Failing" value={totals?.fail ?? "—"} tone={totals && totals.fail > 0 ? "high" : "neutral"} />
        <StatCard label="Matching evidence rows" value={totals?.total ?? "—"} />
        <StatCard label="Ungraded" value={totals?.ungraded ?? "—"} hint="outside pass / fail denominator" />
      </StatGrid>
      </>}
      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "controls", label: "Controls", content: <div className="space-y-5">
          <div className="flex flex-wrap items-end gap-3">
            <Field label="Framework" htmlFor="compliance-framework" className="min-w-56 flex-1"><Select id="compliance-framework" value={active} onChange={event => selectFramework(event.target.value)}><option value="all">All frameworks</option>{!validFramework && <option value={active}>Reported framework: {active}</option>}{Object.entries(groupBy(frameworks, framework => framework.category)).map(([category, items]) => <optgroup key={category} label={category}>{items!.map(framework => <option key={framework.id} value={framework.id}>{framework.name}</option>)}</optgroup>)}</Select></Field>
            <Field label="Status cohort" htmlFor="compliance-status"><Select id="compliance-status" value={status} onChange={event => route.update({ status: event.target.value === "all" ? null : event.target.value })}>{["all", "graded", "ungraded", "pass", "fail", "manual", "not_applicable", "exempted"].map(value => <option key={value} value={value}>{value === "all" ? "All evidence statuses" : value === "graded" ? "Graded: pass or fail" : value.replaceAll("_", " ")}</option>)}</Select></Field>
            <Field label="Search control evidence" htmlFor="compliance-search" className="min-w-64 flex-1"><input id="compliance-search" className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" value={route.query} onChange={event => route.setQuery(event.target.value)} placeholder="Framework, control, title or evidence" /></Field>
            <Button disabled={checks.isFetching || !validFilters || route.debouncing} onClick={refreshControls}>Refresh controls</Button>
          </div>
          {search.get("profile") && <p className="text-sm text-muted-foreground">Profile mapping filter: {search.get("profile")} <Button size="sm" onClick={() => route.update({ profile: null })}>Clear profile</Button></p>}
          {search.get("control_id") && <p className="text-sm text-muted-foreground">Exact control filter: {search.get("control_id")} <Button size="sm" onClick={() => route.update({ control_id: null })}>Clear control</Button></p>}
          {(fws.isError || summary.isError) && <ErrorState title="Framework labels or the source summary could not be refreshed. The control table uses its own scoped source." action={<Button onClick={() => { void fws.refetch(); void summary.refetch(); }}>Retry framework sources</Button>} />}
          {!validFilters ? <ErrorState title="Choose a supported status or sort before loading controls." action={<Button onClick={() => route.update({ status: null, sort: null, order: null })}>Reset filters and sort</Button>} /> : checks.isError || invalid ? <ErrorState title="Controls could not be loaded or refreshed. Evidence and export are unavailable." action={<Button onClick={() => void checks.refetch()}>Retry controls</Button>} /> : !available ? <LoadingState label="Loading controls…" /> : <>
            {checks.isFetching && <p role="status" className="text-sm text-muted-foreground">Refreshing control evidence…</p>}
            <section className="space-y-4" data-testid="framework-detail">
              <p className="text-sm text-muted-foreground">{totals!.total.toLocaleString()} evidence rows match the server filters across {active === "all" ? "all reported frameworks" : active}. Metrics cover all matches. Matching CSV covers up to 100,000 rows across pages, independent of visible columns.</p>
              <ScanInventoryExport context={context} disabled={checks.isFetching} download={shouldDownload => compliance.exportChecksCSV(request, shouldDownload)} />
              {revokeExemption.isError && <p role="alert" className="text-sm text-status-error">Could not revoke this exemption. Refresh the controls and try again.</p>}
              <DataTable rows={checkRows} columns={checkColumns} rowKey={item => item.id!} preferencesKey="compliance-controls" testId="compliance-controls-table" pagination={false} manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })} emptyState={<EmptyState title="No evaluated controls match these filters" hint="This is a filtered evidence cohort, not a claim that the cluster has no compliance checks." />} />
              {route.page > 0 && checkRows.length === 0 && <Button onClick={() => route.setPage(0)}>First page</Button>}
              <Pager page={route.page} pageSize={100} rowsOnPage={checkRows.length} total={totals!.total} onPage={route.setPage} />
              <Collapse label="Advanced: status counts and exemption history">
                <p className="text-sm text-muted-foreground">Within the selected filters: {totals!.manual} manual · {totals!.exempted} exempted · {totals!.not_applicable} not applicable. Exemption history describes decisions and does not change this cohort’s denominator.</p>
                {exemptions.isPending ? <LoadingState label="Loading exemptions…" /> : exemptions.isError ? <ErrorState title="Exemption history could not be refreshed." action={<Button onClick={() => void exemptions.refetch()}>Retry exemptions</Button>} /> : exemptions.isSuccess && (exemptions.data.exemptions.length ? <ComplianceExemptionsList exemptions={exemptions.data.exemptions.filter(item => !item.cluster_id || item.cluster_id === clusterId)} onRevoke={id => revokeExemption.mutate(id)} pending={checks.isFetching || exemptions.isFetching || revokeExemption.isPending} /> : <EmptyState title="No exemption history" />)}
              </Collapse>
            </section>
          </>}
        </div> },
        { value: "evidence", label: "Source evidence", content: <ComplianceEvidenceInventory clusterId={clusterId!} ready={scopeReady} active={tab === "evidence"} /> },
        { value: "benchmarks", label: "Benchmarks", content: <BenchmarksWorkspace active={tab === "benchmarks"} /> },
        { value: "schedules", label: "Schedules", content: <SchedulesManager clusterId={clusterId!} listPath={listPath} scopeReady={scopeReady} /> },
      ]} />
    </>}
  </div>;
}

function checksResponseMatches(data: ComplianceChecksResponse, request: ComplianceChecksParams) {
  const total = data.total, rows = data.checks;
  const keys = ["total", "pass", "fail", "manual", "exempted", "not_applicable", "graded", "ungraded"];
  if (!Array.isArray(rows) || data.cluster_id !== request.cluster_id || data.framework !== (request.framework === "all" ? "" : request.framework || "") || data.status !== (request.status || "") || data.profile !== (request.profile || "") || data.control_id !== (request.control_id || "") || data.q !== (request.q || "").trim() || data.limit !== 100 || data.offset !== request.offset || data.sort !== request.sort || data.order !== request.order || !Number.isSafeInteger(total) || total! < 0 || !keys.every(key => Number.isSafeInteger(data.summary?.[key]) && data.summary![key] >= 0) || data.summary!.total !== total || data.summary!.graded !== data.summary!.pass + data.summary!.fail || total !== data.summary!.graded + data.summary!.ungraded || rows.length !== Math.min(100, Math.max(0, total! - request.offset!)) || data.has_more !== (total! > request.offset! + rows.length)) return false;
  const ids = new Set<string>();
  return rows.every(row => { if (!row.id?.trim() || ids.has(row.id) || row.cluster_id !== request.cluster_id || request.framework && request.framework !== "all" && row.framework !== request.framework || request.control_id && row.control_id !== request.control_id || request.status === "graded" && !["pass", "fail"].includes(row.effective_status) || request.status === "ungraded" && ["pass", "fail"].includes(row.effective_status) || request.status && !["graded", "ungraded"].includes(request.status) && row.effective_status !== request.status) return false; ids.add(row.id); return true; });
}

function ComplianceExemptionsList({
  exemptions,
  onRevoke,
  pending,
}: {
  exemptions: ComplianceExemption[];
  onRevoke: (id: string) => void;
  pending: boolean;
}) {
  return (
    <section className="mt-4 rounded-md border border-border bg-background p-3" data-testid="compliance-exemptions-list">
      <h3 className="text-sm font-semibold">Exemptions</h3>
      <div className="mt-2 space-y-2">
        {exemptions.map((item) => (
          <div key={item.id} className="flex items-start justify-between gap-3 rounded-md border border-border/70 p-2 text-xs">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono">{item.framework} · {item.control_id}</span>
                <span className="text-muted-foreground">{item.cluster_id ? "Cluster exemption" : "Organization-wide exemption"}</span>
                <span className={`rounded-md px-1.5 py-0.5 ${statusClass(item.status === "active" ? "exempted" : "manual")}`}>
                  {item.status}
                </span>
                <span className="text-muted-foreground">expires {formatDateTime(item.expires_at)}</span>
              </div>
              <div className="mt-1 truncate text-muted-foreground" title={item.reason}>{item.reason}</div>
            </div>
            {item.status === "active" && (
              <button
                type="button"
                onClick={() => onRevoke(item.id)}
                disabled={pending}
                className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border px-2 py-1 hover:bg-accent disabled:opacity-50"
              >
                <Trash2 className="h-3 w-3" aria-hidden />
                Revoke
              </button>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}


function SchedulesManager({ clusterId, listPath, scopeReady }: { clusterId: string; listPath: string; scopeReady: boolean }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [search] = useRouteSearchParams();
  const [activeRunsFor, setActiveRunsFor] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["compliance", "db-schedules", clusterId], queryFn: () => compliance.listDBSchedules(clusterId), enabled: scopeReady });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["compliance", "db-schedules", clusterId] });
  const runNow = useMutation({ mutationFn: (id: string) => compliance.runScheduleNow(id), onSuccess: () => { void invalidate(); void qc.invalidateQueries({ queryKey: ["compliance", "schedule-runs"] }); } });
  const remove = useMutation({ mutationFn: (id: string) => compliance.deleteSchedule(id), onSuccess: () => void invalidate() });
  const rows = (list.data?.schedules ?? []).filter((schedule) => !schedule.cluster_id || schedule.cluster_id === clusterId);
  const busy = !scopeReady || list.isError || list.isFetching || runNow.isPending || remove.isPending;
  return <section className="space-y-4" data-testid="compliance-schedules-manager">
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-lg font-semibold">Scheduled compliance runs</h2><p className="text-sm text-muted-foreground">Includes schedules configured for this cluster and inherited organization schedules. Review run history to confirm execution, signatures, and artifact delivery.</p><p className="mt-1 text-xs text-muted-foreground">{list.data ? `${rows.length} configured · ${rows.filter((schedule) => schedule.enabled).length} enabled · ${rows.filter((schedule) => !schedule.enabled).length} disabled` : "Schedule counts unavailable"}</p></div><div className="flex gap-2"><Button variant="outline" onClick={() => void list.refetch()} disabled={!scopeReady || list.isFetching}>Refresh</Button><Button disabled={!scopeReady} data-testid="schedule-create-open" onClick={() => { const next = new URLSearchParams(search); next.set("tab", "schedules"); navigate({ href: `${listPath}/schedules/new?${next}` }); }}><Plus className="mr-1 h-4 w-4" /> New schedule</Button></div></div>
    {list.isPending && <LoadingState label="Loading schedules…" />}
    {list.isError && <ErrorState title={list.data ? "Could not refresh schedules. Showing the last loaded configuration." : "Schedules could not be loaded."} action={<Button onClick={() => void list.refetch()}>Retry</Button>} />}
    {(runNow.isError || remove.isError) && <p role="alert" className="text-sm text-status-error">Could not update the schedule. Refresh and try again.</p>}
    {runNow.data && <p role="status" className="text-sm">{runNow.data.queued ? "Compliance run queued. Review History for its result." : "The service did not queue a new run. Review History before retrying."}</p>}
    <div className="space-y-3" data-testid="schedule-list">{list.data && rows.length === 0 && <EmptyState title="No compliance schedules" hint="Create a schedule to configure recurring evidence reports." />}{rows.map((schedule) => <ScheduleRow key={schedule.id} schedule={schedule} running={runNow.isPending && runNow.variables === schedule.id} unavailable={busy} onRunNow={() => { runNow.reset(); remove.reset(); runNow.mutate(schedule.id); }} onDelete={() => { runNow.reset(); remove.reset(); remove.mutate(schedule.id); }} onToggleRuns={() => setActiveRunsFor(activeRunsFor === schedule.id ? null : schedule.id)} runsOpen={activeRunsFor === schedule.id} />)}</div>
  </section>;
}

function ScheduleRow({
  schedule,
  running,
  unavailable,
  onRunNow,
  onDelete,
  onToggleRuns,
  runsOpen,
}: {
  schedule: ComplianceScheduleDB;
  running: boolean;
  unavailable: boolean;
  onRunNow: () => void;
  onDelete: () => void;
  onToggleRuns: () => void;
  runsOpen: boolean;
}) {
  const identity = useTablePreferencesIdentity();
  const qc = useQueryClient();
  const runKey = ["compliance", "schedule-runs", schedule.id, identity?.org_id, identity?.user_id];
  const runs = useQuery({
    queryKey: runKey,
    queryFn: () => compliance.scheduleRuns(schedule.id, 25).then(response => {
      if (!Array.isArray(response.runs) || response.runs.some(run => run.org_id !== identity?.org_id || run.schedule_id && run.schedule_id !== schedule.id)) throw new Error("Run history does not match the reviewed schedule");
      return response;
    }),
    enabled: runsOpen && !unavailable && !!identity?.org_id && !!identity.user_id,
  });
  const current = () => !!identity?.org_id && !!identity.user_id && !unavailable && exportQueryReady(qc, runKey, runs.data) && !!runs.data?.runs.every(run => run.org_id === identity.org_id);
  const captureDownload = useExportGuard(JSON.stringify(runKey), !current(), current);
  return (
    <article className="rounded-lg border border-border bg-card p-3" data-testid={`schedule-${schedule.id}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-0.5">
          <h3 className="text-sm font-semibold">{schedule.name}</h3>
          <p className="text-xs text-muted-foreground">
            {schedule.framework} · <code>{schedule.cron_expression}</code> {schedule.timezone} ·{" "}
            {schedule.report_format}
          </p>
          <p className="text-xs font-medium">{schedule.cluster_id ? "Cluster schedule" : "Organization schedule · applies across clusters"}</p>
          {schedule.description && (
            <p className="text-xs text-muted-foreground">{schedule.description}</p>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className={`rounded-md px-2 py-0.5 text-xs ${
              schedule.last_status === "succeeded"
                ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
                : schedule.last_status === "failed"
                  ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
                  : "bg-muted text-muted-foreground"
            }`}
          >
            {schedule.last_status || "No runs yet"}
          </span>
          <button
            type="button"
            onClick={onRunNow}
            disabled={running || unavailable}
            data-testid={`schedule-run-${schedule.id}`}
            className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent disabled:opacity-50"
          >
            <span className="inline-flex items-center gap-1.5">
              <PlayCircle className="h-3.5 w-3.5" aria-hidden />
              Run now
            </span>
          </button>
          <button
            type="button"
            onClick={onToggleRuns}
            disabled={unavailable}
            data-testid={`schedule-runs-toggle-${schedule.id}`}
            className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent"
          >
            History
          </button>
          <button
            type="button"
            disabled={running || unavailable}
            onClick={() => {
              if (window.confirm(`Delete schedule "${schedule.name}"?`)) onDelete();
            }}
            data-testid={`schedule-delete-${schedule.id}`}
            className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent"
            aria-label="Delete schedule"
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
          </button>
        </div>
      </div>

      <div className="mt-2 grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
        <Info label="Next run" value={schedule.next_run_at ? new Date(schedule.next_run_at).toLocaleString() : "—"} />
        <Info label="Last run" value={schedule.last_run_at ? new Date(schedule.last_run_at).toLocaleString() : "—"} />
        <Info label="Delivery" value={schedule.delivery.map((d) => d.kind).join(", ") || "none"} />
        <Info label="Template" value={schedule.report_template} />
      </div>

      {runsOpen && (
        <div className="mt-3 rounded-md border border-border bg-background p-2" data-testid={`schedule-runs-${schedule.id}`}>
          <p className="text-xs text-muted-foreground">Latest 25 loaded runs for this schedule. CSV contains run metadata; artifact downloads remain separate.</p>
          {runs.isError && <ErrorState title="Run history could not be loaded." action={<Button onClick={() => void runs.refetch()}>Retry</Button>} />}
          {runs.isPending && <p className="text-xs text-muted-foreground">Loading runs…</p>}
          {!runs.isError && !runs.isFetching && runs.data && runs.data.runs.length === 0 && (
            <p className="text-xs text-muted-foreground">No runs recorded yet.</p>
          )}
          {!runs.isError && !runs.isFetching && runs.data && runs.data.runs.length > 0 && (
            <DataTable
              rows={runs.data.runs}
              rowKey={(run) => run.id}
              preferencesKey="compliance-schedule-run-history"
              canExport={current}
              exportFileName={`constellation-compliance-schedule-${schedule.id}-loaded-runs`}
              exportLabel="Export loaded run metadata CSV"
              sourceLimit={25} sourceCount={runs.data.runs.length}
              columns={[
                { id: "started", exportValue: run => run.started_at, header: "Started", kind: "date", size: 192, minSize: 176, cell: (run) => new Date(run.started_at).toLocaleString() },
                { id: "status", exportValue: run => run.status, header: "Status", kind: "status", size: 144, minSize: 128, cell: (run) => <span className={`rounded-md px-1.5 py-0.5 text-[10px] ${run.status === "succeeded" ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]" : run.status === "failed" ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]" : "bg-muted text-muted-foreground"}`}>{run.status}</span> },
                { id: "summary", exportValue: run => `${run.summary.pass ?? 0} / ${run.summary.fail ?? 0} / ${run.summary.manual ?? 0}`, header: "Pass / Fail / Manual", kind: "count", numeric: true, size: 184, minSize: 176, cell: (run) => `${run.summary.pass ?? 0} / ${run.summary.fail ?? 0} / ${run.summary.manual ?? 0}` },
                { id: "signature", exportValue: run => run.artifact_signature || "Not recorded", header: "Signature", kind: "status", size: 176, minSize: 160, cell: (run) => run.artifact_signature ? <span title={run.artifact_signature} className="rounded bg-[color:var(--color-status-success)]/15 px-1.5 py-0.5 text-[color:var(--color-status-success)]">Signature recorded</span> : <span className="text-muted-foreground">—</span> },
                { id: "format", header: "Artifact format", kind: "status", cell: run => run.artifact_metadata_known && run.artifact_format ? run.artifact_format.toUpperCase() : "Not recorded", exportValue: run => run.artifact_metadata_known ? run.artifact_format ?? "" : "Not recorded" },
                { id: "artifact", exportable: false, header: "Artifact", kind: "actions", size: 160, minSize: 144, cell: (run) => run.artifact_uri ? <button type="button" disabled={!current()} title={run.artifact_filename || undefined} onClick={() => compliance.downloadRunArtifact(run.id, captureDownload()).catch(() => toast.error("Artifact download failed or its reviewed scope changed. Refresh before retrying."))} className="inline-flex items-center gap-1 text-foreground hover:underline" data-testid={`run-download-${run.id}`}><Download className="h-3 w-3" aria-hidden /> {run.artifact_uri.startsWith("s3://") ? "Download metadata" : "Download"}</button> : <span className="text-muted-foreground">—</span> },
              ]}
            />
          )}
        </div>
      )}
    </article>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
      <div className="mt-1">{value}</div>
    </div>
  );
}

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function statusClass(status: string) {
  switch (status) {
    case "pass": return "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]";
    case "fail": return "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]";
    case "exempted": return "bg-[color:var(--color-status-info)]/15 text-[color:var(--color-status-info)]";
    case "manual": return "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]";
    default: return "bg-muted text-muted-foreground";
  }
}


function groupBy<T>(items: T[], key: (item: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const item of items) { const category = key(item); (out[category] ||= []).push(item); }
  return out;
}
