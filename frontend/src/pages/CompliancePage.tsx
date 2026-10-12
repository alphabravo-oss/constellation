import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { Download, PlayCircle, Plus, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import { compliance, type ComplianceCheck, type ComplianceEvidenceItem, type ComplianceEvidenceResponse, type ComplianceExemption, type ComplianceScheduleDB } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { Field, Select } from "@/components/ui/form";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { DataTable, type Column } from "@/components/ui/data-table";
import { downloadCsv } from "@/lib/csv";

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
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const resolvedScope = !!clusterId && cluster?.id === clusterId;
  const scopeReady = resolvedScope && !clusterLoading && !clusterError;
  const navigate = useNavigate();
  const [search, setSearch] = useRouteSearchParams();
  const [requestedTab, setTab] = useTabParam("tab", "frameworks");
  const tab = ["frameworks", "evidence", "schedules"].includes(requestedTab) ? requestedTab : "frameworks";
  const listPath = `/clusters/${encodeURIComponent(clusterId ?? "")}/compliance`;
  const fws = useQuery({ queryKey: ["compliance", "frameworks"], queryFn: () => compliance.frameworks(), enabled: scopeReady });
  const summary = useQuery({ queryKey: ["compliance", "summary", clusterId], queryFn: () => compliance.summary(clusterId!), enabled: scopeReady });
  const active = search.get("framework") ?? fws.data?.frameworks[0]?.id ?? null;
  const validFramework = !!active && !!fws.data?.frameworks.some((framework) => framework.id === active);
  const checks = useQuery({ queryKey: ["compliance", "checks", active, clusterId], queryFn: () => compliance.checks(active!, clusterId!), enabled: scopeReady && validFramework && tab === "frameworks" });
  const checkRows = useMemo(() => {
    const occurrences = new Map<string, number>();
    return (checks.data?.checks ?? []).map((check) => {
      // The checks endpoint returns evidence rows without a server row ID;
      // several rows can legitimately share the same framework/control tuple.
      const identity = JSON.stringify([check.framework, check.control_id, check.title, check.evidence, check.evaluated_at]);
      const occurrence = occurrences.get(identity) ?? 0;
      occurrences.set(identity, occurrence + 1);
      return { ...check, evidenceRowKey: JSON.stringify([identity, occurrence]) };
    });
  }, [checks.data]);
  const exemptions = useQuery({ queryKey: ["compliance", "exemptions", active, clusterId], queryFn: () => compliance.listExemptions({ framework: active!, cluster_id: clusterId! }), enabled: scopeReady && validFramework && tab === "frameworks" });
  const evidence = useQuery({ queryKey: ["compliance", "evidence", clusterId], queryFn: () => compliance.evidence({ cluster_id: clusterId!, limit: 500 }), enabled: scopeReady && tab === "evidence" });
  const schedules = useQuery({ queryKey: ["compliance", "db-schedules", clusterId], queryFn: () => compliance.listDBSchedules(clusterId!), enabled: scopeReady && tab === "schedules" });
  const qc = useQueryClient();
  const retryScope = () => { void qc.invalidateQueries({ queryKey: ["clusters"] }); void qc.invalidateQueries({ queryKey: ["cluster", clusterId] }); };
  const totals = useMemo(() => (summary.data?.frameworks ?? []).reduce((acc, item) => ({ total: acc.total + item.total, pass: acc.pass + item.pass, fail: acc.fail + item.fail, manual: acc.manual + item.manual, exempted: acc.exempted + (item.exempted ?? 0) }), { total: 0, pass: 0, fail: 0, manual: 0, exempted: 0 }), [summary.data]);
  const invalidate = () => {
    for (const family of ["summary", "checks", "evidence", "exemptions"]) void qc.invalidateQueries({ queryKey: ["compliance", family] });
  };
  const revokeExemption = useMutation({ mutationFn: (id: string) => compliance.revokeExemption(id), onSuccess: invalidate });
  const selectFramework = (value: string) => { const next = new URLSearchParams(search); next.set("framework", value); setSearch(next); };
  const selectedSummary = summary.data?.frameworks.find((item) => item.framework === active);
  const workspaceFailed = !scopeReady || summary.isError || fws.isError || (tab === "frameworks" && checks.isError) || (tab === "evidence" && evidence.isError) || (tab === "schedules" && schedules.isError);
  const checkColumns: Column<ComplianceCheck>[] = [
    {
      id: "control", kind: "id", size: 160, minSize: 128, wrap: true,
      hideable: false, exportValue: (c) => c.control_id,
      header: "Control",
      cell: (c) => <span className="font-mono text-xs">{c.control_id}</span>,
    },
    {
      id: "title", kind: "text", grow: true, minSize: 280, wrap: true,
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
      id: "status", kind: "status", size: 120, minSize: 104,
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
      id: "severity", kind: "badge", size: 112, minSize: 104,
      exportValue: (c) => c.severity,
      header: "Severity",
      cell: (c) => <span className="text-xs text-muted-foreground">{c.severity}</span>,
    },
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
            disabled={!scopeReady || revokeExemption.isPending || checks.isError || checks.isFetching || exemptions.isError || exemptions.isFetching}
            className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
          >
            <Trash2 className="h-3 w-3" aria-hidden />
            Revoke
          </button>
        ) : c.status === "fail" ? (
          <button
            type="button"
            onClick={() => {
              const next = new URLSearchParams(search); next.set("framework", c.framework); next.set("control_id", c.control_id); next.set("tab", "frameworks");
              navigate({ href: `${listPath}/exemptions/new?${next}` });
            }}
            disabled={!scopeReady || checks.isError || checks.isFetching}
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
    <PageHeader title="Compliance" description="Review evaluated security controls, inspect supporting evidence, and configure recurring reports for this cluster." />
    {clusterLoading && !resolvedScope ? <LoadingState label="Loading cluster…" /> : !clusterId ? <ErrorState title="Select a cluster to review compliance." /> : !resolvedScope ? <ErrorState title="The selected cluster could not be resolved. Review its registration and retry." action={<Button onClick={retryScope}>Retry cluster</Button>} /> : <>
      {!scopeReady && <ErrorState title="Current cluster scope is unavailable. Showing the last loaded results; actions are paused." action={<Button onClick={retryScope}>Retry cluster</Button>} />}
      <VerdictBanner status={workspaceFailed ? "degraded" : !summary.data || totals.total === 0 ? "info" : totals.fail > 0 ? "degraded" : "ok"}
        title={workspaceFailed ? "Compliance data could not be refreshed" : !summary.data ? "Loading evaluated compliance checks" : totals.total === 0 ? "No compliance checks evaluated" : totals.fail > 0 ? `${totals.fail} compliance checks need review` : "Evaluated checks have no active failures"}
        detail="Results describe collected evidence. Exemptions are time-bound acceptances; schedules describe report configuration and do not confirm execution or delivery." />
      <section className="grid grid-cols-2 gap-3 lg:grid-cols-5" data-testid="compliance-summary">
        <StatCard label="Evaluated checks" value={summary.data ? totals.total : "—"} />
        <StatCard label="Passing" value={summary.data ? totals.pass : "—"} icon={<ShieldCheck className="h-3.5 w-3.5" />} />
        <StatCard label="Failing" value={summary.data ? totals.fail : "—"} tone={summary.data && totals.fail > 0 ? "high" : "neutral"} />
        <StatCard label="Manual review" value={summary.data ? totals.manual : "—"} />
        <StatCard label="Exempted" value={summary.data ? totals.exempted : "—"} />
      </section>
      {summary.isError && <ErrorState title={summary.data ? "Could not refresh totals. Showing the last loaded summary." : "Compliance totals are unavailable."} action={<Button onClick={() => void summary.refetch()}>Retry</Button>} />}
      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "frameworks", label: "Frameworks", count: fws.data?.frameworks.length, content: <div className="space-y-5">
          {fws.isPending && <LoadingState label="Loading frameworks…" />}
          {fws.isError && <ErrorState title="Current compliance frameworks could not be loaded." action={<Button onClick={() => void fws.refetch()}>Retry</Button>} />}
          {fws.data && fws.data.frameworks.length === 0 && <EmptyState title="No compliance frameworks" hint="No frameworks are available for this cluster." />}
          {fws.data && fws.data.frameworks.length > 0 && <>
            <Field label="Framework" htmlFor="compliance-framework">
              <Select id="compliance-framework" value={active ?? ""} onChange={(event) => selectFramework(event.target.value)}>{!validFramework && <option value={active ?? ""}>Unknown framework</option>}{Object.entries(groupBy(fws.data.frameworks, (framework) => framework.category)).map(([category, items]) => <optgroup key={category} label={category}>{items!.map((framework) => <option key={framework.id} value={framework.id}>{framework.name}</option>)}</optgroup>)}</Select>
            </Field>
            {!validFramework ? <ErrorState title="This framework is unavailable. Select an available framework." /> : <section className="space-y-4 rounded-lg border border-border bg-card p-4" data-testid="framework-detail">
              <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-lg font-medium">{fws.data.frameworks.find((framework) => framework.id === active)?.name}</h2><p className="text-xs text-muted-foreground">{selectedSummary ? `${selectedSummary.fail} failing · ${selectedSummary.total} evaluated · ${selectedSummary.effective_pass_pct ?? selectedSummary.pass_pct}% effective pass` : "Framework summary unavailable"}</p></div><Button variant="outline" size="sm" disabled={!scopeReady || checks.isFetching} onClick={() => { void checks.refetch(); void exemptions.refetch(); }}>Refresh controls</Button></div>
              {checks.isPending && <LoadingState label="Loading controls…" />}
              {checks.isError && <ErrorState title={checks.data ? "Could not refresh controls. Showing the last loaded results." : "Controls could not be loaded."} action={<Button onClick={() => void checks.refetch()}>Retry</Button>} />}
              {revokeExemption.isError && <p role="alert" className="text-sm text-status-error">Could not revoke this exemption. Refresh the controls and try again.</p>}
              {checks.data && <>
                <div className="flex justify-end"><Button variant="outline" size="sm" onClick={() => downloadCsv(`constellation-compliance-${active}`, ["Framework", "Control", "Title", "Status", "Severity", "Standards", "Evidence"], checks.data!.checks.map((check) => [check.framework, check.control_id, check.title, check.effective_status ?? check.status, check.severity, Object.keys(check.tags_v2 ?? {}).map(regLabel).join(" "), check.evidence]))}>Export controls CSV</Button></div>
                <DataTable<ComplianceCheck & { evidenceRowKey: string }> rows={checkRows} columns={checkColumns} rowKey={(check) => check.evidenceRowKey} preferencesKey="compliance-controls" testId="compliance-controls-table" emptyState={<EmptyState title="No evaluated controls" hint="Collected results will appear here after this framework runs." />} />
              </>}
              <Collapse label="Advanced: exemption history">
                {exemptions.isPending && <LoadingState label="Loading exemptions…" />}
                {exemptions.isError && <ErrorState title="Exemption history could not be refreshed." action={<Button onClick={() => void exemptions.refetch()}>Retry</Button>} />}
                {exemptions.data && (exemptions.data.exemptions.length > 0 ? <ComplianceExemptionsList exemptions={exemptions.data.exemptions.filter((item) => !item.cluster_id || item.cluster_id === clusterId)} onRevoke={(id) => revokeExemption.mutate(id)} pending={!scopeReady || revokeExemption.isPending || exemptions.isError} /> : <EmptyState title="No exemption history" />)}
              </Collapse>
            </section>}
          </>}
        </div> },
        { value: "evidence", label: "Evidence", content: <EvidencePanel data={evidence.data} isPending={evidence.isPending} isError={evidence.isError} onRetry={() => void evidence.refetch()} /> },
        { value: "schedules", label: "Schedules", content: <SchedulesManager clusterId={clusterId} listPath={listPath} scopeReady={scopeReady} /> },
      ]} />
    </>}
  </div>;
}

const evidenceColumns: Column<ComplianceEvidenceItem>[] = [
  {
    id: "scope", kind: "status", size: 112, minSize: 96,
    exportValue: (item) => item.scope,
    header: "Scope",
    cell: (item) => <span className="text-xs text-muted-foreground">{item.scope}</span>,
  },
  {
    id: "target", kind: "name", grow: true, minSize: 200, wrap: true,
    exportValue: (item) => item.target,
    header: "Target",
    cell: (item) => (
      <>
        <div className="font-medium" title={item.target}>{item.target}</div>
        <div className="text-xs text-muted-foreground">{item.target_kind}</div>
      </>
    ),
  },
  {
    id: "control", kind: "id", size: 160, minSize: 128, wrap: true,
    exportValue: (item) => `${item.framework} · ${item.control_id}`,
    header: "Control",
    cell: (item) => (
      <>
        <div className="font-mono text-xs">{item.framework} · {item.control_id}</div>
        <div className="text-xs text-muted-foreground" title={item.title}>{item.title}</div>
      </>
    ),
  },
  {
    id: "status", kind: "status", size: 120, minSize: 104,
    exportValue: (item) => item.effective_status ?? item.status,
    header: "Status",
    cell: (item) => {
      const status = item.effective_status ?? item.status;
      return (
        <span className={`rounded-md px-1.5 py-0.5 text-xs ${statusClass(status)}`}>
          {status}
        </span>
      );
    },
  },
  {
    id: "evidence", kind: "text", grow: true, minSize: 280, wrap: true,
    exportValue: (item) => item.evidence ?? "",
    header: "Evidence",
    cell: (item) => (
      <>
        <div className="text-xs text-muted-foreground" title={item.evidence || ""}>
          {item.evidence || "No evidence text"}
        </div>
        {item.exemption && (
          <div className="mt-0.5 text-xs text-muted-foreground" title={item.exemption.reason}>
            Exempt until {formatDateTime(item.exemption.expires_at)} · {item.exemption.reason}
          </div>
        )}
      </>
    ),
  },
];


function EvidencePanel({ data, isPending, isError, onRetry }: { data?: ComplianceEvidenceResponse; isPending: boolean; isError: boolean; onRetry: () => void }) {
  const items = data?.items ?? [];
  return <section className="space-y-4" data-testid="compliance-evidence-panel">
    <p className="text-sm text-muted-foreground">Collected evidence across node, workload, Kubernetes, and cloud scopes. This view loads up to 500 records.</p>
    {isPending && <LoadingState label="Loading evidence…" />}
    {isError && <ErrorState title={data ? "Could not refresh evidence. Showing the last loaded records." : "Compliance evidence could not be loaded."} action={<Button onClick={onRetry}>Retry</Button>} />}
    {data && <>
      <Collapse label="Evidence status details"><div className="grid gap-2 text-xs md:grid-cols-5" data-testid="compliance-evidence-summary"><StatusMetric label="Pass" value={data.summary.pass} status="pass" /><StatusMetric label="Fail" value={data.summary.fail} status="fail" /><StatusMetric label="Manual" value={data.summary.manual} status="manual" /><StatusMetric label="Exempted" value={data.summary.exempted} status="exempted" /><StatusMetric label="N/A" value={data.summary.not_applicable} status="not_applicable" /></div></Collapse>
      <DataTable rows={items} sourceLimit={500} sourceCount={items.length} columns={evidenceColumns} rowKey={(item) => item.id} preferencesKey="compliance-evidence" exportFileName="compliance-evidence.csv" emptyState={<EmptyState title="No collected compliance evidence" hint="Evidence will appear here after controls are evaluated." />} />
    </>}
  </section>;
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
                <span className="font-mono">{item.control_id}</span>
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

function StatusMetric({ label, value, status }: { label: string; value: number; status: string }) {
  return (
    <div className="rounded-md border border-border bg-background p-2">
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
      <div className={`mt-1 inline-flex rounded-md px-1.5 py-0.5 font-mono text-sm ${statusClass(status)}`}>
        {value}
      </div>
    </div>
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
  const runs = useQuery({
    queryKey: ["compliance", "schedule-runs", schedule.id],
    queryFn: () => compliance.scheduleRuns(schedule.id, 25),
    enabled: runsOpen && !unavailable,
  });
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
          {runs.isError && <ErrorState title="Run history could not be loaded." action={<Button onClick={() => void runs.refetch()}>Retry</Button>} />}
          {runs.isPending && <p className="text-xs text-muted-foreground">Loading runs…</p>}
          {runs.data && runs.data.runs.length === 0 && (
            <p className="text-xs text-muted-foreground">No runs recorded yet.</p>
          )}
          {runs.data && runs.data.runs.length > 0 && (
            <DataTable
              rows={runs.data.runs}
              rowKey={(run) => run.id}
              showDensityToggle={false}
              columns={[
                { id: "started", header: "Started", kind: "date", size: 192, minSize: 176, cell: (run) => new Date(run.started_at).toLocaleString() },
                { id: "status", header: "Status", kind: "status", size: 144, minSize: 128, cell: (run) => <span className={`rounded-md px-1.5 py-0.5 text-[10px] ${run.status === "succeeded" ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]" : run.status === "failed" ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]" : "bg-muted text-muted-foreground"}`}>{run.status}</span> },
                { id: "summary", header: "Pass / Fail / Manual", kind: "count", numeric: true, size: 184, minSize: 176, cell: (run) => `${run.summary.pass ?? 0} / ${run.summary.fail ?? 0} / ${run.summary.manual ?? 0}` },
                { id: "signature", header: "Signature", kind: "status", size: 176, minSize: 160, cell: (run) => run.artifact_signature ? <span title={run.artifact_signature} className="rounded bg-[color:var(--color-status-success)]/15 px-1.5 py-0.5 text-[color:var(--color-status-success)]">Signature recorded</span> : <span className="text-muted-foreground">—</span> },
                { id: "artifact", header: "Artifact", kind: "actions", size: 144, minSize: 136, cell: (run) => run.artifact_uri ? <button type="button" disabled={unavailable} onClick={() => compliance.downloadRunArtifact(run.id).catch(() => toast.error("Artifact download failed. Try again."))} className="inline-flex items-center gap-1 text-foreground hover:underline" data-testid={`run-download-${run.id}`}><Download className="h-3 w-3" aria-hidden /> Download</button> : <span className="text-muted-foreground">—</span> },
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
