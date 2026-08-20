// Compliance page — framework list + drill-down with per-control table.
//
// Layout mirrors StackRox's Compliance pattern: a left rail of frameworks (categorized) +
// a main pane with summary tiles per status and a check table you can filter to a single
// framework.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { CalendarClock, Download, FileText, PlayCircle, Send, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import {
  compliance,
  type ComplianceCheck,
  type ComplianceEvidenceItem,
  type ComplianceEvidenceResponse,
  type ComplianceExemption,
  type ComplianceScheduleDB,
  type ComplianceScheduleDelivery,
  type ComplianceSummary,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
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
  // Cluster-scoped per the cluster-first IA: every fetch threads cluster_id so we
  // never display compliance evidence from a sibling cluster.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [tab, setTab] = useTabParam("tab", "frameworks");
  const fws = useQuery({ queryKey: ["compliance", "frameworks"], queryFn: () => compliance.frameworks() });
  const summary = useQuery({
    queryKey: ["compliance", "summary", clusterId],
    queryFn: () => compliance.summary(clusterId),
  });
  const [active, setActive] = useState<string | null>(null);
  const [exempting, setExempting] = useState<ComplianceCheck | null>(null);
  const [exemptionReason, setExemptionReason] = useState("");
  const [exemptionExpiresAt, setExemptionExpiresAt] = useState(defaultExemptionExpiresAt());
  const [exemptionError, setExemptionError] = useState<string | null>(null);
  const schedules = useQuery({
    queryKey: ["compliance", "db-schedules", clusterId],
    queryFn: () => compliance.listDBSchedules(clusterId),
  });
  const evidence = useQuery({
    queryKey: ["compliance", "evidence", clusterId],
    queryFn: () => compliance.evidence({ cluster_id: clusterId, limit: 500 }),
  });
  const queryClient = useQueryClient();
  const invalidateComplianceEvidence = () => {
    void queryClient.invalidateQueries({ queryKey: ["compliance", "summary"] });
    void queryClient.invalidateQueries({ queryKey: ["compliance", "checks"] });
    void queryClient.invalidateQueries({ queryKey: ["compliance", "evidence"] });
    void queryClient.invalidateQueries({ queryKey: ["compliance", "exemptions"] });
  };
  const runNow = useMutation({
    mutationFn: (id: string) => compliance.runScheduleNow(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["compliance", "db-schedules"] });
    },
  });
  const checks = useQuery({
    queryKey: ["compliance", "checks", active, clusterId],
    queryFn: () => compliance.checks(active ?? undefined, clusterId),
    enabled: active != null,
  });
  const exemptions = useQuery({
    queryKey: ["compliance", "exemptions", active, clusterId],
    queryFn: () => compliance.listExemptions({ framework: active ?? undefined, cluster_id: clusterId }),
    enabled: active != null,
  });
  const createExemption = useMutation({
    mutationFn: () => {
      if (!exempting) throw new Error("No compliance control selected");
      return compliance.createExemption({
        cluster_id: clusterId,
        framework: exempting.framework,
        control_id: exempting.control_id,
        reason: exemptionReason,
        expires_at: new Date(exemptionExpiresAt).toISOString(),
      });
    },
    onSuccess: () => {
      setExempting(null);
      setExemptionReason("");
      setExemptionExpiresAt(defaultExemptionExpiresAt());
      setExemptionError(null);
      invalidateComplianceEvidence();
    },
    onError: (err: unknown) => setExemptionError(err instanceof Error ? err.message : "Failed to create exemption"),
  });
  const revokeExemption = useMutation({
    mutationFn: (id: string) => compliance.revokeExemption(id),
    onSuccess: () => invalidateComplianceEvidence(),
  });

  const summaryByFramework = useMemo(() => {
    const map: Record<string, ComplianceSummary> = {};
    for (const s of summary.data?.frameworks ?? []) map[s.framework] = s;
    return map;
  }, [summary.data]);

  if (clusterLoading) return <LoadingState label="Loading cluster…" />;
  if (fws.isPending) return <LoadingState label="Loading frameworks…" />;
  if (fws.isError) return <ErrorState error={fws.error} />;
  if ((fws.data?.frameworks ?? []).length === 0)
    return <EmptyState title="No compliance frameworks" hint="No frameworks are configured for this cluster yet." />;

  const categories = groupBy(fws.data?.frameworks ?? [], (f) => f.category);

  const checkColumns: Column<ComplianceCheck>[] = [
    {
      id: "control",
      header: "Control",
      cell: (c) => <span className="font-mono text-xs">{c.control_id}</span>,
    },
    {
      id: "title",
      header: "Title",
      cell: (c) => (
        <div>
          <div>{c.title}</div>
          {c.evidence && (
            <div className="mt-0.5 max-w-xl truncate text-xs text-muted-foreground" title={c.evidence}>
              {c.evidence}
            </div>
          )}
          {c.remediation && c.effective_status === "fail" && (
            <div className="mt-1 max-w-xl rounded border-l-2 border-[color:var(--color-severity-medium)] bg-muted/40 px-2 py-1 text-[11px] text-muted-foreground">
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
      id: "status",
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
      id: "severity",
      header: "Severity",
      cell: (c) => <span className="text-xs text-muted-foreground">{c.severity}</span>,
    },
    {
      id: "action",
      header: "Action",
      cell: (c) => {
        const effectiveStatus = c.effective_status ?? c.status;
        return effectiveStatus === "exempted" && c.exemption ? (
          <button
            type="button"
            onClick={() => revokeExemption.mutate(c.exemption!.id)}
            disabled={revokeExemption.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
          >
            <Trash2 className="h-3 w-3" aria-hidden />
            Revoke
          </button>
        ) : c.status === "fail" ? (
          <button
            type="button"
            onClick={() => {
              setExempting(c);
              setExemptionReason("");
              setExemptionExpiresAt(defaultExemptionExpiresAt());
              setExemptionError(null);
            }}
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

  return (
    <div className="space-y-6" data-testid="compliance-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Compliance"
        description={
          <>
            Measure this cluster against {fws.data?.frameworks.length ?? 0} security and regulatory frameworks. Pick a
            framework to see how each control scored, review collected evidence, or schedule signed evidence reports for
            your auditors.
          </>
        }
      />

      <Tabs
        value={tab}
        onValueChange={setTab}
        items={[
          {
            value: "frameworks",
            label: "Frameworks",
            count: fws.data?.frameworks.length,
            content: (
              <div className="space-y-6">

      <section className="grid grid-cols-2 gap-3 md:grid-cols-4" data-testid="compliance-schedule-metrics">
        <StatCard label="Schedules" value={schedules.data?.summary.total ?? 0} icon={<CalendarClock className="h-3.5 w-3.5" />} />
        <StatCard label="Enabled" value={schedules.data?.summary.enabled ?? 0} icon={<PlayCircle className="h-3.5 w-3.5" />} />
        <StatCard label="Formats" value={schedules.data?.report_formats.length ?? 0} icon={<FileText className="h-3.5 w-3.5" />} />
        <StatCard label="Deliveries" value={(schedules.data?.schedules ?? []).reduce((sum, item) => sum + item.delivery.length, 0)} icon={<Send className="h-3.5 w-3.5" />} />
      </section>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[260px_1fr]" data-testid="compliance-layout">
        <aside className="space-y-3 rounded-lg border border-border bg-card p-3" data-testid="frameworks-rail">
          {Object.entries(categories).map(([cat, list]) => (
            <section key={cat}>
              <h2 className="mb-1 text-xs font-semibold uppercase text-muted-foreground">{cat}</h2>
              <ul className="space-y-0.5">
                {list.map((f) => {
                  const s = summaryByFramework[f.id];
                  const pct = s?.effective_pass_pct ?? s?.pass_pct ?? null;
                  return (
                    <li key={f.id}>
                      <button
                        type="button"
                        onClick={() => setActive(f.id)}
                        data-testid={`framework-${f.id}`}
                        className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1 text-left text-sm transition-colors ${
                          active === f.id
                            ? "bg-accent text-foreground"
                            : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                        }`}
                      >
                        <span className="truncate">{f.name}</span>
                        {pct !== null && (
                          <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                            {pct}%
                          </span>
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </section>
          ))}
        </aside>

        <main className="rounded-lg border border-border bg-card p-4" data-testid="framework-detail">
          {!active && (
            <p className="text-sm text-muted-foreground">
              Select a framework from the left to see control-level evidence.
            </p>
          )}
          {active && (
            <>
              <h2 className="text-lg font-medium">{fws.data?.frameworks.find((f) => f.id === active)?.name}</h2>
              <p className="mb-3 text-xs text-muted-foreground">{active}</p>
              {summaryByFramework[active] && (
                <div className="mb-3 grid grid-cols-2 gap-2 text-xs md:grid-cols-5" data-testid="framework-status-summary">
                  <StatusMetric label="Pass" value={summaryByFramework[active].pass} status="pass" />
                  <StatusMetric label="Fail" value={summaryByFramework[active].fail} status="fail" />
                  <StatusMetric label="Manual" value={summaryByFramework[active].manual} status="manual" />
                  <StatusMetric label="Exempted" value={summaryByFramework[active].exempted ?? 0} status="exempted" />
                  <StatusMetric label="Total" value={summaryByFramework[active].total} status="not_applicable" />
                </div>
              )}
              {checks.isPending && <p className="text-xs text-muted-foreground">Loading controls…</p>}
              {checks.data && checks.data.checks.length === 0 && (
                <p className="text-xs text-muted-foreground">
                  No controls evaluated yet for this framework. Run <code>kubectl exec</code> on the
                  operator pod to trigger a kube-bench sweep, or POST kube-bench JSON to
                  <code> /api/v1/compliance/ingest</code>.
                </p>
              )}
              {checks.data && checks.data.checks.length > 0 && (
                <>
                  <div className="mb-2 flex justify-end">
                    <button
                      type="button"
                      onClick={() => downloadCsv(`constellation-compliance-${active ?? "all"}`, ["Framework", "Control", "Title", "Status", "Severity", "Standards", "Evidence"],
                        checks.data!.checks.map((c) => [c.framework, c.control_id, c.title, c.effective_status, c.severity, Object.keys(c.tags_v2 ?? {}).map((s) => regLabel(s)).join(" "), c.evidence]))}
                      className="rounded h-7 px-2.5 text-[11px] border border-border bg-card hover:bg-accent transition-colors"
                    >Export CSV</button>
                  </div>
                  <DataTable<ComplianceCheck>
                    rows={checks.data.checks}
                    columns={checkColumns}
                    rowKey={(c) => `${c.framework}-${c.control_id}`}
                  />
                </>
              )}
              {exemptions.data && exemptions.data.exemptions.length > 0 && (
                <ComplianceExemptionsList
                  exemptions={exemptions.data.exemptions}
                  onRevoke={(id) => revokeExemption.mutate(id)}
                  pending={revokeExemption.isPending}
                />
              )}
            </>
          )}
        </main>
      </div>

      <section className="space-y-3" data-testid="compliance-schedules">
        <div>
          <h2 className="text-lg font-semibold">Scheduled Evidence</h2>
          <p className="text-sm text-muted-foreground">
            Report jobs with scoped frameworks, delivery targets, run history, and signed artifacts.
          </p>
        </div>
        <div className="grid gap-3 xl:grid-cols-3">
          {(schedules.data?.schedules ?? []).map((schedule) => (
            <ScheduleSummaryCard
              key={schedule.id}
              schedule={schedule}
              onRunNow={() => runNow.mutate(schedule.id)}
              activeMessage={runNow.data?.schedule.id === schedule.id ? runNow.data.message : undefined}
              pending={runNow.isPending}
            />
          ))}
        </div>
      </section>
              </div>
            ),
          },
          {
            value: "evidence",
            label: "Evidence",
            content: <EvidencePanel data={evidence.data} isPending={evidence.isPending} />,
          },
          {
            value: "schedules",
            label: "Schedules",
            content: <SchedulesManager clusterId={clusterId} frameworks={fws.data?.frameworks ?? []} />,
          },
        ]}
      />
      {exempting && (
        <ComplianceExemptionDialog
          check={exempting}
          reason={exemptionReason}
          expiresAt={exemptionExpiresAt}
          error={exemptionError}
          pending={createExemption.isPending}
          onReasonChange={setExemptionReason}
          onExpiresAtChange={setExemptionExpiresAt}
          onClose={() => setExempting(null)}
          onSubmit={() => createExemption.mutate()}
        />
      )}
    </div>
  );
}

const evidenceColumns: Column<ComplianceEvidenceItem>[] = [
  {
    id: "scope",
    header: "Scope",
    cell: (item) => <span className="text-xs text-muted-foreground">{item.scope}</span>,
  },
  {
    id: "target",
    header: "Target",
    cell: (item) => (
      <>
        <div className="max-w-[220px] truncate font-medium" title={item.target}>{item.target}</div>
        <div className="text-xs text-muted-foreground">{item.target_kind}</div>
      </>
    ),
  },
  {
    id: "control",
    header: "Control",
    cell: (item) => (
      <>
        <div className="font-mono text-xs">{item.framework} · {item.control_id}</div>
        <div className="max-w-md truncate text-xs text-muted-foreground" title={item.title}>{item.title}</div>
      </>
    ),
  },
  {
    id: "status",
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
    id: "evidence",
    header: "Evidence",
    cell: (item) => (
      <>
        <div className="max-w-xl truncate text-xs text-muted-foreground" title={item.evidence || ""}>
          {item.evidence || "No evidence text"}
        </div>
        {item.exemption && (
          <div className="mt-0.5 max-w-xl truncate text-xs text-muted-foreground" title={item.exemption.reason}>
            Exempt until {formatDateTime(item.exemption.expires_at)} · {item.exemption.reason}
          </div>
        )}
      </>
    ),
  },
];

function EvidencePanel({ data, isPending }: { data?: ComplianceEvidenceResponse; isPending: boolean }) {
  const items = data?.items ?? [];
  return (
    <section className="space-y-3" data-testid="compliance-evidence-panel">
      <div className="grid gap-2 text-xs md:grid-cols-5" data-testid="compliance-evidence-summary">
        <StatusMetric label="Pass" value={data?.summary.pass ?? 0} status="pass" />
        <StatusMetric label="Fail" value={data?.summary.fail ?? 0} status="fail" />
        <StatusMetric label="Manual" value={data?.summary.manual ?? 0} status="manual" />
        <StatusMetric label="Exempted" value={data?.summary.exempted ?? 0} status="exempted" />
        <StatusMetric label="N/A" value={data?.summary.not_applicable ?? 0} status="not_applicable" />
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        {isPending && <p className="text-xs text-muted-foreground">Loading evidence…</p>}
        {!isPending && items.length === 0 && (
          <p className="text-xs text-muted-foreground">No compliance evidence has been collected for this cluster yet.</p>
        )}
        {items.length > 0 && (
          <DataTable<ComplianceEvidenceItem>
            rows={items}
            columns={evidenceColumns}
            rowKey={(item) => item.id}
          />
        )}
      </div>
    </section>
  );
}

function ComplianceExemptionDialog({
  check,
  reason,
  expiresAt,
  error,
  pending,
  onReasonChange,
  onExpiresAtChange,
  onClose,
  onSubmit,
}: {
  check: ComplianceCheck;
  reason: string;
  expiresAt: string;
  error: string | null;
  pending: boolean;
  onReasonChange: (value: string) => void;
  onExpiresAtChange: (value: string) => void;
  onClose: () => void;
  onSubmit: () => void;
}) {
  const canSubmit = reason.trim().length >= 12 && Boolean(expiresAt);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" data-testid="compliance-exemption-dialog">
      <div className="w-full max-w-md rounded-lg border border-border bg-card p-4 shadow-xl">
        <header className="mb-3 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold">Exempt compliance control</h3>
            <p className="mt-1 text-xs text-muted-foreground">
              {check.framework} · {check.control_id}
            </p>
          </div>
          <button type="button" onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">
            Cancel
          </button>
        </header>
        <div className="space-y-2">
          <div>
            <div className="text-xs font-medium">{check.title}</div>
            {check.evidence && <div className="mt-1 text-xs text-muted-foreground">{check.evidence}</div>}
          </div>
          <label className="block text-xs text-muted-foreground">Reason</label>
          <textarea
            value={reason}
            onChange={(e) => onReasonChange(e.target.value)}
            rows={4}
            className="w-full resize-none rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            placeholder="Compensating control, owner, ticket, or auditor-approved exception"
          />
          <label className="block text-xs text-muted-foreground">Expires</label>
          <input
            type="datetime-local"
            value={expiresAt}
            onChange={(e) => onExpiresAtChange(e.target.value)}
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
          />
        </div>
        {error && <p className="mt-2 text-xs text-[color:var(--color-status-error)]">{error}</p>}
        <footer className="mt-3 flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-accent">
            Cancel
          </button>
          <button
            type="button"
            onClick={onSubmit}
            disabled={!canSubmit || pending}
            className="rounded-md bg-foreground px-3 py-1.5 text-xs text-background hover:opacity-90 disabled:opacity-50"
          >
            {pending ? "Saving…" : "Create exemption"}
          </button>
        </footer>
      </div>
    </div>
  );
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

// SchedulesManager is the Wave N8 Schedules tab — DB-backed list + create
// wizard + run history with download links.
function SchedulesManager({
  clusterId,
  frameworks,
}: {
  clusterId?: string;
  frameworks: { id: string; name: string }[];
}) {
  const queryClient = useQueryClient();
  const list = useQuery({
    queryKey: ["compliance", "db-schedules", clusterId],
    queryFn: () => compliance.listDBSchedules(clusterId),
  });
  const [showWizard, setShowWizard] = useState(false);
  const [activeRunsFor, setActiveRunsFor] = useState<string | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["compliance", "db-schedules"] });

  const runNow = useMutation({
    mutationFn: (id: string) => compliance.runScheduleNow(id),
    onSuccess: () => invalidate(),
  });
  const remove = useMutation({
    mutationFn: (id: string) => compliance.deleteSchedule(id),
    onSuccess: () => invalidate(),
  });

  return (
    <section className="space-y-3" data-testid="compliance-schedules-manager">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Scheduled compliance runs</h2>
          <p className="text-sm text-muted-foreground">
            Cron-driven framework runs. Each run is rendered, cosign-signed, and delivered to
            the configured targets.
          </p>
        </div>
        <button
          type="button"
          data-testid="schedule-create-open"
          onClick={() => setShowWizard(true)}
          className="rounded-md bg-foreground px-3 py-1.5 text-sm text-background hover:opacity-90"
        >
          New schedule
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="Total" value={list.data?.summary.total ?? 0} icon={<CalendarClock className="h-3.5 w-3.5" />} />
        <StatCard label="Enabled" value={list.data?.summary.enabled ?? 0} icon={<PlayCircle className="h-3.5 w-3.5" />} />
        <StatCard label="Disabled" value={list.data?.summary.disabled ?? 0} icon={<FileText className="h-3.5 w-3.5" />} />
        <StatCard label="Formats" value={list.data?.report_formats.length ?? 0} icon={<ShieldCheck className="h-3.5 w-3.5" />} />
      </div>

      {showWizard && (
        <CreateScheduleWizard
          clusterId={clusterId}
          frameworks={frameworks}
          onClose={() => setShowWizard(false)}
          onCreated={() => {
            setShowWizard(false);
            invalidate();
          }}
        />
      )}

      <div className="space-y-2" data-testid="schedule-list">
        {list.isPending && <p className="text-sm text-muted-foreground">Loading schedules…</p>}
        {list.data && list.data.schedules.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No schedules yet. Create one to start emailing cosign-signed evidence to your auditors.
          </p>
        )}
        {list.data?.schedules.map((s) => (
          <ScheduleRow
            key={s.id}
            schedule={s}
            running={runNow.isPending && runNow.variables === s.id}
            onRunNow={() => runNow.mutate(s.id)}
            onDelete={() => remove.mutate(s.id)}
            onToggleRuns={() => setActiveRunsFor(activeRunsFor === s.id ? null : s.id)}
            runsOpen={activeRunsFor === s.id}
          />
        ))}
      </div>
    </section>
  );
}

function ScheduleRow({
  schedule,
  running,
  onRunNow,
  onDelete,
  onToggleRuns,
  runsOpen,
}: {
  schedule: ComplianceScheduleDB;
  running: boolean;
  onRunNow: () => void;
  onDelete: () => void;
  onToggleRuns: () => void;
  runsOpen: boolean;
}) {
  const runs = useQuery({
    queryKey: ["compliance", "schedule-runs", schedule.id],
    queryFn: () => compliance.scheduleRuns(schedule.id, 25),
    enabled: runsOpen,
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
            {schedule.last_status ?? "pending"}
          </span>
          <button
            type="button"
            onClick={onRunNow}
            disabled={running}
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
            data-testid={`schedule-runs-toggle-${schedule.id}`}
            className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent"
          >
            History
          </button>
          <button
            type="button"
            onClick={() => {
              if (confirm(`Delete schedule "${schedule.name}"?`)) onDelete();
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
          {runs.isPending && <p className="text-xs text-muted-foreground">Loading runs…</p>}
          {runs.data && runs.data.runs.length === 0 && (
            <p className="text-xs text-muted-foreground">No runs recorded yet.</p>
          )}
          {runs.data && runs.data.runs.length > 0 && (
            <table className="w-full text-xs">
              <thead className="text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="px-1.5 py-1 text-left">Started</th>
                  <th className="px-1.5 py-1 text-left">Status</th>
                  <th className="px-1.5 py-1 text-left">Pass / Fail / Manual</th>
                  <th className="px-1.5 py-1 text-left">Signature</th>
                  <th className="px-1.5 py-1 text-left">Artifact</th>
                </tr>
              </thead>
              <tbody>
                {runs.data.runs.map((r) => (
                  <tr key={r.id} className="border-b border-border/40">
                    <td className="px-1.5 py-1">{new Date(r.started_at).toLocaleString()}</td>
                    <td className="px-1.5 py-1">
                      <span
                        className={`rounded-md px-1.5 py-0.5 text-[10px] ${
                          r.status === "succeeded"
                            ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
                            : r.status === "failed"
                              ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
                              : "bg-muted text-muted-foreground"
                        }`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td className="px-1.5 py-1 font-mono">
                      {r.summary.pass ?? 0} / {r.summary.fail ?? 0} / {r.summary.manual ?? 0}
                    </td>
                    <td className="px-1.5 py-1 font-mono text-[10px]" title={r.artifact_signature ?? ""}>
                      {r.artifact_signature ? (
                        <span className="rounded bg-[color:var(--color-status-success)]/15 px-1.5 py-0.5 text-[color:var(--color-status-success)]">
                          cosign ✓
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-1.5 py-1">
                      {r.artifact_uri ? (
                        <button
                          type="button"
                          onClick={() => compliance.downloadRunArtifact(r.id).catch((e: Error) => toast.error(`Artifact download failed: ${e.message}`))}
                          className="inline-flex items-center gap-1 text-foreground hover:underline"
                          data-testid={`run-download-${r.id}`}
                        >
                          <Download className="h-3 w-3" aria-hidden />
                          Download
                        </button>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </article>
  );
}

// CreateScheduleWizard is a 4-step (framework, cadence, delivery, format) modal
// that posts /api/v1/compliance/schedules on submit.
function CreateScheduleWizard({
  clusterId,
  frameworks,
  onClose,
  onCreated,
}: {
  clusterId?: string;
  frameworks: { id: string; name: string }[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [step, setStep] = useState(1);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [framework, setFramework] = useState(frameworks[0]?.id ?? "cis-k8s-1.9");
  const [cron, setCron] = useState("0 2 * * *");
  const [tz, setTz] = useState("UTC");
  const [delivery, setDelivery] = useState<ComplianceScheduleDelivery[]>([
    { kind: "file", target: "file:///tmp/compliance-out/" },
  ]);
  const [reportFormat, setReportFormat] = useState("pdf");
  const [reportTemplate, setReportTemplate] = useState("compliance-detailed");
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      compliance.createSchedule({
        name,
        description,
        cluster_id: clusterId,
        framework,
        cron_expression: cron,
        timezone: tz,
        delivery,
        report_format: reportFormat,
        report_template: reportTemplate,
      }),
    onSuccess: () => onCreated(),
    onError: (e: Error) => setErr(e.message),
  });

  const presetCadences: Array<{ label: string; cron: string }> = [
    { label: "Daily 02:00", cron: "0 2 * * *" },
    { label: "Weekly Mon 02:00", cron: "0 2 * * 1" },
    { label: "Monthly 1st 02:00", cron: "0 2 1 * *" },
    { label: "Every 5 minutes (test)", cron: "*/5 * * * *" },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" data-testid="schedule-wizard">
      <div className="w-full max-w-lg rounded-lg border border-border bg-card p-4 shadow-xl">
        <header className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold">
            New compliance schedule <span className="text-muted-foreground">· step {step} of 4</span>
          </h3>
          <button type="button" onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">
            Cancel
          </button>
        </header>

        {step === 1 && (
          <div className="space-y-2" data-testid="wizard-step-framework">
            <label className="block text-xs text-muted-foreground">Name</label>
            <input
              data-testid="wizard-name"
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="cis-k8s-monthly"
            />
            <label className="block text-xs text-muted-foreground">Description</label>
            <input
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Monthly evidence package for the audit team"
            />
            <label className="block text-xs text-muted-foreground">Framework</label>
            <select
              data-testid="wizard-framework"
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
            >
              {frameworks.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name} ({f.id})
                </option>
              ))}
            </select>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-2" data-testid="wizard-step-cadence">
            <p className="text-xs text-muted-foreground">Pick a preset or enter a 5-field cron expression.</p>
            <div className="grid grid-cols-2 gap-1.5">
              {presetCadences.map((p) => (
                <button
                  key={p.cron}
                  type="button"
                  onClick={() => setCron(p.cron)}
                  className={`rounded-md border px-2 py-1.5 text-xs ${
                    cron === p.cron ? "border-foreground bg-accent" : "border-border hover:bg-accent"
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
            <label className="block text-xs text-muted-foreground">Cron expression</label>
            <input
              data-testid="wizard-cron"
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
            />
            <label className="block text-xs text-muted-foreground">Timezone</label>
            <input
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              value={tz}
              onChange={(e) => setTz(e.target.value)}
            />
          </div>
        )}

        {step === 3 && (
          <div className="space-y-2" data-testid="wizard-step-delivery">
            <p className="text-xs text-muted-foreground">Where should signed reports be delivered?</p>
            {delivery.map((d, i) => (
              <div key={i} className="space-y-1 rounded-md border border-border p-2">
                <div className="flex items-center gap-1.5">
                  <select
                    className="rounded-md border border-border bg-background px-2 py-1 text-xs"
                    value={d.kind}
                    onChange={(e) => {
                      const next = [...delivery];
                      next[i] = { ...next[i], kind: e.target.value as ComplianceScheduleDelivery["kind"] };
                      setDelivery(next);
                    }}
                  >
                    <option value="email">email</option>
                    <option value="s3">s3</option>
                    <option value="webhook">webhook</option>
                    <option value="file">file (local)</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => setDelivery(delivery.filter((_, j) => j !== i))}
                    className="ml-auto text-xs text-muted-foreground hover:text-foreground"
                  >
                    Remove
                  </button>
                </div>
                {d.kind === "email" && (
                  <input
                    placeholder="auditor@example.com"
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                    value={d.target ?? ""}
                    onChange={(e) => {
                      const next = [...delivery];
                      next[i] = { ...next[i], target: e.target.value };
                      setDelivery(next);
                    }}
                  />
                )}
                {d.kind === "s3" && (
                  <>
                    <input
                      placeholder="bucket"
                      className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                      value={d.bucket ?? ""}
                      onChange={(e) => {
                        const next = [...delivery];
                        next[i] = { ...next[i], bucket: e.target.value };
                        setDelivery(next);
                      }}
                    />
                    <input
                      placeholder="prefix/"
                      className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                      value={d.prefix ?? ""}
                      onChange={(e) => {
                        const next = [...delivery];
                        next[i] = { ...next[i], prefix: e.target.value };
                        setDelivery(next);
                      }}
                    />
                  </>
                )}
                {d.kind === "webhook" && (
                  <input
                    placeholder="https://example.com/webhook"
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                    value={d.url ?? ""}
                    onChange={(e) => {
                      const next = [...delivery];
                      next[i] = { ...next[i], url: e.target.value };
                      setDelivery(next);
                    }}
                  />
                )}
                {d.kind === "file" && (
                  <input
                    placeholder="file:///tmp/compliance-out/"
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                    value={d.target ?? ""}
                    onChange={(e) => {
                      const next = [...delivery];
                      next[i] = { ...next[i], target: e.target.value };
                      setDelivery(next);
                    }}
                  />
                )}
              </div>
            ))}
            <button
              type="button"
              onClick={() => setDelivery([...delivery, { kind: "email", target: "" }])}
              className="rounded-md border border-dashed border-border px-2 py-1 text-xs text-muted-foreground hover:bg-accent"
            >
              + Add target
            </button>
          </div>
        )}

        {step === 4 && (
          <div className="space-y-2" data-testid="wizard-step-format">
            <label className="block text-xs text-muted-foreground">Report format</label>
            <select
              data-testid="wizard-format"
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              value={reportFormat}
              onChange={(e) => setReportFormat(e.target.value)}
            >
              <option value="pdf">PDF (cosign-signed)</option>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
              <option value="sarif">SARIF 2.1</option>
            </select>
            <label className="block text-xs text-muted-foreground">Template</label>
            <select
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              value={reportTemplate}
              onChange={(e) => setReportTemplate(e.target.value)}
            >
              <option value="compliance-detailed">compliance-detailed (cover + TOC + per-control + executive summary)</option>
            </select>
          </div>
        )}

        {err && <p className="mt-2 text-xs text-[color:var(--color-status-error)]">{err}</p>}

        <footer className="mt-3 flex items-center justify-between">
          <button
            type="button"
            onClick={() => setStep(Math.max(1, step - 1))}
            disabled={step === 1}
            className="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            Back
          </button>
          {step < 4 ? (
            <button
              type="button"
              onClick={() => setStep(step + 1)}
              disabled={step === 1 && (!name.trim() || !framework)}
              className="rounded-md bg-foreground px-3 py-1.5 text-xs text-background hover:opacity-90 disabled:opacity-50"
            >
              Next
            </button>
          ) : (
            <button
              type="button"
              data-testid="wizard-submit"
              onClick={() => create.mutate()}
              disabled={create.isPending}
              className="rounded-md bg-foreground px-3 py-1.5 text-xs text-background hover:opacity-90 disabled:opacity-50"
            >
              {create.isPending ? "Creating…" : "Create schedule"}
            </button>
          )}
        </footer>
      </div>
    </div>
  );
}

function ScheduleSummaryCard({
  schedule,
  onRunNow,
  activeMessage,
  pending,
}: {
  schedule: ComplianceScheduleDB;
  onRunNow: () => void;
  activeMessage?: string;
  pending: boolean;
}) {
  const delivery = schedule.delivery.map(deliveryTargetLabel).join(", ") || "No delivery target";
  return (
    <article className="rounded-lg border border-border bg-card p-4" data-testid="compliance-schedule-card">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">{schedule.name}</h3>
          <p className="mt-1 text-xs text-muted-foreground">{schedule.description}</p>
        </div>
        <span className={`rounded-md px-2 py-1 text-xs ${schedule.enabled ? statusClass("pass") : statusClass("manual")}`}>
          {schedule.enabled ? "enabled" : "disabled"}
        </span>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <Info label="Framework" value={schedule.framework} />
        <Info label="Cadence" value={schedule.cron_expression} />
        <Info label="Scope" value={schedule.cluster_id ? "cluster" : "organization"} />
        <Info label="Next run" value={schedule.next_run_at ? new Date(schedule.next_run_at).toLocaleDateString() : "manual"} />
      </div>
      <div className="mt-3 flex flex-wrap gap-1">
        <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{schedule.report_format}</span>
        {schedule.delivery.map((target, index) => (
          <span key={`${target.kind}-${index}`} className="rounded-md bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{target.kind}</span>
        ))}
      </div>
      <div className="mt-3 rounded-md bg-muted p-3 text-xs text-muted-foreground">
        <div className="font-medium text-foreground">Last run</div>
        <div className="mt-1">{schedule.last_status || "No runs yet"}</div>
        <div className="mt-1 truncate">{delivery}</div>
      </div>
      <button
        type="button"
        onClick={onRunNow}
        className="mt-3 inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-xs hover:bg-accent"
        disabled={pending}
      >
        <PlayCircle className="h-3.5 w-3.5" aria-hidden />
        Run now
      </button>
      {activeMessage && <p className="mt-2 text-xs text-muted-foreground">{activeMessage}</p>}
    </article>
  );
}

function deliveryTargetLabel(target: ComplianceScheduleDelivery) {
  switch (target.kind) {
    case "email":
      return target.target || "email";
    case "s3":
      return target.bucket ? `s3://${target.bucket}/${target.prefix ?? ""}` : "s3";
    case "webhook":
      return target.receiver_id || target.url || "webhook";
    case "file":
      return target.target || "file";
    default:
      return target.kind;
  }
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
      <div className="mt-1">{value}</div>
    </div>
  );
}

function defaultExemptionExpiresAt() {
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  return expires.toISOString().slice(0, 16);
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

function groupBy<T>(items: T[], key: (t: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const item of items) {
    const k = key(item);
    (out[k] ||= []).push(item);
  }
  return out;
}
