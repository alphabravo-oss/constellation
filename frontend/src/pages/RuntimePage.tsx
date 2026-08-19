import { useQuery } from "@tanstack/react-query";
import { Activity, Clock3, RadioTower, Shield, ShieldAlert, Skull } from "lucide-react";
import { useState } from "react";

import { enterprise, runtimeEvents, type RuntimeEvent, type RuntimeOverview } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { useCluster } from "@/hooks/useCluster";

export function RuntimePage() {
  // Cluster-scoped runtime: every events query threads cluster_id so we never
  // surface eBPF telemetry from a sibling cluster's runtime-agent.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [hours, setHours] = useState(24);
  const [selectedEventID, setSelectedEventID] = useState<string | null>(null);
  const q = useQuery({
    queryKey: ["runtime-overview", hours, clusterId],
    queryFn: () => enterprise.runtime({ hours, cluster_id: clusterId }),
  });
  // Wave I4 live feed: poll the raw runtime-events feed every 10s. This is the data
  // the per-node runtime-agent DaemonSet POSTs to /api/v1/events:bulk in real time.
  const liveQ = useQuery({
    queryKey: ["runtime-events-live", clusterId],
    queryFn: () => runtimeEvents.list({ limit: 100, cluster_id: clusterId }),
    refetchInterval: 10_000,
  });
  const liveEvents = liveQ.data?.events ?? [];
  const subsystems = q.data?.subsystems ?? [];
  const rules = q.data?.rules ?? [];
  const events = q.data?.recent_events ?? [];
  const workloads = q.data?.workloads ?? [];
  const summary = q.data?.summary;
  const selectedEvent = events.find((event) => event.id === selectedEventID) ?? events[0];
  const ready = subsystems.filter((s) => s.status.includes("ready")).length;
  const gated = subsystems.filter((s) => s.status.includes("gated")).length;

  // Columns for the "Recent runtime events" table. Defined in-component because
  // the Workload cell's select button dispatches setSelectedEventID.
  const recentEventColumns: Column<RuntimeOverview["recent_events"][number]>[] = [
    {
      id: "workload",
      header: "Workload",
      className: "align-top",
      cell: (event) => (
        <>
          <button type="button" className="text-left font-medium hover:underline" onClick={() => setSelectedEventID(event.id)}>
            {event.workload_id}
          </button>
          <div className="mt-1 text-[11px] text-muted-foreground">{event.cluster_name || event.cluster_id}</div>
        </>
      ),
    },
    {
      id: "signal",
      header: "Signal",
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
      className: "align-top",
      cell: (event) => <span className="rounded-md border border-border px-2 py-1 text-xs">{event.verdict}</span>,
    },
    {
      id: "attack",
      header: "ATT&CK",
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
      className: "align-top text-xs text-muted-foreground",
      cell: (event) => (
        <>
          <div>{event.message || new Date(event.at).toLocaleTimeString()}</div>
          {event.rule_name && <div className="mt-1 font-mono text-[11px]">{event.rule_name}</div>}
        </>
      ),
    },
  ];

  if (clusterLoading) {
    return <p className="text-sm text-muted-foreground" data-testid="runtime-loading">Loading cluster…</p>;
  }

  return (
    <div className="space-y-6" data-testid="runtime-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Runtime"
        description="Live threat detection and enforcement in your running workloads — process, endpoint, network, WAF, DLP, Falco, and forensics signals, mapped to MITRE ATT&CK."
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5" data-testid="runtime-summary">
        <StatCard label="Ready" value={ready} icon={<Shield className="h-3.5 w-3.5" />} />
        <StatCard label="Gated" value={gated} tone={gated > 0 ? "medium" : "neutral"} icon={<Skull className="h-3.5 w-3.5" />} />
        <StatCard label="Rules" value={rules.length} icon={<RadioTower className="h-3.5 w-3.5" />} />
        <StatCard label="Events" value={summary?.events ?? 0} icon={<Activity className="h-3.5 w-3.5" />} />
        <StatCard label="Blocks" value={summary?.blocks ?? 0} tone={(summary?.blocks ?? 0) > 0 ? "high" : "neutral"} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
      </section>

      <section className="rounded-lg border border-border bg-card p-3" data-testid="runtime-evidence-summary">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold">Runtime evidence</h2>
            <p className="text-xs text-muted-foreground">
              Recent Falco, WAF, DLP, eBPF, and network telemetry correlated to workloads and ATT&CK techniques.
            </p>
          </div>
          <label className="flex items-center gap-2 text-xs">
            <Clock3 className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
            <select
              className="rounded-md border border-border bg-background px-2 py-1"
              value={hours}
              onChange={(event) => setHours(Number(event.target.value))}
              data-testid="runtime-window-select"
            >
              <option value={1}>1h</option>
              <option value={6}>6h</option>
              <option value={24}>24h</option>
              <option value={72}>72h</option>
              <option value={168}>7d</option>
            </select>
          </label>
        </div>
        <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-5">
          <Field label="Alerts" value={`${summary?.alerts ?? 0}`} />
          <Field label="Quarantines" value={`${summary?.quarantines ?? 0}`} />
          <Field label="Workloads" value={`${summary?.affected_workloads ?? 0}`} />
          <Field label="Techniques" value={`${summary?.techniques ?? 0}`} />
          <Field label="Window" value={`${summary?.window_hours ?? hours}h`} />
        </dl>
      </section>

      <section className="rounded-lg border border-border bg-card" data-testid="runtime-live-events">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-3 py-2">
          <div>
            <h2 className="text-sm font-semibold">Live runtime events</h2>
            <p className="text-xs text-muted-foreground">
              Raw eBPF stream from the runtime-agent DaemonSet · refreshing every 10s · last {liveEvents.length} events
            </p>
          </div>
          <span
            className={`rounded-md px-2 py-1 text-[10px] ${liveQ.isFetching ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"}`}
            data-testid="runtime-live-status"
          >
            {liveQ.isFetching ? "fetching" : liveQ.isError ? "error" : "live"}
          </span>
        </div>
        <DataTable
          rows={liveEvents}
          rowKey={(e) => e.id}
          columns={liveColumns}
          defaultSort={{ id: "at", dir: "desc" }}
          density="compact"
          showDensityToggle={false}
          emptyState={
            <div className="px-3 py-6 text-sm text-muted-foreground">
              No live runtime events yet — the runtime-agent DaemonSet hasn't reported any in this window.
            </div>
          }
        />
      </section>

      <section className="grid gap-3 md:grid-cols-3">
        {(q.data?.modes ?? []).map((mode) => (
          <div key={mode.id} className="rounded-lg border border-border bg-card p-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold">{mode.label}</h2>
              <span className="rounded-md bg-muted px-2 py-1 text-[10px] text-muted-foreground">
                {mode.blocks ? "blocks" : "observe"}
              </span>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">{mode.description}</p>
          </div>
        ))}
      </section>

      <section className="flex flex-col gap-6">
        <div className="space-y-4">
          <div data-testid="runtime-subsystems">
            <DataTable
              rows={subsystems}
              columns={subsystemColumns}
              rowKey={(s) => s.id}
              showDensityToggle={false}
              emptyState={
                <div className="px-3 py-6 text-sm text-muted-foreground">No runtime subsystems reported.</div>
              }
            />
          </div>

          <div className="overflow-hidden rounded-lg border border-border bg-card" data-testid="runtime-event-evidence">
            <div className="border-b border-border px-3 py-2">
              <h2 className="text-sm font-semibold">Recent runtime events</h2>
            </div>
            <DataTable
              rows={events}
              columns={recentEventColumns}
              rowKey={(event) => event.id}
              rowTestId={() => "runtime-event-row"}
              selected={selectedEvent ? new Set([selectedEvent.id]) : undefined}
              showDensityToggle={false}
              className="rounded-none border-0"
              emptyState={
                <div className="px-3 py-6 text-sm text-muted-foreground">No runtime events in this window.</div>
              }
            />
          </div>
        </div>

        <aside className="space-y-4">
          {selectedEvent && <RuntimeEventInspector event={selectedEvent} />}

          <section className="rounded-lg border border-border bg-card p-4">
            <h2 className="text-sm font-semibold">Affected workloads</h2>
            <ul className="mt-3 space-y-2" data-testid="runtime-workloads">
              {workloads.map((workload) => (
                <li key={workload.workload_id} className="rounded-md border border-border p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-sm font-medium">{workload.workload_id}</div>
                      <div className="mt-1 text-xs text-muted-foreground">{workload.events} events · {workload.alerts} alerts · {workload.blocks} blocks</div>
                    </div>
                    <span className="rounded-md bg-muted px-2 py-1 text-[10px] text-muted-foreground">{workload.highest_severity}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {[...workload.sources, ...workload.techniques].map((value) => (
                      <span key={value} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                        {value}
                      </span>
                    ))}
                  </div>
                </li>
              ))}
              {workloads.length === 0 && <li className="text-xs text-muted-foreground">No affected workloads in this window.</li>}
            </ul>
          </section>

          <section className="rounded-lg border border-border bg-card p-4">
            <h2 className="text-sm font-semibold">Runtime rule catalog</h2>
            <ul className="mt-3 space-y-2" data-testid="runtime-rules">
              {rules.map((r) => (
                <li key={r.name} className="rounded-md border border-border p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-sm font-medium">{r.name}</div>
                      <div className="mt-1 text-xs text-muted-foreground">{r.source} · {r.severity}</div>
                    </div>
                    <span className="rounded-md bg-muted px-2 py-1 text-[10px] text-muted-foreground">{r.mode}</span>
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-[11px]" data-testid="runtime-rule-evidence">
                    <Field label="Events" value={`${r.event_count ?? 0}`} />
                    <Field label="Workloads" value={`${r.affected_workloads ?? 0}`} />
                  </div>
                  {r.last_triggered_at && <div className="mt-2 text-[11px] text-muted-foreground">last triggered {new Date(r.last_triggered_at).toLocaleString()}</div>}
                  <div className="mt-2 flex flex-wrap gap-1">
                    {r.techniques.map((t) => (
                      <span key={t} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                        {t}
                      </span>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          </section>
        </aside>
      </section>
    </div>
  );
}

// Column definitions for the Wave I4 live runtime events DataTable. Kept module-level so
// the component identity is stable across renders (React would otherwise reset the
// DataTable's internal sort state on every parent re-render).
const liveColumns: Column<RuntimeEvent>[] = [
  {
    id: "at",
    header: "Time",
    sort: (a, b) => a.at.localeCompare(b.at),
    cell: (e) => <span className="font-mono text-[11px]">{new Date(e.at).toLocaleTimeString()}</span>,
    width: "120px",
  },
  {
    id: "kind",
    header: "Kind",
    sort: (a, b) => a.kind.localeCompare(b.kind),
    cell: (e) => <span className="font-mono text-xs">{e.kind}</span>,
    width: "140px",
  },
  {
    id: "pod",
    header: "Pod",
    cell: (e) => {
      const pod = typeof e.payload?.pod === "string" ? (e.payload.pod as string) : "";
      return (
        <div>
          <div className="font-medium">{pod || "—"}</div>
          {e.container_id && (
            <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{e.container_id.slice(0, 12)}</div>
          )}
        </div>
      );
    },
  },
  {
    id: "namespace",
    header: "Namespace",
    sort: (a, b) => (a.namespace ?? "").localeCompare(b.namespace ?? ""),
    cell: (e) => <span className="font-mono text-xs">{e.namespace || "—"}</span>,
    width: "140px",
  },
  {
    id: "attack",
    header: "ATT&CK",
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
    sort: (a, b) => severityOrder(a.severity) - severityOrder(b.severity),
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
    width: "100px",
  },
];

// Subsystem status table (left column). Module-level to keep column identity
// stable across renders so DataTable's internal sort state survives.
type RuntimeSubsystem = RuntimeOverview["subsystems"][number];
const subsystemColumns: Column<RuntimeSubsystem>[] = [
  {
    id: "name",
    header: "Subsystem",
    cell: (s) => <span className="font-medium">{s.name}</span>,
    sort: (a, b) => a.name.localeCompare(b.name),
  },
  {
    id: "mode",
    header: "Mode",
    cell: (s) => <span className="font-mono text-xs">{s.mode}</span>,
    sort: (a, b) => a.mode.localeCompare(b.mode),
  },
  {
    id: "status",
    header: "Status",
    cell: (s) => <span className="rounded-md border border-border px-2 py-1 text-xs">{s.status}</span>,
    sort: (a, b) => a.status.localeCompare(b.status),
  },
  {
    id: "evidence",
    header: "Evidence",
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

