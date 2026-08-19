import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Gauge, Search, ServerCog, ShieldCheck, SlidersHorizontal } from "lucide-react";

import {
  componentsInventory,
  type ComponentDiagnosticCheck,
  type ComponentDiagnosticConfig,
  type ComponentDiagnosticCounter,
  type ComponentDiagnostics,
  type ComponentInstance,
  type ComponentRollup,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { DataTable, type Column } from "@/components/ui/data-table";

const statuses = ["all", "healthy", "degraded", "stale", "drift", "crashlooping", "missing", "not-observed"];

export function ComponentsPage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [selectedID, setSelectedID] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["components-inventory", clusterId],
    queryFn: () => componentsInventory.list({ cluster_id: clusterId, limit: 1000 }),
    enabled: !!clusterId,
    refetchInterval: 30_000,
  });
  const selectedQ = useQuery({
    queryKey: ["component-instance", clusterId, selectedID],
    queryFn: () => componentsInventory.get(selectedID!),
    enabled: !!selectedID,
    refetchInterval: 30_000,
  });

  const rollups = useMemo(() => q.data?.rollups ?? [], [q.data?.rollups]);
  const instances = useMemo(() => q.data?.components ?? [], [q.data?.components]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return instances.filter((item) => {
      if (status !== "all" && item.status !== status) return false;
      if (!needle) return true;
      return [
        item.component,
        item.display_name,
        item.role,
        item.scope,
        item.kind,
        item.hostname,
        item.version ?? "",
        item.commit ?? "",
        item.cluster_name ?? "",
        item.status_reason ?? "",
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [instances, query, status]);
  const selected = selectedQ.data?.component ?? filtered.find((item) => item.id === selectedID) ?? filtered[0] ?? null;
  const diagnosticsQ = useQuery({
    queryKey: ["component-diagnostics", clusterId, selected?.id],
    queryFn: () => componentsInventory.diagnostics(selected!.id),
    enabled: !!selected?.id,
    refetchInterval: 30_000,
    retry: (failureCount, error) => !isForbidden(error) && failureCount < 2,
  });
  const summary = q.data?.summary;

  if (clusterLoading) return <p className="text-sm text-muted-foreground">Loading cluster...</p>;

  const columns: Column<ComponentInstance>[] = [
    {
      id: "component",
      header: "Component",
      cell: (item) => (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            <StatusPill status={item.status} />
            <Pill tone="neutral">{item.role}</Pill>
          </div>
          <div className="mt-2 font-medium">{item.display_name}</div>
          <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{item.hostname}</div>
        </>
      ),
    },
    {
      id: "build",
      header: "Build",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.version || "unknown"}</div>
          <div className="mt-1 font-mono text-muted-foreground">{item.commit_short || "commit unknown"}</div>
        </div>
      ),
    },
    {
      id: "runtime",
      header: "Runtime",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{formatUptime(item.uptime_seconds)}</div>
          <div className="mt-1 text-muted-foreground">{item.restart_count} restarts</div>
        </div>
      ),
    },
    {
      id: "counters",
      header: "Counters",
      cell: (item) => (
        <div className="text-xs">
          <CounterMini item={item} />
        </div>
      ),
    },
    {
      id: "status",
      header: "Status",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{formatDate(item.last_seen_at)}</div>
          <div className="mt-1 text-muted-foreground">{item.status_reason || item.last_error || "heartbeat current"}</div>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6" data-testid="components-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Components"
        description="Live health and build inventory of every Constellation component — controller, scanner, importer, admission, discoverer, and runtime agents — with heartbeat and drift diagnostics."
      />

      {(() => {
        const degraded = (summary?.degraded ?? 0) + (summary?.drift ?? 0) + (summary?.stale ?? 0);
        return (
          <section className="grid grid-cols-2 gap-3 sm:grid-cols-3" data-testid="component-summary">
            <StatCard label="Instances" value={summary?.total_instances ?? 0} icon={<ServerCog className="h-3.5 w-3.5" />} />
            <StatCard label="Missing" value={summary?.missing ?? 0} tone={(summary?.missing ?? 0) > 0 ? "critical" : "neutral"} icon={<AlertTriangle className="h-3.5 w-3.5" />} />
            <StatCard label="Degraded" value={degraded} tone={degraded > 0 ? "medium" : "neutral"} icon={<Activity className="h-3.5 w-3.5" />} />
          </section>
        );
      })()}

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" data-testid="component-rollups">
        {rollups.map((rollup) => (
          <RollupCard key={rollup.component} rollup={rollup} />
        ))}
      </section>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search component, host, version, role"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="component-search"
            />
          </label>
          <select
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="component-status-filter"
          >
            {statuses.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All statuses" : item}</option>
            ))}
          </select>
        </div>
      </section>

      <section className="flex flex-col gap-6">
        <DataTable<ComponentInstance>
          rows={filtered}
          columns={columns}
          rowKey={(item) => item.id}
          onRowClick={(item) => setSelectedID(item.id)}
          selected={selected ? new Set([selected.id]) : undefined}
          emptyState={
            <div className="px-3 py-8 text-center text-xs text-muted-foreground">
              {q.isPending ? "Loading components..." : "No component instances match the current filters."}
            </div>
          }
        />

        <ComponentPreview
          item={selected}
          diagnostics={diagnosticsQ.data ?? null}
          diagnosticsLoading={diagnosticsQ.isFetching}
          diagnosticsError={diagnosticsQ.error}
        />
      </section>
    </div>
  );
}

function RollupCard({ rollup }: { rollup: ComponentRollup }) {
  return (
    <article className={cn("rounded-lg border border-border bg-card p-3", rollup.status === "missing" && "border-destructive/30")}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">{rollup.display_name}</h2>
          <p className="mt-1 text-xs text-muted-foreground">{rollup.role} · {rollup.scope} · {rollup.kind}</p>
        </div>
        <StatusPill status={rollup.status} />
      </div>
      <div className="mt-3 grid grid-cols-5 gap-2 text-xs">
        <Mini label="Ready" value={rollup.healthy} />
        <Mini label="Stale" value={rollup.stale} />
        <Mini label="Drift" value={rollup.drift} />
        <Mini label="Crash" value={rollup.crashlooping} />
        <Mini label="Missing" value={rollup.missing} />
      </div>
      {rollup.last_status_cause ? <p className="mt-2 text-xs text-muted-foreground">{rollup.last_status_cause}</p> : null}
    </article>
  );
}

function ComponentPreview({
  item,
  diagnostics,
  diagnosticsLoading,
  diagnosticsError,
}: {
  item: ComponentInstance | null;
  diagnostics: ComponentDiagnostics | null;
  diagnosticsLoading: boolean;
  diagnosticsError: unknown;
}) {
  if (!item) {
    return (
      <aside className="rounded-lg border border-border bg-card p-4" data-testid="component-preview">
        <h2 className="text-sm font-semibold">Component inspection</h2>
        <p className="mt-2 text-xs text-muted-foreground">Select a component instance to inspect heartbeat metadata and build drift evidence.</p>
      </aside>
    );
  }
  return (
    <aside className="space-y-4" data-testid="component-preview">
      <section className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <StatusPill status={item.status} />
            <h2 className="mt-2 break-all text-sm font-semibold">{item.display_name}</h2>
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{item.hostname}</p>
          </div>
          <Pill tone="accent">{item.scope} · {item.kind}</Pill>
        </div>
        <dl className="mt-4 grid gap-2 text-sm">
          <Field label="Role" value={item.role} />
          <Field label="Kind" value={item.kind} />
          <Field label="Version" value={item.version || "-"} />
          <Field label="Commit" value={item.commit || "-"} />
          <Field label="Build Time" value={formatDate(item.build_time)} />
          <Field label="First Seen" value={formatDate(item.first_seen_at)} />
          <Field label="Last Seen" value={formatDate(item.last_seen_at)} />
          <Field label="Status Reason" value={item.status_reason || item.last_error || "-"} />
        </dl>
      </section>
      <DiagnosticsPanel diagnostics={diagnostics} loading={diagnosticsLoading} error={diagnosticsError} />
      <section className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Public heartbeat metadata</h3>
        <pre className="mt-3 max-h-[420px] overflow-auto rounded-md border border-border bg-muted p-3 text-xs">
          {JSON.stringify(item.metadata ?? {}, null, 2)}
        </pre>
      </section>
    </aside>
  );
}

function DiagnosticsPanel({ diagnostics, loading, error }: { diagnostics: ComponentDiagnostics | null; loading: boolean; error: unknown }) {
  if (isForbidden(error)) {
    return (
      <section className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
          <h3 className="text-sm font-semibold">Diagnostics</h3>
        </div>
        <p className="mt-2 text-xs text-muted-foreground">Global admin access required.</p>
      </section>
    );
  }
  if (!diagnostics) {
    return (
      <section className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center gap-2">
          <Gauge className="h-4 w-4 text-muted-foreground" aria-hidden />
          <h3 className="text-sm font-semibold">Diagnostics</h3>
        </div>
        <p className="mt-2 text-xs text-muted-foreground">{loading ? "Loading diagnostics..." : "Diagnostics unavailable."}</p>
      </section>
    );
  }
  const counters = visibleDiagnosticCounters(diagnostics.counters);
  return (
    <section className="space-y-3 rounded-lg border border-border bg-card p-4" data-testid="component-diagnostics">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Gauge className="h-4 w-4 text-muted-foreground" aria-hidden />
          <h3 className="text-sm font-semibold">Diagnostics</h3>
        </div>
        <Pill tone="accent">{diagnostics.admin_gate}</Pill>
      </div>
      <div className="grid grid-cols-2 gap-2">
        {counters.map((counter) => (
          <CounterCard key={counter.key} counter={counter} />
        ))}
      </div>
      <DiagnosticList checks={diagnostics.diagnostics} />
      <ConfigList config={diagnostics.config} />
      <div className="rounded-md border border-border p-3">
        <div className="flex items-center gap-2 text-xs font-semibold">
          <SlidersHorizontal className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          Debug gates
        </div>
        <div className="mt-2 grid grid-cols-3 gap-2 text-xs">
          <Mini label="Profiling" value={diagnostics.debug.profiling_enabled ? 1 : 0} />
          <Mini label="Logs" value={diagnostics.debug.live_logs_enabled ? 1 : 0} />
          <Mini label="Bundle" value={diagnostics.debug.support_bundle_enabled ? 1 : 0} />
        </div>
        {diagnostics.debug.notes?.length ? (
          <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
            {diagnostics.debug.notes.map((note) => <li key={note}>{note}</li>)}
          </ul>
        ) : null}
      </div>
    </section>
  );
}

function visibleDiagnosticCounters(counters: ComponentDiagnosticCounter[]) {
  const priority = new Map<string, number>([
    ["node_container_count", 0],
    ["node_process_count", 1],
    ["node_package_count", 2],
    ["node_cis_failed", 3],
    ["active_jobs", 4],
    ["idle_capacity", 5],
    ["max_concurrent", 6],
    ["processed_events", 7],
    ["dropped_events", 8],
  ]);
  return counters
    .map((counter, index) => ({ counter, index, rank: priority.get(counter.key) ?? 100 + index }))
    .sort((a, b) => a.rank - b.rank || a.index - b.index)
    .slice(0, 12)
    .map((item) => item.counter);
}

function DiagnosticList({ checks }: { checks: ComponentDiagnosticCheck[] }) {
  if (checks.length === 0) return null;
  return (
    <div className="space-y-2">
      {checks.map((check) => (
        <div key={check.key} className="rounded-md border border-border p-3 text-xs">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <div className="font-semibold">{check.label}</div>
              <div className="mt-1 break-all text-muted-foreground">{check.evidence}</div>
            </div>
            <StatusPill status={check.status} />
          </div>
          {check.value !== undefined ? <div className="mt-2 break-all font-mono text-[11px]">{formatDiagnosticValue(check.value)}</div> : null}
          {check.reason ? <div className="mt-2 break-all text-muted-foreground">{check.reason}</div> : null}
        </div>
      ))}
    </div>
  );
}

function ConfigList({ config }: { config: ComponentDiagnosticConfig[] }) {
  if (config.length === 0) return null;
  return (
    <div className="rounded-md border border-border p-3">
      <div className="text-xs font-semibold">Config</div>
      <dl className="mt-2 grid gap-2 text-xs">
        {config.slice(0, 12).map((item) => (
          <div key={item.key} className="grid grid-cols-[120px_minmax(0,1fr)] gap-2">
            <dt className="text-muted-foreground">{item.label}</dt>
            <dd className="break-all font-mono">{formatDiagnosticValue(item.value)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function CounterCard({ counter }: { counter: ComponentDiagnosticCounter }) {
  return (
    <div className="rounded-md border border-border p-2 text-xs">
      <div className="text-muted-foreground">{counter.label}</div>
      <div className="mt-1 break-all font-semibold">{formatDiagnosticValue(counter.value)}{counter.unit ? ` ${counter.unit}` : ""}</div>
    </div>
  );
}

function CounterMini({ item }: { item: ComponentInstance }) {
  const metadata = item.metadata ?? {};
  const active = numberValue(metadata.active_jobs);
  const max = numberValue(metadata.max_concurrent);
  const idle = numberValue(metadata.idle_capacity);
  const processed = numberValue(metadata.processed_events);
  const dropped = numberValue(metadata.dropped_events);
  const vulndb = getRecord(metadata.vulndb);
  const vulndbStatus = stringValue(vulndb?.status) || (boolValue(vulndb?.ready) ? "ready" : "");
  const parts = [
    active !== null && max !== null ? `${active}/${max} active` : null,
    idle !== null ? `${idle} idle` : null,
    vulndbStatus ? `vulndb ${vulndbStatus}` : null,
    processed !== null ? `${processed} events` : null,
    dropped !== null && dropped > 0 ? `${dropped} dropped` : null,
  ].filter(Boolean);
  if (parts.length === 0) return <span className="text-muted-foreground">-</span>;
  return <div className="space-y-1 text-muted-foreground">{parts.slice(0, 3).map((part) => <div key={part}>{part}</div>)}</div>;
}

function Mini({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
      <div className="font-semibold">{value}</div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border p-2">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-medium">{value}</dd>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const tone = status === "healthy"
    || status === "ready"
    ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
    : status === "degraded" || status === "stale" || status === "drift" || status === "disabled" || status === "saturated" || status === "read-only"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
    : status === "missing" || status === "crashlooping"
        ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
        : "bg-muted text-muted-foreground";
  return <span className={cn("inline-flex h-5 items-center rounded px-1.5 text-[10px] font-medium", tone)}>{status}</span>;
}

function Pill({ children, tone }: { children: ReactNode; tone: "neutral" | "accent" }) {
  return (
    <span className={cn("inline-flex h-5 items-center rounded px-1.5 text-[10px] font-medium", tone === "neutral" && "bg-muted text-muted-foreground", tone === "accent" && "bg-primary/10 text-primary")}>
      {children}
    </span>
  );
}

function formatDate(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatUptime(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "-";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatDiagnosticValue(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" || typeof value === "string") return String(value);
  return JSON.stringify(value);
}

function getRecord(value: unknown): Record<string, unknown> | null {
  if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
  return null;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function boolValue(value: unknown): boolean {
  return value === true;
}

function isForbidden(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const response = (error as { response?: { status?: number } }).response;
  return response?.status === 403;
}
