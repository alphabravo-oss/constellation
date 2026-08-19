import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  RefreshCcw,
  ShieldAlert,
  Sparkles,
} from "lucide-react";

import {
  systemHealth,
  type SystemHealthClusterDrift,
  type SystemHealthHeartbeat,
  type SystemHealthLicense,
} from "@/api/client";
import { StatCard } from "@/components/ui/stat-card";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";

const heartbeatColumns: Column<SystemHealthHeartbeat>[] = [
  { id: "component", header: "Component", className: "font-medium", cell: (hb) => hb.component },
  { id: "version", header: "Version", className: "font-mono", cell: (hb) => hb.version },
  { id: "commit", header: "Commit", className: "font-mono", cell: (hb) => <span title={hb.commit}>{hb.commit_short}</span> },
  { id: "hostname", header: "Hostname", className: "font-mono", cell: (hb) => hb.hostname },
  { id: "cluster", header: "Cluster", cell: (hb) => hb.cluster_name ?? <span className="text-muted-foreground">(control-plane)</span> },
  { id: "uptime", header: "Uptime", cell: (hb) => formatUptime(hb.uptime_seconds) },
  { id: "lastSeen", header: "Last seen", cell: (hb) => formatRelative(hb.last_seen_at) },
  { id: "restarts", header: "Restarts", cell: (hb) => hb.restart_count },
  { id: "details", header: "Details", cell: (hb) => <HeartbeatDetails hb={hb} /> },
  { id: "status", header: "Status", cell: (hb) => <StatusPill status={hb.status} reason={hb.drift_reason} /> },
];

/**
 * System Health — verdict-first (pattern P1).
 *
 * License banner (auto-hidden when healthy) + a single derived verdict + 5 fleet
 * tiles above the fold; everything else behind tabs (Clusters / Components /
 * Crashloops / Incidents & Actions). The legacy static "component catalog +
 * signals + Catalog metrics" model was removed — it duplicated the live telemetry.
 */
export function SystemHealthPage() {
  const q = useQuery({
    queryKey: ["system-health"],
    queryFn: () => systemHealth.overview(),
    refetchInterval: 30_000,
  });

  const [tab, setTab] = useTabParam("tab", "clusters");

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading system health...</p>;
  const data = q.data;
  if (!data) return <p className="text-sm text-muted-foreground">No system-health data.</p>;

  const heartbeats = data.heartbeats ?? [];
  const drift = data.version_drift ?? [];
  const crashloop = data.crashloop_history ?? [];
  const license = data.license;
  const cp = data.control_plane ?? {};
  const incidents = data.incidents ?? [];
  const actions = data.remediation_actions ?? [];
  const s = data.summary;

  // Verdict-first (pattern P1): one derived top-line answer.
  const isCritical = (s.crashlooping ?? 0) > 0;
  const isDegraded = (s.degraded ?? 0) > 0 || (s.drift ?? 0) > 0 || (s.stale ?? 0) > 0;
  const verdictStatus = isCritical ? "critical" : isDegraded ? "degraded" : "ok";
  const verdictTitle = isCritical
    ? `Platform degraded — ${s.crashlooping} component${s.crashlooping === 1 ? "" : "s"} crashlooping`
    : isDegraded
      ? "Platform degraded — version drift or stale/degraded components"
      : "Platform healthy";
  const verdictDetail = `${s.healthy ?? 0} healthy · ${heartbeats.length} reporting${
    license?.expires_at ? ` · license expires in ${license.days_to_expiry}d` : ""
  }`;

  const tabs = [
    {
      value: "clusters",
      label: "Clusters",
      count: drift.length,
      content:
        drift.length > 0 ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" data-testid="system-health-clusters">
            {drift.map((c) => (
              <ClusterCard key={`${c.cluster_id ?? "control"}-${c.cluster_name}`} cluster={c} />
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">No cluster drift data.</p>
        ),
    },
    {
      value: "components",
      label: "Components",
      count: heartbeats.length,
      content: (
        <div data-testid="system-health-heartbeats">
          <DataTable
            rows={heartbeats}
            columns={heartbeatColumns}
            rowKey={(hb) => `${hb.cluster_id ?? "control"}-${hb.component}@${hb.hostname}`}
            emptyState={
              <div className="px-3 py-6 text-center text-xs text-muted-foreground">
                No heartbeats received yet. Components POST to <span className="font-mono">/api/v1/heartbeats</span> every 30s.
              </div>
            }
          />
        </div>
      ),
    },
    {
      value: "crashloops",
      label: "Crashloops",
      count: crashloop.length,
      content:
        crashloop.length > 0 ? (
          <ol className="space-y-1.5 rounded-lg border border-border bg-card p-3" data-testid="system-health-crashloop">
            {crashloop.map((ev) => (
              <li key={ev.id} className="flex items-center justify-between gap-3 rounded-md bg-muted/30 px-3 py-1.5 text-xs">
                <div className="flex items-center gap-2">
                  <span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--color-severity-critical)" }} />
                  <span className="font-mono">{ev.component}</span>
                  <span className="text-muted-foreground">@</span>
                  <span className="font-mono">{ev.hostname}</span>
                </div>
                <div className="text-muted-foreground">
                  uptime <span className="text-foreground tabular-nums">{ev.prev_uptime_s}s</span> → <span className="text-foreground tabular-nums">{ev.new_uptime_s}s</span>
                </div>
                <div className="text-muted-foreground">{formatRelative(ev.detected_at)}</div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-sm text-muted-foreground">No crashloop events. 🎉</p>
        ),
    },
    {
      value: "incidents",
      label: "Incidents & Actions",
      count: incidents.length + actions.length,
      content: (
        <div className="grid gap-3 lg:grid-cols-2">
          <section className="rounded-lg border border-border bg-card p-4" data-testid="system-health-incidents">
            <h2 className="text-sm font-semibold">Active incidents</h2>
            <div className="mt-3 space-y-2">
              {incidents.length === 0 && <p className="text-xs text-muted-foreground">No active incidents.</p>}
              {incidents.map((incident) => (
                <article key={incident.id} className="rounded-md border border-border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-xs font-medium">{incident.summary}</div>
                    <Status value={incident.status} />
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">{incident.impact}</p>
                </article>
              ))}
            </div>
          </section>
          <section className="rounded-lg border border-border bg-card p-4" data-testid="system-health-actions">
            <h2 className="text-sm font-semibold">Remediation actions</h2>
            <div className="mt-3 space-y-2">
              {actions.length === 0 && <p className="text-xs text-muted-foreground">No open actions.</p>}
              {actions.map((action) => (
                <article key={action.id} className="rounded-md bg-muted p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-xs font-medium">{action.title}</div>
                    <Status value={action.priority} />
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{action.owner} · due {new Date(action.due_at).toLocaleString()}</p>
                  <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
                    {action.steps.map((step) => <li key={step}>{step}</li>)}
                  </ul>
                </article>
              ))}
            </div>
          </section>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-5" data-testid="system-health-page">
      {/* ------------- LICENSE BANNER ------------- */}
      {license && license.banner_visible && <LicenseBanner license={license} />}

      <PageHeader
        title="System Health"
        description="Fleet-wide build version, restart history, drift, and licensing for the control plane and every connected cluster."
        actions={
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Sparkles className="h-4 w-4" />
            <span>License: <span className="font-medium text-foreground">{license?.kind ?? "unknown"}</span></span>
            {license?.expires_at && (
              <span className="ml-2">expires in <span className="font-medium text-foreground">{license.days_to_expiry}d</span></span>
            )}
          </div>
        }
      />
      {cp.commit_short && (
        <p className="text-xs text-muted-foreground">
          API build <span className="font-mono">{cp.commit_short}</span> · v{cp.version} · up {formatUptime(Number(cp.uptime_s || 0))}
        </p>
      )}

      {/* ------------- VERDICT ------------- */}
      <VerdictBanner status={verdictStatus} title={verdictTitle} detail={verdictDetail} />

      {/* ------------- FLEET STAT TILES ------------- */}
      <section
        className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5"
        data-testid="system-health-fleet-tiles"
      >
        <StatCard
          label="Healthy components"
          value={data.summary.healthy ?? 0}
          icon={<CheckCircle2 className="h-3.5 w-3.5" />}
          tone={(data.summary.healthy ?? 0) > 0 ? "accent" : "neutral"}
          hint={`${heartbeats.length} reporting`}
        />
        <StatCard
          label="Version drift"
          value={data.summary.drift ?? 0}
          icon={<RefreshCcw className="h-3.5 w-3.5" />}
          tone={(data.summary.drift ?? 0) > 0 ? "high" : "neutral"}
          hint={(data.summary.drift ?? 0) > 0 ? "components on mismatched build" : "all on same build"}
        />
        <StatCard
          label="Degraded scanners"
          value={data.summary.degraded ?? 0}
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
          tone={(data.summary.degraded ?? 0) > 0 ? "high" : "neutral"}
          hint={(data.summary.degraded ?? 0) > 0 ? "alive but dependency degraded" : "scanner dependencies ready"}
        />
        <StatCard
          label="Stale (>5m)"
          value={data.summary.stale ?? 0}
          icon={<Clock className="h-3.5 w-3.5" />}
          tone={(data.summary.stale ?? 0) > 0 ? "medium" : "neutral"}
          hint="heartbeat overdue"
        />
        <StatCard
          label="Crashlooping"
          value={data.summary.crashlooping ?? 0}
          icon={<AlertTriangle className="h-3.5 w-3.5" />}
          tone={(data.summary.crashlooping ?? 0) > 0 ? "critical" : "neutral"}
          hint=">3 restarts/hour"
        />
      </section>

      {/* ------------- DETAIL TABS (progressive disclosure) ------------- */}
      <Tabs value={tab} onValueChange={setTab} items={tabs} />
    </div>
  );
}

// -----------------------------------------------------------------------------
// Sub-components
// -----------------------------------------------------------------------------

function LicenseBanner({ license }: { license: SystemHealthLicense }) {
  const tone = ({
    info: "border-[color:var(--color-status-success)] bg-[color:var(--color-status-success)]/10 text-[color:var(--color-status-success)]",
    warning: "border-[color:var(--color-status-warning)] bg-[color:var(--color-status-warning)]/10 text-[color:var(--color-status-warning)]",
    critical: "border-[color:var(--color-severity-critical)] bg-[color:var(--color-severity-critical)]/10 text-[color:var(--color-severity-critical)]",
    fatal: "border-[color:var(--color-severity-critical)] bg-[color:var(--color-severity-critical)]/20 text-[color:var(--color-severity-critical)]",
  } as Record<string, string>)[license.severity] ?? "border-border bg-muted";
  return (
    <div
      className={`flex items-center gap-3 rounded-md border px-4 py-2 text-sm ${tone}`}
      data-testid="system-health-license-banner"
      role="status"
    >
      <ShieldAlert className="h-4 w-4" />
      <div className="flex-1">
        <div className="font-medium">{license.message}</div>
        <div className="text-[11px] opacity-80">
          {license.kind} · expires {license.expires_at ?? "n/a"} · {license.days_to_expiry}d remaining
        </div>
      </div>
    </div>
  );
}

function ClusterCard({ cluster }: { cluster: SystemHealthClusterDrift }) {
  const degraded = cluster.degraded ?? 0;
  const trouble = degraded + cluster.drift + cluster.stale + cluster.crashlooping;
  return (
    <article
      className="rounded-lg border border-border bg-card p-3"
      data-testid="system-health-cluster-card"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm font-semibold">{cluster.cluster_name}</div>
        <span
          className={`rounded-md px-2 py-0.5 text-[10px] ${
            trouble === 0
              ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
              : "bg-[color:var(--color-severity-high)]/15 text-[color:var(--color-severity-high)]"
          }`}
        >
          {trouble === 0 ? "in sync" : `${trouble} issue${trouble === 1 ? "" : "s"}`}
        </span>
      </div>
      <div className="mt-2 grid grid-cols-5 gap-2 text-[10px]">
        <Stat label="healthy" value={cluster.healthy} tone="success" />
        <Stat label="degraded" value={degraded} tone="warning" />
        <Stat label="drift" value={cluster.drift} tone="warning" />
        <Stat label="stale" value={cluster.stale} tone="warning" />
        <Stat label="crash" value={cluster.crashlooping} tone="error" />
      </div>
      <div className="mt-2 text-[10px] text-muted-foreground">
        control build <span className="font-mono">{cluster.control_commit || "—"}</span>
      </div>
      <details className="mt-1">
        <summary className="cursor-pointer text-[10px] text-muted-foreground hover:text-foreground">
          versions ({cluster.versions.length})
        </summary>
        <ul className="mt-1 space-y-0.5 text-[10px] text-muted-foreground">
          {cluster.versions.map((v) => (
            <li key={`${v.component}-${v.commit}`} className="flex items-center justify-between gap-2">
              <span>{v.component}</span>
              <span className="font-mono">{v.commit}</span>
              <span>×{v.count}</span>
            </li>
          ))}
        </ul>
      </details>
    </article>
  );
}

function StatusPill({ status, reason }: { status: SystemHealthHeartbeat["status"]; reason?: string }) {
  const cls =
    status === "healthy"
      ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
      : status === "drift"
      ? "bg-[color:var(--color-severity-high)]/15 text-[color:var(--color-severity-high)]"
      : status === "degraded"
      ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
      : status === "stale"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
      : status === "crashlooping"
      ? "bg-[color:var(--color-severity-critical)]/20 text-[color:var(--color-severity-critical)]"
      : "bg-muted text-muted-foreground";
  return (
    <span className={`rounded-md px-2 py-0.5 text-[10px] ${cls}`} title={reason ?? undefined}>
      {status}
    </span>
  );
}

function HeartbeatDetails({ hb }: { hb: SystemHealthHeartbeat }) {
  if (hb.component !== "scanner" || !hb.metadata) {
    return <span className="text-muted-foreground">—</span>;
  }
  const vulndb = hb.metadata.vulndb;
  const cacheHealth = hb.metadata.cache_health ?? {};
  const cacheBad = Object.entries(cacheHealth)
    .filter(([, item]) => item.configured && item.writable === false)
    .map(([name, item]) => `${name}:${item.status ?? "bad"}`);
  const activeTargets = compactCountMap(hb.metadata.active_jobs_by_target_type);
  const targetCapacity = compactCountMap(hb.metadata.target_capacity);
  return (
    <div className="max-w-[280px] truncate text-[11px] text-muted-foreground">
      <span className="font-mono text-foreground">{hb.metadata.active_jobs ?? 0}/{hb.metadata.max_concurrent ?? "?"}</span>
      <span> busy</span>
      <span> · idle </span>
      <span className="font-mono text-foreground">{hb.metadata.idle_capacity ?? 0}</span>
      {activeTargets && <span title={`active jobs: ${activeTargets}`}> · active {activeTargets}</span>}
      {targetCapacity && <span title={`target capacity: ${targetCapacity}`}> · cap {targetCapacity}</span>}
      {vulndb && (
        <span>
          {" · vulndb "}
          <span className="font-mono text-foreground">{vulndb.status ?? (vulndb.ready ? "ready" : "unknown")}</span>
          {vulndb.bundle_version ? <span className="font-mono"> {vulndb.bundle_version}</span> : null}
        </span>
      )}
      {cacheBad.length > 0 && <span title={cacheBad.join(", ")}> · cache {cacheBad.length} bad</span>}
    </div>
  );
}

function compactCountMap(values?: Record<string, number>) {
  if (!values) return "";
  return Object.entries(values)
    .filter(([, value]) => value !== undefined && value !== null)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}:${value}`)
    .join(" ");
}

function Stat({ label, value, tone }: { label: string; value: number; tone: "success" | "warning" | "error" }) {
  const color = tone === "success"
    ? "var(--color-status-success)"
    : tone === "warning"
    ? "var(--color-status-warning)"
    : "var(--color-severity-critical)";
  return (
    <div className="rounded-md bg-muted px-1.5 py-1 text-center">
      <div className="text-sm font-semibold tabular-nums" style={{ color: value > 0 ? color : undefined }}>
        {value}
      </div>
      <div className="text-[9px] text-muted-foreground">{label}</div>
    </div>
  );
}

function Status({ value }: { value: string }) {
  const cls = value === "healthy" || value === "done"
    ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
    : value === "warning" || value === "mitigating" || value === "in_progress" || value === "medium"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
      : value === "degraded" || value === "critical" || value === "high"
        ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
        : "bg-muted text-muted-foreground";
  return <span className={`rounded-md px-2 py-1 text-xs ${cls}`}>{value}</span>;
}

// -----------------------------------------------------------------------------
// Formatting helpers
// -----------------------------------------------------------------------------

function formatUptime(seconds: number): string {
  if (!seconds || seconds <= 0) return "—";
  const d = Math.floor(seconds / 86400);
  if (d > 0) return `${d}d${Math.floor((seconds % 86400) / 3600)}h`;
  const h = Math.floor(seconds / 3600);
  if (h > 0) return `${h}h${Math.floor((seconds % 3600) / 60)}m`;
  const m = Math.floor(seconds / 60);
  if (m > 0) return `${m}m${seconds % 60}s`;
  return `${seconds}s`;
}

function formatRelative(iso: string): string {
  const t = new Date(iso).getTime();
  if (!t) return iso;
  const diff = Math.floor((Date.now() - t) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
