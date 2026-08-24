import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { Activity, AlertTriangle, Download, Gauge, Search, ServerCog, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { toast } from "sonner";

import {
  componentsInventory,
  supportBundles,
  type ComponentDiagnosticCheck,
  type ComponentDiagnosticConfig,
  type ComponentDiagnosticCounter,
  type ComponentDiagnostics,
  type ComponentInstance,
  type ComponentRollup,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";
import { NV_COMPONENT_ROLES, normalizeNVRole, nvRoleAlias } from "@/lib/component-roles";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { downloadJson } from "@/lib/download";

const statuses = ["all", "healthy", "degraded", "stale", "drift", "crashlooping", "missing", "not-observed"];

export function ComponentsPage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [searchParams, setSearchParams] = useSearchParams();
  const roleParam = normalizeNVRole(searchParams.get("role"));
  const queryParam = searchParams.get("q") ?? "";
  const [query, setQuery] = useState(queryParam);
  const [status, setStatus] = useState("all");
  const [nvRole, setNvRole] = useState(roleParam);
  const selectedParam = searchParams.get("component");
  const [selectedID, setSelectedID] = useState<string | null>(selectedParam);

  useEffect(() => {
    setNvRole(roleParam);
  }, [roleParam]);

  useEffect(() => {
    setQuery(queryParam);
  }, [queryParam]);

  useEffect(() => {
    setSelectedID(selectedParam);
  }, [selectedParam]);

  function selectNVRole(role: string) {
    setNvRole(role);
    const next = new URLSearchParams(searchParams);
    if (role === "all") {
      next.delete("role");
    } else {
      next.set("role", role);
    }
    setSearchParams(next, { replace: true });
  }

  function selectComponent(id: string) {
    setSelectedID(id);
    const next = new URLSearchParams(searchParams);
    next.set("component", id);
    setSearchParams(next, { replace: true });
  }

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
  const nvRoleCounts = useMemo(() => {
    const counts = new Map<string, number>();
    counts.set("all", instances.length);
    for (const item of instances) {
      const alias = nvRoleAlias(item).id;
      counts.set(alias, (counts.get(alias) ?? 0) + 1);
    }
    return counts;
  }, [instances]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return instances.filter((item) => {
      if (status !== "all" && item.status !== status) return false;
      if (nvRole !== "all" && nvRoleAlias(item).id !== nvRole) return false;
      if (!needle) return true;
      return [
        item.component,
        item.display_name,
        item.role,
        nvRoleAlias(item).label,
        item.scope,
        item.kind,
        item.hostname,
        item.version ?? "",
        item.commit ?? "",
        item.cluster_name ?? "",
        item.status_reason ?? "",
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [instances, query, status, nvRole]);
  const versionRows = useMemo(() => componentVersionRows(rollups, instances), [rollups, instances]);
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
      exportValue: (item) => item.display_name || item.component,
      cell: (item) => (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            <StatusPill status={item.status} />
            <Pill tone="accent">{nvRoleAlias(item).label}</Pill>
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
      exportValue: (item) => `${item.version || "unknown"} ${item.commit_short || item.commit || ""}`.trim(),
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
      exportValue: (item) => `${formatUptime(item.uptime_seconds)}; ${item.restart_count} restarts`,
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
      exportValue: (item) => compactComponentCounters(item),
      cell: (item) => (
        <div className="text-xs">
          <CounterMini item={item} />
        </div>
      ),
    },
    {
      id: "status",
      header: "Status",
      exportValue: (item) => `${item.status}; ${item.status_reason || item.last_error || "heartbeat current"}; last_seen=${item.last_seen_at}`,
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{formatDate(item.last_seen_at)}</div>
          <div className="mt-1 text-muted-foreground">{item.status_reason || item.last_error || "heartbeat current"}</div>
        </div>
      ),
    },
  ];
  const versionColumns: Column<ComponentVersionRow>[] = [
    {
      id: "component",
      header: "Component",
      exportValue: (row) => row.displayName,
      cell: (row) => (
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill tone="accent">{row.roleLabel}</Pill>
            <StatusPill status={row.status} />
          </div>
          <div className="mt-1 truncate text-xs font-medium" title={row.displayName}>{row.displayName}</div>
          <div className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground" title={row.component}>{row.component}</div>
        </div>
      ),
      sort: (a, b) => a.roleRank - b.roleRank || a.displayName.localeCompare(b.displayName),
    },
    {
      id: "build",
      header: "Build",
      exportValue: (row) => `${row.version} ${row.commit}`.trim(),
      cell: (row) => (
        <div className="text-xs">
          <div className="font-medium">{row.version}</div>
          <div className="mt-1 font-mono text-muted-foreground">{row.commit}</div>
        </div>
      ),
      sort: (a, b) => a.version.localeCompare(b.version) || a.commit.localeCompare(b.commit),
    },
    {
      id: "instances",
      header: "Instances",
      numeric: true,
      cell: (row) => <span className="font-mono text-xs">{row.healthy}/{row.instances}</span>,
      exportValue: (row) => `${row.healthy}/${row.instances}`,
      sort: (a, b) => a.instances - b.instances,
    },
    {
      id: "readiness",
      header: "Readiness",
      exportValue: (row) => `${row.readiness}; ${row.reason}`,
      cell: (row) => (
        <div className="text-xs">
          <div className={cn("font-medium", row.attention > 0 ? "text-[color:var(--color-status-warning)]" : "text-[color:var(--color-status-success)]")}>{row.readiness}</div>
          <div className="mt-1 text-muted-foreground">{row.reason}</div>
        </div>
      ),
      sort: (a, b) => b.attention - a.attention || a.readiness.localeCompare(b.readiness),
    },
    {
      id: "capacity",
      header: "Scanner capacity",
      cell: (row) => <span className="text-xs text-muted-foreground">{row.capacity}</span>,
      exportValue: (row) => row.capacity,
    },
    {
      id: "heartbeat",
      header: "Last heartbeat",
      cell: (row) => <span className="text-xs text-muted-foreground">{formatDate(row.lastSeenAt)}</span>,
      exportValue: (row) => row.lastSeenAt ?? "",
      sort: (a, b) => timeValue(a.lastSeenAt) - timeValue(b.lastSeenAt),
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
          <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6" data-testid="component-summary">
            <StatCard label="Instances" value={summary?.total_instances ?? 0} icon={<ServerCog className="h-3.5 w-3.5" />} />
            <StatCard label="Missing" value={summary?.missing ?? 0} tone={(summary?.missing ?? 0) > 0 ? "critical" : "neutral"} icon={<AlertTriangle className="h-3.5 w-3.5" />} />
            <StatCard label="Degraded" value={degraded} tone={degraded > 0 ? "medium" : "neutral"} icon={<Activity className="h-3.5 w-3.5" />} />
            <StatCard label="NV Controllers" value={nvRoleCounts.get("controller") ?? 0} icon={<ServerCog className="h-3.5 w-3.5" />} />
            <StatCard label="NV Enforcers" value={nvRoleCounts.get("enforcer") ?? 0} icon={<ShieldCheck className="h-3.5 w-3.5" />} />
            <StatCard label="NV Scanners" value={nvRoleCounts.get("scanner") ?? 0} icon={<Gauge className="h-3.5 w-3.5" />} />
          </section>
        );
      })()}

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" data-testid="component-rollups">
        {rollups.map((rollup) => (
          <RollupCard key={rollup.component} rollup={rollup} />
        ))}
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-card p-3" data-testid="component-version-matrix">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold">Version Drift & Readiness</h2>
            <p className="mt-1 text-xs text-muted-foreground">Controller, enforcer, scanner, admission, and importer build state with heartbeat reason and scanner capacity.</p>
          </div>
          <span className="text-xs text-muted-foreground">{versionRows.length} component families</span>
        </div>
        <DataTable<ComponentVersionRow>
          rows={versionRows}
          columns={versionColumns}
          rowKey={(row) => row.id}
          showDensityToggle={false}
          defaultSort={{ id: "component", dir: "asc" }}
          exportFileName="constellation-component-version-matrix"
          emptyState={
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              No component rollups have reported yet.
            </div>
          }
          className="rounded-md"
        />
      </section>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="mb-3 flex flex-wrap gap-2" data-testid="component-nv-role-filters">
            {NV_COMPONENT_ROLES.map((item) => {
            const active = nvRole === item.id;
            const count = nvRoleCounts.get(item.id) ?? 0;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => selectNVRole(item.id)}
                data-testid={`component-nv-role-${item.id}`}
                className={cn(
                  "inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors",
                  active
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-background text-muted-foreground hover:text-foreground",
                )}
              >
                <span>{item.label}</span>
                <span className="font-mono text-[10px]">{count}</span>
              </button>
            );
          })}
        </div>
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search component, host, version, role, NV alias"
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
          onRowClick={(item) => selectComponent(item.id)}
          selected={selected ? new Set([selected.id]) : undefined}
          exportFileName="constellation-components"
          testId="component-inventory-table"
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

interface ComponentVersionRow {
  id: string;
  roleID: string;
  roleLabel: string;
  roleRank: number;
  component: string;
  displayName: string;
  status: string;
  instances: number;
  healthy: number;
  attention: number;
  version: string;
  commit: string;
  readiness: string;
  reason: string;
  capacity: string;
  lastSeenAt?: string;
}

function RollupCard({ rollup }: { rollup: ComponentRollup }) {
  const alias = nvRoleAlias(rollup);
  return (
    <article className={cn("rounded-lg border border-border bg-card p-3", rollup.status === "missing" && "border-destructive/30")}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">{rollup.display_name}</h2>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            <Pill tone="accent">{alias.label}</Pill>
            <span className="text-xs text-muted-foreground">{rollup.role} · {rollup.scope} · {rollup.kind}</span>
          </div>
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

function componentVersionRows(rollups: ComponentRollup[], instances: ComponentInstance[]): ComponentVersionRow[] {
  const byComponent = new Map<string, ComponentInstance[]>();
  for (const instance of instances) {
    const list = byComponent.get(instance.component) ?? [];
    list.push(instance);
    byComponent.set(instance.component, list);
  }
  return rollups.map((rollup) => {
    const alias = nvRoleAlias(rollup);
    const peers = byComponent.get(rollup.component) ?? [];
    const attention = rollup.degraded + rollup.stale + rollup.drift + rollup.crashlooping + rollup.missing;
    return {
      id: rollup.component,
      roleID: alias.id,
      roleLabel: alias.label,
      roleRank: roleRank(alias.id),
      component: rollup.component,
      displayName: rollup.display_name,
      status: rollup.status,
      instances: rollup.instances,
      healthy: rollup.healthy,
      attention,
      version: rollup.latest_version || newestInstanceValue(peers, "version") || "unknown",
      commit: shortCommit(rollup.latest_commit || newestInstanceValue(peers, "commit") || ""),
      readiness: readinessLabel(rollup),
      reason: rollup.last_status_cause || "heartbeat current",
      capacity: alias.id === "scanner" ? scannerCapacitySummary(peers) : "-",
      lastSeenAt: rollup.latest_seen_at || newestInstanceSeen(peers),
    };
  }).sort((a, b) => a.roleRank - b.roleRank || a.displayName.localeCompare(b.displayName));
}

function readinessLabel(rollup: ComponentRollup): string {
  if (rollup.crashlooping > 0) return `${rollup.crashlooping} crashlooping`;
  if (rollup.missing > 0) return `${rollup.missing} missing`;
  if (rollup.stale > 0) return `${rollup.stale} stale`;
  if (rollup.drift > 0) return `${rollup.drift} drift`;
  if (rollup.degraded > 0) return `${rollup.degraded} degraded`;
  return "ready";
}

function scannerCapacitySummary(instances: ComponentInstance[]): string {
  let active = 0;
  let max = 0;
  let idle = 0;
  let sawCapacity = false;
  for (const instance of instances) {
    const metadata = instance.metadata ?? {};
    const activeJobs = numberValue(metadata.active_jobs);
    const maxConcurrent = numberValue(metadata.max_concurrent);
    const idleCapacity = numberValue(metadata.idle_capacity);
    if (activeJobs !== null) {
      active += activeJobs;
      sawCapacity = true;
    }
    if (maxConcurrent !== null) {
      max += maxConcurrent;
      sawCapacity = true;
    }
    if (idleCapacity !== null) {
      idle += idleCapacity;
      sawCapacity = true;
    }
  }
  if (!sawCapacity) return "-";
  const parts = [];
  if (max > 0) parts.push(`${active}/${max} active`);
  if (idle > 0) parts.push(`${idle} idle`);
  return parts.join(" · ") || `${active} active`;
}

function newestInstanceValue(instances: ComponentInstance[], key: "version" | "commit"): string {
  return [...instances]
    .sort((a, b) => timeValue(b.last_seen_at) - timeValue(a.last_seen_at))
    .find((instance) => instance[key])?.[key] ?? "";
}

function newestInstanceSeen(instances: ComponentInstance[]): string | undefined {
  return [...instances]
    .sort((a, b) => timeValue(b.last_seen_at) - timeValue(a.last_seen_at))[0]?.last_seen_at;
}

function shortCommit(value: string): string {
  if (!value) return "commit unknown";
  return value.length > 12 ? value.slice(0, 12) : value;
}

function roleRank(role: string): number {
  const order = ["controller", "enforcer", "scanner", "admission", "discoverer", "other"];
  const index = order.indexOf(role);
  return index === -1 ? order.length : index;
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
  const alias = nvRoleAlias(item);
  return (
    <aside className="space-y-4" data-testid="component-preview">
      <section className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex flex-wrap items-center gap-1.5">
              <StatusPill status={item.status} />
              <Pill tone="accent">{alias.label}</Pill>
            </div>
            <h2 className="mt-2 break-all text-sm font-semibold">{item.display_name}</h2>
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{item.hostname}</p>
          </div>
          <Pill tone="accent">{item.scope} · {item.kind}</Pill>
        </div>
        <dl className="mt-4 grid gap-2 text-sm">
          <Field label="NeuVector Role" value={alias.label} />
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
  const supportBundle = useMutation({
    mutationFn: supportBundles.download,
    onSuccess: (bundle) => {
      downloadJson(supportBundleFileName(bundle.generated_at), bundle);
      toast.success("Support bundle downloaded");
    },
    onError: () => toast.error("Support bundle download failed"),
  });
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
        <div className="flex items-center gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => supportBundle.mutate()}
            disabled={!diagnostics.debug.support_bundle_enabled || supportBundle.isPending}
            data-testid="component-support-bundle"
            title="Download redacted support bundle"
          >
            <Download className="h-3.5 w-3.5" aria-hidden />
            Bundle
          </Button>
          <Pill tone="accent">{diagnostics.admin_gate}</Pill>
        </div>
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

function supportBundleFileName(generatedAt: string) {
  const stamp = generatedAt ? generatedAt.replace(/[^0-9A-Za-z]/g, "-") : new Date().toISOString().replace(/[^0-9A-Za-z]/g, "-");
  return `constellation-support-bundle-${stamp}.json`;
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

function compactComponentCounters(item: ComponentInstance) {
  const metadata = item.metadata ?? {};
  const active = numberValue(metadata.active_jobs);
  const max = numberValue(metadata.max_concurrent);
  const idle = numberValue(metadata.idle_capacity);
  const processed = numberValue(metadata.processed_events);
  const dropped = numberValue(metadata.dropped_events);
  const vulndb = getRecord(metadata.vulndb);
  const vulndbStatus = stringValue(vulndb?.status) || (boolValue(vulndb?.ready) ? "ready" : "");
  return [
    active !== null && max !== null ? `${active}/${max} active` : null,
    idle !== null ? `${idle} idle` : null,
    vulndbStatus ? `vulndb ${vulndbStatus}` : null,
    processed !== null ? `${processed} events` : null,
    dropped !== null && dropped > 0 ? `${dropped} dropped` : null,
  ].filter((part): part is string => Boolean(part)).join("; ");
}

function CounterMini({ item }: { item: ComponentInstance }) {
  const parts = compactComponentCounters(item).split("; ").filter(Boolean);
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

function timeValue(value?: string): number {
  const parsed = Date.parse(value ?? "");
  return Number.isFinite(parsed) ? parsed : 0;
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
