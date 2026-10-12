import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouteSearchParams } from "@/lib/route-search";
import { Activity, AlertTriangle, Clock, Gauge, Search, ServerCog, ShieldCheck, SlidersHorizontal } from "lucide-react";
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
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState, LoadingState } from "@/components/ui/states";

const statuses = ["all", "healthy", "degraded", "stale", "drift", "crashlooping", "missing", "not-observed"];

export function ComponentsPage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const clusterFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
  const clusterDetail = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
  const cachedScopeValid = (!registry || (registry.status === "success" && registry.fetchStatus === "idle")) && (!clusterDetail || (clusterDetail.status !== "error" && clusterDetail.fetchStatus === "idle"));
  const clusterResolved = Boolean(clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError && !registryFetching && !clusterFetching && cachedScopeValid && ((!registry && !clusterDetail) || (registry?.data?.clusters.find((item) => item.id === clusterId) ?? clusterDetail?.data)?.id === clusterId));
  const [searchParams, setSearchParams] = useRouteSearchParams();
  const query = searchParams.get("q") ?? "";
  const status = statuses.includes(searchParams.get("status") ?? "") ? searchParams.get("status")! : "all";
  const nvRole = normalizeNVRole(searchParams.get("role"));
  const selectedID = searchParams.get("component");
  const tab = ["inventory", "families", "versions"].find((value) => value === searchParams.get("tab")) ?? "inventory";
  function updateURL(changes: Record<string, string | null>, replace = false) {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      for (const [key, value] of Object.entries(changes)) {
        if (value === null || value === "") next.delete(key); else next.set(key, value);
      }
      return next;
    }, { replace });
  }
  function selectNVRole(role: string) { updateURL({ role: role === "all" ? null : role }); }
  function selectComponent(id: string) { updateURL({ component: id }); }
  const q = useQuery({
    queryKey: ["components-inventory", clusterId],
    queryFn: () => componentsInventory.list({ cluster_id: clusterId, limit: 1000 }),
    enabled: clusterResolved,
    refetchInterval: 30_000,
  });
  const inventoryScopeValid = q.data?.components.every((item) => item.cluster_id === clusterId) ?? false;
  const selectedQ = useQuery({
    queryKey: ["component-instance", clusterId, selectedID],
    queryFn: () => componentsInventory.get(selectedID!),
    enabled: clusterResolved && tab === "inventory" && q.isSuccess && !q.isFetching && inventoryScopeValid && !!selectedID,
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
    return instances.filter((item) => matchesComponentFilters(item, needle, status, nvRole));
  }, [instances, query, status, nvRole]);
  const versionRows = useMemo(() => componentVersionRows(rollups, instances), [rollups, instances]);
  const detailMatches = Boolean(selectedID && selectedQ.data?.component?.id === selectedID && selectedQ.data.component.cluster_id === clusterId);
  const selectionKey = `${clusterId}:${selectedID}`;
  const [confirmedSelection, setConfirmedSelection] = useState<string | null>(null);
  const detailSettled = clusterResolved && selectedQ.isFetchedAfterMount && selectedQ.isSuccess && !selectedQ.isFetching && detailMatches;
  if (detailSettled && confirmedSelection !== selectionKey) setConfirmedSelection(selectionKey);
  const selected = selectedQ.isSuccess && detailMatches && (detailSettled || confirmedSelection === selectionKey) ? selectedQ.data!.component : null;
  const selectedFilteredOut = Boolean(selected && !matchesComponentFilters(selected, query, status, nvRole));
  const diagnosticsQ = useQuery({
    queryKey: ["component-diagnostics", clusterId, selectedID],
    queryFn: () => componentsInventory.diagnostics(selectedID!),
    enabled: clusterResolved && tab === "inventory" && q.isSuccess && !q.isFetching && inventoryScopeValid && !selectedQ.isFetching && Boolean(selected) && !selectedFilteredOut,
    refetchInterval: 30_000,
    retry: (failureCount, error) => !isForbidden(error) && failureCount < 2,
  });
  const diagnosticsMatches = Boolean(diagnosticsQ.data?.component?.id === selectedID && diagnosticsQ.data?.component.cluster_id === clusterId);
  const bundleScopeReady = () => {
    const inventoryState = qc.getQueryState(["components-inventory", clusterId]);
    const detailState = qc.getQueryState<{ component: ComponentInstance }>(["component-instance", clusterId, selectedID]);
    const diagnosticState = qc.getQueryState<ComponentDiagnostics>(["component-diagnostics", clusterId, selectedID]);
    const currentRegistry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
    const currentCluster = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
    return clusterResolved && inventoryScopeValid && !selectedFilteredOut && ((!currentRegistry && !currentCluster) || (currentRegistry?.data?.clusters.find((item) => item.id === clusterId) ?? currentCluster?.data)?.id === clusterId) && (!currentRegistry || (currentRegistry.status === "success" && currentRegistry.fetchStatus === "idle")) && (!currentCluster || (currentCluster.status !== "error" && currentCluster.fetchStatus === "idle"))
      && inventoryState?.status === "success" && inventoryState.fetchStatus === "idle"
      && detailState?.status === "success" && detailState.fetchStatus === "idle" && detailState.data?.component.id === selectedID && detailState.data.component.cluster_id === clusterId
      && diagnosticState?.status === "success" && diagnosticState.fetchStatus === "idle" && diagnosticState.data?.component.id === selectedID && diagnosticState.data.component.cluster_id === clusterId && diagnosticState.data.debug.support_bundle_enabled;
  };
  const summary = q.data?.summary;

  if (clusterLoading || registryFetching || clusterFetching) return <LoadingState label="Loading cluster…" />;
  if (!clusterResolved) return <ErrorState title="Cluster could not be resolved." error={clusterError} />;
  if (q.isPending) return <LoadingState label="Loading component inventory…" />;
  if (q.isSuccess && !inventoryScopeValid) return <ErrorState title="Component inventory does not match the active cluster." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  if (q.isError) return <div className="space-y-6" data-testid="components-page">
    <PageHeader title="Components" description="Health and build inventory for this cluster." />
    <ErrorState title="Component inventory could not be loaded." error={q.error} action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
  </div>;

  const attention = (summary?.degraded ?? 0) + (summary?.drift ?? 0) + (summary?.stale ?? 0) + (summary?.crashlooping ?? 0) + (summary?.missing ?? 0);

  const columns: Column<ComponentInstance>[] = [
    {
      id: "component",
      header: "Component", kind: "name", wrap: true,
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
      header: "Build", kind: "version", size: 184, minSize: 128, maxSize: 240, wrap: true,
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
      header: "Runtime", kind: "age", size: 152, minSize: 112, maxSize: 192, wrap: true,
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
      header: "Counters", kind: "text", size: 224, minSize: 160, maxSize: 320, wrap: true,
      exportValue: (item) => compactComponentCounters(item),
      cell: (item) => (
        <div className="text-xs">
          <CounterMini item={item} />
        </div>
      ),
    },
    {
      id: "status",
      header: "Status", kind: "text", size: 240, minSize: 208, maxSize: 320, wrap: true,
      exportValue: (item) => `${item.status}; ${item.status_reason || item.last_error || "No status reason recorded"}; last_seen=${item.last_seen_at}`,
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{formatDate(item.last_seen_at)}</div>
          <div className="mt-1 text-muted-foreground">{item.status_reason || item.last_error || "No status reason recorded"}</div>
        </div>
      ),
    },
  ];
  const versionColumns: Column<ComponentVersionRow>[] = [
    {
      id: "component",
      header: "Component", kind: "name", wrap: true,
      exportValue: (row) => row.displayName,
      cell: (row) => (
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill tone="accent">{row.roleLabel}</Pill>
            <StatusPill status={row.status} />
          </div>
          <div className="mt-1 text-xs font-medium" title={row.displayName}>{row.displayName}</div>
          <div className="mt-0.5 font-mono text-[10px] text-muted-foreground" title={row.component}>{row.component}</div>
        </div>
      ),
      sort: (a, b) => a.roleRank - b.roleRank || a.displayName.localeCompare(b.displayName),
    },
    {
      id: "build",
      header: "Build", kind: "version", size: 184, minSize: 128, maxSize: 240, wrap: true,
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
      header: "Instances", kind: "count",
      numeric: true,
      cell: (row) => <span className="font-mono text-xs">{row.healthy}/{row.instances}</span>,
      exportValue: (row) => `${row.healthy}/${row.instances}`,
      sort: (a, b) => a.instances - b.instances,
    },
    {
      id: "readiness",
      header: "Readiness", kind: "text", size: 224, minSize: 160, maxSize: 280, wrap: true,
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
      header: "Scanner capacity", kind: "text", size: 224, minSize: 176, maxSize: 320, wrap: true,
      cell: (row) => <span className="text-xs text-muted-foreground">{row.capacity}</span>,
      exportValue: (row) => row.capacity,
    },
    {
      id: "heartbeat",
      header: "Last heartbeat", kind: "date", size: 224, minSize: 208, maxSize: 240,
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

      <VerdictBanner status={(summary?.crashlooping ?? 0) || (summary?.missing ?? 0) ? "critical" : attention ? "degraded" : (summary?.total_instances ?? 0) ? "ok" : "info"}
        title={attention ? `${attention} component${attention === 1 ? " needs" : "s need"} attention` : (summary?.total_instances ?? 0) ? "Observed components are healthy" : "No component instances observed"}
        detail="Health totals cover the active cluster. Inventory search and role/status filters apply to loaded instances." />
      <StatGrid data-testid="component-summary">
        <StatCard label="Instances" value={summary?.total_instances ?? 0} icon={<ServerCog className="h-3.5 w-3.5" />} />
        <StatCard label="Healthy" value={summary?.healthy ?? 0} icon={<Activity className="h-3.5 w-3.5" />} />
        <StatCard label="Needs attention" value={attention} tone={attention ? "medium" : "neutral"} hint="Unhealthy instances and missing expected component families." />
        <StatCard label="Crashlooping" value={summary?.crashlooping ?? 0} tone={(summary?.crashlooping ?? 0) ? "critical" : "neutral"} />
        <StatCard label="Missing" value={summary?.missing ?? 0} tone={(summary?.missing ?? 0) ? "critical" : "neutral"} icon={<AlertTriangle className="h-3.5 w-3.5" />} />
      </StatGrid>
      {q.isFetching && <LoadingState label="Refreshing component inventory…" />}
      <Tabs value={tab} onValueChange={(value) => updateURL({ tab: value === "inventory" ? null : value })} items={[
        { value: "inventory", label: "Inventory", content: (<div className="space-y-4">
      <section className="rounded-lg border border-border bg-card p-3">
        <p className="mb-2 text-xs text-muted-foreground">Role counts cover loaded instances.</p>
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
              aria-label="Search components"
              onChange={(event) => updateURL({ q: event.target.value }, true)}
              placeholder="Search component, host, version, role, NV alias"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="component-search"
            />
          </label>
          <select
            value={status}
            aria-label="Component status"
            onChange={(event) => updateURL({ status: event.target.value === "all" ? null : event.target.value })}
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
          sourceLimit={1000}
          sourceCount={instances.length}
          columns={columns}
          rowKey={(item) => item.id}
          onRowClick={(item) => selectComponent(item.id)}
          selected={selected ? new Set([selected.id]) : undefined}
          preferencesKey="components.inventory"
          exportFileName="constellation-components-loaded"
          exportLabel="Export matching loaded instances CSV"
          testId="component-inventory-table"
          emptyState={
            <div className="px-3 py-8 text-center text-xs text-muted-foreground">
              No component instances match the current filters.
            </div>
          }
        />

        <p className="text-xs text-muted-foreground">{filtered.length} matching loaded instances. Search, role counts, and inventory CSV cover up to 1,000 loaded instances. Select an instance to inspect its diagnostics.</p>
        {selectedID && <div><Button size="sm" variant="outline" onClick={() => updateURL({ component: null })}>Clear inspection</Button></div>}
        {selected && (q.isFetching || selectedQ.isFetching) && <p role="status" className="text-xs text-muted-foreground">Refreshing selected component… The confirmed preview remains visible; bundle creation is paused.</p>}
        {!selectedID ? <ComponentPreview item={null} diagnostics={null} diagnosticsLoading={false} diagnosticsError={null} onRetryDiagnostics={() => void diagnosticsQ.refetch()} bundleScopeReady={bundleScopeReady} />
          : !selected && (selectedQ.isPending || selectedQ.isFetching) ? <LoadingState label={selectedQ.isPending ? "Loading selected component…" : "Refreshing selected component…"} />
          : selectedQ.isError ? <ErrorState title="Selected component could not be loaded." action={<Button onClick={() => void selectedQ.refetch()}>Retry component</Button>} />
          : !detailMatches ? <ErrorState title="Selected component is unavailable in the active cluster." action={<Button onClick={() => void selectedQ.refetch()}>Retry component</Button>} />
          : selectedFilteredOut ? <EmptyState title="Selected component is outside the active filters" hint="Clear the inventory filters to inspect this component. Your URL selection is preserved." />
          : <ComponentPreview key={`${clusterId}:${selectedID}`} item={selected} diagnostics={diagnosticsMatches ? diagnosticsQ.data ?? null : null} diagnosticsLoading={diagnosticsQ.isPending || diagnosticsQ.isFetching}
              diagnosticsError={diagnosticsQ.isError ? diagnosticsQ.error : diagnosticsQ.isSuccess && !diagnosticsMatches ? new Error("Scope mismatch") : null} onRetryDiagnostics={() => void diagnosticsQ.refetch()} bundleScopeReady={bundleScopeReady} />}
      </section>
      </div>) },
        { value: "families", label: "Families", content: (
      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" data-testid="component-rollups">
        {rollups.map((rollup) => (
          <RollupCard key={rollup.component} rollup={rollup} />
        ))}
      </section>

        ) },
        { value: "versions", label: "Versions", content: (
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
          preferencesKey="components.versions"
          exportFileName="constellation-component-version-matrix"
          emptyState={
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              No component rollups have reported yet.
            </div>
          }
          className="rounded-md"
        />
      </section>

        ) },
      ]} />
    </div>
  );
}

function matchesComponentFilters(item: ComponentInstance, query: string, status: string, role: string) {
  if (status !== "all" && item.status !== status) return false;
  if (role !== "all" && nvRoleAlias(item).id !== role) return false;
  const needle = query.trim().toLowerCase();
  return !needle || [item.component, item.display_name, item.role, nvRoleAlias(item).label, item.scope, item.kind, item.hostname, item.version ?? "", item.commit ?? "", item.cluster_name ?? "", item.status_reason ?? ""].some((value) => value.toLowerCase().includes(needle));
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
      reason: rollup.last_status_cause || "No status reason recorded",
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
  onRetryDiagnostics,
  bundleScopeReady,
}: {
  item: ComponentInstance | null;
  diagnostics: ComponentDiagnostics | null;
  diagnosticsLoading: boolean;
  diagnosticsError: unknown;
  onRetryDiagnostics: () => void;
  bundleScopeReady: () => boolean;
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
      <DiagnosticsPanel diagnostics={diagnostics} loading={diagnosticsLoading} error={diagnosticsError} onRetry={onRetryDiagnostics} bundleScopeReady={bundleScopeReady} />
      <section className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Public heartbeat metadata</h3>
        <pre className="mt-3 max-h-[420px] overflow-auto rounded-md border border-border bg-muted p-3 text-xs">
          {JSON.stringify(item.metadata ?? {}, null, 2)}
        </pre>
      </section>
    </aside>
  );
}

function DiagnosticsPanel({ diagnostics, loading, error, onRetry, bundleScopeReady }: { diagnostics: ComponentDiagnostics | null; loading: boolean; error: unknown; onRetry: () => void; bundleScopeReady: () => boolean }) {
  const [queuedJobId, setQueuedJobId] = useState<string | null>(null);
  const supportBundle = useMutation({
    mutationFn: () => { if (!bundleScopeReady()) throw new Error("Current diagnostics are unavailable"); return supportBundles.createJob(); },
    onSuccess: (job) => {
      setQueuedJobId(job.id);
      toast.success("Support bundle queued. Track it in System Health.");
    },
    onError: () => toast.error("Could not queue support bundle"),
  });
  if (isForbidden(error)) {
    return (
      <section className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
          <h3 className="text-sm font-semibold">Diagnostics</h3>
        </div>
        <p className="mt-2 text-xs text-muted-foreground">Global admin access required.</p>
        <Button className="mt-3" onClick={onRetry}>Retry diagnostics</Button>
      </section>
    );
  }
  if (error) return <ErrorState title="Component diagnostics could not be loaded." action={<Button onClick={onRetry}>Retry diagnostics</Button>} />;
  if (loading) return <LoadingState label="Loading or refreshing diagnostics…" />;
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
            disabled={!diagnostics.debug.support_bundle_enabled || supportBundle.isPending || !bundleScopeReady()}
            data-testid="component-support-bundle"
            title="Queue a redacted support bundle for the organization"
          >
            <Clock className="h-3.5 w-3.5" aria-hidden />
            {supportBundle.isPending ? "Queuing..." : "Create org-wide bundle"}
          </Button>
          <Pill tone="accent">{diagnostics.admin_gate}</Pill>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">Support bundles cover the organization; they are not limited to this component or cluster.</p>
      {supportBundle.isError && <ErrorState title="Could not queue an organization support bundle. Try again." />}
      {queuedJobId && <p className="text-xs text-muted-foreground" role="status" data-testid="component-support-bundle-feedback">
        Bundle job <span className="font-mono">{queuedJobId}</span> queued. <a href="/settings/health?tab=bundles" className="text-[color:var(--color-primary)] hover:underline">View status and download in System Health</a>.
      </p>}
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
