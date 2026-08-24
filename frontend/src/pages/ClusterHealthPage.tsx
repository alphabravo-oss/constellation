import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Activity, Boxes, KeyRound, PackageCheck, ShieldCheck, UploadCloud } from "lucide-react";

import { clusters } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { sortClustersByActivity } from "@/lib/clusters";
import { componentDiagnosticsHref, nvRoleAlias } from "@/lib/component-roles";

type HealthComponent = Awaited<ReturnType<typeof clusters.health>>["components"][number];

export function ClusterHealthPage() {
  const list = useQuery({ queryKey: ["clusters"], queryFn: () => clusters.list() });
  const clusterList = useMemo(() => sortClustersByActivity(list.data?.clusters ?? []), [list.data?.clusters]);
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const selected = useMemo(
    () => clusterList.find((cluster) => cluster.id === (selectedID ?? clusterList[0]?.id)),
    [clusterList, selectedID],
  );
  const health = useQuery({
    queryKey: ["cluster-health", selected?.id],
    queryFn: () => clusters.health(selected!.id),
    enabled: !!selected?.id,
  });
  const platform = useQuery({
    queryKey: ["cluster-platform", selected?.id],
    queryFn: () => clusters.platformFacts(selected!.id),
    enabled: !!selected?.id,
    refetchInterval: 30_000,
  });

  if (list.isPending) return <p className="text-sm text-muted-foreground">Loading clusters...</p>;

  const componentColumns: Column<HealthComponent>[] = [
    {
      id: "name",
      header: "Component",
      exportValue: (c) => c.name,
      cell: (c) => {
        const role = nvRoleAlias({ name: c.name, kind: c.kind });
        return (
          <Link
            to={componentDiagnosticsHref({ clusterId: selected?.id, component: c.name, role: role.id })}
            className="font-medium hover:text-[color:var(--color-primary)]"
            data-testid={`cluster-health-component-link-${safeTestID(c.name)}`}
            title={`Open ${role.label.toLowerCase()} diagnostics`}
          >
            {c.name}
          </Link>
        );
      },
    },
    { id: "kind", header: "Kind", cell: (c) => <span className="text-xs text-muted-foreground">{c.kind}</span>, exportValue: (c) => c.kind },
    { id: "version", header: "Version", cell: (c) => <span className="font-mono text-xs">{c.version}</span>, exportValue: (c) => c.version },
    { id: "ready", header: "Ready", cell: (c) => <span className="text-xs">{c.ready}/{c.desired}</span>, exportValue: (c) => `${c.ready}/${c.desired}` },
    { id: "status", header: "Status", cell: (c) => <Status value={c.status} />, exportValue: (c) => c.status },
  ];

  return (
    <PageContainer className="space-y-4">
      <PageHeader
        title="Clusters"
        description="Sensor readiness, registration bundles, upgrade posture, and health gates for connected Kubernetes estates."
      />

      <section className="grid grid-cols-3 gap-3" data-testid="clusters-stats">
        <StatCard label="Clusters" value={clusterList.length} icon={<Boxes className="h-3.5 w-3.5" />} />
        <StatCard label="Sensors" value={health.data?.summary.connected_sensors ?? 0} icon={<Activity className="h-3.5 w-3.5" />} />
        <StatCard label="Gates" value={health.data?.gates.length ?? 0} icon={<ShieldCheck className="h-3.5 w-3.5" />} />
      </section>

      <section className="grid gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
        <div className="space-y-3" data-testid="clusters-list">
          {clusterList.map((cluster) => (
            <button
              key={cluster.id}
              type="button"
              onClick={() => setSelectedID(cluster.id)}
              className={`w-full rounded-lg border p-4 text-left transition-colors ${
                selected?.id === cluster.id ? "border-foreground bg-accent" : "border-border bg-card hover:bg-accent/50"
              }`}
              data-testid="cluster-card"
              data-cluster-id={cluster.id}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold">{cluster.name}</div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {cluster.distro} · {cluster.cloud_provider || "onprem"} · {cluster.region || "unknown"}
                  </div>
                </div>
                <Status value={cluster.state} />
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
                <MiniStat label="Deployments" value={cluster.deployments} />
                <MiniStat label="Max risk" value={cluster.max_risk} />
                <MiniStat label="Sensors" value={`${cluster.sensor_health?.ready ?? 0}/${cluster.sensor_health?.total ?? 0}`} />
              </div>
              {cluster.upgrade?.available && (
                <div className="mt-3 rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">
                  Upgrade {cluster.upgrade.target_version} · {cluster.upgrade.rollout_status}
                </div>
              )}
            </button>
          ))}
        </div>

        <main className="space-y-4" data-testid="cluster-health-panel">
          {!selected && <p className="text-sm text-muted-foreground">No clusters registered yet.</p>}
          {selected && (
            <>
              <section className="rounded-lg border border-border bg-card p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h2 className="text-lg font-semibold">{selected.name}</h2>
                    <p className="text-xs text-muted-foreground">
                      Last check-in {formatDate(health.data?.summary.last_check_in ?? selected.last_heartbeat_at)}
                    </p>
                  </div>
                  <Status value={health.data?.summary.status ?? selected.state} />
                </div>
                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <CommandBlock icon={UploadCloud} label="Install / upgrade" value={health.data?.registration.helm_command} />
                  <CommandBlock icon={KeyRound} label="Rotate token" value={health.data?.registration.rotate_command} />
                </div>
              </section>

              <section className="rounded-lg border border-border bg-card p-4" data-testid="cluster-platform-panel">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <PackageCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
                    <div>
                      <h2 className="text-sm font-semibold">Platform posture</h2>
                      <p className="text-xs text-muted-foreground">
                        {platform.data?.facts?.observed_at ? `Observed ${formatDate(platform.data.facts.observed_at)}` : "No platform facts reported"}
                      </p>
                    </div>
                  </div>
                  <Status value={platform.data?.status ?? "missing"} />
                </div>
                <div className="mt-4 grid grid-cols-2 gap-3 text-xs md:grid-cols-5">
                  <MiniStat label="Kubernetes" value={platform.data?.facts?.kubernetes_git_version || "unknown"} />
                  <MiniStat label="Distro" value={platform.data?.facts?.distro || selected.distro || "unknown"} />
                  <MiniStat label="Nodes" value={platform.data?.facts?.node_count ?? 0} />
                  <MiniStat label="Packages" value={platform.data?.evidence?.package_count ?? 0} />
                  <MiniStat label="Open vulns" value={platform.data?.findings_summary.open ?? 0} />
                </div>
              </section>

              <section className="space-y-4">
                <div data-testid="cluster-components-table">
                  <DataTable
                    rows={health.data?.components ?? []}
                    columns={componentColumns}
                    rowKey={(c) => c.name}
                    exportFileName={`constellation-${selected.id}-components`}
                    testId="cluster-components-data-table"
                  />
                </div>

                {(health.data?.gates ?? []).length > 0 && (
                  <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                    {(health.data?.gates ?? []).map((gate) => (
                      <article key={gate.name} className="rounded-lg border border-border bg-card p-3" data-testid="cluster-health-gate">
                        <div className="flex items-center justify-between gap-2">
                          <h3 className="text-sm font-medium">{gate.name}</h3>
                          <Status value={gate.status} />
                        </div>
                        <p className="mt-2 text-xs text-muted-foreground">{gate.evidence}</p>
                      </article>
                    ))}
                  </div>
                )}
              </section>
            </>
          )}
        </main>
      </section>
    </PageContainer>
  );
}

function MiniStat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
      <div className="font-semibold">{value}</div>
    </div>
  );
}

function CommandBlock({ icon: Icon, label, value }: { icon: typeof UploadCloud; label: string; value?: string }) {
  return (
    <div className="rounded-md border border-border p-3">
      <div className="mb-2 flex items-center gap-2 text-xs font-medium">
        <Icon className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
        {label}
      </div>
      <code className="block overflow-x-auto rounded bg-muted p-2 text-xs">{value ?? "pending health data"}</code>
    </div>
  );
}

function Status({ value }: { value: string }) {
  const cls = value === "healthy" || value === "connected" || value === "ready" || value === "pass"
    ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
    : value === "warn" || value === "degraded" || value === "staged"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
      : "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]";
  return <span className={`rounded-md px-2 py-1 text-xs ${cls}`}>{value}</span>;
}

function formatDate(value?: string) {
  if (!value) return "not yet";
  return new Date(value).toLocaleString();
}

function safeTestID(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "component";
}
