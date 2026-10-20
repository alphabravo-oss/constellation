import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation, useParams } from "@tanstack/react-router";
import { KeyRound, CloudUpload } from "lucide-react";
import { clusters } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { sortClustersByActivity } from "@/lib/clusters";
import { componentDiagnosticsHref, nvRoleAlias } from "@/lib/component-roles";
import { StatusPill } from "@/components/ui/status-pill";
type HealthComponent = Awaited<ReturnType<typeof clusters.health>>["components"][number];
export function ClusterHealthPage() {
  const { id: clusterID } = useParams({ strict: false });
  const location = useLocation();
  const [requestedTab, setTab] = useTabParam("tab", "components");
  const tab = ["components", "gates", "platform", "registration", "clusters"].includes(requestedTab) ? requestedTab : "components";
  const list = useQuery({ queryKey: ["clusters"], queryFn: () => clusters.list() });
  const clusterList = useMemo(() => list.isSuccess ? sortClustersByActivity(list.data.clusters) : [], [list.data, list.isSuccess]);
  const selected = clusterList.find(cluster => cluster.id === clusterID);
  const health = useQuery({ queryKey: ["cluster-health", selected?.id], enabled: !!selected,
    queryFn: async () => { const data = await clusters.health(selected!.id); if (data.cluster_id !== selected!.id) throw new Error("Health evidence does not match the selected cluster"); return data; } });
  const platform = useQuery({ queryKey: ["cluster-platform", selected?.id], enabled: !!selected, refetchInterval: 30_000,
    queryFn: async () => { const data = await clusters.platformFacts(selected!.id); if (data.cluster_id !== selected!.id || (data.facts && data.facts.cluster_id !== selected!.id)) throw new Error("Platform evidence does not match the selected cluster"); return data; } });
  const h = selected && health.isSuccess && health.data.cluster_id === selected.id ? health.data : undefined;
  const p = selected && platform.isSuccess && platform.data.cluster_id === selected.id && (!platform.data.facts || platform.data.facts.cluster_id === selected.id) ? platform.data : undefined;
  const retryHealth = <Button onClick={() => void health.refetch()}>Retry health</Button>;
  const healthUnavailable = health.isError || (health.isSuccess && !h);
  const componentColumns: Column<HealthComponent>[] = [
    {
      id: "name",
      header: "Component", kind: "name", wrap: true,
      exportValue: (c) => c.name,
      cell: (c) => {
        const role = nvRoleAlias({ name: c.name, kind: c.kind });
        return (
          <a
            href={componentDiagnosticsHref({ clusterId: selected?.id, component: c.name, role: role.id })}
            className="font-medium hover:underline"
            data-testid={`cluster-health-component-link-${safeTestID(c.name)}`}
            title={`Open ${role.label.toLowerCase()} diagnostics`}
          >
            {c.name}
          </a>
        );
      },
    },
    { id: "kind", header: "Kind", kind: "status", cell: (c) => <span className="text-xs text-muted-foreground">{c.kind}</span>, exportValue: (c) => c.kind },
    { id: "version", header: "Version", kind: "version", size: 160, minSize: 112, maxSize: 224, wrap: true, cell: (c) => <span className="font-mono text-xs">{c.version}</span>, exportValue: (c) => c.version },
    { id: "ready", header: "Ready", kind: "count", cell: (c) => <span className="text-xs">{c.ready}/{c.desired}</span>, exportValue: (c) => `${c.ready}/${c.desired}` },
    { id: "status", header: "Status", kind: "status", cell: (c) => <Status value={c.status} />, exportValue: (c) => c.status },
  ];

  return <PageContainer className="space-y-4">
    <PageHeader title="Sensor health" description="Reported sensor readiness, platform facts and registration for the selected cluster."
      actions={<Button variant="outline" disabled={list.isFetching || health.isFetching || platform.isFetching} onClick={() => { void list.refetch(); if (selected) { void health.refetch(); void platform.refetch(); } }}>Refresh</Button>} />
    <div data-testid="clusters-stats"><VerdictBanner status={list.isError || healthUnavailable ? "degraded" : h?.summary.status === "healthy" ? "ok" : h ? "degraded" : "info"}
      title={list.isError ? "Cluster inventory unavailable" : list.isPending ? "Loading cluster scope" : !selected ? "Cluster not found" : healthUnavailable ? "Cluster health unavailable" : !h ? "Loading cluster health" : `${selected.name}: ${h.summary.status}`}
      detail="Health reflects returned sensor and gate reports. Platform facts and registration details are separate workspaces." numbers={[{ label: "Reported components", value: h ? h.components.length : "—" }, { label: "Connected sensors", value: h ? h.summary.connected_sensors : "—", title: h ? `${h.summary.expected_sensors} expected` : undefined }, { label: "Reported gates", value: h ? h.gates.length : "—" }]} /></div>
    
    <div className="space-y-4" data-testid="cluster-health-panel">
      {list.isPending ? <LoadingState label="Loading clusters…" /> : list.isError ? <ErrorState title="Cluster inventory unavailable" error={list.error} action={<Button onClick={() => void list.refetch()}>Retry clusters</Button>} /> : !selected ? <ErrorState title="Cluster not found" /> : <>
      <h2 className="text-lg font-semibold">{selected.name}</h2>
      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "components", label: "Components", content: healthUnavailable ? <ErrorState title="Cluster health unavailable" error={health.error} action={retryHealth} /> : !h ? <LoadingState label="Loading health reports…" /> : <div data-testid="cluster-components-table"><DataTable rows={h.components} columns={componentColumns} rowKey={c => c.name} preferencesKey="cluster-health-components" exportFileName={`constellation-${selected.id}-components`} testId="cluster-components-data-table" /></div> },
        { value: "gates", label: "Health gates", content: healthUnavailable ? <ErrorState title="Cluster health unavailable" error={health.error} action={retryHealth} /> : !h ? <LoadingState /> : <DataTable rows={h.gates} rowKey={g => g.name} rowTestId={() => "cluster-health-gate"} preferencesKey="cluster-health-gates" exportFileName={`constellation-${selected.id}-gates`} columns={[
          { id: "name", header: "Gate", kind: "name", cell: g => g.name, exportValue: g => g.name },
          { id: "status", header: "Status", kind: "status", cell: g => <Status value={g.status} />, exportValue: g => g.status },
          { id: "evidence", header: "Evidence", kind: "text", wrap: true, grow: true, cell: g => g.evidence, exportValue: g => g.evidence },
        ]} /> },
        { value: "platform", label: "Platform facts", content: platform.isError || (platform.isSuccess && !p) ? <ErrorState title="Platform facts unavailable" error={platform.error} action={<Button onClick={() => void platform.refetch()}>Retry platform</Button>} /> : !p ? <LoadingState label="Loading platform facts…" /> : <section className="rounded-md border border-border bg-card p-4" data-testid="cluster-platform-panel">
          <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="font-semibold">Platform posture</h3><Status value={p.status} /></div>
          <p className="mt-2 text-xs text-muted-foreground">{p.facts?.observed_at ? `Observed ${formatDate(p.facts.observed_at)}` : "No platform facts reported"}</p>
          <dl className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <MiniStat label="Kubernetes" value={p.facts?.kubernetes_git_version || "Not reported"} />
            <MiniStat label="Distro" value={p.facts?.distro || "Not reported"} />
            <MiniStat label="Nodes" value={p.facts?.node_count ?? "Not reported"} />
            <MiniStat label="Packages" value={p.evidence?.package_count ?? "Not reported"} />
            <MiniStat label="Open findings" value={p.findings_summary?.open ?? "Not reported"} />
          </dl>
          <a href={`/clusters/${selected.id}/dashboard?tab=operations`} className="mt-4 inline-block text-sm text-primary hover:underline">Inspect platform package evidence</a>
        </section> },
        { value: "registration", label: "Registration", content: healthUnavailable ? <ErrorState title="Registration evidence unavailable" error={health.error} action={retryHealth} /> : !h ? <LoadingState /> : <section className="space-y-4"><p className="text-sm text-muted-foreground">Last check-in {formatDate(h.summary.last_check_in)} · {h.summary.registration_state}</p><CommandBlock icon={CloudUpload} label="Install / upgrade" value={h.registration.helm_command} /><CommandBlock icon={KeyRound} label="Rotate token" value={h.registration.rotate_command} /></section> },
        { value: "clusters", label: "Other clusters", content: <div className="grid gap-4 md:grid-cols-2" data-testid="clusters-list">{clusterList.map(cluster => <a key={cluster.id} href={`/clusters/${cluster.id}/health${location.searchStr}${location.hash ? `#${location.hash}` : ""}`} className="rounded-md border border-border bg-card p-4 hover:bg-accent" data-testid="cluster-card" data-cluster-id={cluster.id}><span className="font-medium" data-testid="cluster-health-card-name">{cluster.name}</span><p className="mt-2 text-xs text-muted-foreground">{cluster.distro} · {cluster.cloud_provider || "onprem"}</p></a>)}</div> },
      ]} />
      </>}
    </div>
  </PageContainer>;
}

function MiniStat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <dt className="text-micro  text-muted-foreground">{label}</dt>
      <dd className="font-semibold">{value}</dd>
    </div>
  );
}

function CommandBlock({ icon: Icon, label, value }: { icon: typeof CloudUpload; label: string; value?: string }) {
  return (
    <div className="rounded-md border border-border p-3">
      <div className="mb-2 flex items-center gap-2 text-xs font-medium">
        <Icon className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
        {label}
      </div>
      <code className="block overflow-x-auto rounded bg-muted p-2 text-xs">{value ?? "Not reported"}</code>
    </div>
  );
}

function Status({ value }: { value: string }) {
  const tone: "success" | "warning" | "error" | "info" | "pending" | "neutral" = value === "healthy" || value === "connected" || value === "ready" || value === "pass"
    ? "success"
    : value === "warn" || value === "degraded" || value === "staged"
      ? "warning"
      : "error";
  return <StatusPill label={value} tone={tone} />;
}

function formatDate(value?: string) {
  if (!value) return "not yet";
  return new Date(value).toLocaleString();
}

function safeTestID(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "component";
}
