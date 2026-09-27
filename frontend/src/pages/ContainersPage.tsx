// ContainersPage — the per-running-container inventory (NeuVector's Assets → Containers).
// Constellation previously only aggregated to the deployment level; this lists every
// live container across all nodes with its pod, image, node, state, and workload
// security posture (privileged/root/risk). Closes the #1 structural NV-parity gap.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Boxes, ShieldAlert } from "lucide-react";

import { containers, type ContainerRow } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { PlatformVisibilityToggle } from "@/components/ui/platform-visibility-toggle";
import { cn } from "@/lib/cn";
import { downloadCsv } from "@/lib/csv";
import { isPlatformResource } from "@/lib/platform-components";
import { usePlatformComponentVisibility } from "@/hooks/usePlatformComponentVisibility";

export function ContainersPage() {
  const { clusterId } = useCluster();
  const [search, setSearch] = useState("");
  const [hidePlatformComponents, setHidePlatformComponents] = usePlatformComponentVisibility();
  const q = useQuery({
    queryKey: ["containers", clusterId],
    queryFn: () => containers.list(clusterId!),
    enabled: !!clusterId,
  });
  const items = useMemo(() => q.data?.items ?? [], [q.data?.items]);
  const platformCount = useMemo(() => items.filter((item) => isPlatformResource(item.platform_role, item.namespace)).length, [items]);
  const visibleItems = useMemo(
    () => hidePlatformComponents ? items.filter((item) => !isPlatformResource(item.platform_role, item.namespace)) : items,
    [hidePlatformComponents, items],
  );
  const summary = useMemo(
    () => visibleItems.reduce(
      (acc, item) => {
        acc.total += 1;
        if (item.state.replace("CONTAINER_", "").toLowerCase() === "running") acc.running += 1;
        if (item.privileged) acc.privileged += 1;
        if (item.run_as_root) acc.run_as_root += 1;
        return acc;
      },
      { total: 0, running: 0, privileged: 0, run_as_root: 0 },
    ),
    [visibleItems],
  );
  const rows = useMemo(() => {
    const n = search.trim().toLowerCase();
    if (!n) return visibleItems;
    return visibleItems.filter((c) => [c.name, c.namespace, c.pod_name, c.image, c.node, c.workload ?? ""].some((v) => v.toLowerCase().includes(n)));
  }, [visibleItems, search]);

  const columns: Column<ContainerRow>[] = [
    { id: "name", header: "Container", cell: (c) => (
        <div>
          <span className="text-xs font-medium">{c.name || "—"}</span>
          {c.privileged && <span className="ml-1.5 rounded px-1 py-px text-[9px] font-semibold uppercase" style={{ background: "color-mix(in oklab, var(--color-severity-critical) 16%, transparent)", color: "var(--color-severity-critical)" }} title="Owning workload includes a privileged container">workload: priv</span>}
          {c.run_as_root && <span className="ml-1 rounded px-1 py-px text-[9px] font-semibold uppercase" style={{ background: "color-mix(in oklab, var(--color-severity-high) 16%, transparent)", color: "var(--color-severity-high)" }} title="Owning workload includes a container configured to run as root">workload: root</span>}
        </div>
      ), sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "pod", header: "Pod", cell: (c) => (
        c.workload && clusterId
          ? <Link to={`/clusters/${clusterId}/deployments?q=${encodeURIComponent(c.workload)}`} className="text-mono text-[11px] text-[color:var(--color-primary)] hover:underline" title={`${c.namespace}/${c.pod_name}`}>{c.namespace}/{c.pod_name}</Link>
          : <span className="text-mono text-[11px] text-muted-foreground">{c.namespace}/{c.pod_name}</span>
      ), sort: (a, b) => (a.namespace + a.pod_name).localeCompare(b.namespace + b.pod_name) },
    { id: "image", header: "Image", cell: (c) => <span className="text-mono text-[11px] max-w-[280px] truncate block" title={c.image}>{displayImage(c.image)}</span>, sort: (a, b) => a.image.localeCompare(b.image) },
    { id: "node", header: "Node", cell: (c) => clusterId ? <Link to={`/clusters/${clusterId}/nodes/${encodeURIComponent(c.node)}`} className="text-mono text-[11px] text-[color:var(--color-primary)] hover:underline">{c.node}</Link> : <span className="text-mono text-[11px]">{c.node || "Not reported"}</span>, sort: (a, b) => a.node.localeCompare(b.node) },
    { id: "risk", header: "Vulns", numeric: true, width: "110px", cell: (c) => (
        (c.critical + c.high) === 0
          ? <span className="text-[11px] text-muted-foreground">—</span>
          : <span className="flex items-center justify-end gap-1">
              {c.critical > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-critical)" }}>{c.critical}C</span>}
              {c.high > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-high)" }}>{c.high}H</span>}
            </span>
      ), sort: (a, b) => (b.critical * 1000 + b.high) - (a.critical * 1000 + a.high) },
    { id: "state", header: "State", width: "104px", cell: (c) => {
        const st = c.state.replace("CONTAINER_", "").toLowerCase();
        return <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-medium", st === "running" ? "bg-[color-mix(in_oklab,var(--color-severity-low)_16%,transparent)] text-[color:var(--color-severity-low)]" : "bg-muted text-muted-foreground")}>{st || "—"}</span>;
      }, sort: (a, b) => a.state.localeCompare(b.state) },
  ];

  return (
    <div className="space-y-4" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Containers"
        description="Every running container across the cluster's nodes, with its pod, image, node, and workload security posture."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <PlatformVisibilityToggle
              hidden={hidePlatformComponents}
              onHiddenChange={setHidePlatformComponents}
              hiddenCount={platformCount}
            />
            <button
              type="button"
              onClick={() => downloadCsv("constellation-containers", ["Container", "Namespace", "Platform Role", "Pod", "Image", "Node", "State", "Privileged", "RunAsRoot", "Critical", "High"],
                rows.map((c) => [c.name, c.namespace, c.platform_role ?? "", c.pod_name, c.image, c.node, c.state, c.privileged ? "yes" : "", c.run_as_root ? "yes" : "", c.critical, c.high]))}
              className="rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent"
            >Export CSV</button>
          </div>
        }
      />
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Containers" value={summary.total} icon={<Boxes className="h-3.5 w-3.5" />} hint={`${summary.running} running`} />
        <StatCard label="Running" value={summary.running} tone="low" />
        <StatCard label="In privileged workloads" value={summary.privileged} tone={summary.privileged > 0 ? "critical" : "neutral"} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <StatCard label="In root workloads" value={summary.run_as_root} tone={summary.run_as_root > 0 ? "high" : "neutral"} />
      </section>
      <input
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search container, pod, image, node…"
        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
      />
      {q.isPending ? (
        <p className="text-sm text-muted-foreground">Loading containers…</p>
      ) : rows.length === 0 ? (
        <EmptyState
          title="No containers"
          hint={
            hidePlatformComponents && platformCount > 0 && visibleItems.length === 0
              ? `${platformCount} platform ${platformCount === 1 ? "container is" : "containers are"} hidden. Use Platform hidden to show them.`
              : search.trim()
                ? "No containers match the current search."
                : "The runtime-agent reports each node's running containers; none are recorded yet."
          }
        />
      ) : (
        <DataTable rows={rows} sourceLimit={3000} sourceCount={items.length} columns={columns} rowKey={(c) => `${c.node}-${c.id || c.pod_name + c.name}`} defaultSort={{ id: "risk", dir: "desc" }} />
      )}
    </div>
  );
}

function displayImage(value: string): string {
  if (!value) return "Not reported";
  if (value.startsWith("sha256:")) return `digest ${value.slice(7, 19)}`;
  return value;
}
