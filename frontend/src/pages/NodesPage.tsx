import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import {
  Activity,
  CheckCircle2,
  Search,
  Server,
  ShieldAlert,
} from "lucide-react";
import { api, type NodeListResponse, type NodeSummary } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { cn } from "@/lib/cn";

const agentStatuses = ["all", "healthy", "stale", "missing"];
const riskFilters = ["all", "critical", "high", "open", "clean", "host-cves"];
const pageSize = 100;
type NodePage = NodeListResponse & { total: number; limit: number; offset: number };

export function NodesPage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [agentStatus, setAgentStatus] = useState("all");
  const riskFilter = riskFilters.includes(searchParams.get("risk") ?? "") ? searchParams.get("risk")! : "all";
  const hostCVEs = riskFilter === "host-cves";
  const [selectedName, setSelectedName] = useState<string | null>(null);

  const nodesQ = useInfiniteQuery({
    queryKey: ["nodes", clusterId, hostCVEs],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api.get<NodePage>(`/clusters/${encodeURIComponent(clusterId!)}/nodes`, {
      params: { limit: pageSize, offset: pageParam, ...(hostCVEs ? { host_cves: "open" } : {}) },
    }).then((response) => response.data),
    getNextPageParam: (lastPage) => lastPage.offset + lastPage.items.length < lastPage.total
      ? lastPage.offset + lastPage.items.length : undefined,
    enabled: !!clusterId,
  });

  const inventory = useMemo(() => nodesQ.data?.pages.flatMap((page) => page.items) ?? [], [nodesQ.data]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return inventory.filter((item) => {
      if (agentStatus !== "all" && item.runtime_agent_status !== agentStatus) return false;
      if (!matchesRiskFilter(item, riskFilter)) return false;
      if (!needle) return true;
      return [
        item.node,
        item.os_id ?? "",
        item.os_version_id ?? "",
        item.kernel_release ?? "",
        item.arch ?? "",
        item.cni_name ?? "",
        item.cri_runtime ?? "",
        item.package_source ?? "",
        item.inventory_hash ?? "",
        item.coverage_gaps?.join(" ") ?? "",
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [agentStatus, inventory, query, riskFilter]);

  const selected = filtered.find((item) => item.node === selectedName) ?? filtered[0] ?? null;
  const summary = summarizeNodes(inventory);
  const total = nodesQ.data?.pages[0]?.total ?? 0;

  if (clusterLoading) {
    return <p className="text-sm text-muted-foreground" data-testid="nodes-loading">Loading cluster...</p>;
  }

  const columns: Column<NodeSummary>[] = [
    {
      id: "node",
      header: "Node",
      cell: (item) => (
        <div>
          <Link to={`/clusters/${clusterId}/nodes/${encodeURIComponent(item.node)}`} className="block break-all font-mono text-xs font-medium hover:underline">
            {item.node}
          </Link>
          {item.coverage_gaps?.length ? <div className="mt-1 text-[11px] text-status-warn">{item.coverage_gaps.length} coverage gap{item.coverage_gaps.length === 1 ? "" : "s"}</div> : null}
        </div>
      ),
      sort: (a, b) => a.node.localeCompare(b.node),
      sticky: true,
      exportValue: (item) => item.node,
    },
    {
      id: "agent",
      header: "Agent",
      cell: (item) => <StatusPill status={item.runtime_agent_status} />,
      sort: (a, b) => a.runtime_agent_status.localeCompare(b.runtime_agent_status),
      exportValue: (item) => item.runtime_agent_status,
    },
    {
      id: "os",
      header: "Operating system",
      cell: (item) => <span className="text-xs">{displayOS(item)}</span>,
      sort: (a, b) => displayOS(a).localeCompare(displayOS(b)),
      exportValue: displayOS,
    },
    {
      id: "critical",
      header: "Critical",
      cell: (item) => item.last_scanned_at || item.critical_vulns > 0 ? <RiskCount value={item.critical_vulns} tone="danger" /> : <NotCollected label="Not scanned" />,
      sort: (a, b) => a.critical_vulns - b.critical_vulns,
      numeric: true,
      exportValue: (item) => item.critical_vulns,
    },
    {
      id: "high",
      header: "High",
      cell: (item) => item.last_scanned_at || item.high_vulns > 0 ? <RiskCount value={item.high_vulns} tone="warn" /> : <NotCollected label="Not scanned" />,
      sort: (a, b) => a.high_vulns - b.high_vulns,
      numeric: true,
      exportValue: (item) => item.high_vulns,
    },
    {
      id: "open",
      header: "Open",
      cell: (item) => item.last_scanned_at || item.open_vulns > 0 ? item.open_vulns.toLocaleString() : <NotCollected label="Not scanned" />,
      sort: (a, b) => a.open_vulns - b.open_vulns,
      numeric: true,
      exportValue: (item) => item.open_vulns,
    },
    {
      id: "packages",
      header: "Packages",
      cell: (item) => item.packages_observed_at ? item.package_count.toLocaleString() : <NotCollected />,
      sort: (a, b) => a.package_count - b.package_count,
      numeric: true,
      exportValue: (item) => item.package_count,
    },
    {
      id: "containers",
      header: "Containers",
      cell: (item) => item.containers_observed_at ? item.container_count.toLocaleString() : <NotCollected />,
      sort: (a, b) => a.container_count - b.container_count,
      numeric: true,
      exportValue: (item) => item.container_count,
    },
    {
      id: "cis",
      header: "CIS failed",
      cell: (item) => item.cis_observed_at ? <RiskCount value={item.cis_failed} tone="warn" /> : <NotCollected />,
      sort: (a, b) => a.cis_failed - b.cis_failed,
      numeric: true,
      exportValue: (item) => item.cis_failed,
    },
    {
      id: "last_scan",
      header: "Last scan",
      cell: (item) => formatDate(item.last_scanned_at),
      sort: (a, b) => timestamp(a.last_scanned_at) - timestamp(b.last_scanned_at),
      exportValue: (item) => item.last_scanned_at ?? "",
    },
  ];

  return (
    <div className="space-y-4" data-testid="nodes-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Nodes"
        description="Host posture, package evidence, runtime-agent health, and node CVEs. Search and sorting use loaded nodes."
        actions={
          <div className="flex items-center gap-2">
            <Link
              to={selected ? `/clusters/${clusterId}/nodes/${encodeURIComponent(selected.node)}` : `/clusters/${clusterId}/nodes`}
              className={cn(
                "inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent",
                !selected && "pointer-events-none opacity-50",
              )}
            >
              <Server className="h-4 w-4" aria-hidden />
              Open Node
            </Link>
          </div>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4" data-testid="nodes-summary">
        <StatCard label="Nodes" value={total.toLocaleString()} icon={<Server className="h-3.5 w-3.5" />} hint={`${inventory.length} loaded`} />
        <StatCard label="Loaded agents" value={summary.runtime_agent_healthy.toLocaleString()} icon={<Activity className="h-3.5 w-3.5" />} hint={`${summary.runtime_agent_stale} stale · ${summary.runtime_agent_missing} missing`} />
        <StatCard label="Loaded critical / high" value={(summary.critical_vulns + summary.high_vulns).toLocaleString()} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary.critical_vulns + summary.high_vulns > 0 ? "high" : "neutral"} hint={`${summary.critical_vulns} critical · ${summary.high_vulns} high`} />
        <StatCard label="Loaded CIS failures" value={summary.cis_failed.toLocaleString()} icon={<CheckCircle2 className="h-3.5 w-3.5" />} tone={summary.cis_failed > 0 ? "medium" : "neutral"} hint={`${summary.scan_gaps} loaded nodes with scan gaps`} />
      </section>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search loaded nodes, OS, kernel, runtime, coverage gap"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="node-search"
            />
          </label>
          <select
            value={agentStatus}
            onChange={(event) => setAgentStatus(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="node-agent-filter"
          >
            {agentStatuses.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All agents" : item}</option>
            ))}
          </select>
          <select
            value={riskFilter}
            onChange={(event) => setSearchParams((params) => {
              const next = new URLSearchParams(params);
              if (event.target.value === "all") next.delete("risk");
              else next.set("risk", event.target.value);
              return next;
            })}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="node-risk-filter"
          >
            {riskFilters.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All risk" : item === "host-cves" ? "Open host CVEs" : item}</option>
            ))}
          </select>
        </div>
      </section>

      <section className="flex flex-col gap-4">
        <div data-testid="nodes-table">
          <DataTable
            rows={filtered}
            columns={columns}
            rowKey={(item) => item.node}
            onRowClick={(item) => setSelectedName(item.node)}
            selected={selected ? new Set([selected.node]) : new Set()}
            defaultSort={{ id: "critical", dir: "desc" }}
            preferencesKey="cluster-nodes"
            exportFileName="constellation-nodes"
            emptyState={
              nodesQ.isPending ? (
                <div className="px-3 py-8 text-center text-xs text-muted-foreground">Loading nodes...</div>
              ) : (
                <div className="px-3 py-8 text-center text-xs text-muted-foreground">No nodes match the current filters.</div>
              )
            }
          />
          {nodesQ.isError && <p role="alert" className="p-3 text-sm text-status-error">Could not load nodes.</p>}
          <div className="flex items-center justify-between gap-3 p-3 text-xs text-muted-foreground">
            <span data-testid="nodes-page-count">Showing {inventory.length.toLocaleString()} of {total.toLocaleString()} nodes</span>
            {nodesQ.hasNextPage && <button type="button" onClick={() => void nodesQ.fetchNextPage()} disabled={nodesQ.isFetchingNextPage} className="rounded-md border border-border px-3 py-1.5 text-foreground hover:bg-accent" data-testid="nodes-load-more">{nodesQ.isFetchingNextPage ? "Loading..." : "Load more"}</button>}
          </div>
        </div>

        <NodePreview node={selected} clusterId={clusterId} />
      </section>
    </div>
  );
}

function RiskCount({ value, tone }: { value: number; tone: "warn" | "danger" }) {
  return <span className={cn("tabular-nums", value > 0 && (tone === "danger" ? "font-semibold text-status-error" : "font-medium text-status-warn"))}>{value.toLocaleString()}</span>;
}

function NotCollected({ label = "Not collected" }: { label?: string }) {
  return <span className="text-xs italic text-muted-foreground">{label}</span>;
}

function timestamp(value?: string | null): number {
  return value ? Date.parse(value) || 0 : 0;
}

function NodePreview({ node, clusterId }: { node: NodeSummary | null; clusterId?: string }) {
  if (!node) {
    return (
      <aside className="rounded-lg border border-border bg-card p-4" data-testid="node-preview">
        <h2 className="text-sm font-semibold">Node inspection</h2>
        <p className="mt-2 text-xs text-muted-foreground">Select a node to inspect host evidence and scan freshness.</p>
      </aside>
    );
  }
  return (
    <aside className="space-y-4" data-testid="node-preview">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <NodeBadge item={node} />
            <h2 className="mt-2 break-all font-mono text-sm font-semibold">{node.node}</h2>
            <p className="mt-1 text-xs text-muted-foreground">{displayOS(node)} · kernel {node.kernel_release || "unknown"}</p>
          </div>
          <div className="flex items-center gap-2">
            <Link to={`/clusters/${clusterId}/risk/node/${encodeURIComponent(node.node)}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent" data-testid="node-risk-workspace-link">
              Risk workspace
            </Link>
            <Link to={`/clusters/${clusterId}/nodes/${encodeURIComponent(node.node)}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
              Full Details
            </Link>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-2">
          <MiniMetric label="Critical" value={node.critical_vulns} tone={node.critical_vulns > 0 ? "danger" : "normal"} />
          <MiniMetric label="High" value={node.high_vulns} tone={node.high_vulns > 0 ? "warn" : "normal"} />
          <MiniMetric label="Open" value={node.open_vulns} tone={node.open_vulns > 0 ? "warn" : "normal"} />
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Runtime and scan state</h3>
        <dl className="mt-3 grid gap-2 text-sm">
          <Field label="Runtime agent" value={node.runtime_agent_status} />
          <Field label="Agent version" value={node.runtime_agent_version || "-"} />
          <Field label="Agent last seen" value={formatDate(node.runtime_agent_last_seen_at)} />
          <Field label="CRI runtime" value={node.cri_runtime || "-"} />
          <Field label="CNI" value={node.cni_name || "-"} />
          <Field label="Scan status" value={node.scan_status || "-"} />
          <Field label="Last scanned" value={formatDate(node.last_scanned_at)} />
          <Field label="Inventory hash" value={node.inventory_hash || "-"} wide />
        </dl>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Coverage</h3>
        {node.coverage_gaps?.length ? (
          <div className="mt-3 flex flex-wrap gap-2">
            {node.coverage_gaps.map((gap) => <Pill key={gap} tone="warn">{gap}</Pill>)}
          </div>
        ) : (
          <p className="mt-2 text-xs text-muted-foreground">No coverage gaps reported.</p>
        )}
        <dl className="mt-4 grid gap-2 text-sm">
          <Field label="Packages observed" value={formatDate(node.packages_observed_at)} />
          <Field label="Containers observed" value={formatDate(node.containers_observed_at)} />
          <Field label="Processes observed" value={formatDate(node.processes_observed_at)} />
          <Field label="CIS observed" value={formatDate(node.cis_observed_at)} />
        </dl>
      </div>
    </aside>
  );
}

function MiniMetric({ label, value, tone }: { label: string; value: number; tone: "normal" | "warn" | "danger" }) {
  return (
    <div className={cn("rounded-md border border-border p-2 text-center", tone === "danger" && "border-status-error/30 bg-status-error/10", tone === "warn" && "border-status-warn/30 bg-status-warn/10")}>
      <div className="text-lg font-semibold">{value.toLocaleString()}</div>
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
    </div>
  );
}

function Field({ label, value, wide }: { label: string; value: ReactNode; wide?: boolean }) {
  return (
    <div className={cn("grid gap-1", wide && "sm:col-span-2")}>
      <dt className="text-[10px] uppercase text-muted-foreground">{label}</dt>
      <dd className="break-all font-mono text-xs">{value}</dd>
    </div>
  );
}

function NodeBadge({ item }: { item: NodeSummary }) {
  const healthy = item.runtime_agent_status === "healthy" && item.scan_status === "completed" && !(item.coverage_gaps?.length);
  return (
    <Pill tone={healthy ? "ok" : item.runtime_agent_status === "missing" ? "danger" : "warn"}>
      {healthy ? "covered" : item.runtime_agent_status || "unknown"}
    </Pill>
  );
}

function StatusPill({ status }: { status: string }) {
  const normalized = status || "missing";
  return (
    <Pill tone={normalized === "healthy" || normalized === "completed" ? "ok" : normalized === "missing" || normalized === "failed" ? "danger" : "warn"}>
      {normalized}
    </Pill>
  );
}

function Pill({ tone, children }: { tone: "neutral" | "ok" | "warn" | "danger"; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium",
        tone === "neutral" && "bg-muted text-muted-foreground",
        tone === "ok" && "bg-status-ok/10 text-status-ok",
        tone === "warn" && "bg-status-warn/10 text-status-warn",
        tone === "danger" && "bg-status-error/10 text-status-error",
      )}
    >
      {children}
    </span>
  );
}

function matchesRiskFilter(item: NodeSummary, filter: string): boolean {
  switch (filter) {
    case "critical":
      return item.critical_vulns > 0;
    case "high":
      return item.critical_vulns > 0 || item.high_vulns > 0;
    case "open":
    case "host-cves":
      return item.open_vulns > 0;
    case "clean":
      return item.open_vulns === 0 && item.cis_failed === 0 && !(item.coverage_gaps?.length);
    default:
      return true;
  }
}

function summarizeNodes(items: NodeSummary[]) {
  return items.reduce(
    (acc, item) => {
      acc.nodes += 1;
      if (item.runtime_agent_status === "healthy") acc.runtime_agent_healthy += 1;
      else if (item.runtime_agent_status === "stale") acc.runtime_agent_stale += 1;
      else acc.runtime_agent_missing += 1;
      if (item.scan_status === "completed") acc.scan_completed += 1;
      else acc.scan_gaps += 1;
      acc.critical_vulns += item.critical_vulns;
      acc.high_vulns += item.high_vulns;
      acc.cis_failed += item.cis_failed;
      return acc;
    },
    {
      nodes: 0,
      runtime_agent_healthy: 0,
      runtime_agent_stale: 0,
      runtime_agent_missing: 0,
      scan_completed: 0,
      scan_gaps: 0,
      critical_vulns: 0,
      high_vulns: 0,
      cis_failed: 0,
    },
  );
}

function displayOS(item: NodeSummary): string {
  if (item.os_id && item.os_version_id) return `${item.os_id} ${item.os_version_id}`;
  return item.os_id || item.os_version_id || "OS unknown";
}

function formatDate(value?: string): string {
  if (!value) return "Not collected";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
