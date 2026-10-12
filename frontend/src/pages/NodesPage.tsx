import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useInventoryRoute, ScanInventoryExport } from "./inventory-workspace";
import { useEntityClusterScope } from "./entity-detail-scope";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { Pager } from "@/components/ui/pager";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { LoadingState, ErrorState } from "@/components/ui/states";
import {
  Activity,
  CheckCircle2,
  Search,
  Server,
  ShieldAlert,
} from "lucide-react";
import { nodes, type NodeListResponse, type NodeSummary, type NodeInventoryParams } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { cn } from "@/lib/cn";

const agentStatuses = ["all", "healthy", "stale", "missing"];
const riskFilters = ["all", "critical", "high", "open", "clean", "host-cves"];
export function NodesPage() {
  const scope = useEntityClusterScope(); const { clusterId } = scope;
  const route = useInventoryRoute(); const params = route.params;
  const identity = useTablePreferencesIdentity(); const owner = `${identity?.org_id}:${identity?.user_id}`;
  const query = route.query; const agentStatus = params.get("agent") || "all";
  const riskFilter = params.get("risk") || "all"; const hostCVEs = riskFilter === "host-cves" || params.get("host_cves") === "open";
  const sort = params.get("sort") || "critical"; const order = params.get("order") || "desc";
  const selectedName = params.get("selected");
  const rawPage = params.get("page"); const validPage = rawPage === null || /^\d+$/.test(rawPage) && Number.isSafeInteger(Number(rawPage)) && Number(rawPage) >= 1 && Number(rawPage) <= 10000;
  const validFilters = validPage && agentStatuses.includes(agentStatus) && riskFilters.includes(riskFilter) && (!params.get("host_cves") || params.get("host_cves") === "open") && ["node", "agent", "os", "critical", "high", "open", "packages", "containers", "cis", "last_scan", "seen"].includes(sort) && ["asc", "desc"].includes(order);
  const update = (changes: Record<string, string | null>, reset = true, replace = false) => route.update({ ...(reset ? { page: null } : {}), ...changes }, false, replace);
  const request: NodeInventoryParams = { q: route.debouncedQuery || undefined, agent: agentStatus === "all" ? undefined : agentStatus, risk: riskFilter === "all" ? undefined : riskFilter, host_cves: hostCVEs ? "open" : undefined, sort, order: order as "asc" | "desc", limit: 100, offset: route.offset };
  const key = ["nodes", clusterId, owner, request]; const context = JSON.stringify(key);
  const nodesQ = useQuery({ queryKey: key, queryFn: () => nodes.list(clusterId!, request), enabled: scope.ready && validFilters && !route.debouncing });
  const validResponse = !!nodesQ.data && nodeInventoryMatches(nodesQ.data, clusterId!, request);
  const available = scope.ready && validFilters && !route.debouncing && nodesQ.isSuccess && validResponse;
  const filtered = available ? nodesQ.data!.items : []; const summary = available ? nodesQ.data!.summary : undefined; const total = available ? nodesQ.data!.total : undefined;
  // Inspection is an exact identity from this successful page. An off-page or
  // filtered selection remains in the URL and never selects another node.
  const selected = filtered.find(item => item.node === selectedName) ?? null;
  const selectedHref = selected && clusterId ? `/clusters/${encodeURIComponent(clusterId)}/nodes/${encodeURIComponent(selected.node)}` : undefined;
  if (!scope.ready) return <div className="space-y-5" data-testid="nodes-page"><PageHeader title="Nodes" description="Review host posture and runtime-agent evidence for the selected cluster." />{scope.loading ? <LoadingState label="Loading cluster…" /> : <ErrorState title="The selected cluster could not be resolved." action={<Button onClick={scope.retry}>Retry cluster</Button>} />}</div>;

  const columns: Column<NodeSummary>[] = [
    {
      id: "node",
      header: "Node",
      kind: "name",
      code: true,
      hideable: false,
      cell: (item) => (
        <div>
          <a href={`/clusters/${clusterId}/nodes/${encodeURIComponent(item.node)}`} className="block font-mono text-sm font-medium hover:underline">
            {item.node}
          </a>
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
      kind: "status",
      cell: (item) => <StatusPill status={item.runtime_agent_status} />,
      sort: (a, b) => a.runtime_agent_status.localeCompare(b.runtime_agent_status),
      exportValue: (item) => item.runtime_agent_status,
    },
    {
      id: "os",
      header: "Operating system",
      kind: "text",
      size: 184,
      maxSize: 240,
      cell: (item) => <span className="text-xs">{displayOS(item)}</span>,
      sort: (a, b) => displayOS(a).localeCompare(displayOS(b)),
      exportValue: displayOS,
    },
    {
      id: "critical",
      header: "Critical",
      kind: "text",
      align: "right",
      size: 112,
      minSize: 112,
      maxSize: 136,
      cell: (item) => item.last_scanned_at || item.critical_vulns > 0 ? <RiskCount value={item.critical_vulns} tone="danger" /> : <NotCollected label="Not scanned" />,
      sort: (a, b) => a.critical_vulns - b.critical_vulns,
      numeric: true,
      exportValue: (item) => item.critical_vulns,
    },
    {
      id: "high",
      header: "High",
      kind: "text",
      align: "right",
      size: 112,
      minSize: 112,
      maxSize: 136,
      cell: (item) => item.last_scanned_at || item.high_vulns > 0 ? <RiskCount value={item.high_vulns} tone="warn" /> : <NotCollected label="Not scanned" />,
      sort: (a, b) => a.high_vulns - b.high_vulns,
      numeric: true,
      exportValue: (item) => item.high_vulns,
    },
    {
      id: "open",
      header: "Open",
      kind: "text",
      align: "right",
      size: 112,
      minSize: 112,
      maxSize: 136,
      cell: (item) => item.last_scanned_at || item.open_vulns > 0 ? item.open_vulns.toLocaleString() : <NotCollected label="Not scanned" />,
      sort: (a, b) => a.open_vulns - b.open_vulns,
      numeric: true,
      exportValue: (item) => item.open_vulns,
    },
    {
      id: "packages",
      header: "Packages",
      kind: "text",
      align: "right",
      size: 124,
      minSize: 112,
      maxSize: 144,
      cell: (item) => item.packages_observed_at ? item.package_count.toLocaleString() : <NotCollected />,
      sort: (a, b) => a.package_count - b.package_count,
      numeric: true,
      exportValue: (item) => item.package_count,
    },
    {
      id: "containers",
      header: "Containers",
      kind: "text",
      align: "right",
      size: 124,
      minSize: 112,
      maxSize: 144,
      cell: (item) => item.containers_observed_at ? item.container_count.toLocaleString() : <NotCollected />,
      sort: (a, b) => a.container_count - b.container_count,
      numeric: true,
      exportValue: (item) => item.container_count,
    },
    {
      id: "cis",
      header: "CIS failed",
      kind: "text",
      align: "right",
      size: 124,
      minSize: 112,
      maxSize: 144,
      cell: (item) => item.cis_observed_at ? <RiskCount value={item.cis_failed} tone="warn" /> : <NotCollected />,
      sort: (a, b) => a.cis_failed - b.cis_failed,
      numeric: true,
      exportValue: (item) => item.cis_failed,
    },
    {
      id: "last_scan",
      header: "Last scan",
      kind: "date",
      size: 224,
      minSize: 208,
      maxSize: 240,
      cell: (item) => formatDate(item.last_scanned_at),
      sort: (a, b) => timestamp(a.last_scanned_at) - timestamp(b.last_scanned_at),
      exportValue: (item) => item.last_scanned_at ?? "",
    },
    { id: "seen", header: "Last observed", kind: "date", size: 224, minSize: 208, maxSize: 240, sort: (a, b) => timestamp(a.last_seen_at) - timestamp(b.last_seen_at), cell: item => formatDate(item.last_seen_at), exportValue: item => item.last_seen_at },
  ];

  return <div className="space-y-5" data-testid="nodes-page" data-cluster-id={clusterId}>
    <PageHeader title="Nodes" description="Review host posture, package evidence, runtime-agent freshness and node vulnerabilities across the selected cluster." actions={<Button disabled={nodesQ.isFetching || !validFilters || route.debouncing} onClick={() => void nodesQ.refetch()}>Refresh nodes</Button>} />
    <VerdictBanner status={!available ? nodesQ.isError || nodesQ.isSuccess && !validResponse ? "degraded" : "info" : summary!.critical_vulns || summary!.high_vulns || summary!.cis_failed || summary!.scan_gaps ? "degraded" : "ok"}
      title={!validFilters ? "The requested node filter or sort is invalid" : !available ? nodesQ.isError || nodesQ.isSuccess && !validResponse ? "Node evidence is unavailable" : "Loading node evidence" : !total ? "No nodes match these filters" : summary!.critical_vulns || summary!.high_vulns ? "Host vulnerability evidence needs review" : summary!.scan_gaps ? "Some matching nodes lack completed scan evidence" : "Matching nodes have no reported critical or high host vulnerabilities"}
      detail="Counts cover all server matches across pages. Agent freshness is inferred from its last heartbeat; a zero vulnerability count without completed scan evidence does not establish a clean host. Existing attributed host findings remain included unless the exact source-cluster host CVE cohort is selected." />
    {available && <StatGrid data-testid="nodes-summary">
      <StatCard label="Matching nodes" value={total!} icon={<Server className="h-3.5 w-3.5" />} />
      <StatCard label="Healthy agents" value={summary!.runtime_agent_healthy} icon={<Activity className="h-3.5 w-3.5" />} hint={`${summary!.runtime_agent_stale} stale · ${summary!.runtime_agent_missing} missing`} />
      <StatCard label="Critical / high" value={summary!.critical_vulns + summary!.high_vulns} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary!.critical_vulns + summary!.high_vulns > 0 ? "high" : "neutral"} />
      <StatCard label="CIS failures" value={summary!.cis_failed} icon={<CheckCircle2 className="h-3.5 w-3.5" />} />
      <StatCard label="Scan gaps" value={summary!.scan_gaps} />
    </StatGrid>}
    <section className="rounded-lg border border-border bg-card p-3"><div className="flex flex-wrap gap-3">
      <label className="relative min-w-64 flex-1"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden /><input value={query} onChange={event => update({ q: event.target.value || null }, true, true)} placeholder="Search node, OS, kernel, runtime or coverage gap" aria-label="Search nodes" className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm" data-testid="node-search" /></label>
      <select value={agentStatus} onChange={event => update({ agent: event.target.value === "all" ? null : event.target.value })} aria-label="Runtime agent filter" className="rounded-md border border-border bg-background p-2 text-sm" data-testid="node-agent-filter">{agentStatuses.map(item => <option key={item} value={item}>{item === "all" ? "All agents" : item}</option>)}</select>
      <select value={riskFilter} onChange={event => update({ risk: event.target.value === "all" ? null : event.target.value, host_cves: null })} aria-label="Host risk filter" className="rounded-md border border-border bg-background p-2 text-sm" data-testid="node-risk-filter">{riskFilters.map(item => <option key={item} value={item}>{item === "all" ? "All risk" : item === "host-cves" ? "Open host CVEs in this source cluster" : item}</option>)}</select>
    </div>{params.get("host_cves") === "open" && riskFilter !== "host-cves" && <p className="mt-2 text-xs text-muted-foreground">Source-cluster open host CVE cohort is active. <Button size="sm" onClick={() => update({ host_cves: null })}>Clear host CVE cohort</Button></p>}</section>
    {!validFilters ? <ErrorState title="Choose supported node filters and sorting." action={<Button onClick={() => update({ agent: null, risk: null, host_cves: null, sort: null, order: null })}>Reset filters and sort</Button>} /> : nodesQ.isError || nodesQ.isSuccess && !validResponse ? <ErrorState title="Node inventory could not be loaded or refreshed. Evidence and export are unavailable." action={<Button onClick={() => void nodesQ.refetch()}>Retry nodes</Button>} /> : !available ? <LoadingState label="Loading node inventory…" /> : <section className="space-y-4">
      {nodesQ.isFetching && <p role="status" className="text-sm text-muted-foreground">Refreshing node evidence…</p>}
      <p className="text-xs text-muted-foreground">{total!.toLocaleString()} nodes match the server filters; {filtered.length} on this page. Matching CSV covers up to 100,000 nodes across pages, independently of visible columns.</p>
      <ScanInventoryExport context={context} disabled={nodesQ.isFetching} download={() => nodes.exportCSV(clusterId!, request)} />
      <div data-testid="nodes-table"><DataTable rows={filtered} columns={columns} rowKey={item => item.node} onRowClick={item => update({ selected: item.node }, false)} selected={new Set(selected ? [selected.node] : [])} preferencesKey="cluster-nodes" manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => update({ sort: next?.id ?? null, order: next?.dir ?? null })} pagination={false} defaultHiddenColumnIds={["seen"]} emptyState={<p className="p-6 text-sm text-muted-foreground">No nodes match the current server filters or page.</p>} /></div>
      {route.page > 0 && !filtered.length && <Button onClick={() => update({ page: null }, false)}>First page</Button>}
      <Pager page={route.page} pageSize={100} total={total} rowsOnPage={filtered.length} onPage={page => update({ page: page ? String(page + 1) : null }, false)} />
      {selectedName && <div className="flex flex-wrap items-center gap-3"><Button size="sm" variant="outline" onClick={() => update({ selected: null }, false)}>Clear selection</Button>{selectedHref ? <a href={selectedHref} className="text-sm text-primary hover:underline">Open selected node</a> : <p role="status" className="text-sm text-muted-foreground">The selected node is outside this page or filter. Its URL selection is preserved; no other node has been substituted.</p>}</div>}
      {selected && <Collapse key={`${clusterId}:${selected.node}`} label={`Node inspection · ${selected.node}`} defaultOpen><NodePreview node={selected} clusterId={clusterId} /></Collapse>}
    </section>}
  </div>;
}

function nodeInventoryMatches(data: NodeListResponse, clusterId: string, request: NodeInventoryParams) {
 const total = data.total; const offset = request.offset || 0;
 if (!data.summary || typeof data.summary !== "object" || !Array.isArray(data.items) || data.cluster_id !== clusterId || data.q !== (request.q || "").trim() || data.agent !== (request.agent || "") || data.risk !== (request.risk || "") || data.host_cves !== (request.host_cves || "") || data.sort !== request.sort || data.order !== request.order || data.limit !== 100 || data.offset !== offset || !Number.isSafeInteger(total) || total! < 0 || data.items.length !== Math.min(100, Math.max(0, total! - offset)) || data.has_more !== (total! > offset + data.items.length) || data.summary.nodes !== total || !["nodes", "runtime_agent_healthy", "runtime_agent_stale", "runtime_agent_missing", "scan_completed", "scan_gaps", "critical_vulns", "high_vulns", "cis_failed"].every(key => Number.isSafeInteger(data.summary[key as keyof typeof data.summary]) && data.summary[key as keyof typeof data.summary] >= 0)) return false;
 const names = new Set<string>();
 return data.items.every(item => { if (!item.node?.trim() || names.has(item.node) || item.cluster_id !== clusterId || request.agent && item.runtime_agent_status !== request.agent || !matchesRiskFilter(item, request.risk || "all")) return false; names.add(item.node); return true; });
}

function RiskCount({ value, tone }: { value: number; tone: "warn" | "danger" }) {
  return <span className={cn("tabular-nums", value > 0 && (tone === "danger" ? "font-semibold text-status-error" : "font-medium text-status-warn"))}>{value.toLocaleString()}</span>;
}

function NotCollected({ label = "Not collected" }: { label?: string }) {
  return <span className="font-sans text-xs italic text-muted-foreground">{label}</span>;
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
            <a href={`/clusters/${clusterId}/risk/node/${encodeURIComponent(node.node)}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent" data-testid="node-risk-workspace-link">
              Risk workspace
            </a>
            <a href={`/clusters/${clusterId}/nodes/${encodeURIComponent(node.node)}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
              Full Details
            </a>
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

function displayOS(item: NodeSummary): string {
  if (item.os_id && item.os_version_id) return `${item.os_id} ${item.os_version_id}`;
  return item.os_id || item.os_version_id || "OS unknown";
}

function formatDate(value?: string): string {
  if (!value) return "Not collected";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  if (date.getTime() <= 0) return "Not collected";
  return date.toLocaleString();
}
