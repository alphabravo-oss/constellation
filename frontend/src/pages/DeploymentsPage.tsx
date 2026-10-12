// Risk-prioritized deployment dashboard — StackRox parity.
//
// The center of the platform's operational workflow: show the riskiest
// deployments first and expose the factors behind the score. The discoverer
// rolls image/workload findings and runtime exposure into deployments.risk_score.
import { useState } from "react";
import { useRouteSearchParams } from "@/lib/route-search";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Flame, Layers, RefreshCw, ShieldAlert } from "lucide-react";
import { deployments, type Deployment } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { PlatformVisibilityToggle } from "@/components/ui/platform-visibility-toggle";
import { Pager } from "@/components/ui/pager";
import { Button } from "@/components/ui/button";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { usePlatformComponentVisibility } from "@/hooks/usePlatformComponentVisibility";

const PAGE_SIZE = 100;

export function DeploymentsPage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const scopeReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError;
  const [searchParams, setSearchParams] = useRouteSearchParams();
  const search = searchParams.get("q") ?? searchParams.get("name") ?? "";
  const namespace = searchParams.get("namespace") ?? "";
  const riskFact = searchParams.get("risk_fact") ?? "";
  const platformRole = searchParams.get("platform_role") ?? "all";
  const requestedPage = Number(searchParams.get("page") ?? "1");
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 && requestedPage <= Math.floor(Number.MAX_SAFE_INTEGER / PAGE_SIZE) ? requestedPage - 1 : 0;
  const [preferredHidden, setPreferredHidden] = usePlatformComponentVisibility();
  const visibility = searchParams.get("hide_platform");
  const normalizedVisibility = visibility?.toLowerCase();
  const validVisibility = visibility === null || ["true", "false", "1", "0", "t", "f"].includes(normalizedVisibility!);
  const hidePlatformComponents = visibility === null ? preferredHidden : ["true", "1", "t"].includes(normalizedVisibility!);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<unknown>(null);
  const filters = { q: search.trim() || undefined, namespace: namespace || undefined, cluster_id: clusterId, hide_platform: hidePlatformComponents, platform_role: platformRole === "all" ? undefined : platformRole, ...(riskFact ? { risk_fact: riskFact } : {}) };
  const q = useQuery({
    queryKey: ["deployments", clusterId, search.trim(), namespace, platformRole, riskFact, hidePlatformComponents, visibility, page],
    queryFn: async () => {
      if (!validVisibility) throw new Error("Invalid platform visibility filter");
      return deployments.list({ ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE });
    },
    enabled: scopeReady,
  });
  const rows = scopeReady && !q.isError ? q.data?.deployments ?? [] : [];
  const summary = scopeReady && !q.isError ? q.data?.summary : undefined;
  const total = scopeReady && !q.isError ? q.data?.total : undefined;
  const platformCount = scopeReady && !q.isError ? q.data?.platform_count : undefined;
  const updateFilter = (key: string, value: string) => setSearchParams((current) => {
    if (key === "q") current.delete("name");
    if (value) current.set(key, value); else current.delete(key);
    current.delete("page");
    return current;
  }, { replace: key === "q" || key === "namespace" });
  const setPage = (nextPage: number) => setSearchParams((current) => {
    if (nextPage === 0) current.delete("page"); else current.set("page", String(nextPage + 1));
    return current;
  });
  const exportMatching = async () => {
    setExportError(null); setExporting(true);
    try {
      const blob = await deployments.exportCsv(filters);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = "constellation-workloads.csv";
      anchor.click(); URL.revokeObjectURL(url);
    } catch (error) { setExportError(error); }
    finally { setExporting(false); }
  };

  // The server fixes order by risk, last seen, then ID. No client comparators
  // are supplied, so a sortable header cannot reorder only the current page.
  const columns: Column<Deployment>[] = [
    {
      id: "risk", kind: "count", size: 88, numeric: true,
      header: "Risk",
      className: "font-mono",
      cell: (d) => <span className={`rounded-md px-2 py-0.5 ${riskClass(d.risk_score)}`}>{d.risk_score}</span>,
    },
    {
      id: "deployment", kind: "name", grow: true, minSize: 280, wrap: true,
      header: "Deployment",
      cell: (d) => (
        <>
          <a href={`/clusters/${clusterId}/deployments/${d.id}`} className="hover:underline">
            <span className="text-foreground font-medium">
              {d.namespace}/{d.name}
            </span>
          </a>
          <span className="ml-1 text-xs text-muted-foreground">· {d.kind}</span>
          {/* Security-context posture chips (NeuVector surfaces privileged/root as columns). */}
          {Number(d.risk_factors?.privileged) > 0 && <span className="ml-1.5 rounded px-1 py-px text-[9px] font-semibold uppercase" style={{ background: "color-mix(in oklab, var(--color-severity-critical) 16%, transparent)", color: "var(--color-severity-critical)" }} title="privileged container">priv</span>}
          {Number(d.risk_factors?.run_as_root) > 0 && <span className="ml-1 rounded px-1 py-px text-[9px] font-semibold uppercase" style={{ background: "color-mix(in oklab, var(--color-severity-high) 16%, transparent)", color: "var(--color-severity-high)" }} title="runs as root">root</span>}
          {Number(d.risk_factors?.host_network) > 0 && <span className="ml-1 rounded px-1 py-px text-[9px] font-semibold uppercase" style={{ background: "color-mix(in oklab, var(--color-severity-high) 16%, transparent)", color: "var(--color-severity-high)" }} title="host network">hostnet</span>}
          <a
            href={`/clusters/${clusterId}/risk/deployment/${encodeURIComponent(d.id)}`}
            className="ml-2 text-[10px] text-muted-foreground hover:text-foreground hover:underline"
            data-testid="deployment-risk-workspace-link"
          >
            risk workspace
          </a>
        </>
      ),
    },
    {
      id: "findings", kind: "count", size: 200, minSize: 176, maxSize: 232, wrap: true,
      header: "Findings",
      className: "text-xs",
      cell: (d) => (
        <>
          {d.finding_count} total
          {d.critical_count > 0 && (
            <span className="ml-2 rounded-md bg-[color:var(--color-severity-critical)]/15 px-1.5 py-0.5 text-[color:var(--color-severity-critical)]">
              {d.critical_count} critical
            </span>
          )}
          {d.high_count > 0 && (
            <span className="ml-1 rounded-md bg-[color:var(--color-severity-high)]/15 px-1.5 py-0.5 text-[color:var(--color-severity-high)]">
              {d.high_count} high
            </span>
          )}
        </>
      ),
    },
    {
      id: "factors", kind: "percent", size: 144, minSize: 128, maxSize: 160,
      header: "Risk factors",
      className: "text-xs",
      cell: (d) => <FactorBar factors={d.risk_factors} />,
    },
    {
      id: "lastSeen", kind: "date", size: 176, minSize: 160,
      header: "Last seen",
      className: "text-xs text-muted-foreground",
      cell: (d) => <>{new Date(d.last_seen_at).toLocaleString()}</>,
    },
  ];

  return (
    <div className="space-y-4" data-testid="deployments-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Deployments at risk"
        description="Your riskiest deployments first. The score blends open vulnerabilities, exploit signals (CVSS, KEV), runtime exposure, and workload posture."
      />
      <VerdictBanner
        status={clusterError ? "degraded" : !scopeReady || q.isPending ? "info" : q.isError ? "degraded" : !total ? "info" : (summary?.at_risk ?? 0) > 0 ? "degraded" : "ok"}
        title={clusterError ? "Cluster inventory is unavailable" : !scopeReady ? clusterLoading ? "Resolving cluster" : "Select a resolved cluster" : q.isPending ? "Loading deployment inventory" : q.isError ? "Deployment inventory is unavailable" : !total ? "No matching deployments" : (summary?.at_risk ?? 0) > 0 ? "Deployments need risk review" : "No high-risk deployments match these filters"}
        detail="Search, visibility, counts, paging and CSV use the same source filters. Platform visibility does not change collection or protection."
      />

      <div className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-card p-3">
        <label className="min-w-48 flex-1 space-y-1 text-xs"><span className="text-muted-foreground">Search</span><input type="search" value={search} onChange={(event) => updateFilter("q", event.target.value)} placeholder="Deployment name or namespace/name" className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" data-testid="deployment-search" /></label>
        <label className="space-y-1 text-xs"><span className="text-muted-foreground">Namespace</span><input value={namespace} onChange={(event) => updateFilter("namespace", event.target.value)} placeholder="All namespaces" className="block rounded-md border border-border bg-background px-3 py-2 text-sm" data-testid="namespace-filter" /></label>
        <label className="space-y-1 text-xs"><span className="text-muted-foreground">Deployment type</span><select value={platformRole} onChange={(event) => {
          const value = event.target.value;
          if (value === "core") setPreferredHidden(false);
          setSearchParams((current) => {
            if (value === "all") current.delete("platform_role"); else current.set("platform_role", value);
            if (value === "core") current.set("hide_platform", "false");
            current.delete("page"); return current;
          });
        }} className="block rounded-md border border-border bg-background px-3 py-2 text-sm" data-testid="deployment-role-filter"><option value="all">All types</option><option value="none">Customer deployments</option><option value="core">Platform deployments</option></select></label>
        <label className="space-y-1 text-xs"><span className="text-muted-foreground">Recorded risk fact</span><select aria-label="Recorded risk fact" value={riskFact} onChange={(event) => updateFilter("risk_fact", event.target.value)} className="block rounded-md border border-border bg-background px-3 py-2 text-sm"><option value="">Any fact</option><option value="privileged">Privileged</option><option value="run_as_root">Runs as root</option><option value="net_exposure">Network exposure</option><option value="host_network">Host network</option>{riskFact && !["privileged", "run_as_root", "net_exposure", "host_network"].includes(riskFact) && <option value={riskFact}>Invalid fact: {riskFact}</option>}</select></label>
        <PlatformVisibilityToggle hidden={hidePlatformComponents} onHiddenChange={(hidden) => { setPreferredHidden(hidden); updateFilter("hide_platform", String(hidden)); }} hiddenCount={platformCount} />
        <Button variant="outline" disabled={!scopeReady || q.isFetching} onClick={() => void q.refetch()}><RefreshCw className="h-4 w-4" />Refresh</Button>
        <Button variant="outline" disabled={!scopeReady || q.isPending || q.isFetching || q.isError || !total || exporting} onClick={() => void exportMatching()}>{exporting ? "Exporting…" : "Export CSV"}</Button>
      </div>
      {riskFact && <p className="text-xs text-muted-foreground" data-testid="deployment-risk-fact-scope">Recorded risk fact: {riskFact}. Matches deployments reporting this key, including zero or null values; this does not assert that the condition is active.</p>}
      {exportError ? <ErrorState title="Deployment export failed" error={exportError} /> : null}

      <StatGrid data-testid="deployments-summary">
        <StatCard label="Deployments" value={summary?.total.toLocaleString() ?? "—"} icon={<Layers className="h-3.5 w-3.5" />} />
        <StatCard label="At risk" value={summary?.at_risk.toLocaleString() ?? "—"} icon={<AlertTriangle className="h-3.5 w-3.5" />} tone={(summary?.at_risk ?? 0) > 0 ? "high" : "neutral"} hint="risk score ≥ 60" />
        <StatCard label="Critical findings" value={summary?.critical_count.toLocaleString() ?? "—"} icon={<Flame className="h-3.5 w-3.5" />} tone={(summary?.critical_count ?? 0) > 0 ? "critical" : "neutral"} />
        <StatCard label="High findings" value={summary?.high_count.toLocaleString() ?? "—"} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={(summary?.high_count ?? 0) > 0 ? "high" : "neutral"} />
      </StatGrid>

      {!scopeReady ? clusterError ? <ErrorState title="Cluster inventory is unavailable" error={clusterError} /> : clusterLoading ? <LoadingState label="Resolving cluster…" /> : <p className="text-sm text-muted-foreground">Select a resolved cluster to view deployments.</p> : q.isPending ? <LoadingState label="Loading deployments…" /> : q.isError ? <ErrorState title="Could not load deployments" error={q.error} action={<Button variant="outline" onClick={() => void q.refetch()}>Retry</Button>} /> : <>
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(d) => d.id}
          preferencesKey="deployments"
          testId="deployments-table"
          rowTestId={() => "deployment-row"}
          pagination={false}
          className="rounded-lg"
          emptyState={<div className="px-3 py-6 text-center text-xs text-muted-foreground">{hidePlatformComponents && platformCount ? `${platformCount} matching platform deployments are hidden. Use Platform hidden to show them.` : page > 0 ? "No deployments on this page. Return to the first page or change the filters." : search.trim() || namespace || riskFact || platformRole !== "all" ? "No deployments match this search." : "No deployments yet. The operator discovers workloads and persists their risk."}</div>}
        />
        <p className="text-xs text-muted-foreground" data-testid="deployment-page-scope">Showing {rows.length ? page * PAGE_SIZE + 1 : 0}–{page * PAGE_SIZE + rows.length} of {total ?? "unknown"} matching deployments, ranked by risk then last seen. CSV exports all matching deployments.</p>
        <Pager page={page} pageSize={PAGE_SIZE} total={total} hasMore={q.data?.has_more} rowsOnPage={rows.length} onPage={setPage} />
        {page > 0 && rows.length === 0 ? <Button variant="outline" onClick={() => setPage(0)}>First page</Button> : null}
      </>}

    </div>
  );
}

function riskClass(score: number): string {
  if (score >= 80) return "bg-[color:var(--color-severity-critical)]/15 text-[color:var(--color-severity-critical)]";
  if (score >= 60) return "bg-[color:var(--color-severity-high)]/15 text-[color:var(--color-severity-high)]";
  if (score >= 30) return "bg-[color:var(--color-severity-medium)]/15 text-[color:var(--color-severity-medium)]";
  return "bg-muted text-foreground";
}

// FactorBar renders a thin stacked bar of risk-factor contributions so the dashboard tells
// a one-glance story: "this deployment is risky because of CVSS+KEV, not because it's
// privileged." Mirrors StackRox's risk-factor list view.
function FactorBar({ factors }: { factors: Record<string, number> }) {
  const entries = Object.entries(factors ?? {}).filter(([, v]) => v > 0);
  const total = entries.reduce((s, [, v]) => s + v, 0) || 1;
  const colors: Record<string, string> = {
    cvss:           "bg-[color:var(--color-severity-critical)]",
    kev:            "bg-[color:var(--color-severity-high)]",
    epss:           "bg-[color:var(--color-severity-medium)]",
    privileged:     "bg-[color:var(--color-status-warning)]",
    net_exposure:   "bg-[color:var(--color-status-info)]",
    reachability:   "bg-[color:var(--color-status-pending)]",
  };
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-32 overflow-hidden rounded-full bg-muted">
        {entries.map(([k, v]) => (
          <span
            key={k}
            title={`${k}: ${v}`}
            className={`${colors[k] ?? "bg-foreground/40"}`}
            style={{ width: `${(v / total) * 100}%` }}
          />
        ))}
      </div>
      <span className="text-[10px] text-muted-foreground">
        {entries.map(([k, v]) => `${k}=${v}`).join(" · ")}
      </span>
    </div>
  );
}
