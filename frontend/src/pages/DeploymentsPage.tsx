import { ResourceSavedViewsControl } from "@/components/ResourceSavedViewsControl";
// Risk-prioritized deployment dashboard — StackRox parity.
//
// The center of the platform's operational workflow: show the riskiest
// deployments first and expose the factors behind the score. The discoverer
// rolls image/workload findings and runtime exposure into deployments.risk_score.
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { useState } from "react";
import { useRouteSearchParams } from "@/lib/route-search";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { deployments, type Deployment } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { FilterLabel, InventoryMoreFilters, InventorySearch } from "./inventory-workspace";
import { Pager } from "@/components/ui/pager";
import { Button } from "@/components/ui/button";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { usePlatformComponentVisibility } from "@/hooks/usePlatformComponentVisibility";
import { Select, TextInput } from "@/components/ui/form";

const PAGE_SIZE = 100;

export function DeploymentsPage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const client = useQueryClient();
  const scopeReady = !!owner && !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError;
  const [searchParams, setSearchParams] = useRouteSearchParams();
  const search = searchParams.get("q") ?? searchParams.get("name") ?? "";
  const namespace = searchParams.get("namespace") ?? "";
  const groupMode = searchParams.get("group_mode") ?? "";
  const riskFact = searchParams.get("risk_fact") ?? "";
  const platformRole = searchParams.get("platform_role") ?? "all";
  const requestedPage = Number(searchParams.get("page") ?? "1");
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 && requestedPage <= Math.floor(Number.MAX_SAFE_INTEGER / PAGE_SIZE) ? requestedPage - 1 : 0;
  const [preferredHidden, setPreferredHidden] = usePlatformComponentVisibility();
  const visibility = searchParams.get("hide_platform");
  const normalizedVisibility = visibility?.toLowerCase();
  const validVisibility = visibility === null || ["true", "false", "1", "0", "t", "f"].includes(normalizedVisibility!);
  const hidePlatformComponents = visibility === null ? preferredHidden : ["true", "1", "t"].includes(normalizedVisibility!);
  const [pendingExport, setPendingExport] = useState<string | null>(null);
  const [exportError, setExportError] = useState<{context:string;error:unknown} | null>(null);
  const presence = searchParams.get("presence") || "current";
  const filters = { presence, q: search.trim() || undefined, namespace: namespace || undefined, cluster_id: clusterId, hide_platform: hidePlatformComponents, platform_role: platformRole === "all" ? undefined : platformRole, ...(groupMode ? { group_mode: groupMode } : {}), ...(riskFact ? { risk_fact: riskFact } : {}) };
  const inventoryKey = ["deployments", owner, clusterId, search.trim(), namespace, platformRole, groupMode, riskFact, hidePlatformComponents, visibility, presence, page];
  const q = useQuery({
    queryKey: inventoryKey,
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
  const exportContext = JSON.stringify([owner, filters, page]);
  const exporting = pendingExport === exportContext;
  const captureExport = useExportGuard(exportContext, !scopeReady || !q.isSuccess || q.isFetching, () => !!clusterId && clusterCacheReady(client, clusterId) && exportQueryReady(client, inventoryKey, q.data));
  const exportMatching = async () => {
    const current = captureExport();
    if (!current() || exporting) return;
    const context = exportContext;
    setExportError(null); setPendingExport(context);
    try {
      const blob = await deployments.exportCsv(filters);
      if (!current()) return;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = "constellation-workloads.csv";
      anchor.click(); URL.revokeObjectURL(url);
    } catch (error) { if (current()) setExportError({context,error}); }
    finally { setPendingExport(previous => previous === context ? null : previous); }
  };

  // The server fixes order by risk, last seen, then ID. No client comparators
  // are supplied, so a sortable header cannot reorder only the current page.
  const columns: Column<Deployment>[] = [
    {id:"presence",header:"Presence",kind:"status",cell:d=>d.inventory_presence === "scaled_to_zero" ? "Scaled to zero" : d.inventory_presence === "absent" ? "Absent from fresh inventory" : d.inventory_presence === "present" ? "Present" : "Unverified",exportValue:d=>d.inventory_presence || "unverified"},
    {
      id: "risk", kind: "count", size: 88, numeric: true,
      header: "Risk",
      className: "font-mono",
      cell: (d) => <span className={`font-mono text-13 font-semibold tabular-nums ${riskClass(d.risk_score)}`}>{d.risk_score}</span>,
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
          {Number(d.risk_factors?.privileged) > 0 && <span className="ml-1.5 rounded px-1 py-px text-micro font-semibold " style={{ background: "color-mix(in oklab, var(--color-severity-critical) 16%, transparent)", color: "var(--color-severity-critical)" }} title="privileged container">priv</span>}
          {Number(d.risk_factors?.run_as_root) > 0 && <span className="ml-1 rounded px-1 py-px text-micro font-semibold " style={{ background: "color-mix(in oklab, var(--color-severity-high) 16%, transparent)", color: "var(--color-severity-high)" }} title="runs as root">root</span>}
          {Number(d.risk_factors?.host_network) > 0 && <span className="ml-1 rounded px-1 py-px text-micro font-semibold " style={{ background: "color-mix(in oklab, var(--color-severity-high) 16%, transparent)", color: "var(--color-severity-high)" }} title="host network">hostnet</span>}
          <a
            href={`/clusters/${clusterId}/risk/deployment/${encodeURIComponent(d.id)}`}
            className="ml-2 text-micro text-muted-foreground hover:text-foreground hover:underline"
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
      cell: (d) => (
        <span className="tabular-nums">
          {d.finding_count} total
          {d.critical_count > 0 && (
            <span className="ml-2"><span className="font-semibold text-severity-critical">{d.critical_count}</span> critical</span>
          )}
          {d.high_count > 0 && (
            <span className="ml-2"><span className="font-semibold text-severity-high">{d.high_count}</span> high</span>
          )}
        </span>
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

  const toolbar = <>
    <InventorySearch value={search} onChange={(value) => updateFilter("q", value)} label="Search workloads" placeholder="Search workloads or namespace/name" testId="deployment-search" className="max-w-xs" />
    <Select aria-label="Strongest group mode" value={groupMode} onChange={(event) => updateFilter("group_mode", event.target.value)} className="h-9"><option value="">Any group mode</option><option value="discover">Discover</option><option value="monitor">Monitor</option><option value="protect">Protect</option>{groupMode && !["discover", "monitor", "protect"].includes(groupMode) && <option value={groupMode}>Invalid mode: {groupMode}</option>}</Select>
    <InventoryMoreFilters count={[namespace, riskFact, platformRole !== "all" ? platformRole : "", presence !== "current" ? presence : ""].filter(Boolean).length}>
      <FilterLabel label="Recorded risk fact">
    <Select aria-label="Recorded risk fact" value={riskFact} onChange={(event) => updateFilter("risk_fact", event.target.value)} className="w-full"><option value="">Any risk fact</option><option value="privileged">Privileged</option><option value="run_as_root">Runs as root</option><option value="net_exposure">Network exposure</option><option value="host_network">Host network</option>{riskFact && !["privileged", "run_as_root", "net_exposure", "host_network"].includes(riskFact) && <option value={riskFact}>Invalid fact: {riskFact}</option>}</Select>
      </FilterLabel>
      <FilterLabel label="Presence">
    <Select aria-label="Workload presence" value={presence} onChange={event=>updateFilter("presence",event.target.value)} className="w-full">
      <option value="current">Current and unverified</option><option value="all">Include absent workloads</option><option value="absent">Absent from fresh inventory</option><option value="scaled_to_zero">Scaled to zero</option><option value="unverified">Unverified</option>
    </Select>
      </FilterLabel>
      <FilterLabel label="Namespace"><TextInput value={namespace} onChange={(event) => updateFilter("namespace", event.target.value)} placeholder="All namespaces" data-testid="namespace-filter" /></FilterLabel>
      <FilterLabel label="Workload type"><Select aria-label="Workload type" value={platformRole} onChange={(event) => {
        const value = event.target.value;
        if (value === "core") setPreferredHidden(false);
        setSearchParams((current) => {
          if (value === "all") current.delete("platform_role"); else current.set("platform_role", value);
          if (value === "core") current.set("hide_platform", "false");
          current.delete("page"); return current;
        });
      }} className="w-full" data-testid="deployment-role-filter"><option value="all">All types</option><option value="none">Customer workloads</option><option value="core">Platform workloads</option></Select></FilterLabel>
    </InventoryMoreFilters>
  </>;
  return (
    <div className="space-y-4" data-testid="deployments-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Workloads"
        description="Riskiest workloads first: open vulnerabilities, exploit signals (CVSS, KEV), runtime exposure and posture."
        actions={<><ResourceSavedViewsControl inventory="deployments" clusterId={clusterId} ready={scopeReady && q.isSuccess && !q.isFetching} overrides={{hide_platform:String(hidePlatformComponents),presence}}/><Button disabled={!scopeReady || q.isFetching} onClick={() => void q.refetch()}><RefreshCw className="h-4 w-4" />Refresh</Button></>}
      />
      <VerdictBanner
        status={clusterError ? "degraded" : !scopeReady || q.isPending ? "info" : q.isError ? "degraded" : !total ? "info" : (summary?.at_risk ?? 0) > 0 ? "degraded" : "ok"}
        title={clusterError ? "Cluster inventory is unavailable" : !scopeReady ? clusterLoading ? "Resolving cluster" : "Select a resolved cluster" : q.isPending ? "Loading workload inventory" : q.isError ? "Workload inventory is unavailable" : !total ? "No matching workloads" : (summary?.at_risk ?? 0) > 0 ? "Workloads need risk review" : "No high-risk workloads match these filters"}
        numbers={summary ? [
          { label: "workloads", value: summary.total.toLocaleString() },
          { label: "at risk", value: summary.at_risk.toLocaleString(), tone: summary.at_risk > 0 ? "high" : "default", title: "Risk score 60 or more" },
          { label: "critical findings", value: summary.critical_count.toLocaleString(), tone: summary.critical_count > 0 ? "critical" : "default" },
          { label: "high findings", value: summary.high_count.toLocaleString(), tone: summary.high_count > 0 ? "high" : "default" },
        ] : undefined}
        detail={<div className="space-y-1">
          <p data-testid="deployments-summary">Workloads {summary?.total.toLocaleString() ?? "—"} · at risk {summary?.at_risk.toLocaleString() ?? "—"} · critical findings {summary?.critical_count.toLocaleString() ?? "—"} · high findings {summary?.high_count.toLocaleString() ?? "—"}{platformCount ? ` · ${platformCount} platform workloads ${hidePlatformComponents ? "hidden" : "shown"}` : ""}</p>
          <p>Search, visibility, counts, paging and CSV use the same source filters. The System workloads scope does not change collection or protection.</p>
          {groupMode && <p data-testid="deployment-group-mode-scope">Workloads whose strongest configured group mode is {groupMode}. Unmatched workloads are excluded. This describes cached group membership, not applied protection.</p>}
          {riskFact && <p data-testid="deployment-risk-fact-scope">Recorded risk fact: {riskFact}. Matches workloads reporting this key, including zero or null values; this does not assert that the condition is active.</p>}
        </div>}
      />
      {exportError?.context === exportContext ? <ErrorState title="Workload export failed" error={exportError.error} /> : null}
      {!scopeReady ? clusterError ? <ErrorState title="Cluster inventory is unavailable" error={clusterError} /> : clusterLoading ? <LoadingState label="Resolving cluster…" /> : <p className="text-sm text-muted-foreground">Select a resolved cluster to view deployments.</p> : q.isPending ? <LoadingState label="Loading workloads" /> : q.isError ? <ErrorState title="Could not load deployments" error={q.error} action={<Button variant="outline" onClick={() => void q.refetch()}>Retry</Button>} /> : <>
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(d) => d.id}
          toolbar={toolbar}
          exportOptions={[{ label: exporting ? "Exporting…" : "Matching workloads", description: "Every page", disabled: !scopeReady || q.isPending || q.isFetching || q.isError || !total || exporting, onSelect: () => void exportMatching() }]}
          preferencesKey="deployments"
          testId="deployments-table"
          rowTestId={() => "deployment-row"}
          pagination={false}
          className="rounded-lg"
          emptyState={<div className="px-3 py-6 text-center text-sm text-muted-foreground">{hidePlatformComponents && platformCount ? `${platformCount} matching platform workloads are hidden. Turn on System workloads in the header to show them.` : page > 0 ? "No workloads on this page. Return to the first page or change the filters." : search.trim() || namespace || groupMode || riskFact || platformRole !== "all" ? "No workloads match this search." : "No workloads yet. The operator discovers workloads and persists their risk."}</div>}
        />
        <p className="sr-only" data-testid="deployment-page-scope">Showing {rows.length ? page * PAGE_SIZE + 1 : 0}–{page * PAGE_SIZE + rows.length} of {total ?? "unknown"} matching workloads, ranked by risk then last seen.</p>
        <Pager page={page} pageSize={PAGE_SIZE} total={total} hasMore={q.data?.has_more} rowsOnPage={rows.length} onPage={setPage} />
        {page > 0 && rows.length === 0 ? <Button variant="outline" onClick={() => setPage(0)}>First page</Button> : null}
      </>}

    </div>
  );
}

function riskClass(score: number): string {
  if (score >= 80) return "text-severity-critical";
  if (score >= 60) return "text-severity-high";
  if (score >= 30) return "text-severity-medium";
  return "text-foreground";
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
      <span className="text-micro text-muted-foreground">
        {entries.map(([k, v]) => `${k}=${v}`).join(" · ")}
      </span>
    </div>
  );
}
