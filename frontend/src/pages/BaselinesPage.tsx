import { useState, useSyncExternalStore } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity, TriangleAlert, ShieldCheck, Sparkles, Clock3 } from "lucide-react";
import { baselines as baselinesApi, type BaselineSummary, type BaselineMode, type BaselineInventoryRow, type BaselineInventoryResponse } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { StatusPill, ModePill } from "@/components/ui/status-pill";
import { DataTable, type Column as TableColumn } from "@/components/ui/data-table";
import { usePlatformComponentVisibility } from "@/hooks/usePlatformComponentVisibility";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Pager } from "@/components/ui/pager";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { cn } from "@/lib/cn";
import { InventorySearch, useInventoryRoute, useScanInventoryExport } from "./inventory-workspace";
import { useBaselineScope, baselinePath } from "./baselines/context";
import { BASELINE_INVENTORY_SORTS, baselineInventoryMatches } from "./baselines/inventory";
import { Checkbox, Select } from "@/components/ui/form";

const COLUMNS: Array<{ mode: BaselineMode; title: string; tagline: string; tone: "info" | "warning" | "success"; icon: typeof Activity }> = [
 { mode: "learn", title: "Learn", tagline: "Configured to learn observed processes.", tone: "info", icon: Activity },
 { mode: "monitor", title: "Monitor", tagline: "Configured to report baseline deviations.", tone: "warning", icon: TriangleAlert },
 { mode: "enforce", title: "Enforce", tagline: "Configured to block deviations; check agent evidence.", tone: "success", icon: ShieldCheck },
];
export function BaselinesPage() {
  const scope = useBaselineScope();
  const { clusterId, scopeReady } = scope;
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const route = useInventoryRoute(INVENTORY_MAX_PAGE);
  const [tab, setTab] = useTabParam("tab", "inventory");
  const [highlight, setHighlight] = useState(false);
  const { params } = route;
  const namespace = (params.get("namespace") ?? "").trim();
  const rawMode = params.get("mode") ?? "";
  const mode = rawMode === "all" ? "" : rawMode;
  const [platformHidden] = usePlatformComponentVisibility();
  const hidePlatform = params.has("hide_platform") ? params.get("hide_platform") === "true" : platformHidden;
  const sort = params.get("sort") ?? "workload";
  const order = params.get("order") ?? "asc";
  const rawPage = params.get("page");
  const invalid = ["q", "namespace", "mode", "hide_platform", "sort", "order", "page", "tab"].some(key => params.getAll(key).length > 1) || !BASELINE_INVENTORY_SORTS.includes(sort) || !["asc", "desc"].includes(order) || mode !== "" && !["learn", "monitor", "enforce"].includes(mode) || params.has("hide_platform") && !["true", "false"].includes(params.get("hide_platform")!) || rawPage !== null && (!/^\d+$/.test(rawPage) || !Number.isSafeInteger(Number(rawPage)) || Number(rawPage) < 1 || Number(rawPage) > INVENTORY_MAX_PAGE);
  const request = { cluster_id: clusterId ?? "", q: route.debouncedQuery.trim().toLowerCase() || undefined, namespace: namespace || undefined, mode: mode ? mode as BaselineMode : undefined, hide_platform: hidePlatform, sort, order: order as "asc" | "desc", limit: 100, offset: route.offset };
  const key = ["baselines-inventory", owner, clusterId, request];
  const enabled = Boolean(owner && scopeReady && !invalid && !route.debouncing);
  const q = useQuery({ queryKey: key, enabled, queryFn: async () => {
    const data = await baselinesApi.inventory(request);
    if (!baselineInventoryMatches(data, request)) throw new Error("Process profile response does not match the requested scope or page");
    return data;
  } });
  const freshCache = useSyncExternalStore(
    notify => scope.qc.getQueryCache().subscribe(notify),
    () => Boolean(clusterId && clusterCacheReady(scope.qc, clusterId) && !scope.qc.getQueryState(key)?.isInvalidated),
  );
  const invalidResponse = q.isSuccess && !q.isFetching && !baselineInventoryMatches(q.data, request);
  const available = enabled && q.isSuccess && !q.isFetching && !invalidResponse && freshCache;
  const data = available ? q.data : undefined;
  const profiles = data?.profiles ?? [];
  const retry = () => scopeReady && owner && !invalid ? void q.refetch() : scope.retryScope();
  const context = JSON.stringify([key, route.query]);
  const exportCurrent = () => {
    const state = scope.qc.getQueryState<BaselineInventoryResponse>(key);
    if (!available || !clusterId || !clusterCacheReady(scope.qc, clusterId) || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || !baselineInventoryMatches(state.data, request)) return false;
    return true;
  };
  const exportCSV = (shouldDownload: () => boolean) => {
    if (!exportCurrent()) return Promise.reject(new Error("Refresh process profiles before exporting"));
    return baselinesApi.inventoryCSV(request, () => shouldDownload() && exportCurrent());
  };
  const columns: TableColumn<BaselineInventoryRow>[] = [
    { id: "workload", header: "Workload", kind: "name", wrap: true, sort: () => 0, cell: p => <a href={baselinePath(clusterId!,p.workload_id)} className="text-primary hover:underline">{p.workload_id}</a>, exportValue: p => p.workload_id },
    { id: "namespace", header: "Namespace", kind: "text", sort: () => 0, cell: p => p.namespace, exportValue: p => p.namespace },
    { id: "mode", header: "Mode", kind: "status", sort: () => 0, cell: p => <ModePill mode={p.mode} />, exportValue: p => p.mode },
    { id: "processes", header: "Processes (retained)", kind: "count", sort: () => 0, cell: p => p.learned_processes_count, exportValue: p => p.learned_processes_count },
    { id: "alerts", header: "Alerts (retained 24h)", kind: "count", sort: () => 0, cell: p => p.monitored_alerts_24h, exportValue: p => p.monitored_alerts_24h },
    { id: "blocks", header: "Blocks (retained 24h)", kind: "count", sort: () => 0, cell: p => p.enforced_blocks_24h, exportValue: p => p.enforced_blocks_24h },
    { id: "rules", header: "Configured rules", kind: "count", sort: () => 0, cell: p => p.rule_count, exportValue: p => p.rule_count },
    { id: "last_new", header: "Last new process", kind: "date", sort: () => 0, cell: p => p.last_new_process_at ? new Date(p.last_new_process_at).toLocaleString() : "Not reported", exportValue: p => p.last_new_process_at ?? "" },
    { id: "learn_started", header: "Learn started", kind: "date", sort: () => 0, cell: p => p.learn_started_at ? new Date(p.learn_started_at).toLocaleString() : "Not reported", exportValue: p => p.learn_started_at ?? "" },
    { id: "platform-role", header: "Platform role", kind: "status", cell: p => p.platform_role === "core" ? "Core" : "Unclassified", exportValue: p => p.platform_role },
    { id: "owners", header: "Inventory owners", kind: "count", cell: p => p.owner_ambiguous ? `${p.owner_count} (ambiguous)` : p.owner_count, exportValue: p => p.owner_count },
    { id: "configured", header: "Mode state", kind: "status", cell: p => p.configured ? "Configured" : "Default learn", exportValue: p => p.configured },
  ];
  const matching = useScanInventoryExport({ context, disabled: !available, download: exportCSV });
  const toolbar = <>
    <InventorySearch value={route.query} onChange={route.setQuery} label="Search workloads" />
    <Select aria-label="Namespace" value={namespace} onChange={e => route.update({ namespace: e.target.value })} className="h-9 max-w-48"><option value="">Any namespace</option>{(data?.namespaces ?? []).filter(Boolean).map(ns => <option key={ns}>{ns}</option>)}{namespace && !data?.namespaces.includes(namespace) && <option>{namespace}</option>}</Select>
    <Select aria-label="Mode" value={mode} onChange={e => route.update({ mode: e.target.value })} className="h-9"><option value="">Any mode</option>{COLUMNS.map(c => <option key={c.mode} value={c.mode}>{c.title}</option>)}</Select>
    {(route.query || namespace || mode) && <Button variant="ghost" onClick={() => route.update({ q: null, namespace: null, mode: null, hide_platform: null, sort: null, order: null })}>Reset filters</Button>}
  </>;
  const pageControls = data && <Pager page={route.page} pageSize={100} total={data.total} rowsOnPage={profiles.length} onPage={route.setPage} />;
  return <div className="space-y-5" data-testid="baselines-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title="Process baselines" description="Configured process profiles and observed execution evidence." actions={<Button disabled={!scopeReady || !owner || invalid || q.isFetching || route.debouncing} onClick={retry}>Refresh</Button>} />
    <VerdictBanner status={data ? "info" : "degraded"} title={data ? `${data.total.toLocaleString()} matching workload profiles` : "Process profile evidence unavailable"} numbers={COLUMNS.map(c => ({ label: c.title.toLowerCase(), value: data?.summary[c.mode] ?? "—" }))} detail={<><p>Modes describe configured behavior. Agent activity and enforcement must be verified separately.</p><p>Totals cover every matching retained process profile, including saved profiles and authored rules without a current inventory owner. Observed process and 24-hour alert/block counts use all retained process events for the workload and exact owned pods; they do not establish collection completeness. Detail pages retain their separately labeled latest-1,000-event sample. Lifecycle cards cover the current server page and preview up to five process names. Matching CSV exports up to 100,000 profiles across pages; page CSV uses selected visible columns.</p>{data && <p>{data.summary.processes.toLocaleString()} observed process identities · {data.summary.alerts_24h.toLocaleString()} retained 24-hour alerts · {data.summary.blocks_24h.toLocaleString()} retained 24-hour blocks · {data.summary.rules.toLocaleString()} configured rules · {data.summary.ambiguous_owners.toLocaleString()} ambiguous inventory owners across matching profiles.</p>}</>} />
    <p className="sr-only" data-testid="baselines-summary">Matching profiles <span className="app-stat-value">{data?.total ?? "—"}</span>{COLUMNS.map(c => <span key={c.mode}> {c.title} <span className="app-stat-value">{data?.summary[c.mode] ?? "—"}</span></span>)}</p>
    {!scopeReady || !owner ? scope.error || !owner ? <ErrorState title={owner ? "Could not resolve this cluster." : "Sign in to load process profiles."} action={<Button onClick={retry}>Retry</Button>} /> : <LoadingState label="Resolving cluster…" /> : invalid ? <ErrorState title="Choose supported profile filters, sorting, and a valid page." /> : q.isError || invalidResponse ? <ErrorState title="Could not load or refresh process profiles." action={<Button onClick={retry}>Retry</Button>} /> : !data ? <LoadingState label="Loading profiles…" /> : <>
      <p className="sr-only">{data.total.toLocaleString()} matching profiles · {profiles.length} on page {route.page + 1}</p>{matching.status}
      <Tabs value={["inventory", "lifecycle"].includes(tab) ? tab : "inventory"} onValueChange={setTab} items={[
        { value: "inventory", label: "Inventory", content: <DataTable rows={profiles} columns={columns} rowKey={p => p.row_id} rowTestId={p => `baselines-card-${p.workload_id}`} testId="baselines-table" preferencesKey="process-baselines" defaultHiddenColumnIds={["namespace", "alerts", "blocks", "learn_started", "platform-role", "owners", "configured"]} manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => route.update({ sort: next?.id ?? "workload", order: next?.dir ?? (sort === "workload" && order === "asc" ? "desc" : "asc") })} pagination={false} toolbar={toolbar} exportOptions={[matching.option]} exportFileName="process-baselines-page" exportLabel="This page" emptyState={<p>No profiles match these filters or page.</p>} /> },
        { value: "lifecycle", label: "Lifecycle", content: <div className="space-y-4"><p className="text-xs text-muted-foreground">Current server page: {profiles.length} of {data.total.toLocaleString()} matching profiles. Mode totals above cover all matches.</p><label className="flex items-center gap-2 text-sm"><Checkbox checked={highlight} onChange={e => setHighlight(e.target.checked)} aria-label="Highlight promotion candidates" /> Highlight learning profiles observed for at least 14 days with no new process in the last 24 hours</label><p className="text-xs text-muted-foreground">A review hint based on retained observations. Nothing is promoted automatically.</p><section className="grid gap-4 lg:grid-cols-3" data-testid="baselines-columns">{COLUMNS.map(c => <Column key={c.mode} {...c} Icon={c.icon} profiles={profiles.filter(p => p.mode === c.mode)} highlightIDs={highlight ? profiles.filter(qualifiesForAutoPromote).map(p => p.workload_id) : []} loading={false} clusterId={clusterId!} />)}</section></div> },
      ]} />
      {profiles.length === 0 && route.page > 0 && <Button onClick={() => route.setPage(0)}>First page</Button>}
      {pageControls}
    </>}
  </div>;
}
// ----- Column ---------------------------------------------------------------

function Column({
  mode, title, tagline, tone, Icon, profiles, clusterId, highlightIDs, loading,
}: {
  mode: BaselineMode;
  title: string;
  tagline: string;
  tone: "info" | "warning" | "success";
  Icon: typeof Activity;
  profiles: BaselineSummary[];
  clusterId: string;
  highlightIDs: string[];
  loading: boolean;
}) {
  const tint =
    tone === "warning" ? "border-status-warning/30 bg-status-warning/[0.03]" :
    tone === "success" ? "border-status-success/30 bg-status-success/[0.03]" :
    "border-border bg-muted/30";
  return (
    <div
      className={cn("flex flex-col rounded-lg border", tint)}
      data-testid={`baselines-column-${mode}`}
    >
      <header className="flex items-start justify-between gap-2 border-b border-border/60 px-3 py-2.5">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
            <h2 className="text-sm font-semibold">{title}</h2>
            <StatusPill label={String(profiles.length)} tone={tone} dot={false} uppercase={false} />
          </div>
          <p className="mt-0.5 text-micro text-muted-foreground">{tagline}</p>
        </div>
      </header>
      <div className="flex-1 space-y-2 p-3" data-testid={`baselines-column-cards-${mode}`}>
        {loading && profiles.length === 0 && (
          <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
            Loading…
          </p>
        )}
        {!loading && profiles.length === 0 && (
          <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
            No workloads in {title.toLowerCase()} mode on this page.
          </p>
        )}
        {profiles.map((p) => (
          <ProfileCard
            key={p.workload_id}
            profile={p}
            highlight={highlightIDs.includes(p.workload_id)}
            href={baselinePath(clusterId,p.workload_id)}
          />
        ))}
      </div>
    </div>
  );
}

// ----- Card -----------------------------------------------------------------

function ProfileCard({
  profile, href, highlight,
}: {
  profile: BaselineSummary;
  href: string;
  highlight: boolean;
}) {
  const top = profile.top_processes ?? [];
  const age = ageSince(profile.learn_started_at);
  return (
    <a
      href={href}
      data-testid={`baselines-card-${profile.workload_id}`}
      className={cn(
        "group relative block w-full rounded-md border bg-card p-3 text-left transition-colors",
        "hover:bg-accent hover:border-primary/40 focus:outline-none focus:ring-2 focus:ring-primary/40",
        highlight ? "border-primary/60 ring-1 ring-primary/30" : "border-border",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-micro  text-muted-foreground">
            {profile.namespace}
          </p>
          <p className="truncate text-sm font-semibold">{profile.name}</p>
        </div>
        <ModePill mode={profile.mode} />
      </div>

      <dl className="mt-3 grid grid-cols-3 gap-2 text-micro">
        <Stat label="Procs" value={profile.learned_processes_count} />
        <Stat label="Alerts · retained 24h" value={profile.monitored_alerts_24h} tone={profile.monitored_alerts_24h > 0 ? "warning" : "muted"} />
        <Stat label="Blocks · retained 24h" value={profile.enforced_blocks_24h} tone={profile.enforced_blocks_24h > 0 ? "error" : "muted"} />
      </dl>

      <div className="mt-2 flex items-center gap-1.5 text-micro text-muted-foreground">
        <Clock3 className="h-3 w-3" aria-hidden />
        <span>Learn started {age}</span>
      </div>

      {/* hover-only top-5 processes */}
      {top.length > 0 && (
        <div className="mt-2 hidden flex-wrap gap-1 group-hover:flex" data-testid="baselines-card-hover-procs">
          {top.map((p, index) => (
            <span
              key={`${p}:${index}`}
              className="rounded bg-muted px-1.5 py-0.5 text-micro font-mono text-muted-foreground"
            >
              {p}
            </span>
          ))}
        </div>
      )}

      {highlight && (
        <span className="absolute right-2 top-2 inline-flex items-center gap-1 rounded-full bg-primary/15 px-1.5 py-0.5 text-micro font-semibold  text-primary">
          <Sparkles className="h-2.5 w-2.5" aria-hidden /> Ready
        </span>
      )}
    </a>
  );
}

function Stat({
  label, value, tone = "muted",
}: {
  label: string;
  value: number;
  tone?: "muted" | "warning" | "error";
}) {
  const valueColor =
    tone === "warning" ? "text-status-warning dark:text-status-warning" :
    tone === "error"   ? "text-status-error dark:text-status-error" :
    "text-foreground";
  return (
    <div>
      <dt className="truncate text-muted-foreground">{label}</dt>
      <dd className={cn("text-sm font-semibold tabular-nums", valueColor)}>{value}</dd>
    </div>
  );
}

// ----- helpers --------------------------------------------------------------

function qualifiesForAutoPromote(p: BaselineSummary): boolean {
  if (p.mode !== "learn") return false;
  if (!p.learn_started_at || !p.last_new_process_at || p.learned_processes_count === 0) return false;
  const learnAgeDays = (Date.now() - new Date(p.learn_started_at).getTime()) / (24 * 3600 * 1000);
  if (!Number.isFinite(learnAgeDays) || learnAgeDays < 14) return false;
  if (p.last_new_process_at) {
    const lastNewHours = (Date.now() - new Date(p.last_new_process_at).getTime()) / (3600 * 1000);
    if (!Number.isFinite(lastNewHours) || lastNewHours < 24) return false;
  }
  return true;
}

function ageSince(iso?: string | null): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const secs = Math.max(1, Math.floor((Date.now() - t) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
