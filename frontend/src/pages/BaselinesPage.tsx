import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Activity, AlertTriangle, ShieldCheck, Sparkles, Clock3 } from "lucide-react";
import { baselines as baselinesApi, type BaselineSummary, type BaselineMode } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { StatusPill, ModePill } from "@/components/ui/status-pill";
import { DataTable, type Column as TableColumn } from "@/components/ui/data-table";
import { StatGrid, StatCard } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { useRouteSearchParams } from "@/lib/route-search";
import { cn } from "@/lib/cn";
import { useBaselineScope, baselinePath, SOURCE_NOTE } from "./baselines/context";

const COLUMNS: Array<{ mode: BaselineMode; title: string; tagline: string; tone: "info" | "warning" | "success"; icon: typeof Activity }> = [
 { mode: "learn", title: "Learn", tagline: "Configured to learn observed processes.", tone: "info", icon: Activity },
 { mode: "monitor", title: "Monitor", tagline: "Configured to report baseline deviations.", tone: "warning", icon: AlertTriangle },
 { mode: "enforce", title: "Enforce", tagline: "Configured to block deviations; check agent evidence.", tone: "success", icon: ShieldCheck },
];
export function BaselinesPage() {
 const scope = useBaselineScope(); const { clusterId, scopeReady } = scope;
 const navigate = useNavigate(); const [highlight, setHighlight] = useState(false);
 const [tab, setTab] = useTabParam("tab", "inventory"); const [params, setParams] = useRouteSearchParams();
 const q = useQuery({ queryKey: ["baselines", clusterId], enabled: scopeReady, queryFn: () => baselinesApi.list({ cluster_id: clusterId }) });
 const valid = scopeReady && q.isSuccess && !q.isError && q.data?.profiles.every(p => p.cluster_id === clusterId && ["learn", "monitor", "enforce"].includes(p.mode));
 const profiles = valid ? q.data!.profiles : undefined;
 const search = params.get("q") ?? ""; const namespace = params.get("namespace") ?? "";
 const filtered = profiles?.filter(p => (!namespace || p.namespace === namespace) && (!search || `${p.namespace}/${p.name}`.toLowerCase().includes(search.toLowerCase()))) ?? [];
 const update = (key: string, value: string) => setParams(current => { if (value) current.set(key, value); else current.delete(key); return current; }, { replace: key === "q" });
 const columns: TableColumn<BaselineSummary>[] = [
  { id: "workload", header: "Workload", kind: "name", wrap: true, sort: (a,b) => a.workload_id.localeCompare(b.workload_id), cell: p => <a href={baselinePath(clusterId!,p.workload_id)} className="text-primary hover:underline">{p.workload_id}</a>, exportValue: p => p.workload_id },
  { id: "mode", header: "Mode", kind: "status", cell: p => <ModePill mode={p.mode} />, exportValue: p => p.mode },
  { id: "processes", header: "Processes", kind: "count", cell: p => p.learned_processes_count, exportValue: p => p.learned_processes_count },
  { id: "alerts", header: "Alerts (24h)", kind: "count", cell: p => p.monitored_alerts_24h, exportValue: p => p.monitored_alerts_24h },
  { id: "blocks", header: "Blocks (24h)", kind: "count", cell: p => p.enforced_blocks_24h, exportValue: p => p.enforced_blocks_24h },
  { id: "last", header: "Last new process", kind: "date", cell: p => p.last_new_process_at ? new Date(p.last_new_process_at).toLocaleString() : "Not reported", exportValue: p => p.last_new_process_at ?? "" },
 ];
 const retry = () => scopeReady ? void q.refetch() : scope.retryScope();
 return <div className="space-y-5" data-testid="baselines-page" data-cluster-id={clusterId ?? ""}>
  <PageHeader title="Process Baselines" description="Review configured process profiles and observed execution evidence for this cluster." actions={<Button disabled={!scopeReady || q.isFetching} onClick={retry}>Refresh</Button>} />
  <VerdictBanner status={profiles ? "info" : "degraded"} title={profiles ? `${profiles.length} workload profiles reported` : "Process profile evidence unavailable"} detail={profiles ? "Profiles describe configured behavior. Agent activity and protection must be verified separately." : "Resolve this cluster and load its profiles before assessing configured coverage."} />
  <StatGrid><StatCard label="Workloads" value={profiles?.length ?? "—"} />{COLUMNS.map(c => <StatCard key={c.mode} label={c.title} value={profiles ? profiles.filter(p => p.mode === c.mode).length : "—"} />)}</StatGrid>
  {!scopeReady ? scope.error ? <ErrorState title="Could not resolve this cluster." action={<Button onClick={retry}>Retry</Button>} /> : <LoadingState label="Resolving cluster…" /> : q.isPending ? <LoadingState label="Loading profiles…" /> : q.isError ? <ErrorState title="Could not load or refresh process profiles." error={q.error} action={<Button onClick={retry}>Retry</Button>} /> : !profiles ? <ErrorState title="Returned profile scope does not match this cluster." action={<Button onClick={retry}>Retry</Button>} /> : <>
   {q.isFetching && <p role="status" className="text-sm text-muted-foreground">Refreshing profiles…</p>}
   <div className="flex flex-wrap gap-3"><label className="text-sm">Search workloads<input aria-label="Search workloads" value={search} onChange={e => update("q",e.target.value)} className="ml-2 rounded border border-border bg-background px-3 py-2" /></label><label className="text-sm">Namespace<select aria-label="Namespace" value={namespace} onChange={e => update("namespace",e.target.value)} className="ml-2 rounded border border-border bg-background px-3 py-2"><option value="">All namespaces</option>{Array.from(new Set(profiles.map(p => p.namespace))).sort().map(ns => <option key={ns}>{ns}</option>)}{namespace && !profiles.some(p => p.namespace === namespace) && <option>{namespace}</option>}</select></label></div>
   <p className="text-xs text-muted-foreground">{SOURCE_NOTE}</p>
   <Tabs value={["inventory","lifecycle"].includes(tab) ? tab : "inventory"} onValueChange={setTab} items={[
    { value: "inventory", label: "Inventory", content: <DataTable rows={filtered} columns={columns} rowKey={p => `${p.cluster_id}/${p.workload_id}`} rowTestId={p => `baselines-card-${p.workload_id}`} testId="baselines-table" preferencesKey="process-baselines" exportFileName="process-baselines.csv" exportLabel="Export matching profiles" emptyState={<p>No profiles match these filters.</p>} /> },
    { value: "lifecycle", label: "Lifecycle", content: <div className="space-y-4"><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={highlight} onChange={e => setHighlight(e.target.checked)} /> Highlight learning profiles observed for at least 14 days with no new process in the last 24 hours</label><p className="text-xs text-muted-foreground">A review hint based on retained observations. Nothing is promoted automatically.</p><section className="grid gap-4 lg:grid-cols-3" data-testid="baselines-columns">{COLUMNS.map(c => <Column key={c.mode} {...c} Icon={c.icon} profiles={filtered.filter(p => p.mode === c.mode)} highlightIDs={highlight ? filtered.filter(qualifiesForAutoPromote).map(p => p.workload_id) : []} loading={false} onSelect={id => void navigate({ href: baselinePath(clusterId!,id) })} />)}</section></div> },
   ]} /><Collapse label="Advanced: source coverage"><p className="text-sm text-muted-foreground">{SOURCE_NOTE} Inventory, authored rules, and transitions have no response cap. Lifecycle cards preview up to five process names.</p></Collapse>
  </>}
 </div>;
}
// ----- Column ---------------------------------------------------------------

function Column({
  mode, title, tagline, tone, Icon, profiles, onSelect, highlightIDs, loading,
}: {
  mode: BaselineMode;
  title: string;
  tagline: string;
  tone: "info" | "warning" | "success";
  Icon: typeof Activity;
  profiles: BaselineSummary[];
  onSelect: (id: string) => void;
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
          <p className="mt-0.5 text-[11px] text-muted-foreground">{tagline}</p>
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
            No workloads in {title.toLowerCase()} mode.
          </p>
        )}
        {profiles.map((p) => (
          <ProfileCard
            key={p.workload_id}
            profile={p}
            highlight={highlightIDs.includes(p.workload_id)}
            onClick={() => onSelect(p.workload_id)}
          />
        ))}
      </div>
    </div>
  );
}

// ----- Card -----------------------------------------------------------------

function ProfileCard({
  profile, onClick, highlight,
}: {
  profile: BaselineSummary;
  onClick: () => void;
  highlight: boolean;
}) {
  const top = profile.top_processes ?? [];
  const age = ageSince(profile.learn_started_at);
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={`baselines-card-${profile.workload_id}`}
      className={cn(
        "group relative w-full rounded-md border bg-card p-3 text-left transition-colors",
        "hover:bg-accent hover:border-primary/40 focus:outline-none focus:ring-2 focus:ring-primary/40",
        highlight ? "border-primary/60 ring-1 ring-primary/30" : "border-border",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-[11px] uppercase tracking-wider text-muted-foreground">
            {profile.namespace}
          </p>
          <p className="truncate text-sm font-semibold">{profile.name}</p>
        </div>
        <ModePill mode={profile.mode} />
      </div>

      <dl className="mt-3 grid grid-cols-3 gap-2 text-[11px]">
        <Stat label="Procs" value={profile.learned_processes_count} />
        <Stat label="Alerts · retained 24h" value={profile.monitored_alerts_24h} tone={profile.monitored_alerts_24h > 0 ? "warning" : "muted"} />
        <Stat label="Blocks · retained 24h" value={profile.enforced_blocks_24h} tone={profile.enforced_blocks_24h > 0 ? "error" : "muted"} />
      </dl>

      <div className="mt-2 flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <Clock3 className="h-3 w-3" aria-hidden />
        <span>Learn started {age}</span>
      </div>

      {/* hover-only top-5 processes */}
      {top.length > 0 && (
        <div className="mt-2 hidden flex-wrap gap-1 group-hover:flex" data-testid="baselines-card-hover-procs">
          {top.map((p) => (
            <span
              key={p}
              className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground"
            >
              {p}
            </span>
          ))}
        </div>
      )}

      {highlight && (
        <span className="absolute right-2 top-2 inline-flex items-center gap-1 rounded-full bg-primary/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-primary">
          <Sparkles className="h-2.5 w-2.5" aria-hidden /> Ready
        </span>
      )}
    </button>
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
