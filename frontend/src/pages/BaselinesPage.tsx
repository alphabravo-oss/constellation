// BaselinesPage — Wave L4. Process Baseline lifecycle kanban (NeuVector parity).
//
// Three columns: Learn (gray) | Monitor (amber) | Enforce (green/red).
// Each card represents one workload's process baseline. Click → navigates to the
// dedicated detail page (runtime/baselines/:baselineId) with the full process
// table + audit timeline + promote/rollback actions (Astronomer detail-as-a-page).
//
// Cluster-scoped: every fetch threads cluster_id (derived from useCluster()).
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Activity, AlertTriangle, GitMerge, ShieldCheck, Sparkles, Clock3 } from "lucide-react";

import {
  baselines as baselinesApi,
  type BaselineSummary,
  type BaselineMode,
} from "@/api/client";
import { EntityHeader } from "@/components/EntityHeader";
import { useCluster } from "@/hooks/useCluster";
import { StatusPill, ModePill } from "@/components/ui/status-pill";
import { cn } from "@/lib/cn";

const COLUMNS: Array<{
  mode: BaselineMode;
  title: string;
  tagline: string;
  tone: "info" | "warning" | "success";
  icon: typeof Activity;
}> = [
  { mode: "learn",   title: "Learn",   tagline: "Observing processes — no alerts emitted.",  tone: "info",    icon: Activity },
  { mode: "monitor", title: "Monitor", tagline: "Baseline frozen — alerts on deviation.",     tone: "warning", icon: AlertTriangle },
  { mode: "enforce", title: "Enforce", tagline: "Block + alert on out-of-baseline exec.",     tone: "success", icon: ShieldCheck },
];

export function BaselinesPage() {
  const { clusterId, cluster, isLoading: clusterLoading } = useCluster();
  const navigate = useNavigate();
  const [autoPromote, setAutoPromote] = useState(false);

  const listQ = useQuery({
    queryKey: ["baselines", clusterId],
    queryFn: () => baselinesApi.list({ cluster_id: clusterId }),
    enabled: !!clusterId,
  });

  const profiles = listQ.data?.profiles ?? [];
  const summary = listQ.data?.summary;
  const byMode = useMemo(() => {
    const groups: Record<BaselineMode, BaselineSummary[]> = { learn: [], monitor: [], enforce: [] };
    profiles.forEach((p) => groups[p.mode].push(p));
    return groups;
  }, [profiles]);

  const autoPromoteCandidates = useMemo(
    () => profiles.filter((p) => p.mode === "learn" && qualifiesForAutoPromote(p)).map((p) => p.workload_id),
    [profiles],
  );

  if (clusterLoading) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="baselines-loading">
        Loading cluster…
      </p>
    );
  }

  const clusterName = cluster?.name ?? "—";

  return (
    <div className="space-y-5" data-testid="baselines-page" data-cluster-id={clusterId ?? ""}>
      <EntityHeader
        breadcrumbs={[
          { label: "Clusters", to: "/clusters" },
          { label: clusterName, to: clusterId ? `/clusters/${clusterId}/dashboard` : "/clusters" },
          { label: "Runtime", to: clusterId ? `/clusters/${clusterId}/runtime` : "/clusters" },
          { label: "Process Baselines" },
        ]}
        title={
          <span className="inline-flex items-center gap-2">
            <GitMerge className="h-5 w-5 text-primary" aria-hidden />
            Process Baselines · {clusterName}
          </span>
        }
        subtitle="Learn → Monitor → Enforce lifecycle per workload, mirroring NeuVector's process-profile model."
        stats={[
          { label: "Workloads", value: profiles.length },
          { label: "Learning",  value: summary?.learn   ?? 0, tone: "neutral" },
          { label: "Monitoring",value: summary?.monitor ?? 0, tone: "high" },
          { label: "Enforcing", value: summary?.enforce ?? 0, tone: "accent" },
        ]}
        actions={
          <label className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-1.5 text-xs">
            <input
              type="checkbox"
              className="h-3.5 w-3.5"
              checked={autoPromote}
              onChange={(e) => setAutoPromote(e.target.checked)}
              data-testid="baselines-auto-promote-toggle"
            />
            <Sparkles className="h-3.5 w-3.5 text-primary" aria-hidden />
            <span className="font-medium">Auto-promote hint</span>
            <span className="text-muted-foreground">
              {autoPromote ? `${autoPromoteCandidates.length} ready` : "off"}
            </span>
          </label>
        }
      />

      {autoPromote && (
        <p className="rounded-md border border-border bg-status-warning/5 px-3 py-2 text-xs text-muted-foreground">
          Auto-promote is a UI hint only. Workloads with a learn-start &gt; 14d ago AND no new process seen in 24h are
          highlighted below — promotion still requires a click on the workload card.
        </p>
      )}

      <section
        className="grid gap-4 lg:grid-cols-3"
        data-testid="baselines-columns"
      >
        {COLUMNS.map((col) => (
          <Column
            key={col.mode}
            mode={col.mode}
            title={col.title}
            tagline={col.tagline}
            tone={col.tone}
            Icon={col.icon}
            profiles={byMode[col.mode]}
            onSelect={(id) =>
              navigate(
                clusterId
                  ? `/clusters/${clusterId}/runtime/baselines/${encodeURIComponent(id)}`
                  : "/clusters",
              )
            }
            highlightIDs={autoPromote ? autoPromoteCandidates : []}
            loading={listQ.isPending}
          />
        ))}
      </section>
    </div>
  );
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
        <Stat label="Alerts 24h" value={profile.monitored_alerts_24h} tone={profile.monitored_alerts_24h > 0 ? "warning" : "muted"} />
        <Stat label="Blocks 24h" value={profile.enforced_blocks_24h} tone={profile.enforced_blocks_24h > 0 ? "error" : "muted"} />
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
  if (!p.learn_started_at) return false;
  const learnAgeDays = (Date.now() - new Date(p.learn_started_at).getTime()) / (24 * 3600 * 1000);
  if (learnAgeDays < 14) return false;
  if (p.last_new_process_at) {
    const lastNewHours = (Date.now() - new Date(p.last_new_process_at).getTime()) / (3600 * 1000);
    if (lastNewHours < 24) return false;
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
