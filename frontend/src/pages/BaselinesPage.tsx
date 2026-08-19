// BaselinesPage — Wave L4. Process Baseline lifecycle kanban (NeuVector parity).
//
// Three columns: Learn (gray) | Monitor (amber) | Enforce (green/red).
// Each card represents one workload's process baseline. Click → Drawer with the
// full process table + audit timeline + promote/rollback footer buttons.
//
// Cluster-scoped: every fetch threads cluster_id (derived from useCluster()).
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, GitMerge, ShieldCheck, Sparkles, Clock3, ArrowRight, ArrowLeft } from "lucide-react";

import {
  baselines as baselinesApi,
  type BaselineSummary,
  type BaselineMode,
  type BaselineDetail,
} from "@/api/client";
import { EntityHeader } from "@/components/EntityHeader";
import { useCluster } from "@/hooks/useCluster";
import { Drawer } from "@/components/ui/drawer";
import { Button } from "@/components/ui/button";
import { StatusPill, ModePill } from "@/components/ui/status-pill";
import { DataTable, type Column } from "@/components/ui/data-table";
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
  const [selectedWorkload, setSelectedWorkload] = useState<string | null>(null);
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
            onSelect={(id) => setSelectedWorkload(id)}
            highlightIDs={autoPromote ? autoPromoteCandidates : []}
            loading={listQ.isPending}
          />
        ))}
      </section>

      <Drawer
        open={!!selectedWorkload}
        onOpenChange={(o) => {
          if (!o) setSelectedWorkload(null);
        }}
        width="xl"
        title={selectedWorkload ?? ""}
        description="Process baseline — learned exec list and lifecycle audit trail."
      >
        {selectedWorkload && (
          <BaselineDrawerBody
            workloadID={selectedWorkload}
            clusterID={clusterId}
            onClose={() => setSelectedWorkload(null)}
          />
        )}
      </Drawer>
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

// ----- Drawer body ----------------------------------------------------------

function BaselineDrawerBody({
  workloadID, clusterID, onClose,
}: {
  workloadID: string;
  clusterID: string | undefined;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const detailQ = useQuery({
    queryKey: ["baseline", workloadID, clusterID],
    queryFn: () => baselinesApi.get(workloadID, { cluster_id: clusterID }),
  });
  const setMode = useMutation({
    mutationFn: (mode: BaselineMode) => baselinesApi.setMode(workloadID, { mode }, { cluster_id: clusterID }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["baseline", workloadID, clusterID] });
      queryClient.invalidateQueries({ queryKey: ["baselines", clusterID] });
    },
  });

  if (detailQ.isPending) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }
  if (detailQ.isError || !detailQ.data) {
    return <p className="text-sm text-status-error">Failed to load profile.</p>;
  }
  const profile = detailQ.data;
  const canPromote = nextPromoteMode(profile.mode);
  const canRollback = nextRollbackMode(profile.mode);

  const processColumns: Column<BaselineDetail["processes"][number]>[] = [
    { id: "name", header: "Process", cell: (p) => <span className="font-mono">{p.name}</span> },
    {
      id: "path",
      header: "Path",
      className: "max-w-0 truncate text-muted-foreground",
      cell: (p) => (
        <span title={`${p.path} ${p.args.join(" ")}`}>
          {p.path} <span className="text-muted-foreground/60">{p.args.join(" ")}</span>
        </span>
      ),
    },
    { id: "seen", header: "Seen", numeric: true, cell: (p) => <span className="tabular-nums">{p.observed_count}</span> },
    { id: "last_seen", header: "Last seen", cell: (p) => <span className="text-muted-foreground">{ageSince(p.last_seen)}</span> },
  ];

  return (
    <div className="space-y-5" data-testid="baselines-drawer-body">
      <section className="grid grid-cols-4 gap-3 rounded-md border border-border bg-muted/30 p-3 text-xs">
        <DrawerStat label="Mode" value={<ModePill mode={profile.mode} />} />
        <DrawerStat label="Processes" value={String(profile.learned_processes_count)} />
        <DrawerStat label="Alerts 24h" value={String(profile.monitored_alerts_24h)} />
        <DrawerStat label="Blocks 24h" value={String(profile.enforced_blocks_24h)} />
      </section>

      <section>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Learned processes
        </h3>
        <div data-testid="baselines-drawer-process-table">
          <DataTable
            rows={profile.processes}
            columns={processColumns}
            rowKey={(p) => `${p.name}-${p.path}`}
            emptyState={<div className="px-2 py-4 text-center text-xs text-muted-foreground">No processes observed yet.</div>}
          />
        </div>
      </section>

      <section>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Mode transitions
        </h3>
        <ol className="space-y-2" data-testid="baselines-drawer-timeline">
          {profile.transitions.map((t, i) => (
            <li key={i} className="flex gap-3 rounded-md border border-border bg-card px-2.5 py-2 text-xs">
              <div className="mt-0.5 flex-shrink-0">
                <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-primary/15 text-primary">
                  <ArrowRight className="h-3 w-3" aria-hidden />
                </span>
              </div>
              <div className="min-w-0 flex-1">
                <p className="font-medium">
                  {t.from ? `${t.from} → ${t.to}` : `Started in ${t.to}`}
                </p>
                <p className="text-muted-foreground">{t.reason}</p>
                <p className="mt-0.5 text-[10px] text-muted-foreground">
                  {ageSince(t.at)} · actor <span className="font-mono">{t.actor}</span>
                </p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <DrawerFooter
        profile={profile}
        canPromote={canPromote}
        canRollback={canRollback}
        pending={setMode.isPending}
        onPromote={() => canPromote && setMode.mutate(canPromote)}
        onRollback={() => canRollback && setMode.mutate(canRollback)}
        onClose={onClose}
      />
    </div>
  );
}

function DrawerStat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <div className="mt-1 text-sm font-semibold">{value}</div>
    </div>
  );
}

function DrawerFooter({
  profile, canPromote, canRollback, pending, onPromote, onRollback, onClose,
}: {
  profile: BaselineDetail;
  canPromote: BaselineMode | null;
  canRollback: BaselineMode | null;
  pending: boolean;
  onPromote: () => void;
  onRollback: () => void;
  onClose: () => void;
}) {
  return (
    <div className="sticky bottom-0 -mx-5 -mb-4 mt-4 flex items-center justify-between gap-2 border-t border-border bg-card/95 px-5 py-3 backdrop-blur">
      <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={!canRollback || pending}
          onClick={onRollback}
          data-testid="baselines-drawer-rollback"
        >
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
          {canRollback ? `Roll back to ${canRollback}` : "Roll back"}
        </Button>
        <Button
          variant="primary"
          size="sm"
          disabled={!canPromote || pending}
          onClick={onPromote}
          data-testid="baselines-drawer-promote"
        >
          {canPromote === "monitor" && "Promote to Monitor"}
          {canPromote === "enforce" && "Promote to Enforce"}
          {!canPromote && (profile.mode === "enforce" ? "Already enforcing" : "Promote")}
          {canPromote && <ArrowRight className="h-3.5 w-3.5" aria-hidden />}
        </Button>
      </div>
    </div>
  );
}

// ----- helpers --------------------------------------------------------------

function nextPromoteMode(mode: BaselineMode): BaselineMode | null {
  if (mode === "learn") return "monitor";
  if (mode === "monitor") return "enforce";
  return null;
}

function nextRollbackMode(mode: BaselineMode): BaselineMode | null {
  if (mode === "monitor") return "learn";
  if (mode === "enforce") return "monitor";
  return null;
}

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
