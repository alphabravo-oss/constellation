// GroupDetailPage — NeuVector-parity group detail. NV users live in this view: it
// bundles the group's policy/profile mode, membership criteria, members, and links to
// the network rules that reference it — the single surface NV shows per group. Our
// Groups list previously only showed counts with no drill-in.
import { Link, useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, ArrowUp, ChevronLeft, FileText, Network, ShieldCheck, UsersRound } from "lucide-react";
import { toast } from "sonner";

import { groupsApi, type Group, type GroupUsage, type GroupUsageReference } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { fmtRelative } from "@/lib/format";

function ModeBadge({ mode, label }: { mode?: string; label: string }) {
  const m = (mode || "discover").toLowerCase();
  const color = m === "protect" || m === "enforce" ? "var(--color-severity-low)" : m === "monitor" || m === "evaluate" ? "var(--color-severity-medium)" : "var(--color-severity-high)";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span className="rounded px-1.5 py-0.5 text-[11px] font-medium capitalize" style={{ background: `color-mix(in oklab, ${color} 16%, transparent)`, color }}>{m}</span>
    </span>
  );
}

const NEXT_MODE: Record<string, string> = { discover: "monitor", monitor: "protect" };

export function GroupDetailPage() {
  const { groupId } = useParams<{ groupId: string }>();
  const { clusterId } = useCluster();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["groups", clusterId], queryFn: () => groupsApi.list({ cluster_id: clusterId }) });
  const group: Group | undefined = q.data?.groups.find((g) => g.id === groupId);
  const usageQ = useQuery({
    queryKey: ["group-usage", clusterId, groupId],
    queryFn: () => groupsApi.usage(groupId!, { cluster_id: clusterId }),
    enabled: Boolean(groupId),
  });

  const promote = useMutation({
    mutationFn: (dim: "policy_mode" | "profile_mode") => {
      const next = NEXT_MODE[(group![dim] as string) ?? "discover"] as Group["policy_mode"];
      return groupsApi.update(group!.id, {
        name: group!.name, kind: group!.kind, comment: group!.comment, criteria: group!.criteria,
        members: group!.members, learned_from: group!.learned_from, cfg_type: group!.cfg_type,
        policy_mode: dim === "policy_mode" ? next : group!.policy_mode,
        profile_mode: dim === "profile_mode" ? next : group!.profile_mode,
      });
    },
    onSuccess: (_r, dim) => { toast.success(`Promoted ${dim === "policy_mode" ? "network" : "process"} mode`); void qc.invalidateQueries({ queryKey: ["groups", clusterId] }); },
    onError: () => toast.error("Failed to promote"),
  });

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading group…</p>;
  if (!group) return <p className="text-sm text-status-error">Group not found.</p>;
  const g = group;
  const nextOf = (m?: string) => NEXT_MODE[m ?? "discover"];
  const membership = group.membership ?? {
    criteria_count: group.criteria?.length ?? 0,
    member_count: group.members?.length ?? 0,
    policy_mode: group.policy_mode,
    profile_mode: group.profile_mode,
    last_matched_at: undefined,
    last_matched_member: undefined,
  };

  return (
    <div className="space-y-4">
      <PageHeader
        backLink={<Link to={clusterId ? `/clusters/${clusterId}/groups` : "/groups"} className="inline-flex items-center gap-1 hover:text-foreground"><ChevronLeft className="h-3.5 w-3.5" />Groups</Link>}
        title={group.name}
        mono
        badges={
          <>
            <span className="rounded bg-muted px-2 py-0.5 text-[11px] capitalize">{group.kind}</span>
            <span className="rounded bg-muted px-2 py-0.5 text-[11px]">{group.cfg_type || (group.learned_from ? "learned" : "user-created")}</span>
          </>
        }
        description={group.comment || "Service group — membership criteria, policy/profile mode, and associated policy/profile usage."}
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-md border border-border bg-card p-3 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <ModeBadge mode={g.policy_mode} label="Network mode" />
            {nextOf(g.policy_mode) && g.cfg_type !== "learned" && (
              <button type="button" disabled={promote.isPending} onClick={() => promote.mutate("policy_mode")}
                className="inline-flex items-center gap-0.5 rounded border border-border px-1.5 py-0.5 text-[10px] hover:bg-accent disabled:opacity-40">
                <ArrowUp className="h-3 w-3" />{nextOf(g.policy_mode)}
              </button>
            )}
          </div>
          <div className="flex items-center justify-between gap-2">
            <ModeBadge mode={g.profile_mode} label="Process/file mode" />
            {nextOf(g.profile_mode) && g.cfg_type !== "learned" && (
              <button type="button" disabled={promote.isPending} onClick={() => promote.mutate("profile_mode")}
                className="inline-flex items-center gap-0.5 rounded border border-border px-1.5 py-0.5 text-[10px] hover:bg-accent disabled:opacity-40">
                <ArrowUp className="h-3 w-3" />{nextOf(g.profile_mode)}
              </button>
            )}
          </div>
        </div>
        <StatCard label="Members" value={group.members?.length ?? 0} icon={<UsersRound className="h-3.5 w-3.5" />} />
        <StatCard label="Criteria" value={group.criteria?.length ?? 0} />
        <div className="rounded-md border border-border bg-card p-3">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Network rules</div>
          <Link to={clusterId ? `/clusters/${clusterId}/network-rules` : "/network-rules"} className="mt-1 block text-sm text-[color:var(--color-primary)] hover:underline">View rules →</Link>
        </div>
      </section>

      <section className="overflow-hidden rounded-lg border border-border bg-card" data-testid="group-membership-preview">
        <header className="border-b border-border px-3 py-2">
          <h2 className="text-sm font-semibold">Membership preview</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">Current selector result and freshest matching workload evidence.</p>
        </header>
        <div className="grid gap-2 p-3 md:grid-cols-4">
          <PreviewMetric label="Criteria" value={membership.criteria_count} />
          <PreviewMetric label="Members" value={membership.member_count} />
          <div className="rounded-md border border-border bg-background px-3 py-2">
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Modes</div>
            <div className="mt-2 flex flex-wrap gap-2">
              <ModeBadge mode={membership.policy_mode} label="Network" />
              <ModeBadge mode={membership.profile_mode} label="Profile" />
            </div>
          </div>
          <div className="rounded-md border border-border bg-background px-3 py-2">
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Last matched</div>
            <div className="mt-1 text-sm font-medium text-foreground">{fmtRelative(membership.last_matched_at)}</div>
            <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground" title={membership.last_matched_member || undefined}>
              {membership.last_matched_member || "No current deployment evidence"}
            </div>
          </div>
        </div>
      </section>

      <GroupUsagePanel usage={usageQ.data} isLoading={usageQ.isPending} isError={usageQ.isError} />

      <section className="overflow-hidden rounded-lg border border-border bg-card">
        <header className="border-b border-border px-3 py-2"><h2 className="text-sm font-semibold">Membership criteria</h2><p className="mt-0.5 text-xs text-muted-foreground">Selectors that determine which workloads belong to this group.</p></header>
        {(group.criteria?.length ?? 0) === 0 ? (
          <EmptyState title="No criteria" hint="This group has no membership selectors." />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted text-xs uppercase text-muted-foreground"><tr><th className="px-3 py-2 text-left">Key</th><th className="px-3 py-2 text-left">Operator</th><th className="px-3 py-2 text-left">Value</th></tr></thead>
            <tbody>
              {group.criteria.map((c, i) => (
                <tr key={i} className="border-t border-border">
                  <td className="px-3 py-2 font-mono text-xs">{c.key}</td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">{c.op}</td>
                  <td className="px-3 py-2 font-mono text-xs">{c.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="overflow-hidden rounded-lg border border-border bg-card">
        <header className="border-b border-border px-3 py-2"><h2 className="text-sm font-semibold">Members</h2><p className="mt-0.5 text-xs text-muted-foreground">{group.members?.length ?? 0} workload{(group.members?.length ?? 0) === 1 ? "" : "s"} currently matching.</p></header>
        {(group.members?.length ?? 0) === 0 ? (
          <EmptyState title="No members" hint="No workloads currently match this group's criteria." />
        ) : (
          <ul className="divide-y divide-border">
            {group.members.map((m) => (
              <li key={m}>
                <Link to={clusterId ? `/clusters/${clusterId}/deployments?q=${encodeURIComponent(m.split("/").pop() ?? m)}` : "#"} className="block px-3 py-2 text-mono text-xs hover:bg-muted/40">{m}</Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function PreviewMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-background px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold tabular-nums text-foreground">{value}</div>
    </div>
  );
}

function GroupUsagePanel({ usage, isLoading, isError }: { usage?: GroupUsage; isLoading: boolean; isError: boolean }) {
  const refs = usage?.references ?? [];
  const summary = usage?.summary;
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card" data-testid="group-usage-panel">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">Policy usage</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">Concrete references that depend on this group, plus modeled coverage.</p>
        </div>
        {summary?.delete_blocked ? (
          <span className="inline-flex items-center gap-1.5 rounded border border-status-warning/30 bg-status-warning/10 px-2 py-1 text-xs text-status-warning">
            <AlertTriangle className="h-3.5 w-3.5" />
            Delete blocked by {summary.blocking_references} reference{summary.blocking_references === 1 ? "" : "s"}
          </span>
        ) : summary ? (
          <span className="inline-flex items-center gap-1.5 rounded border border-status-success/30 bg-status-success/10 px-2 py-1 text-xs text-status-success">
            <ShieldCheck className="h-3.5 w-3.5" />
            No blocking references
          </span>
        ) : null}
      </header>

      {isLoading ? (
        <p className="px-3 py-4 text-sm text-muted-foreground">Loading usage...</p>
      ) : isError ? (
        <p className="px-3 py-4 text-sm text-status-error">Usage could not be loaded.</p>
      ) : !usage ? (
        <p className="px-3 py-4 text-sm text-muted-foreground">No usage data available.</p>
      ) : (
        <div className="space-y-4 p-3">
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-8">
            <UsageMetric label="References" value={summary?.total_references ?? 0} />
            <UsageMetric label="Blocking refs" value={summary?.blocking_references ?? 0} />
            <UsageMetric label="Network rules" value={summary?.network_rules ?? 0} />
            <UsageMetric label="DLP/WAF bindings" value={summary?.dpi_sensor_bindings ?? 0} />
            <UsageMetric label="Response rules" value={summary?.response_rules ?? 0} />
            <UsageMetric label="Admission rules" value={summary?.admission_rules ?? 0} />
            <UsageMetric label="Process profiles" value={summary?.process_profiles ?? 0} />
            <UsageMetric label="File profiles" value={summary?.file_profiles ?? 0} />
          </div>

          {refs.length === 0 ? (
            <EmptyState title="No concrete references" hint="No group-rule edges, admission/response rules, DLP/WAF bindings, or member profile artifacts currently reference this group." />
          ) : (
            <div className="divide-y divide-border rounded-md border border-border" data-testid="group-usage-references">
              {refs.map((ref) => <UsageReferenceRow key={`${ref.family}:${ref.id}`} refItem={ref} />)}
            </div>
          )}

          <div className="grid gap-2 md:grid-cols-2" data-testid="group-usage-coverage">
            {usage.coverage.map((item) => (
              <div key={item.family} className="rounded-md border border-border bg-background px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-foreground">{item.family}</span>
                  <span className={`rounded px-1.5 py-0.5 text-[10px] uppercase ${coverageClass(item.status)}`}>{item.status.replace("_", " ")}</span>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{item.detail}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function UsageMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-background px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold tabular-nums text-foreground">{value}</div>
    </div>
  );
}

function UsageReferenceRow({ refItem }: { refItem: GroupUsageReference }) {
  const icon =
    refItem.family === "network" ? <Network className="h-3.5 w-3.5" /> :
    refItem.family === "process" ? <Activity className="h-3.5 w-3.5" /> :
    refItem.family === "file" ? <FileText className="h-3.5 w-3.5" /> :
    <ShieldCheck className="h-3.5 w-3.5" />;
  const body = (
    <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 hover:bg-muted/40">
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-sm font-medium text-foreground">
          <span className="text-muted-foreground">{icon}</span>
          <span className="truncate">{refItem.name}</span>
        </div>
        <div className="mt-0.5 flex flex-wrap gap-2 text-[11px] text-muted-foreground">
          <span>{refItem.kind}</span>
          {refItem.role ? <span>role {refItem.role}</span> : null}
          {refItem.mode ? <span>mode {refItem.mode}</span> : null}
          {refItem.detail ? <span>{refItem.detail}</span> : null}
        </div>
      </div>
      {refItem.blocking ? (
        <span className="rounded bg-status-warning/10 px-1.5 py-0.5 text-[10px] text-status-warning">blocking</span>
      ) : (
        <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">derived</span>
      )}
    </div>
  );
  if (refItem.route) {
    return <Link to={refItem.route}>{body}</Link>;
  }
  return body;
}

function coverageClass(status: string) {
  if (status === "covered") return "bg-status-success/10 text-status-success";
  if (status === "derived") return "bg-status-warning/10 text-status-warning";
  return "bg-muted text-muted-foreground";
}
