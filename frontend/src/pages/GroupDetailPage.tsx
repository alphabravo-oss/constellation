// GroupDetailPage — NeuVector-parity group detail. NV users live in this view: it
// bundles the group's policy/profile mode, membership criteria, members, and links to
// the network rules that reference it — the single surface NV shows per group. Our
// Groups list previously only showed counts with no drill-in.
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, UsersRound } from "lucide-react";

import { groupsApi, type Group } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";

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

export function GroupDetailPage() {
  const { groupId } = useParams<{ groupId: string }>();
  const { clusterId } = useCluster();
  const q = useQuery({ queryKey: ["groups", clusterId], queryFn: () => groupsApi.list({ cluster_id: clusterId }) });
  const group: Group | undefined = q.data?.groups.find((g) => g.id === groupId);

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading group…</p>;
  if (!group) return <p className="text-sm text-status-error">Group not found.</p>;

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
        description={group.comment || "Service group — membership criteria, policy/profile mode, and associated network rules."}
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-md border border-border bg-card p-3 space-y-2">
          <ModeBadge mode={group.policy_mode} label="Network mode" />
          <ModeBadge mode={group.profile_mode} label="Process/file mode" />
        </div>
        <StatCard label="Members" value={group.members?.length ?? 0} icon={<UsersRound className="h-3.5 w-3.5" />} />
        <StatCard label="Criteria" value={group.criteria?.length ?? 0} />
        <div className="rounded-md border border-border bg-card p-3">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Network rules</div>
          <Link to={clusterId ? `/clusters/${clusterId}/network-rules` : "/network-rules"} className="mt-1 block text-sm text-[color:var(--color-primary)] hover:underline">View rules →</Link>
        </div>
      </section>

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
