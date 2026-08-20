// NetworkRulesPage — NeuVector-parity Network Rules table. Presents the cluster's
// observed connectivity as an ordered allow/deny rule list (ID, From, To, Applications,
// Ports, Action, Learned, Enabled, Match count) so NeuVector users see their network
// policy in exactly the shape they expect. Rules are learned from flow rollups (as NV
// learns from observed conversations); edit/deny/reorder CRUD is the next step.
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Network as NetworkIcon, Check, Ban, Plus, Power, PowerOff, Trash2, Pencil, ArrowUpToLine } from "lucide-react";

import { networkRules, type NetworkRule } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { downloadCsv } from "@/lib/csv";
import { fmtRelative } from "@/lib/format";

function endpointLabel(w: string): string {
  if (w === "external" || w.startsWith("external")) return "external";
  return w;
}

export function NetworkRulesPage() {
  const { clusterId } = useCluster();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const q = useQuery({
    queryKey: ["network-rules", clusterId],
    queryFn: () => networkRules.list(clusterId!),
    enabled: !!clusterId,
  });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["network-rules", clusterId] });
  const upsert = useMutation({
    mutationFn: (r: NetworkRule & { _action?: "allow" | "deny"; _disable?: boolean }) =>
      networkRules.upsert(clusterId!, {
        from: r.from, to: r.to, ports: r.ports, applications: r.applications,
        action: r._action ?? r.action, disable: r._disable ?? r.disable,
        comment: r.comment, priority: r.priority,
      }),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (r: NetworkRule) => networkRules.remove(clusterId!, r.from, r.to),
    onSuccess: invalidate,
  });
  const moveTop = useMutation({
    mutationFn: (r: NetworkRule) => networkRules.moveTop(clusterId!, r.from, r.to),
    onSuccess: invalidate,
  });
  const editHref = (r: NetworkRule) =>
    `${clusterId ? `/clusters/${clusterId}` : ""}/network-rules/new?from=${encodeURIComponent(r.from)}&to=${encodeURIComponent(r.to)}&ports=${encodeURIComponent(r.ports)}&applications=${encodeURIComponent(r.applications.join(", "))}&action=${r.action}&comment=${encodeURIComponent(r.comment)}`;
  const all = q.data?.rules ?? [];
  const summary = q.data?.summary ?? { total: 0, allow: 0, deny: 0, learned: 0 };
  const rows = useMemo(() => {
    const n = search.trim().toLowerCase();
    if (!n) return all;
    return all.filter((r) => [r.from, r.to, r.ports, r.applications.join(",")].some((v) => v.toLowerCase().includes(n)));
  }, [all, search]);

  const columns: Column<NetworkRule>[] = [
    { id: "id", header: "ID", width: "72px", numeric: true, cell: (r) => <span className="text-mono text-[11px] text-muted-foreground">{r.id}</span>, sort: (a, b) => a.priority - b.priority },
    { id: "from", header: "From", cell: (r) => <span className="text-mono text-xs">{endpointLabel(r.from)}</span>, sort: (a, b) => a.from.localeCompare(b.from) },
    { id: "to", header: "To", cell: (r) => <span className="text-mono text-xs">{endpointLabel(r.to)}</span>, sort: (a, b) => a.to.localeCompare(b.to) },
    { id: "apps", header: "Applications", cell: (r) => (
        r.applications.length === 0 ? <span className="text-xs text-muted-foreground">any</span>
          : <span className="flex flex-wrap gap-1">{r.applications.slice(0, 5).map((a) => <span key={a} className="rounded bg-muted px-1.5 py-px text-[10px] font-medium uppercase text-muted-foreground">{a}</span>)}</span>
      ) },
    { id: "ports", header: "Ports", width: "120px", cell: (r) => <span className="text-mono text-[11px] text-muted-foreground">{r.ports}</span> },
    { id: "action", header: "Action", width: "92px", cell: (r) => (
        r.action === "deny"
          ? <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: "color-mix(in oklab, var(--color-severity-critical) 16%, transparent)", color: "var(--color-severity-critical)" }}><Ban className="h-3 w-3" />deny</span>
          : <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: "color-mix(in oklab, var(--color-severity-low) 16%, transparent)", color: "var(--color-severity-low)" }}><Check className="h-3 w-3" />allow</span>
      ), sort: (a, b) => a.action.localeCompare(b.action) },
    { id: "learned", header: "Type", width: "88px", cell: (r) => <span className="rounded bg-muted px-1.5 py-px text-[10px] text-muted-foreground">{r.learned ? "learned" : r.cfg_type}</span> },
    { id: "matches", header: "Matches", numeric: true, width: "96px", cell: (r) => <span className="text-mono text-xs">{r.match_counter.toLocaleString()}</span>, sort: (a, b) => a.match_counter - b.match_counter },
    { id: "last", header: "Last match", numeric: true, width: "110px", cell: (r) => <span className="text-[10px] text-muted-foreground">{r.last_match_timestamp ? fmtRelative(new Date(r.last_match_timestamp * 1000).toISOString()) : "—"}</span>, sort: (a, b) => a.last_match_timestamp - b.last_match_timestamp },
    { id: "actions", header: "", width: "160px", cell: (r) => {
        const busy = upsert.isPending || remove.isPending || moveTop.isPending;
        const overridden = r.cfg_type !== "learned"; // has a persisted override / manual rule
        const isTop = rows.length > 0 && r.id === rows[0].id;
        return (
          <div className="flex items-center justify-end gap-1">
            <button type="button" title={isTop ? "Already highest precedence" : "Move to top (evaluate first)"} disabled={busy || isTop}
              onClick={() => moveTop.mutate(r)}
              className="rounded p-1 hover:bg-accent disabled:opacity-40">
              <ArrowUpToLine className="h-3.5 w-3.5" />
            </button>
            <button type="button" title={r.action === "deny" ? "Set to allow" : "Set to deny"} disabled={busy}
              onClick={() => upsert.mutate({ ...r, _action: r.action === "deny" ? "allow" : "deny" })}
              className="rounded p-1 hover:bg-accent disabled:opacity-40">
              {r.action === "deny" ? <Check className="h-3.5 w-3.5" /> : <Ban className="h-3.5 w-3.5" />}
            </button>
            <button type="button" title={r.disable ? "Enable rule" : "Disable rule"} disabled={busy}
              onClick={() => upsert.mutate({ ...r, _disable: !r.disable })}
              className="rounded p-1 hover:bg-accent disabled:opacity-40">
              {r.disable ? <Power className="h-3.5 w-3.5" /> : <PowerOff className="h-3.5 w-3.5" />}
            </button>
            <Link to={editHref(r)} title="Edit" className="rounded p-1 hover:bg-accent"><Pencil className="h-3.5 w-3.5" /></Link>
            {overridden && (
              <button type="button" title={r.learned ? "Revert to learned" : "Delete rule"} disabled={busy}
                onClick={() => remove.mutate(r)}
                className="rounded p-1 text-status-error hover:bg-accent disabled:opacity-40">
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        );
      } },
  ];

  return (
    <div className="space-y-4" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Network Rules"
        description="The cluster's connectivity as an ordered allow/deny rule set, learned from observed conversations — NeuVector-style network policy."
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => downloadCsv("constellation-network-rules", ["ID", "From", "To", "Applications", "Ports", "Action", "Type", "Matches"],
                rows.map((r) => [r.id, r.from, r.to, r.applications.join(" "), r.ports, r.action, r.learned ? "learned" : r.cfg_type, r.match_counter]))}
              className="rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent"
            >Export CSV</button>
            <button
              type="button"
              onClick={() => navigate(`${clusterId ? `/clusters/${clusterId}` : ""}/network-rules/new`)}
              className="inline-flex items-center gap-1.5 rounded-md bg-[color:var(--color-primary)] px-3 py-2 text-sm font-medium text-white hover:opacity-90"
            ><Plus className="h-4 w-4" />Add rule</button>
          </div>
        }
      />
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Rules" value={summary.total} icon={<NetworkIcon className="h-3.5 w-3.5" />} />
        <StatCard label="Allow" value={summary.allow} tone="low" />
        <StatCard label="Deny" value={summary.deny} tone={summary.deny > 0 ? "critical" : "neutral"} />
        <StatCard label="Learned" value={summary.learned} tone="neutral" />
      </section>
      <input
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search from, to, application, port…"
        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
      />
      {q.isPending ? (
        <p className="text-sm text-muted-foreground">Loading rules…</p>
      ) : rows.length === 0 ? (
        <EmptyState title="No network rules" hint="Rules are learned from observed traffic; none have been recorded for this cluster yet." />
      ) : (
        <DataTable rows={rows} columns={columns} rowKey={(r) => String(r.id)} defaultSort={{ id: "matches", dir: "desc" }} />
      )}
    </div>
  );
}
