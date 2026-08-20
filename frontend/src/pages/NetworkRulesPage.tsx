// NetworkRulesPage — NeuVector-parity Network Rules table. Presents the cluster's
// observed connectivity as an ordered allow/deny rule list (ID, From, To, Applications,
// Ports, Action, Learned, Enabled, Match count) so NeuVector users see their network
// policy in exactly the shape they expect. Rules are learned from flow rollups (as NV
// learns from observed conversations); edit/deny/reorder CRUD is the next step.
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Network as NetworkIcon, Check, Ban } from "lucide-react";

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
  const [search, setSearch] = useState("");
  const q = useQuery({
    queryKey: ["network-rules", clusterId],
    queryFn: () => networkRules.list(clusterId!),
    enabled: !!clusterId,
  });
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
  ];

  return (
    <div className="space-y-4" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Network Rules"
        description="The cluster's connectivity as an ordered allow/deny rule set, learned from observed conversations — NeuVector-style network policy."
        actions={
          <button
            type="button"
            onClick={() => downloadCsv("constellation-network-rules", ["ID", "From", "To", "Applications", "Ports", "Action", "Type", "Matches"],
              rows.map((r) => [r.id, r.from, r.to, r.applications.join(" "), r.ports, r.action, r.learned ? "learned" : r.cfg_type, r.match_counter]))}
            className="rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent"
          >Export CSV</button>
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
