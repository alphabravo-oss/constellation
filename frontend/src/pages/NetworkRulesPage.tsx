import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { Network as NetworkIcon, Check, Ban, Plus, Power, PowerOff, Trash2, Pencil, ArrowUpToLine } from "lucide-react";

import { networkRules, type NetworkRule } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { ImportExportButtons } from "@/components/ImportExportButtons";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState } from "@/components/ui/states";
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
    `${clusterId ? `/clusters/${clusterId}` : ""}/network-rules/${r.id}/edit?from=${encodeURIComponent(r.from)}&to=${encodeURIComponent(r.to)}`;
  const all = useMemo(() => q.data?.rules ?? [], [q.data?.rules]);
  const summary = q.data?.summary;
  const rows = useMemo(() => {
    const n = search.trim().toLowerCase();
    if (!n) return all;
    return all.filter((r) => [r.from, r.to, r.ports, r.applications.join(",")].some((v) => v.toLowerCase().includes(n)));
  }, [all, search]);

  const columns: Column<NetworkRule>[] = [
    { id: "id", exportValue: (r) => r.id, header: "ID", kind: "count",  numeric: true, cell: (r) => <span className="text-mono text-[11px] text-muted-foreground">{r.id}</span>, sort: (a, b) => a.id - b.id },
    { id: "priority", exportValue: (r) => r.priority, header: "Priority", kind: "count",  numeric: true, cell: (r) => <span className="text-mono text-xs">{r.priority}</span>, sort: (a, b) => a.priority - b.priority },
    { id: "from", exportValue: (r) => r.from, header: "From", kind: "name", code: true, cell: (r) => <span className="text-mono text-xs">{endpointLabel(r.from)}</span>, sort: (a, b) => a.from.localeCompare(b.from) },
    { id: "to", exportValue: (r) => r.to, header: "To", kind: "text", code: true, size: 224, minSize: 160, maxSize: 320, cell: (r) => <span className="text-mono text-xs">{endpointLabel(r.to)}</span>, sort: (a, b) => a.to.localeCompare(b.to) },
    { id: "apps", exportValue: (r) => r.applications.join(", ") || "any", header: "Applications", kind: "badge", size: 184, minSize: 160, maxSize: 240, wrap: true, cell: (r) => (
        r.applications.length === 0 ? <span className="text-xs text-muted-foreground">any</span>
          : <span className="flex flex-wrap gap-1">{r.applications.slice(0, 5).map((a) => <span key={a} className="rounded bg-muted px-1.5 py-px text-[10px] font-medium uppercase text-muted-foreground">{a}</span>)}</span>
      ) },
    { id: "ports", exportValue: (r) => r.ports, header: "Ports", kind: "text", code: true, size: 128, minSize: 104, maxSize: 176, wrap: true,  cell: (r) => <span className="text-mono text-[11px] text-muted-foreground">{r.ports}</span> },
    { id: "action", exportValue: (r) => r.action, header: "Action", kind: "status",  cell: (r) => (
        r.action === "deny"
          ? <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: "color-mix(in oklab, var(--color-severity-critical) 16%, transparent)", color: "var(--color-severity-critical)" }}><Ban className="h-3 w-3" />deny</span>
          : <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: "color-mix(in oklab, var(--color-severity-low) 16%, transparent)", color: "var(--color-severity-low)" }}><Check className="h-3 w-3" />allow</span>
      ), sort: (a, b) => a.action.localeCompare(b.action) },
    { id: "status", header: "Status", kind: "status", cell: (r) => <span className="text-xs">{r.disable ? "Disabled" : "Enabled"}</span>, exportValue: (r) => r.disable ? "Disabled" : "Enabled" },
    { id: "learned", exportValue: (r) => r.learned ? "learned" : r.cfg_type, header: "Type", kind: "badge",  cell: (r) => <span className="rounded bg-muted px-1.5 py-px text-[10px] text-muted-foreground">{r.learned ? "learned" : r.cfg_type}</span> },
    { id: "matches", exportValue: (r) => r.match_counter, header: "Matches", kind: "count", numeric: true,  cell: (r) => <span className="text-mono text-xs">{r.match_counter.toLocaleString()}</span>, sort: (a, b) => a.match_counter - b.match_counter },
    { id: "last", exportValue: (r) => r.last_match_timestamp ? new Date(r.last_match_timestamp * 1000).toISOString() : "", header: "Last match", kind: "age", size: 160, minSize: 144, maxSize: 192, align: "right", numeric: true,  cell: (r) => <span className="text-[10px] text-muted-foreground">{r.last_match_timestamp ? fmtRelative(new Date(r.last_match_timestamp * 1000).toISOString()) : "—"}</span>, sort: (a, b) => a.last_match_timestamp - b.last_match_timestamp },
    { id: "actions", hideable: false, exportable: false, header: "", kind: "actions", size: 168, minSize: 160, maxSize: 192,  cell: (r) => {
        const busy = q.isError || upsert.isPending || remove.isPending || moveTop.isPending;
        const overridden = r.cfg_type !== "learned"; // has a persisted override / manual rule
        const isTop = all.length > 0 && r.from === all[0].from && r.to === all[0].to;
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
            <Link to="." href={editHref(r)} title="Edit" aria-label={`Edit rule from ${r.from} to ${r.to}`} className="rounded p-1 hover:bg-accent"><Pencil className="h-3.5 w-3.5" /></Link>
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
        description="Review learned traffic rules and manage configured allow or deny rules for this cluster."
        actions={
          <div className="flex items-center gap-2">
            {clusterId ? (
              <ImportExportButtons
                filename="constellation-network-rules.yaml"
                label="network rules"
                exportYaml={() => networkRules.exportYaml(clusterId)}
                importYaml={(text) => networkRules.importYaml(clusterId, text)}
                onImported={() => void invalidate()}
              />
            ) : null}
            <button
              type="button"
              onClick={() => navigate({ href: `${clusterId ? `/clusters/${clusterId}` : ""}/network-rules/new` })}
              className="inline-flex items-center gap-1.5 rounded-md bg-[color:var(--color-primary)] px-3 py-2 text-sm font-medium text-white hover:opacity-90"
            ><Plus className="h-4 w-4" />Add rule</button>
          </div>
        }
      />
      <VerdictBanner status={q.isError ? "degraded" : "info"}
        title={q.isError ? "Network rules could not be refreshed" : q.isPending ? "Loading network rules" : `${summary?.total ?? 0} network rules returned`}
        detail="Configured rules appear before learned rules. Rule counts describe configuration and observed traffic; they do not confirm enforcement on workloads." />
      <StatGrid>
        <StatCard label="Rules" value={summary?.total ?? "—"} icon={<NetworkIcon className="h-3.5 w-3.5" />} />
        <StatCard label="Allow" value={summary?.allow ?? "—"} tone="low" />
        <StatCard label="Deny" value={summary?.deny ?? "—"} tone={(summary?.deny ?? 0) > 0 ? "critical" : "neutral"} />
        <StatCard label="Learned" value={summary?.learned ?? "—"} tone="neutral" />
        <StatCard label="Disabled" value={summary?.disabled ?? "—"} tone="neutral" />
      </StatGrid>
      <input
        aria-label="Search network rules"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search from, to, application, port…"
        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
      />
      {(upsert.isError || remove.isError || moveTop.isError) && <p role="alert" className="text-sm text-status-error">Could not update this network rule. Try the action again.</p>}
      {q.isError && <ErrorState title="Could not load network rules." action={<button type="button" onClick={() => void q.refetch()}>Retry</button>} />}
      {q.isPending ? (
        <p className="text-sm text-muted-foreground">Loading rules…</p>
      ) : q.isError && !q.data ? null : rows.length === 0 ? (
        <EmptyState title={search ? "No matching network rules" : "No network rules"} hint={search ? "Change the search to see other rules." : "Add a rule or wait for learned traffic to appear."} />
      ) : (
        <div>
          <p className="mb-2 text-xs text-muted-foreground">Initially shown in server evaluation order. Column sorting changes only the view; Move to top changes rule precedence.</p>
          <DataTable preferencesKey="network-rules" exportFileName="constellation-network-rules" rows={rows} sourceLimit={3000} sourceCount={all.length} columns={columns} rowKey={(r) => JSON.stringify([r.from, r.to])} />
        </div>
      )}
    </div>
  );
}
