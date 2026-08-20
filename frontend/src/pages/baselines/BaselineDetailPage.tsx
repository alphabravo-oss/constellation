// BaselineDetailPage — /clusters/:id/runtime/baselines/:baselineId.
//
// The dedicated page that replaced the BaselinesPage slide-in Drawer (the
// Astronomer detail-as-a-page pattern). This is not an add/edit form — it is the
// process-baseline detail view (learned exec list + lifecycle audit trail) with
// inline promote/rollback mode-transition actions. Deep-linkable per workload.
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { ArrowRight, ArrowLeft, GitMerge, Plus, Check, Ban, Power, PowerOff, Trash2 } from "lucide-react";

import {
  baselines as baselinesApi,
  type BaselineMode,
  type BaselineDetail,
  type ProcessRule,
} from "@/api/client";
import { EntityHeader } from "@/components/EntityHeader";
import { useCluster } from "@/hooks/useCluster";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ModePill } from "@/components/ui/status-pill";
import { DataTable, type Column } from "@/components/ui/data-table";
import { TextInput, Select } from "@/components/ui/form";

export function BaselineDetailPage() {
  const { clusterId, cluster } = useCluster();
  const { baselineId } = useParams<{ baselineId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const workloadID = baselineId ?? "";
  const clusterName = cluster?.name ?? "—";
  const listPath = clusterId ? `/clusters/${clusterId}/runtime/baselines` : "/clusters";
  const backToList = () => navigate(listPath);

  const detailQ = useQuery({
    queryKey: ["baseline", workloadID, clusterId],
    queryFn: () => baselinesApi.get(workloadID, { cluster_id: clusterId }),
    enabled: !!workloadID,
  });
  const setMode = useMutation({
    mutationFn: (mode: BaselineMode) => baselinesApi.setMode(workloadID, { mode }, { cluster_id: clusterId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["baseline", workloadID, clusterId] });
      queryClient.invalidateQueries({ queryKey: ["baselines", clusterId] });
    },
  });

  const invalidateDetail = () => queryClient.invalidateQueries({ queryKey: ["baseline", workloadID, clusterId] });
  const [newRule, setNewRule] = useState({ name: "", path: "", action: "allow" as "allow" | "deny", user: "" });
  const createRule = useMutation({
    mutationFn: () => baselinesApi.createRule(workloadID, { ...newRule }),
    onSuccess: () => { setNewRule({ name: "", path: "", action: "allow", user: "" }); invalidateDetail(); },
  });
  const updateRule = useMutation({
    mutationFn: (v: { r: ProcessRule; patch: Partial<ProcessRule> }) =>
      baselinesApi.updateRule(workloadID, v.r.rule_id, {
        name: v.r.name, path: v.r.path, action: v.r.action, user: v.r.user,
        allow_update: v.r.allow_update, enabled: v.r.enabled, description: v.r.description, ...v.patch,
      }),
    onSuccess: invalidateDetail,
  });
  const deleteRule = useMutation({
    mutationFn: (ruleID: string) => baselinesApi.deleteRule(workloadID, ruleID),
    onSuccess: invalidateDetail,
  });

  const profile = detailQ.data;

  const processColumns: Column<BaselineDetail["processes"][number]>[] = useMemo(() => [
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
  ], []);

  const header = (
    <EntityHeader
      breadcrumbs={[
        { label: "Clusters", to: "/clusters" },
        { label: clusterName, to: clusterId ? `/clusters/${clusterId}/dashboard` : "/clusters" },
        { label: "Runtime", to: clusterId ? `/clusters/${clusterId}/runtime` : "/clusters" },
        { label: "Process Baselines", to: listPath },
        { label: workloadID },
      ]}
      title={
        <span className="inline-flex items-center gap-2">
          <GitMerge className="h-5 w-5 text-primary" aria-hidden />
          {workloadID}
        </span>
      }
      subtitle="Process baseline — learned exec list and lifecycle audit trail."
      actions={
        <Button variant="ghost" size="sm" onClick={backToList}>
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back to baselines
        </Button>
      }
    />
  );

  if (detailQ.isPending) {
    return (
      <div className="space-y-5">
        {header}
        <p className="text-sm text-muted-foreground">Loading…</p>
      </div>
    );
  }
  if (detailQ.isError || !profile) {
    return (
      <div className="space-y-5">
        {header}
        <p className="text-sm text-status-error">Failed to load profile.</p>
      </div>
    );
  }

  const canPromote = nextPromoteMode(profile.mode);
  const canRollback = nextRollbackMode(profile.mode);

  return (
    <div className="space-y-5" data-testid="baselines-drawer-body" data-cluster-id={clusterId ?? ""}>
      {header}

      <section className="grid grid-cols-4 gap-3 rounded-md border border-border bg-muted/30 p-3 text-xs">
        <DetailStat label="Mode" value={<ModePill mode={profile.mode} />} />
        <DetailStat label="Processes" value={String(profile.learned_processes_count)} />
        <DetailStat label="Alerts 24h" value={String(profile.monitored_alerts_24h)} />
        <DetailStat label="Blocks 24h" value={String(profile.enforced_blocks_24h)} />
      </section>

      <Card title="Learned processes" description="Exec activity observed for this workload during the learn window.">
        <div data-testid="baselines-drawer-process-table">
          <DataTable
            rows={profile.processes}
            columns={processColumns}
            rowKey={(p) => `${p.name}-${p.path}`}
            emptyState={<div className="px-2 py-4 text-center text-xs text-muted-foreground">No processes observed yet.</div>}
          />
        </div>
      </Card>

      <Card
        title="Process rules"
        description="Author allow/deny rules for specific processes (NeuVector-style). Deny blocks a process even if it was learned; allow whitelists one the baseline hasn't seen."
      >
        <form
          className="mb-3 flex flex-wrap items-end gap-2"
          onSubmit={(e) => { e.preventDefault(); if (newRule.name.trim() || newRule.path.trim()) createRule.mutate(); }}
        >
          <div className="min-w-[140px] flex-1">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground">Process name</label>
            <TextInput placeholder="nginx" value={newRule.name} onChange={(e) => setNewRule((s) => ({ ...s, name: e.target.value }))} />
          </div>
          <div className="min-w-[160px] flex-1">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground">Path</label>
            <TextInput placeholder="/usr/sbin/nginx" value={newRule.path} onChange={(e) => setNewRule((s) => ({ ...s, path: e.target.value }))} />
          </div>
          <div className="w-[110px]">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground">User</label>
            <TextInput placeholder="any" value={newRule.user} onChange={(e) => setNewRule((s) => ({ ...s, user: e.target.value }))} />
          </div>
          <div className="w-[100px]">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground">Action</label>
            <Select value={newRule.action} onChange={(e) => setNewRule((s) => ({ ...s, action: e.target.value as "allow" | "deny" }))}>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </Select>
          </div>
          <Button type="submit" variant="primary" size="sm" disabled={(!newRule.name.trim() && !newRule.path.trim()) || createRule.isPending}>
            <Plus className="h-3.5 w-3.5" /> Add rule
          </Button>
        </form>
        {profile.rules.length === 0 ? (
          <div className="px-2 py-4 text-center text-xs text-muted-foreground">No process rules yet. Add one above to allow or deny a specific process.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b border-border">
                <th className="px-2 py-1.5 text-left">Process</th>
                <th className="px-2 py-1.5 text-left">Path</th>
                <th className="px-2 py-1.5 text-left">User</th>
                <th className="px-2 py-1.5 text-left">Action</th>
                <th className="px-2 py-1.5 text-right"></th>
              </tr>
            </thead>
            <tbody>
              {profile.rules.map((rule) => {
                const busy = updateRule.isPending || deleteRule.isPending;
                return (
                  <tr key={rule.rule_id} className={`border-b border-border/60 ${rule.enabled ? "" : "opacity-50"}`}>
                    <td className="px-2 py-1.5 font-mono text-xs">{rule.name || "—"}</td>
                    <td className="px-2 py-1.5 font-mono text-xs text-muted-foreground">{rule.path || "any"}</td>
                    <td className="px-2 py-1.5 text-xs text-muted-foreground">{rule.user || "any"}</td>
                    <td className="px-2 py-1.5">
                      <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold" style={
                        rule.action === "deny"
                          ? { background: "color-mix(in oklab, var(--color-severity-critical) 16%, transparent)", color: "var(--color-severity-critical)" }
                          : { background: "color-mix(in oklab, var(--color-severity-low) 16%, transparent)", color: "var(--color-severity-low)" }
                      }>
                        {rule.action === "deny" ? <Ban className="h-3 w-3" /> : <Check className="h-3 w-3" />}{rule.action}
                      </span>
                    </td>
                    <td className="px-2 py-1.5">
                      <div className="flex items-center justify-end gap-1">
                        <button type="button" title={rule.action === "deny" ? "Set to allow" : "Set to deny"} disabled={busy}
                          onClick={() => updateRule.mutate({ r: rule, patch: { action: rule.action === "deny" ? "allow" : "deny" } })}
                          className="rounded p-1 hover:bg-accent disabled:opacity-40">
                          {rule.action === "deny" ? <Check className="h-3.5 w-3.5" /> : <Ban className="h-3.5 w-3.5" />}
                        </button>
                        <button type="button" title={rule.enabled ? "Disable" : "Enable"} disabled={busy}
                          onClick={() => updateRule.mutate({ r: rule, patch: { enabled: !rule.enabled } })}
                          className="rounded p-1 hover:bg-accent disabled:opacity-40">
                          {rule.enabled ? <PowerOff className="h-3.5 w-3.5" /> : <Power className="h-3.5 w-3.5" />}
                        </button>
                        <button type="button" title="Delete" disabled={busy}
                          onClick={() => deleteRule.mutate(rule.rule_id)}
                          className="rounded p-1 text-status-error hover:bg-accent disabled:opacity-40">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Mode transitions" description="Audit trail of learn → monitor → enforce lifecycle changes.">
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
      </Card>

      <div className="flex items-center justify-between gap-2 border-t border-border pt-4">
        <Button variant="ghost" size="sm" onClick={backToList}>Close</Button>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={!canRollback || setMode.isPending}
            onClick={() => canRollback && setMode.mutate(canRollback)}
            data-testid="baselines-drawer-rollback"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
            {canRollback ? `Roll back to ${canRollback}` : "Roll back"}
          </Button>
          <Button
            variant="primary"
            size="sm"
            disabled={!canPromote || setMode.isPending}
            onClick={() => canPromote && setMode.mutate(canPromote)}
            data-testid="baselines-drawer-promote"
          >
            {canPromote === "monitor" && "Promote to Monitor"}
            {canPromote === "enforce" && "Promote to Enforce"}
            {!canPromote && (profile.mode === "enforce" ? "Already enforcing" : "Promote")}
            {canPromote && <ArrowRight className="h-3.5 w-3.5" aria-hidden />}
          </Button>
        </div>
      </div>
    </div>
  );
}

function DetailStat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <div className="mt-1 text-sm font-semibold">{value}</div>
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
