import { useRuntimePolicyScope, policyMatches, policyFingerprint, policyRevision, policyReceiptMatches, policyRules } from "./runtime-policy-context";
import { exportQueryReady, useExportGuard } from "@/hooks/useExportGuard";
// Runtime policy inventory and explicit mode-change confirmations.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useRouteSearchParams } from "@/lib/route-search";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ListChecks,
  Plus,
  Edit3,
  Trash2,
  X,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { StatusPill } from "@/components/ui/status-pill";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";

import {
  runtimePolicies,
  type PolicyMatchStats,
  type RuntimePolicy,
  type RuntimePolicyMode,
} from "@/api/client";

const MODE_BADGE: Record<RuntimePolicyMode, { label: string; tone: "success" | "warning" | "neutral"; icon: React.ReactNode }> = {
  monitor:  { label: "Monitor",  tone: "warning", icon: <ShieldAlert className="h-3 w-3" aria-hidden /> },
  enforce:  { label: "Enforce",  tone: "success", icon: <ShieldCheck className="h-3 w-3" aria-hidden /> },
  disabled: { label: "Disabled", tone: "neutral", icon: <ShieldOff   className="h-3 w-3" aria-hidden /> },
};

export function RuntimePoliciesPage() {
  const [search] = useRouteSearchParams();
  const scope = useRuntimePolicyScope();
  const clusterID = scope.clusterId ?? "";
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const key = ["runtime-policies", scope.owner, clusterID];
  const valid = (rows: unknown): rows is RuntimePolicy[] => Array.isArray(rows) && rows.every(policy => policyMatches(policy, scope.org, clusterID)) && new Set(rows.map(policy => policy.id)).size === rows.length;
  const q = useQuery({ queryKey: key, queryFn: async () => { const policies = await runtimePolicies.list(clusterID); if (!valid(policies)) throw new Error("Policy inventory does not match this scope"); return policies; }, enabled: scope.ready });
  const available = scope.ready && q.isSuccess && !q.isFetching && exportQueryReady(queryClient, key) && valid(q.data);
  const fresh = (policy?: RuntimePolicy) => scope.recheck() && available && exportQueryReady(queryClient, key, q.data) && valid(queryClient.getQueryData(key)) && (!policy || q.data!.some(current => current.id === policy.id && policyFingerprint(current) === policyFingerprint(policy)));
  const [confirmation, setConfirmation] = useState<{ context: string; policy: RuntimePolicy } | null>(null);
  const context = JSON.stringify([scope.owner, clusterID]);
  const confirmPolicy = confirmation?.context === context ? confirmation.policy : null;
  // Add/edit now live on dedicated routes (Astronomer pattern; see
  // frontend/CLAUDE.md). Preserve any ?cluster_id= fallback across the nav.
  const openNew = () => navigate({ to: "/clusters/$id/runtime-policies/new", params: { id: clusterID }, search: Object.fromEntries(search) });
  const openEdit = (id: string) => navigate({ to: "/clusters/$id/runtime-policies/$policyId", params: { id: clusterID, policyId: id }, search: Object.fromEntries(search) });

  const policies = scope.ready && !q.isError && valid(q.data) ? q.data! : [];
  const enforceCount = policies.filter((p) => p.mode === "enforce").length;
  const monitorCount = policies.filter((p) => p.mode === "monitor").length;

  const columns: Column<RuntimePolicy>[] = [
    { id: "workload", header: "Workload", kind: "text", code: true, size: 224, minSize: 160, maxSize: 320, cell: (p) => <span className="font-mono">{p.workload}</span>, sort: (a, b) => a.workload.localeCompare(b.workload) },
    { id: "name", header: "Policy", kind: "name", cell: (p) => p.name, sort: (a, b) => a.name.localeCompare(b.name) },
    {
      id: "mode",
      header: "Mode", kind: "status",
      cell: (p) => {
        const badge = MODE_BADGE[p.mode];
        return <StatusPill label={badge.label} tone={badge.tone} />;
      },
      sort: (a, b) => a.mode.localeCompare(b.mode),
    },
    {
      id: "rules",
      header: "Rules", kind: "count",
      numeric: true,
      cell: (p) => (policyRules(p)?.length ?? 0),
      sort: (a, b) => (policyRules(a)?.length ?? 0) - (policyRules(b)?.length ?? 0),
    },
    {
      id: "updated",
      header: "Updated", kind: "date", size: 224, minSize: 208, maxSize: 240,
      cell: (p) => <span className="text-muted-foreground">{new Date(p.updated_at).toLocaleString()}</span>,
      sort: (a, b) => a.updated_at.localeCompare(b.updated_at),
    },
    {
      id: "actions",
      header: "Actions", kind: "actions", size: 224, minSize: 208, maxSize: 256, wrap: true,
      className: "text-right",
      cell: (p) => (
        <PolicyActions
          p={p} owner={scope.owner} available={available} recheck={() => fresh(p)}
          onEdit={() => openEdit(p.id)}
          onPromoteClick={() => { if (fresh(p)) setConfirmation({ context, policy: p }); }}
        />
      ),
    },
  ];

  if (!scope.ready) {
    return (
      <div className="flex h-[calc(100vh-72px)] items-center justify-center text-sm text-muted-foreground" data-testid="runtime-policies-empty">
        <div className="space-y-3 text-center"><p>Resolve the selected cluster and operator before reviewing runtime policies.</p><Button variant="outline" onClick={scope.retry}>Retry cluster</Button></div>
      </div>
    );
  }
  return (
    <div className="space-y-6" data-testid="runtime-policies-page">
      <PageHeader
        title="Runtime Policies"
        description="Manage network rules for individual workloads. New policies observe traffic; promote a reviewed policy to enable enforcement."
        actions={
          <><Button size="sm" variant="outline" disabled={q.isFetching} onClick={() => void q.refetch()}>Refresh</Button><Button
            size="sm"
            variant="outline"
            onClick={openNew} disabled={!available}
            data-testid="runtime-policies-new"
          >
            <Plus className="mr-1 h-3.5 w-3.5" /> New policy
          </Button></>
        }
      />

      <VerdictBanner status={q.isError ? "degraded" : "info"}
        title={q.isError ? "Runtime policies could not be loaded" : q.isPending ? "Loading runtime policies" : !available ? "Runtime policy evidence is being refreshed" : policies.length === 0 ? "No runtime policies configured" : `${enforceCount} policies configured to enforce`}
        detail="Configured modes describe policy intent. Review observed matches before promotion; mode alone does not prove agent enforcement." />
      <StatGrid>
        <StatCard label="Total policies" value={available ? policies.length : "—"} icon={<ListChecks className="h-3.5 w-3.5" />} />
        <StatCard label="Monitoring" value={available ? monitorCount : "—"} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <StatCard label="Enforcing" value={available ? enforceCount : "—"} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={enforceCount > 0 ? "accent" : "neutral"} />
      </StatGrid>

      <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="runtime-policies-list">
        {q.isLoading && <LoadingState />}
        {q.isError && <ErrorState title="Runtime policies could not be loaded or refreshed." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />}
        {q.isFetching && !q.isPending && <p role="status" className="p-3 text-xs text-muted-foreground">Refreshing policy evidence; actions are paused.</p>}
        {!q.isError && valid(q.data) && (
          <DataTable
            rows={policies}
            columns={columns}
            rowKey={(p) => p.id}
            preferencesKey="runtime-policies" canExport={() => fresh()}
            exportFileName="runtime-policies"
            emptyState={<EmptyState title="No policies yet" hint="Click New policy to author one." />}
          />
        )}
      </div>

      <PromoteConfirmDialog key={`${context}:${confirmPolicy?.id ?? "closed"}`}
        policy={confirmPolicy} owner={scope.owner} available={available} recheck={() => !!confirmPolicy && fresh(confirmPolicy)}
        onClose={() => setConfirmation(null)}
        onConfirmed={() => {
          setConfirmation(null);
          void queryClient.invalidateQueries({ queryKey: key });
        }}
      />
    </div>
  );
}

function PolicyActions({ p, owner, available, recheck, onEdit, onPromoteClick }: {
  p: RuntimePolicy; owner: string; available: boolean; recheck: () => boolean; onEdit: () => void; onPromoteClick: () => void;
}) {
  const queryClient = useQueryClient();
  const [uncertain, setUncertain] = useState(false);
  const captureCurrent = useExportGuard(JSON.stringify([owner, policyFingerprint(p)]), !available || uncertain, recheck);
  const action = useMutation({ mutationFn: async (kind: "demote" | "remove") => {
    if (!available || uncertain || !recheck()) throw new Error("Policy evidence is unavailable");
    const current = captureCurrent(), review = { cluster_id: p.cluster_id, expected_version: policyRevision(p)! };
    const response = kind === "remove" ? await runtimePolicies.removeReviewed(p.id, review) : await runtimePolicies.demoteReviewed(p.id, review);
    if (!current()) { setUncertain(true); throw new Error("Response is no longer current"); }
    const deleted = response as Awaited<ReturnType<typeof runtimePolicies.removeReviewed>>;
    const matched = kind === "remove" ? deleted.deleted === p.id && deleted.id === p.id && deleted.cluster_id === p.cluster_id && deleted.workload === p.workload && deleted.revision === policyRevision(p) : policyReceiptMatches(response, p, "monitor");
    if (!matched) { setUncertain(true); throw new Error("Action could not be confirmed"); }
    void queryClient.invalidateQueries({ queryKey: ["runtime-policies", owner, p.cluster_id] });
  }, onError: error => { if ((error as { response?: { status?: number } }).response?.status === 409 && recheck()) void queryClient.invalidateQueries({ queryKey: ["runtime-policies", owner, p.cluster_id] }); } });
  const busy = !available || uncertain || action.isPending;
  return (
    <div className="inline-flex flex-wrap items-center justify-end gap-1" data-testid={`runtime-policy-row-${p.id}`}>
      {p.mode === "monitor" && (
        <Button size="sm" variant="outline" onClick={onPromoteClick} disabled={busy} data-testid={`runtime-policy-promote-${p.id}`}>
          Promote
        </Button>
      )}
      {p.mode === "enforce" && (
        <Button size="sm" variant="outline" onClick={() => action.mutate("demote")} disabled={busy} data-testid={`runtime-policy-demote-${p.id}`}>
          Demote
        </Button>
      )}
      <Button size="sm" variant="ghost" aria-label={`Edit ${p.name}`} onClick={() => { if (recheck()) onEdit(); }} disabled={busy} data-testid={`runtime-policy-edit-${p.id}`}>
        <Edit3 className="h-3.5 w-3.5" />
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => {
          if (recheck() && window.confirm(`Delete policy "${p.name}"?`)) action.mutate("remove");
        }}
        disabled={busy}
        aria-label={`Delete ${p.name}`}
        data-testid={`runtime-policy-delete-${p.id}`}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
      {uncertain && <span role="alert" className="w-full text-xs text-status-error">Reload before another write; the action response is no longer current.</span>}
      {action.isError && <span role="alert" className="w-full text-xs text-status-error">Action failed or could not be confirmed. Refresh and review this policy before retrying.</span>}
    </div>
  );
}

function PromoteConfirmDialog({ policy, owner, available, recheck, onClose, onConfirmed }: {
  policy: RuntimePolicy | null; owner: string; available: boolean; recheck: () => boolean; onClose: () => void; onConfirmed: () => void;
}) {
  const policyID = policy?.id;
  // Wave B2: fetch match-stats for the policy so the operator sees how many
  // flows would be allowed vs would-be-blocked in the last 24h before they
  // flip the switch. The policy is currently in monitor mode, so the deny
  // counter here means "dp would have dropped this packet if we were in
  // enforce mode" — exactly the question the operator wants to answer.
  const statsQ = useQuery({
    queryKey: ["runtime-policy-match-stats", owner, policy?.cluster_id, policyID, policy && policyRevision(policy)],
    queryFn: () => runtimePolicies.matchStats(policyID as string, 24),
    enabled: !!policyID && available && recheck(),
  });

  const queryClient = useQueryClient();
  const [uncertain, setUncertain] = useState(false);
  const statsKey = ["runtime-policy-match-stats", owner, policy?.cluster_id, policyID, policy && policyRevision(policy)];
  const previewReady = statsQ.isSuccess && !statsQ.isFetching && exportQueryReady(queryClient, statsKey, statsQ.data) && statsQ.data.workload === policy?.workload && statsQ.data.window_hours === 24;
  const currentReview = () => available && recheck() && exportQueryReady(queryClient, statsKey, statsQ.data) && statsQ.data?.workload === policy?.workload;
  const captureCurrent = useExportGuard(JSON.stringify([owner, policy && policyFingerprint(policy)]), !available || !previewReady || uncertain, currentReview);
  const promote = useMutation({ mutationFn: async () => {
    if (!policy || !previewReady || uncertain || !currentReview()) throw new Error("Policy review is unavailable");
    const current = captureCurrent();
    const saved = await runtimePolicies.promoteReviewed(policy.id, { cluster_id: policy.cluster_id, expected_version: policyRevision(policy)! });
    if (!current()) { setUncertain(true); throw new Error("Response is no longer current"); }
    if (!policyReceiptMatches(saved, policy, "enforce")) { setUncertain(true); throw new Error("Promotion could not be confirmed"); }
    onConfirmed();
  } });
  if (!policy) return null;
  const stats = statsQ.data;
  return (
    <Dialog.Root open onOpenChange={(o) => { if (!o && !promote.isPending) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-background/40 backdrop-blur-[1px]" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-[min(520px,calc(100%-2rem))] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-card p-4 shadow-[var(--elev-3)]"
          data-testid="runtime-policy-promote-dialog"
        >
          <div className="flex items-start justify-between gap-2">
            <Dialog.Title className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck className="h-4 w-4 text-[color:var(--color-status-success)]" />
              Promote to enforce
            </Dialog.Title>
            <Dialog.Close disabled={promote.isPending} className="rounded p-1 hover:bg-accent" aria-label="Close" data-testid="runtime-policy-promote-cancel">
              <X className="h-4 w-4" />
            </Dialog.Close>
          </div>
          <Dialog.Description className="mt-2 text-xs text-muted-foreground">
            Agents configured to enforce will block packets matched by this policy's <code>deny</code> rules.
          </Dialog.Description>
          {statsQ.isError && <p role="alert">Match preview could not be loaded. <button type="button" className="underline" onClick={() => void statsQ.refetch()}>Retry preview</button></p>}
          {promote.isError && <p role="alert">Promotion failed. The policy may have changed or you may lack permission. Refresh and try again.</p>}
          <MatchStatsPane stats={previewReady ? stats : undefined} loading={statsQ.isLoading || statsQ.isFetching} />
          {!available && <p role="alert">Current policy scope is unavailable; promotion is paused.</p>}
          {uncertain && <p role="alert">The promotion could not be confirmed. Reload before another write.</p>}
          <p className="mt-2 text-[11px] text-muted-foreground">
            The auto-rollback watcher demotes back to monitor automatically if
            the per-policy deny rate exceeds the configured threshold (default
            1000 / 60s) — your safety belt against a bad rule.
          </p>
          <div className="mt-3 flex items-center justify-end gap-2">
            <Button variant="outline" size="sm" disabled={promote.isPending} onClick={onClose}>Cancel</Button>
            <Button size="sm" onClick={() => promote.mutate()} disabled={promote.isPending || !available || !previewReady || uncertain || !recheck()} data-testid="runtime-policy-promote-confirm">
              {promote.isPending ? "Promoting…" : "Promote"}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Wave B2/B3: shared component that visualises allow/monitor/deny counts
 *  from /match-stats or /simulate. The "deny" column is the one operators
 *  care about — that's what would be dropped if (or when) enforce is on. */
function MatchStatsPane({ stats, loading }: { stats?: PolicyMatchStats; loading?: boolean }) {
  if (loading) return <div className="mt-3 text-[11px] text-muted-foreground">Loading match preview…</div>;
  if (!stats) return null;
  const cards: Array<{ key: "allow" | "monitor" | "deny"; label: string; tone: string; n: number }> = [
    { key: "allow",   label: "Allow",        tone: "var(--color-status-success)", n: stats.allow },
    { key: "monitor", label: "Monitor-only", tone: "var(--color-status-warning)", n: stats.monitor },
    { key: "deny",    label: "Would block",  tone: "var(--color-status-error)",   n: stats.deny },
  ];
  return (
    <div className="mt-3 space-y-2" data-testid="runtime-policy-match-stats">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        Last {stats.window_hours}h · {stats.total} flows matched · workload <span className="text-mono text-foreground">{stats.workload}</span>
      </div>
      <div className="grid grid-cols-3 gap-2">
        {cards.map((c) => (
          <div
            key={c.key}
            className="rounded border border-border bg-card/50 p-2 text-center"
            data-testid={`match-stats-${c.key}`}
          >
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{c.label}</div>
            <div className="text-mono text-2xl font-semibold tabular-nums" style={{ color: c.tone }}>{c.n}</div>
          </div>
        ))}
      </div>
      {stats.deny > 0 && stats.samples?.deny && stats.samples.deny.length > 0 && (
        <details className="text-[11px]">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground" data-testid="runtime-policy-match-stats-samples-toggle">
            Sample of would-be-blocked flows ({stats.samples.deny.length})
          </summary>
          <ul className="mt-1 space-y-0.5 rounded border border-border bg-background/40 p-2 font-mono text-[10px]">
            {stats.samples.deny.map((s, i) => (
              <li key={i} className="truncate">
                {s.src} → {s.dst}:{s.dst_port} · {s.protocol.toUpperCase()}
                {s.l7_protocol ? ` · ${s.l7_protocol.toUpperCase()}` : ""}
                · {(s.bytes / 1024).toFixed(1)} KB
              </li>
            ))}
          </ul>
        </details>
      )}
      {stats.default > 0 && (
        <div className="text-[10px] text-muted-foreground">
          {stats.default} of these matched no rule and fell through to the policy's default action.
        </div>
      )}
    </div>
  );
}
