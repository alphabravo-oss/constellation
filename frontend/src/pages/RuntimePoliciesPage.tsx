// Wave B1: Runtime policies UI.
//
// Two tabs:
//   - Authored: list of policies for the selected cluster. Each row shows
//     the mode badge, workload, rule count, last update, and the four
//     action buttons (Promote / Demote / Edit / Delete). Promote pops a
//     confirmation since it starts dropping packets.
//   - Editor: a barebones form for now (workload, name, JSON rules
//     textarea, mode). The rich form (peer dropdowns, port multi-add,
//     L7 picker) is a follow-up — landing the round-trip first keeps
//     the slice useful even while the editor evolves.
//
// All writes go through the API which writes audit_events; the
// auto-rollback watcher (Wave A5) handles enforce-mode safety.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
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
import { StatCard } from "@/components/ui/stat-card";
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
  const [search] = useSearchParams();
  // Cluster comes from either the path param (under /clusters/:id/...) or
  // a fallback ?cluster_id= query string (for standalone routing). Falls
  // through to a "select a cluster" empty state.
  const { id: pathClusterID } = useParams();
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const navigate = useNavigate();

  const queryClient = useQueryClient();
  const q = useQuery({
    queryKey: ["runtime-policies", clusterID],
    queryFn: () => runtimePolicies.list(clusterID),
    enabled: !!clusterID,
  });

  const [confirmPromoteID, setConfirmPromoteID] = useState<string | null>(null);

  // Add/edit now live on dedicated routes (Astronomer pattern; see
  // frontend/CLAUDE.md). Preserve any ?cluster_id= fallback across the nav.
  const openNew = () => navigate({ pathname: "new", search: search.toString() });
  const openEdit = (id: string) => navigate({ pathname: id, search: search.toString() });

  const policies = useMemo(() => q.data ?? [], [q.data]);
  const enforceCount = policies.filter((p) => p.mode === "enforce").length;
  const monitorCount = policies.filter((p) => p.mode === "monitor").length;

  const columns: Column<RuntimePolicy>[] = [
    { id: "workload", header: "Workload", cell: (p) => <span className="font-mono">{p.workload}</span>, sort: (a, b) => a.workload.localeCompare(b.workload) },
    { id: "name", header: "Policy", cell: (p) => p.name, sort: (a, b) => a.name.localeCompare(b.name) },
    {
      id: "mode",
      header: "Mode",
      cell: (p) => {
        const badge = MODE_BADGE[p.mode];
        return <StatusPill label={badge.label} tone={badge.tone} />;
      },
      sort: (a, b) => a.mode.localeCompare(b.mode),
    },
    {
      id: "rules",
      header: "Rules",
      numeric: true,
      cell: (p) => (Array.isArray(p.rules) ? p.rules.length : 0),
      sort: (a, b) => (Array.isArray(a.rules) ? a.rules.length : 0) - (Array.isArray(b.rules) ? b.rules.length : 0),
    },
    {
      id: "updated",
      header: "Updated",
      cell: (p) => <span className="text-muted-foreground">{new Date(p.updated_at).toLocaleString()}</span>,
      sort: (a, b) => a.updated_at.localeCompare(b.updated_at),
    },
    {
      id: "actions",
      header: "Actions",
      className: "text-right",
      cell: (p) => (
        <PolicyActions
          p={p}
          onEdit={() => openEdit(p.id)}
          onPromoteClick={() => setConfirmPromoteID(p.id)}
        />
      ),
    },
  ];

  if (!clusterID) {
    return (
      <div className="flex h-[calc(100vh-72px)] items-center justify-center text-sm text-muted-foreground" data-testid="runtime-policies-empty">
        Select a cluster (the URL needs <code>?cluster_id=&lt;uuid&gt;</code>).
      </div>
    );
  }
  return (
    <div className="space-y-6" data-testid="runtime-policies-page">
      <PageHeader
        title="Runtime Policies"
        description="Per-workload network policy bundles dp enforces. New policies start in monitor mode (observe only); promote one to enforce to start dropping matched packets."
        actions={
          <Button
            size="sm"
            variant="outline"
            onClick={openNew}
            data-testid="runtime-policies-new"
          >
            <Plus className="mr-1 h-3.5 w-3.5" /> New policy
          </Button>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <StatCard label="Total policies" value={policies.length} icon={<ListChecks className="h-3.5 w-3.5" />} />
        <StatCard label="Monitoring" value={monitorCount} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <StatCard label="Enforcing" value={enforceCount} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={enforceCount > 0 ? "accent" : "neutral"} />
      </section>

      <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="runtime-policies-list">
        {q.isLoading && <LoadingState />}
        {q.isError && <ErrorState error={q.error} />}
        {q.data && (
          <DataTable
            rows={policies}
            columns={columns}
            rowKey={(p) => p.id}
            showDensityToggle={false}
            emptyState={<EmptyState title="No policies yet" hint="Click New policy to author one." />}
          />
        )}
      </div>

      <PromoteConfirmDialog
        policyID={confirmPromoteID}
        onClose={() => setConfirmPromoteID(null)}
        onConfirmed={() => {
          setConfirmPromoteID(null);
          void queryClient.invalidateQueries({ queryKey: ["runtime-policies", clusterID] });
        }}
      />
    </div>
  );
}

function PolicyActions({
  p,
  onEdit,
  onPromoteClick,
}: {
  p: RuntimePolicy;
  onEdit: () => void;
  onPromoteClick: () => void;
}) {
  const queryClient = useQueryClient();
  const demote = useMutation({
    mutationFn: () => runtimePolicies.demote(p.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-policies"] }),
  });
  const remove = useMutation({
    mutationFn: () => runtimePolicies.remove(p.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-policies"] }),
  });
  return (
    <div className="inline-flex items-center gap-1" data-testid={`runtime-policy-row-${p.id}`}>
      {p.mode === "monitor" && (
        <Button size="sm" variant="outline" onClick={onPromoteClick} data-testid={`runtime-policy-promote-${p.id}`}>
          Promote
        </Button>
      )}
      {p.mode === "enforce" && (
        <Button size="sm" variant="outline" onClick={() => demote.mutate()} disabled={demote.isPending} data-testid={`runtime-policy-demote-${p.id}`}>
          Demote
        </Button>
      )}
      <Button size="sm" variant="ghost" onClick={onEdit} data-testid={`runtime-policy-edit-${p.id}`}>
        <Edit3 className="h-3.5 w-3.5" />
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => {
          if (window.confirm(`Delete policy "${p.name}"?`)) remove.mutate();
        }}
        disabled={remove.isPending}
        data-testid={`runtime-policy-delete-${p.id}`}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

function PromoteConfirmDialog({
  policyID,
  onClose,
  onConfirmed,
}: {
  policyID: string | null;
  onClose: () => void;
  onConfirmed: () => void;
}) {
  // Wave B2: fetch match-stats for the policy so the operator sees how many
  // flows would be allowed vs would-be-blocked in the last 24h before they
  // flip the switch. The policy is currently in monitor mode, so the deny
  // counter here means "dp would have dropped this packet if we were in
  // enforce mode" — exactly the question the operator wants to answer.
  const statsQ = useQuery({
    queryKey: ["runtime-policy-match-stats", policyID],
    queryFn: () => runtimePolicies.matchStats(policyID as string, 24),
    enabled: !!policyID,
  });

  const promote = useMutation({
    mutationFn: () => runtimePolicies.promote(policyID as string),
    onSuccess: onConfirmed,
  });
  if (!policyID) return null;

  const stats = statsQ.data;
  return (
    <Dialog.Root open onOpenChange={(o) => { if (!o) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-background/40 backdrop-blur-[1px]" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-[520px] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-card p-4 shadow-[var(--elev-3)]"
          data-testid="runtime-policy-promote-dialog"
        >
          <div className="flex items-start justify-between gap-2">
            <Dialog.Title className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck className="h-4 w-4 text-[color:var(--color-status-success)]" />
              Promote to enforce
            </Dialog.Title>
            <Dialog.Close className="rounded p-1 hover:bg-accent" aria-label="Close" data-testid="runtime-policy-promote-cancel">
              <X className="h-4 w-4" />
            </Dialog.Close>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            dp will start dropping packets matched by this policy's <code>deny</code> rules.
          </p>
          <MatchStatsPane stats={stats} loading={statsQ.isLoading} />
          <p className="mt-2 text-[11px] text-muted-foreground">
            The auto-rollback watcher demotes back to monitor automatically if
            the per-policy deny rate exceeds the configured threshold (default
            1000 / 60s) — your safety belt against a bad rule.
          </p>
          <div className="mt-3 flex items-center justify-end gap-2">
            <Button variant="outline" size="sm" onClick={onClose}>Cancel</Button>
            <Button size="sm" onClick={() => promote.mutate()} disabled={promote.isPending} data-testid="runtime-policy-promote-confirm">
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
