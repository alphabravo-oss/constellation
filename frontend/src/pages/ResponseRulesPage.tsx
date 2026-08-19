import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Save, Trash2, X } from "lucide-react";

import {
  responseRulesV2,
  type ResponseRuleV2,
  type RRV2Condition,
  type RRV2Action,
  type RRV2CondType,
  type RRV2ActionKind,
  type RRV2EventType,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { Drawer } from "@/components/ui/drawer";

const COND_TYPES: { id: RRV2CondType; label: string; help: string }[] = [
  { id: "name", label: "Event name", help: "Regex against event name or title" },
  { id: "level", label: "Severity ≥", help: "info | low | medium | high | critical" },
  { id: "cve_critical", label: "CVE critical + score floor", help: "Matches when any CVE is critical AND base score ≥ value" },
  { id: "proc", label: "Process name", help: "Regex against process basename" },
  { id: "event_type", label: "Event type", help: "admission | runtime | scan | compliance" },
];

const ACTION_KINDS: { id: RRV2ActionKind; label: string; help: string }[] = [
  { id: "notify", label: "Notify receiver", help: "Send via pkg/notify (slack/jira/pagerduty/etc)" },
  { id: "ticket", label: "Open ticket", help: "Notify via ITSM destination (Jira/SNOW)" },
  { id: "quarantine", label: "Quarantine workload", help: "Runtime action (requires data plane)" },
  { id: "isolate", label: "Network isolate", help: "NetworkPolicy isolation" },
];

const EVENT_TYPES: RRV2EventType[] = ["admission", "runtime", "scan", "compliance", "*"];

function emptyRule(): Omit<ResponseRuleV2, "id" | "created_at" | "updated_at"> {
  return {
    name: "",
    description: "",
    enabled: true,
    event_type: "runtime",
    conditions: [{ type: "name", value: ".*" }],
    actions: [{ kind: "notify", target: "slack" }],
    workload_match: {},
  };
}

export function ResponseRulesPage() {
  const qc = useQueryClient();
  // Cluster-scoped config: rules created in cluster mode are tagged with the
  // cluster_id on the server; the list query filters to "matches this cluster
  // OR org-wide (NULL)" so the user sees what actually applies here.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const q = useQuery({
    queryKey: ["response-rules-v2", clusterId],
    queryFn: () => responseRulesV2.list({ cluster_id: clusterId }),
  });
  const rules = useMemo(() => q.data?.rules ?? [], [q.data]);
  const [editing, setEditing] = useState<Omit<ResponseRuleV2, "id" | "created_at" | "updated_at"> & { id?: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!editing && rules.length === 0) {
      // no auto-open
    }
  }, [editing, rules]);

  const saveMut = useMutation({
    mutationFn: async () => {
      if (!editing) return;
      setError(null);
      const body = { ...editing };
      delete (body as { id?: string }).id;
      if (editing.id) {
        await responseRulesV2.update(editing.id, body);
      } else {
        await responseRulesV2.create(body, { cluster_id: clusterId });
      }
    },
    onSuccess: () => {
      setEditing(null);
      void qc.invalidateQueries({ queryKey: ["response-rules-v2", clusterId] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const delMut = useMutation({
    mutationFn: async (id: string) => responseRulesV2.delete(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["response-rules-v2", clusterId] }),
  });

  const columns: Column<ResponseRuleV2>[] = [
    { id: "name", header: "Name", cell: (r) => <span className="font-medium">{r.name}</span> },
    { id: "event_type", header: "Event type", cell: (r) => <span className="text-xs">{r.event_type}</span> },
    { id: "conditions", header: "Conditions", cell: (r) => <span className="text-xs text-muted-foreground">{r.conditions.length} clause(s)</span> },
    { id: "actions", header: "Actions", cell: (r) => <span className="text-xs text-muted-foreground">{r.actions.map((a) => a.kind).join(", ")}</span> },
    { id: "enabled", header: "Enabled", cell: (r) => <span className="text-xs">{r.enabled ? "yes" : "no"}</span> },
    {
      id: "row-actions",
      header: "",
      cell: (r) => (
        <div className="flex items-center justify-end gap-1">
          <button
            type="button"
            onClick={() => setEditing({ ...r })}
            className="rounded-md px-2 py-1 text-xs hover:bg-accent"
          >
            Edit
          </button>
          <button
            type="button"
            onClick={() => {
              if (window.confirm(`Delete rule "${r.name}"?`)) delMut.mutate(r.id);
            }}
            className="rounded-md p-1 text-xs hover:bg-accent"
            aria-label="Delete"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ),
    },
  ];

  if (clusterLoading) {
    return <p className="text-sm text-muted-foreground" data-testid="response-rules-loading">Loading cluster…</p>;
  }

  return (
    <div className="space-y-4" data-testid="response-rules-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Response Rules"
        description="Match incoming events to automatic actions — notify a channel, open a ticket, or quarantine/isolate a workload — when the conditions you define all hold."
        actions={
          <button
            type="button"
            onClick={() => setEditing(emptyRule())}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
          >
            <Plus className="h-3.5 w-3.5" /> New rule
          </button>
        }
      />

      <section className="grid grid-cols-3 gap-3">
        <StatCard label="Rules" value={rules.length} />
        <StatCard label="Enabled" value={rules.filter((r) => r.enabled).length} tone="accent" />
        <StatCard label="Disabled" value={rules.filter((r) => !r.enabled).length} />
      </section>

      <DataTable
        rows={rules}
        columns={columns}
        rowKey={(r) => r.id}
        showDensityToggle={false}
        emptyState={
          q.isPending ? (
            <div className="py-6" />
          ) : (
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              No response rules yet. Click "New rule" to create your first.
            </div>
          )
        }
      />

      <Drawer
        open={!!editing}
        onOpenChange={(o) => {
          if (!o) {
            setEditing(null);
            setError(null);
          }
        }}
        width="xl"
      >
        {editing && (
          <RuleEditor
            rule={editing}
            onChange={setEditing}
            onSave={() => saveMut.mutate()}
            onCancel={() => {
              setEditing(null);
              setError(null);
            }}
            error={error}
            saving={saveMut.isPending}
          />
        )}
      </Drawer>
    </div>
  );
}

function RuleEditor({
  rule,
  onChange,
  onSave,
  onCancel,
  error,
  saving,
}: {
  rule: Omit<ResponseRuleV2, "id" | "created_at" | "updated_at"> & { id?: string };
  onChange: (r: Omit<ResponseRuleV2, "id" | "created_at" | "updated_at"> & { id?: string }) => void;
  onSave: () => void;
  onCancel: () => void;
  error: string | null;
  saving: boolean;
}) {
  const setCond = (idx: number, c: RRV2Condition) => {
    const next = [...rule.conditions];
    next[idx] = c;
    onChange({ ...rule, conditions: next });
  };
  const setAct = (idx: number, a: RRV2Action) => {
    const next = [...rule.actions];
    next[idx] = a;
    onChange({ ...rule, actions: next });
  };

  return (
    <section className="rounded-lg border border-border bg-card p-4 space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">{rule.id ? "Edit rule" : "New rule"}</h2>
          <p className="text-xs text-muted-foreground">Guided builder for the response condition catalog</p>
        </div>
        <button type="button" onClick={onCancel} className="rounded-md p-1 hover:bg-accent" aria-label="Close">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="text-xs">
          <div className="mb-1 text-muted-foreground">Name</div>
          <input
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            value={rule.name}
            onChange={(e) => onChange({ ...rule, name: e.target.value })}
          />
        </label>
        <label className="text-xs">
          <div className="mb-1 text-muted-foreground">Event type</div>
          <select
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            value={rule.event_type}
            onChange={(e) => onChange({ ...rule, event_type: e.target.value as RRV2EventType })}
          >
            {EVENT_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </label>
        <label className="col-span-full text-xs">
          <div className="mb-1 text-muted-foreground">Description</div>
          <input
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            value={rule.description}
            onChange={(e) => onChange({ ...rule, description: e.target.value })}
          />
        </label>
        <label className="text-xs">
          <div className="mb-1 text-muted-foreground">Enabled</div>
          <input
            type="checkbox"
            className="h-4 w-4"
            checked={rule.enabled}
            onChange={(e) => onChange({ ...rule, enabled: e.target.checked })}
          />
        </label>
      </div>

      <fieldset className="space-y-2 rounded-md border border-border p-3">
        <legend className="px-1 text-xs font-medium uppercase text-muted-foreground">Conditions (AND)</legend>
        {rule.conditions.map((c, i) => (
          <div key={i} className="flex gap-2">
            <select
              className="w-44 rounded-md border border-border bg-background px-2 py-1.5 text-xs"
              value={c.type}
              onChange={(e) => setCond(i, { ...c, type: e.target.value as RRV2CondType })}
            >
              {COND_TYPES.map((ct) => (
                <option key={ct.id} value={ct.id}>{ct.label}</option>
              ))}
            </select>
            <input
              className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs font-mono"
              value={c.value}
              placeholder={COND_TYPES.find((ct) => ct.id === c.type)?.help}
              onChange={(e) => setCond(i, { ...c, value: e.target.value })}
            />
            <button
              type="button"
              onClick={() => onChange({ ...rule, conditions: rule.conditions.filter((_, j) => j !== i) })}
              className="rounded-md p-1 hover:bg-accent"
              aria-label="Remove condition"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
        <button
          type="button"
          onClick={() => onChange({ ...rule, conditions: [...rule.conditions, { type: "name", value: ".*" }] })}
          className="text-xs text-primary hover:underline"
        >
          + Add condition
        </button>
      </fieldset>

      <fieldset className="space-y-2 rounded-md border border-border p-3">
        <legend className="px-1 text-xs font-medium uppercase text-muted-foreground">Actions</legend>
        {rule.actions.map((a, i) => (
          <div key={i} className="flex gap-2">
            <select
              className="w-44 rounded-md border border-border bg-background px-2 py-1.5 text-xs"
              value={a.kind}
              onChange={(e) => setAct(i, { ...a, kind: e.target.value as RRV2ActionKind })}
            >
              {ACTION_KINDS.map((ak) => (
                <option key={ak.id} value={ak.id}>{ak.label}</option>
              ))}
            </select>
            {(a.kind === "notify" || a.kind === "ticket") && (
              <input
                className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                placeholder="receiver name (e.g. slack, pagerduty, jira)"
                value={a.target ?? ""}
                onChange={(e) => setAct(i, { ...a, target: e.target.value })}
              />
            )}
            <button
              type="button"
              onClick={() => onChange({ ...rule, actions: rule.actions.filter((_, j) => j !== i) })}
              className="rounded-md p-1 hover:bg-accent"
              aria-label="Remove action"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
        <button
          type="button"
          onClick={() => onChange({ ...rule, actions: [...rule.actions, { kind: "notify", target: "slack" }] })}
          className="text-xs text-primary hover:underline"
        >
          + Add action
        </button>
      </fieldset>

      <fieldset className="space-y-2 rounded-md border border-border p-3">
        <legend className="px-1 text-xs font-medium uppercase text-muted-foreground">Workload selector</legend>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <input
            className="rounded-md border border-border bg-background px-2 py-1.5 text-xs"
            placeholder="cluster (optional)"
            value={rule.workload_match.cluster ?? ""}
            onChange={(e) => onChange({ ...rule, workload_match: { ...rule.workload_match, cluster: e.target.value } })}
          />
          <input
            className="rounded-md border border-border bg-background px-2 py-1.5 text-xs"
            placeholder="namespace (optional)"
            value={rule.workload_match.namespace ?? ""}
            onChange={(e) => onChange({ ...rule, workload_match: { ...rule.workload_match, namespace: e.target.value } })}
          />
        </div>
      </fieldset>

      {error && <p className="text-xs text-status-error">{error}</p>}

      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-accent"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={saving || !rule.name}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          <Save className="h-3.5 w-3.5" /> {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </section>
  );
}
