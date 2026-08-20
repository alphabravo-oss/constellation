// Routes: /clusters/:id/response-rules/new (create) and
// /clusters/:id/response-rules/:ruleId (edit).
//
// Dedicated form page (the Astronomer add/edit-as-a-page pattern, replacing the
// old drawer). Guided builder for a response rule: match incoming events to
// automatic actions (notify / ticket / quarantine / isolate).
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Save, Trash2 } from "lucide-react";

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
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";

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

type RuleDraft = Omit<ResponseRuleV2, "id" | "created_at" | "updated_at"> & { id?: string };

function emptyRule(): RuleDraft {
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

export function ResponseRuleFormPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  // Cluster-scoped config: rules created in cluster mode are tagged with the
  // cluster_id on the server. cluster_id comes from the /clusters/:id parent route.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const { ruleId } = useParams<{ ruleId: string }>();
  const isEdit = Boolean(ruleId);
  const backTo = `/clusters/${clusterId ?? ""}/response-rules`;

  const [rule, setRule] = useState<RuleDraft>(emptyRule());
  const [error, setError] = useState<string | null>(null);

  // No single-rule endpoint — load the list and find the one being edited.
  const q = useQuery({
    queryKey: ["response-rules-v2", clusterId],
    queryFn: () => responseRulesV2.list({ cluster_id: clusterId }),
    enabled: isEdit,
  });
  const loaded = q.data?.rules.find((r) => r.id === ruleId) ?? null;

  useEffect(() => {
    if (isEdit && loaded) setRule({ ...loaded });
  }, [isEdit, loaded]);

  const saveMut = useMutation({
    mutationFn: async () => {
      setError(null);
      const body = { ...rule };
      delete (body as { id?: string }).id;
      if (ruleId) {
        await responseRulesV2.update(ruleId, body);
      } else {
        await responseRulesV2.create(body, { cluster_id: clusterId });
      }
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["response-rules-v2", clusterId] });
      navigate(backTo);
    },
    onError: (err: Error) => setError(err.message),
  });

  const onChange = (r: RuleDraft) => setRule(r);
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

  const notFound = isEdit && !clusterLoading && !q.isLoading && !q.error && !loaded;

  return (
    <div className="space-y-6" data-testid="response-rules-page">
      <PageHeader
        backLink={
          <Link to={backTo} className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Response Rules
          </Link>
        }
        title={isEdit ? "Edit rule" : "New rule"}
        description="Match incoming events to automatic actions — notify a channel, open a ticket, or quarantine/isolate a workload — when the conditions you define all hold."
      />

      {isEdit && (clusterLoading || q.isLoading) ? (
        <Card title="Rule">
          <div className="text-sm text-muted-foreground">Loading rule…</div>
        </Card>
      ) : notFound ? (
        <Card title="Rule">
          <div className="text-sm text-destructive">Response rule not found.</div>
        </Card>
      ) : (
        <Card
          title="Rule"
          description="Guided builder for the response condition catalog."
        >
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              saveMut.mutate();
            }}
          >
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
                onClick={() => navigate(backTo)}
                className="rounded-md border border-border px-3 py-1.5 text-xs hover:bg-accent"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saveMut.isPending || !rule.name}
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                <Save className="h-3.5 w-3.5" /> {saveMut.isPending ? "Saving…" : "Save"}
              </button>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
}
