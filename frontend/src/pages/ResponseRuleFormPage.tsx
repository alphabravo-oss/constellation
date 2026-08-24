// Routes: /clusters/:id/response-rules/new (create) and
// /clusters/:id/response-rules/:ruleId (edit).
//
// Dedicated form page (the Astronomer add/edit-as-a-page pattern, replacing the
// old drawer). Guided builder for a response rule: match incoming events to
// automatic actions (notify / ticket / quarantine / isolate).
import { useEffect, useMemo, useState } from "react";
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
  type RRV2CatalogItem,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { GroupPicker } from "@/components/GroupPicker";

const FALLBACK_COND_TYPES: Array<RRV2CatalogItem & { id: RRV2CondType }> = [
  { id: "name", label: "Event name", help: "Regex against event name or title" },
  { id: "level", label: "Severity ≥", help: "info | low | medium | high | critical" },
  { id: "cve_critical", label: "CVE critical + score floor", help: "Matches when any CVE is critical AND base score ≥ value" },
  { id: "cve_critical_count", label: "Critical CVE count ≥", help: "Integer count" },
  { id: "cve_high_count", label: "High+ CVE count ≥", help: "Integer count" },
  { id: "cve_with_fix_count", label: "Fixable CVE count ≥", help: "Integer count" },
  { id: "cve_max_age_days", label: "Fixable CVE age >", help: "Days" },
  { id: "proc", label: "Process name", help: "Regex against process basename" },
  { id: "event_type", label: "Event type", help: "Event type or alias" },
];

const FALLBACK_ACTION_KINDS: Array<RRV2CatalogItem & { id: RRV2ActionKind }> = [
  { id: "notify", label: "Notify receiver", help: "Send via pkg/notify (slack/jira/pagerduty/etc)" },
  { id: "webhook", label: "Webhook receiver", help: "NeuVector-compatible receiver action" },
  { id: "ticket", label: "Open ticket", help: "Notify via ITSM destination (Jira/SNOW)" },
  { id: "suppress-log", label: "Suppress log", help: "Suppress matching runtime security-event logs" },
  { id: "quarantine", label: "Quarantine workload", help: "Runtime action (requires data plane)" },
  { id: "isolate", label: "Network isolate", help: "NetworkPolicy isolation" },
  { id: "kill", label: "Kill process", help: "Runtime kill action when supported" },
];

const FALLBACK_EVENT_TYPES: Array<{ id: RRV2EventType; label: string; conditions: RRV2CondType[]; actions: RRV2ActionKind[] }> = [
  { id: "*", label: "All events", conditions: FALLBACK_COND_TYPES.map((c) => c.id), actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "security-event", label: "Security event", conditions: ["name", "level", "proc", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "threat", label: "Threat", conditions: ["name", "level", "proc", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "cve-report", label: "CVE report", conditions: ["name", "level", "cve_critical", "cve_critical_count", "cve_high_count", "cve_with_fix_count", "cve_max_age_days", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "admission-control", label: "Admission control", conditions: ["name", "level", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "compliance", label: "Compliance", conditions: ["name", "level", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "runtime", label: "Runtime", conditions: ["name", "level", "proc", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "scan", label: "Scan", conditions: ["name", "level", "cve_critical", "cve_critical_count", "cve_high_count", "cve_with_fix_count", "cve_max_age_days", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "admission", label: "Admission", conditions: ["name", "level", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "event", label: "Event", conditions: ["name", "level", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "activity", label: "Activity", conditions: ["name", "level", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "incident", label: "Incident", conditions: ["name", "level", "proc", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "violation", label: "Violation", conditions: ["name", "level", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "dlp", label: "DLP", conditions: ["name", "level", "proc", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "waf", label: "WAF", conditions: ["name", "level", "proc", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
  { id: "serverless", label: "Serverless", conditions: ["name", "level", "event_type"], actions: FALLBACK_ACTION_KINDS.map((a) => a.id) },
];

type RuleDraft = Omit<ResponseRuleV2, "id" | "priority" | "created_at" | "updated_at"> & { id?: string };

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

function cleanSelector(selector: RuleDraft["workload_match"]): RuleDraft["workload_match"] {
  const next: RuleDraft["workload_match"] = {};
  const cluster = selector.cluster?.trim();
  const namespace = selector.namespace?.trim();
  const group = selector.group?.trim();
  if (cluster) next.cluster = cluster;
  if (namespace) next.namespace = namespace;
  if (group) next.group = group;
  const labels = Object.fromEntries(
    Object.entries(selector.labels ?? {})
      .map(([key, value]) => [key.trim(), value.trim()])
      .filter(([key, value]) => key && value),
  );
  if (Object.keys(labels).length > 0) next.labels = labels;
  return next;
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
  const optionsQ = useQuery({
    queryKey: ["response-rules-v2-options"],
    queryFn: () => responseRulesV2.options(),
  });
  const eventTypes = optionsQ.data?.event_types?.length ? optionsQ.data.event_types : FALLBACK_EVENT_TYPES;
  const conditionCatalog = optionsQ.data?.condition_types?.length ? optionsQ.data.condition_types : FALLBACK_COND_TYPES;
  const actionCatalog = optionsQ.data?.action_kinds?.length ? optionsQ.data.action_kinds : FALLBACK_ACTION_KINDS;
  const receiverOptions = optionsQ.data?.receivers ?? [];
  const selectedEvent = eventTypes.find((ev) => ev.id === rule.event_type);
  const conditionOptions = useMemo(() => {
    const allowed = new Set<RRV2CondType>(selectedEvent?.conditions ?? FALLBACK_COND_TYPES.map((c) => c.id));
    const current = new Set(rule.conditions.map((c) => c.type));
    return conditionCatalog.filter((ct) => allowed.has(ct.id as RRV2CondType) || current.has(ct.id as RRV2CondType));
  }, [conditionCatalog, rule.conditions, selectedEvent?.conditions]);
  const actionOptions = useMemo(() => {
    const allowed = new Set<RRV2ActionKind>(selectedEvent?.actions ?? FALLBACK_ACTION_KINDS.map((a) => a.id));
    const current = new Set(rule.actions.map((a) => a.kind));
    return actionCatalog.filter((ak) => allowed.has(ak.id as RRV2ActionKind) || current.has(ak.id as RRV2ActionKind));
  }, [actionCatalog, rule.actions, selectedEvent?.actions]);

  useEffect(() => {
    if (isEdit && loaded) setRule({ ...loaded });
  }, [isEdit, loaded]);

  const saveMut = useMutation({
    mutationFn: async () => {
      setError(null);
      const body = { ...rule, workload_match: cleanSelector(rule.workload_match) };
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
  const setSelectorField = (key: "cluster" | "namespace" | "group", value: string) => {
    const next = { ...rule.workload_match };
    if (value.trim()) {
      next[key] = value;
    } else {
      delete next[key];
    }
    onChange({ ...rule, workload_match: next });
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
                  {eventTypes.map((t) => (
                    <option key={t.id} value={t.id}>{t.label}</option>
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
                    {conditionOptions.map((ct) => (
                      <option key={ct.id} value={ct.id}>{ct.label}</option>
                    ))}
                  </select>
                  <input
                    className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs font-mono"
                    value={c.value}
                    placeholder={conditionCatalog.find((ct) => ct.id === c.type)?.help}
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
                    {actionOptions.map((ak) => (
                      <option key={ak.id} value={ak.id}>{ak.label}</option>
                    ))}
                  </select>
                  {(a.kind === "notify" || a.kind === "ticket" || a.kind === "webhook") && (
                    receiverOptions.length > 0 ? (
                      <select
                        className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                        value={a.target ?? ""}
                        onChange={(e) => setAct(i, { ...a, target: e.target.value })}
                      >
                        {!a.target && <option value="">Select receiver</option>}
                        {a.target && !receiverOptions.some((r) => r.name === a.target || r.id === a.target) && (
                          <option value={a.target}>{a.target}</option>
                        )}
                        {receiverOptions.map((r) => (
                          <option key={r.id} value={r.name}>{r.name} ({r.kind})</option>
                        ))}
                      </select>
                    ) : (
                    <input
                      className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                      placeholder="receiver name (e.g. slack, pagerduty, jira)"
                      value={a.target ?? ""}
                      onChange={(e) => setAct(i, { ...a, target: e.target.value })}
                    />
                    )
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
                onClick={() => onChange({ ...rule, actions: [...rule.actions, { kind: "notify", target: receiverOptions[0]?.name ?? "" }] })}
                className="text-xs text-primary hover:underline"
              >
                + Add action
              </button>
            </fieldset>

            <fieldset className="space-y-2 rounded-md border border-border p-3">
              <legend className="px-1 text-xs font-medium uppercase text-muted-foreground">Workload selector</legend>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <label className="text-xs">
                  <div className="mb-1 text-muted-foreground">Group</div>
                  <GroupPicker
                    clusterId={clusterId}
                    value={rule.workload_match.group ?? ""}
                    onChange={(value) => setSelectorField("group", value)}
                    allowExternal={false}
                    placeholder="Any group"
                    testId="response-rule-group-picker"
                  />
                </label>
                <label className="text-xs">
                  <div className="mb-1 text-muted-foreground">Namespace</div>
                  <input
                    className="h-9 w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                    placeholder="Any namespace"
                    value={rule.workload_match.namespace ?? ""}
                    onChange={(e) => setSelectorField("namespace", e.target.value)}
                  />
                </label>
                <label className="text-xs">
                  <div className="mb-1 text-muted-foreground">Cluster</div>
                  <input
                    className="h-9 w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                    placeholder="Route cluster"
                    value={rule.workload_match.cluster ?? ""}
                    onChange={(e) => setSelectorField("cluster", e.target.value)}
                  />
                </label>
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
