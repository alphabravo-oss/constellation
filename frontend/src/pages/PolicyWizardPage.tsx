// PolicyWizardPage — multi-step builder for the new boolean policy DSL.
//
// Six steps:
//   1. Identity         — name + description + severity + lifecycle stages
//   2. Scope            — cluster / namespace / label inclusion filters
//   3. Criteria         — visual AND/OR/NOT PolicyGroup tree using the curated
//                         field registry from GET /api/v1/policy/fields
//   4. Exclusions       — deployment/image/namespace + optional expiry date
//   5. Actions          — enforcement mode + action list (notify / block / etc)
//   6. Review           — YAML diff of the assembled policy + Submit
//
// No Formik / zod dependency — state machine is a single useState shape; the
// wizard validates on Next() before advancing. Each step is its own component
// so adding a step later doesn't bloat this file.
import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ChevronLeft, ChevronRight, Plus, Trash2 } from "lucide-react";

import { api, policies } from "@/api/client";
import { PageHeader } from "@/components/ui/page";

// --- DSL types (mirror pkg/policy/dsl) ---
type LifecycleStage = "BUILD" | "DEPLOY" | "RUNTIME";
type Severity = "info" | "low" | "medium" | "high" | "critical";
type BoolOp = "AND" | "OR" | "NOT";

interface Criterion {
  field: string;
  operator: string;
  values: string[];
  negate?: boolean;
}

interface PolicyGroup {
  operator: BoolOp;
  criteria?: Criterion[];
  children?: PolicyGroup[];
}

interface Scope {
  cluster?: string;
  namespace?: string;
  labels?: Record<string, string>;
}

interface Exclusion {
  name?: string;
  deployment?: string;
  image?: string;
  namespace?: string;
  expiration?: string;
}

interface PolicyDraft {
  name: string;
  description: string;
  severity: Severity;
  lifecycle_stages: LifecycleStage[];
  mitre_attack_vectors: string[];
  scopes: Scope[];
  group: PolicyGroup;
  exclusions: Exclusion[];
  enforcement_mode: "monitor" | "enforce";
  actions: string[];
  source: "imperative";
}

interface PolicyField {
  name: string;
  description: string;
  type: "string" | "bool" | "int" | "float" | "enum" | "regex";
  enum_values?: string[];
  scope_applicability: string[];
  category: string;
}

const STEPS = ["Identity", "Scope", "Criteria", "Exclusions", "Actions", "Review"] as const;
type Step = (typeof STEPS)[number];

function initialDraft(): PolicyDraft {
  return {
    name: "",
    description: "",
    severity: "medium",
    lifecycle_stages: ["DEPLOY"],
    mitre_attack_vectors: [],
    scopes: [],
    group: { operator: "AND", criteria: [] },
    exclusions: [],
    enforcement_mode: "monitor",
    actions: ["alert"],
    source: "imperative",
  };
}

export function PolicyWizardPage() {
  const nav = useNavigate();
  const [step, setStep] = useState<Step>("Identity");
  const [draft, setDraft] = useState<PolicyDraft>(initialDraft());

  const fieldsQ = useQuery({
    queryKey: ["policy-fields"],
    queryFn: () => api.get<{ fields: PolicyField[] }>("/policy/fields").then((r) => r.data),
  });
  const fields = fieldsQ.data?.fields ?? [];

  const create = useMutation({
    mutationFn: async () =>
      policies.create({
        name: draft.name,
        description: draft.description,
        engine: "dsl",
        category: "admission",
        spec_yaml: JSON.stringify(draft, null, 2),
        enabled: false,
        mode: draft.enforcement_mode,
      }),
    onSuccess: () => {
      toast.success("Policy created (monitor-mode)");
      nav("/policies");
    },
    onError: (e: unknown) => toast.error(`Create failed: ${(e as Error).message}`),
  });

  const stepIndex = STEPS.indexOf(step);
  function go(dir: number) {
    const next = STEPS[stepIndex + dir];
    if (next) setStep(next);
  }
  function canAdvance(): boolean {
    if (step === "Identity") return draft.name.trim().length > 0 && draft.lifecycle_stages.length > 0;
    if (step === "Criteria") {
      const g = draft.group;
      return (g.criteria?.length ?? 0) + (g.children?.length ?? 0) > 0;
    }
    return true;
  }

  return (
    <div className="space-y-6" data-testid="policy-wizard">
      <PageHeader
        title="Create Policy"
        description="Build a Constellation boolean policy. Coexists with Kyverno / Rego / CEL — pick the engine that best matches your team's authoring style."
      />

      <ol className="flex flex-wrap gap-2 text-xs" data-testid="wizard-steps">
        {STEPS.map((s, i) => (
          <li key={s}>
            <button
              type="button"
              onClick={() => i <= stepIndex && setStep(s)}
              className={`rounded-md border px-2 py-1 ${
                i === stepIndex
                  ? "border-foreground bg-foreground text-background"
                  : i < stepIndex
                    ? "border-border bg-muted text-foreground"
                    : "border-border bg-background text-muted-foreground"
              }`}
            >
              {i + 1}. {s}
            </button>
          </li>
        ))}
      </ol>

      <section className="rounded-lg border border-border bg-card p-4" data-testid={`wizard-step-${step}`}>
        {step === "Identity" && <IdentityStep draft={draft} setDraft={setDraft} />}
        {step === "Scope" && <ScopeStep draft={draft} setDraft={setDraft} />}
        {step === "Criteria" && <CriteriaStep draft={draft} setDraft={setDraft} fields={fields} />}
        {step === "Exclusions" && <ExclusionsStep draft={draft} setDraft={setDraft} />}
        {step === "Actions" && <ActionsStep draft={draft} setDraft={setDraft} />}
        {step === "Review" && <ReviewStep draft={draft} />}
      </section>

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => go(-1)}
          disabled={stepIndex === 0}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs disabled:opacity-40"
        >
          <ChevronLeft className="h-3.5 w-3.5" /> Back
        </button>
        {step !== "Review" ? (
          <button
            type="button"
            onClick={() => go(1)}
            disabled={!canAdvance()}
            className="inline-flex items-center gap-1 rounded-md bg-foreground px-3 py-1.5 text-xs text-background disabled:opacity-40"
            data-testid="wizard-next"
          >
            Next <ChevronRight className="h-3.5 w-3.5" />
          </button>
        ) : (
          <button
            type="button"
            onClick={() => create.mutate()}
            disabled={create.isPending}
            className="rounded-md bg-foreground px-3 py-1.5 text-xs text-background disabled:opacity-40"
            data-testid="wizard-submit"
          >
            Create policy
          </button>
        )}
      </div>
    </div>
  );
}

// ---- step components ----

function IdentityStep({ draft, setDraft }: { draft: PolicyDraft; setDraft: (d: PolicyDraft) => void }) {
  return (
    <div className="space-y-3">
      <Labelled label="Name">
        <input
          value={draft.name}
          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
          data-testid="wizard-name"
        />
      </Labelled>
      <Labelled label="Description">
        <textarea
          value={draft.description}
          onChange={(e) => setDraft({ ...draft, description: e.target.value })}
          rows={2}
          className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
        />
      </Labelled>
      <Labelled label="Severity">
        <select
          value={draft.severity}
          onChange={(e) => setDraft({ ...draft, severity: e.target.value as Severity })}
          className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
        >
          {(["info", "low", "medium", "high", "critical"] as Severity[]).map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </Labelled>
      <Labelled label="Lifecycle stages">
        <div className="flex flex-wrap gap-2 text-xs">
          {(["BUILD", "DEPLOY", "RUNTIME"] as LifecycleStage[]).map((stage) => {
            const on = draft.lifecycle_stages.includes(stage);
            return (
              <label key={stage} className={`rounded-md border px-2 py-1 ${on ? "border-foreground bg-foreground text-background" : "border-border bg-background"}`}>
                <input
                  type="checkbox"
                  checked={on}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      lifecycle_stages: e.target.checked
                        ? [...draft.lifecycle_stages, stage]
                        : draft.lifecycle_stages.filter((s) => s !== stage),
                    })
                  }
                  className="mr-1"
                />
                {stage}
              </label>
            );
          })}
        </div>
      </Labelled>
    </div>
  );
}

function ScopeStep({ draft, setDraft }: { draft: PolicyDraft; setDraft: (d: PolicyDraft) => void }) {
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Scopes restrict where the policy applies. Empty means cluster-wide.
      </p>
      {draft.scopes.map((s, i) => (
        <div key={i} className="grid grid-cols-1 gap-2 rounded-md border border-border bg-background p-3 md:grid-cols-3">
          <input
            placeholder="cluster"
            value={s.cluster ?? ""}
            onChange={(e) => updateScope(draft, setDraft, i, { ...s, cluster: e.target.value })}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
          <input
            placeholder="namespace"
            value={s.namespace ?? ""}
            onChange={(e) => updateScope(draft, setDraft, i, { ...s, namespace: e.target.value })}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
          <input
            placeholder="labels (k=v,k=v)"
            value={Object.entries(s.labels ?? {}).map(([k, v]) => `${k}=${v}`).join(",")}
            onChange={(e) =>
              updateScope(draft, setDraft, i, { ...s, labels: parseLabels(e.target.value) })
            }
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
          <button
            type="button"
            onClick={() => setDraft({ ...draft, scopes: draft.scopes.filter((_, j) => j !== i) })}
            className="inline-flex items-center gap-1 self-start text-[11px] text-muted-foreground hover:text-destructive"
          >
            <Trash2 className="h-3 w-3" /> remove
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() => setDraft({ ...draft, scopes: [...draft.scopes, {}] })}
        className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs hover:bg-accent"
      >
        <Plus className="h-3 w-3" /> add scope
      </button>
    </div>
  );
}

function updateScope(draft: PolicyDraft, setDraft: (d: PolicyDraft) => void, i: number, next: Scope) {
  const copy = draft.scopes.slice();
  copy[i] = next;
  setDraft({ ...draft, scopes: copy });
}

function parseLabels(s: string): Record<string, string> {
  return Object.fromEntries(
    s
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean)
      .map((p) => {
        const idx = p.indexOf("=");
        return idx > -1 ? [p.slice(0, idx), p.slice(idx + 1)] : [p, ""];
      }),
  );
}

function CriteriaStep({
  draft, setDraft, fields,
}: {
  draft: PolicyDraft;
  setDraft: (d: PolicyDraft) => void;
  fields: PolicyField[];
}) {
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Build a Boolean tree of criteria. AND requires every leaf to match; OR requires at least one;
        NOT inverts a single branch.
      </p>
      <GroupBuilder
        group={draft.group}
        onChange={(g) => setDraft({ ...draft, group: g })}
        fields={fields}
        depth={0}
      />
    </div>
  );
}

function GroupBuilder({
  group, onChange, fields, depth,
}: {
  group: PolicyGroup;
  onChange: (g: PolicyGroup) => void;
  fields: PolicyField[];
  depth: number;
}) {
  const useChildren = (group.children?.length ?? 0) > 0;
  return (
    <div
      className="rounded-md border border-border bg-background p-3"
      style={{ marginLeft: depth * 12 }}
      data-testid="group-builder"
    >
      <div className="mb-2 flex items-center gap-2 text-xs">
        <span className="text-muted-foreground">Operator</span>
        <select
          value={group.operator}
          onChange={(e) => onChange({ ...group, operator: e.target.value as BoolOp })}
          className="rounded-md border border-border bg-background px-1.5 py-0.5"
        >
          <option value="AND">AND</option>
          <option value="OR">OR</option>
          <option value="NOT">NOT</option>
        </select>
      </div>
      {!useChildren ? (
        <CriteriaList
          criteria={group.criteria ?? []}
          fields={fields}
          onChange={(c) => onChange({ ...group, criteria: c })}
        />
      ) : (
        <div className="space-y-2">
          {(group.children ?? []).map((c, i) => (
            <GroupBuilder
              key={i}
              group={c}
              onChange={(g) => {
                const next = (group.children ?? []).slice();
                next[i] = g;
                onChange({ ...group, children: next });
              }}
              fields={fields}
              depth={depth + 1}
            />
          ))}
          <button
            type="button"
            onClick={() => onChange({ ...group, children: [...(group.children ?? []), { operator: "AND", criteria: [] }] })}
            className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-[11px] hover:bg-accent"
          >
            <Plus className="h-3 w-3" /> nested group
          </button>
        </div>
      )}
      {!useChildren && depth < 4 && (
        <button
          type="button"
          onClick={() => onChange({ ...group, children: [{ operator: "AND", criteria: group.criteria ?? [] }], criteria: [] })}
          className="mt-2 text-[11px] text-muted-foreground hover:text-foreground"
        >
          + nest as sub-group
        </button>
      )}
    </div>
  );
}

function CriteriaList({
  criteria, fields, onChange,
}: {
  criteria: Criterion[];
  fields: PolicyField[];
  onChange: (c: Criterion[]) => void;
}) {
  return (
    <div className="space-y-2">
      {criteria.map((c, i) => (
        <CriterionRow
          key={i}
          c={c}
          fields={fields}
          onChange={(next) => {
            const copy = criteria.slice();
            copy[i] = next;
            onChange(copy);
          }}
          onRemove={() => onChange(criteria.filter((_, j) => j !== i))}
        />
      ))}
      <button
        type="button"
        onClick={() => onChange([...criteria, { field: fields[0]?.name ?? "", operator: "EQ", values: [""] }])}
        className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-[11px] hover:bg-accent"
        data-testid="criteria-add"
      >
        <Plus className="h-3 w-3" /> add criterion
      </button>
    </div>
  );
}

function CriterionRow({
  c, fields, onChange, onRemove,
}: {
  c: Criterion;
  fields: PolicyField[];
  onChange: (c: Criterion) => void;
  onRemove: () => void;
}) {
  const f = useMemo(() => fields.find((x) => x.name === c.field), [fields, c.field]);
  return (
    <div className="grid grid-cols-1 gap-2 rounded-md border border-border bg-card p-2 md:grid-cols-[2fr_1fr_2fr_auto]">
      <select
        value={c.field}
        onChange={(e) => onChange({ ...c, field: e.target.value })}
        className="rounded-md border border-border bg-background px-1.5 py-1 text-xs"
        data-testid="criterion-field"
      >
        {fields.map((x) => (
          <option key={x.name} value={x.name}>
            {x.name}
          </option>
        ))}
      </select>
      <select
        value={c.operator}
        onChange={(e) => onChange({ ...c, operator: e.target.value })}
        className="rounded-md border border-border bg-background px-1.5 py-1 text-xs"
      >
        {["EQ", "NEQ", "IN", "NOTIN", "CONTAINS", "REGEX", "EXISTS", "GT", "GTE", "LT", "LTE"].map((op) => (
          <option key={op} value={op}>
            {op}
          </option>
        ))}
      </select>
      {f?.type === "enum" && f.enum_values ? (
        <select
          value={c.values[0] ?? ""}
          onChange={(e) => onChange({ ...c, values: [e.target.value] })}
          className="rounded-md border border-border bg-background px-1.5 py-1 text-xs"
        >
          {f.enum_values.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      ) : (
        <input
          value={c.values.join(",")}
          onChange={(e) =>
            onChange({ ...c, values: e.target.value.split(",").map((v) => v.trim()) })
          }
          placeholder={f?.description ?? "value"}
          className="rounded-md border border-border bg-background px-1.5 py-1 text-xs"
        />
      )}
      <button
        type="button"
        onClick={onRemove}
        className="text-muted-foreground hover:text-destructive"
        aria-label="remove criterion"
      >
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

function ExclusionsStep({ draft, setDraft }: { draft: PolicyDraft; setDraft: (d: PolicyDraft) => void }) {
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Exclusions silence the policy for specific deployments / images / namespaces. Expiration is
        a hard cutoff — once past, the exclusion is no longer honored.
      </p>
      {draft.exclusions.map((e, i) => (
        <div key={i} className="grid grid-cols-1 gap-2 rounded-md border border-border bg-background p-3 md:grid-cols-5">
          <input
            placeholder="name"
            value={e.name ?? ""}
            onChange={(ev) => updateExcl(draft, setDraft, i, { ...e, name: ev.target.value })}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
          <input
            placeholder="deployment"
            value={e.deployment ?? ""}
            onChange={(ev) => updateExcl(draft, setDraft, i, { ...e, deployment: ev.target.value })}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
          <input
            placeholder="image substr"
            value={e.image ?? ""}
            onChange={(ev) => updateExcl(draft, setDraft, i, { ...e, image: ev.target.value })}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
          <input
            placeholder="namespace"
            value={e.namespace ?? ""}
            onChange={(ev) => updateExcl(draft, setDraft, i, { ...e, namespace: ev.target.value })}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
          <input
            type="date"
            value={e.expiration?.slice(0, 10) ?? ""}
            onChange={(ev) =>
              updateExcl(draft, setDraft, i, { ...e, expiration: ev.target.value ? `${ev.target.value}T23:59:59Z` : undefined })
            }
            className="rounded-md border border-border bg-background px-2 py-1 text-xs"
          />
        </div>
      ))}
      <button
        type="button"
        onClick={() => setDraft({ ...draft, exclusions: [...draft.exclusions, {}] })}
        className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs hover:bg-accent"
      >
        <Plus className="h-3 w-3" /> add exclusion
      </button>
    </div>
  );
}

function updateExcl(draft: PolicyDraft, setDraft: (d: PolicyDraft) => void, i: number, next: Exclusion) {
  const copy = draft.exclusions.slice();
  copy[i] = next;
  setDraft({ ...draft, exclusions: copy });
}

function ActionsStep({ draft, setDraft }: { draft: PolicyDraft; setDraft: (d: PolicyDraft) => void }) {
  const ACTIONS = ["alert", "block", "scale_down", "open_incident", "notify_slack", "notify_pagerduty"];
  return (
    <div className="space-y-3">
      <Labelled label="Enforcement mode">
        <select
          value={draft.enforcement_mode}
          onChange={(e) => setDraft({ ...draft, enforcement_mode: e.target.value as "monitor" | "enforce" })}
          className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
        >
          <option value="monitor">monitor (no blocking, alerts only)</option>
          <option value="enforce">enforce (block at admission)</option>
        </select>
      </Labelled>
      <Labelled label="Actions">
        <div className="flex flex-wrap gap-2 text-xs">
          {ACTIONS.map((a) => {
            const on = draft.actions.includes(a);
            return (
              <label key={a} className={`rounded-md border px-2 py-1 ${on ? "border-foreground bg-foreground text-background" : "border-border bg-background"}`}>
                <input
                  type="checkbox"
                  checked={on}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      actions: e.target.checked ? [...draft.actions, a] : draft.actions.filter((x) => x !== a),
                    })
                  }
                  className="mr-1"
                />
                {a}
              </label>
            );
          })}
        </div>
      </Labelled>
    </div>
  );
}

function ReviewStep({ draft }: { draft: PolicyDraft }) {
  const yaml = JSON.stringify(draft, null, 2);
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        This is the assembled policy. After Create, the policy is added in <em>monitor</em> mode —
        toggle to <em>enforce</em> from the catalog once you've verified the matches.
      </p>
      <pre
        className="max-h-96 overflow-auto rounded-md bg-muted p-3 font-mono text-[11px]"
        data-testid="wizard-review-yaml"
      >
{yaml}
      </pre>
    </div>
  );
}

function Labelled({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block text-xs">
      <span className="text-muted-foreground">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}
