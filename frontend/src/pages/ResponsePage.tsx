import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, CheckCircle2, RadioTower, Save, ShieldAlert, TestTube2 } from "lucide-react";

import { responseRules, type ResponseRule, type ResponseRuleMode, type ResponseRulePreview } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";

const EVENT_TYPES = ["all", "process", "network", "file", "admission", "dlp"] as const;

export function ResponsePage() {
  const [eventType, setEventType] = useState<(typeof EVENT_TYPES)[number]>("all");
  const [selectedID, setSelectedID] = useState("network-unauthorized-egress");
  const [draftMode, setDraftMode] = useState<ResponseRuleMode>("enforce");
  const [draftEnabled, setDraftEnabled] = useState(true);
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<ResponseRulePreview | null>(null);
  const [actionMessage, setActionMessage] = useState("");
  const queryClient = useQueryClient();
  const q = useQuery({ queryKey: ["response-rules"], queryFn: () => responseRules.list() });
  const rules = useMemo(() => q.data?.rules ?? [], [q.data?.rules]);
  const filtered = useMemo(
    () => (eventType === "all" ? rules : rules.filter((rule) => rule.event_type === eventType)),
    [eventType, rules],
  );
  const selected = useMemo(() => rules.find((rule) => rule.id === selectedID) ?? rules[0], [rules, selectedID]);
  const previewMutation = useMutation({
    mutationFn: () => responseRules.preview(selected.id, { mode: draftMode, enabled: draftEnabled, reason }),
    onSuccess: (data) => {
      setPreview(data.preview);
      setActionMessage("dry-run preview ready");
    },
    onError: (err: Error) => setActionMessage(err.message),
  });
  const saveMutation = useMutation({
    mutationFn: () => responseRules.update(selected.id, { mode: draftMode, enabled: draftEnabled, reason }),
    onSuccess: (data) => {
      setPreview(data.preview);
      setActionMessage("saved and audited");
      void queryClient.invalidateQueries({ queryKey: ["response-rules"] });
    },
    onError: (err: Error) => setActionMessage(err.message),
  });

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading response rules...</p>;
  const selectRule = (rule: ResponseRule) => {
    setSelectedID(rule.id);
    setDraftMode(rule.mode);
    setDraftEnabled(rule.enabled);
    setReason(rule.override_reason ?? "");
    setPreview(null);
    setActionMessage("");
  };

  const columns: Column<ResponseRule>[] = [
    {
      id: "rule",
      header: "Rule",
      className: "max-w-[360px] align-top",
      cell: (rule) => (
        <>
          <button type="button" className="text-left font-medium hover:underline" onClick={() => selectRule(rule)}>
            {rule.name}
          </button>
          <div className="mt-1 text-xs text-muted-foreground">{rule.description}</div>
          <code className="mt-2 block whitespace-normal rounded-md bg-muted px-2 py-1 text-[11px] text-muted-foreground">
            {rule.match}
          </code>
        </>
      ),
    },
    {
      id: "event",
      header: "Event",
      className: "align-top",
      cell: (rule) => <span className="rounded-md border border-border px-2 py-1 text-xs">{rule.event_type}</span>,
    },
    {
      id: "mode",
      header: "Mode",
      className: "align-top",
      cell: (rule) => <ModeBadge mode={rule.mode} />,
    },
    {
      id: "actions",
      header: "Actions",
      className: "align-top",
      cell: (rule) => (
        <div className="flex flex-wrap gap-1">
          {rule.actions.map((action) => (
            <span key={action} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {action}
            </span>
          ))}
        </div>
      ),
    },
    {
      id: "state",
      header: "State",
      className: "align-top",
      cell: (rule) => (
        <>
          <span className={`rounded-md px-2 py-1 text-xs ${rule.enabled ? "bg-status-success/15 text-status-success" : "bg-muted text-muted-foreground"}`}>
            {rule.enabled ? "enabled" : "disabled"}
          </span>
          {rule.managed && <div className="mt-2 text-[11px] text-muted-foreground">managed override</div>}
        </>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Response Rules"
        description="What Constellation does automatically when a runtime event fires — the event it matches, the actions it takes, and whether it only monitors or actively enforces."
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <StatCard label="Rules" value={q.data?.summary.total ?? 0} icon={<BellRing className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Enabled" value={q.data?.summary.enabled ?? 0} tone="accent" icon={<CheckCircle2 className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Monitor" value={q.data?.summary.monitor ?? 0} tone="medium" icon={<RadioTower className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Enforce" value={q.data?.summary.enforce ?? 0} tone="high" icon={<ShieldAlert className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Managed" value={q.data?.summary.managed ?? 0} icon={<Save className="h-3.5 w-3.5" aria-hidden />} />
      </section>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-sm font-medium">Event type</div>
          <div className="flex flex-wrap gap-1" data-testid="response-rule-filters">
            {EVENT_TYPES.map((type) => (
              <button
                key={type}
                type="button"
                onClick={() => setEventType(type)}
                className={`rounded-md border px-2.5 py-1 text-xs transition-colors ${
                  eventType === type
                    ? "border-foreground bg-foreground text-background"
                    : "border-border bg-background text-muted-foreground hover:text-foreground"
                }`}
              >
                {type}
              </button>
            ))}
          </div>
        </div>
      </section>

      <DataTable
        rows={filtered}
        columns={columns}
        rowKey={(rule) => rule.id}
        showDensityToggle={false}
        testId="response-rules-table"
        rowTestId={() => "response-rule-row"}
      />

      {selected && (
        <RuleManager
          rule={selected}
          draftMode={draftMode}
          draftEnabled={draftEnabled}
          reason={reason}
          preview={preview}
          actionMessage={actionMessage}
          pending={previewMutation.isPending || saveMutation.isPending}
          onModeChange={setDraftMode}
          onEnabledChange={setDraftEnabled}
          onReasonChange={setReason}
          onPreview={() => previewMutation.mutate()}
          onSave={() => saveMutation.mutate()}
        />
      )}

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {filtered.map((rule) => (
          <RuleCard key={rule.id} rule={rule} onSelect={() => selectRule(rule)} />
        ))}
      </section>
    </div>
  );
}

function ModeBadge({ mode }: { mode: ResponseRule["mode"] }) {
  const colors = {
    learn: "bg-muted text-muted-foreground",
    monitor: "bg-[color:var(--color-severity-medium)]/15 text-[color:var(--color-severity-medium)]",
    enforce: "bg-[color:var(--color-severity-high)]/15 text-[color:var(--color-severity-high)]",
  };
  return <span className={`rounded-md px-2 py-1 text-xs ${colors[mode]}`}>{mode}</span>;
}

function RuleManager({
  rule,
  draftMode,
  draftEnabled,
  reason,
  preview,
  actionMessage,
  pending,
  onModeChange,
  onEnabledChange,
  onReasonChange,
  onPreview,
  onSave,
}: {
  rule: ResponseRule;
  draftMode: ResponseRuleMode;
  draftEnabled: boolean;
  reason: string;
  preview: ResponseRulePreview | null;
  actionMessage: string;
  pending: boolean;
  onModeChange: (mode: ResponseRuleMode) => void;
  onEnabledChange: (enabled: boolean) => void;
  onReasonChange: (reason: string) => void;
  onPreview: () => void;
  onSave: () => void;
}) {
  return (
    <section className="rounded-lg border border-border bg-card p-4" data-testid="response-rule-manager">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">{rule.name}</h2>
          <p className="mt-1 text-xs text-muted-foreground">{rule.event_type} · {rule.source}</p>
        </div>
        <ModeBadge mode={rule.mode} />
      </div>
      <div className="mt-3 grid gap-3 text-xs">
        <label className="grid gap-1">
          <span className="font-medium">Mode</span>
          <select
            className="rounded-md border border-border bg-background px-2 py-1.5"
            value={draftMode}
            onChange={(event) => onModeChange(event.target.value as ResponseRuleMode)}
            data-testid="response-rule-mode-select"
          >
            <option value="learn">learn</option>
            <option value="monitor">monitor</option>
            <option value="enforce">enforce</option>
          </select>
        </label>
        <label className="flex items-center justify-between gap-3 rounded-md border border-border px-2 py-2">
          <span className="font-medium">Enabled</span>
          <input
            type="checkbox"
            checked={draftEnabled}
            onChange={(event) => onEnabledChange(event.target.checked)}
            data-testid="response-rule-enabled-toggle"
          />
        </label>
        <label className="grid gap-1">
          <span className="font-medium">Change reason</span>
          <textarea
            className="min-h-20 rounded-md border border-border bg-background px-2 py-1.5"
            value={reason}
            onChange={(event) => onReasonChange(event.target.value)}
            data-testid="response-rule-reason"
          />
        </label>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-xs hover:bg-muted disabled:opacity-50"
            onClick={onPreview}
            disabled={pending}
            data-testid="response-rule-preview"
          >
            <TestTube2 className="h-3.5 w-3.5" aria-hidden />
            Preview
          </button>
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded-md bg-foreground px-2.5 py-1.5 text-xs text-background disabled:opacity-50"
            onClick={onSave}
            disabled={pending || reason.trim().length === 0}
            data-testid="response-rule-save"
          >
            <Save className="h-3.5 w-3.5" aria-hidden />
            Save
          </button>
        </div>
      </div>
      {actionMessage && <div className="mt-3 rounded-md border border-border p-2 text-xs text-muted-foreground" data-testid="response-rule-action-state">{actionMessage}</div>}
      {preview && (
        <div className="mt-3 rounded-md border border-border p-3 text-xs" data-testid="response-rule-preview-card">
          <div className="font-medium">Action preview</div>
          <p className="mt-1 text-muted-foreground">{preview.impact}</p>
          <div className="mt-2 font-mono text-[11px] text-muted-foreground">
            {preview.current_mode}/{preview.current_enabled ? "enabled" : "disabled"} -&gt; {preview.next_mode}/{preview.next_enabled ? "enabled" : "disabled"}
          </div>
          {preview.warnings.length > 0 && (
            <ul className="mt-2 space-y-1 text-[11px] text-[color:var(--color-status-warning)]">
              {preview.warnings.map((warning) => <li key={warning}>{warning}</li>)}
            </ul>
          )}
          <div className="mt-2 text-[11px] text-muted-foreground">{preview.persists ? "persists and writes audit" : "dry-run only"}</div>
        </div>
      )}
    </section>
  );
}

function RuleCard({ rule, onSelect }: { rule: ResponseRule; onSelect: () => void }) {
  return (
    <article className="rounded-lg border border-border bg-card p-4" data-testid="response-rule-card">
      <div className="flex items-start justify-between gap-2">
        <div>
          <button type="button" className="text-left text-sm font-semibold hover:underline" onClick={onSelect}>
            {rule.name}
          </button>
          <p className="mt-1 text-xs text-muted-foreground">{rule.source} · {rule.severity}</p>
        </div>
        <ModeBadge mode={rule.mode} />
      </div>
      <p className="mt-3 text-xs text-muted-foreground">{rule.description}</p>
      {rule.managed && <p className="mt-2 text-[11px] text-muted-foreground">{rule.override_reason || "managed override"}</p>}
      <div className="mt-3 flex flex-wrap gap-1">
        {rule.actions.map((action) => (
          <span key={action} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            {action}
          </span>
        ))}
      </div>
    </article>
  );
}
