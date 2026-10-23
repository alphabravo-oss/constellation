import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { FileCheck2, Plus, Pencil, Power, PowerOff, ShieldCheck, Trash2 } from "lucide-react";

import { componentsInventory, policies as policiesApi, type AdmissionCriterionOption, type AdmissionRuleRow, type AdmissionState } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card, DetailRow } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { TextInput } from "@/components/ui/form";
import { VerdictBanner, type VerdictStatus } from "@/components/ui/verdict-banner";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { StatusPill } from "@/components/ui/status-pill";
import { admissionDryRunHistoryKey, admissionDryRunHistoryEntryFromRow, admissionWebhookHealth, appendAdmissionDryRunHistory, makeAdmissionDryRunHistoryEntry, mergeAdmissionDryRunHistory, readAdmissionDryRunHistory, writeAdmissionDryRunHistory, type AdmissionDryRunHistoryEntry as DryRunHistoryEntry } from "@/lib/admission-ops";

export function AdmissionPage() {
  const { clusterId } = useCluster();
  return <AdmissionWorkspace key={clusterId ?? "none"} clusterId={clusterId} />;
}

function AdmissionWorkspace({ clusterId }: { clusterId?: string }) {
  const [requestedTab, setTab] = useTabParam("tab", "rules");
  const tab = ["rules", "assessment", "catalog", "webhook"].includes(requestedTab) ? requestedTab : "rules";
  const navigate = useNavigate();
  const qc = useQueryClient();
  const params = { cluster_id: clusterId };

  const stateQ = useQuery({
    queryKey: ["admission-state", clusterId],
    queryFn: () => policiesApi.admissionState(params),
    enabled: !!clusterId,
  });
  const rulesQ = useQuery({
    queryKey: ["admission-rules", clusterId],
    queryFn: () => policiesApi.admissionRules(params),
    enabled: !!clusterId,
  });
  const optionsQ = useQuery({ queryKey: ["admission-options"], queryFn: () => policiesApi.admissionOptions() });
  const admissionComponentsQ = useQuery({
    queryKey: ["components", "admission", clusterId],
    queryFn: () => componentsInventory.list({ cluster_id: clusterId, component: "admission", limit: 20 }),
    enabled: !!clusterId,
  });
  const serverDryRunHistoryQ = useQuery({
    queryKey: ["admission-dry-run-history", clusterId],
    queryFn: () => policiesApi.admissionDryRunHistory({ ...params, limit: 50 }),
    enabled: !!clusterId,
  });

  const invalidateRules = () => {
    void qc.invalidateQueries({ queryKey: ["admission-rules"] });
    void qc.invalidateQueries({ queryKey: ["policies"] });
  };
  const toggleRule = useMutation({
    mutationFn: (rule: AdmissionRuleRow) => policiesApi.update(rule.id, { enabled: !rule.enabled }),
    onSuccess: invalidateRules,
  });
  const deleteRule = useMutation({
    mutationFn: (id: string) => policiesApi.delete(id),
    onSuccess: invalidateRules,
  });

  const state = stateQ.data;
  const historyKey = admissionDryRunHistoryKey(clusterId);
  const [image, setImage] = useState("");
  const [namespace, setNamespace] = useState("");
  const [dryRunHistory, setDryRunHistory] = useState<DryRunHistoryEntry[]>(() => readAdmissionDryRunHistory(historyKey));
  useEffect(() => {
    setDryRunHistory(readAdmissionDryRunHistory(historyKey));
  }, [historyKey]);
  const clearLocalDryRunHistory = () => {
    writeAdmissionDryRunHistory(historyKey, []);
    setDryRunHistory([]);
  };
  const clearDryRunHistory = useMutation({
    mutationFn: () => policiesApi.clearAdmissionDryRunHistory(params),
    onSuccess: () => {
      clearLocalDryRunHistory();
      void qc.invalidateQueries({ queryKey: ["admission-dry-run-history", clusterId] });
    },
  });
  const assess = useMutation({
    mutationFn: () => policiesApi.assess({ image: image.trim(), namespace: namespace.trim() || undefined }, params),
    onSuccess: (result) => {
      const outcome = state ? admissionOutcome(state, result.decision) : { current: labelCase(result.decision), protect: labelCase(result.decision) };
      const entry = makeAdmissionDryRunHistoryEntry({
        result,
        image,
        namespace,
        clusterId,
        currentOutcome: outcome.current,
        protectOutcome: outcome.protect,
      });
      setDryRunHistory((current) => {
        const next = appendAdmissionDryRunHistory(current, entry);
        writeAdmissionDryRunHistory(historyKey, next);
        return next;
      });
      void qc.invalidateQueries({ queryKey: ["admission-dry-run-history", clusterId] });
    },
  });
  const rules = useMemo(() => rulesQ.data?.rules ?? [], [rulesQ.data?.rules]);
  const criteria = useMemo(() => optionsQ.data?.criteria ?? [], [optionsQ.data?.criteria]);
  const admissionComponents = useMemo(() => admissionComponentsQ.data?.components ?? [], [admissionComponentsQ.data?.components]);
  const webhookHealth = useMemo(() => admissionWebhookHealth(admissionComponents), [admissionComponents]);
  const groupedCriteria = useMemo(() => groupCriteria(criteria), [criteria]);
  const ruleStats = useMemo(() => summarizeRules(rules), [rules]);
  const serverDryRunHistory = useMemo(
    () => (serverDryRunHistoryQ.data?.history ?? []).map(admissionDryRunHistoryEntryFromRow),
    [serverDryRunHistoryQ.data?.history],
  );
  const mergedDryRunHistory = useMemo(
    () => mergeAdmissionDryRunHistory(serverDryRunHistory, dryRunHistory),
    [serverDryRunHistory, dryRunHistory],
  );
  const verdict = stateQ.isError ? { status: "degraded" as const, title: "Admission state could not be refreshed", detail: "Retry before relying on the displayed configuration." } : admissionVerdict(state);
  const dryRunOutcome = state && assess.data ? admissionOutcome(state, assess.data.decision) : null;

  const ruleColumns = useMemo<Column<AdmissionRuleRow>[]>(
    () => [
      {
        id: "rule", exportValue: rule => rule.name,
        header: "Rule", kind: "name",
        cell: (rule) => (
          <div className="min-w-0">
            <div className="font-medium text-foreground" title={rule.name}>{rule.name}</div>
            <div className="mt-0.5 text-micro  text-muted-foreground">{rule.category || "admission"}</div>
          </div>
        ),
        sort: (a, b) => a.name.localeCompare(b.name),
      },
      {
        id: "status", exportValue: rule => rule.enabled ? "enabled" : "disabled",
        header: "State", kind: "status",

        cell: (rule) => <StatusPill label={rule.enabled ? "enabled" : "disabled"} tone={rule.enabled ? "success" : "neutral"} />,
        sort: (a, b) => Number(a.enabled) - Number(b.enabled),
      },
      {
        id: "group", exportValue: rule => rule.group || "Any group",
        header: "Group", kind: "text", code: true, size: 176, minSize: 128, maxSize: 240,

        cell: (rule) => rule.group ? (
          <span className="inline-flex max-w-full rounded bg-muted px-1.5 py-px font-mono text-micro text-muted-foreground" title={rule.group}>
            {rule.group}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">Any group</span>
        ),
        sort: (a, b) => (a.group ?? "").localeCompare(b.group ?? ""),
      },
      {
        id: "mode", exportValue: rule => rule.mode,
        header: "Mode", kind: "status",

        cell: (rule) => <RuleModePill mode={rule.mode} />,
        sort: (a, b) => a.mode.localeCompare(b.mode),
      },
      {
        id: "action", exportValue: rule => rule.action,
        header: "Action", kind: "status",

        cell: (rule) => <ActionPill action={rule.action} />,
        sort: (a, b) => a.action.localeCompare(b.action),
      },
      {
        id: "criteria", exportValue: rule => rule.criteria.join("; "),
        header: "Criteria", kind: "text", size: 264, minSize: 192, maxSize: 360, wrap: true,
        cell: (rule) => (
          rule.criteria.length === 0 ? (
            <span className="text-xs text-muted-foreground">No parsed criteria</span>
          ) : (
            <span className="flex flex-wrap gap-1">
              {rule.criteria.map((criterion, index) => (
                <span key={`${rule.id}-${index}`} className="rounded bg-muted px-1.5 py-px text-micro text-muted-foreground">
                  {criterion}
                </span>
              ))}
            </span>
          )
        ),
      },
      {
        id: "actions", exportable: false,
        header: "", kind: "actions", size: 112, minSize: 112, maxSize: 128,

        cell: (rule) => {
          const busy = toggleRule.isPending || deleteRule.isPending;
          return (
            <div className="flex items-center justify-end gap-1">
              <Link to="." href={`/clusters/${clusterId}/policies/${rule.id}?from=admission`} aria-label={`Edit ${rule.name}`} className="rounded p-1 hover:bg-accent"><Pencil className="h-3.5 w-3.5" /></Link>
              <button
                type="button"
                title={rule.enabled ? "Disable" : "Enable"}
                disabled={busy}
                onClick={() => toggleRule.mutate(rule)}
                className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-40"
              >
                {rule.enabled ? <PowerOff className="h-3.5 w-3.5" /> : <Power className="h-3.5 w-3.5" />}
              </button>
              <button
                type="button"
                title="Delete"
                disabled={busy}
                onClick={() => deleteRule.mutate(rule.id)}
                className="rounded p-1 text-status-error hover:bg-accent disabled:opacity-40"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          );
        },
      },
    ],
    [clusterId, deleteRule, toggleRule],
  );

  const criteriaColumns = useMemo<Column<AdmissionCriterionOption>[]>(
    () => [
      {
        id: "criterion",
        header: "Criterion", kind: "name", wrap: true,
        cell: (option) => (
          <div className="min-w-0">
            <div className="font-medium text-foreground">{option.label}</div>
            <div className="mt-0.5 font-mono text-micro text-muted-foreground">{option.key}</div>
          </div>
        ),
        sort: (a, b) => a.label.localeCompare(b.label),
      },
      {
        id: "family",
        header: "Family", kind: "badge", size: 152, minSize: 144, maxSize: 184,

        cell: (option) => <StatusPill label={criterionFamily(option.key)} tone="info" />,
        sort: (a, b) => criterionFamily(a.key).localeCompare(criterionFamily(b.key)),
      },
      {
        id: "value",
        header: "Input", kind: "version", size: 128, minSize: 104, maxSize: 176,

        cell: (option) => <span className="font-mono text-xs text-muted-foreground">{option.value_type}</span>,
        sort: (a, b) => a.value_type.localeCompare(b.value_type),
      },
      {
        id: "notes",
        header: "Notes", kind: "text", size: 280, minSize: 176, maxSize: 400, wrap: true,
        cell: (option) => <span className="text-xs text-muted-foreground">{option.help}</span>,
      },
    ],
    [],
  );

  const historyColumns = useMemo<Column<DryRunHistoryEntry>[]>(
    () => [
      {
        id: "time", exportValue: entry => entry.assessed_at,
        header: "Assessed", kind: "date", size: 224, minSize: 208, maxSize: 240,

        cell: (entry) => <span className="text-xs text-muted-foreground">{formatDateTime(entry.assessed_at)}</span>,
        sort: (a, b) => a.assessed_at.localeCompare(b.assessed_at),
      },
      {
        id: "image", exportValue: entry => `${entry.image} (namespace: ${entry.namespace || "not reported"})`,
        header: "Image", kind: "name", code: true,
        cell: (entry) => (
          <div className="min-w-0">
            <div className="font-mono text-xs text-foreground" title={entry.image}>{entry.image}</div>
            <div className="mt-0.5 text-micro text-muted-foreground">{entry.namespace}</div>
          </div>
        ),
        sort: (a, b) => a.image.localeCompare(b.image),
      },
      {
        id: "decision", exportValue: entry => entry.decision,
        header: "Decision", kind: "status",

        cell: (entry) => <ActionPill action={entry.decision} />,
        sort: (a, b) => a.decision.localeCompare(b.decision),
      },
      {
        id: "current", exportValue: entry => entry.current_outcome,
        header: "Current", kind: "status",

        cell: (entry) => <OutcomePill outcome={entry.current_outcome} />,
        sort: (a, b) => a.current_outcome.localeCompare(b.current_outcome),
      },
      {
        id: "protect", exportValue: entry => entry.protect_outcome,
        header: "Protect", kind: "status",

        cell: (entry) => <OutcomePill outcome={entry.protect_outcome} />,
        sort: (a, b) => a.protect_outcome.localeCompare(b.protect_outcome),
      },
      {
        id: "matches", exportValue: entry => entry.matches,
        header: "Matches", kind: "count",

        numeric: true,
        cell: (entry) => entry.matches.toLocaleString(),
        sort: (a, b) => a.matches - b.matches,
      },
    ],
    [],
  );

  const rulesView = (
      <Card
        title="Compiled for the webhook"
        padded={false}
        action={
          <Button size="sm" variant="primary" onClick={() => navigate({ href: `${clusterId ? `/clusters/${clusterId}` : ""}/admission/new` })}>
            <Plus className="h-3.5 w-3.5" /> Add rule
          </Button>
        }
      >
        {(toggleRule.isError || deleteRule.isError) && <ErrorState title="Could not update this admission rule. try again." />}
        {rulesQ.isError ? <ErrorState title="Could not load admission rules." action={<Button onClick={() => void rulesQ.refetch()}>Retry</Button>} /> : rulesQ.isPending ? <LoadingState label="Loading admission rules…" /> : <DataTable<AdmissionRuleRow>
          rows={rules}
          columns={ruleColumns}
          rowKey={(rule) => rule.id}
          preferencesKey="admission-rules"
          exportFileName="constellation-admission-rules" exportLabel="Export listed rules CSV"
          testId="admission-rule-table"
          emptyState={
            <div className="px-6 py-10 text-center text-xs text-muted-foreground">
              No admission rules yet. Use the profile templates or create a custom rule.
            </div>
          }
        />}
      </Card>

  );
  const catalogView = (
        <Card title="Criteria catalog" description="Supported rule-builder criteria." padded={false}>
          {optionsQ.isError && <ErrorState title="Could not load criteria." action={<Button onClick={() => void optionsQ.refetch()}>Retry</Button>} />}
          <div className="border-b border-border p-4" data-testid="admission-options-catalog">
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              {groupedCriteria.map((group) => (
                <div key={group.family} className="rounded-md border border-border bg-background px-3 py-2">
                  <div className="text-micro  text-muted-foreground">{group.family}</div>
                  <div className="mt-1 text-lg font-semibold tabular-nums text-foreground">{group.count}</div>
                </div>
              ))}
            </div>
          </div>
          <DataTable<AdmissionCriterionOption>
            rows={criteria}
            columns={criteriaColumns}
            rowKey={(option) => option.key}
            density="compact"
            showDensityToggle={false}
            emptyState={<div className="px-6 py-10 text-center text-xs text-muted-foreground">No criteria returned.</div>}
          />
        </Card>

  );
  const webhookView = (
        <Card title="Webhook details" description="Current admission-control fields." bodyClassName="p-5">
          {stateQ.isError ? <ErrorState title="Could not load admission state." action={<Button onClick={() => void stateQ.refetch()}>Retry</Button>} /> : state ? (
            <dl className="divide-y divide-border">
              <DetailRow label="Cluster" mono>{state.cluster_id}</DetailRow>
              {admissionComponentsQ.isError && <DetailRow label="Status">Component health could not be loaded.</DetailRow>}
              <DetailRow label="Liveness"><StatusPill label={webhookHealth.label} tone={webhookHealth.tone} /></DetailRow>
              <DetailRow label="Instances">{webhookHealth.instances} observed / {webhookHealth.healthy} healthy</DetailRow>
              <DetailRow label="Last heartbeat">{formatDateTime(webhookHealth.latestSeenAt)}</DetailRow>
              <DetailRow label="Applied revision" mono>{webhookHealth.appliedRevision || "-"}</DetailRow>
              {webhookHealth.lastError ? <DetailRow label="Last component error">{webhookHealth.lastError}</DetailRow> : null}
              <DetailRow label="Enabled"><StatusPill label={state.enabled ? "enabled" : "disabled"} tone={state.enabled ? "success" : "neutral"} /></DetailRow>
              <DetailRow label="Mode"><RuleModePill mode={state.mode} /></DetailRow>
              <DetailRow label="Default action"><ActionPill action={state.default_action} /></DetailRow>
              <DetailRow label="Failure policy">
                <StatusPill label={state.failure_policy === "fail" ? "fail closed" : "fail open"} tone={state.failure_policy === "fail" ? "success" : "warning"} />
              </DetailRow>
              <DetailRow label="Updated">{formatDateTime(state.updated_at)}</DetailRow>
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground">Loading...</p>
          )}
        </Card>
  );
  const assessmentView = (
      <Card title="Dry-run assessment" description="Evaluate an image against the current admission ruleset.">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (image.trim() && !assess.isPending) assess.mutate();
          }}
        >
          <div className="min-w-[260px] flex-1">
            <label className="mb-1 block text-micro  text-muted-foreground" htmlFor="admission-assess-image">Image</label>
            <TextInput id="admission-assess-image" placeholder="ghcr.io/org/app:1.2.3" value={image} disabled={assess.isPending} onChange={(event) => { assess.reset(); setImage(event.target.value); }} />
          </div>
          <div className="w-[180px]">
            <label className="mb-1 block text-micro  text-muted-foreground" htmlFor="admission-assess-namespace">Namespace</label>
            <TextInput id="admission-assess-namespace" placeholder="default" value={namespace} disabled={assess.isPending} onChange={(event) => { assess.reset(); setNamespace(event.target.value); }} />
          </div>
          <Button type="submit" variant="primary" size="sm" disabled={!image.trim() || assess.isPending}>
            {assess.isPending ? "Assessing..." : "Assess"}
          </Button>
        </form>

        {assess.data ? (
          <div className="mt-4 space-y-4">
            <StatGrid data-testid="admission-dry-run-diff">
              <StatCard
                label="Rule decision"
                value={labelCase(assess.data.decision)}
                tone={assess.data.decision === "deny" ? "critical" : "low"}
                icon={<ShieldCheck className="h-3.5 w-3.5" />}
                hint={`matcher mode ${assess.data.enforcement_mode || "none"}`}
              />
              <StatCard
                label="Current outcome"
                value={dryRunOutcome?.current ?? "..."}
                tone={dryRunOutcome?.current === "Block" ? "critical" : dryRunOutcome?.current === "Admit + log" ? "medium" : "low"}
                icon={<FileCheck2 className="h-3.5 w-3.5" />}
                hint={state ? `${labelCase(state.mode)} / default ${state.default_action}` : "loading state"}
              />
              <StatCard
                label="Protect outcome"
                value={dryRunOutcome?.protect ?? "..."}
                tone={dryRunOutcome?.protect === "Block" ? "critical" : "low"}
                icon={<Power className="h-3.5 w-3.5" />}
                hint="if protect is enabled"
              />
            </StatGrid>
            {assess.data.matches.length === 0 ? (
              <p className="text-xs text-muted-foreground">No admission rules matched.</p>
            ) : (
              <DataTable
                rows={assess.data.matches}
                columns={[
                  {
                    id: "rule",
                    header: "Rule", kind: "name",
                    cell: (match) => <span className="font-mono text-xs">{String(match.policy_name ?? match.rule_id ?? "-")}</span>,
                  },
                  {
                    id: "action",
                    header: "Action", kind: "status",

                    cell: (match) => <ActionPill action={String(match.action ?? "-")} />,
                  },
                  {
                    id: "reason",
                    header: "Reason", kind: "text", size: 320, minSize: 200, maxSize: 480, wrap: true,
                    cell: (match) => <span className="text-xs text-muted-foreground">{String(match.reason ?? "")}</span>,
                  },
                ]}
                rowKey={(match) => String(match.rule_id ?? match.policy_name ?? match.reason ?? match.action ?? "match")}
                density="compact"
                showDensityToggle={false}
              />
            )}
          </div>
        ) : null}
        {assess.isError ? <p className="mt-3 text-sm text-status-error">{errorMessage()}</p> : null}
        {(serverDryRunHistoryQ.isError || clearDryRunHistory.isError) && <ErrorState title="Assessment history could not be refreshed." action={<Button onClick={() => void serverDryRunHistoryQ.refetch()}>Retry</Button>} />}
        {mergedDryRunHistory.length > 0 ? (
          <div className="mt-5 border-t border-border pt-4" data-testid="admission-dry-run-history">
            <div className="mb-2 flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-foreground">Recent assessments</div>
                <div className="text-xs text-muted-foreground">Stored for this cluster.</div>
              </div>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                disabled={clearDryRunHistory.isPending}
                title="Clears up to 1,000 assessments per request. Repeat if history remains."
                onClick={() => {
                  if (serverDryRunHistory.length > 0) {
                    clearDryRunHistory.mutate();
                    return;
                  }
                  clearLocalDryRunHistory();
                }}
              >
                <Trash2 className="h-3.5 w-3.5" />
                Clear
              </Button>
            </div>
            <DataTable<DryRunHistoryEntry>
              rows={mergedDryRunHistory}
              columns={historyColumns}
              rowKey={(entry) => entry.id}
              preferencesKey="admission-dry-run-history"
              exportFileName="admission-dry-run-history" exportLabel="Export loaded history CSV"
            />
          </div>
        ) : null}
      </Card>
  );
  return (
    <div className="space-y-5">
      <PageHeader
        title="Admission rules"
        description="Review admission rules and assess which deployments they would block."
        actions={<div className="flex gap-2"><Button onClick={() => navigate({ href: `/clusters/${clusterId}/admission/settings` })}>Edit admission settings</Button><Button onClick={() => navigate({ href: `/clusters/${clusterId}/admission/import` })}>Import profile</Button></div>}
      />

      <VerdictBanner status={verdict.status} title={verdict.title}  numbers={[{ label: "Webhook", value: !admissionComponentsQ.data ? "—" : webhookHealth.label, tone: (state?.enabled === false ? "warning" : webhookHealth.statTone === "critical" ? "error" : "default"), title: admissionComponentsQ.isError ? "Component health unavailable" : state ? `${state.enabled ? "enabled" : "disabled"} · ${webhookHealth.detail}` : "State unavailable" }, { label: "Mode", value: state?.mode ? labelCase(state.mode) : "—", tone: (state?.mode === "protect" ? "default" : "default"), title: state?.default_action ? `default ${state.default_action}` : "cluster posture" }, { label: "Rules", value: !rulesQ.data ? "—" : ruleStats.total.toLocaleString(), title: rulesQ.data ? `${ruleStats.enabled} enabled / ${ruleStats.disabled} disabled` : "Rules unavailable" }, { label: "Enforce configured", value: !rulesQ.data ? "—" : ruleStats.enforce.toLocaleString(), tone: (ruleStats.enforce > 0 ? "default" : "default"), title: rulesQ.data ? `${ruleStats.monitor} monitor` : "Rules unavailable" }]} detail={<><p>{verdict.detail}</p><p>{"Criteria"}: {!optionsQ.data ? "—" : criteria.length.toLocaleString()}</p></>} />

      

      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "rules", label: "Rules", content: rulesView },
        { value: "assessment", label: "Assessment", content: assessmentView },
        { value: "catalog", label: "Criteria", content: catalogView },
        { value: "webhook", label: "Webhook status", content: webhookView },
      ]} />
    </div>
  );
}

function admissionVerdict(state?: AdmissionState): { status: VerdictStatus; title: string; detail: string } {
  if (!state) {
    return { status: "info", title: "Loading admission state...", detail: "" };
  }
  if (!state.enabled) {
    return {
      status: "degraded",
      title: "Admission control is disabled",
      detail: "The webhook is not gating deployments. Enable it to monitor or block workloads at admission time.",
    };
  }
  if (state.mode === "protect") {
    return {
      status: "ok",
      title: "Admission is configured to protect",
      detail: `Check webhook health and applied revision to confirm delivery. Default action: ${state.default_action}, on webhook failure: ${state.failure_policy}.`,
    };
  }
  return {
    status: "info",
    title: "Admission is configured to monitor",
    detail: `Violations are logged but not blocked. Switch to Protect to enforce. On webhook failure: ${state.failure_policy}.`,
  };
}

function summarizeRules(rules: AdmissionRuleRow[]) {
  return rules.reduce(
    (acc, rule) => {
      acc.total += 1;
      if (rule.enabled) acc.enabled += 1; else acc.disabled += 1;
      if (rule.mode === "enforce") acc.enforce += 1; else acc.monitor += 1;
      if (rule.action === "deny") acc.deny += 1;
      if (rule.action === "allow") acc.allow += 1;
      return acc;
    },
    { total: 0, enabled: 0, disabled: 0, enforce: 0, monitor: 0, deny: 0, allow: 0 },
  );
}

function groupCriteria(criteria: AdmissionCriterionOption[]) {
  const counts = new Map<string, number>();
  for (const option of criteria) {
    const family = criterionFamily(option.key);
    counts.set(family, (counts.get(family) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([family, count]) => ({ family, count }))
    .sort((a, b) => a.family.localeCompare(b.family));
}

function criterionFamily(key: string) {
  if (key === "namespace") return "scope";
  if (key.includes("cve") || key.includes("cvss") || key.includes("severity") || key.includes("fix")) return "vulnerability";
  if (key.includes("registry") || key.includes("digest") || key.includes("tag") || key.includes("image")) return "image";
  if (key.includes("pss") || key.includes("resource")) return "pod";
  return "runtime";
}

function admissionOutcome(state: AdmissionState, decision: string) {
  const denyByRule = decision === "deny";
  const denyByDefault = !denyByRule && state.default_action === "deny";
  const wouldDeny = denyByRule || denyByDefault;
  const current = !state.enabled ? "Admit" : state.mode === "monitor" && wouldDeny ? "Admit + log" : wouldDeny ? "Block" : "Admit";
  return {
    current,
    protect: wouldDeny ? "Block" : "Admit",
  };
}

function RuleModePill({ mode }: { mode: string }) {
  const normalized = mode.toLowerCase();
  const tone =
    normalized === "protect" || normalized === "enforce" ? "success" :
    normalized === "monitor" ? "warning" :
    "neutral";
  return <StatusPill label={labelCase(normalized)} tone={tone} />;
}

function ActionPill({ action }: { action: string }) {
  const normalized = action.toLowerCase();
  const tone =
    normalized === "deny" ? "error" :
    normalized === "allow" ? "success" :
    normalized === "warn" ? "warning" :
    "neutral";
  return <StatusPill label={labelCase(normalized)} tone={tone} />;
}

function OutcomePill({ outcome }: { outcome: string }) {
  const normalized = outcome.toLowerCase();
  const tone =
    normalized.includes("block") ? "error" :
    normalized.includes("log") ? "warning" :
    normalized.includes("admit") ? "success" :
    "neutral";
  return <StatusPill label={outcome || "-"} tone={tone} />;
}

function labelCase(value: string) {
  if (!value) return "-";
  return value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, " ");
}

function formatDateTime(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function errorMessage() {
  return "Request failed. Your inputs are preserved. Try again.";
}
