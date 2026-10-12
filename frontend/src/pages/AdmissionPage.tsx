import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import {
  FileCheck2,
  ListChecks,
  Plus,
  Pencil,
  Power,
  PowerOff,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from "lucide-react";

import {
  componentsInventory,
  policies as policiesApi,
  type AdmissionCriterionOption,
  type AdmissionRuleRow,
  type AdmissionState,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card, DetailRow } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { TextInput } from "@/components/ui/form";
import { VerdictBanner, type VerdictStatus } from "@/components/ui/verdict-banner";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { StatusPill } from "@/components/ui/status-pill";
import {
  admissionDryRunHistoryKey,
  admissionDryRunHistoryEntryFromRow,
  admissionWebhookHealth,
  appendAdmissionDryRunHistory,
  makeAdmissionDryRunHistoryEntry,
  mergeAdmissionDryRunHistory,
  readAdmissionDryRunHistory,
  writeAdmissionDryRunHistory,
  type AdmissionDryRunHistoryEntry as DryRunHistoryEntry,
} from "@/lib/admission-ops";


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
        id: "rule",
        header: "Rule",
        cell: (rule) => (
          <div className="min-w-0">
            <div className="truncate font-medium text-foreground" title={rule.name}>{rule.name}</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{rule.category || "admission"}</div>
          </div>
        ),
        sort: (a, b) => a.name.localeCompare(b.name),
      },
      {
        id: "status",
        header: "State",
        width: "110px",
        cell: (rule) => <StatusPill label={rule.enabled ? "enabled" : "disabled"} tone={rule.enabled ? "success" : "neutral"} />,
        sort: (a, b) => Number(a.enabled) - Number(b.enabled),
      },
      {
        id: "group",
        header: "Group",
        width: "150px",
        cell: (rule) => rule.group ? (
          <span className="inline-flex max-w-full truncate rounded bg-muted px-1.5 py-px font-mono text-[10px] text-muted-foreground" title={rule.group}>
            {rule.group}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">Any group</span>
        ),
        sort: (a, b) => (a.group ?? "").localeCompare(b.group ?? ""),
      },
      {
        id: "mode",
        header: "Mode",
        width: "105px",
        cell: (rule) => <RuleModePill mode={rule.mode} />,
        sort: (a, b) => a.mode.localeCompare(b.mode),
      },
      {
        id: "action",
        header: "Action",
        width: "95px",
        cell: (rule) => <ActionPill action={rule.action} />,
        sort: (a, b) => a.action.localeCompare(b.action),
      },
      {
        id: "criteria",
        header: "Criteria",
        cell: (rule) => (
          rule.criteria.length === 0 ? (
            <span className="text-xs text-muted-foreground">No parsed criteria</span>
          ) : (
            <span className="flex flex-wrap gap-1">
              {rule.criteria.map((criterion, index) => (
                <span key={`${rule.id}-${index}`} className="rounded bg-muted px-1.5 py-px text-[10px] text-muted-foreground">
                  {criterion}
                </span>
              ))}
            </span>
          )
        ),
      },
      {
        id: "actions",
        header: "",
        width: "88px",
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
        header: "Criterion",
        cell: (option) => (
          <div className="min-w-0">
            <div className="font-medium text-foreground">{option.label}</div>
            <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{option.key}</div>
          </div>
        ),
        sort: (a, b) => a.label.localeCompare(b.label),
      },
      {
        id: "family",
        header: "Family",
        width: "130px",
        cell: (option) => <StatusPill label={criterionFamily(option.key)} tone="info" />,
        sort: (a, b) => criterionFamily(a.key).localeCompare(criterionFamily(b.key)),
      },
      {
        id: "value",
        header: "Input",
        width: "120px",
        cell: (option) => <span className="font-mono text-xs text-muted-foreground">{option.value_type}</span>,
        sort: (a, b) => a.value_type.localeCompare(b.value_type),
      },
      {
        id: "notes",
        header: "Notes",
        cell: (option) => <span className="text-xs text-muted-foreground">{option.help}</span>,
      },
    ],
    [],
  );

  const historyColumns = useMemo<Column<DryRunHistoryEntry>[]>(
    () => [
      {
        id: "time",
        header: "Assessed",
        width: "150px",
        cell: (entry) => <span className="text-xs text-muted-foreground">{formatDateTime(entry.assessed_at)}</span>,
        sort: (a, b) => a.assessed_at.localeCompare(b.assessed_at),
      },
      {
        id: "image",
        header: "Image",
        cell: (entry) => (
          <div className="min-w-0">
            <div className="truncate font-mono text-xs text-foreground" title={entry.image}>{entry.image}</div>
            <div className="mt-0.5 text-[10px] text-muted-foreground">{entry.namespace}</div>
          </div>
        ),
        sort: (a, b) => a.image.localeCompare(b.image),
      },
      {
        id: "decision",
        header: "Decision",
        width: "110px",
        cell: (entry) => <ActionPill action={entry.decision} />,
        sort: (a, b) => a.decision.localeCompare(b.decision),
      },
      {
        id: "current",
        header: "Current",
        width: "120px",
        cell: (entry) => <OutcomePill outcome={entry.current_outcome} />,
        sort: (a, b) => a.current_outcome.localeCompare(b.current_outcome),
      },
      {
        id: "protect",
        header: "Protect",
        width: "120px",
        cell: (entry) => <OutcomePill outcome={entry.protect_outcome} />,
        sort: (a, b) => a.protect_outcome.localeCompare(b.protect_outcome),
      },
      {
        id: "matches",
        header: "Matches",
        width: "90px",
        numeric: true,
        cell: (entry) => entry.matches.toLocaleString(),
        sort: (a, b) => a.matches - b.matches,
      },
    ],
    [],
  );

  const rulesView = (
      <Card
        title="Admission Rules"
        description="Admission policies compiled for the webhook."
        padded={false}
        action={
          <Button size="sm" variant="primary" onClick={() => navigate({ href: `${clusterId ? `/clusters/${clusterId}` : ""}/admission/new` })}>
            <Plus className="h-3.5 w-3.5" /> Add rule
          </Button>
        }
      >
        {(toggleRule.isError || deleteRule.isError) && <ErrorState title="Could not update this admission rule. Try again." />}
        {rulesQ.isError ? <ErrorState title="Could not load admission rules." action={<Button onClick={() => void rulesQ.refetch()}>Retry</Button>} /> : rulesQ.isPending ? <LoadingState label="Loading admission rules…" /> : <DataTable<AdmissionRuleRow>
          rows={rules}
          columns={ruleColumns}
          rowKey={(rule) => rule.id}
          preferencesKey="admission-rules"
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
        <Card title="Criteria Catalog" description="Supported rule-builder criteria." padded={false}>
          {optionsQ.isError && <ErrorState title="Could not load criteria." action={<Button onClick={() => void optionsQ.refetch()}>Retry</Button>} />}
          <div className="border-b border-border p-4" data-testid="admission-options-catalog">
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              {groupedCriteria.map((group) => (
                <div key={group.family} className="rounded-md border border-border bg-background px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{group.family}</div>
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
        <Card title="Webhook Details" description="Current admission-control fields." bodyClassName="p-5">
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
      <Card title="Dry-run Assessment" description="Evaluate an image against the current admission ruleset.">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (image.trim() && !assess.isPending) assess.mutate();
          }}
        >
          <div className="min-w-[260px] flex-1">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground" htmlFor="admission-assess-image">Image</label>
            <TextInput id="admission-assess-image" placeholder="ghcr.io/org/app:1.2.3" value={image} disabled={assess.isPending} onChange={(event) => { assess.reset(); setImage(event.target.value); }} />
          </div>
          <div className="w-[180px]">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground" htmlFor="admission-assess-namespace">Namespace</label>
            <TextInput id="admission-assess-namespace" placeholder="default" value={namespace} disabled={assess.isPending} onChange={(event) => { assess.reset(); setNamespace(event.target.value); }} />
          </div>
          <Button type="submit" variant="primary" size="sm" disabled={!image.trim() || assess.isPending}>
            {assess.isPending ? "Assessing..." : "Assess"}
          </Button>
        </form>

        {assess.data ? (
          <div className="mt-4 space-y-4">
            <div className="grid gap-3 md:grid-cols-3" data-testid="admission-dry-run-diff">
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
            </div>
            {assess.data.matches.length === 0 ? (
              <p className="text-xs text-muted-foreground">No admission rules matched.</p>
            ) : (
              <DataTable
                rows={assess.data.matches}
                columns={[
                  {
                    id: "rule",
                    header: "Rule",
                    cell: (match) => <span className="font-mono text-xs">{String(match.policy_name ?? match.rule_id ?? "-")}</span>,
                  },
                  {
                    id: "action",
                    header: "Action",
                    width: "95px",
                    cell: (match) => <ActionPill action={String(match.action ?? "-")} />,
                  },
                  {
                    id: "reason",
                    header: "Reason",
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
              density="compact"
              showDensityToggle={false}
              exportFileName="admission-dry-run-history"
            />
          </div>
        ) : null}
      </Card>
  );
  return (
    <div className="space-y-5">
      <PageHeader
        title="Admission Control"
        description="Review admission rules and assess which deployments they would block."
        actions={<div className="flex gap-2"><Button onClick={() => navigate({ href: `/clusters/${clusterId}/admission/settings` })}>Edit admission settings</Button><Button onClick={() => navigate({ href: `/clusters/${clusterId}/admission/import` })}>Import profile</Button></div>}
      />

      <VerdictBanner status={verdict.status} title={verdict.title} detail={verdict.detail} />

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5" data-testid="admission-summary">
        <StatCard
          label="Webhook"
          value={!admissionComponentsQ.data ? "—" : webhookHealth.label}
          tone={state?.enabled === false ? "medium" : webhookHealth.statTone}
          icon={<ShieldCheck className="h-3.5 w-3.5" />}
          hint={admissionComponentsQ.isError ? "Component health unavailable" : state ? `${state.enabled ? "enabled" : "disabled"} · ${webhookHealth.detail}` : "State unavailable"}
        />
        <StatCard
          label="Mode"
          value={state?.mode ? labelCase(state.mode) : "—"}
          tone={state?.mode === "protect" ? "low" : "accent"}
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
          hint={state?.default_action ? `default ${state.default_action}` : "cluster posture"}
        />
        <StatCard
          label="Rules"
          value={!rulesQ.data ? "—" : ruleStats.total.toLocaleString()}
          icon={<ListChecks className="h-3.5 w-3.5" />}
          hint={rulesQ.data ? `${ruleStats.enabled} enabled / ${ruleStats.disabled} disabled` : "Rules unavailable"}
        />
        <StatCard
          label="Enforce configured"
          value={!rulesQ.data ? "—" : ruleStats.enforce.toLocaleString()}
          tone={ruleStats.enforce > 0 ? "low" : "neutral"}
          icon={<Power className="h-3.5 w-3.5" />}
          hint={rulesQ.data ? `${ruleStats.monitor} monitor` : "Rules unavailable"}
        />
        <StatCard
          label="Criteria"
          value={!optionsQ.data ? "—" : criteria.length.toLocaleString()}
          icon={<FileCheck2 className="h-3.5 w-3.5" />}
          hint={`${groupedCriteria.length} families`}
        />

      </div>


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
