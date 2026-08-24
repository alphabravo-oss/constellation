import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Download,
  FileCheck2,
  FileText,
  ListChecks,
  Plus,
  Power,
  PowerOff,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  UploadCloud,
} from "lucide-react";

import {
  componentsInventory,
  policies as policiesApi,
  type AdmissionCriterionOption,
  type AdmissionProfile,
  type AdmissionProfileImportPolicy,
  type AdmissionRuleRow,
  type AdmissionState,
  type AdmissionStateInput,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { Card, DetailRow } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch, Field, Select, TextInput } from "@/components/ui/form";
import { VerdictBanner, type VerdictStatus } from "@/components/ui/verdict-banner";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
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

type ProfileMode = "monitor" | "enforce";

export function AdmissionPage() {
  const { clusterId } = useCluster();
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
  const profilesQ = useQuery({ queryKey: ["admission-profiles"], queryFn: () => policiesApi.admissionProfiles() });
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

  const saveState = useMutation({
    mutationFn: (patch: Partial<AdmissionStateInput>) => policiesApi.updateAdmissionState(patch, params),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admission-state", clusterId] }),
  });

  const invalidateRules = () => {
    void qc.invalidateQueries({ queryKey: ["admission-rules", clusterId] });
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

  const [profileSelection, setProfileSelection] = useState("");
  const [profileMode, setProfileMode] = useState<ProfileMode>("monitor");
  const [profileEnabled, setProfileEnabled] = useState(true);
  const [profileMessage, setProfileMessage] = useState("");

  const profiles = useMemo(() => profilesQ.data?.profiles ?? [], [profilesQ.data?.profiles]);
  const selectedProfileId = profileSelection || profiles[0]?.id || "";
  const selectedProfile = profiles.find((profile) => profile.id === selectedProfileId);

  const previewProfile = useMutation({
    mutationFn: () =>
      policiesApi.importAdmissionProfile({
        profile_id: selectedProfileId,
        mode: profileMode,
        enabled: profileEnabled,
        dry_run: true,
      }),
    onSuccess: () => setProfileMessage(""),
  });
  const importProfile = useMutation({
    mutationFn: () =>
      policiesApi.importAdmissionProfile({
        profile_id: selectedProfileId,
        mode: profileMode,
        enabled: profileEnabled,
        dry_run: false,
      }),
    onSuccess: (result) => {
      invalidateRules();
      setProfileMessage(`Imported ${result.imported} admission rules from ${result.profile_id}.`);
    },
  });
  const exportProfile = useMutation({
    mutationFn: (id: string) => policiesApi.exportAdmissionProfile(id),
    onSuccess: (bundle) => downloadJSON(`${bundle.profile.id}-admission-profile.json`, bundle),
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
  const profileStats = useMemo(() => summarizeProfiles(profiles), [profiles]);
  const serverDryRunHistory = useMemo(
    () => (serverDryRunHistoryQ.data?.history ?? []).map(admissionDryRunHistoryEntryFromRow),
    [serverDryRunHistoryQ.data?.history],
  );
  const mergedDryRunHistory = useMemo(
    () => mergeAdmissionDryRunHistory(serverDryRunHistory, dryRunHistory),
    [serverDryRunHistory, dryRunHistory],
  );
  const selectedProfileStats = useMemo(
    () => summarizeProfile(selectedProfile),
    [selectedProfile],
  );
  const verdict = admissionVerdict(state);
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
    [deleteRule, toggleRule],
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

  const previewColumns = useMemo<Column<AdmissionProfileImportPolicy>[]>(
    () => [
      {
        id: "policy",
        header: "Policy",
        cell: (policy) => (
          <div className="min-w-0">
            <div className="truncate font-medium text-foreground" title={policy.policy_name}>{policy.policy_name}</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{policy.category}</div>
          </div>
        ),
        sort: (a, b) => a.policy_name.localeCompare(b.policy_name),
      },
      {
        id: "mode",
        header: "Mode",
        width: "105px",
        cell: (policy) => <RuleModePill mode={policy.mode} />,
        sort: (a, b) => a.mode.localeCompare(b.mode),
      },
      {
        id: "enabled",
        header: "State",
        width: "110px",
        cell: (policy) => <StatusPill label={policy.enabled ? "enabled" : "disabled"} tone={policy.enabled ? "success" : "neutral"} />,
        sort: (a, b) => Number(a.enabled) - Number(b.enabled),
      },
      {
        id: "description",
        header: "Description",
        cell: (policy) => <span className="text-xs text-muted-foreground">{policy.description}</span>,
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

  return (
    <div className="space-y-5">
      <PageHeader
        title="Admission Control"
        description="Cluster admission state, rules, criteria, profile templates, and dry-run results in one workspace."
      />

      <VerdictBanner status={verdict.status} title={verdict.title} detail={verdict.detail} />

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-6" data-testid="admission-summary">
        <StatCard
          label="Webhook"
          value={admissionComponentsQ.isPending ? "..." : webhookHealth.label}
          tone={state?.enabled === false ? "medium" : webhookHealth.statTone}
          icon={<ShieldCheck className="h-3.5 w-3.5" />}
          hint={state ? `${state.enabled ? "enabled" : "disabled"} · ${webhookHealth.detail}` : "loading"}
        />
        <StatCard
          label="Mode"
          value={state?.mode ? labelCase(state.mode) : "..."}
          tone={state?.mode === "protect" ? "low" : "accent"}
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
          hint={state?.default_action ? `default ${state.default_action}` : "cluster posture"}
        />
        <StatCard
          label="Rules"
          value={rulesQ.isPending ? "..." : ruleStats.total.toLocaleString()}
          icon={<ListChecks className="h-3.5 w-3.5" />}
          hint={`${ruleStats.enabled} enabled / ${ruleStats.disabled} disabled`}
        />
        <StatCard
          label="Enforcing"
          value={rulesQ.isPending ? "..." : ruleStats.enforce.toLocaleString()}
          tone={ruleStats.enforce > 0 ? "low" : "neutral"}
          icon={<Power className="h-3.5 w-3.5" />}
          hint={`${ruleStats.monitor} monitor`}
        />
        <StatCard
          label="Criteria"
          value={optionsQ.isPending ? "..." : criteria.length.toLocaleString()}
          icon={<FileCheck2 className="h-3.5 w-3.5" />}
          hint={`${groupedCriteria.length} families`}
        />
        <StatCard
          label="Profiles"
          value={profilesQ.isPending ? "..." : profiles.length.toLocaleString()}
          icon={<Sparkles className="h-3.5 w-3.5" />}
          hint={`${profileStats.rules} template rules`}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <Card title="State" description="Global admission-control posture for the selected cluster.">
          {stateQ.isPending || !state ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : (
            <div className="space-y-4" data-testid="admission-state-panel">
              <Switch
                checked={state.enabled}
                disabled={saveState.isPending}
                onCheckedChange={(enabled) => saveState.mutate({ enabled })}
                label="Enable admission control"
                description="When off, workloads are admitted even if rules would match."
              />
              <div className="grid gap-4 sm:grid-cols-3">
                <Field label="Mode" hint="Monitor observes; Protect blocks deny decisions.">
                  <Select
                    value={state.mode}
                    disabled={!state.enabled || saveState.isPending}
                    onChange={(event) => saveState.mutate({ mode: event.target.value as "monitor" | "protect" })}
                  >
                    <option value="monitor">Monitor</option>
                    <option value="protect">Protect</option>
                  </Select>
                </Field>
                <Field label="Default action" hint="Verdict when no rule matches.">
                  <Select
                    value={state.default_action}
                    disabled={!state.enabled || saveState.isPending}
                    onChange={(event) => saveState.mutate({ default_action: event.target.value as "allow" | "deny" })}
                  >
                    <option value="allow">Allow</option>
                    <option value="deny">Deny</option>
                  </Select>
                </Field>
                <Field label="Failure policy" hint="API-server behavior when the webhook is unreachable.">
                  <Select
                    value={state.failure_policy}
                    disabled={!state.enabled || saveState.isPending}
                    onChange={(event) => saveState.mutate({ failure_policy: event.target.value as "ignore" | "fail" })}
                  >
                    <option value="ignore">Ignore (fail-open)</option>
                    <option value="fail">Fail (fail-closed)</option>
                  </Select>
                </Field>
              </div>
              {saveState.isError ? <p className="text-sm text-status-error">{errorMessage(saveState.error)}</p> : null}
            </div>
          )}
        </Card>

        <Card title="Webhook Details" description="Current admission-control fields." bodyClassName="p-5">
          {state ? (
            <dl className="divide-y divide-border">
              <DetailRow label="Cluster" mono>{state.cluster_id}</DetailRow>
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
      </div>

      <Card
        title="Admission Rules"
        description="Admission policies compiled for the webhook."
        padded={false}
        action={
          <Button size="sm" variant="primary" onClick={() => navigate(`${clusterId ? `/clusters/${clusterId}` : ""}/admission/new`)}>
            <Plus className="h-3.5 w-3.5" /> Add rule
          </Button>
        }
      >
        <DataTable<AdmissionRuleRow>
          rows={rules}
          columns={ruleColumns}
          rowKey={(rule) => rule.id}
          density="compact"
          showDensityToggle={false}
          testId="admission-rule-table"
          emptyState={
            <div className="px-6 py-10 text-center text-xs text-muted-foreground">
              No admission rules yet. Use the profile templates or create a custom rule.
            </div>
          }
        />
      </Card>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
        <Card title="Criteria Catalog" description="Supported rule-builder criteria." padded={false}>
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

        <Card
          title="Profile Templates"
          description="Built-in admission bundles for NeuVector-style rollout."
          action={
            <Button
              size="sm"
              variant="outline"
              disabled={!selectedProfileId || exportProfile.isPending}
              onClick={() => exportProfile.mutate(selectedProfileId)}
            >
              <Download className="h-3.5 w-3.5" /> Export
            </Button>
          }
        >
          <div className="space-y-4" data-testid="admission-profile-templates">
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_160px_120px]">
              <Field label="Profile">
                <Select value={selectedProfileId} onChange={(event) => setProfileSelection(event.target.value)}>
                  {profiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>{profile.name}</option>
                  ))}
                </Select>
              </Field>
              <Field label="Import mode">
                <Select value={profileMode} onChange={(event) => setProfileMode(event.target.value as ProfileMode)}>
                  <option value="monitor">Monitor</option>
                  <option value="enforce">Enforce</option>
                </Select>
              </Field>
              <div className="pt-5">
                <Switch checked={profileEnabled} onCheckedChange={setProfileEnabled} label="Enabled" />
              </div>
            </div>

            {selectedProfile ? <ProfileSummary profile={selectedProfile} stats={selectedProfileStats} /> : null}

            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={!selectedProfileId || previewProfile.isPending}
                onClick={() => previewProfile.mutate()}
              >
                <FileText className="h-3.5 w-3.5" /> {previewProfile.isPending ? "Previewing..." : "Preview"}
              </Button>
              <Button
                type="button"
                variant="primary"
                size="sm"
                disabled={!selectedProfileId || importProfile.isPending}
                onClick={() => importProfile.mutate()}
              >
                <UploadCloud className="h-3.5 w-3.5" /> {importProfile.isPending ? "Importing..." : "Import profile"}
              </Button>
              {profileMessage ? <span className="text-xs text-status-success">{profileMessage}</span> : null}
            </div>

            {previewProfile.isError ? <p className="text-sm text-status-error">{errorMessage(previewProfile.error)}</p> : null}
            {importProfile.isError ? <p className="text-sm text-status-error">{errorMessage(importProfile.error)}</p> : null}
            {exportProfile.isError ? <p className="text-sm text-status-error">{errorMessage(exportProfile.error)}</p> : null}

            {previewProfile.data ? (
              <div data-testid="admission-profile-preview">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-foreground">Preview</span>
                  <span className="text-xs text-muted-foreground">{previewProfile.data.policies.length} rules</span>
                </div>
                <DataTable<AdmissionProfileImportPolicy>
                  rows={previewProfile.data.policies}
                  columns={previewColumns}
                  rowKey={(policy) => policy.policy_name}
                  density="compact"
                  showDensityToggle={false}
                />
              </div>
            ) : null}
          </div>
        </Card>
      </div>

      <Card title="Dry-run Assessment" description="Evaluate an image against the current admission ruleset.">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (image.trim()) assess.mutate();
          }}
        >
          <div className="min-w-[260px] flex-1">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground">Image</label>
            <TextInput placeholder="ghcr.io/org/app:1.2.3" value={image} onChange={(event) => setImage(event.target.value)} />
          </div>
          <div className="w-[180px]">
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-muted-foreground">Namespace</label>
            <TextInput placeholder="default" value={namespace} onChange={(event) => setNamespace(event.target.value)} />
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
        {assess.isError ? <p className="mt-3 text-sm text-status-error">{errorMessage(assess.error)}</p> : null}
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
      title: "Protecting - admission is enforcing",
      detail: `Violating workloads are blocked at admission. Default action: ${state.default_action}, on webhook failure: ${state.failure_policy}.`,
    };
  }
  return {
    status: "info",
    title: "Monitoring - admission is observing",
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

function summarizeProfiles(profiles: AdmissionProfile[]) {
  return profiles.reduce(
    (acc, profile) => {
      acc.rules += profile.rules.length;
      return acc;
    },
    { rules: 0 },
  );
}

function summarizeProfile(profile?: AdmissionProfile) {
  if (!profile) return { total: 0, enforce: 0, monitor: 0, enabled: 0 };
  return profile.rules.reduce(
    (acc, rule) => {
      acc.total += 1;
      if (rule.enabled) acc.enabled += 1;
      if (rule.mode === "enforce") acc.enforce += 1; else acc.monitor += 1;
      return acc;
    },
    { total: 0, enforce: 0, monitor: 0, enabled: 0 },
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

function ProfileSummary({ profile, stats }: { profile: AdmissionProfile; stats: ReturnType<typeof summarizeProfile> }) {
  return (
    <div className="rounded-md border border-border bg-background p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="font-medium text-foreground">{profile.name}</div>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{profile.description}</p>
        </div>
        <StatusPill label={profile.failure_policy === "Fail" ? "fail closed" : "fail open"} tone={profile.failure_policy === "Fail" ? "success" : "warning"} />
      </div>
      <div className="mt-3 grid gap-2 sm:grid-cols-4">
        <MiniMetric label="Rules" value={stats.total} />
        <MiniMetric label="Enabled" value={stats.enabled} />
        <MiniMetric label="Enforce" value={stats.enforce} />
        <MiniMetric label="Monitor" value={stats.monitor} />
      </div>
    </div>
  );
}

function MiniMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-border bg-card px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="text-base font-semibold tabular-nums text-foreground">{value.toLocaleString()}</div>
    </div>
  );
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

function errorMessage(error: unknown) {
  return (error as { response?: { data?: { error?: string } } })?.response?.data?.error
    ?? (error as Error)?.message
    ?? "Request failed";
}

function downloadJSON(filename: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
