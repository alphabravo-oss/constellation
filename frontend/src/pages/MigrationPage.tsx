import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, Download, RotateCcw, ShieldCheck, Wand2 } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { clusters as clustersApi, enterprise, type MigrationImportListItem, type MigrationPreview, type MigrationUnsupported } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, Select, Textarea } from "@/components/ui/form";
import { StatusPill } from "@/components/ui/status-pill";
import {
  buildMigrationReadiness,
  buildMigrationReport,
  countReadiness,
  MIGRATION_RECOMMENDED_ACTIONS,
  migrationAppliedSummaryLabel,
  migrationSourceLabel,
  type MigrationReadinessCategory,
} from "@/lib/migration-readiness";
import { downloadJson } from "@/lib/download";

type MigrationPolicy = MigrationPreview["policies"][number];
type MigrationFileProfile = MigrationPreview["file_profiles"][number];
type MigrationProcessProfile = MigrationPreview["process_profiles"][number];
type MigrationGroup = MigrationPreview["groups"][number];
type MigrationDPIRule = MigrationPreview["dpi_rules"][number];
type MigrationDPIBinding = MigrationPreview["dpi_bindings"][number];
type MigrationNetworkRule = MigrationPreview["network_rules"][number];

const dpiRuleProvenance = (rule: MigrationDPIRule) => {
  const parts = [`${rule.source_sensor || "NeuVector sensor"} · ${String(rule.category).toUpperCase()}`];
  if (rule.source_path) parts.push(rule.source_path);
  const cfg = [
    rule.source_cfg_type ? `sensor cfg ${rule.source_cfg_type}` : "",
    rule.source_rule_cfg_type ? `rule cfg ${rule.source_rule_cfg_type}` : "",
  ].filter(Boolean).join(", ");
  if (cfg) parts.push(cfg);
  if (rule.federated) parts.push("federated");
  if (rule.source_groups?.length) parts.push(`groups ${rule.source_groups.join(", ")}`);
  return parts.join(" · ");
};

const policyColumns: Column<MigrationPolicy>[] = [
  {
    id: "policy",
    header: "Policy",
    exportHeader: "Policy",
    exportValue: (p) => p.name,
    cell: (p) => (
      <div data-testid="migration-preview-policy">
        <div className="font-medium">{p.name}</div>
        <div className="text-muted-foreground">{p.engine} · {p.category}</div>
      </div>
    ),
  },
  { id: "action", header: "Action", cell: (p) => p.diff_action, exportValue: (p) => p.diff_action },
  { id: "mode", header: "Mode", cell: (p) => p.mode, exportValue: (p) => p.mode },
];

const fileProfileColumns: Column<MigrationFileProfile>[] = [
  {
    id: "profile",
    header: "File profile",
    exportHeader: "File profile",
    exportValue: (p) => p.group,
    cell: (p) => (
      <div data-testid="migration-preview-file-profile">
        <div className="font-medium">{p.group}</div>
        {p.description ? <div className="text-muted-foreground">{p.description}</div> : null}
      </div>
    ),
  },
  { id: "mode", header: "Mode", cell: (p) => p.mode, exportValue: (p) => p.mode },
  { id: "rules", header: "Rules", cell: (p) => p.rules.length, exportValue: (p) => p.rules.length },
  { id: "targets", header: "Targets", cell: (p) => p.target_workloads?.length ?? "-", exportValue: (p) => p.target_workloads?.length ?? "" },
  { id: "action", header: "Action", cell: (p) => p.diff_action, exportValue: (p) => p.diff_action },
];

const processProfileColumns: Column<MigrationProcessProfile>[] = [
  {
    id: "profile",
    header: "Process profile",
    exportHeader: "Process profile",
    exportValue: (p) => p.group,
    cell: (p) => (
      <div data-testid="migration-preview-process-profile">
        <div className="font-medium">{p.group}</div>
        <div className="text-muted-foreground">{p.baseline || "NeuVector baseline"}</div>
      </div>
    ),
  },
  { id: "mode", header: "Mode", cell: (p) => p.mode, exportValue: (p) => p.mode },
  { id: "rules", header: "Rules", cell: (p) => p.rules.length, exportValue: (p) => p.rules.length },
  { id: "targets", header: "Targets", cell: (p) => p.target_workloads?.length ?? "-", exportValue: (p) => p.target_workloads?.length ?? "" },
  { id: "action", header: "Action", cell: (p) => p.diff_action, exportValue: (p) => p.diff_action },
];

const groupColumns: Column<MigrationGroup>[] = [
  {
    id: "group",
    header: "Group",
    exportHeader: "Group",
    exportValue: (group) => group.name,
    cell: (group) => (
      <div data-testid="migration-preview-group">
        <div className="font-medium">{group.name}</div>
        {group.comment ? <div className="text-muted-foreground">{group.comment}</div> : null}
      </div>
    ),
  },
  { id: "kind", header: "Kind", cell: (group) => group.kind, exportValue: (group) => group.kind },
  {
    id: "modes",
    header: "Modes",
    cell: (group) => `${group.policy_mode || "monitor"} / ${group.profile_mode || "monitor"}`,
    exportValue: (group) => `${group.policy_mode || "monitor"} / ${group.profile_mode || "monitor"}`,
  },
  { id: "criteria", header: "Criteria", cell: (group) => group.criteria.length, exportValue: (group) => group.criteria.length },
  { id: "action", header: "Action", cell: (group) => group.diff_action, exportValue: (group) => group.diff_action },
];

const dpiRuleColumns: Column<MigrationDPIRule>[] = [
  {
    id: "rule",
    header: "DLP / WAF rule",
    exportHeader: "DLP / WAF rule",
    exportValue: (r) => `${r.name} (${dpiRuleProvenance(r)})`,
    cell: (r) => (
      <div data-testid="migration-preview-dpi-rule">
        <div className="font-medium">{r.name}</div>
        <div className="break-all text-muted-foreground">{dpiRuleProvenance(r)}</div>
      </div>
    ),
  },
  { id: "mode", header: "Mode", cell: (r) => r.mode, exportValue: (r) => r.mode },
  { id: "direction", header: "Direction", cell: (r) => directionLabel(r.apply_dir), exportValue: (r) => directionLabel(r.apply_dir) },
  { id: "patterns", header: "Patterns", cell: (r) => r.patterns.length, exportValue: (r) => r.patterns.length },
  { id: "action", header: "Action", cell: (r) => r.diff_action, exportValue: (r) => r.diff_action },
];

const dpiBindingColumns: Column<MigrationDPIBinding>[] = [
  {
    id: "group",
    header: "DLP / WAF group scope",
    exportHeader: "DLP / WAF group scope",
    exportValue: (binding) => binding.target_group_name,
    cell: (binding) => (
      <div data-testid="migration-preview-dpi-binding">
        <div className="font-medium">{binding.target_group_name}</div>
        <div className="text-muted-foreground">NeuVector group {binding.source_group}</div>
      </div>
    ),
  },
  {
    id: "kind",
    header: "Detector",
    cell: (binding) => <StatusPill label={binding.sensor_kind.toUpperCase()} tone={binding.sensor_kind === "waf" ? "accent" : "info"} />,
    exportValue: (binding) => binding.sensor_kind,
  },
  {
    id: "sensors",
    header: "Source sensors",
    cell: (binding) => binding.source_sensors?.join(", ") || "-",
    exportValue: (binding) => binding.source_sensors?.join(", ") || "",
  },
  { id: "action", header: "Action", cell: (binding) => binding.diff_action, exportValue: (binding) => binding.diff_action },
];

const networkRuleColumns: Column<MigrationNetworkRule>[] = [
  {
    id: "edge",
    header: "Network edge",
    exportHeader: "Network edge",
    exportValue: (rule) => `${rule.from_group} -> ${rule.to_group}`,
    cell: (rule) => (
      <div data-testid="migration-preview-network-rule">
        <div className="flex min-w-0 items-center gap-2 font-medium">
          <span className="truncate">{rule.from_group}</span>
          <ArrowRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
          <span className="truncate">{rule.to_group}</span>
        </div>
        {rule.comment ? <div className="text-muted-foreground">{rule.comment}</div> : null}
      </div>
    ),
  },
  { id: "mode", header: "Mode", cell: (rule) => rule.mode, exportValue: (rule) => rule.mode },
  { id: "ports", header: "Ports", cell: (rule) => networkPortLabel(rule.ports), exportValue: (rule) => networkPortLabel(rule.ports) },
  { id: "priority", header: "Priority", cell: (rule) => rule.priority || "-", exportValue: (rule) => rule.priority || "" },
  { id: "action", header: "Action", cell: (rule) => rule.diff_action, exportValue: (rule) => rule.diff_action },
];

const unsupportedColumns: Column<MigrationUnsupported>[] = [
  {
    id: "item",
    header: "Item",
    exportHeader: "Item",
    exportValue: (item) => item.name,
    cell: (item) => (
      <div>
        <div className="font-medium">{item.name}</div>
        <div className="text-muted-foreground">{item.kind.replace("_", " ")}</div>
      </div>
    ),
  },
  {
    id: "reason",
    header: "Reason",
    exportValue: (item) => item.suggestion ? `${item.reason} Suggested fix: ${item.suggestion}` : item.reason,
    cell: (item) => (
      <div className="max-w-xl text-xs leading-relaxed">
        <div>{item.reason}</div>
        {item.suggestion ? <div className="mt-1 text-muted-foreground">{item.suggestion}</div> : null}
      </div>
    ),
  },
  {
    id: "source",
    header: "Source",
    exportValue: (item) => item.source ? JSON.stringify(item.source) : "",
    cell: (item) => (
      <code className="block max-w-64 truncate rounded bg-muted px-1.5 py-1 text-[11px] text-muted-foreground">
        {item.source ? JSON.stringify(item.source) : "-"}
      </code>
    ),
  },
];

/**
 * Migration Imports — its own home (plan §4). Previously an inline wizard buried in
 * the Settings hub; now a focused page. Paste an export from another tool, preview
 * the generated policies/file-profiles + rollback bundle before importing.
 */
export function MigrationPage() {
  const qc = useQueryClient();
  const sourcesQ = useQuery({ queryKey: ["migration-sources"], queryFn: () => enterprise.migration() });
  const importsQ = useQuery({ queryKey: ["migration-imports"], queryFn: () => enterprise.migrationImports() });
  const clustersQ = useQuery({ queryKey: ["clusters"], queryFn: () => clustersApi.list(), staleTime: 30_000 });
  const sources = sourcesQ.data?.sources ?? [];
  const clusterOptions = useMemo(() => clustersQ.data?.clusters ?? [], [clustersQ.data?.clusters]);

  const [source, setSource] = useState("neuvector");
  const [exportText, setExportText] = useState("");
  const [targetClusterID, setTargetClusterID] = useState("");
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);

  useEffect(() => {
    if (!targetClusterID && clusterOptions.length === 1) {
      setTargetClusterID(clusterOptions[0].id);
    }
  }, [clusterOptions, targetClusterID]);

  const preview = useMutation({
    mutationFn: () => enterprise.migrationPreview({ source, export: exportText, cluster_id: targetClusterID || undefined }),
    onSuccess: (data) => {
      setSelectedPolicy(data.policies[0]?.name ?? null);
      void qc.invalidateQueries({ queryKey: ["migration-imports"] });
      toast.success(data.import_id ? "Migration preview saved" : "Migration preview generated");
    },
    onError: () => toast.error("Migration preview failed"),
  });

  const applyImport = useMutation({
    mutationFn: (id: string) => enterprise.migrationApply(id),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["migration-imports"] });
      if (targetClusterID) {
        void qc.invalidateQueries({ queryKey: ["runtime-dlp-rules", targetClusterID] });
        void qc.invalidateQueries({ queryKey: ["runtime-signatures", targetClusterID] });
        void qc.invalidateQueries({ queryKey: ["network-rules", targetClusterID] });
        void qc.invalidateQueries({ queryKey: ["baselines", targetClusterID] });
      }
      void qc.invalidateQueries({ queryKey: ["dpi-group-bindings"] });
      void qc.invalidateQueries({ queryKey: ["groups"] });
      void qc.invalidateQueries({ queryKey: ["group-usage"] });
      void qc.invalidateQueries({ queryKey: ["network-rules"] });
      toast.success(res.already_applied ? "Migration import already applied" : "Migration import applied");
    },
    onError: () => toast.error("Migration apply failed"),
  });

  const rollbackImport = useMutation({
    mutationFn: (id: string) => enterprise.migrationRollback(id),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["migration-imports"] });
      if (targetClusterID) {
        void qc.invalidateQueries({ queryKey: ["runtime-dlp-rules", targetClusterID] });
        void qc.invalidateQueries({ queryKey: ["runtime-signatures", targetClusterID] });
        void qc.invalidateQueries({ queryKey: ["network-rules", targetClusterID] });
        void qc.invalidateQueries({ queryKey: ["baselines", targetClusterID] });
      }
      void qc.invalidateQueries({ queryKey: ["dpi-group-bindings"] });
      void qc.invalidateQueries({ queryKey: ["groups"] });
      void qc.invalidateQueries({ queryKey: ["group-usage"] });
      void qc.invalidateQueries({ queryKey: ["network-rules"] });
      toast.success(`Migration rollback complete (${res.restored} restored, ${res.deleted} deleted)`);
    },
    onError: () => toast.error("Migration rollback failed"),
  });

  const rollbackBundleDownload = useMutation({
    mutationFn: (id: string) => enterprise.migrationRollbackBundle(id),
    onSuccess: (bundle, id) => {
      downloadJson(`constellation-migration-rollback-${id}.json`, bundle);
      toast.success("Rollback bundle downloaded");
    },
    onError: () => toast.error("Rollback bundle download failed"),
  });

  const data = preview.data;
  const selected = data?.policies.find((p) => p.name === selectedPolicy) ?? data?.policies[0];
  const processProfiles = data?.process_profiles ?? [];
  const groups = data?.groups ?? [];
  const dpiBindings = data?.dpi_bindings ?? [];
  const networkRules = data?.network_rules ?? [];
  const imports = importsQ.data ?? [];
  const activeImport = data?.import_id ? imports.find((item) => item.id === data.import_id) : imports[0];
  const activeStatus = activeImport?.status ?? (data?.import_id ? "previewed" : "preview");
  const canApplyActive = Boolean(data?.import_id) && (activeStatus === "previewed" || activeStatus === "rolled_back");
  const readiness = buildMigrationReadiness(data, activeImport, imports);
  const readinessCounts = countReadiness(readiness);
  const reportText = buildMigrationReport({
    source,
    preview: data,
    activeImport,
    imports,
    readiness,
    actions: MIGRATION_RECOMMENDED_ACTIONS,
  });

  const historyColumns: Column<MigrationImportListItem>[] = [
    {
      id: "import",
      header: "Import",
      exportHeader: "Import ID",
      exportValue: (item) => item.id,
      cell: (item) => (
        <div>
          <div className="font-medium">{migrationSourceLabel(item.source)}</div>
          <div className="font-mono text-[11px] text-muted-foreground">{item.id}</div>
        </div>
      ),
    },
    {
      id: "status",
      header: "Status",
      exportValue: (item) => item.status,
      cell: (item) => <StatusPill label={item.status.replace("_", " ")} tone={migrationStatusTone(item.status)} />,
    },
    {
      id: "summary",
      header: "Summary",
      exportValue: (item) => `${item.summary.total} items; ${item.summary.create} create; ${item.summary.update} update; ${item.applied_summary ? migrationAppliedSummaryLabel(item.applied_summary) : "not applied"}`,
      cell: (item) => (
        <div className="text-xs text-muted-foreground">
          <div>{item.summary.total} items · {item.summary.create} create · {item.summary.update} update</div>
          <div>{item.applied_summary ? migrationAppliedSummaryLabel(item.applied_summary) : "Not applied"}</div>
        </div>
      ),
    },
    {
      id: "created",
      header: "Created",
      cell: (item) => formatDate(item.created_at),
      exportValue: (item) => item.created_at,
      className: "text-xs text-muted-foreground",
    },
    {
      id: "actions",
      header: "Actions",
      exportable: false,
      cell: (item) => (
        <div className="flex flex-wrap justify-end gap-2">
          <Button
            size="sm"
            variant="primary"
            onClick={() => applyImport.mutate(item.id)}
            disabled={!canApplyImport(item) || applyImport.isPending}
            data-testid={`migration-import-apply-${item.id}`}
          >
            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
            Apply
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => rollbackImport.mutate(item.id)}
            disabled={!canRollbackImport(item) || rollbackImport.isPending}
            data-testid={`migration-import-rollback-${item.id}`}
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden />
            Rollback
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => rollbackBundleDownload.mutate(item.id)}
            disabled={!canDownloadRollbackBundle(item) || rollbackBundleDownload.isPending}
            data-testid={`migration-import-rollback-bundle-${item.id}`}
          >
            <Download className="h-3.5 w-3.5" aria-hidden />
            Bundle
          </Button>
        </div>
      ),
      className: "text-right",
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Migration Imports"
        description="Import policies, process profiles, DLP/WAF rules, and file profiles from another security tool. Preview the diff and rollback bundle before applying."
      />

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]" data-testid="migration-switch-readiness">
        <Card
          title="Switch Readiness"
          description="Current import state, manual mapping work, and rollback evidence for a NeuVector cutover."
        >
          <div className="grid gap-3 sm:grid-cols-4">
            <StatCard label="Blockers" value={readinessCounts.blocker} tone={readinessCounts.blocker > 0 ? "critical" : "neutral"} />
            <StatCard label="Warnings" value={readinessCounts.warning} tone={readinessCounts.warning > 0 ? "medium" : "neutral"} />
            <StatCard label="Ready" value={readinessCounts.ready} tone={readinessCounts.ready > 0 ? "accent" : "neutral"} />
            <StatCard label="Imports" value={imports.length} />
          </div>
          <div className="mt-4 space-y-2" data-testid="migration-readiness-checklist">
            {readiness.map((item) => (
              <article key={item.id} className="rounded-md border border-border bg-background p-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-medium">{item.title}</div>
                    <p className="mt-1 text-xs text-muted-foreground">{item.detail}</p>
                  </div>
                  <StatusPill label={item.category} tone={readinessTone(item.category)} />
                </div>
                {item.href ? (
                  <Link to={item.href} className="mt-2 inline-flex items-center gap-1 text-xs text-[color:var(--color-primary)] hover:underline">
                    Open <ArrowRight className="h-3 w-3" aria-hidden />
                  </Link>
                ) : null}
              </article>
            ))}
          </div>
        </Card>

        <Card
          title="Migration Report"
          description="Export a cutover summary with imported counts, unsupported objects, rollback state, and recommended follow-up."
        >
          <div className="space-y-3" data-testid="migration-report-panel">
            <div className="rounded-md bg-muted p-3 text-xs text-muted-foreground">
                <div className="font-medium text-foreground">{migrationSourceLabel(data?.summary.source ?? source)} report</div>
              <div className="mt-1">
                {(data?.summary.total ?? activeImport?.summary.total ?? 0)} previewed items · {(data?.summary.unsupported ?? activeImport?.summary.unsupported ?? 0)} need mapping · {imports.length} saved imports
              </div>
            </div>
            <Button
              variant="outline"
              onClick={() => downloadMigrationReport(reportText, data?.summary.source ?? source)}
              data-testid="migration-report-export"
            >
              <Download className="h-4 w-4" aria-hidden />
              Export report
            </Button>
          </div>
        </Card>
      </section>

      <Card
        title="Post-Import Actions"
        description="Controls that should be reviewed after policy migration so the cutover uses Constellation's stronger evidence and operations model."
        padded={false}
      >
        <div className="grid gap-2 p-3 md:grid-cols-2 xl:grid-cols-4" data-testid="migration-recommended-actions">
          {MIGRATION_RECOMMENDED_ACTIONS.map((action) => (
            <Link
              key={action.id}
              to={action.href}
              className="group rounded-md border border-border bg-background p-3 transition-colors hover:border-[color:var(--color-primary)]/60 hover:bg-accent"
              data-testid={`migration-action-${action.id}`}
            >
              <div className="flex items-center gap-2 text-sm font-medium">
                <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground group-hover:text-[color:var(--color-primary)]" aria-hidden />
                {action.title}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{action.detail}</p>
            </Link>
          ))}
        </div>
      </Card>

      <div data-testid="migration-preview-wizard">
        <Card
          title="Paste an export"
          description="Choose the source tool and target cluster, then paste its exported configuration to preview generated policies, process profiles, DLP/WAF rules, file profiles, and rollback metadata."
        >
          <div className="space-y-5">
            <div className="flex flex-wrap items-end gap-3">
              <Field label="Source" className="w-56">
                <Select
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  data-testid="migration-source-select"
                >
                  {sources.length === 0 && <option value="neuvector">NeuVector</option>}
                  {sources.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </Select>
              </Field>
              <Field label="Target cluster" className="w-64">
                <Select
                  value={targetClusterID}
                  onChange={(e) => setTargetClusterID(e.target.value)}
                  disabled={clustersQ.isLoading || clusterOptions.length === 0}
                  data-testid="migration-target-cluster-select"
                >
                  <option value="">{clustersQ.isLoading ? "Loading clusters..." : "Select cluster"}</option>
                  {clusterOptions.map((cluster) => (
                    <option key={cluster.id} value={cluster.id}>{cluster.name || cluster.id}</option>
                  ))}
                </Select>
              </Field>
              <Button
                variant="primary"
                onClick={() => preview.mutate()}
                disabled={preview.isPending || exportText.trim().length < 8 || !targetClusterID}
                data-testid="migration-preview-submit"
              >
                <Wand2 className="h-4 w-4" aria-hidden />
                Preview import
              </Button>
            </div>

            <Textarea
              value={exportText}
              onChange={(e) => setExportText(e.target.value)}
              rows={8}
              spellCheck={false}
              placeholder="Paste the exported configuration from your source tool…"
              className="font-mono text-xs"
              data-testid="migration-export-input"
            />
          </div>
        </Card>
      </div>

      {data ? (
        <div className="space-y-4" data-testid="migration-preview-result">
          <div className="rounded-md border border-border bg-muted px-3 py-2 text-xs text-muted-foreground">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span>Preview persisted</span>
                  <StatusPill label={activeStatus.replace("_", " ")} tone={migrationStatusTone(activeStatus)} />
                </div>
                <div className="mt-1 truncate font-mono" data-testid="migration-import-id">
                  {data.import_id ?? "No import id returned by the API."}
                </div>
              </div>
              <Button
                variant="primary"
                onClick={() => data.import_id && applyImport.mutate(data.import_id)}
                disabled={!canApplyActive || applyImport.isPending}
                data-testid="migration-import-apply-active"
              >
                <CheckCircle2 className="h-4 w-4" aria-hidden />
                Apply import
              </Button>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5 xl:grid-cols-6 2xl:grid-cols-[repeat(12,minmax(0,1fr))]">
            <StatCard label="Source Objects" value={data.summary.source_total ?? data.summary.total} />
            <StatCard label="Policies" value={data.policies.length} />
            <StatCard label="Create" value={data.summary.create} tone="low" />
            <StatCard label="Update" value={data.summary.update} tone="medium" />
            <StatCard label="Enforce" value={data.summary.enforce} tone="high" />
            <StatCard label="File Profiles" value={data.summary.file_profiles} />
            <StatCard label="Process Profiles" value={data.summary.process_profiles ?? processProfiles.length} />
            <StatCard label="Groups" value={data.summary.groups ?? groups.length} />
            <StatCard label="Network Rules" value={data.summary.network_rules ?? networkRules.length} />
            <StatCard label="DLP / WAF" value={data.summary.dpi_rules} />
            <StatCard label="Group Scopes" value={data.summary.dpi_bindings ?? dpiBindings.length} />
            <StatCard label="Needs Mapping" value={data.summary.unsupported} tone={data.summary.unsupported > 0 ? "medium" : "neutral"} />
          </div>
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <DataTable
              rows={data.policies}
              columns={policyColumns}
              rowKey={(p) => p.name}
              onRowClick={(p) => setSelectedPolicy(p.name)}
              showDensityToggle={false}
              exportFileName={`constellation-${data.summary.source}-policies`}
              testId="migration-preview-policies"
            />
            <Card title="Generated policy YAML">
              <pre className="max-h-64 overflow-auto rounded bg-muted p-2 text-xs" data-testid="migration-preview-yaml">
                {selected?.spec_yaml ?? "No policy selected."}
              </pre>
            </Card>
          </div>
          {data.file_profiles.length > 0 ? (
            <div data-testid="migration-preview-file-profiles">
              <DataTable
                rows={data.file_profiles}
                columns={fileProfileColumns}
                rowKey={(p) => p.group}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-file-profiles`}
                testId="migration-preview-file-profile-table"
              />
            </div>
          ) : null}
          {processProfiles.length > 0 ? (
            <div data-testid="migration-preview-process-profiles">
              <DataTable
                rows={processProfiles}
                columns={processProfileColumns}
                rowKey={(p) => `${p.cluster_id}:${p.group}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-process-profiles`}
                testId="migration-preview-process-profile-table"
              />
            </div>
          ) : null}
          {groups.length > 0 ? (
            <div data-testid="migration-preview-groups">
              <DataTable
                rows={groups}
                columns={groupColumns}
                rowKey={(group) => `${group.cluster_id}:${group.name}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-groups`}
                testId="migration-preview-group-table"
              />
            </div>
          ) : null}
          {networkRules.length > 0 ? (
            <div data-testid="migration-preview-network-rules">
              <DataTable
                rows={networkRules}
                columns={networkRuleColumns}
                rowKey={(rule) => `${rule.cluster_id}:${rule.from_group}:${rule.to_group}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-network-rules`}
                testId="migration-preview-network-rule-table"
              />
            </div>
          ) : null}
          {data.dpi_rules.length > 0 ? (
            <div data-testid="migration-preview-dpi-rules">
              <DataTable
                rows={data.dpi_rules}
                columns={dpiRuleColumns}
                rowKey={(r) => `${r.cluster_id}:${r.name}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-dlp-waf-rules`}
                testId="migration-preview-dpi-rule-table"
              />
            </div>
          ) : null}
          {dpiBindings.length > 0 ? (
            <div data-testid="migration-preview-dpi-bindings">
              <DataTable
                rows={dpiBindings}
                columns={dpiBindingColumns}
                rowKey={(binding) => `${binding.sensor_kind}:${binding.target_group_id}:${binding.source_group}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-dlp-waf-group-scopes`}
                testId="migration-preview-dpi-binding-table"
              />
            </div>
          ) : null}
          {(data.unsupported?.length ?? 0) > 0 ? (
            <Card
              title="Queued or Unsupported Items"
              description="These records were converted and saved in the preview, but require extra target mapping before an automated apply can mutate live objects."
              padded={false}
            >
              <DataTable
                rows={data.unsupported ?? []}
                columns={unsupportedColumns}
                rowKey={(item) => `${item.kind}:${item.name}`}
                showDensityToggle={false}
                testId="migration-preview-unsupported"
                exportFileName={`constellation-${data.summary.source}-unsupported`}
              />
            </Card>
          ) : null}
          <Card title="Rollback bundle preview" description="Apply this bundle to revert the import if needed.">
            <pre className="max-h-40 overflow-auto rounded bg-muted p-2 text-xs" data-testid="migration-rollback-bundle">
              {data.rollback_bundle}
            </pre>
          </Card>
        </div>
      ) : null}

      <Card
        title="Import History"
        description="Persisted previews, applied imports, partial imports, failures, and rollback state for the current organization."
        padded={false}
      >
        <DataTable
          rows={imports}
          columns={historyColumns}
          rowKey={(item) => item.id}
          showDensityToggle={false}
          testId="migration-import-history"
          exportFileName="constellation-migration-import-history"
          emptyState={<div className="px-6 py-10 text-center text-xs text-muted-foreground">No migration imports yet.</div>}
        />
      </Card>
    </div>
  );
}

function canApplyImport(item: MigrationImportListItem) {
  return item.status === "previewed" || item.status === "rolled_back";
}

function canRollbackImport(item: MigrationImportListItem) {
  return item.status === "applied" || item.status === "partial_applied";
}

function canDownloadRollbackBundle(item: MigrationImportListItem) {
  return item.status === "applied" || item.status === "partial_applied" || item.status === "rolled_back";
}

function directionLabel(value: number) {
	switch (value) {
		case 1:
			return "Egress";
    case 2:
      return "Ingress";
    case 3:
      return "Both";
    default:
      return "-";
	}
}

function networkPortLabel(ports: MigrationNetworkRule["ports"]) {
	if (!ports || ports.length === 0) return "any";
	return ports.map((port) => `${port.protocol || "TCP"}/${port.port || "any"}`).join(", ");
}

function migrationStatusTone(status: string): "neutral" | "success" | "warning" | "error" | "info" | "pending" | "accent" {
	switch (status) {
    case "applied":
      return "success";
    case "partial_applied":
      return "warning";
    case "previewed":
      return "info";
    case "rolled_back":
      return "neutral";
    case "failed":
      return "error";
    default:
      return "pending";
  }
}

function formatDate(value?: string) {
  if (!value) return "-";
  try {
    return new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function downloadMigrationReport(report: string, source: string) {
  const blob = new Blob([report], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `constellation-${source || "migration"}-report-${new Date().toISOString().slice(0, 10)}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

function readinessTone(category: MigrationReadinessCategory): "neutral" | "success" | "warning" | "error" | "info" | "pending" | "accent" {
  switch (category) {
    case "blocker":
      return "error";
    case "warning":
      return "warning";
    case "ready":
      return "success";
    default:
      return "info";
  }
}
