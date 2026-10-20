import { useEffect, useMemo, useRef, useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, CircleCheck, Download, RotateCcw, ShieldCheck, WandSparkles } from "lucide-react";
import { toast } from "sonner";

import { clusters as clustersApi, enterprise, type MigrationImportListItem, type MigrationPreview, type MigrationUnsupported } from "@/api/client";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Collapse } from "@/components/ui/collapse";
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
  migrationSummaryLabel,
  migrationVulnerabilityScopeLabel,
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
type MigrationVulnerabilityProfile = NonNullable<MigrationPreview["vulnerability_profiles"]>[number];
type MigrationRegistry = NonNullable<MigrationPreview["registries"]>[number];
type MigrationDiagnostic = MigrationUnsupported & { diagnosticIndex: number };

const MAX_EXPORT_BYTES = 2 * 1024 * 1024;

const vulnerabilityProfileColumns: Column<MigrationVulnerabilityProfile>[] = [
  {
    id: "profile",
    header: "Vulnerability profile", kind: "name", wrap: true,
    exportValue: (profile) => profile.name,
    cell: (profile) => (
      <div data-testid="migration-preview-vulnerability-profile">
        <div className="font-medium">{profile.name}</div>
        {profile.description ? <div className="text-muted-foreground">{profile.description}</div> : null}
      </div>
    ),
  },
  { id: "action", header: "Action", kind: "status", cell: (profile) => profile.diff_action, exportValue: (profile) => profile.diff_action },
  { id: "active", header: "State", kind: "status", cell: (profile) => profile.active ? "Active" : "Inactive", exportValue: (profile) => profile.active ? "Active" : "Inactive" },
  { id: "scope", header: "Effective scope", kind: "text", wrap: true, size: 264, minSize: 192, maxSize: 400, code: true, cell: migrationVulnerabilityScopeLabel, exportValue: migrationVulnerabilityScopeLabel },
  { id: "entries", header: "Entries", kind: "count", cell: (profile) => profile.entries.length, exportValue: (profile) => profile.entries.length },
];

const registryColumns: Column<MigrationRegistry>[] = [
  {
    id: "registry",
    header: "Registry", kind: "name", wrap: true,
    exportValue: (registry) => `${registry.name} (${registry.kind}) ${registry.endpoint}`,
    cell: (registry) => (
      <div data-testid="migration-preview-registry">
        <div className="font-medium">{registry.name}</div>
        <div className="break-all text-muted-foreground">{registry.kind} · {registry.endpoint}</div>
      </div>
    ),
  },
  { id: "action", header: "Action", kind: "status", cell: (registry) => registry.diff_action, exportValue: (registry) => registry.diff_action },
  { id: "scope", header: "Effective image scope", kind: "text", wrap: true, size: 264, minSize: 192, maxSize: 400, code: true, cell: (registry) => registry.image_globs.join(", ") || "All images", exportValue: (registry) => registry.image_globs.join(", ") || "All images" },
  { id: "filters", header: "Image filters", kind: "count", cell: (registry) => registry.image_globs.length, exportValue: (registry) => registry.image_globs.length },
  {
    id: "scanning",
    header: "Scanning and credentials", kind: "text", wrap: true, size: 264, minSize: 208, maxSize: 360,
    exportValue: (registry) => `Manual scans; no credentials imported${registry.credentials_required ? "; reissue credentials before scanning" : ""}`,
    cell: (registry) => (
      <div className="text-xs">
        <div>{registry.scan_cadence} scans · no credentials imported</div>
        {registry.credentials_required ? <div className="mt-1 text-status-warning">Reissue credentials before scanning.</div> : null}
      </div>
    ),
  },
];

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
    header: "Policy", kind: "name", wrap: true,
    exportHeader: "Policy",
    exportValue: (p) => p.name,
    cell: (p) => (
      <div data-testid="migration-preview-policy">
        <div className="font-medium">{p.name}</div>
        <div className="text-muted-foreground">{p.engine} · {p.category}</div>
      </div>
    ),
  },
  { id: "action", header: "Action", kind: "status", cell: (p) => p.diff_action, exportValue: (p) => p.diff_action },
  { id: "mode", header: "Mode", kind: "status", cell: (p) => p.mode, exportValue: (p) => p.mode },
];

const fileProfileColumns: Column<MigrationFileProfile>[] = [
  {
    id: "profile",
    header: "File profile", kind: "name", wrap: true,
    exportHeader: "File profile",
    exportValue: (p) => p.group,
    cell: (p) => (
      <div data-testid="migration-preview-file-profile">
        <div className="font-medium">{p.group}</div>
        {p.description ? <div className="text-muted-foreground">{p.description}</div> : null}
      </div>
    ),
  },
  { id: "mode", header: "Mode", kind: "status", cell: (p) => p.mode, exportValue: (p) => p.mode },
  { id: "rules", header: "Rules", kind: "count", cell: (p) => p.rules.length, exportValue: (p) => p.rules.length },
  { id: "targets", header: "Targets", kind: "count", cell: (p) => p.target_workloads?.length ?? "-", exportValue: (p) => p.target_workloads?.length ?? "" },
  { id: "action", header: "Action", kind: "status", cell: (p) => p.diff_action, exportValue: (p) => p.diff_action },
];

const processProfileColumns: Column<MigrationProcessProfile>[] = [
  {
    id: "profile",
    header: "Process profile", kind: "name", wrap: true,
    exportHeader: "Process profile",
    exportValue: (p) => p.group,
    cell: (p) => (
      <div data-testid="migration-preview-process-profile">
        <div className="font-medium">{p.group}</div>
        <div className="text-muted-foreground">{p.baseline || "NeuVector baseline"}</div>
      </div>
    ),
  },
  { id: "mode", header: "Mode", kind: "status", cell: (p) => p.mode, exportValue: (p) => p.mode },
  { id: "rules", header: "Rules", kind: "count", cell: (p) => p.rules.length, exportValue: (p) => p.rules.length },
  { id: "targets", header: "Targets", kind: "count", cell: (p) => p.target_workloads?.length ?? "-", exportValue: (p) => p.target_workloads?.length ?? "" },
  { id: "action", header: "Action", kind: "status", cell: (p) => p.diff_action, exportValue: (p) => p.diff_action },
];

const groupColumns: Column<MigrationGroup>[] = [
  {
    id: "group",
    header: "Group", kind: "name", wrap: true,
    exportHeader: "Group",
    exportValue: (group) => group.name,
    cell: (group) => (
      <div data-testid="migration-preview-group">
        <div className="font-medium">{group.name}</div>
        {group.comment ? <div className="text-muted-foreground">{group.comment}</div> : null}
      </div>
    ),
  },
  { id: "kind", header: "Kind", kind: "badge", cell: (group) => group.kind, exportValue: (group) => group.kind },
  {
    id: "modes",
    header: "Modes", kind: "status", size: 176, minSize: 152, maxSize: 208,
    cell: (group) => `${group.policy_mode || "monitor"} / ${group.profile_mode || "monitor"}`,
    exportValue: (group) => `${group.policy_mode || "monitor"} / ${group.profile_mode || "monitor"}`,
  },
  { id: "criteria", header: "Criteria", kind: "count", cell: (group) => group.criteria.length, exportValue: (group) => group.criteria.length },
  { id: "action", header: "Action", kind: "status", cell: (group) => group.diff_action, exportValue: (group) => group.diff_action },
];

const dpiRuleColumns: Column<MigrationDPIRule>[] = [
  {
    id: "rule",
    header: "DLP / WAF rule", kind: "name", wrap: true,
    exportHeader: "DLP / WAF rule",
    exportValue: (r) => `${r.name} (${dpiRuleProvenance(r)})`,
    cell: (r) => (
      <div data-testid="migration-preview-dpi-rule">
        <div className="font-medium">{r.name}</div>
        <div className="break-all text-muted-foreground">{dpiRuleProvenance(r)}</div>
      </div>
    ),
  },
  { id: "mode", header: "Mode", kind: "status", cell: (r) => r.mode, exportValue: (r) => r.mode },
  { id: "direction", header: "Direction", kind: "status", cell: (r) => directionLabel(r.apply_dir), exportValue: (r) => directionLabel(r.apply_dir) },
  { id: "patterns", header: "Patterns", kind: "count", cell: (r) => r.patterns.length, exportValue: (r) => r.patterns.length },
  { id: "action", header: "Action", kind: "status", cell: (r) => r.diff_action, exportValue: (r) => r.diff_action },
];

const dpiBindingColumns: Column<MigrationDPIBinding>[] = [
  {
    id: "group",
    header: "DLP / WAF group scope", kind: "name", wrap: true,
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
    header: "Detector", kind: "badge",
    cell: (binding) => <StatusPill label={binding.sensor_kind.toUpperCase()} tone={binding.sensor_kind === "waf" ? "accent" : "info"} />,
    exportValue: (binding) => binding.sensor_kind,
  },
  {
    id: "sensors",
    header: "Source sensors", kind: "text", wrap: true, size: 224, minSize: 160, maxSize: 320,
    cell: (binding) => binding.source_sensors?.join(", ") || "-",
    exportValue: (binding) => binding.source_sensors?.join(", ") || "",
  },
  { id: "action", header: "Action", kind: "status", cell: (binding) => binding.diff_action, exportValue: (binding) => binding.diff_action },
];

const networkRuleColumns: Column<MigrationNetworkRule>[] = [
  {
    id: "edge",
    header: "Network edge", kind: "name", wrap: true,
    exportHeader: "Network edge",
    exportValue: (rule) => `${rule.from_group} -> ${rule.to_group}`,
    cell: (rule) => (
      <div data-testid="migration-preview-network-rule">
        <div className="flex min-w-0 flex-wrap items-center gap-2 font-medium">
          <span className="">{rule.from_group}</span>
          <ArrowRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
          <span className="">{rule.to_group}</span>
        </div>
        {rule.comment ? <div className="text-muted-foreground">{rule.comment}</div> : null}
      </div>
    ),
  },
  { id: "mode", header: "Mode", kind: "status", cell: (rule) => rule.mode, exportValue: (rule) => rule.mode },
  { id: "ports", header: "Ports", kind: "text", code: true, wrap: true, size: 152, minSize: 112, maxSize: 208, cell: (rule) => networkPortLabel(rule.ports), exportValue: (rule) => networkPortLabel(rule.ports) },
  { id: "priority", header: "Priority", kind: "count", cell: (rule) => rule.priority || "-", exportValue: (rule) => rule.priority || "" },
  { id: "action", header: "Action", kind: "status", cell: (rule) => rule.diff_action, exportValue: (rule) => rule.diff_action },
];

const unsupportedColumns: Column<MigrationUnsupported>[] = [
  {
    id: "item",
    header: "Item", kind: "name", wrap: true,
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
    header: "Reason", kind: "text", wrap: true, size: 320, minSize: 224, maxSize: 480, grow: true,
    exportValue: (item) => item.suggestion ? `${item.reason} Suggested fix: ${item.suggestion}` : item.reason,
    cell: (item) => (
      <div className="text-xs leading-relaxed">
        <div>{item.reason}</div>
        {item.suggestion ? <div className="mt-1 text-muted-foreground">{item.suggestion}</div> : null}
      </div>
    ),
  },
  {
    id: "source",
    header: "Source", kind: "text", code: true, wrap: true, size: 264, minSize: 192, maxSize: 400,
    exportValue: (item) => item.source ? JSON.stringify(item.source) : "",
    cell: (item) => (
      <code className="block rounded bg-muted px-1.5 py-1 text-[11px] text-muted-foreground">
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
  const [requestedTab, setTab] = useTabParam("tab", "import");
  const tab = ["import", "readiness", "report", "history"].includes(requestedTab) ? requestedTab : "import";
  const [family, setFamily] = useTabParam("family", "policies");
  const uploadGeneration = useRef(0);
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; uploadGeneration.current += 1; }; }, []);
  const sourcesQ = useQuery({ queryKey: ["migration-sources"], queryFn: () => enterprise.migration() });
  const importsQ = useInfiniteQuery({
    queryKey: ["migration-imports-pages"],
    queryFn: ({ pageParam }) => enterprise.migrationImportsPage(pageParam ? { limit: 25, cursor: pageParam } : { limit: 25 }),
    initialPageParam: "",
    getNextPageParam: (page) => page.has_more ? page.next_cursor : undefined,
  });
  const clustersQ = useQuery({ queryKey: ["clusters"], queryFn: () => clustersApi.list(), staleTime: 30_000 });
  const sources = sourcesQ.isSuccess ? sourcesQ.data.sources : [];
  const clusterOptions = useMemo(() => clustersQ.isSuccess ? clustersQ.data.clusters : [], [clustersQ.isSuccess, clustersQ.data?.clusters]);

  const [source, setSource] = useState("neuvector");
  const [exportText, setExportText] = useState("");
  const [uploadError, setUploadError] = useState("");
  const [targetClusterID, setTargetClusterID] = useState("");
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);

  const draftKey = JSON.stringify([source, exportText, targetClusterID]);
  const currentDraftKey = useRef(draftKey);
  currentDraftKey.current = draftKey;
  const targetReady = !targetClusterID || clustersQ.isSuccess && !clustersQ.isFetching && clusterOptions.some(cluster => cluster.id === targetClusterID);
  const sourceReady = sourcesQ.isSuccess && !sourcesQ.isFetching && (sources.some(item => item.id === source) || sources.length === 0 && source === "neuvector");
  const preview = useMutation({
    mutationFn: async (input: { source: string; export: string; cluster_id?: string; draftKey: string }) => {
      const sourceState = qc.getQueryState<Awaited<ReturnType<typeof enterprise.migration>>>(["migration-sources"]);
      const clusterState = qc.getQueryState<Awaited<ReturnType<typeof clustersApi.list>>>(["clusters"]);
      if (!active.current || currentDraftKey.current !== input.draftKey || sourceState?.status !== "success" || sourceState.fetchStatus !== "idle" || sourceState.isInvalidated ||
        !(sourceState.data?.sources.some(item => item.id === input.source) || sourceState.data?.sources.length === 0 && input.source === "neuvector") ||
        input.cluster_id && (clusterState?.status !== "success" || clusterState.fetchStatus !== "idle" || clusterState.isInvalidated || !clusterState.data?.clusters.some(cluster => cluster.id === input.cluster_id))) {
        throw new Error("Source or target changed. Wait for the current configuration and preview again.");
      }
      if (new Blob([input.export]).size > MAX_EXPORT_BYTES) throw new Error("Export exceeds the 2 MiB limit.");
      const result = await enterprise.migrationPreview({ source: input.source, export: input.export, cluster_id: input.cluster_id });
      if (result.summary.source !== input.source || (result.target_cluster_id || "") !== (input.cluster_id || "")) throw new Error("Preview response did not confirm the reviewed source and target. Preview again before applying.");
      return result;
    },
    onSuccess: (result, input) => {
      if (active.current && currentDraftKey.current === input.draftKey) setSelectedPolicy(result.policies[0]?.name ?? null);
      void qc.invalidateQueries({ queryKey: ["migration-imports-pages"] });
      if (active.current && currentDraftKey.current === input.draftKey) toast.success(result.import_id ? "Migration preview saved" : "Migration preview generated");
    },
    onError: (error) => toast.error(migrationErrorMessage(error, "Migration preview failed")),
  });

  function requireCurrentImport(id: string, action: "apply" | "rollback" | "download") {
    const state = qc.getQueryState<typeof importsQ.data>(["migration-imports-pages"]);
    const item = state?.data?.pages.flatMap(page => page.imports).find(item => item.id === id);
    if (!active.current || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || !item ||
      (action === "apply" ? !canApplyImport(item) : action === "rollback" ? !canRollbackImport(item) : !canDownloadRollbackBundle(item))) {
      throw new Error("Import history changed or is unavailable. Refresh it before continuing.");
    }
    return item;
  }

  const applyImport = useMutation({
    mutationFn: (id: string) => { requireCurrentImport(id, "apply"); return enterprise.migrationApply(id); },
    onSuccess: (res, id) => {
      const appliedTarget = qc.getQueryData<typeof importsQ.data>(["migration-imports-pages"])?.pages.flatMap(page => page.imports).find(item => item.id === id)?.target_cluster_id;
      void qc.invalidateQueries({ queryKey: ["migration-imports-pages"] });
      if (appliedTarget) {
        void qc.invalidateQueries({ queryKey: ["runtime-dlp-rules", appliedTarget] });
        void qc.invalidateQueries({ queryKey: ["runtime-signatures", appliedTarget] });
        void qc.invalidateQueries({ queryKey: ["network-rules", appliedTarget] });
        void qc.invalidateQueries({ queryKey: ["baselines", appliedTarget] });
      }
      void qc.invalidateQueries({ queryKey: ["dpi-group-bindings"] });
      void qc.invalidateQueries({ queryKey: ["groups"] });
      void qc.invalidateQueries({ queryKey: ["group-usage"] });
      void qc.invalidateQueries({ queryKey: ["network-rules"] });
      void qc.invalidateQueries({ queryKey: ["registries"] });
      void qc.invalidateQueries({ queryKey: ["registry"] });
      void qc.invalidateQueries({ queryKey: ["vuln-profiles"] });
      if (res.status === "partial_applied" || (res.unsupported?.length ?? 0) > 0) {
        toast.warning("Migration partially applied. Unsupported records or omitted fields were not imported or queued. Review diagnostics and credential reissue instructions.");
      } else {
        toast.success(res.already_applied ? "Migration import already applied" : "Migration import applied");
      }
    },
    onError: (error) => toast.error(migrationErrorMessage(error, "Migration apply failed")),
  });

  const rollbackImport = useMutation({
    mutationFn: (id: string) => { requireCurrentImport(id, "rollback"); return enterprise.migrationRollback(id); },
    onSuccess: (res, id) => {
      const appliedTarget = qc.getQueryData<typeof importsQ.data>(["migration-imports-pages"])?.pages.flatMap(page => page.imports).find(item => item.id === id)?.target_cluster_id;
      void qc.invalidateQueries({ queryKey: ["migration-imports-pages"] });
      if (appliedTarget) {
        void qc.invalidateQueries({ queryKey: ["runtime-dlp-rules", appliedTarget] });
        void qc.invalidateQueries({ queryKey: ["runtime-signatures", appliedTarget] });
        void qc.invalidateQueries({ queryKey: ["network-rules", appliedTarget] });
        void qc.invalidateQueries({ queryKey: ["baselines", appliedTarget] });
      }
      void qc.invalidateQueries({ queryKey: ["dpi-group-bindings"] });
      void qc.invalidateQueries({ queryKey: ["groups"] });
      void qc.invalidateQueries({ queryKey: ["group-usage"] });
      void qc.invalidateQueries({ queryKey: ["network-rules"] });
      void qc.invalidateQueries({ queryKey: ["registries"] });
      void qc.invalidateQueries({ queryKey: ["registry"] });
      void qc.invalidateQueries({ queryKey: ["vuln-profiles"] });
      toast.success(res.already_rolled_back ? "Migration import already rolled back" : `Migration rollback complete (${res.restored ?? 0} restored, ${res.deleted ?? 0} deleted)`);
    },
    onError: (error) => toast.error(migrationErrorMessage(error, "Migration rollback failed")),
  });

  const rollbackBundleDownload = useMutation({
    mutationFn: (id: string) => { requireCurrentImport(id, "download"); return enterprise.migrationRollbackBundle(id); },
    onSuccess: (bundle, id) => {
      if (!active.current) return;
      downloadJson(`constellation-migration-rollback-${id}.json`, bundle);
      toast.success("Rollback bundle downloaded");
    },
    onError: (error) => toast.error(migrationErrorMessage(error, "Rollback bundle download failed")),
  });

  const data = preview.variables?.draftKey === draftKey ? preview.data : undefined;
  const historyReady = importsQ.isSuccess && !importsQ.isFetching;
  const selected = data?.policies.find((p) => p.name === selectedPolicy);
  const processProfiles = data?.process_profiles ?? [];
  const groups = data?.groups ?? [];
  const dpiBindings = data?.dpi_bindings ?? [];
  const networkRules = data?.network_rules ?? [];
  const vulnerabilityProfiles = data?.vulnerability_profiles ?? [];
  const registries = data?.registries ?? [];
  const unsupportedRows = useMemo(() => (data?.unsupported ?? []).map((item, diagnosticIndex) => ({ ...item, diagnosticIndex })), [data?.unsupported]);
  const imports = importsQ.isSuccess || importsQ.isFetchNextPageError ? importsQ.data?.pages.flatMap((page) => page.imports) ?? [] : [];
  const activeImport = data?.import_id ? imports.find((item) => item.id === data.import_id) : undefined;
  const activeStatus = activeImport?.status ?? (data?.import_id ? "status unavailable" : "preview");
  const canApplyActive = Boolean(activeImport) && historyReady && targetReady && sourceReady && (activeStatus === "previewed" || activeStatus === "rolled_back");
  const readiness = buildMigrationReadiness(data, activeImport, imports);
  const readinessCounts = countReadiness(readiness);
  const reportReady = historyReady && (!data?.import_id || !!activeImport);
  const reportText = `Evidence scope: current draft preview and ${imports.length} loaded organization-wide import records. History is fetched in pages of 25${importsQ.hasNextPage ? "; older records remain unloaded" : ""}. This report is not a full inventory or cutover validation.\n\n` + buildMigrationReport({
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
      header: "Import", kind: "name", wrap: true,
      exportHeader: "Import ID",
      exportValue: (item) => item.id,
      cell: (item) => (
        <div>
          <div className="font-medium">{migrationSourceLabel(item.source)}</div>
          <div className="font-mono text-[11px] text-muted-foreground">{item.id}</div>
          <div className="text-[11px] text-muted-foreground">Target: {item.target_cluster_id ?? "unknown or unspecified"}</div>
        </div>
      ),
    },
    {
      id: "status",
      header: "Status", kind: "status", size: 152, minSize: 128, maxSize: 192,
      exportValue: (item) => item.status,
      cell: (item) => <StatusPill label={item.status.replace("_", " ")} tone={migrationStatusTone(item.status)} />,
    },
    {
      id: "summary",
      header: "Summary", kind: "text", wrap: true, size: 320, minSize: 240, maxSize: 480, grow: true,
      exportValue: (item) => `${migrationSummaryLabel(item.summary)}; ${item.applied_summary ? migrationAppliedSummaryLabel(item.applied_summary) : "not applied"}${item.status === "rolled_back" ? "; subsequently rolled back" : ""}; ${(item.unsupported ?? []).map((diagnostic) => `${diagnostic.kind}: ${diagnostic.reason} ${diagnostic.suggestion ?? ""}`).join("; ")}`,
      cell: (item) => (
        <div className="whitespace-normal text-xs text-muted-foreground">
          <div>{migrationSummaryLabel(item.summary)}</div>
          <div>{item.applied_summary ? migrationAppliedSummaryLabel(item.applied_summary) : "Not applied"}{item.status === "rolled_back" ? " (subsequently rolled back)" : ""}</div>
          {item.error ? <div className="mt-1 text-destructive">{item.error}</div> : null}
          {(item.unsupported?.length ?? 0) > 0 ? (
            <details className="mt-2">
              <summary className="cursor-pointer font-medium text-foreground">Unsupported diagnostics and reissue instructions ({item.unsupported?.length})</summary>
              <p className="mt-2">Unsupported records and omitted fields are not imported or queued.</p>
              {item.unsupported?.map((diagnostic, index) => (
                <div key={`${diagnostic.kind}:${diagnostic.name}:${index}`} className="mt-2">
                  <div className="font-medium">{diagnostic.kind} · {diagnostic.name}</div>
                  <div>{diagnostic.reason}</div>
                  {diagnostic.suggestion ? <div>{diagnostic.suggestion}</div> : null}
                </div>
              ))}
            </details>
          ) : null}
        </div>
      ),
    },
    {
      id: "created",
      header: "Created", kind: "date", size: 224, minSize: 208, maxSize: 240,
      cell: (item) => formatDate(item.created_at),
      exportValue: (item) => item.created_at,
      className: "text-xs text-muted-foreground",
    },
    {
      id: "actions",
      header: "Actions", kind: "actions", size: 320, minSize: 296, maxSize: 352, wrap: true,
      exportable: false,
      cell: (item) => (
        <div className="flex flex-wrap justify-end gap-2">
          <Button
            size="sm"
            variant="primary"
            onClick={() => applyImport.mutate(item.id)}
            disabled={!historyReady || !canApplyImport(item) || applyImport.isPending || rollbackImport.isPending}
            data-testid={`migration-import-apply-${item.id}`}
          >
            <CircleCheck className="h-3.5 w-3.5" aria-hidden />
            Apply
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => rollbackImport.mutate(item.id)}
            disabled={!historyReady || !canRollbackImport(item) || rollbackImport.isPending || applyImport.isPending}
            data-testid={`migration-import-rollback-${item.id}`}
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden />
            Rollback
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => rollbackBundleDownload.mutate(item.id)}
            disabled={!historyReady || !canDownloadRollbackBundle(item) || rollbackBundleDownload.isPending}
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
        description="Preview policies, runtime profiles, groups, network rules, vulnerability profiles, and registry metadata from another security tool before applying."
      />

      <VerdictBanner status={sourcesQ.isError || importsQ.isError ? "degraded" : "info"}
        title={sourcesQ.isError || importsQ.isError ? "Migration evidence is unavailable" : data ? "Review this preview before applying" : "Preview an export before changing live configuration"}
        detail="Migration imports are organization-wide. Cluster-bound objects use the explicitly selected target; unsupported records and credentials are not imported." />
          <StatGrid>
            <StatCard label="Source Objects" value={data?.summary.source_total ?? data?.summary.total ?? "—"} />
            <StatCard label="Create" value={data?.summary.create ?? "—"} tone="low" />
            <StatCard label="Update" value={data?.summary.update ?? "—"} tone="medium" />
            <StatCard label="Enforce" value={data?.summary.enforce ?? "—"} tone="high" />
            <StatCard label="Unsupported Diagnostics" value={data?.summary.unsupported ?? "—"} tone={(data?.summary.unsupported ?? 0) > 0 ? "medium" : "neutral"} />
          </StatGrid>
      {(applyImport.isError || rollbackImport.isError || rollbackBundleDownload.isError) && <p role="alert" className="text-sm text-destructive">{migrationErrorMessage(applyImport.error ?? rollbackImport.error ?? rollbackBundleDownload.error, "Migration action failed")}</p>}
      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "import", label: "Preview import", content: <div className="space-y-6">
      <div data-testid="migration-preview-wizard">
        <Card
          title="Paste or upload an export"
          description="Choose the source tool and preview its exported configuration. The target cluster is optional; the server validates families that require a cluster."
        >
          <div className="space-y-5">
            <div className="flex flex-wrap items-end gap-3">
              <Field label="Source" className="w-56">
                <Select
                  disabled={sourcesQ.isPending || sourcesQ.isError || preview.isPending}
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
              <Field label="Target cluster (optional)" className="w-64">
                <Select
                  value={targetClusterID}
                  onChange={(e) => setTargetClusterID(e.target.value)}
                  disabled={preview.isPending || clustersQ.isFetching || clustersQ.isError}
                  data-testid="migration-target-cluster-select"
                >
                  <option value="">{clustersQ.isLoading ? "Loading clusters..." : "No target cluster"}</option>
                  {targetClusterID && !clusterOptions.some(cluster => cluster.id === targetClusterID) && <option value={targetClusterID}>Selected cluster unavailable ({targetClusterID})</option>}
                  {clusterOptions.map((cluster) => (
                    <option key={cluster.id} value={cluster.id}>{cluster.name || cluster.id}</option>
                  ))}
                </Select>
              </Field>
              <Button
                variant="primary"
                onClick={() => preview.mutate({ source, export: exportText, cluster_id: targetClusterID || undefined, draftKey })}
                disabled={preview.isPending || !targetReady || !sourceReady || exportText.trim().length === 0}
                data-testid="migration-preview-submit"
              >
                <WandSparkles className="h-4 w-4" aria-hidden />
                Preview import
              </Button>
            </div>

            {sourcesQ.isPending && <p role="status" className="text-sm text-muted-foreground">Loading migration sources…</p>}
            {uploadError && <p role="alert" className="text-sm text-destructive">{uploadError} Your draft is preserved.</p>}
            {sourcesQ.isError && <p role="alert" className="text-sm text-destructive">Migration sources are unavailable. Your draft is preserved. <Button onClick={() => void sourcesQ.refetch()}>Retry sources</Button></p>}
            {clustersQ.isError && <p role="alert" className="text-sm text-destructive">Target clusters are unavailable. Your selected target is preserved. <Button onClick={() => void clustersQ.refetch()}>Retry clusters</Button></p>}
            {!targetReady && !clustersQ.isFetching && <p role="alert" className="text-sm text-destructive">The selected cluster is unavailable. Choose a verified target before previewing or applying.</p>}
            {preview.isError && preview.variables?.draftKey === draftKey && <p role="alert" className="text-sm text-destructive">{migrationErrorMessage(preview.error, "Migration preview failed. Your draft is preserved")}</p>}
            {preview.data && preview.variables?.draftKey !== draftKey && <p role="status" className="text-sm text-muted-foreground">The draft changed. Preview again before applying.</p>}
            <p className="text-xs text-muted-foreground">Preview is read-only for live configuration: it saves an import preview but does not write live policies, profiles, or registries. Apply is a separate action.</p>
            <Field label="Upload export (maximum 2 MiB)">
              <input
                type="file"
                accept=".json,.yaml,.yml,.txt,application/json,application/yaml,text/plain"
                data-testid="migration-export-upload"
                className="text-xs"
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  event.target.value = "";
                  if (!file) return;
                  setUploadError("");
                  if (file.size > MAX_EXPORT_BYTES) {
                    setUploadError("Export exceeds the 2 MiB limit.");
                    toast.error("Export exceeds the 2 MiB limit.");
                    return;
                  }
                  const generation = ++uploadGeneration.current;
                  try {
                    const text = await file.text();
                    if (active.current && generation === uploadGeneration.current) setExportText(text);
                  } catch {
                    if (active.current && generation === uploadGeneration.current) setUploadError("Could not read the export file.");
                    toast.error("Could not read the export file.");
                  }
                }}
              />
            </Field>
            <Textarea
              value={exportText}
              onChange={(e) => { uploadGeneration.current += 1; setUploadError(""); setExportText(e.target.value); }}
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
                  <span>{data.import_id ? "Preview persisted" : "Preview not persisted"}</span>
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
                <CircleCheck className="h-4 w-4" aria-hidden />
                Apply import
              </Button>
            </div>
          </div>
          <Collapse label="Additional import object counts">
            <StatGrid>
              <StatCard label="Policies" value={data.policies.length} />
              <StatCard label="Unchanged" value={data.summary.unchanged ?? 0} />
              <StatCard label="File Profiles" value={data.summary.file_profiles} />
              <StatCard label="Process Profiles" value={data.summary.process_profiles ?? processProfiles.length} />
              <StatCard label="Groups" value={data.summary.groups ?? groups.length} />
              <StatCard label="Network Rules" value={data.summary.network_rules ?? networkRules.length} />
              <StatCard label="DLP / WAF" value={data.summary.dpi_rules} />
              <StatCard label="Group Scopes" value={data.summary.dpi_bindings ?? dpiBindings.length} />
              <StatCard label="Vulnerability Profiles" value={data.summary.vulnerability_profiles ?? vulnerabilityProfiles.length} />
              <StatCard label="Registries" value={data.summary.registries ?? registries.length} />
            </StatGrid>
          </Collapse>
          <Tabs value={["policies", "files", "processes", "groups", "network", "dpi", "bindings", "vulnerabilities", "registries", "diagnostics", "rollback"].includes(family) ? family : "policies"} onValueChange={setFamily} items={[
            { value: "policies", label: "Policies", content: <>
          <div className="space-y-4">
            <DataTable
              rows={data.policies}
              columns={policyColumns}
              rowKey={(p) => p.name}
              onRowClick={(p) => setSelectedPolicy(p.name)}
              showDensityToggle={false}
              exportFileName={`constellation-${data.summary.source}-policies`}
              preferencesKey="migration-preview-policies"
              testId="migration-preview-policies"
            />
            <Collapse label="Generated policy YAML"><Card title="Generated policy YAML">
              <pre className="max-h-64 overflow-auto rounded bg-muted p-2 text-xs" data-testid="migration-preview-yaml">
                {selected?.spec_yaml ?? "No policy selected."}
              </pre>
            </Card></Collapse>
          </div>
            </> },
            { value: "files", label: "File profiles", content: <>
          {data.file_profiles.length > 0 ? (
            <div data-testid="migration-preview-file-profiles">
              <DataTable
                rows={data.file_profiles}
                columns={fileProfileColumns}
                rowKey={(p) => p.group}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-file-profiles`}
                preferencesKey="migration-preview-file-profile-table"
              testId="migration-preview-file-profile-table"
              />
            </div>
          ) : <p className="py-6 text-sm text-muted-foreground">No file profiles in this preview.</p>}
            </> },
            { value: "processes", label: "Process profiles", content: <>
          {processProfiles.length > 0 ? (
            <div data-testid="migration-preview-process-profiles">
              <DataTable
                rows={processProfiles}
                columns={processProfileColumns}
                rowKey={(p) => `${p.cluster_id}:${p.group}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-process-profiles`}
                preferencesKey="migration-preview-process-profile-table"
              testId="migration-preview-process-profile-table"
              />
            </div>
          ) : <p className="py-6 text-sm text-muted-foreground">No process profiles in this preview.</p>}
            </> },
            { value: "groups", label: "Groups", content: <>
          {groups.length > 0 ? (
            <div data-testid="migration-preview-groups">
              <DataTable
                rows={groups}
                columns={groupColumns}
                rowKey={(group) => `${group.cluster_id}:${group.name}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-groups`}
                preferencesKey="migration-preview-group-table"
              testId="migration-preview-group-table"
              />
            </div>
          ) : <p className="py-6 text-sm text-muted-foreground">No groups in this preview.</p>}
            </> },
            { value: "network", label: "Network rules", content: <>
          {networkRules.length > 0 ? (
            <div data-testid="migration-preview-network-rules">
              <DataTable
                rows={networkRules}
                columns={networkRuleColumns}
                rowKey={(rule) => `${rule.cluster_id}:${rule.from_group}:${rule.to_group}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-network-rules`}
                preferencesKey="migration-preview-network-rule-table"
              testId="migration-preview-network-rule-table"
              />
            </div>
          ) : <p className="py-6 text-sm text-muted-foreground">No network rules in this preview.</p>}
            </> },
            { value: "dpi", label: "DLP / WAF", content: <>
          {data.dpi_rules.length > 0 ? (
            <div data-testid="migration-preview-dpi-rules">
              <DataTable
                rows={data.dpi_rules}
                columns={dpiRuleColumns}
                rowKey={(r) => `${r.cluster_id}:${r.name}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-dlp-waf-rules`}
                preferencesKey="migration-preview-dpi-rule-table"
              testId="migration-preview-dpi-rule-table"
              />
            </div>
          ) : <p className="py-6 text-sm text-muted-foreground">No DLP / WAF rules in this preview.</p>}
            </> },
            { value: "bindings", label: "Group scopes", content: <>
          {dpiBindings.length > 0 ? (
            <div data-testid="migration-preview-dpi-bindings">
              <DataTable
                rows={dpiBindings}
                columns={dpiBindingColumns}
                rowKey={(binding) => `${binding.sensor_kind}:${binding.target_group_id}:${binding.source_group}`}
                showDensityToggle={false}
                exportFileName={`constellation-${data.summary.source}-dlp-waf-group-scopes`}
                preferencesKey="migration-preview-dpi-binding-table"
              testId="migration-preview-dpi-binding-table"
              />
            </div>
          ) : <p className="py-6 text-sm text-muted-foreground">No group scopes in this preview.</p>}
            </> },
            { value: "vulnerabilities", label: "Vulnerability profiles", content: <>
          {vulnerabilityProfiles.length > 0 ? (
            <DataTable
              rows={vulnerabilityProfiles}
              columns={vulnerabilityProfileColumns}
              rowKey={(profile) => `${profile.cluster_id ?? ""}:${profile.name}`}
              showDensityToggle={false}
              preferencesKey="migration-preview-vulnerability-profiles"
              testId="migration-preview-vulnerability-profiles"
              exportFileName={`constellation-${data.summary.source}-vulnerability-profiles`}
            />
          ) : <p className="py-6 text-sm text-muted-foreground">No vulnerability profiles in this preview.</p>}
            </> },
            { value: "registries", label: "Registries", content: <>
          {registries.length > 0 ? (
            <Card title="Registry metadata" description="Imported registries use manual scan cadence and no credentials. No scans are queued. Reissue required credentials and review image scope before scanning." padded={false}>
              <DataTable
                rows={registries}
                columns={registryColumns}
                rowKey={(registry) => registry.name}
                showDensityToggle={false}
                preferencesKey="migration-preview-registries"
              testId="migration-preview-registries"
                exportFileName={`constellation-${data.summary.source}-registries`}
              />
            </Card>
          ) : <p className="py-6 text-sm text-muted-foreground">No registries in this preview.</p>}
            </> },
            { value: "diagnostics", label: "Diagnostics", content: <>
          {(data.unsupported?.length ?? 0) > 0 ? (
            <Card
              title="Unsupported Diagnostics"
              description="Unsupported records and omitted fields are not imported or queued. Diagnostics can overlap supported object counts. Review reasons and reissue instructions before cutover."
              padded={false}
            >
              <DataTable<MigrationDiagnostic>
                rows={unsupportedRows}
                columns={unsupportedColumns}
                rowKey={(item) => `${item.kind}:${item.name}:${item.diagnosticIndex}`}
                showDensityToggle={false}
                preferencesKey="migration-preview-unsupported"
              testId="migration-preview-unsupported"
                exportFileName={`constellation-${data.summary.source}-unsupported`}
              />
            </Card>
          ) : <p className="py-6 text-sm text-muted-foreground">No unsupported diagnostics in this preview.</p>}
            </> },
            { value: "rollback", label: "Rollback preview", content: <>
          <Card title="Rollback bundle preview" description="This preview bundle is nonreplayable and cannot restore live objects. After apply, download the saved rollback bundle from import history. Later changes may block rollback.">
            <pre className="max-h-40 overflow-auto rounded bg-muted p-2 text-xs" data-testid="migration-rollback-bundle">
              {data.rollback_bundle}
            </pre>
          </Card>
            </> },
          ]} />
        </div>
      ) : null}

        </div> },
        { value: "readiness", label: "Readiness", content: <>
      <section className="space-y-4" data-testid="migration-switch-readiness">
        {importsQ.isPending ? <LoadingState label="Loading migration readiness evidence…" /> : importsQ.isError && !importsQ.isFetchNextPageError ? <ErrorState title="Migration readiness evidence is unavailable." action={<Button onClick={() => void importsQ.refetch()}>Retry history</Button>} /> : <Card
          title="Switch Readiness"
          description="Current preview, loaded import history, manual mapping work and rollback evidence. These checks do not validate the complete organization inventory."
        >
          <p className="text-sm text-muted-foreground">{readinessCounts.blocker} blockers · {readinessCounts.warning} warnings · {readinessCounts.ready} ready checks · {imports.length} loaded imports</p>
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
                  <a href={item.href} className="mt-2 inline-flex items-center gap-1 text-xs text-[color:var(--color-primary)] hover:underline">
                    Open <ArrowRight className="h-3 w-3" aria-hidden />
                  </a>
                ) : null}
              </article>
            ))}
          </div>
        </Card>}

      </section>
        </> },
        { value: "report", label: "Report and follow-up", content: <div className="space-y-6">
        {importsQ.isError && !importsQ.isFetchNextPageError && <ErrorState title="Report history is unavailable. Export is paused." action={<Button onClick={() => void importsQ.refetch()}>Retry history</Button>} />}
        <Card
          title="Migration Report"
          description="Export a cutover summary with imported counts, unsupported objects, rollback state, and recommended follow-up."
        >
          <div className="space-y-3" data-testid="migration-report-panel">
            <p className="text-xs text-muted-foreground">This report covers the current preview and {imports.length} loaded import records. {importsQ.hasNextPage ? "Older history remains unloaded. " : ""}It is not a full inventory or cutover validation.</p>
            <div className="rounded-md bg-muted p-3 text-xs text-muted-foreground">
                <div className="font-medium text-foreground">{migrationSourceLabel(data?.summary.source ?? activeImport?.source ?? source)} report</div>
              <div className="mt-1">
                {(data?.summary.total ?? activeImport?.summary.total ?? 0)} previewed items · {(data?.summary.unsupported ?? activeImport?.summary.unsupported ?? 0)} unsupported diagnostics · {importsQ.isSuccess || importsQ.isFetchNextPageError ? imports.length : "Unavailable"} loaded saved imports
              </div>
            </div>
            <Button
              variant="outline"
              onClick={() => downloadMigrationReport(reportText, data?.summary.source ?? activeImport?.source ?? source)}
              disabled={!reportReady}
              data-testid="migration-report-export"
            >
              <Download className="h-4 w-4" aria-hidden />
              Export report
            </Button>
          </div>
        </Card>


      <Card
        title="Post-Import Actions"
        description="Controls that should be reviewed after policy migration so the cutover uses Constellation's stronger evidence and operations model."
        padded={false}
      >
        <div className="grid gap-2 p-3 md:grid-cols-2 xl:grid-cols-4" data-testid="migration-recommended-actions">
          {MIGRATION_RECOMMENDED_ACTIONS.map((action) => (
            <a
              key={action.id}
              href={action.href}
              className="group rounded-md border border-border bg-background p-3 transition-colors hover:border-[color:var(--color-primary)]/60 hover:bg-accent"
              data-testid={`migration-action-${action.id}`}
            >
              <div className="flex items-center gap-2 text-sm font-medium">
                <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground group-hover:text-[color:var(--color-primary)]" aria-hidden />
                {action.title}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{action.detail}</p>
            </a>
          ))}
        </div>
      </Card>

        </div> },
        { value: "history", label: "Import history", content: <>
      <Card
        title="Import History"
        description="Persisted previews, applied imports, partial imports, failures, and rollback state for the current organization. Load more to inspect older records."
        padded={false}
      >
        <div className="flex flex-wrap items-center justify-between gap-2 px-6 pt-4 text-xs text-muted-foreground">
          <span>The table’s CSV includes loaded rows only.</span>
          <a href="/api/v1/migration/imports/export" download="migration-imports.ndjson" className="font-medium text-primary underline underline-offset-2" data-testid="migration-import-history-export-all">
            Download all history (NDJSON)
          </a>
        </div>
        <p className="px-6 pt-1 text-xs text-muted-foreground">The download contains metadata only. Verify its final complete record and count before treating it as a full export.</p>
        {importsQ.isPending ? <p className="px-6 pt-4 text-xs" role="status">Loading import history…</p> : null}
        {importsQ.isError && !importsQ.isFetchNextPageError ? <p className="px-6 pt-4 text-xs text-destructive" role="alert">Import history is unavailable. Actions are paused. <Button onClick={() => void importsQ.refetch()}>Retry history</Button></p> : null}
        {importsQ.isFetching && !importsQ.isPending && <p role="status" className="px-6 pt-4 text-xs">Refreshing import history…</p>}
        <DataTable
          rows={imports}
          columns={historyColumns}
          rowKey={(item) => item.id}
          preferencesKey="migration-import-history"
          testId="migration-import-history"
          exportFileName="constellation-migration-import-history"
          emptyState={<div className="px-6 py-10 text-center text-xs text-muted-foreground">{importsQ.isPending ? "Loading import history…" : importsQ.isError ? "Import history is unavailable." : "No migration imports yet."}</div>}
        />
        {importsQ.isFetchNextPageError ? <p className="px-6 py-2 text-xs text-destructive" role="alert">Could not load older imports. Try again.</p> : null}
        {importsQ.hasNextPage ? (
          <div className="px-6 py-4">
            <Button variant="outline" data-testid="migration-import-history-load-more" disabled={importsQ.isFetchingNextPage} onClick={() => void importsQ.fetchNextPage()}>
              {importsQ.isFetchingNextPage ? "Loading more…" : "Load more imports"}
            </Button>
          </div>
        ) : null}
      </Card>        </> },
      ]} />
    </div>
  );
}

function migrationErrorMessage(error: unknown, fallback: string) {
  if (error && typeof error === "object" && "response" in error) {
    const response = error.response as { data?: { error?: unknown; message?: unknown } } | undefined;
    const reason = response?.data?.error ?? response?.data?.message;
    if (typeof reason === "string" && reason.trim()) return `${fallback}: ${reason}`;
  }
  return error instanceof Error && error.message ? `${fallback}: ${error.message}` : fallback;
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
