import type { MigrationImportListItem, MigrationPreview, MigrationUnsupported } from "@/api/client";

export type MigrationReadinessCategory = "blocker" | "warning" | "info" | "ready";

export interface MigrationReadinessItem {
  id: string;
  category: MigrationReadinessCategory;
  title: string;
  detail: string;
  href?: string;
}

export interface MigrationRecommendedAction {
  id: string;
  title: string;
  detail: string;
  href: string;
}

export const MIGRATION_RECOMMENDED_ACTIONS: MigrationRecommendedAction[] = [
  {
    id: "attestation-trust",
    title: "Enable attestation trust",
    detail: "Require signed SBOM, VEX, provenance, or deploy attestations for release gates.",
    href: "/settings/attestation-trust",
  },
  {
    id: "repository-scans",
    title: "Configure repository scans",
    detail: "Scan source repositories and IaC alongside running image findings.",
    href: "/repositories",
  },
  {
    id: "serverless-scans",
    title: "Review serverless inventory",
    detail: "Cover functions and packages that do not appear as Kubernetes workloads.",
    href: "/serverless",
  },
  {
    id: "compliance-reports",
    title: "Schedule compliance reports",
    detail: "Use signed evidence and scheduled posture runs for audit-ready exports.",
    href: "/compliance",
  },
  {
    id: "siem-routing",
    title: "Connect SIEM and webhooks",
    detail: "Route runtime, admission, scan, and migration audit events to operations tools.",
    href: "/settings/integrations",
  },
  {
    id: "backup",
    title: "Enable backup",
    detail: "Protect imported policy state, config revisions, and audit continuity.",
    href: "/settings/backup",
  },
  {
    id: "federation",
    title: "Review federation controls",
    detail: "Confirm signed trust, join policy, and peer health before multi-cluster rollout.",
    href: "/federation",
  },
  {
    id: "effective-config",
    title: "Verify effective config",
    detail: "Compare scanner, registry, network, syslog, auth, and component-applied state.",
    href: "/settings/effective-config",
  },
];

export function buildMigrationReadiness(
  preview: MigrationPreview | undefined,
  activeImport: MigrationImportListItem | undefined,
  imports: MigrationImportListItem[],
): MigrationReadinessItem[] {
  const items: MigrationReadinessItem[] = [];
  const unsupported = preview?.unsupported ?? activeImport?.unsupported ?? [];
  const status = activeImport?.status ?? (preview?.import_id ? "previewed" : "");
  const failedImports = imports.filter((item) => item.status === "failed");

  if (!preview && imports.length === 0) {
    items.push({
      id: "preview-required",
      category: "blocker",
      title: "Import preview required",
      detail: "Paste an export and generate a persisted preview before planning a switch.",
    });
  }

  if (preview && !preview.import_id) {
    items.push({
      id: "preview-not-persisted",
      category: "warning",
      title: "Preview is not persisted",
      detail: "Apply and rollback require a saved import ID from the API.",
    });
  }

  if (status === "previewed" || status === "rolled_back") {
    items.push({
      id: "apply-pending",
      category: "warning",
      title: "Import apply is pending",
      detail: "The preview is saved but converted objects have not been applied to live storage.",
    });
  }

  if (status === "failed") {
    items.push({
      id: "import-failed",
      category: "blocker",
      title: "Latest import failed",
      detail: activeImport?.error || "Review the failed import and generate a fresh preview before retrying.",
    });
  }

  if (unsupported.length > 0) {
    items.push({
      id: "manual-mapping",
      category: "warning",
      title: `${unsupported.length} object${unsupported.length === 1 ? "" : "s"} need manual mapping`,
      detail: "Unsupported or queued records were preserved in the preview and report, but require target mapping before they can be enforced automatically.",
    });
  }

  const unaccounted = preview?.summary.unaccounted_source ?? activeImport?.summary.unaccounted_source ?? 0;
  if (unaccounted > 0) {
    items.push({
      id: "source-count-gap",
      category: "warning",
      title: `${unaccounted} source object${unaccounted === 1 ? "" : "s"} need count reconciliation`,
      detail: "Source counts exceed converted plus unsupported rows. Review the family counts before treating the cutover as complete.",
    });
  }

  if (preview?.rollback_bundle || activeImport?.status === "applied" || activeImport?.status === "partial_applied") {
    items.push({
      id: "rollback-ready",
      category: "ready",
      title: "Rollback evidence is available",
      detail: "The import includes rollback metadata for created or updated policies, groups, and runtime profiles.",
    });
  }

  if (activeImport?.status === "applied" && unsupported.length === 0) {
    items.push({
      id: "policy-import-complete",
      category: "ready",
      title: "Converted import is complete",
      detail: migrationAppliedSummaryLabel(activeImport.applied_summary ?? {}),
    });
  }

  if (activeImport?.status === "partial_applied") {
    items.push({
      id: "partial-apply",
      category: "warning",
      title: "Import is partially applied",
      detail: "Converted objects were applied, but queued records remain for manual mapping.",
    });
  }

  if (failedImports.length > 0) {
    items.push({
      id: "failed-history",
      category: "info",
      title: `${failedImports.length} failed import${failedImports.length === 1 ? "" : "s"} in history`,
      detail: "Keep failed attempts in the migration report so operators can reconcile retries and audit events.",
    });
  }

  if (items.length === 0) {
    items.push({
      id: "ready-for-preview",
      category: "info",
      title: "Ready for import preview",
      detail: "No saved import state exists yet for this view.",
    });
  }

  return items;
}

export function countReadiness(items: MigrationReadinessItem[]) {
  return items.reduce<Record<MigrationReadinessCategory, number>>(
    (acc, item) => {
      acc[item.category] += 1;
      return acc;
    },
    { blocker: 0, warning: 0, info: 0, ready: 0 },
  );
}

export function buildMigrationReport({
  source,
  preview,
  activeImport,
  imports,
  readiness,
  actions,
}: {
  source: string;
  preview?: MigrationPreview;
  activeImport?: MigrationImportListItem;
  imports: MigrationImportListItem[];
  readiness: MigrationReadinessItem[];
  actions: MigrationRecommendedAction[];
}) {
  const summary = preview?.summary ?? activeImport?.summary;
  const unsupported = preview?.unsupported ?? activeImport?.unsupported ?? [];
  const lines = [
    `# ${migrationSourceLabel(summary?.source ?? source)} Migration Report`,
    "",
    `Generated: ${new Date().toISOString()}`,
    `Active import: ${activeImport?.id ?? preview?.import_id ?? "none"}`,
    `Status: ${activeImport?.status ?? (preview?.import_id ? "previewed" : "not-previewed")}`,
    "",
    "## Summary",
    `- Source objects: ${summary?.source_total ?? summary?.total ?? 0}`,
    `- Total items: ${summary?.total ?? 0}`,
    `- Create: ${summary?.create ?? 0}`,
    `- Update: ${summary?.update ?? 0}`,
    `- Enforce: ${summary?.enforce ?? 0}`,
    `- Monitor: ${summary?.monitor ?? 0}`,
    `- File profiles: ${summary?.file_profiles ?? 0}`,
    `- Process profiles: ${summary?.process_profiles ?? 0}`,
    `- Groups: ${summary?.groups ?? 0}`,
    `- Network rules: ${summary?.network_rules ?? 0}`,
    `- DLP/WAF rules: ${summary?.dpi_rules ?? 0}`,
    `- DLP/WAF group scopes: ${summary?.dpi_bindings ?? 0}`,
    `- Unsupported or queued: ${summary?.unsupported ?? unsupported.length}`,
    `- Unaccounted source objects: ${summary?.unaccounted_source ?? 0}`,
    "",
    "## Source Counts",
    ...formatSourceCountRows(summary?.source_counts),
    "",
    "## Readiness",
    ...readiness.map((item) => `- [${item.category}] ${item.title}: ${item.detail}`),
    "",
    "## Unsupported Or Queued Objects",
    ...formatUnsupportedReportRows(unsupported),
    "",
    "## Import History",
    ...(imports.length > 0
      ? imports.map((item) => `- ${item.id} ${migrationSourceLabel(item.source)} ${item.status} created=${item.created_at}${item.applied_at ? ` applied=${item.applied_at}` : ""}${item.rolled_back_at ? ` rolled_back=${item.rolled_back_at}` : ""}`)
      : ["- None"]),
    "",
    "## Recommended Follow-Up",
    ...actions.map((action) => `- ${action.title}: ${action.detail} (${action.href})`),
    "",
  ];
  return lines.join("\n");
}

export function migrationSourceLabel(value: string) {
  switch (value) {
    case "neuvector":
      return "NeuVector";
    case "stackrox":
    case "rhacs":
      return "StackRox / RHACS";
    case "aqua":
      return "Aqua";
    case "prisma":
      return "Prisma Cloud";
    default:
      return value;
  }
}

export function migrationAppliedSummaryLabel(summary: Record<string, number>) {
  const created = summary.created ?? 0;
  const updated = summary.updated ?? 0;
  const policies = summary.policies ?? created + updated;
  const fileProfiles = summary.file_profiles ?? 0;
  const processProfiles = summary.process_profiles ?? 0;
  const groups = summary.groups ?? 0;
  const networkRules = summary.network_rules ?? 0;
  const dpiRules = summary.dpi_rules ?? 0;
  const dpiBindings = summary.dpi_bindings ?? 0;
  const fileProfileText = fileProfiles > 0 ? ` · ${fileProfiles} file profiles` : "";
  const processProfileText = processProfiles > 0 ? ` · ${processProfiles} process profiles` : "";
  const groupText = groups > 0 ? ` · ${groups} groups` : "";
  const networkText = networkRules > 0 ? ` · ${networkRules} network rules` : "";
  const dpiText = dpiRules > 0 ? ` · ${dpiRules} DLP/WAF rules` : "";
  const bindingText = dpiBindings > 0 ? ` · ${dpiBindings} DLP/WAF group scopes` : "";
  return `${created + updated} object changes applied · ${created} created · ${updated} updated · ${policies} policies${fileProfileText}${processProfileText}${groupText}${networkText}${dpiText}${bindingText}`;
}

function formatUnsupportedReportRows(unsupported: MigrationUnsupported[]) {
  if (unsupported.length === 0) return ["- None"];
  return unsupported.map((item) => (
    `- ${item.kind} ${item.name}: ${item.reason}${item.suggestion ? ` Suggested fix: ${item.suggestion}` : ""}`
  ));
}

function formatSourceCountRows(counts?: Record<string, number>) {
  if (!counts || Object.keys(counts).length === 0) return ["- Not available"];
  const labels: Record<string, string> = {
    policies: "Policies",
    admission_rules: "Admission rules",
    response_rules: "Response rules",
    file_profiles: "File profiles",
    process_profiles: "Process profiles",
    groups: "Groups",
    network_rules: "Network rules",
    dpi_rules: "DLP/WAF rules",
    dpi_bindings: "DLP/WAF group scopes",
  };
  const order = [
    "policies",
    "admission_rules",
    "response_rules",
    "file_profiles",
    "process_profiles",
    "groups",
    "network_rules",
    "dpi_rules",
    "dpi_bindings",
  ];
  return order
    .filter((key) => counts[key] !== undefined)
    .map((key) => `- ${labels[key] ?? key}: ${counts[key]}`);
}
