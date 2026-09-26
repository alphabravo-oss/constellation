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
  const unsupported = activeImport?.unsupported ?? preview?.unsupported ?? [];
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
      detail: status === "rolled_back" ? "The import was rolled back. Review a fresh preview before applying again." : "The preview is saved. Preview does not write live configuration; apply is a separate action.",
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
      title: `${unsupported.length} unsupported diagnostic${unsupported.length === 1 ? "" : "s"} need review`,
      detail: "Unsupported records and omitted fields are diagnostics only. They are not imported or queued. Review each reason and any credential reissue instructions.",
    });
  }

  const unaccounted = preview?.summary.unaccounted_source ?? activeImport?.summary.unaccounted_source ?? 0;
  if (unaccounted > 0) {
    items.push({
      id: "source-count-gap",
      category: "warning",
      title: `${unaccounted} source object${unaccounted === 1 ? "" : "s"} need count reconciliation`,
      detail: "The server reports a source accounting gap. Review family counts and diagnostics before treating the cutover as complete; diagnostics may describe fields within supported objects.",
    });
  }

  if (activeImport?.status === "applied" || activeImport?.status === "partial_applied") {
    items.push({
      id: "rollback-ready",
      category: "ready",
      title: "Rollback evidence is available",
      detail: "Download the rollback bundle saved during apply to review restoration of created or updated objects, including vulnerability profiles and registries. Rollback can be blocked by later changes.",
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
      detail: "Supported objects were applied. Unsupported records or omitted fields were not imported or queued; review diagnostics and reissue credentials where required.",
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
  const unsupported = activeImport?.unsupported ?? preview?.unsupported ?? [];
  const lines = [
    `# ${migrationSourceLabel(summary?.source ?? source)} Migration Report`,
    "",
    `Generated: ${new Date().toISOString()}`,
    `Active import: ${activeImport?.id ?? preview?.import_id ?? "none"}`,
    `Status: ${activeImport?.status ?? (preview?.import_id ? "previewed" : "not-previewed")}`,
    "Preview is read-only for live configuration. Saving a preview does not apply objects.",
    "The preview rollback bundle is nonreplayable. Download the rollback bundle after apply for restoration evidence.",
    "",
    "## Summary",
    `- Source objects: ${summary?.source_total ?? summary?.total ?? 0}`,
    `- Total items: ${summary?.total ?? 0}`,
    `- Create: ${summary?.create ?? 0}`,
    `- Update: ${summary?.update ?? 0}`,
    `- Unchanged: ${summary?.unchanged ?? 0}`,
    `- Enforce: ${summary?.enforce ?? 0}`,
    `- Monitor: ${summary?.monitor ?? 0}`,
    `- File profiles: ${summary?.file_profiles ?? 0}`,
    `- Process profiles: ${summary?.process_profiles ?? 0}`,
    `- Groups: ${summary?.groups ?? 0}`,
    `- Network rules: ${summary?.network_rules ?? 0}`,
    `- DLP/WAF rules: ${summary?.dpi_rules ?? 0}`,
    `- DLP/WAF group scopes: ${summary?.dpi_bindings ?? 0}`,
    `- Vulnerability profiles: ${summary?.vulnerability_profiles ?? 0}`,
    `- Registries: ${summary?.registries ?? 0}`,
    `- Unsupported diagnostics (not imported or queued): ${summary?.unsupported ?? unsupported.length}`,
    `- Unaccounted source objects: ${summary?.unaccounted_source ?? 0}`,
    `- Applied result: ${activeImport?.applied_summary ? migrationAppliedSummaryLabel(activeImport.applied_summary) : "Not applied"}${activeImport?.status === "rolled_back" ? " (subsequently rolled back)" : ""}`,
    "",
    "## Source Counts",
    ...formatSourceCountRows(summary?.source_counts),
    "",
    "## Readiness",
    ...readiness.map((item) => `- [${item.category}] ${item.title}: ${item.detail}`),
    "",
    "## Unsupported Diagnostics",
    "These diagnostics describe unsupported records or omitted fields. They are not imported or queued, and may overlap supported object counts.",
    ...formatUnsupportedReportRows(unsupported),
    "",
    "## Vulnerability Profiles",
    ...(preview?.vulnerability_profiles?.length
      ? preview.vulnerability_profiles.map((profile) => `- ${profile.name}: ${profile.diff_action}; ${profile.active ? "active" : "inactive"}; ${profile.entries.length} entries; ${migrationVulnerabilityScopeLabel(profile)}`)
      : ["- Preview details unavailable; see summary and saved import diagnostics."]),
    "",
    "## Registries",
    "Migrated registry metadata uses manual scanning and no credentials. Scans are not queued. Reissue required credentials before scanning.",
    ...(preview?.registries?.length
      ? preview.registries.map((registry) => `- ${registry.name}: ${registry.diff_action}; ${registry.kind}; ${registry.endpoint}; image scope: ${registry.image_globs.join(", ") || "all images"}; ${registry.image_globs.length} image filters; manual scan cadence; no credentials imported${registry.credentials_required ? "; credentials must be reissued" : ""}`)
      : ["- Preview details unavailable; see summary and saved import diagnostics."]),
    "",
    "## Import History",
    ...(imports.length > 0
      ? imports.flatMap((item) => [
        `- ${item.id} ${migrationSourceLabel(item.source)} ${item.status} created=${item.created_at}${item.applied_at ? ` applied=${item.applied_at}` : ""}${item.rolled_back_at ? ` rolled_back=${item.rolled_back_at}` : ""}`,
        `  Summary: ${migrationSummaryLabel(item.summary)}`,
        `  Applied result: ${item.applied_summary ? migrationAppliedSummaryLabel(item.applied_summary) : "Not applied"}${item.status === "rolled_back" ? " (subsequently rolled back)" : ""}`,
        ...(item.error ? [`  Error: ${item.error}`] : []),
        "  Unsupported diagnostics (not imported or queued):",
        ...formatUnsupportedReportRows(item.unsupported ?? []).map((row) => `  ${row}`),
      ])
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

export function migrationAppliedSummaryLabel(summary: Record<string, number | undefined>) {
  const created = summary.created ?? 0;
  const updated = summary.updated ?? 0;
  const policies = summary.policies ?? 0;
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
  const vulnerabilityText = summary.vulnerability_profiles ? ` · ${summary.vulnerability_profiles} vulnerability profiles` : "";
  const registryText = summary.registries ? ` · ${summary.registries} registries` : "";
  return `${created + updated} object changes applied · ${created} created · ${updated} updated · ${summary.unchanged ?? 0} unchanged · ${policies} policies${fileProfileText}${processProfileText}${groupText}${networkText}${dpiText}${bindingText}${vulnerabilityText}${registryText}`;
}

export function migrationSummaryLabel(summary: MigrationPreview["summary"]) {
  return `${summary.total} preview items · ${summary.create} create · ${summary.update} update · ${summary.unchanged ?? 0} unchanged · ${summary.file_profiles ?? 0} file profiles · ${summary.process_profiles ?? 0} process profiles · ${summary.groups ?? 0} groups · ${summary.network_rules ?? 0} network rules · ${summary.dpi_rules ?? 0} DLP/WAF rules · ${summary.dpi_bindings ?? 0} DLP/WAF group scopes · ${summary.vulnerability_profiles ?? 0} vulnerability profiles · ${summary.registries ?? 0} registries · ${summary.unsupported ?? 0} unsupported diagnostics`;
}

export function migrationVulnerabilityScopeLabel(profile: NonNullable<MigrationPreview["vulnerability_profiles"]>[number]) {
  const clusters = profile.domain_scope?.clusters?.length ? profile.domain_scope.clusters.join(", ") : profile.cluster_id || "all clusters";
  const namespaces = profile.domain_scope?.namespaces?.length ? profile.domain_scope.namespaces.join(", ") : "all namespaces";
  return `${profile.cluster_id && profile.domain_scope?.clusters?.length ? `Target cluster: ${profile.cluster_id}; ` : ""}Clusters: ${clusters}; namespaces: ${namespaces}`;
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
    vulnerability_profiles: "Vulnerability profiles",
    registries: "Registries",
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
    "vulnerability_profiles",
    "registries",
  ];
  return [...order, ...Object.keys(counts).filter((key) => !order.includes(key)).sort()]
    .filter((key) => counts[key] !== undefined)
    .map((key) => `- ${labels[key] ?? key}: ${counts[key]}`);
}
