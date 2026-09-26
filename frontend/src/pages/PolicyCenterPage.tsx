import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BellRing,
  FileText,
  FileWarning,
  GitMerge,
  Network,
  RadioTower,
  ScrollText,
  ShieldCheck,
  UsersRound,
} from "lucide-react";

import { useCluster } from "@/hooks/useCluster";
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StatusPill } from "@/components/ui/status-pill";
import { ImportExportButtons } from "@/components/ImportExportButtons";
import { enterprise, groupsApi, networkRules, runtimeDLP, runtimeSignatures, vulnProfiles, type MigrationImportListItem, type MigrationUnsupported } from "@/api/client";

interface PolicyFamily {
  title: string;
  nvName: string;
  switchTerms?: string[];
  route: string;
  createRoute?: string;
  icon: ReactNode;
  mode?: "learn" | "monitor" | "enforce";
  ordered?: boolean;
  portable?: "network-rules" | "dlp" | "signatures" | "groups" | "vuln-profiles";
}

const policyFamilies: PolicyFamily[] = [
  {
    title: "Network Rules",
    nvName: "Network policy",
    route: "network-rules",
    createRoute: "network-rules/new",
    icon: <Network className="h-4 w-4" aria-hidden />,
    mode: "monitor",
    ordered: true,
    portable: "network-rules",
  },
  {
    title: "Admission Control",
    nvName: "Admission rules",
    route: "admission",
    createRoute: "admission/new",
    icon: <ShieldCheck className="h-4 w-4" aria-hidden />,
    mode: "enforce",
    ordered: true,
  },
  {
    title: "Runtime Policies",
    nvName: "Response protection",
    route: "runtime-policies",
    createRoute: "runtime-policies/new",
    icon: <ScrollText className="h-4 w-4" aria-hidden />,
    mode: "monitor",
  },
  {
    title: "Process Baselines",
    nvName: "Process profile",
    route: "runtime/baselines",
    icon: <GitMerge className="h-4 w-4" aria-hidden />,
    mode: "learn",
  },
  {
    title: "File Monitor",
    nvName: "File profile",
    route: "file-monitor",
    createRoute: "file-monitor/new",
    icon: <FileWarning className="h-4 w-4" aria-hidden />,
    mode: "monitor",
  },
  {
    title: "DLP Rules",
    nvName: "DLP sensors",
    switchTerms: ["NV DLP Sensors -> DLP Rules", "NV dlp_group -> DLP group scope"],
    route: "runtime-dlp",
    createRoute: "runtime-dlp/new",
    icon: <ShieldCheck className="h-4 w-4" aria-hidden />,
    mode: "monitor",
    portable: "dlp",
  },
  {
    title: "WAF / DPI Signatures",
    nvName: "WAF sensors",
    switchTerms: ["NV WAF Sensors -> WAF/DPI Signatures", "NV waf_group -> WAF/DPI group scope"],
    route: "runtime-signatures",
    createRoute: "runtime-signatures/new",
    icon: <Activity className="h-4 w-4" aria-hidden />,
    mode: "monitor",
    portable: "signatures",
  },
  {
    title: "Response Rules",
    nvName: "Response rules",
    route: "response-rules",
    createRoute: "response-rules/new",
    icon: <BellRing className="h-4 w-4" aria-hidden />,
    ordered: true,
  },
  {
    title: "Vulnerability Profiles",
    nvName: "Vulnerability profile",
    route: "vuln-profiles",
    icon: <FileWarning className="h-4 w-4" aria-hidden />,
    portable: "vuln-profiles",
  },
  {
    title: "Groups",
    nvName: "Groups",
    route: "groups",
    icon: <UsersRound className="h-4 w-4" aria-hidden />,
    mode: "monitor",
    portable: "groups",
  },
  {
    title: "Declarative Policies",
    nvName: "Policy list",
    route: "policies",
    createRoute: "policies/new",
    icon: <FileText className="h-4 w-4" aria-hidden />,
    mode: "monitor",
  },
  {
    title: "Response Catalog",
    nvName: "Response actions",
    route: "response",
    icon: <RadioTower className="h-4 w-4" aria-hidden />,
  },
];

type MigrationDiagnostic = { item: MigrationUnsupported; importRecord: MigrationImportListItem };

const diagnosticFamilies: Record<string, string> = {
  network_rule: "network-rules",
  group: "groups",
  group_criterion: "groups",
  process_profile: "runtime/baselines",
  file_profile: "file-monitor",
  vulnerability_profile: "vuln-profiles",
  dlp_group_scope: "runtime-dlp",
  waf_group_scope: "runtime-signatures",
};

function diagnosticFamily(item: MigrationUnsupported): string | null {
  if (item.kind === "dpi_rule" || item.kind === "dpi_pattern") {
    if (item.source?.category === "dlp") return "runtime-dlp";
    if (item.source?.category === "waf") return "runtime-signatures";
    return null;
  }
  return diagnosticFamilies[item.kind] ?? null;
}

function MigrationDiagnostics({ diagnostics }: { diagnostics: MigrationDiagnostic[] }) {
  return (
    <div className="space-y-2 border-t pt-3 text-xs" aria-label="Org migration diagnostics">
      <div className="font-medium text-foreground">NeuVector migration diagnostics · org history</div>
      {diagnostics.map(({ item, importRecord }, index) => (
        <div key={`${importRecord.id}:${index}`} className="rounded border bg-muted/30 p-2">
          <div className="font-medium text-foreground">{item.kind} · {item.name}</div>
          <div>{item.reason}</div>
          {item.suggestion ? <div>Suggestion: {item.suggestion}</div> : null}
          <div className="mt-1 text-muted-foreground">Import {importRecord.id} · {importRecord.status} · {importRecord.created_at}</div>
        </div>
      ))}
    </div>
  );
}

export function PolicyCenterPage() {
  const { clusterId } = useCluster();
  const queryClient = useQueryClient();
  const importsQuery = useQuery({ queryKey: ["migration-imports"], queryFn: () => enterprise.migrationImports() });
  const diagnostics: MigrationDiagnostic[] = (importsQuery.isError ? [] : importsQuery.data ?? [])
    .filter((importRecord) => importRecord.source === "neuvector")
    .flatMap((importRecord) => (importRecord.unsupported ?? []).map((item) => ({ item, importRecord })));
  const generalDiagnostics = diagnostics.filter(({ item }) => diagnosticFamily(item) === null);
  const to = (route: string) => clusterId ? `/clusters/${clusterId}/${route}` : "/clusters";

  return (
    <PageContainer data-testid="policy-center-page">
      <PageHeader
        title="Policy Center"
        description="One cluster policy entry point for NeuVector-style groups, rules, profiles, sensors, and response actions."
        actions={
          <Button asChild variant="outline">
            <Link to="/settings/migration">Migration Imports</Link>
          </Button>
        }
      />

      <PageSection
        title="Mode Vocabulary"
        description="NeuVector modes are shown beside the Constellation mode used by the target policy family."
      >
        <div className="grid gap-3 md:grid-cols-3" data-testid="policy-mode-vocabulary">
          <ModeBridge nv="Discover" constellation="Learn" detail="Observe behavior and build candidate baselines." />
          <ModeBridge nv="Monitor" constellation="Monitor" detail="Detect and alert without blocking traffic or workload activity." />
          <ModeBridge nv="Protect" constellation="Enforce" detail="Block or deny according to the active rule family." />
        </div>
      </PageSection>

      <PageSection
        title="Policy Families"
        description="Every enforcement and detection surface reachable from one place. Migration diagnostics below are org history; import records do not identify a target cluster. They do not describe this cluster's current policies."
      >
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3" data-testid="policy-family-grid">
          {policyFamilies.map((family) => (
            <div key={family.title} data-testid={`policy-family-${familySlug(family.route)}`}>
              <Card
                title={
                  <span className="inline-flex items-center gap-2">
                    {family.icon}
                    {family.title}
                  </span>
                }
                description={family.nvName}
                action={family.mode ? <ModePair mode={family.mode} /> : undefined}
                className="rounded-lg"
              >
                <div className="flex min-h-[116px] flex-col justify-between gap-4">
                  <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                    {family.switchTerms?.map((term) => (
                      <span key={term} className="rounded border border-primary/20 bg-primary/5 px-2 py-1 text-primary">{term}</span>
                    ))}
                    {family.ordered ? <span className="rounded bg-muted px-2 py-1">ordered</span> : null}
                    {family.portable ? <span className="rounded bg-muted px-2 py-1">yaml</span> : null}
                    <span className="rounded bg-muted px-2 py-1">cluster scoped</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button asChild size="sm" variant="primary">
                      <Link to={to(family.route)} aria-label={`Open ${family.title}`}>Open</Link>
                    </Button>
                    {family.createRoute ? (
                      <Button asChild size="sm" variant="outline">
                        <Link to={to(family.createRoute)} aria-label={`Create ${family.title}`}>Create</Link>
                      </Button>
                    ) : null}
                    {family.portable ? (
                      <span className="contents" data-testid={`policy-family-${familySlug(family.route)}-portable`}>
                        <PolicyFamilyImportExport family={family.portable} clusterId={clusterId} queryClient={queryClient} />
                      </span>
                    ) : null}
                  </div>
                </div>
              </Card>
              {diagnostics.some(({ item }) => diagnosticFamily(item) === family.route) ? (
                <MigrationDiagnostics diagnostics={diagnostics.filter(({ item }) => diagnosticFamily(item) === family.route)} />
              ) : null}
            </div>
          ))}
        </div>
      </PageSection>
      <PageSection title="Migration Diagnostics" description="Org-wide saved NeuVector imports. These records are not attributed to the selected cluster.">
        {importsQuery.isPending ? <p role="status">Loading migration diagnostics…</p> : null}
        {importsQuery.isError ? <p role="alert">Migration diagnostics are unavailable. Review saved imports on the Migration Imports page.</p> : null}
        {importsQuery.isSuccess && diagnostics.length === 0 ? <p>No saved NeuVector unsupported diagnostics in the available import history.</p> : null}
        {generalDiagnostics.length > 0 ? (
          <div data-testid="migration-general-diagnostics">
            <h3 className="text-sm font-medium">Other unsupported objects</h3>
            <MigrationDiagnostics diagnostics={generalDiagnostics} />
          </div>
        ) : null}
      </PageSection>
    </PageContainer>
  );
}

function PolicyFamilyImportExport({
  family,
  clusterId,
  queryClient,
}: {
  family: NonNullable<PolicyFamily["portable"]>;
  clusterId?: string;
  queryClient: ReturnType<typeof useQueryClient>;
}) {
  if (!clusterId) return null;
  if (family === "network-rules") {
    return (
      <ImportExportButtons
        filename="constellation-network-rules.yaml"
        label="network rules"
        exportYaml={() => networkRules.exportYaml(clusterId)}
        importYaml={(text) => networkRules.importYaml(clusterId, text)}
        onImported={() => void queryClient.invalidateQueries({ queryKey: ["network-rules", clusterId] })}
      />
    );
  }
  if (family === "dlp") {
    return (
      <ImportExportButtons
        filename="constellation-dlp-rules.yaml"
        label="DLP rules"
        exportYaml={() => runtimeDLP.exportYaml(clusterId)}
        importYaml={(text) => runtimeDLP.importYaml(clusterId, text)}
        onImported={() => void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules", clusterId] })}
      />
    );
  }
  if (family === "signatures") {
    return (
      <ImportExportButtons
        filename="constellation-dpi-signatures.yaml"
        label="WAF/DPI signatures"
        exportYaml={() => runtimeSignatures.exportYaml(clusterId)}
        importYaml={(text) => runtimeSignatures.importYaml(clusterId, text)}
        onImported={() => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterId] })}
      />
    );
  }
  if (family === "groups") {
    return (
      <ImportExportButtons
        filename="constellation-groups.yaml"
        label="groups"
        exportYaml={() => groupsApi.exportYaml({ cluster_id: clusterId })}
        importYaml={(text) => groupsApi.importYaml(text, { cluster_id: clusterId })}
        onImported={() => void queryClient.invalidateQueries({ queryKey: ["groups", clusterId] })}
      />
    );
  }
  return (
    <ImportExportButtons
      filename="constellation-vuln-profiles.yaml"
      label="profiles"
      exportYaml={() => vulnProfiles.exportYaml({ cluster_id: clusterId })}
      importYaml={(text) => vulnProfiles.importYaml(text, { cluster_id: clusterId })}
      onImported={() => void queryClient.invalidateQueries({ queryKey: ["vuln-profiles", clusterId] })}
    />
  );
}

function ModeBridge({ nv, constellation, detail }: { nv: string; constellation: string; detail: string }) {
  return (
    <Card title={nv} description={detail} className="rounded-lg">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs text-muted-foreground">Constellation</span>
        <StatusPill label={constellation} tone={modeTone(constellation)} />
      </div>
    </Card>
  );
}

function ModePair({ mode }: { mode: "learn" | "monitor" | "enforce" }) {
  return (
    <div className="flex flex-wrap items-center justify-end gap-1.5">
      <StatusPill label={nvMode(mode)} tone={modeTone(mode)} />
      <StatusPill label={mode} tone={modeTone(mode)} />
    </div>
  );
}

function nvMode(mode: "learn" | "monitor" | "enforce") {
  if (mode === "learn") return "Discover";
  if (mode === "enforce") return "Protect";
  return "Monitor";
}

function modeTone(mode: string): "neutral" | "success" | "warning" | "error" | "info" | "pending" | "accent" {
  const normalized = mode.toLowerCase();
  if (normalized === "learn" || normalized === "discover") return "info";
  if (normalized === "monitor") return "warning";
  if (normalized === "enforce" || normalized === "protect") return "success";
  return "neutral";
}

function familySlug(route: string) {
  return route.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
