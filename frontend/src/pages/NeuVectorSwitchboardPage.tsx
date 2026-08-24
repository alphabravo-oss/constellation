import { Link } from "react-router-dom";
import {
  ArrowRight,
  BadgeCheck,
  BellRing,
  ClipboardCheck,
  Database,
  FileText,
  GitBranch,
  Globe2,
  KeyRound,
  Layers,
  Network,
  PackageSearch,
  RadioTower,
  ScrollText,
  Server,
  ServerCog,
  ShieldCheck,
  SlidersHorizontal,
  UsersRound,
  Wand2,
  Waypoints,
} from "lucide-react";

import { useCluster } from "@/hooks/useCluster";
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { StatCard } from "@/components/ui/stat-card";
import { Button } from "@/components/ui/button";

type RouteLink = { label: string; to: string; id?: string };
type Mapping = {
  id: string;
  nv: string;
  constellation: string;
  status: "ready" | "partial" | "better";
  icon: React.ReactNode;
  links: RouteLink[];
  notes: string[];
};

function statusLabel(status: Mapping["status"]) {
  if (status === "better") return "Parity+";
  if (status === "partial") return "In progress";
  return "Mapped";
}

function statusClass(status: Mapping["status"]) {
  if (status === "better") return "border-primary/30 bg-primary/10 text-primary";
  if (status === "partial") return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300";
  return "border-border bg-muted text-foreground";
}

export function NeuVectorSwitchboardPage() {
  const { clusterId, isLoading } = useCluster();
  const c = (path: string) => clusterId ? `/clusters/${clusterId}/${path}` : "/clusters";

  const mappings: Mapping[] = [
    {
      id: "workloads-services",
      nv: "Workloads / Services",
      constellation: "Workloads, assets, containers, runtime, and groups",
      status: "ready",
      icon: <Layers className="h-4 w-4" />,
      links: [
        { label: "Workloads", to: c("deployments") },
        { label: "Containers", to: c("containers") },
        { label: "Assets", to: c("assets") },
        { label: "Groups", to: c("groups") },
      ],
      notes: ["Use Workloads for service posture and Assets for the correlated risk view."],
    },
    {
      id: "hosts",
      nv: "Hosts",
      constellation: "Nodes, host compliance, and component diagnostics",
      status: "ready",
      icon: <Server className="h-4 w-4" />,
      links: [
        { label: "Nodes", to: c("nodes") },
        { label: "Compliance", to: c("compliance") },
        { label: "Components", to: c("components") },
      ],
      notes: ["Nodes cover host posture; Components covers installed Constellation services."],
    },
    {
      id: "components",
      nv: "Controllers / Enforcers / Scanners",
      constellation: "Components, sensor health, scanner sources, and system health",
      status: "partial",
      icon: <ServerCog className="h-4 w-4" />,
      links: [
        { label: "Controllers", to: c("components?role=controller") },
        { label: "Enforcers", to: c("components?role=enforcer") },
        { label: "Scanners", to: c("components?role=scanner") },
        { label: "Sensor Health", to: c("health") },
        { label: "System Health", to: "/settings/health" },
        { label: "Scanner Sources", to: "/settings/scanner" },
      ],
      notes: ["Role filters, version drift, scanner queue/cache, diagnostics, applied config revision, and support bundle download are live; remaining work is async signed bundle lifecycle."],
    },
    {
      id: "network-activity",
      nv: "Network Activity",
      constellation: "Map, conversations, sessions, PCAP, timeline, and network rules",
      status: "ready",
      icon: <Network className="h-4 w-4" />,
      links: [
        { label: "Map", to: c("network?tab=map") },
        { label: "Conversations", to: c("network?tab=conversations") },
        { label: "Sessions", to: c("network?tab=sessions") },
        { label: "PCAP", to: c("network?tab=pcap") },
        { label: "Rules", to: c("network?tab=rules") },
        { label: "Threats", to: c("network?tab=threats") },
        { label: "Network Rules", to: c("network-rules") },
        { label: "Timeline", to: c("timeline") },
      ],
      notes: ["Map, Conversations, Sessions, PCAP, Rules, and Threats are stable workspace tabs."],
    },
    {
      id: "policy",
      nv: "Policy",
      constellation: "Groups, network rules, admission, runtime, file, DLP, WAF, and response",
      status: "partial",
      icon: <Waypoints className="h-4 w-4" />,
      links: [
        { label: "Policy Center", to: c("policy") },
        { label: "Groups", to: c("groups") },
        { label: "Network Rules", to: c("network-rules") },
        { label: "Admission", to: c("admission") },
        { label: "Runtime Policies", to: c("runtime-policies") },
        { label: "Process Baselines", to: c("runtime/baselines") },
        { label: "File Monitor", to: c("file-monitor") },
        { label: "DLP Sensors -> DLP Rules", to: c("runtime-dlp"), id: "dlp-sensors" },
        { label: "WAF Sensors -> WAF/DPI", to: c("runtime-signatures"), id: "waf-sensors" },
        { label: "Response Rules", to: c("response-rules") },
      ],
      notes: ["DLP and WAF sensor exports land as runtime rules plus group-scope bindings, not inert sensor objects.", "Admission has state, criteria catalog, profile templates, and dry-run outcomes; remaining work is shared group picker and hit counts."],
    },
    {
      id: "security-risks",
      nv: "Security Risks",
      constellation: "Findings, CVE database, vulnerability profiles, exceptions, and compliance",
      status: "better",
      icon: <ShieldCheck className="h-4 w-4" />,
      links: [
        { label: "Findings", to: c("findings") },
        { label: "CVE Database", to: "/cve" },
        { label: "Vuln Profiles", to: c("vuln-profiles") },
        { label: "Exceptions", to: c("exceptions") },
        { label: "Compliance", to: c("compliance") },
      ],
      notes: ["Constellation adds KEV, EPSS, SBOM/VEX, reachability, and stronger risk correlation."],
    },
    {
      id: "events-notifications",
      nv: "Events / Notifications",
      constellation: "Timeline, audit log, response catalog, integrations, and routing",
      status: "ready",
      icon: <BellRing className="h-4 w-4" />,
      links: [
        { label: "Timeline", to: c("timeline") },
        { label: "Audit Log", to: c("audit") },
        { label: "Response Catalog", to: c("response") },
        { label: "Integrations", to: "/settings/integrations" },
      ],
      notes: ["Timeline categories, saved views, CSV export, and source-specific detail drawers are live; remaining work is count reconciliation with source tables and risk-report feed."],
    },
    {
      id: "settings",
      nv: "Settings",
      constellation: "Access, API tokens, scanner, network/proxy, backup, connectors, and migration",
      status: "partial",
      icon: <KeyRound className="h-4 w-4" />,
      links: [
        { label: "Access Control", to: "/settings/access" },
        { label: "API Tokens", to: "/settings/api-tokens" },
        { label: "Network & Proxy", to: "/settings/network" },
        { label: "Effective Config", to: "/settings/effective-config" },
        { label: "Backup", to: "/settings/backup" },
        { label: "Connectors", to: "/settings/connectors" },
        { label: "Migration Imports", to: "/settings/migration" },
        { label: "API Reference", to: "/openapi.json" },
      ],
      notes: ["Effective Config shows redacted values, diffs, and component applied-revision reports; remaining work is exact per-key backend provenance and PATCH for mutable settings."],
    },
  ];

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading cluster...</p>;

  return (
    <PageContainer data-testid="neuvector-switchboard">
      <PageHeader
        title="NeuVector Switchboard"
        description="NeuVector navigation and operating concepts mapped to Constellation routes for this cluster."
        actions={
          <Button asChild variant="primary">
            <Link to="/settings/migration">
              <Wand2 className="h-4 w-4" />
              Migration Imports
            </Link>
          </Button>
        }
      />

      <section className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <StatCard label="NV areas mapped" value={mappings.length} hint="Primary console areas" icon={<ClipboardCheck className="h-3.5 w-3.5" />} />
        <StatCard label="Parity+ areas" value={mappings.filter((m) => m.status === "better").length} hint="Stronger than NV today" tone="accent" icon={<BadgeCheck className="h-3.5 w-3.5" />} />
        <StatCard label="Migration path" value="Apply" hint="Preview, apply, rollback" tone="medium" href="/settings/migration" icon={<Wand2 className="h-3.5 w-3.5" />} />
      </section>

      <PageSection title="Navigation Map" description="Use the NeuVector term on the left and jump to the Constellation equivalent on the right.">
        <div className="grid gap-3">
          {mappings.map((mapping) => (
            <Card key={mapping.nv} padded={false}>
              <div className="grid gap-4 p-4 lg:grid-cols-[260px_minmax(0,1fr)]" data-testid={`neuvector-map-${mapping.id}`}>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="flex h-8 w-8 items-center justify-center rounded-md bg-muted text-muted-foreground">
                      {mapping.icon}
                    </span>
                    <div>
                      <div className="text-sm font-semibold text-foreground">{mapping.nv}</div>
                      <span className={`mt-1 inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium ${statusClass(mapping.status)}`}>
                        {statusLabel(mapping.status)}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="min-w-0 space-y-3">
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="font-medium text-foreground">{mapping.constellation}</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {mapping.links.map((link) => (
                      <Link
                        key={`${mapping.nv}:${link.label}`}
                        to={link.to}
                        data-testid={`neuvector-map-link-${mapping.id}-${link.id ?? slugify(link.label)}`}
                        className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2.5 py-1.5 text-xs font-medium text-foreground transition-colors hover:border-primary/40 hover:bg-accent"
                      >
                        {link.label}
                        <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      </Link>
                    ))}
                  </div>
                  <ul className="space-y-1 text-xs text-muted-foreground">
                    {mapping.notes.map((note) => <li key={note}>{note}</li>)}
                  </ul>
                </div>
              </div>
            </Card>
          ))}
        </div>
      </PageSection>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Mode Vocabulary" description="Operator-facing aliases for policy posture.">
          <dl className="grid gap-3 text-sm">
            <ModeRow nv="Discover" constellation="Learn" detail="Observe behavior and collect candidate policy." />
            <ModeRow nv="Monitor" constellation="Monitor" detail="Alert on violations without blocking." />
            <ModeRow nv="Protect" constellation="Enforce" detail="Block according to the active policy family." />
          </dl>
        </Card>

        <Card title="Migration Runway" description="Cutover tasks that should be completed before a production switch.">
          <ul className="space-y-2 text-sm">
            <RunwayLink icon={<Wand2 />} label="Preview NeuVector export" to="/settings/migration" />
            <RunwayLink icon={<ServerCog />} label="Verify components and agents" to={c("components")} />
            <RunwayLink icon={<Database />} label="Check scanner and CVE sources" to="/settings/scanner" />
            <RunwayLink icon={<Globe2 />} label="Confirm proxy and SIEM settings" to="/settings/network" />
            <RunwayLink icon={<SlidersHorizontal />} label="Review effective system config" to="/settings/effective-config" />
            <RunwayLink icon={<UsersRound />} label="Review access and SSO mappings" to="/settings/access" />
          </ul>
        </Card>

        <Card title="Constellation Advantages" description="Capabilities to preserve and surface during migration.">
          <ul className="grid gap-2 text-sm text-foreground">
            <Advantage icon={<PackageSearch />} text="SBOM, VEX, and deeper image evidence" />
            <Advantage icon={<GitBranch />} text="Repository and serverless scanning" />
            <Advantage icon={<BadgeCheck />} text="Attestation trust and signature policy" />
            <Advantage icon={<FileText />} text="Signed compliance evidence and custom checks" />
            <Advantage icon={<RadioTower />} text="Response routing with delivery ledger" />
            <Advantage icon={<ScrollText />} text="Hash-chained audit evidence" />
          </ul>
        </Card>
      </div>
    </PageContainer>
  );
}

function ModeRow({ nv, constellation, detail }: { nv: string; constellation: string; detail: string }) {
  return (
    <div className="grid grid-cols-[92px_1fr] gap-3 rounded-md border border-border p-3">
      <dt className="font-semibold text-foreground">{nv}</dt>
      <dd>
        <div className="font-medium text-foreground">{constellation}</div>
        <div className="mt-1 text-xs text-muted-foreground">{detail}</div>
      </dd>
    </div>
  );
}

function RunwayLink({ icon, label, to }: { icon: React.ReactNode; label: string; to: string }) {
  return (
    <li>
      <Link to={to} className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2 transition-colors hover:bg-accent">
        <span className="flex min-w-0 items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded bg-muted text-muted-foreground [&_svg]:h-3.5 [&_svg]:w-3.5">
            {icon}
          </span>
          <span className="truncate">{label}</span>
        </span>
        <ArrowRight className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
      </Link>
    </li>
  );
}

function Advantage({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <li className="flex items-center gap-2 rounded-md border border-border px-3 py-2">
      <span className="flex h-6 w-6 items-center justify-center rounded bg-muted text-muted-foreground [&_svg]:h-3.5 [&_svg]:w-3.5">
        {icon}
      </span>
      <span>{text}</span>
    </li>
  );
}

function slugify(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
