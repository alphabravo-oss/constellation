import { type ElementType } from "react";
import { Link } from "react-router-dom";
import {
  UsersRound,
  KeyRound,
  ShieldCheck,
  BadgeCheck,
  HeartPulse,
  ScanSearch,
  Globe,
  DatabaseZap,
  Save,
  Plug,
  Cable,
  ArrowLeftRight,
  Server,
  SlidersHorizontal,
  FileCode2,
} from "lucide-react";

/**
 * SettingsLanding — the /settings hub: an Astronomer-style card grid that fans out
 * to every settings area. Each card is a dedicated route (no drawers).
 */
interface SettingsCard {
  to: string;
  title: string;
  description: string;
  icon: ElementType;
  external?: boolean;
}

const CARDS: SettingsCard[] = [
  { to: "/settings/clusters/new", title: "Connect a cluster", description: "Register a Kubernetes cluster and get a one-command install to enroll it.", icon: Server },
  { to: "/settings/access", title: "Access Control", description: "Users, roles, scoped bindings, SSO providers, and service accounts.", icon: UsersRound },
  { to: "/settings/api-tokens", title: "API Tokens", description: "Programmatic access tokens for automation and integrations.", icon: KeyRound },
  { to: "/settings/security-policy", title: "Security Policy", description: "Password strength rules and session / idle timeouts for the org.", icon: ShieldCheck },
  { to: "/settings/attestation-trust", title: "Attestation Trust", description: "Image-signing trust policies and verification sources.", icon: BadgeCheck },
  { to: "/settings/health", title: "System Health", description: "Fleet status, component heartbeats, and active incidents.", icon: HeartPulse },
  { to: "/settings/scanner", title: "Scanner & CVE Sources", description: "Trivy/Grype database freshness and the live CVE feeds.", icon: ScanSearch },
  { to: "/settings/network", title: "Network & Proxy", description: "Egress proxy, upstream TLS trust, and the syslog / SIEM mirror.", icon: Globe },
  { to: "/settings/effective-config", title: "Effective Config", description: "Redacted live system config, revision, and source-of-truth review.", icon: SlidersHorizontal },
  { to: "/settings/retention", title: "Data Retention", description: "How long raw network flows and runtime events are kept.", icon: DatabaseZap },
  { to: "/settings/backup", title: "Backup", description: "Scheduled backups, destinations, and configuration restore.", icon: Save },
  { to: "/settings/integrations", title: "Integrations & Routing", description: "Alert receivers (Slack, PagerDuty, email…) and routing rules.", icon: Plug },
  { to: "/settings/connectors", title: "Connectors", description: "Registry, cloud-account, and scanner-pool coverage.", icon: Cable },
  { to: "/settings/migration", title: "Migration Imports", description: "Preview NeuVector exports and map imported config into Constellation routes.", icon: ArrowLeftRight },
  { to: "/openapi.json", title: "API Reference", description: "Download the generated OpenAPI spec for scripts, runbooks, and NeuVector API mapping.", icon: FileCode2, external: true },
];

export function SettingsLanding() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Organization, platform, and integration configuration.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {CARDS.map((card) => {
          const Icon = card.icon;
          const className = "flex flex-col gap-2 rounded-lg border border-border bg-card p-4 text-left transition-colors hover:border-foreground/20 hover:bg-card/80";
          const content = (
            <>
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg bg-muted">
                  <Icon className="h-4 w-4 text-foreground" />
                </div>
                <p className="text-sm font-medium text-foreground">{card.title}</p>
              </div>
              <p className="line-clamp-2 text-xs leading-relaxed text-muted-foreground">{card.description}</p>
            </>
          );
          if (card.external) {
            return (
              <a key={card.title} href={card.to} className={className} data-testid="settings-openapi-link">
                {content}
              </a>
            );
          }
          return (
            <Link
              key={card.title}
              to={card.to}
              className={className}
            >
              {content}
            </Link>
          );
        })}
      </div>
    </div>
  );
}
