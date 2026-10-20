import { Outlet, useLocation } from "@tanstack/react-router";
import {
  ArrowLeftRight,
  BadgeCheck,
  Cable,
  DatabaseBackup,
  Earth,
  FileCode2,
  Globe,
  HeartPulse,
  KeyRound,
  Lock,
  Plug,
  Plus,
  ScanSearch,
  SlidersHorizontal,
  Timer,
  UsersRound,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { useProduct } from "@/ui";

/**
 * Settings — two layers (sidebar "Settings" → this page with its own section
 * list), the same model as Astronomer. No hub of cards repeating the list.
 */
export interface SettingsLink { to: string; label: string; icon: LucideIcon; external?: boolean }

// eslint-disable-next-line react-refresh/only-export-components
export const SETTINGS_SECTIONS: Array<{ label: string; items: SettingsLink[] }> = [
  {
    label: "Organization",
    items: [
      { to: "/settings/access", label: "Access control", icon: UsersRound },
      { to: "/settings/api-tokens", label: "API tokens", icon: KeyRound },
      { to: "/settings/security-policy", label: "Security policy", icon: Lock },
      { to: "/federation", label: "Federation", icon: Earth },
    ],
  },
  {
    label: "Clusters",
    items: [{ to: "/settings/clusters/new", label: "Register cluster", icon: Plus }],
  },
  {
    label: "Integrations",
    items: [
      { to: "/settings/integrations", label: "Alerts and routing", icon: Plug },
      { to: "/settings/connectors", label: "Connectors", icon: Cable },
    ],
  },
  {
    label: "Platform",
    items: [
      { to: "/settings/health", label: "System health", icon: HeartPulse },
      { to: "/settings/scanner", label: "Scanner and CVE sources", icon: ScanSearch },
      { to: "/settings/attestation-trust", label: "Attestation trust", icon: BadgeCheck },
      { to: "/settings/network", label: "Network and proxy", icon: Globe },
      { to: "/settings/effective-config", label: "Effective configuration", icon: SlidersHorizontal },
      { to: "/settings/retention", label: "Data retention", icon: Timer },
      { to: "/settings/backup", label: "Backup", icon: DatabaseBackup },
    ],
  },
  {
    label: "Migration",
    items: [
      { to: "/settings/migration", label: "NeuVector migration", icon: ArrowLeftRight },
      { to: "/openapi.json", label: "API reference", icon: FileCode2, external: true },
    ],
  },
];

export function settingsSectionFor(pathname: string): SettingsLink | undefined {
  return SETTINGS_SECTIONS.flatMap((section) => section.items)
    .filter((item) => !item.external && (pathname === item.to || pathname.startsWith(`${item.to}/`)))
    .sort((a, b) => b.to.length - a.to.length)[0];
}

export function SettingsNav({ pathname }: { pathname: string }) {
  const { Link } = useProduct();
  const active = settingsSectionFor(pathname);
  return (
    <nav aria-label="Settings" className="w-full shrink-0 space-y-4 lg:sticky lg:top-0 lg:w-56" data-testid="settings-nav">
      {SETTINGS_SECTIONS.map((section) => (
        <div key={section.label}>
          <p className="px-3 pb-1 text-meta font-semibold text-muted-foreground">{section.label}</p>
          <div className="space-y-px">
            {section.items.map((item) => {
              const Icon = item.icon;
              const current = active?.to === item.to;
              const className = cn(
                "relative flex h-8 items-center gap-2.5 rounded-md px-3 text-sm transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
                current ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
              );
              const body = (
                <>
                  {current ? <span aria-hidden className="absolute -left-2 bottom-1.5 top-1.5 w-0.5 rounded-full bg-brand" /> : null}
                  <Icon className="h-4 w-4 shrink-0" aria-hidden />
                  <span className="truncate">{item.label}</span>
                </>
              );
              return item.external ? (
                <a key={item.to} href={item.to} target="_blank" rel="noopener noreferrer" className={className} aria-label={`${item.label} (opens in a new tab)`}>{body}</a>
              ) : (
                <Link key={item.to} to={item.to} current={current} className={className}>{body}</Link>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}

export function SettingsShell() {
  const { pathname } = useLocation();
  return (
    <div className="flex flex-col gap-8 pb-16 lg:flex-row lg:items-start">
      <SettingsNav pathname={pathname} />
      <div className="min-w-0 flex-1">
        <Outlet />
      </div>
    </div>
  );
}
