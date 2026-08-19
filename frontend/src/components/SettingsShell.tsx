import { type ComponentType } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  UsersRound,
  KeyRound,
  BadgeCheck,
  HeartPulse,
  ScanSearch,
  Save,
  Plug,
  Cable,
  ArrowLeftRight,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { PageContainer } from "@/components/ui/page";

/**
 * SettingsShell — the single grouped Settings surface (pattern P3 + P5).
 *
 * Replaces the old split between a flat sidebar "Admin" group and a disjoint
 * `/settings` card hub. Every settings feature now has exactly ONE home, reached
 * from this left sub-nav, grouped by scope: Organization -> Platform -> Integrations.
 */
type SettingsNavItem = { to: string; label: string; icon: ComponentType<{ className?: string }> };
type SettingsNavGroup = { label: string; items: SettingsNavItem[] };

const SETTINGS_NAV: SettingsNavGroup[] = [
  {
    label: "Organization",
    items: [
      { to: "/settings/access", label: "Access Control", icon: UsersRound },
      { to: "/settings/api-tokens", label: "API Tokens", icon: KeyRound },
      { to: "/settings/attestation-trust", label: "Attestation Trust", icon: BadgeCheck },
    ],
  },
  {
    label: "Platform",
    items: [
      { to: "/settings/health", label: "System Health", icon: HeartPulse },
      { to: "/settings/scanner", label: "Scanner & CVE Sources", icon: ScanSearch },
      { to: "/settings/backup", label: "Backup", icon: Save },
    ],
  },
  {
    label: "Integrations",
    items: [
      { to: "/settings/integrations", label: "Integrations & Routing", icon: Plug },
      { to: "/settings/connectors", label: "Connectors", icon: Cable },
      { to: "/settings/migration", label: "Migration Imports", icon: ArrowLeftRight },
    ],
  },
];

export function SettingsShell() {
  return (
    <PageContainer>
      <div className="flex flex-col gap-6 lg:flex-row lg:gap-8">
        <nav className="shrink-0 lg:w-56" aria-label="Settings">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Settings
          </div>
          <div className="mt-3 flex flex-col gap-5">
            {SETTINGS_NAV.map((group) => (
              <div key={group.label}>
                <div className="mb-1 px-2 text-[10px] uppercase tracking-wider text-muted-foreground/70">
                  {group.label}
                </div>
                <div className="flex flex-col gap-0.5">
                  {group.items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      className={({ isActive }) =>
                        cn(
                          "flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors",
                          isActive
                            ? "bg-[color-mix(in_oklab,var(--color-primary)_12%,transparent)] font-medium text-foreground"
                            : "text-muted-foreground hover:bg-muted hover:text-foreground",
                        )
                      }
                    >
                      <item.icon className="h-4 w-4 shrink-0" />
                      {item.label}
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </nav>
        <div className="min-w-0 flex-1">
          <Outlet />
        </div>
      </div>
    </PageContainer>
  );
}
