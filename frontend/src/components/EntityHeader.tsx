import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { RiskGauge, type Subfactor, RiskScore } from "@/components/ui/risk-score";
import { cn } from "@/lib/cn";

/**
 * EntityHeader — used by RiskDetail, AssetDetail, CVEDetail, etc.
 *
 * Layout:
 *   [breadcrumbs                                        ]
 *   [title + criticality pills          ] [actions      ]
 *   [risk gauge | 4 stat tiles                           ]
 */
export interface BreadcrumbItem { label: string; to?: string }

export function EntityHeader({
  breadcrumbs,
  title,
  subtitle,
  badges,
  riskScore,
  subfactors,
  stats,
  actions,
  className,
}: {
  breadcrumbs?: BreadcrumbItem[];
  title: ReactNode;
  subtitle?: ReactNode;
  badges?: ReactNode;
  riskScore?: number;
  subfactors?: Subfactor[];
  stats?: Array<{ label: string; value: ReactNode; tone?: "neutral" | "critical" | "high" | "accent" }>;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("space-y-4", className)}>
      {breadcrumbs && breadcrumbs.length > 0 && (
        <nav aria-label="Breadcrumbs" className="flex flex-wrap items-center gap-1 text-[11px] text-muted-foreground">
          {breadcrumbs.map((b, i) => (
            <span key={i} className="flex items-center gap-1">
              {b.to ? (
                <Link to={b.to} className="hover:text-foreground transition-colors">{b.label}</Link>
              ) : (
                <span className="text-foreground">{b.label}</span>
              )}
              {i < breadcrumbs.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground/60" />}
            </span>
          ))}
        </nav>
      )}

      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-display text-2xl font-semibold tracking-tight">{title}</h1>
            {badges}
          </div>
          {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
        </div>

        <div className="flex flex-wrap items-center gap-3 lg:flex-nowrap">
          {actions && <div className="flex items-center gap-1.5">{actions}</div>}
        </div>
      </div>

      {(riskScore != null || (stats && stats.length > 0)) && (
        <div className="grid grid-cols-1 gap-3 rounded-md border border-border bg-card p-4 lg:grid-cols-[auto_1fr] lg:items-center">
          {riskScore != null && (
            <div className="flex items-center gap-4">
              <RiskGauge score={riskScore} label="risk" />
              {subfactors && subfactors.length > 0 && (
                <div className="hidden md:block">
                  <RiskScore score={riskScore} subfactors={subfactors} size="md" />
                  <div className="mt-1 text-[10px] uppercase tracking-wider text-muted-foreground">hover for breakdown</div>
                </div>
              )}
            </div>
          )}
          {stats && stats.length > 0 && (
            <div className={cn("grid gap-3", `grid-cols-2 md:grid-cols-${Math.min(stats.length, 5)}`)}>
              {stats.map((s, i) => {
                const color =
                  s.tone === "critical" ? "var(--color-severity-critical)" :
                  s.tone === "high" ? "var(--color-severity-high)" :
                  s.tone === "accent" ? "var(--color-primary)" :
                  "var(--color-foreground)";
                return (
                  <div key={i} className="space-y-0.5">
                    <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{s.label}</div>
                    <div className="text-display text-xl font-semibold tabular-nums" style={{ color }}>{s.value}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </header>
  );
}
