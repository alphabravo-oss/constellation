import { type ReactNode } from "react";
import { type Subfactor, RiskScore } from "@/components/ui/risk-score";
import { cn } from "@/lib/cn";
import { useCrumbLabel } from "@/lib/page-title";
import { PageHeader } from "@/components/ui/page";

/**
 * EntityHeader — entity pages (risk workspace, asset, CVE): the kit page
 * header plus one compact numbers strip (risk score with its breakdown, up to
 * four counts). Breadcrumbs live in the shell header; a string title is
 * registered as the last crumb so the header never shows an id.
 */
export interface BreadcrumbItem { label: string; to?: string }

const TONE: Record<string, string> = {
  neutral: "text-foreground",
  critical: "text-severity-critical",
  high: "text-severity-high",
  accent: "text-foreground",
};

export function EntityHeader({
  title,
  subtitle,
  badges,
  riskScore,
  subfactors,
  stats,
  actions,
  className,
}: {
  /** @deprecated breadcrumbs render in the shell header. */
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
  useCrumbLabel(typeof title === "string" ? title : null);
  const shown = (stats ?? []).slice(0, 4);
  return (
    <header className={cn("space-y-4", className)}>
      <PageHeader title={title} description={subtitle} badges={badges} actions={actions} />
      {(riskScore != null || shown.length > 0) && (
        <div className="flex min-h-14 flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border border-border bg-card px-4 py-2" data-testid="entity-numbers">
          {riskScore != null && (
            <div className="flex items-baseline gap-1.5">
              <span className="text-base font-semibold"><RiskScore score={riskScore} subfactors={subfactors} size="md" /></span>
              <span className="text-meta text-muted-foreground">risk score</span>
            </div>
          )}
          {shown.map((stat, index) => (
            <div key={index} className="flex items-baseline gap-1.5">
              <span className={cn("text-base font-semibold tabular-nums", TONE[stat.tone ?? "neutral"])}>{stat.value}</span>
              <span className="text-meta text-muted-foreground">{stat.label}</span>
            </div>
          ))}
        </div>
      )}
    </header>
  );
}
