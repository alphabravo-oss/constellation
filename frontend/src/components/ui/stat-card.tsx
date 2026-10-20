import { type HTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { useProduct } from "@/ui";
import { Sparkline } from "./sparkline";

/** Stat tiles fit the content width (detail pages; list pages use the verdict strip). */
export function StatGrid({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return <section className={cn("app-stat-grid", className)} {...props} />;
}

export type StatTone = "neutral" | "critical" | "high" | "medium" | "low" | "accent";

/** Severity tones color the numeral only — never borders or backgrounds. */
export const statToneText: Record<StatTone, string> = {
  neutral: "text-foreground",
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
  accent: "text-foreground",
};

/**
 * Kit StatCard contract: label 12/500 sentence case, numeral 28 tabular,
 * optional hint/trend/link. `valueKind="text"` keeps timestamps and words at
 * body size.
 */
export function StatCard({
  label,
  value,
  valueKind = "number",
  delta,
  trend,
  href,
  tone = "neutral",
  className,
  hint,
  icon,
}: {
  label: string;
  value: ReactNode;
  valueKind?: "number" | "text";
  delta?: { value: string; positive?: boolean };
  trend?: number[];
  href?: string;
  tone?: StatTone;
  className?: string;
  hint?: string;
  icon?: ReactNode;
}) {
  const { Link } = useProduct();
  const body = (
    <>
      <div className="flex items-start justify-between gap-2">
        <p className="min-w-0 [overflow-wrap:anywhere] text-meta font-medium text-muted-foreground">{label}</p>
        {icon ? <span className="shrink-0 text-muted-foreground [&_svg]:h-4 [&_svg]:w-4" aria-hidden>{icon}</span> : null}
      </div>
      <div className="mt-1 flex flex-wrap items-baseline justify-between gap-2">
        <span
          className={cn(
            "app-stat-value min-w-0 [overflow-wrap:anywhere] font-semibold tabular-nums tracking-tight",
            valueKind === "text" ? "text-body" : "text-stat",
            statToneText[tone],
          )}
          data-kind={valueKind}
        >
          {value}
        </span>
        {delta ? (
          <span className={cn("font-mono text-meta", delta.positive ? "text-status-success" : "text-muted-foreground")}>{delta.value}</span>
        ) : null}
        {trend && trend.length > 0 ? <Sparkline data={trend} color="hsl(var(--muted-foreground))" /> : null}
      </div>
      {hint ? <p className="mt-0.5 text-meta text-muted-foreground">{hint}</p> : null}
    </>
  );
  const frame = "app-stat-card block min-w-0 rounded-lg border border-border bg-card p-4 transition-colors";
  if (href) {
    return (
      <Link to={href} className={cn(frame, "hover:bg-accent/40 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring", className)}>
        {body}
      </Link>
    );
  }
  return <div className={cn(frame, className)}>{body}</div>;
}
