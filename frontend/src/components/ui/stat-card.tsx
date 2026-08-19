import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/cn";
import { Sparkline } from "./sparkline";

/**
 * StatCard / MetricTile — dashboard-grade KPI card.
 *
 * Always shows: large number + label.
 * Optional: trend sparkline (right side), delta vs previous, color tone, link.
 */
export function StatCard({
  label,
  value,
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
  delta?: { value: string; positive?: boolean };
  trend?: number[];
  href?: string;
  tone?: "neutral" | "critical" | "high" | "medium" | "low" | "accent";
  className?: string;
  hint?: string;
  icon?: ReactNode;
}) {
  const toneColor =
    tone === "critical" ? "var(--color-severity-critical)" :
    tone === "high"     ? "var(--color-severity-high)" :
    tone === "medium"   ? "var(--color-severity-medium)" :
    tone === "low"      ? "var(--color-severity-low)" :
    tone === "accent"   ? "var(--color-primary)" :
    "var(--color-muted-foreground)";

  const inner = (
    <div
      className={cn(
        "group relative rounded-md border border-border bg-card px-4 py-3 transition-all duration-100",
        "hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))]",
        href && "cursor-pointer",
        className,
      )}
      style={tone !== "neutral" ? { borderColor: `color-mix(in oklab, ${toneColor} 24%, var(--color-border))` } : undefined}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
            {icon}
            {label}
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span
              className="text-display text-3xl font-semibold tabular-nums"
              style={{ color: tone === "neutral" ? "var(--color-foreground)" : toneColor }}
            >
              {value}
            </span>
            {delta && (
              <span
                className={cn(
                  "text-[11px] text-mono font-medium",
                  delta.positive ? "text-[color:var(--color-status-success)]" : "text-[color:var(--color-severity-high)]",
                )}
              >
                {delta.value}
              </span>
            )}
          </div>
          {hint && <div className="mt-1 text-[10px] text-muted-foreground">{hint}</div>}
        </div>
        <div className="flex flex-col items-end gap-1">
          {href && (
            <ArrowUpRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
          )}
          {trend && trend.length > 0 && <Sparkline data={trend} color={toneColor} />}
        </div>
      </div>
    </div>
  );

  if (href) return <Link to={href} className="block">{inner}</Link>;
  return inner;
}
