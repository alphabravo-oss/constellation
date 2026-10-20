import { Crown } from "lucide-react";
import type { Severity } from "@/api/client";
import { cn } from "@/lib/cn";
import { severityBg } from "@/lib/severity";

const LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

/**
 * Severity pill: Title case, 11 px semibold, severity color on a quiet wash.
 * This is one of the few places severity color is allowed. KEV adds a crown.
 */
export function SeverityBadge({
  severity,
  kev,
  size = "sm",
  className,
}: {
  severity: Severity;
  kev?: boolean;
  size?: "xs" | "sm";
  /** @deprecated severity is always Title case now. */
  uppercase?: boolean;
  className?: string;
}) {
  const label = LABEL[severity] ?? severity;
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1 rounded-full font-semibold text-micro leading-none",
        severityBg[severity],
        size === "xs" ? "h-[18px] px-1.5" : "h-5 px-2",
        className,
      )}
      title={kev ? `${label} · Known exploited (KEV)` : label}
      data-severity={severity}
    >
      {kev && <Crown className="h-3 w-3 fill-current" aria-label="Known exploited vulnerability" />}
      {label}
    </span>
  );
}
