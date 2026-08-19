import { Crown } from "lucide-react";
import type { Severity } from "@/api/client";
import { cn } from "@/lib/cn";
import { severityBg } from "@/lib/severity";

/**
 * Severity pill — used wherever a finding/event/exception severity appears.
 * Optional KEV crown overlay marks Known-Exploited entries inline so analysts
 * can scan a list and immediately see what's weaponized.
 */
export function SeverityBadge({
  severity,
  kev,
  size = "sm",
  uppercase = true,
  className,
}: {
  severity: Severity;
  kev?: boolean;
  size?: "xs" | "sm";
  uppercase?: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded font-medium",
        severityBg[severity],
        size === "xs" ? "h-4 px-1.5 text-[10px]" : "h-5 px-2 text-[11px]",
        uppercase && "uppercase tracking-wider",
        className,
      )}
      title={kev ? `${severity} · KEV listed` : severity}
    >
      {kev && <Crown className="h-3 w-3 fill-current" aria-label="Known Exploited Vulnerability" />}
      {severity}
    </span>
  );
}
