import { Crown, Activity, Target } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * Tiny pills that communicate weaponization, exploitability, and reachability.
 * Used together in finding rows + CVE detail headers.
 */
export function KevBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 rounded px-1.5 h-4 text-[9px] font-semibold uppercase tracking-wider",
        "bg-[color-mix(in_oklab,var(--color-severity-critical)_22%,transparent)] text-[color:var(--color-severity-critical)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-severity-critical)_48%,transparent)]",
        className,
      )}
      data-testid="kev-badge"
      title="CISA Known-Exploited Vulnerability"
    >
      <Crown className="h-2.5 w-2.5 fill-current" /> KEV
    </span>
  );
}

export function EpssBadge({ probability, className }: { probability?: number; className?: string }) {
  if (probability == null) return null;
  const pct = probability * 100;
  const hot = pct >= 70;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-1.5 h-4 text-[10px] text-mono",
        hot
          ? "bg-[color-mix(in_oklab,var(--color-severity-high)_18%,transparent)] text-[color:var(--color-severity-high)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-severity-high)_36%,transparent)]"
          : "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
        className,
      )}
      title={`EPSS exploit probability ${pct.toFixed(1)}%`}
    >
      <Activity className="h-2.5 w-2.5" /> {pct.toFixed(pct < 1 ? 2 : 1)}%
    </span>
  );
}

export function ReachableBadge({ reachable, className }: { reachable?: boolean; className?: string }) {
  if (reachable == null) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-1.5 h-4 text-[10px] font-medium",
        reachable
          ? "bg-[color-mix(in_oklab,var(--color-accent-teal)_18%,transparent)] text-[color:var(--color-accent-teal)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-accent-teal)_36%,transparent)]"
          : "bg-muted text-muted-foreground ring-1 ring-inset ring-border",
        className,
      )}
      title={reachable ? "Code path reachable" : "Not reachable via call graph"}
    >
      <Target className="h-2.5 w-2.5" /> {reachable ? "reachable" : "unreached"}
    </span>
  );
}
