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
        "inline-flex h-5 items-center gap-1 rounded-full border border-severity-critical/40 px-2 text-micro font-semibold text-severity-critical",
        className,
      )}
      data-testid="kev-badge"
      title="CISA known exploited vulnerability"
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
        "inline-flex h-5 items-center gap-1 rounded-full border px-2 font-mono text-micro",
        hot ? "border-severity-high/40 text-severity-high" : "border-border text-muted-foreground",
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
        "inline-flex h-5 items-center gap-1 rounded-full border border-border px-2 text-micro font-medium",
        reachable ? "text-foreground" : "text-muted-foreground",
        className,
      )}
      title={reachable ? "Code path reachable" : "Not reachable via call graph"}
    >
      <Target className="h-2.5 w-2.5" /> {reachable ? "Reachable" : "Not reached"}
    </span>
  );
}
