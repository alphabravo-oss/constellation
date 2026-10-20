import { useId, useState, type ReactNode } from "react";
import { CircleCheck, TriangleAlert, CircleX, Info, ChevronDown } from "lucide-react";
import { cn } from "@/lib/cn";

/** Compact page status. Supporting context is available on demand. */
export type VerdictStatus = "ok" | "degraded" | "critical" | "info";

const STATUS = {
  ok: { icon: CircleCheck, color: "var(--color-status-success)" },
  degraded: { icon: TriangleAlert, color: "var(--color-severity-medium)" },
  critical: { icon: CircleX, color: "var(--color-severity-critical)" },
  info: { icon: Info, color: "var(--color-primary)" },
} as const;

export function VerdictBanner({
  status,
  title,
  detail,
  detailMode = "disclosure",
  actions,
  className,
}: {
  status: VerdictStatus;
  title: ReactNode;
  detail?: ReactNode;
  /** Keep essential action consequences visible in decision forms. */
  detailMode?: "disclosure" | "inline";
  actions?: ReactNode;
  className?: string;
}) {
  const { icon: Icon, color } = STATUS[status];
  const [expanded, setExpanded] = useState(false);
  const detailId = useId();
  const hasDetail = detail !== undefined && detail !== null && detail !== false && detail !== "";
  return (
    <div className={cn("flex flex-wrap items-center gap-x-2 gap-y-1 text-sm", className)} data-slot="page-status">
      <Icon aria-hidden="true" className="h-4 w-4 shrink-0" style={{ color }} />
      <div className="min-w-0 flex-1 font-medium text-foreground">{title}</div>
      {hasDetail && detailMode === "disclosure" && (
        <button type="button" aria-expanded={expanded} aria-controls={detailId}
          onClick={() => setExpanded(value => !value)}
          className="inline-flex min-h-8 shrink-0 items-center gap-1 rounded px-1 text-xs text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring">
          Details<ChevronDown aria-hidden="true" className={cn("h-3 w-3", expanded && "rotate-180")} />
        </button>
      )}
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      {hasDetail && <div id={detailId} hidden={detailMode !== "inline" && !expanded} className="basis-full pl-6 text-xs leading-relaxed text-muted-foreground">{detail}</div>}
    </div>
  );
}
