import { useId, useState, type ReactNode } from "react";
import { CircleCheck, TriangleAlert, CircleX, Info, ChevronDown } from "lucide-react";
import { cn } from "@/lib/cn";
import { useProduct } from "@/ui";

/**
 * The page verdict: the kit's 56 px strip — icon + one sentence + up to four
 * inline numbers + "Details". It replaces the old verdict + stat-card stack
 * (C1). Color appears on the icon and on severity numerals only.
 */
export type VerdictStatus = "ok" | "degraded" | "critical" | "info";

const STATUS: Record<VerdictStatus, { icon: typeof Info; className: string }> = {
  ok: { icon: CircleCheck, className: "text-status-success" },
  degraded: { icon: TriangleAlert, className: "text-status-warning" },
  critical: { icon: CircleX, className: "text-status-error" },
  info: { icon: Info, className: "text-muted-foreground" },
};

export type VerdictNumberTone = "default" | "critical" | "high" | "medium" | "low" | "warning" | "error" | "success" | "muted";

const NUMBER_TONE: Record<VerdictNumberTone, string> = {
  default: "text-foreground",
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
  warning: "text-status-warning",
  error: "text-status-error",
  success: "text-status-success",
  muted: "text-muted-foreground",
};

export interface VerdictNumber {
  label: string;
  value: ReactNode;
  tone?: VerdictNumberTone;
  /** Drill-down link (the number becomes a link). */
  href?: string;
  /** Accessible/hover description of what the number counts. */
  title?: string;
  testId?: string;
}

export function VerdictBanner({
  status,
  title,
  detail,
  detailMode = "disclosure",
  numbers,
  actions,
  className,
}: {
  status: VerdictStatus;
  title: ReactNode;
  detail?: ReactNode;
  /** Keep essential action consequences visible in decision forms. */
  detailMode?: "disclosure" | "inline";
  /** At most four inline numbers (extra entries are ignored). */
  numbers?: VerdictNumber[];
  actions?: ReactNode;
  className?: string;
}) {
  const { icon: Icon, className: toneClass } = STATUS[status];
  const { Link } = useProduct();
  const [expanded, setExpanded] = useState(false);
  const detailId = useId();
  const hasDetail = detail !== undefined && detail !== null && detail !== false && detail !== "";
  return (
    <div className={cn("rounded-lg border border-border bg-card", className)} data-slot="page-status" data-status={status}>
      <div className="flex min-h-14 flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2">
        <Icon aria-hidden="true" className={cn("h-5 w-5 shrink-0", toneClass)} />
        <div className="min-w-0 flex-1 basis-60 text-sm font-medium text-foreground" role="status">{title}</div>
        {numbers && numbers.length > 0 ? (
          <dl className="flex flex-wrap items-baseline gap-x-5 gap-y-1" data-testid="verdict-numbers">
            {numbers.slice(0, 4).map((item) => {
              const value = (
                <dd className={cn("text-base font-semibold tabular-nums", NUMBER_TONE[item.tone ?? "default"])}>{item.value}</dd>
              );
              const content = (
                <>
                  {value}
                  <dt className="text-meta text-muted-foreground">{item.label}</dt>
                </>
              );
              return item.href ? (
                <Link
                  key={item.label}
                  to={item.href}
                  title={item.title}
                  data-testid={item.testId}
                  className="flex flex-row-reverse items-baseline justify-end gap-1.5 rounded-sm hover:underline hover:decoration-muted-foreground/50 hover:underline-offset-4 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {content}
                </Link>
              ) : (
                <div key={item.label} title={item.title} data-testid={item.testId} className="flex flex-row-reverse items-baseline justify-end gap-1.5">
                  {content}
                </div>
              );
            })}
          </dl>
        ) : null}
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        {hasDetail && detailMode === "disclosure" ? (
          <button
            type="button"
            aria-expanded={expanded}
            aria-controls={detailId}
            onClick={() => setExpanded((value) => !value)}
            className="inline-flex h-8 shrink-0 items-center gap-1 rounded-md px-2 text-meta font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
          >
            Details
            <ChevronDown aria-hidden="true" className={cn("h-3.5 w-3.5 transition-transform", expanded && "rotate-180")} />
          </button>
        ) : null}
      </div>
      {hasDetail ? (
        <div
          id={detailId}
          hidden={detailMode !== "inline" && !expanded}
          className="border-t border-border px-4 py-3 text-sm leading-relaxed text-muted-foreground"
        >
          {detail}
        </div>
      ) : null}
    </div>
  );
}
