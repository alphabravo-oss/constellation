import type { ReactNode } from "react";
import { cn } from "./cn";
import { useProduct } from "./product";
import { Skeleton, type StatusTone, statusTextClass } from "./primitives";

export type StatTone = StatusTone | "default";

/**
 * Stat tile: label 12/500 sentence case, numeral 28 tabular, optional hint,
 * optional tone (numeral only — never borders or backgrounds), optional
 * capacity bar. Pass `to` to make the whole tile a link.
 */
export function StatCard({
  label,
  value,
  hint,
  tone = "default",
  icon,
  to,
  loading = false,
  bar,
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: StatTone;
  icon?: ReactNode;
  to?: string;
  loading?: boolean;
  /** 0–100 capacity bar under the numeral. */
  bar?: number;
  className?: string;
}) {
  const { Link } = useProduct();
  const body = (
    <>
      <div className="flex items-start justify-between gap-2">
        <p className="text-meta font-medium text-muted-foreground">{label}</p>
        {icon ? (
          <span className="shrink-0 text-muted-foreground" aria-hidden="true">
            {icon}
          </span>
        ) : null}
      </div>
      {loading ? (
        <>
          <span className="sr-only" role="status">
            Loading {label}
          </span>
          <Skeleton className="mt-2 h-7 w-20" />
          {hint ? <Skeleton className="mt-2 h-3 w-28" /> : null}
        </>
      ) : (
        <>
          <p
            className={cn(
              "mt-1 text-stat font-semibold tabular-nums tracking-tight",
              tone === "default" ? "text-foreground" : statusTextClass[tone],
            )}
          >
            {value}
          </p>
          {hint ? (
            <p className="mt-0.5 text-meta text-muted-foreground">{hint}</p>
          ) : null}
          {bar !== undefined ? (
            <div
              className="gauge-bar mt-3"
              role="meter"
              aria-label={`${label} ${Math.round(bar)}%`}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(bar)}
            >
              <div
                className={cn(
                  "gauge-bar-fill",
                  bar >= 90
                    ? "bg-status-error"
                    : bar >= 75
                      ? "bg-status-warning"
                      : "bg-muted-foreground/60",
                )}
                style={{ width: `${Math.min(100, Math.max(0, bar))}%` }}
              />
            </div>
          ) : null}
        </>
      )}
    </>
  );
  const frame =
    "block rounded-lg border border-border bg-card p-4 transition-colors";
  if (to) {
    return (
      <Link
        to={to}
        className={cn(
          frame,
          "hover:bg-accent/40 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
          className,
        )}
      >
        {body}
      </Link>
    );
  }
  return (
    <div aria-busy={loading || undefined} className={cn(frame, className)}>
      {body}
    </div>
  );
}

export function StatGrid({
  children,
  columns = 4,
  className,
}: {
  children: ReactNode;
  columns?: 2 | 3 | 4 | 5 | 6;
  className?: string;
}) {
  const cols: Record<number, string> = {
    2: "sm:grid-cols-2",
    3: "sm:grid-cols-3",
    4: "sm:grid-cols-2 lg:grid-cols-4",
    5: "sm:grid-cols-3 lg:grid-cols-5",
    6: "sm:grid-cols-3 lg:grid-cols-6",
  };
  return (
    <div className={cn("grid grid-cols-2 gap-3", cols[columns], className)}>
      {children}
    </div>
  );
}
