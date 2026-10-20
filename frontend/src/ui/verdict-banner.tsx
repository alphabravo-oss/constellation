import { useId, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Info,
  XCircle,
} from "lucide-react";
import { cn } from "./cn";

export type VerdictTone = "ok" | "degraded" | "critical" | "info";

const toneIcon: Record<VerdictTone, typeof Info> = {
  ok: CheckCircle2,
  degraded: AlertTriangle,
  critical: XCircle,
  info: Info,
};
const toneText: Record<VerdictTone, string> = {
  ok: "text-status-success",
  degraded: "text-status-warning",
  critical: "text-status-error",
  info: "text-status-info",
};

export interface VerdictNumber {
  label: string;
  value: ReactNode;
  tone?: "default" | "warning" | "error";
  /** Stable key exposed as `data-verdict-number` (tests, analytics). */
  id?: string;
}

/**
 * 56 px verdict strip: icon + one sentence + up to four inline numbers +
 * an optional "Details" disclosure. Color appears on the icon only.
 */
export function VerdictBanner({
  tone,
  sentence,
  numbers = [],
  details,
  className,
}: {
  tone: VerdictTone;
  sentence: ReactNode;
  numbers?: VerdictNumber[];
  details?: ReactNode;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const Icon = toneIcon[tone];
  return (
    <div
      role="status"
      className={cn(
        "rounded-lg border border-border bg-card",
        className,
      )}
    >
      <div className="flex min-h-14 flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2">
        <Icon className={cn("h-5 w-5 shrink-0", toneText[tone])} aria-hidden />
        <p className="min-w-0 flex-1 text-sm text-foreground">{sentence}</p>
        {numbers.slice(0, 4).map((item) => (
          <span
            key={item.label}
            data-verdict-number={item.id}
            className="flex items-baseline gap-1.5"
          >
            <span
              className={cn(
                "text-base font-semibold tabular-nums",
                item.tone === "error"
                  ? "text-status-error"
                  : item.tone === "warning"
                    ? "text-status-warning"
                    : "text-foreground",
              )}
            >
              {item.value}
            </span>
            <span className="text-meta text-muted-foreground">{item.label}</span>
          </span>
        ))}
        {details ? (
          <button
            type="button"
            aria-expanded={open}
            aria-controls={id}
            onClick={() => setOpen((value) => !value)}
            className="inline-flex h-8 items-center gap-1 rounded-md px-2 text-meta font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
          >
            Details
            <ChevronDown
              className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")}
            />
          </button>
        ) : null}
      </div>
      {details && open ? (
        <div id={id} className="border-t border-border px-4 py-3 text-sm">
          {details}
        </div>
      ) : null}
    </div>
  );
}
