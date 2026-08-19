import { type ReactNode } from "react";
import { CheckCircle2, AlertTriangle, XCircle, Info } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * VerdictBanner — the verdict-first primitive (pattern P1).
 *
 * The single top-line answer to a page's one question ("Is the platform healthy?",
 * "Is my supply chain trusted?"). Renders a colored status strip with an icon, a
 * bold title, and optional supporting detail + actions. Everything else on the page
 * lives below it, behind progressive disclosure.
 */
export type VerdictStatus = "ok" | "degraded" | "critical" | "info";

const STATUS = {
  ok: { icon: CheckCircle2, color: "var(--color-status-success)" },
  degraded: { icon: AlertTriangle, color: "var(--color-severity-medium)" },
  critical: { icon: XCircle, color: "var(--color-severity-critical)" },
  info: { icon: Info, color: "var(--color-primary)" },
} as const;

export function VerdictBanner({
  status,
  title,
  detail,
  actions,
  className,
}: {
  status: VerdictStatus;
  title: ReactNode;
  detail?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  const { icon: Icon, color } = STATUS[status];
  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-md border bg-card px-4 py-3",
        className,
      )}
      style={{
        borderColor: `color-mix(in oklab, ${color} 40%, var(--color-border))`,
        background: `color-mix(in oklab, ${color} 6%, var(--color-card))`,
      }}
    >
      <Icon className="h-5 w-5 shrink-0" style={{ color }} />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-foreground">{title}</div>
        {detail && <div className="mt-0.5 text-xs text-muted-foreground">{detail}</div>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}
