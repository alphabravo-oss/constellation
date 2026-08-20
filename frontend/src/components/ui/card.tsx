import { type ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * Card — the enterprise surface primitive. A quiet, elevated container with a
 * hairline border and a soft shadow. Compose with CardHeader / CardContent, or
 * pass `title`/`description`/`action` for the common titled-card shape.
 */
export function Card({
  title,
  description,
  action,
  children,
  className,
  bodyClassName,
  padded = true,
}: {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** When false, CardContent adds no padding (e.g. a flush table). */
  padded?: boolean;
}) {
  return (
    <section
      className={cn(
        "overflow-hidden rounded-xl border border-border bg-card shadow-[0_1px_2px_0_rgb(0_0_0/0.04)]",
        className,
      )}
    >
      {(title || action) && <CardHeader title={title} description={description} action={action} />}
      <div className={cn(padded && "p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

export function CardHeader({
  title,
  description,
  action,
  className,
}: {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-4 border-b border-border px-5 py-4", className)}>
      <div className="min-w-0 space-y-0.5">
        {title && <h2 className="text-sm font-semibold text-foreground">{title}</h2>}
        {description && <p className="text-xs leading-relaxed text-muted-foreground">{description}</p>}
      </div>
      {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
    </div>
  );
}

export function CardContent({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("p-5", className)}>{children}</div>;
}

/**
 * A single label/value pair for card-based detail readouts (a definition row that
 * reads cleanly at enterprise density).
 */
export function DetailRow({ label, children, mono }: { label: ReactNode; children: ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5 py-2">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className={cn("text-sm text-foreground", mono && "font-mono")}>{children}</dd>
    </div>
  );
}
