import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * Page scaffolding primitives (Astronomer-parity).
 *
 * Every page should render:
 *   <PageContainer>
 *     <PageHeader title="…" description="…" actions={…} />
 *     …content…
 *   </PageContainer>
 *
 * This is the single source of truth for page title blocks — do NOT hand-roll
 * <h1> in pages. The AppShell already supplies outer padding, max-width, and the
 * fade-in; these primitives supply the vertical rhythm and header typography.
 */

export function PageContainer({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={cn("space-y-6", className)}>{children}</div>;
}

export function PageHeader({
  title,
  description,
  eyebrow,
  actions,
  backLink,
  badges,
  mono,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  /** Small uppercase label above the title (e.g. section / breadcrumb tail). */
  eyebrow?: ReactNode;
  /** Right-aligned actions (buttons, filters, metric grids). */
  actions?: ReactNode;
  /** Back-navigation link rendered above the title (detail pages). */
  backLink?: ReactNode;
  /** Status/identity pills rendered inline after the title (detail pages). */
  badges?: ReactNode;
  /** Render the title in the mono font (IDs, hostnames, digests). */
  mono?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("space-y-2", className)}>
      {backLink ? <div className="text-xs text-muted-foreground">{backLink}</div> : null}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 space-y-1">
          {eyebrow ? (
            <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {eyebrow}
            </div>
          ) : null}
          <div className="flex flex-wrap items-center gap-2">
            <h1
              className={cn(
                "text-2xl font-semibold tracking-tight text-foreground",
                mono && "font-mono",
              )}
            >
              {title}
            </h1>
            {badges}
          </div>
          {description ? (
            <p className="text-sm text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
      </div>
    </div>
  );
}

export function PageSection({
  title,
  description,
  actions,
  children,
  className,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("space-y-3", className)}>
      {title || actions ? (
        <div className="flex items-center justify-between gap-4">
          <div className="space-y-0.5">
            {title ? <h2 className="text-sm font-semibold text-foreground">{title}</h2> : null}
            {description ? (
              <p className="text-xs text-muted-foreground">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}
