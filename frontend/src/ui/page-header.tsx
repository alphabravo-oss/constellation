import { createContext, useContext, type ReactNode } from "react";
import { cn } from "./cn";

/**
 * Layout routes may publish a scope line that every PageHeader below them
 * shows as its eyebrow (unless the page sets its own).
 */
const PageEyebrowContext = createContext<ReactNode>(null);
export const PageEyebrowProvider = PageEyebrowContext.Provider;

export function PageShell({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("space-y-(--gap-section)", className)}>{children}</div>
  );
}

export interface PageMetadataItem {
  label: string;
  value: ReactNode;
}

/**
 * Title (24/600, tight tracking) + one-line description + metadata row +
 * actions. The only uppercase allowed on a page is the optional eyebrow.
 */
export function PageHeader({
  title,
  description,
  eyebrow,
  status,
  metadata,
  actions,
  tabs,
  mono = false,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  eyebrow?: ReactNode;
  /** Inline status pill next to the title. */
  status?: ReactNode;
  metadata?: PageMetadataItem[];
  actions?: ReactNode;
  /** Route-tab strip rendered under the header, separated by a rule. */
  tabs?: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  const scopeEyebrow = useContext(PageEyebrowContext);
  const eyebrowContent = eyebrow ?? scopeEyebrow;
  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          {eyebrowContent ? (
            <div className="mb-1 text-meta font-medium text-muted-foreground">
              {eyebrowContent}
            </div>
          ) : null}
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <h1
              className={cn(
                "min-w-0 break-words text-page-title font-semibold tracking-[-0.02em] text-foreground",
                mono && "font-mono",
              )}
            >
              {title}
            </h1>
            {status}
          </div>
          {description ? (
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {description}
            </p>
          ) : null}
          {metadata && metadata.length > 0 ? (
            <dl className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-meta text-muted-foreground">
              {metadata.map((item) => (
                <div key={item.label} className="flex items-center gap-1">
                  <dt>{item.label}:</dt>
                  <dd className="text-foreground">{item.value}</dd>
                </div>
              ))}
            </dl>
          ) : null}
        </div>
        {actions ? (
          <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">
            {actions}
          </div>
        ) : null}
      </div>
      {tabs ? <div className="border-b border-border">{tabs}</div> : null}
    </div>
  );
}

export function PageSection({
  children,
  title,
  description,
  actions,
  className,
  size = "md",
}: {
  children: ReactNode;
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
  /** Section title 14 (md) or 16 (lg). */
  size?: "md" | "lg";
}) {
  return (
    <section className={cn("space-y-3", className)}>
      {title || description || actions ? (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <div className="min-w-0">
            {title ? (
              <h2
                className={cn(
                  "font-semibold text-foreground",
                  size === "lg" ? "text-section-title-lg" : "text-section-title",
                )}
              >
                {title}
              </h2>
            ) : null}
            {description ? (
              <p className="mt-1 text-sm text-muted-foreground">
                {description}
              </p>
            ) : null}
          </div>
          {actions ? (
            <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">
              {actions}
            </div>
          ) : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}
