import { createContext, useContext, type HTMLAttributes, type ReactNode } from "react";
import { Info } from "lucide-react";
import { cn } from "@/lib/cn";
import { Tooltip } from "@/ui";

/**
 * Page scaffolding on the kit's PageHeader contract: title 24/600 tight, one
 * short description line, actions on the right. Long explanatory prose moves
 * into an info tooltip next to the title (C1: no explanatory paragraphs in
 * the UI). Inside a tabbed hub (Policies, Agents, Signatures) the page renders
 * as a section of the hub (`EmbeddedPageProvider`).
 */
const EmbeddedPageContext = createContext(false);
export const EmbeddedPageProvider = EmbeddedPageContext.Provider;
export function useEmbeddedPage() {
  return useContext(EmbeddedPageContext);
}

/** Descriptions longer than this become an info tooltip. */
const INLINE_DESCRIPTION_MAX = 96;

export function PageContainer({
  children,
  className,
  ...rest
}: {
  children: ReactNode;
  className?: string;
} & HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("space-y-(--gap-section)", className)} {...rest}>{children}</div>;
}

function textOf(node: ReactNode): string | null {
  if (typeof node === "string") return node;
  if (typeof node === "number") return String(node);
  return null;
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
  /** Small label above the title (scope, entity kind). Never uppercase. */
  eyebrow?: ReactNode;
  actions?: ReactNode;
  /** Back-navigation link rendered above the title (form pages). */
  backLink?: ReactNode;
  /** Status/identity pills inline after the title. */
  badges?: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  const embedded = useEmbeddedPage();
  const text = textOf(description);
  const inline = description != null && (text === null || text.length <= INLINE_DESCRIPTION_MAX);
  const Heading = embedded ? "h2" : "h1";
  return (
    <div className={cn("space-y-1", className)} data-slot="page-header">
      {backLink ? <div className="text-meta text-muted-foreground">{backLink}</div> : null}
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
        <div className="min-w-0 flex-1 basis-72">
          {eyebrow ? <div className="mb-1 text-meta font-medium text-muted-foreground">{eyebrow}</div> : null}
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Heading
              className={cn(
                "min-w-0 max-w-full [overflow-wrap:anywhere] font-semibold text-foreground",
                embedded ? "text-section-title-lg" : "text-page-title tracking-[-0.02em]",
                mono && "font-mono",
              )}
            >
              {title}
            </Heading>
            {description != null && !inline ? (
              <Tooltip content={<span className="block max-w-sm text-meta leading-relaxed">{description}</span>}>
                <button
                  type="button"
                  aria-label="About this page"
                  className="inline-flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <Info className="h-4 w-4" aria-hidden />
                </button>
              </Tooltip>
            ) : null}
            {badges}
          </div>
          {description != null && inline ? (
            <p className="mt-1 max-w-3xl [overflow-wrap:anywhere] text-sm text-muted-foreground">{description}</p>
          ) : null}
          {description != null && !inline ? <p className="sr-only">{description}</p> : null}
        </div>
        {actions ? <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">{actions}</div> : null}
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
  const text = textOf(description);
  const inline = description != null && (text === null || text.length <= INLINE_DESCRIPTION_MAX);
  return (
    <section className={cn("space-y-3", className)}>
      {title || actions ? (
        <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
          <div className="min-w-0 flex-1 basis-64">
            <div className="flex items-center gap-1.5">
              {title ? <h2 className="[overflow-wrap:anywhere] text-section-title font-semibold text-foreground">{title}</h2> : null}
              {description != null && !inline ? (
                <Tooltip content={<span className="block max-w-sm text-meta leading-relaxed">{description}</span>}>
                  <button type="button" aria-label="About this section" className="inline-flex h-5 w-5 items-center justify-center rounded text-muted-foreground hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring">
                    <Info className="h-3.5 w-3.5" aria-hidden />
                  </button>
                </Tooltip>
              ) : null}
            </div>
            {description != null && inline ? (
              <p className="mt-0.5 [overflow-wrap:anywhere] text-meta text-muted-foreground">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="flex max-w-full flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}
