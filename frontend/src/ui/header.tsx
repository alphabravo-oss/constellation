import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { ChevronRight, Menu, Search } from "lucide-react";
import { cn } from "./cn";
import { useProduct } from "./product";
import { Kbd, Tooltip } from "./primitives";

/**
 * 56 px header. Left: scope/context + breadcrumbs (only when depth ≥ 2).
 * Center: one search affordance. Right: actions (theme, notifications,
 * assistant, account). The page title never lives here.
 */
export function Header({
  onOpenMobileNav,
  scope,
  breadcrumbs,
  search,
  actions,
  className,
}: {
  onOpenMobileNav?: () => void;
  scope?: ReactNode;
  breadcrumbs?: ReactNode;
  search?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <header
      className={cn(
        "sticky top-0 z-header flex min-h-(--header-h) flex-wrap items-center gap-2 border-b border-border bg-background/80 px-3 py-2 backdrop-blur-lg sm:px-(--content-gutter)",
        className,
      )}
    >
      {onOpenMobileNav ? (
        <HeaderIconButton
          onClick={onOpenMobileNav}
          aria-label="Open navigation"
          className="mr-1 lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </HeaderIconButton>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
        {scope}
        {breadcrumbs}
      </div>
      {search ? (
        <div className="hidden w-56 shrink-0 px-2 md:block 2xl:w-72">
          {search}
        </div>
      ) : null}
      <div className="ml-auto flex shrink-0 items-center justify-end gap-1">
        {actions}
      </div>
    </header>
  );
}

export interface BreadcrumbItem {
  label: ReactNode;
  to?: string;
}

/**
 * Renders nothing below depth 2. The last crumb is plain text (the page owns
 * its title); earlier crumbs are links.
 */
export function Breadcrumbs({
  items,
  className,
}: {
  items: BreadcrumbItem[];
  className?: string;
}) {
  const { Link } = useProduct();
  if (items.length < 2) return null;
  return (
    <nav
      aria-label="Breadcrumb"
      className={cn(
        "flex min-w-0 shrink-0 items-center gap-1.5 overflow-hidden text-sm",
        className,
      )}
    >
      <ol className="flex min-w-0 items-center gap-1.5">
        {items.map((crumb, index) => {
          const last = index === items.length - 1;
          return (
            <li
              key={`${index}-${typeof crumb.label === "string" ? crumb.label : ""}`}
              className={cn(
                "flex min-w-0 items-center gap-1.5",
                last ? "flex" : "hidden sm:flex",
              )}
            >
              {index > 0 ? (
                <ChevronRight
                  aria-hidden="true"
                  className="hidden h-3.5 w-3.5 shrink-0 text-muted-foreground sm:block"
                />
              ) : null}
              {last || !crumb.to ? (
                <span
                  aria-current={last ? "page" : undefined}
                  className={cn(
                    "truncate",
                    last ? "font-medium text-foreground" : "text-muted-foreground",
                  )}
                >
                  {crumb.label}
                </span>
              ) : (
                <Link
                  to={crumb.to}
                  className="truncate rounded-sm text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {crumb.label}
                </Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/** 32 px icon button for the header's right cluster. */
export const HeaderIconButton = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & {
    tooltip?: ReactNode;
    badge?: number;
  }
>(({ className, tooltip, badge, children, ...props }, ref) => {
  const button = (
    <button
      ref={ref}
      type="button"
      className={cn(
        "relative inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
        className,
      )}
      {...props}
    >
      {children}
      {badge !== undefined && badge > 0 ? (
        <span className="absolute right-0.5 top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-status-error px-1 text-micro font-semibold text-white">
          {badge > 99 ? "99+" : badge}
        </span>
      ) : null}
    </button>
  );
  return tooltip ? <Tooltip content={tooltip}>{button}</Tooltip> : button;
});
HeaderIconButton.displayName = "HeaderIconButton";

/** The one search affordance: a field-shaped button that opens the palette. */
export function SearchTrigger({
  onOpen,
  placeholder = "Search…",
  hotkeys = ["/", "⌘K"],
  className,
}: {
  onOpen: () => void;
  placeholder?: string;
  hotkeys?: string[];
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onOpen}
      aria-haspopup="dialog"
      className={cn(
        "relative flex h-8 w-full items-center gap-2 rounded-md border border-border bg-background pl-8 pr-16 text-left text-sm text-muted-foreground transition-colors hover:bg-accent/50 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
        className,
      )}
    >
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2" />
      <span className="truncate">{placeholder}</span>
      <span
        aria-hidden="true"
        className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 items-center gap-1 sm:flex"
      >
        {hotkeys.map((key) => (
          <Kbd key={key}>{key}</Kbd>
        ))}
      </span>
    </button>
  );
}

/** Scope chip (cluster/org) shown at the left of the header in context. */
export const ScopeChip = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & {
    icon?: ReactNode;
    dot?: ReactNode;
  }
>(({ className, icon, dot, children, ...props }, ref) => (
  <button
    ref={ref}
    type="button"
    className={cn(
      "flex h-8 min-w-0 shrink-0 items-center gap-1.5 rounded-md border border-border px-2 text-sm text-foreground transition-colors hover:bg-accent focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring sm:max-w-52",
      className,
    )}
    {...props}
  >
    {icon}
    {dot}
    <span className="min-w-0 max-w-32 flex-1 truncate text-left">
      {children}
    </span>
  </button>
));
ScopeChip.displayName = "ScopeChip";
