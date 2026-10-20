import {
  forwardRef,
  useId,
  useState,
  type ComponentType,
  type HTMLAttributes,
  type ReactNode,
} from "react";
import { BookOpen, ChevronDown, ChevronLeft, ChevronRight } from "lucide-react";
import type { LucideProps } from "lucide-react";
import { cn } from "./cn";
import { useProduct } from "./product";
import { ProductFooter } from "./app-shell";
import { Popover, PopoverContent, PopoverTrigger, Tooltip } from "./primitives";

export type NavIcon = ComponentType<LucideProps>;

/**
 * Sidebar model: a 240 px panel (or a 64 px rail) made of groups of items.
 * Rules enforced here: sentence-case labels are the caller's job; one icon
 * per item; no raw counts (there is no count slot — counts belong in page
 * content); rail groups open a flyout listing their items.
 */

export interface SidebarFrameProps extends HTMLAttributes<HTMLElement> {
  collapsed?: boolean;
  /** Brand row (mark + name); hidden on the rail. */
  brand?: ReactNode;
  /** Context switcher slot under the brand row (cluster/org panel header). */
  context?: ReactNode;
  /** Collapse toggle handler; omitted → no toggle. */
  onToggleCollapsed?: () => void;
  /** Mobile drawer state. */
  mobileOpen?: boolean;
  inert?: boolean;
  navLabel?: string;
  children: ReactNode;
  footer?: ReactNode;
}

export const SidebarFrame = forwardRef<HTMLElement, SidebarFrameProps>(
  (
    {
      collapsed = false,
      brand,
      context,
      onToggleCollapsed,
      mobileOpen = false,
      inert,
      navLabel = "Primary",
      children,
      footer,
      className,
      ...rest
    },
    ref,
  ) => {
    const product = useProduct();
    return (
      <aside
        ref={ref}
        inert={inert}
        aria-hidden={inert || undefined}
        className={cn(
          "fixed inset-y-0 left-0 z-chrome flex h-screen w-(--sidebar-w) -translate-x-full flex-col border-r border-sidebar-border bg-sidebar transition-transform duration-200 ease-soft lg:static lg:z-auto lg:translate-x-0 lg:transition-[width]",
          mobileOpen && "translate-x-0",
          collapsed ? "lg:w-(--rail-w)" : "lg:w-(--sidebar-w)",
          className,
        )}
        {...rest}
      >
        <div
          className={cn(
            "flex h-(--header-h) shrink-0 items-center border-b border-sidebar-border",
            collapsed ? "justify-center px-2" : "px-4",
          )}
        >
          {!collapsed && brand}
          {onToggleCollapsed ? (
            <button
              type="button"
              onClick={onToggleCollapsed}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              className={cn(
                "nav-item h-8 shrink-0 justify-center px-0 font-normal",
                collapsed ? "w-8" : "ml-auto hidden w-8 lg:flex",
              )}
            >
              {collapsed ? (
                <ChevronRight className="h-4 w-4" />
              ) : (
                <ChevronLeft className="h-4 w-4" />
              )}
            </button>
          ) : null}
        </div>
        {context}
        <nav
          aria-label={navLabel}
          className="no-scrollbar flex-1 overflow-y-auto px-2 py-2"
        >
          {children}
        </nav>
        <div className="mt-auto space-y-1 border-t border-sidebar-border px-2 py-2">
          {footer}
          {product.docsUrl ? (
            <Tooltip content={collapsed ? "Documentation" : null}>
              <a
                href={product.docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Documentation (opens in a new tab)"
                className={cn(
                  "nav-item h-8 py-0 text-meta font-normal",
                  collapsed && "justify-center px-0",
                )}
              >
                <BookOpen className="h-4 w-4 shrink-0" />
                {!collapsed && <span>Documentation</span>}
              </a>
            </Tooltip>
          ) : null}
          {!collapsed && <ProductFooter className="px-3 py-1" />}
        </div>
      </aside>
    );
  },
);
SidebarFrame.displayName = "SidebarFrame";

/** Brand row: product mark + name, linking home. */
export function SidebarBrand({
  to,
  subtitle,
  className,
}: {
  to: string;
  subtitle?: ReactNode;
  className?: string;
}) {
  const product = useProduct();
  const Link = product.Link;
  return (
    <Link
      to={to}
      className={cn(
        "flex min-w-0 items-center gap-2.5 rounded-md focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
        className,
      )}
    >
      <span className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-lg">
        {product.mark}
      </span>
      <span className="flex min-w-0 flex-col">
        <span className="truncate text-sm font-semibold leading-tight tracking-tight text-foreground">
          {product.name}
        </span>
        {subtitle ? (
          <span className="truncate text-micro leading-tight text-muted-foreground">
            {subtitle}
          </span>
        ) : null}
      </span>
    </Link>
  );
}

/** Group header (sentence case, 12/600) with an optional collapse toggle. */
export function SidebarGroup({
  label,
  open = true,
  onToggle,
  children,
  className,
}: {
  label?: string;
  open?: boolean;
  onToggle?: () => void;
  children: ReactNode;
  className?: string;
}) {
  const contentId = useId();
  return (
    <div className={cn("mb-1", className)}>
      {label ? (
        onToggle ? (
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            aria-controls={contentId}
            className="flex h-8 w-full items-center justify-between rounded-md px-3 text-meta font-semibold text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
          >
            <span>{label}</span>
            <ChevronDown
              className={cn(
                "h-3.5 w-3.5 transition-transform",
                !open && "-rotate-90",
              )}
            />
          </button>
        ) : (
          <p className="flex h-8 items-center px-3 text-meta font-semibold text-muted-foreground">
            {label}
          </p>
        )
      ) : null}
      {open ? (
        <div id={contentId} className="space-y-px">
          {children}
        </div>
      ) : null}
    </div>
  );
}

/** One row: icon + label; the brand accent appears only as the active bar. */
export function SidebarItem({
  to,
  icon: Icon,
  label,
  active = false,
  onClick,
  trailing,
  className,
}: {
  to: string;
  icon: NavIcon;
  label: ReactNode;
  active?: boolean;
  onClick?: () => void;
  /** Rare: a star/favorite control. Never a count. */
  trailing?: ReactNode;
  className?: string;
}) {
  const { Link } = useProduct();
  return (
    <div className={cn("group relative flex items-center gap-1", className)}>
      {active ? (
        <span
          aria-hidden="true"
          className="absolute -left-2 top-1.5 bottom-1.5 w-0.5 rounded-full bg-brand"
        />
      ) : null}
      <Link
        to={to}
        current={active}
        onClick={onClick}
        className={cn(
          "flex h-8 min-w-0 flex-1 items-center gap-2.5 rounded-md px-3 text-sm transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
          active
            ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
            : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
        )}
      >
        <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
        <span className="min-w-0 flex-1 truncate">{label}</span>
      </Link>
      {trailing}
    </div>
  );
}

/** Rail (64 px) icon: a single destination. */
export function RailItem({
  to,
  icon: Icon,
  label,
  active = false,
  onClick,
}: {
  to: string;
  icon: NavIcon;
  label: string;
  active?: boolean;
  onClick?: () => void;
}) {
  const { Link } = useProduct();
  return (
    <Tooltip content={label} side="right">
      <Link
        to={to}
        current={active}
        aria-label={label}
        data-active={active ? "true" : undefined}
        onClick={onClick}
        className={cn(
          "relative flex h-9 w-9 items-center justify-center rounded-md transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
          active
            ? "bg-sidebar-accent text-sidebar-accent-foreground"
            : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
        )}
      >
        {active ? (
          <span
            aria-hidden="true"
            className="absolute -left-2 top-1.5 bottom-1.5 w-0.5 rounded-full bg-brand"
          />
        ) : null}
        <Icon className="h-4 w-4" aria-hidden="true" />
      </Link>
    </Tooltip>
  );
}

/** Rail group: one icon that opens a flyout listing the group's items. */
export function RailGroup({
  icon: Icon,
  label,
  active = false,
  children,
}: {
  icon: NavIcon;
  label: string;
  active?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip content={open ? null : label} side="right">
        <PopoverTrigger asChild>
          <button
            type="button"
            aria-label={label}
            data-active={active ? "true" : undefined}
            className={cn(
              "relative flex h-9 w-9 items-center justify-center rounded-md transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
              active || open
                ? "bg-sidebar-accent text-sidebar-accent-foreground"
                : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
            )}
          >
            {active ? (
              <span
                aria-hidden="true"
                className="absolute -left-2 top-1.5 bottom-1.5 w-0.5 rounded-full bg-brand"
              />
            ) : null}
            <Icon className="h-4 w-4" aria-hidden="true" />
          </button>
        </PopoverTrigger>
      </Tooltip>
      <PopoverContent
        side="right"
        align="start"
        sideOffset={8}
        className="w-64 p-1"
        onClick={(event) => {
          // Close on item activation (links bubble a click).
          if ((event.target as HTMLElement).closest("a")) setOpen(false);
        }}
      >
        <p className="px-3 py-1.5 text-meta font-semibold text-muted-foreground">
          {label}
        </p>
        <nav aria-label={label} className="space-y-px">
          {children}
        </nav>
      </PopoverContent>
    </Popover>
  );
}

/** Rail column wrapper (used inside `SidebarFrame` when collapsed, or as the
 * persistent global rail next to a context panel). */
export function Rail({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center gap-1 py-1", className)}>
      {children}
    </div>
  );
}
