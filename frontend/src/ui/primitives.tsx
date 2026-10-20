import {
  forwardRef,
  type ButtonHTMLAttributes,
  type ComponentPropsWithoutRef,
  type HTMLAttributes,
  type ReactElement,
  type ReactNode,
} from "react";
import {
  DropdownMenu as MenuPrimitive,
  Popover as PopoverPrimitive,
  Tooltip as TooltipPrimitive,
} from "radix-ui";
import { Loader2 } from "lucide-react";
import { cn } from "./cn";

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */

export type ButtonIntent =
  | "default"
  | "primary"
  | "destructive"
  | "ghost"
  | "link";
export type ButtonSize = "xs" | "sm" | "md" | "icon" | "icon-sm";

/**
 * Intent → classes. `primary` is the only brand-colored surface in the kit
 * (besides the mark and the active nav indicator).
 */
export const buttonIntentClass: Record<ButtonIntent, string> = {
  default: "border border-border bg-background text-foreground hover:bg-accent",
  primary: "bg-brand text-brand-foreground hover:bg-brand/90",
  destructive: "bg-status-error text-white hover:bg-status-error/90",
  ghost: "text-muted-foreground hover:bg-accent hover:text-foreground",
  link: "text-foreground underline-offset-4 hover:underline",
};

export const buttonSizeClass: Record<ButtonSize, string> = {
  xs: "h-6 px-2 text-meta",
  sm: "h-[calc(var(--control-h)-0.25rem)] px-3 text-meta",
  md: "h-(--control-h) px-4 text-body",
  icon: "h-[calc(var(--control-h)-0.25rem)] w-[calc(var(--control-h)-0.25rem)] p-0",
  "icon-sm": "h-7 w-7 p-0",
};

export const buttonBaseClass =
  "inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  intent?: ButtonIntent;
  size?: ButtonSize;
  icon?: ReactNode;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      intent = "default",
      size = "md",
      icon,
      loading = false,
      disabled,
      className,
      children,
      type = "button",
      ...props
    },
    ref,
  ) => (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      className={cn(
        buttonBaseClass,
        buttonIntentClass[intent],
        buttonSizeClass[size],
        className,
      )}
      {...props}
    >
      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : icon}
      {size !== "icon" && size !== "icon-sm" ? children : null}
      {(size === "icon" || size === "icon-sm") && typeof children === "string" ? (
        <span className="sr-only">{children}</span>
      ) : null}
    </button>
  ),
);
Button.displayName = "Button";

/* ------------------------------------------------------------------ */
/* Kbd                                                                 */
/* ------------------------------------------------------------------ */

export function Kbd({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded border border-border bg-muted px-1 font-mono text-micro text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------ */
/* Tooltip                                                             */
/* ------------------------------------------------------------------ */

export function Tooltip({
  content,
  children,
  side = "top",
  className,
}: {
  content: ReactNode;
  children: ReactElement;
  side?: "top" | "right" | "bottom" | "left";
  className?: string;
}) {
  return (
    <TooltipPrimitive.Provider delayDuration={300}>
      <TooltipPrimitive.Root>
        <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
        {content ? (
          <TooltipPrimitive.Portal>
            <TooltipPrimitive.Content
              side={side}
              sideOffset={6}
              collisionPadding={8}
              className={cn(
                "z-toast max-w-xs rounded-md border border-border bg-popover px-2.5 py-1.5 text-xs text-popover-foreground shadow-elev-2",
                className,
              )}
            >
              {content}
            </TooltipPrimitive.Content>
          </TooltipPrimitive.Portal>
        ) : null}
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  );
}

/* ------------------------------------------------------------------ */
/* Popover                                                             */
/* ------------------------------------------------------------------ */

export const Popover = PopoverPrimitive.Root;
export const PopoverTrigger = PopoverPrimitive.Trigger;
export const PopoverAnchor = PopoverPrimitive.Anchor;
export const PopoverClose = PopoverPrimitive.Close;

export function PopoverContent({
  className,
  align = "start",
  sideOffset = 6,
  ...props
}: ComponentPropsWithoutRef<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        collisionPadding={8}
        className={cn(
          "z-popover w-72 rounded-md border border-border bg-popover p-3 text-popover-foreground shadow-elev-popover outline-none",
          className,
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  );
}

/* ------------------------------------------------------------------ */
/* Dropdown menu                                                       */
/* ------------------------------------------------------------------ */

export const Menu = MenuPrimitive.Root;
export const MenuTrigger = MenuPrimitive.Trigger;
export const MenuGroup = MenuPrimitive.Group;
export const MenuCheckboxItem = MenuPrimitive.CheckboxItem;
export const MenuItemIndicator = MenuPrimitive.ItemIndicator;

export function MenuContent({
  className,
  sideOffset = 4,
  align = "end",
  ...props
}: ComponentPropsWithoutRef<typeof MenuPrimitive.Content>) {
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.Content
        sideOffset={sideOffset}
        align={align}
        collisionPadding={8}
        className={cn(
          "z-popover min-w-40 overflow-y-auto rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-elev-popover outline-none",
          "max-h-(--radix-dropdown-menu-content-available-height)",
          className,
        )}
        {...props}
      />
    </MenuPrimitive.Portal>
  );
}

export function MenuItem({
  className,
  variant = "default",
  ...props
}: ComponentPropsWithoutRef<typeof MenuPrimitive.Item> & {
  variant?: "default" | "destructive";
}) {
  return (
    <MenuPrimitive.Item
      className={cn(
        "flex w-full cursor-default select-none items-center gap-2 rounded-sm px-2.5 py-1.5 text-left text-body outline-none transition-colors",
        "data-disabled:cursor-not-allowed data-disabled:opacity-50",
        variant === "destructive"
          ? "text-status-error data-highlighted:bg-status-error/10"
          : "text-popover-foreground data-highlighted:bg-accent",
        className,
      )}
      {...props}
    />
  );
}

export function MenuSeparator({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof MenuPrimitive.Separator>) {
  return (
    <MenuPrimitive.Separator
      className={cn("-mx-1 my-1 h-px bg-border", className)}
      {...props}
    />
  );
}

export function MenuLabel({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof MenuPrimitive.Label>) {
  return (
    <MenuPrimitive.Label
      className={cn(
        "px-2.5 py-1.5 text-meta font-semibold text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------ */
/* Skeleton                                                            */
/* ------------------------------------------------------------------ */

export function Skeleton({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      aria-hidden="true"
      className={cn("animate-pulse-dot rounded-md bg-muted", className)}
      {...props}
    />
  );
}

export function SkeletonText({
  lines = 3,
  className,
}: {
  lines?: number;
  className?: string;
}) {
  return (
    <div className={cn("space-y-2", className)}>
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton
          key={i}
          className={cn("h-3", i === lines - 1 ? "w-2/3" : "w-full")}
        />
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Status dot + label (never color-only)                               */
/* ------------------------------------------------------------------ */

export type StatusTone =
  | "success"
  | "warning"
  | "error"
  | "info"
  | "pending"
  | "neutral";

export const statusDotClass: Record<StatusTone, string> = {
  success: "bg-status-success",
  warning: "bg-status-warning",
  error: "bg-status-error",
  info: "bg-status-info",
  pending: "bg-status-pending",
  neutral: "bg-status-neutral",
};

export const statusTextClass: Record<StatusTone, string> = {
  success: "text-status-success",
  warning: "text-status-warning",
  error: "text-status-error",
  info: "text-status-info",
  pending: "text-status-pending",
  neutral: "text-status-neutral",
};

export function StatusDot({
  tone,
  label,
  className,
}: {
  tone: StatusTone;
  label: string;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-body", className)}>
      <span
        aria-hidden="true"
        className={cn("h-2 w-2 shrink-0 rounded-full", statusDotClass[tone])}
      />
      <span>{label}</span>
    </span>
  );
}
