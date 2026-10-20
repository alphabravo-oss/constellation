import { type ReactNode } from "react";
import { Command } from "cmdk";
import { Dialog as DialogPrimitive } from "radix-ui";
import { CornerDownLeft, Search } from "lucide-react";
import type { LucideProps } from "lucide-react";
import type { ComponentType } from "react";
import { cn } from "./cn";
import { Kbd } from "./primitives";

/**
 * One palette style for both products: sentence-case rows, grouped, with
 * hotkey hints. Group headings are 12/600 and never uppercase (the uppercase
 * class must not cascade into items).
 */
export function CommandPalette({
  open,
  onOpenChange,
  value,
  onValueChange,
  placeholder = "Search pages, resources and actions…",
  shouldFilter = true,
  children,
  footer,
  label = "Command palette",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  value?: string;
  onValueChange?: (value: string) => void;
  placeholder?: string;
  shouldFilter?: boolean;
  children: ReactNode;
  footer?: ReactNode;
  label?: string;
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-overlay bg-black/50 backdrop-blur-xs" />
        <DialogPrimitive.Content
          aria-describedby={undefined}
          className="fixed left-1/2 top-[18vh] z-overlay w-full max-w-xl -translate-x-1/2 px-4 outline-none"
        >
          <DialogPrimitive.Title className="sr-only">
            {label}
          </DialogPrimitive.Title>
          <Command
            label={label}
            shouldFilter={shouldFilter}
            className="overflow-hidden rounded-xl border border-border bg-popover text-popover-foreground shadow-elev-popover"
          >
            <div className="flex items-center gap-2 border-b border-border px-4">
              <Search className="h-4 w-4 shrink-0 text-muted-foreground" />
              <Command.Input
                value={value}
                onValueChange={onValueChange}
                placeholder={placeholder}
                className="h-12 flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-hidden"
              />
              <Kbd>Esc</Kbd>
            </div>
            <Command.List className="max-h-[min(60vh,28rem)] overflow-y-auto p-2">
              <Command.Empty className="py-8 text-center text-sm text-muted-foreground">
                No results.
              </Command.Empty>
              {children}
            </Command.List>
            <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-2 text-micro text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <Kbd>↑</Kbd>
                <Kbd>↓</Kbd> to move
                <Kbd className="ml-2">
                  <CornerDownLeft className="h-3 w-3" />
                </Kbd>{" "}
                to open
              </span>
              {footer}
            </div>
          </Command>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

export function CommandGroup({
  heading,
  children,
  className,
}: {
  heading: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Command.Group
      heading={heading}
      className={cn(
        "mb-1 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-meta [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:text-muted-foreground",
        className,
      )}
    >
      {children}
    </Command.Group>
  );
}

export function CommandItem({
  value,
  icon: Icon,
  title,
  description,
  hotkey,
  trailing,
  onSelect,
  disabled,
}: {
  value: string;
  icon?: ComponentType<LucideProps>;
  title: ReactNode;
  description?: ReactNode;
  /** Visual hotkey hint, e.g. "G C". */
  hotkey?: string;
  trailing?: ReactNode;
  onSelect: () => void;
  disabled?: boolean;
}) {
  return (
    <Command.Item
      value={value}
      onSelect={onSelect}
      disabled={disabled}
      className="flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm text-foreground data-[disabled=true]:opacity-50 data-[selected=true]:bg-accent"
    >
      {Icon ? (
        <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
      ) : null}
      <span className="min-w-0 flex-1">
        <span className="block truncate">{title}</span>
        {description ? (
          <span className="block truncate text-meta text-muted-foreground">
            {description}
          </span>
        ) : null}
      </span>
      {trailing}
      {hotkey ? (
        <span className="flex shrink-0 items-center gap-1">
          {hotkey.split(" ").map((key, index) => (
            <Kbd key={`${key}-${index}`}>{key}</Kbd>
          ))}
        </span>
      ) : null}
    </Command.Item>
  );
}

export const CommandSeparator = Command.Separator;
