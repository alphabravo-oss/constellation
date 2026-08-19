import { type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * Drawer — right-side slide-in panel.
 *
 * Wraps Radix Dialog and constrains placement to the right edge with a
 * configurable width. Keeps page state behind it so analysts don't lose
 * context when inspecting an entity (StackRox / NeuVector pattern).
 */
export function Drawer({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  width = "lg",
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title?: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: "md" | "lg" | "xl";
  className?: string;
}) {
  const w = width === "xl" ? "max-w-[720px]" : width === "lg" ? "max-w-[560px]" : "max-w-[440px]";
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-background/40 backdrop-blur-[2px]" />
        <Dialog.Content
          className={cn(
            "fixed right-0 top-0 z-50 h-full w-full bg-card border-l border-border shadow-[var(--elev-3)] flex flex-col",
            w,
            className,
          )}
        >
          {(title || description) && (
            <header className="flex items-start justify-between gap-2 border-b border-border px-5 py-4">
              <div className="min-w-0 flex-1">
                {title && (
                  <Dialog.Title className="text-display text-base font-semibold tracking-tight">
                    {title}
                  </Dialog.Title>
                )}
                {description && (
                  <Dialog.Description className="mt-0.5 text-xs text-muted-foreground">
                    {description}
                  </Dialog.Description>
                )}
              </div>
              <Dialog.Close
                aria-label="Close drawer"
                className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
              >
                <X className="h-4 w-4" />
              </Dialog.Close>
            </header>
          )}
          <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
          {footer && <footer className="border-t border-border px-5 py-3">{footer}</footer>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
