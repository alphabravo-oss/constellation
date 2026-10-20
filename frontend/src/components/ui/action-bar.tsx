import { type ReactNode } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * ActionBar — sticky bottom bar that appears when items are bulk-selected.
 * Mirrors the StackRox / Linear bulk-action pattern.
 */
export function ActionBar({
  count,
  onClear,
  children,
  className,
}: {
  count: number;
  onClear?: () => void;
  children: ReactNode;
  className?: string;
}) {
  if (count <= 0) return null;
  return (
    <div
      className={cn(
        "fixed bottom-6 left-1/2 -translate-x-1/2 z-chrome",
        "flex items-center gap-2 rounded-md border border-border bg-card/95 backdrop-blur px-3 py-2 shadow-[var(--elev-3)]",
        className,
      )}
      role="region"
      aria-label={`Bulk actions, ${count} selected`}
    >
      <span className="rounded-full bg-muted px-2 py-0.5 font-mono text-meta font-medium text-foreground">
        {count} selected
      </span>
      <span className="h-4 w-px bg-border" aria-hidden />
      <div className="flex items-center gap-1">{children}</div>
      {onClear && (
        <>
          <span className="h-4 w-px bg-border" aria-hidden />
          <button
            type="button"
            onClick={onClear}
            className="rounded p-1.5 text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            aria-label="Clear selection"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </>
      )}
    </div>
  );
}
