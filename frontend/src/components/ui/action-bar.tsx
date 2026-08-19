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
        "fixed bottom-6 left-1/2 -translate-x-1/2 z-30",
        "flex items-center gap-2 rounded-md border border-border bg-card/95 backdrop-blur px-3 py-2 shadow-[var(--elev-3)]",
        className,
      )}
      role="region"
      aria-label={`Bulk actions, ${count} selected`}
    >
      <span className="rounded bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] px-2 py-0.5 text-[11px] text-mono font-medium text-[color:var(--color-primary)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-primary)_36%,transparent)]">
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
