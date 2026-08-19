import { cn } from "@/lib/cn";
import { tokenize } from "@/lib/kbd";

/**
 * Keyboard chip — renders one or more keycaps for a combo.
 * Usage: <Kbd combo="Mod+k" /> or <Kbd combo="g d" />
 */
export function Kbd({ combo, className }: { combo: string; className?: string }) {
  const tokens = tokenize(combo);
  return (
    <span className={cn("inline-flex items-center gap-1", className)} aria-label={`keyboard shortcut ${combo}`}>
      {tokens.map((t, i) => (
        <kbd
          key={i}
          className="inline-flex h-5 min-w-[20px] items-center justify-center rounded border border-border bg-muted px-1.5 text-[10px] font-medium text-muted-foreground text-mono"
        >
          {t}
        </kbd>
      ))}
    </span>
  );
}
