import { X } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * FilterChip — small removable filter chip used in QueryInput hint rail.
 * Bordered, hover-elevates, X icon to remove.
 */
export function FilterChip({
  label,
  value,
  onRemove,
  onClick,
  active,
  className,
}: {
  label: string;
  value?: string;
  onRemove?: () => void;
  onClick?: () => void;
  active?: boolean;
  className?: string;
}) {
  const interactive = onClick || onRemove;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 h-6 px-2 rounded text-[11px] text-mono whitespace-nowrap border transition-colors duration-100",
        active
          ? "bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] border-[color-mix(in_oklab,var(--color-primary)_36%,transparent)] text-[color:var(--color-primary)]"
          : "bg-card border-border text-foreground hover:bg-accent",
        interactive && "cursor-pointer",
        className,
      )}
      onClick={onClick}
      role={onClick ? "button" : undefined}
    >
      <span className="text-muted-foreground">{label}{value != null && ":"}</span>
      {value != null && <span className="font-medium">{value}</span>}
      {onRemove && (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); onRemove(); }}
          className="-mr-0.5 ml-0.5 rounded hover:bg-muted p-0.5"
          aria-label={`Remove ${label} filter`}
        >
          <X className="h-2.5 w-2.5" />
        </button>
      )}
    </span>
  );
}
