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
        "inline-flex h-7 items-center gap-1 whitespace-nowrap rounded-full border pl-2.5 pr-2 text-meta transition-colors duration-100",
        active
          ? "border-foreground/40 bg-accent text-foreground"
          : "border-border bg-muted/40 text-foreground hover:bg-accent",
        interactive && "cursor-pointer",
        className,
      )}
      onClick={onClick}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      aria-pressed={onClick ? active : undefined}
      onKeyDown={onClick ? (event) => { if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); onClick(); } } : undefined}
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
          <X className="h-3 w-3" />
        </button>
      )}
    </span>
  );
}
