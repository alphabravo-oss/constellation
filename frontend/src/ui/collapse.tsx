import { useId, useState, type ReactNode } from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "./cn";

/**
 * Disclosure for secondary content ("Advanced", "Details"). Closed by
 * default so forms and pages lead with what matters.
 */
export function Collapse({
  title = "Advanced",
  description,
  defaultOpen = false,
  children,
  className,
}: {
  title?: ReactNode;
  description?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
  className?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return (
    <div className={cn("rounded-lg border border-border", className)}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
      >
        <span className="min-w-0">
          <span className="block text-sm font-medium text-foreground">
            {title}
          </span>
          {description ? (
            <span className="mt-0.5 block text-meta text-muted-foreground">
              {description}
            </span>
          ) : null}
        </span>
        <ChevronDown
          aria-hidden
          className={cn(
            "h-4 w-4 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-180",
          )}
        />
      </button>
      {open ? (
        <div id={id} className="border-t border-border px-4 py-4">
          {children}
        </div>
      ) : null}
    </div>
  );
}
