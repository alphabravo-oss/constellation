import { type ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * Collapse — progressive-disclosure disclosure (pattern P2). A styled native
 * <details> so expert/secondary fields (e.g. an "Advanced" section, a per-row
 * detail) are hidden by default and revealed on demand, with no JS state to manage.
 */
export function Collapse({
  label,
  children,
  defaultOpen = false,
  className,
}: {
  label: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
  className?: string;
}) {
  return (
    <details open={defaultOpen} className={cn("group/collapse", className)}>
      <summary className="flex cursor-pointer list-none items-center gap-1.5 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground">
        <ChevronRight className="h-3.5 w-3.5 transition-transform group-open/collapse:rotate-90" />
        {label}
      </summary>
      <div className="pt-2">{children}</div>
    </details>
  );
}
