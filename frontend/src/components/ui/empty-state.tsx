import { type ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * EmptyState — never leave a panel bare. Always provide a CTA or hint.
 */
export function EmptyState({
  title,
  hint,
  action,
  icon,
  className,
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-10 text-center", className)}>
      {icon && <div className="mb-3 text-muted-foreground/60">{icon}</div>}
      <div className="text-sm font-medium text-foreground">{title}</div>
      {hint && <p className="mt-1 max-w-sm text-xs text-muted-foreground">{hint}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}
