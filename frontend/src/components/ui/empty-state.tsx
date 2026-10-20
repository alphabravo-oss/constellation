import { isValidElement, type ReactNode } from "react";
import { Inbox } from "lucide-react";
import { cn } from "@/lib/cn";

/** Empty state: icon tile, one line, an optional hint, and the action that fixes it. */
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
    <div className={cn("flex min-w-0 flex-col items-center justify-center space-y-3 px-6 py-10 text-center", className)} data-testid="empty-state">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted text-muted-foreground [&_svg]:h-5 [&_svg]:w-5">
        {isValidElement(icon) ? icon : <Inbox aria-hidden />}
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {hint ? <p className="mx-auto max-w-md text-meta text-muted-foreground">{hint}</p> : null}
      </div>
      {action ? <div className="flex flex-wrap items-center justify-center gap-2">{action}</div> : null}
    </div>
  );
}
