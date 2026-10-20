// Shared data-page states on the kit: skeletons for first load (never a
// spinner), errors with retry + the request correlation id, empty states with
// the one action that fixes them.
import { type ReactNode } from "react";
import { AlertCircle } from "lucide-react";
import { cn } from "@/lib/cn";
import { LoadingState as KitLoadingState, StatePanel } from "@/ui";
import { apiErrorMessage, apiRequestId } from "@/lib/api-error";

export { EmptyState } from "./empty-state";

export function LoadingState({
  label = "Loading",
  variant,
  className,
}: {
  label?: string;
  /** Skeleton shape; defaults to a table body for inventories. */
  variant?: "panel" | "table" | "cards";
  className?: string;
}) {
  return (
    <div data-testid="loading-state" className={className}>
      <KitLoadingState title={label} variant={variant ?? "table"} rows={5} />
    </div>
  );
}

/** Correlation id from an API error (`error.request_id` or X-Request-ID). */
export const correlationIdOf = apiRequestId;

export function ErrorState({
  title = "Could not load this data",
  error,
  action,
  onRetry,
  correlationId: correlationIdProp,
  className,
}: {
  title?: string;
  /** Request failure: its server message is shown and its request id becomes the reference. */
  error?: unknown;
  /** Show only the reference (no message), e.g. when server text must stay private. */
  correlationId?: string | null;
  action?: ReactNode;
  onRetry?: () => void;
  className?: string;
}) {
  const message = error === undefined ? undefined : apiErrorMessage(error) ?? (error instanceof Error ? error.message : typeof error === "string" ? error : undefined);
  const correlationId = correlationIdProp ?? correlationIdOf(error);
  return (
    <div data-testid="error-state" className={className}>
      <StatePanel
        icon={AlertCircle}
        tone="danger"
        role="alert"
        title={title}
        description={message}
        className="py-10"
        action={onRetry && !action ? { label: "Retry", onClick: onRetry, intent: "default" } : undefined}
        secondary={
          <>
            {action ? <div className={cn("flex flex-wrap items-center justify-center gap-2")}>{action}</div> : null}
            {correlationId ? (
              <p className="text-micro text-muted-foreground">
                Reference <code className="font-mono text-foreground">{correlationId}</code>
              </p>
            ) : null}
          </>
        }
      />
    </div>
  );
}
