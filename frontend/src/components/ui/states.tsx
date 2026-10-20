// Shared data-page states on the kit: skeletons for first load (never a
// spinner), errors with retry + the request correlation id, empty states with
// the one action that fixes them.
import { type ReactNode } from "react";
import { AlertCircle } from "lucide-react";
import { cn } from "@/lib/cn";
import { LoadingState as KitLoadingState, StatePanel } from "@/ui";

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

/** Correlation id from an API error (X-Request-ID echoed by the server). */
export function correlationIdOf(error: unknown): string | null {
  const candidate = error as { response?: { headers?: Record<string, unknown>; data?: { request_id?: unknown } }; requestId?: unknown } | null;
  const headers = candidate?.response?.headers;
  const header = headers?.["x-request-id"] ?? headers?.["X-Request-ID"];
  if (typeof header === "string" && header) return header;
  const body = candidate?.response?.data?.request_id;
  if (typeof body === "string" && body) return body;
  if (typeof candidate?.requestId === "string") return candidate.requestId;
  return null;
}

export function ErrorState({
  title = "Could not load this data",
  error,
  action,
  onRetry,
  className,
}: {
  title?: string;
  error?: unknown;
  action?: ReactNode;
  onRetry?: () => void;
  className?: string;
}) {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : undefined;
  const correlationId = correlationIdOf(error);
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
