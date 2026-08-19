// Shared data-page states (C3).
//
// Three components every `useQuery` data page should render so loading / empty /
// error look identical across the product instead of bespoke per-page spinners:
//
//   <LoadingState />  — query is pending
//   <ErrorState  />   — query failed (pass the error)
//   <EmptyState  />   — query succeeded but returned nothing (re-exported here)
//
// Keep these dumb and presentational. EmptyState already lived in empty-state.tsx;
// it is re-exported so pages can import all three from one module.
import { type ReactNode } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";

export { EmptyState } from "./empty-state";

/** Centered spinner + label for a pending query. */
export function LoadingState({
  label = "Loading…",
  className,
}: {
  label?: string;
  className?: string;
}) {
  return (
    <div
      className={cn("flex flex-col items-center justify-center px-6 py-10 text-center", className)}
      role="status"
      aria-busy="true"
      data-testid="loading-state"
    >
      <Loader2 className="mb-2 h-4 w-4 animate-spin text-muted-foreground/70" aria-hidden />
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}

/** Centered error panel for a failed query, with an optional retry action. */
export function ErrorState({
  title = "Failed to load",
  error,
  action,
  className,
}: {
  title?: string;
  error?: unknown;
  action?: ReactNode;
  className?: string;
}) {
  const message =
    error instanceof Error ? error.message : typeof error === "string" ? error : undefined;
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center px-6 py-10 text-center",
        className,
      )}
      role="alert"
      data-testid="error-state"
    >
      <AlertTriangle className="mb-2 h-4 w-4 text-[color:var(--color-status-error)]" aria-hidden />
      <div className="text-sm font-medium text-foreground">{title}</div>
      {message && <p className="mt-1 max-w-sm text-xs text-muted-foreground">{message}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}
