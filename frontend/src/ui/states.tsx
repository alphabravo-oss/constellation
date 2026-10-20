import type { ComponentType, ReactNode } from "react";
import { AlertCircle, Compass, Lock, type LucideProps } from "lucide-react";
import { cn } from "./cn";
import { useProduct } from "./product";
import { Button, Skeleton, SkeletonText } from "./primitives";

type Tone = "neutral" | "danger" | "warning" | "info";

const toneClass: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground",
  danger: "bg-status-error/10 text-status-error",
  warning: "bg-status-warning/10 text-status-warning",
  info: "bg-status-info/10 text-status-info",
};

export interface StateAction {
  label: string;
  to?: string;
  onClick?: () => void;
  icon?: ReactNode;
  intent?: "primary" | "default";
}

function StateActionButton({ action }: { action: StateAction }) {
  const { Link } = useProduct();
  if (action.to) {
    return (
      <Link
        to={action.to}
        className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-border px-4 text-sm font-medium transition-colors hover:bg-accent focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
      >
        {action.icon}
        {action.label}
      </Link>
    );
  }
  return (
    <Button
      intent={action.intent ?? "primary"}
      onClick={action.onClick}
      icon={action.icon}
    >
      {action.label}
    </Button>
  );
}

/** Shared frame for empty/error/forbidden panels. */
export function StatePanel({
  icon: Icon,
  title,
  description,
  tone = "neutral",
  action,
  secondary,
  role,
  className,
  children,
}: {
  icon?: ComponentType<LucideProps>;
  title: string;
  description?: ReactNode;
  tone?: Tone;
  action?: StateAction;
  secondary?: ReactNode;
  role?: string;
  className?: string;
  children?: ReactNode;
}) {
  return (
    <div
      role={role}
      className={cn(
        "flex min-w-0 flex-col items-center justify-center space-y-3 py-16 text-center",
        className,
      )}
    >
      {Icon ? (
        <div
          className={cn(
            "flex h-12 w-12 items-center justify-center rounded-lg",
            toneClass[tone],
          )}
        >
          <Icon className="h-6 w-6" aria-hidden="true" />
        </div>
      ) : null}
      <div className="w-full min-w-0 space-y-1 px-4">
        <p className="break-words text-base font-medium text-foreground">
          {title}
        </p>
        {description ? (
          <p className="mx-auto max-w-md break-words text-sm text-muted-foreground">
            {description}
          </p>
        ) : null}
      </div>
      {children}
      {action ? <StateActionButton action={action} /> : null}
      {secondary}
    </div>
  );
}

/** Empty state with the one action that fixes it. */
export function EmptyState(props: {
  icon: ComponentType<LucideProps>;
  title: string;
  description?: ReactNode;
  action?: StateAction;
  compact?: boolean;
  className?: string;
}) {
  return (
    <StatePanel
      icon={props.icon}
      title={props.title}
      description={props.description}
      action={props.action}
      className={cn(props.compact && "py-8", props.className)}
    />
  );
}

/** First-load skeleton (never a spinner); announces to assistive tech. */
export function LoadingState({
  title = "Loading",
  variant = "panel",
  rows = 6,
  className,
}: {
  title?: string;
  variant?: "panel" | "table" | "cards";
  rows?: number;
  className?: string;
}) {
  return (
    <div role="status" aria-busy="true" className={cn("w-full", className)}>
      <span className="sr-only">{title}</span>
      {variant === "table" ? (
        <div className="overflow-hidden rounded-lg border border-border">
          <div className="h-10 bg-muted/60" />
          {Array.from({ length: rows }, (_, i) => (
            <div
              key={i}
              className="flex h-(--row-h) items-center gap-6 border-t border-border px-4"
            >
              <Skeleton className="h-3 w-1/3" />
              <Skeleton className="h-3 w-16" />
              <Skeleton className="h-3 w-24" />
              <Skeleton className="ml-auto h-3 w-12" />
            </div>
          ))}
        </div>
      ) : variant === "cards" ? (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i} className="rounded-lg border border-border bg-card p-4">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="mt-3 h-7 w-16" />
            </div>
          ))}
        </div>
      ) : (
        <div className="mx-auto flex w-full max-w-md flex-col items-center space-y-3 py-16">
          <Skeleton className="h-12 w-12 rounded-lg" />
          <Skeleton className="h-4 w-40" />
          <SkeletonText lines={2} className="w-full max-w-xs" />
        </div>
      )}
    </div>
  );
}

/** Error with retry and the request correlation id for support. */
export function ErrorState({
  title = "Something went wrong",
  description,
  correlationId,
  onRetry,
  retryLabel = "Retry",
  className,
}: {
  title?: string;
  description?: ReactNode;
  correlationId?: string | null;
  onRetry?: () => void;
  retryLabel?: string;
  className?: string;
}) {
  return (
    <StatePanel
      icon={AlertCircle}
      tone="danger"
      title={title}
      description={description}
      role="alert"
      action={onRetry ? { label: retryLabel, onClick: onRetry } : undefined}
      secondary={
        correlationId ? (
          <p className="text-micro text-muted-foreground">
            Reference{" "}
            <code className="font-mono text-foreground">{correlationId}</code>
          </p>
        ) : undefined
      }
      className={className}
    />
  );
}

/** 404 rendered inside the shell. */
export function NotFoundState({
  homeTo,
  homeLabel = "Back to overview",
  description = "This page does not exist. It may have moved or been removed.",
}: {
  homeTo: string;
  homeLabel?: string;
  description?: ReactNode;
}) {
  return (
    <div data-testid="route-not-found">
      <StatePanel
        icon={Compass}
        tone="info"
        title="Page not found"
        description={description}
        action={{ label: homeLabel, to: homeTo }}
      />
    </div>
  );
}

/** 403 rendered inside the shell. */
export function ForbiddenState({
  permission,
  description,
  homeTo,
}: {
  permission?: string;
  description?: ReactNode;
  homeTo?: string;
}) {
  return (
    <div data-testid="route-forbidden">
      <StatePanel
        icon={Lock}
        tone="warning"
        title="You do not have access"
        description={
          description ??
          (permission ? (
            <>
              This page needs{" "}
              <code className="font-mono text-foreground">{permission}</code>.
              Ask an administrator for access.
            </>
          ) : (
            "Ask an administrator for access to this page."
          ))
        }
        action={homeTo ? { label: "Back to overview", to: homeTo } : undefined}
      />
    </div>
  );
}
