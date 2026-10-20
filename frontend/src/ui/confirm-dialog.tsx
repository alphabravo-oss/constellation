import { useId, useState, type ReactNode } from "react";
import { Dialog as DialogPrimitive } from "radix-ui";
import { AlertTriangle, X } from "lucide-react";
import { cn } from "./cn";
import { Button } from "./primitives";

export interface ImpactPreview {
  scope: string;
  consequences: readonly string[];
  recovery: string;
}

/**
 * Confirmation dialog. Destructive actions require typing `confirmValue`
 * (the object's name) before the confirm button enables.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  onConfirm,
  title,
  description,
  confirmLabel = "Confirm",
  confirmValue,
  destructive = false,
  loading = false,
  impact,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  /** Typed confirmation; required when `destructive`. */
  confirmValue?: string;
  destructive?: boolean;
  loading?: boolean;
  impact?: ImpactPreview;
  children?: ReactNode;
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      {open ? (
        <ConfirmBody
          key={confirmValue ?? title}
          onClose={() => onOpenChange(false)}
          onConfirm={onConfirm}
          title={title}
          description={description}
          confirmLabel={confirmLabel}
          confirmValue={destructive ? (confirmValue ?? title) : confirmValue}
          destructive={destructive}
          loading={loading}
          impact={impact}
        >
          {children}
        </ConfirmBody>
      ) : null}
    </DialogPrimitive.Root>
  );
}

function ConfirmBody({
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel,
  confirmValue,
  destructive,
  loading,
  impact,
  children,
}: {
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description?: ReactNode;
  confirmLabel: string;
  confirmValue?: string;
  destructive: boolean;
  loading: boolean;
  impact?: ImpactPreview;
  children?: ReactNode;
}) {
  const [typed, setTyped] = useState("");
  const inputId = useId();
  const canConfirm = confirmValue ? typed === confirmValue : true;
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-overlay bg-black/50 backdrop-blur-xs" />
      <DialogPrimitive.Content
        className={cn(
          "fixed left-1/2 top-1/2 z-overlay w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-card p-0 shadow-elev-popover outline-none",
        )}
      >
        <div className="flex items-start gap-3 border-b border-border px-5 py-4">
          {destructive ? (
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-status-error/10">
              <AlertTriangle className="h-5 w-5 text-status-error" />
            </span>
          ) : null}
          <div className="min-w-0 flex-1">
            <DialogPrimitive.Title className="text-base font-semibold text-foreground">
              {title}
            </DialogPrimitive.Title>
            {description ? (
              <DialogPrimitive.Description className="mt-1 text-sm text-muted-foreground">
                {description}
              </DialogPrimitive.Description>
            ) : null}
          </div>
          <DialogPrimitive.Close
            aria-label="Close"
            className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </DialogPrimitive.Close>
        </div>
        <div className="space-y-4 px-5 py-4">
          {impact ? (
            <section
              aria-label="Impact"
              className="rounded-md border border-status-error/20 bg-status-error/5 p-3 text-meta"
            >
              <dl className="space-y-2">
                <div>
                  <dt className="font-medium text-muted-foreground">Scope</dt>
                  <dd className="mt-0.5 break-words font-mono text-foreground">
                    {impact.scope}
                  </dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">
                    What happens
                  </dt>
                  <dd>
                    <ul className="mt-1 list-disc space-y-1 pl-4 text-foreground">
                      {impact.consequences.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Recovery</dt>
                  <dd className="mt-0.5 text-foreground">{impact.recovery}</dd>
                </div>
              </dl>
            </section>
          ) : null}
          {confirmValue ? (
            <div>
              <label
                htmlFor={inputId}
                className="mb-1.5 block text-meta text-muted-foreground"
              >
                Type{" "}
                <span className="font-mono font-medium text-foreground">
                  {confirmValue}
                </span>{" "}
                to confirm
              </label>
              <input
                id={inputId}
                type="text"
                value={typed}
                onChange={(event) => setTyped(event.target.value)}
                placeholder={confirmValue}
                autoComplete="off"
                spellCheck={false}
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-hidden focus:ring-2 focus:ring-ring"
              />
            </div>
          ) : null}
          {children}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <Button intent="ghost" size="sm" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            intent={destructive ? "destructive" : "primary"}
            size="sm"
            onClick={onConfirm}
            disabled={!canConfirm || loading}
            loading={loading}
          >
            {confirmLabel}
          </Button>
        </div>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}
