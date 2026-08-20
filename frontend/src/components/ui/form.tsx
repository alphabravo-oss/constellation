import { type ReactNode, type ComponentProps } from "react";
import { cn } from "@/lib/cn";

/**
 * Form primitives — one consistent, enterprise-grade control set so every input
 * across the app looks and behaves identically. Elite = predictable + quiet.
 */

const controlBase =
  "flex h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground shadow-[0_1px_1px_0_rgb(0_0_0/0.03)] transition-colors placeholder:text-muted-foreground/70 focus-visible:outline-none focus-visible:border-[color:var(--color-brand)] focus-visible:ring-2 focus-visible:ring-[color:color-mix(in_oklab,var(--color-brand)_25%,transparent)] disabled:cursor-not-allowed disabled:opacity-50";

export function TextInput({ className, ...props }: ComponentProps<"input">) {
  return <input className={cn(controlBase, className)} {...props} />;
}

export function Select({ className, children, ...props }: ComponentProps<"select">) {
  return (
    <select className={cn(controlBase, "cursor-pointer pr-8", className)} {...props}>
      {children}
    </select>
  );
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return (
    <textarea
      className={cn(controlBase, "h-auto min-h-[80px] py-2 leading-relaxed", className)}
      {...props}
    />
  );
}

/**
 * Field — label + control + hint/error, with the label wired to the control.
 * Wrap any TextInput/Select/Textarea (or a custom control) as children.
 */
export function Field({
  label,
  hint,
  error,
  required,
  htmlFor,
  children,
  className,
}: {
  label?: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  htmlFor?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("space-y-1.5", className)}>
      {label && (
        <label htmlFor={htmlFor} className="block text-xs font-medium text-foreground">
          {label}
          {required && <span className="ml-0.5 text-destructive">*</span>}
        </label>
      )}
      {children}
      {error ? (
        <p className="text-xs text-destructive">{error}</p>
      ) : hint ? (
        <p className="text-xs leading-relaxed text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  );
}

/**
 * Switch — an accessible toggle. The elite alternative to a bare checkbox for
 * on/off settings. Optionally renders a label + description block beside it.
 */
export function Switch({
  checked,
  onCheckedChange,
  disabled,
  label,
  description,
  className,
}: {
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  disabled?: boolean;
  label?: ReactNode;
  description?: ReactNode;
  className?: string;
}) {
  const toggle = (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:color-mix(in_oklab,var(--color-brand)_30%,transparent)] disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "bg-[color:var(--color-brand)]" : "bg-muted",
        className,
      )}
    >
      <span
        className={cn(
          "inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform",
          checked ? "translate-x-4" : "translate-x-0.5",
        )}
      />
    </button>
  );
  if (!label && !description) return toggle;
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="min-w-0">
        {label && <div className="text-sm font-medium text-foreground">{label}</div>}
        {description && <div className="text-xs leading-relaxed text-muted-foreground">{description}</div>}
      </div>
      {toggle}
    </div>
  );
}
