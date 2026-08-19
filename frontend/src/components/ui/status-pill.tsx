import { cn } from "@/lib/cn";

/**
 * Generic status pill — used for lifecycle, mode (learn/monitor/enforce),
 * and arbitrary "state" badges. Visual is a small dot + label.
 */
export function StatusPill({
  label,
  tone = "neutral",
  className,
  dot = true,
  uppercase = true,
}: {
  label: string;
  tone?: "neutral" | "success" | "warning" | "error" | "info" | "pending" | "accent";
  className?: string;
  dot?: boolean;
  uppercase?: boolean;
}) {
  const color =
    tone === "success" ? "var(--color-status-success)" :
    tone === "warning" ? "var(--color-status-warning)" :
    tone === "error"   ? "var(--color-status-error)" :
    tone === "info"    ? "var(--color-status-info)" :
    tone === "pending" ? "var(--color-status-pending)" :
    tone === "accent"  ? "var(--color-primary)" :
    "var(--color-muted-foreground)";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded h-5 px-2 text-[10px] font-medium ring-1 ring-inset",
        uppercase && "uppercase tracking-wider",
        className,
      )}
      style={{
        background: `color-mix(in oklab, ${color} 14%, transparent)`,
        color,
        boxShadow: `inset 0 0 0 1px color-mix(in oklab, ${color} 28%, transparent)`,
      }}
    >
      {dot && <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />}
      {label}
    </span>
  );
}

export function ModePill({ mode }: { mode: "learn" | "monitor" | "enforce" | "discover" | "protect" }) {
  const tone: "warning" | "info" | "success" | "accent" =
    mode === "learn" || mode === "discover" ? "info" :
    mode === "monitor" ? "warning" :
    mode === "enforce" || mode === "protect" ? "success" : "info";
  return <StatusPill label={mode} tone={tone} />;
}

export function LifecycleBadge({ lifecycle }: { lifecycle: string }) {
  const tone: "neutral" | "success" | "warning" | "info" | "error" | "pending" =
    lifecycle === "resolved" ? "success" :
    lifecycle === "suppressed" ? "neutral" :
    lifecycle === "accepted" ? "pending" :
    lifecycle === "triaged" || lifecycle === "in_progress" ? "info" :
    lifecycle === "open" ? "warning" : "neutral";
  return <StatusPill label={lifecycle.replace("_", " ")} tone={tone} />;
}
