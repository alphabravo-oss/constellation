import { cn } from "@/lib/cn";

type Tone = "neutral" | "success" | "warning" | "error" | "info" | "pending" | "accent";

const DOT: Record<Tone, string> = {
  neutral: "bg-status-neutral",
  success: "bg-status-success",
  warning: "bg-status-warning",
  error: "bg-status-error",
  info: "bg-status-info",
  pending: "bg-status-pending",
  accent: "bg-brand",
};

/** Sentence-case a lifecycle/state value: "in_progress" → "In progress". */
export function sentenceValue(value: string): string {
  const words = value.replace(/[_-]+/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : words;
}

/**
 * Status pill: dot + sentence-case label on a neutral chip. Status color is on
 * the dot only (never color alone).
 */
export function StatusPill({
  label,
  tone = "neutral",
  className,
  dot = true,
}: {
  label: string;
  tone?: Tone;
  className?: string;
  dot?: boolean;
  /** @deprecated values are always sentence case now. */
  uppercase?: boolean;
}) {
  return (
    <span className={cn("inline-flex h-5 shrink-0 items-center gap-1.5 rounded-full border border-border bg-muted/40 px-2 text-micro font-medium leading-none text-foreground", className)}>
      {dot && <span aria-hidden className={cn("h-1.5 w-1.5 rounded-full", DOT[tone])} />}
      {sentenceValue(label)}
    </span>
  );
}

export function ModePill({ mode }: { mode: "learn" | "monitor" | "enforce" | "discover" | "protect" }) {
  const tone: Tone =
    mode === "learn" || mode === "discover" ? "info" :
    mode === "monitor" ? "warning" :
    mode === "enforce" || mode === "protect" ? "success" : "info";
  return <StatusPill label={mode} tone={tone} />;
}

export function LifecycleBadge({ lifecycle }: { lifecycle: string }) {
  const tone: Tone =
    lifecycle === "resolved" ? "success" :
    lifecycle === "suppressed" ? "neutral" :
    lifecycle === "accepted" ? "pending" :
    lifecycle === "triaged" || lifecycle === "in_progress" ? "info" :
    lifecycle === "open" ? "warning" : "neutral";
  return <StatusPill label={lifecycle} tone={tone} />;
}
