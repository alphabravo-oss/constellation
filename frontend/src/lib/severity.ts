import type { Severity } from "@/api/client";

/**
 * Background+text utility classes for a severity badge / chip.
 * Uses OKLCH-based tokens defined in index.css; bg is a translucent wash, text
 * is the saturated value — ensures AA contrast against the dark surface.
 */
export const severityBg: Record<Severity, string> = {
  info:     "bg-[color-mix(in_oklab,var(--color-severity-info)_18%,transparent)] text-[color:var(--color-severity-info)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-severity-info)_36%,transparent)]",
  low:      "bg-[color-mix(in_oklab,var(--color-severity-low)_18%,transparent)] text-[color:var(--color-severity-low)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-severity-low)_36%,transparent)]",
  medium:   "bg-[color-mix(in_oklab,var(--color-severity-medium)_18%,transparent)] text-[color:var(--color-severity-medium)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-severity-medium)_36%,transparent)]",
  high:     "bg-[color-mix(in_oklab,var(--color-severity-high)_18%,transparent)] text-[color:var(--color-severity-high)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-severity-high)_36%,transparent)]",
  critical: "bg-[color-mix(in_oklab,var(--color-severity-critical)_22%,transparent)] text-[color:var(--color-severity-critical)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-severity-critical)_48%,transparent)]",
};

export function severityOrder(sev: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(sev);
}

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

export function severityVar(sev: Severity): string {
  return `var(--color-severity-${sev})`;
}

export function riskTier(score: number): { label: string; color: string } {
  if (score >= 80) return { label: "critical", color: "var(--color-severity-critical)" };
  if (score >= 60) return { label: "high",     color: "var(--color-severity-high)" };
  if (score >= 40) return { label: "medium",   color: "var(--color-severity-medium)" };
  if (score >= 20) return { label: "low",      color: "var(--color-severity-low)" };
  return { label: "info", color: "var(--color-severity-info)" };
}
