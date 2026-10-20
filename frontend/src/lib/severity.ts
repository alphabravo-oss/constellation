import type { Severity } from "@/api/client";

/**
 * Background+text utility classes for a severity badge / chip.
 * Kit severity ramp (HSL light/dark pairs): a quiet wash with the severity
 * text color, AA on both themes.
 */
export const severityBg: Record<Severity, string> = {
  info:     "border border-severity-info/45 text-severity-info",
  low:      "border border-severity-low/45 text-severity-low",
  medium:   "border border-severity-medium/45 text-severity-medium",
  high:     "border border-severity-high/45 text-severity-high",
  critical: "border border-severity-critical/45 text-severity-critical",
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
