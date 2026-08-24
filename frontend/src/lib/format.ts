/**
 * Small formatters used across the elite UX surface.
 * Kept dependency-light: only `date-fns` (already in bundle).
 */
import { formatDistanceToNowStrict } from "date-fns";

const DAY_MS = 86_400_000;

export function fmtNum(n: number | undefined | null): string {
  if (n == null || Number.isNaN(n)) return "—";
  return n.toLocaleString();
}

export function fmtBytes(b: number | undefined | null): string {
  if (!b || b < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = b;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtAge(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return formatDistanceToNowStrict(new Date(iso), { addSuffix: false });
  } catch {
    return "—";
  }
}

export function fmtRelative(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return formatDistanceToNowStrict(new Date(iso), { addSuffix: true });
  } catch {
    return "—";
  }
}

export function fmtPct(n: number | undefined, digits = 0): string {
  if (n == null || Number.isNaN(n)) return "—";
  return `${(n * 100).toFixed(digits)}%`;
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

export function dateInputDaysFromNow(days: number): string {
  return new Date(Date.now() + days * DAY_MS).toISOString().slice(0, 10);
}

export function dateInputEndOfDayWithinDays(value: string, maxDays: number): string {
  const selected = new Date(`${value}T23:59:59Z`).getTime();
  const max = Date.now() + maxDays * DAY_MS;
  return new Date(Number.isFinite(selected) ? Math.min(selected, max) : max).toISOString();
}

export function truncate(s: string | undefined, n = 60): string {
  if (!s) return "";
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}
