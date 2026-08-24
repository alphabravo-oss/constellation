import type { TimelineSource } from "@/api/client";

export const TIMELINE_ALL_SOURCES: TimelineSource[] = ["dpi_threat", "runtime_event", "network_violation", "audit"];

export interface TimelineFilterPayload {
  category: string;
  sources: TimelineSource[];
  severities: string[];
  query: string;
  namespace: string;
  workload: string;
  reference: string;
  from: string;
  to: string;
}

export function compactTimelineFilters(payload: TimelineFilterPayload) {
  return {
    category: payload.category,
    sources: uniqueOrderedSources(payload.sources),
    severities: uniqueOrderedStrings(payload.severities),
    query: payload.query.trim(),
    namespace: payload.namespace.trim(),
    workload: payload.workload.trim(),
    reference: payload.reference.trim(),
    from: payload.from.trim(),
    to: payload.to.trim(),
  };
}

export function timelineSourceParam(sources: TimelineSource[]) {
  const ordered = uniqueOrderedSources(sources);
  if (ordered.length === 0 || ordered.length === TIMELINE_ALL_SOURCES.length) return undefined;
  return ordered.join(",");
}

export function timelineSeverityParam(severities: string[]) {
  const ordered = uniqueOrderedStrings(severities);
  return ordered.length === 0 ? undefined : ordered.join(",");
}

export function timelineDateParam(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const parsed = new Date(trimmed);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return parsed.toISOString();
}

export function timelineTextParam(value: string) {
  const trimmed = value.trim();
  return trimmed || undefined;
}

export function uniqueOrderedSources(values: TimelineSource[]) {
  const wanted = new Set(values);
  return TIMELINE_ALL_SOURCES.filter((source) => wanted.has(source));
}

export function uniqueOrderedStrings(values: string[]) {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of values) {
    const value = raw.trim().toLowerCase();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

export function timelineSavedViewSummary(payload: TimelineFilterPayload) {
  const filters = compactTimelineFilters(payload);
  return [
    filters.category !== "custom" ? filters.category : undefined,
    filters.sources.length !== TIMELINE_ALL_SOURCES.length ? `${filters.sources.length} sources` : undefined,
    filters.severities.length ? filters.severities.join("/") : undefined,
    filters.query || undefined,
    filters.namespace ? `ns:${filters.namespace}` : undefined,
    filters.workload ? `workload:${filters.workload}` : undefined,
    filters.reference ? `ref:${filters.reference}` : undefined,
  ].filter(Boolean).join(" · ") || "all events";
}
