import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import type { RuntimeEvent, RuntimeEventsParams, RuntimeEventsResponse } from "@/api/client";
import { sameTimelineBoundary, timelineAfterParam } from "@/lib/timeline-filters";

export const EVENT_SORTS = ["at", "workload", "kind", "source", "severity", "verdict", "namespace", "node"];
export const EVENT_VERDICTS = ["observed", "alert", "block", "quarantine"];
export const EVENT_SEVERITIES = ["info", "low", "medium", "high", "critical"];
export const eventCSVFilter = (value: string) => value.split(",").map(item => item.trim()).filter(Boolean).sort().join(",");

function boundaryNanos(value: string) {
  const remainder = (value.match(/\.(\d{1,9})(?:Z|[+-])/i)?.[1] || "").padEnd(9, "0").slice(3);
  return BigInt(new Date(value).getTime()) * 1000000n + BigInt(remainder || "0");
}

export function runtimeEventFiltersValid(params: URLSearchParams) {
  const page = params.get("page");
  const after = params.get("after")?.trim() || "", before = params.get("before")?.trim() || "";
  return EVENT_SORTS.includes(params.get("sort") || "at") && ["asc", "desc"].includes(params.get("order") || "desc")
    && (!params.get("severity") || EVENT_SEVERITIES.includes(params.get("severity")!))
    && eventCSVFilter(params.get("verdict") || "").split(",").every(value => !value || EVENT_VERDICTS.includes(value))
    && (!page || /^\d+$/.test(page) && Number.isSafeInteger(Number(page)) && Number(page) >= 1 && Number(page) <= INVENTORY_MAX_PAGE)
    && (!after || !!timelineAfterParam(after)) && (!before || !!timelineAfterParam(before))
    && (!after || !before || boundaryNanos(after) < boundaryNanos(before));
}

function record(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function rowValid(value: unknown): value is RuntimeEvent {
  if (!record(value) || !["row_id", "id", "cluster_id", "at", "kind", "source", "severity", "verdict", "node_id", "workload_id"].every(key => typeof value[key] === "string") || !value.row_id || !value.id || !timelineAfterParam(value.at as string)) return false;
  if (!(value.row_id as string).startsWith((value.id as string) + "@") || !sameTimelineBoundary((value.row_id as string).slice((value.id as string).length + 1), value.at as string)) return false;
  return ["namespace", "container_id", "platform_role"].every(key => value[key] === undefined || typeof value[key] === "string") && Array.isArray(value.attack_techniques) && value.attack_techniques.every(item => typeof item === "string") && record(value.payload);
}
export function runtimeEventsResponseValid(data: RuntimeEventsResponse | undefined, request: RuntimeEventsParams) {
  if (!record(data) || !record(data.summary) || !Array.isArray(data.events) || !data.events.every(rowValid)) return false;
  const total = data.total, summary = data.summary;
  if (!Number.isSafeInteger(total) || total! < 0 || summary.total !== total || !(["total", "alerting", "blocks", "quarantines", "affected_workloads", "observed"] as const).every(key => Number.isSafeInteger(summary[key]) && (summary[key] as number) >= 0 && (summary[key] as number) <= total!)) return false;
  if (summary.blocks + summary.quarantines > summary.alerting || summary.alerting + summary.observed > total!) return false;
  if (data.cluster_id !== request.cluster_id || data.limit !== request.limit || data.offset !== request.offset || data.sort !== request.sort || data.order !== request.order) return false;
  if (!["q", "workload", "kind", "source", "severity", "verdict", "namespace", "node"].every(key => (data[key as keyof RuntimeEventsResponse] ?? "") === (request[key as keyof RuntimeEventsParams] ?? ""))) return false;
  for (const key of ["after", "before"] as const) { if (data[key] !== undefined && typeof data[key] !== "string") return false; if (request[key] ? !data[key] || !sameTimelineBoundary(data[key]!, request[key]!) : !!data[key]) return false; }
  const rows = data.events;
  return rows.length === Math.min(request.limit!, Math.max(0, total! - request.offset!)) && data.has_more === (total! > request.offset! + rows.length)
    && new Set(rows.map(row => row.row_id)).size === rows.length && rows.every(row => row.cluster_id === request.cluster_id && (!request.namespace || row.namespace === request.namespace) && (!request.node || row.node_id === request.node) && (!request.verdict || request.verdict.split(",").includes(row.verdict)) && (!request.kind || request.kind.split(",").includes(row.kind)) && (!request.source || request.source.split(",").includes(row.source)) && (!request.workload || row.workload_id.toLowerCase().includes(request.workload.toLowerCase())) && (!request.severity || Math.max(0, EVENT_SEVERITIES.indexOf(row.severity)) >= EVENT_SEVERITIES.indexOf(request.severity)) && (!request.after || boundaryNanos(row.at) >= boundaryNanos(request.after)) && (!request.before || boundaryNanos(row.at) < boundaryNanos(request.before)));
}
