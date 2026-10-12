import type { FindingKind, Lifecycle, Severity } from "@/api/client";
import type { SavedViewBase } from "@/hooks/useSavedViews";
import { TIMELINE_ALL_SOURCES, compactTimelineFilters, timelineDateParam, timelineAfterParam, TIMELINE_VERDICTS, type TimelineFilterPayload } from "./timeline-filters";

export const FINDING_VIEWS_KEY = "constellation.findings.views.v1";
export const TIMELINE_VIEWS_KEY = "constellation.timeline.views.v1";
export type InventoryViewKind = "findings" | "timeline";
export interface FindingSavedView extends SavedViewBase {
  kind: FindingKind | ""; lifecycle: Lifecycle | ""; query: string;
  groupMode?: string; idScope?: "all"; targetType?: string; severity?: Severity | ""; fixable?: boolean; view?: "instances" | "cve";
  group?: "none" | "severity" | "kind" | "asset"; sort?: string; order?: "asc" | "desc";
}
export interface TimelineSavedView extends SavedViewBase, TimelineFilterPayload {}
const findingKinds = ["", "vulnerability", "iac", "license", "cloud-config", "drift", "signature", "ml-model", "compliance", "runtime"];
const findingTargets = ["", "image", "image-workload", "host", "platform", "workload", "registry", "repository", "serverless"];
const lifecycles = ["", "open", "triaged", "in_progress", "accepted", "suppressed", "resolved"];
const severities = ["critical", "high", "medium", "low", "info"];
const categories: Record<string, string[]> = { all: TIMELINE_ALL_SOURCES, activity: ["runtime_event", "audit"], audit: ["audit"], event: ["runtime_event"], incident: ["dpi_threat", "runtime_event", "network_violation"], threat: ["dpi_threat", "runtime_event"], violation: ["network_violation"], security: ["dpi_threat", "runtime_event", "network_violation"] };
const findingSorts = ["risk", "severity", "cve", "cvss", "cvss_vector", "title", "package", "fixed", "asset", "lifecycle", "kind", "age", "last_seen"];
const record = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === "object" && !Array.isArray(value));
const optionalEnum = (value: unknown, allowed: string[]) => value === undefined || (typeof value === "string" && allowed.includes(value));
export function isFindingSavedView(value: unknown): value is FindingSavedView {
  return record(value) && typeof value.kind === "string" && findingKinds.includes(value.kind) && typeof value.lifecycle === "string" && lifecycles.includes(value.lifecycle) && typeof value.query === "string"
    && optionalEnum(value.groupMode, ["", "discover", "monitor", "protect"]) && optionalEnum(value.idScope, ["all"]) && optionalEnum(value.targetType, findingTargets) && optionalEnum(value.severity, ["", ...severities]) && (value.fixable === undefined || typeof value.fixable === "boolean") && optionalEnum(value.view, ["instances", "cve"]) && optionalEnum(value.group, ["none", "severity", "kind", "asset"]) && optionalEnum(value.sort, findingSorts) && optionalEnum(value.order, ["asc", "desc"]);
}
export function isTimelineSavedView(value: unknown): value is TimelineSavedView {
  if (!record(value) || !optionalEnum(value.category, [...Object.keys(categories), "custom"]) || typeof value.category !== "string") return false;
  if (!Array.isArray(value.sources) || !value.sources.every(source => typeof source === "string" && TIMELINE_ALL_SOURCES.includes(source as typeof TIMELINE_ALL_SOURCES[number]))) return false;
  if (value.category !== "custom" && (new Set(value.sources).size !== categories[value.category].length || categories[value.category].some(source => !(value.sources as string[]).includes(source)))) return false;
  if (!Array.isArray(value.severities) || !value.severities.every(severity => typeof severity === "string" && severities.includes(severity))) return false;
  if (!["query", "namespace", "workload", "reference", "from", "to"].every(key => typeof value[key] === "string")) return false;
  if (value.after !== undefined && (typeof value.after !== "string" || !timelineAfterParam(value.after))) return false;
  if (value.hours !== undefined && (typeof value.hours !== "number" || !Number.isInteger(value.hours) || value.hours<1 || value.hours>2160)) return false;
  if (value.after && value.hours !== undefined || (value.after || value.hours !== undefined) && (value.from || value.to)) return false;
  if (value.afterExclusive !== undefined && (typeof value.afterExclusive !== "boolean" || !value.after && value.hours===undefined)) return false;
  if (value.verdicts !== undefined && (!Array.isArray(value.verdicts) || !value.verdicts.every(verdict => typeof verdict === "string" && TIMELINE_VERDICTS.includes(verdict)) || value.verdicts.length>0 && (value.sources.length!==1 || value.sources[0]!=="runtime_event"))) return false;
  const from = timelineDateParam(value.from as string); const to = timelineDateParam(value.to as string);
  return !(value.from && !from) && !(value.to && !to) && !(from && to && from > to);
}
export function findingViewPayload(params: URLSearchParams): Omit<FindingSavedView, "id" | "name"> | null {
  const kind = params.get("kind") ?? ""; const lifecycle = params.get("lifecycle") === "all" ? "" : params.get("lifecycle") ?? "open";
  const severity = params.get("severity") ?? "";
  const view = params.get("view") ?? (kind && kind !== "vulnerability" ? "instances" : severity || lifecycle !== "open" ? "instances" : "cve");
  const value = { kind, lifecycle, ...(params.has("group_mode") ? { groupMode: params.get("group_mode")! } : {}), ...(params.has("id_scope") ? { idScope: params.get("id_scope")! } : {}), ...(params.has("target_type") ? { targetType: params.get("target_type")! } : {}), query: params.get("q") ?? "", severity, fixable: params.get("fixable") === "true" || params.get("fixable") === "1", view: kind && kind !== "vulnerability" ? "instances" : view, group: params.get("group") ?? "none", sort: params.get("sort") ?? "risk", order: params.get("order") ?? "desc" };
  if (params.has("fixable") && !["true", "false", "1", "0", ""].includes(params.get("fixable")!)) return null;
  return isFindingSavedView(value) ? value : null;
}
export function timelineViewPayload(params: URLSearchParams): TimelineFilterPayload | null {
  const category = params.get("tab") ?? "all";
  if (!Object.keys(categories).includes(category) && category !== "custom") return null;
  const selectedSources = category === "custom" ? params.has("type") ? params.get("type") === "none" ? [] : params.get("type")!.split(",") : TIMELINE_ALL_SOURCES : categories[category];
  if (params.has("after_exclusive") && !["true","false"].includes(params.get("after_exclusive")!)) return null;
  const value = { category, sources: selectedSources, severities: params.get("severity")?.split(",").filter(Boolean) ?? [], query: params.get("q") ?? "", namespace: params.get("namespace") ?? "", workload: params.get("workload") ?? "", reference: params.get("ref") ?? "", from: params.get("from") ?? "", to: params.get("to") ?? "", ...(params.has("after") ? { after: params.get("after")! } : {}), ...(params.has("hours") ? { hours: Number(params.get("hours")) } : {}), ...(params.has("after_exclusive") ? { afterExclusive: params.get("after_exclusive")==="true" } : {}), ...(params.has("verdict") ? { verdicts: params.get("verdict")!.split(",") } : {}) };
  return isTimelineSavedView(value) ? compactTimelineFilters(value) : null;
}
export function inventoryViewHref(clusterId: string, inventory: InventoryViewKind, params: URLSearchParams, hash = "", form = false) {
  const encoded = params.toString(); const fragment = hash.replace(/^#/, "");
  return `/clusters/${encodeURIComponent(clusterId)}/${inventory}${form ? "/views/new" : ""}${encoded ? `?${encoded}` : ""}${fragment ? `#${fragment}` : ""}`;
}
