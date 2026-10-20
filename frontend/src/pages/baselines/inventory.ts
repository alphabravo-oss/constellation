import type { BaselineInventoryParams, BaselineInventoryResponse } from "@/api/client";
import { scanInventoryResponseValid } from "../inventory-workspace";

export const BASELINE_INVENTORY_SORTS = ["workload", "namespace", "mode", "processes", "alerts", "blocks", "rules", "last_new", "learn_started"];
const modes = ["learn", "monitor", "enforce"];
const summaryKeys = ["learn", "monitor", "enforce", "processes", "alerts_24h", "blocks_24h", "rules", "ambiguous_owners"];
const countKeys = ["learned_processes_count", "monitored_alerts_24h", "enforced_blocks_24h", "rule_count", "owner_count"] as const;
const dates = ["learn_started_at", "monitor_started_at", "enforce_started_at", "last_new_process_at"] as const;

export function baselineInventoryMatches(data: BaselineInventoryResponse | undefined, request: BaselineInventoryParams): data is BaselineInventoryResponse {
  if (!data || typeof data !== "object" || !Array.isArray(data.profiles) || !Array.isArray(data.namespaces) || !data.namespaces.every(ns => typeof ns === "string") || new Set(data.namespaces).size !== data.namespaces.length || data.cluster_id !== request.cluster_id || data.source_complete !== true || data.summary_scope !== "matching_retained_process_events" || !data.filters || data.filters.q !== (request.q ?? "") || data.filters.namespace !== (request.namespace ?? "") || data.filters.mode !== (request.mode ?? "") || data.filters.hide_platform !== request.hide_platform || !scanInventoryResponseValid(data, data.profiles.length, request.offset ?? 0, request.sort ?? "workload", request.order ?? "asc", summaryKeys)) return false;
  if (data.summary.learn + data.summary.monitor + data.summary.enforce !== data.total || data.summary.ambiguous_owners > data.total) return false;
  const keys = new Set<string>();
  for (const row of data.profiles) {
    if (!row || typeof row !== "object" || typeof row.row_id !== "string" || typeof row.workload_id !== "string" || !row.workload_id || row.cluster_id !== request.cluster_id || typeof row.namespace !== "string" || typeof row.name !== "string" || !modes.includes(row.mode) || !["", "core"].includes(row.platform_role) || typeof row.configured !== "boolean" || typeof row.owner_ambiguous !== "boolean" || countKeys.some(key => !Number.isSafeInteger(row[key]) || row[key] < 0) || row.owner_ambiguous !== (row.owner_count > 1) || dates.some(key => row[key] !== undefined && row[key] !== null && (typeof row[key] !== "string" || !Number.isFinite(Date.parse(row[key]!)))) || row.top_processes !== undefined && (!Array.isArray(row.top_processes) || row.top_processes.length > 5 || row.top_processes.some(name => typeof name !== "string"))) return false;
    let identity: unknown;
    try { identity = JSON.parse(row.row_id); } catch { return false; }
    if (!Array.isArray(identity) || identity.length !== 2 || identity[0] !== request.cluster_id || identity[1] !== row.workload_id || keys.has(row.workload_id) || request.namespace && row.namespace !== request.namespace || request.mode && row.mode !== request.mode || request.hide_platform && row.platform_role === "core") return false;
    keys.add(row.workload_id);
  }
  return true;
}
