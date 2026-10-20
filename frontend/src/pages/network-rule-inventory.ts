import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useInventoryScope } from "./inventory-workspace";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { useQueryClient } from "@tanstack/react-query";
import type {
  NetworkRuleInventoryParams,
  NetworkRuleInventoryResponse,
  NetworkRuleInventoryRow,
} from "@/api/client";

export const NETWORK_RULE_SORTS = [
  "evaluation",
  "priority",
  "from",
  "to",
  "action",
  "matches",
  "last_match",
  "type",
  "status",
  "apps",
  "ports",
  "id",
];
export function useNetworkRuleScope() {
  const scope = useInventoryScope(),
    identity = useTablePreferencesIdentity(),
    client = useQueryClient();
  const ready =
    scope.ready &&
    !!identity?.org_id &&
    !!identity?.user_id &&
    !!scope.clusterId &&
    clusterCacheReady(client, scope.clusterId);
  return {
    ...scope,
    ready,
    client,
    recheck: () =>
      ready && !!scope.clusterId && clusterCacheReady(client, scope.clusterId),
  };
}
export function networkRuleValid(
  value: unknown,
): value is NetworkRuleInventoryRow {
  if (!value || typeof value !== "object") return false;
  const row = value as NetworkRuleInventoryRow;
  if (
    !Number.isSafeInteger(row.id) ||
    row.id < 0 ||
    row.id > 4294967295 ||
    ![row.from, row.to].every(
      (text) => typeof text === "string" && !!text.trim(),
    ) ||
    typeof row.row_id !== "string"
  )
    return false;
  try {
    const pair = JSON.parse(row.row_id);
    if (
      !Array.isArray(pair) ||
      pair.length !== 2 ||
      pair[0] !== row.from ||
      pair[1] !== row.to
    )
      return false;
  } catch {
    return false;
  }
  return (
    [row.ports, row.comment].every((text) => typeof text === "string") &&
    Array.isArray(row.applications) &&
    row.applications.every((app) => typeof app === "string") &&
    ["allow", "deny"].includes(row.action) &&
    typeof row.disable === "boolean" &&
    typeof row.learned === "boolean" &&
    ["learned", "learned_override", "user_created"].includes(row.cfg_type) &&
    row.learned === (row.cfg_type !== "user_created") &&
    Number.isSafeInteger(row.priority) &&
    [row.match_counter, row.last_match_timestamp].every(
      (count) => Number.isSafeInteger(count) && count >= 0,
    ) &&
    (row.last_match_timestamp === 0 ||
      Number.isFinite(new Date(row.last_match_timestamp * 1000).getTime())) &&
    [row.from_platform_role, row.to_platform_role].every(
      (role) => role === "" || role === "core",
    )
  );
}
export function networkRuleInventoryMatches(
  value: unknown,
  cluster: string,
  request: NetworkRuleInventoryParams,
): value is NetworkRuleInventoryResponse {
  if (!value || typeof value !== "object") return false;
  const data = value as NetworkRuleInventoryResponse,
    filters = data.filters,
    summary = data.summary;
  const limit = request.limit ?? 100,
    offset = request.offset ?? 0;
  if (
    data.cluster_id !== cluster ||
    data.source !== "retained_flow_rollups_and_authored_overrides" ||
    data.source_complete !== true ||
    data.summary_scope !== "matching_rules" ||
    data.limit !== limit ||
    data.offset !== offset ||
    data.sort !== (request.sort ?? "evaluation") ||
    data.order !== (request.order ?? "asc") ||
    !Number.isSafeInteger(data.total) ||
    data.total < 0 ||
    !filters ||
    !summary ||
    !Array.isArray(data.rules)
  )
    return false;
  if (
    ["q", "from", "to", "action", "status", "cfg_type"].some(
      (key) =>
        filters[key as keyof typeof filters] !==
        (request[key as keyof NetworkRuleInventoryParams] ?? ""),
    ) ||
    filters.hide_platform !== (request.hide_platform ?? false)
  )
    return false;
  if (
    summary.total !== data.total ||
    !(["total", "allow", "deny", "learned", "disabled"] as const).every(
      (key) =>
        Number.isSafeInteger(summary[key]) &&
        summary[key] >= 0 &&
        summary[key] <= data.total,
    ) ||
    summary.allow + summary.deny !== data.total ||
    data.rules.length !== Math.min(limit, Math.max(0, data.total - offset)) ||
    data.has_more !== data.total > offset + data.rules.length
  )
    return false;
  return (
    data.rules.every(
      (row) =>
        networkRuleValid(row) &&
        (!request.hide_platform ||
          (!row.from_platform_role && !row.to_platform_role)) &&
        (!request.from || row.from === request.from) &&
        (!request.to || row.to === request.to) &&
        (!request.action || row.action === request.action) &&
        (!request.status || row.disable === (request.status === "disabled")) &&
        (!request.cfg_type || row.cfg_type === request.cfg_type),
    ) &&
    new Set(data.rules.map((row) => JSON.stringify([row.from, row.to])))
      .size === data.rules.length
  );
}
export function networkRuleFingerprint(row: NetworkRuleInventoryRow) {
  return JSON.stringify([
    row.row_id,
    row.id,
    row.from,
    row.to,
    row.ports,
    row.applications,
    row.action,
    row.disable,
    row.comment,
    row.priority,
    row.learned,
    row.cfg_type,
  ]);
}
export function networkRuleReturnHref(cluster: string, raw: string | null) {
  const path = `/clusters/${encodeURIComponent(cluster)}/network-rules`;
  if (!raw || !raw.startsWith("/") || raw.startsWith("//")) return path;
  try {
    const url = new URL(raw, "https://console.invalid");
    return url.origin === "https://console.invalid" && url.pathname === path
      ? url.pathname + url.search + url.hash
      : path;
  } catch {
    return path;
  }
}
