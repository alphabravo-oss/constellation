import { isPlatformNamespace } from "@/lib/platform-components";
import type { DeploymentFindingsParams, DeploymentFindingsResponse } from "@/api/client";
import { scanInventoryResponseValid } from "./inventory-workspace";

export const deploymentFindingSorts = ["finding", "cve", "severity", "risk", "lifecycle", "kind", "package", "fixed", "observed", "first_seen"];
export const deploymentFindingLifecycles = ["open", "in_progress", "triaged", "accepted", "suppressed", "resolved"];
export const deploymentFindingSeverities = ["critical", "high", "medium", "low", "info", "unknown"];
const summaryKeys = [...deploymentFindingLifecycles, "critical", "high", "fixable", "canonical", "pod", "ambiguous_owners", "other_lifecycle"];
const textFields = ["row_id", "id", "first_seen_at", "last_seen_at", "kind", "external_id", "title", "severity", "lifecycle", "target_ref", "package_name", "package_version", "fixed_version", "platform_role"] as const;

// Compare the full PostgreSQL timestamp identity without losing microseconds in Date.
function exactInstance(rowID: string, id: string, firstSeen: string) {
  if (!rowID.startsWith(`${id}:`)) return false;
  const epoch = rowID.slice(id.length + 1).match(/^(-?)(\d+)(?:\.(\d{1,9}))?$/);
  const timestamp = firstSeen.match(/^(.*:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/);
  if (!epoch || !timestamp) return false;
  const whole = Date.parse(`${timestamp[1]}${timestamp[3]}`);
  if (!Number.isFinite(whole)) return false;
  const value = BigInt(epoch[2]) * 1_000_000_000n + BigInt((epoch[3] ?? "").padEnd(9, "0"));
  return (epoch[1] ? -value : value) === BigInt(whole) * 1_000_000n + BigInt((timestamp[2] ?? "").padEnd(9, "0"));
}
export function deploymentFindingsMatch(data: DeploymentFindingsResponse | undefined, deploymentID: string, workloadID: string, request: DeploymentFindingsParams): data is DeploymentFindingsResponse {
  if (!data || typeof data !== "object" || !Array.isArray(data.items) || data.deployment_id !== deploymentID || data.cluster_id !== request.cluster_id || data.workload_id !== workloadID || data.source_complete !== true || data.summary_scope !== "matching_direct_workload_findings" || !Number.isSafeInteger(data.owner_count) || data.owner_count < 1 || data.owner_ambiguous !== (data.owner_count > 1) || !data.filters || data.filters.q !== (request.q ?? "") || data.filters.lifecycle !== (request.lifecycle ?? "open") || data.filters.severity !== (request.severity ?? "") || data.filters.fixable !== (request.fixable === undefined ? "" : String(request.fixable)) || !scanInventoryResponseValid(data, data.items.length, request.offset ?? 0, request.sort ?? "risk", request.order ?? "desc", summaryKeys)) return false;
  if (deploymentFindingLifecycles.reduce((sum, key) => sum + data.summary[key], data.summary.other_lifecycle) !== data.total || data.summary.canonical + data.summary.pod !== data.total || data.summary.critical + data.summary.high > data.total || data.summary.fixable > data.total || data.summary.ambiguous_owners > data.total) return false;
  const identities = new Set<string>();
  for (const row of data.items) {
    if (!row || typeof row !== "object" || textFields.some(key => typeof row[key] !== "string") || !row.id || !row.kind || !exactInstance(row.row_id, row.id, row.first_seen_at) || !Number.isFinite(Date.parse(row.last_seen_at)) || identities.has(row.row_id) || !deploymentFindingSeverities.includes(row.severity) || !row.lifecycle.trim() || !Number.isSafeInteger(row.risk_score) || row.risk_score < 0 || typeof row.fixable !== "boolean" || row.target_type !== "workload" || row.effective_target_cluster_id !== request.cluster_id || row.source_cluster_id !== null && (typeof row.source_cluster_id !== "string" || !row.source_cluster_id) || row.target_cluster_id !== null && (typeof row.target_cluster_id !== "string" || !row.target_cluster_id) || (row.target_cluster_id ?? row.source_cluster_id) !== request.cluster_id || !["", "core"].includes(row.platform_role) || row.source_cluster_id !== request.cluster_id && row.platform_role !== "" || !Number.isSafeInteger(row.owner_count) || row.owner_count < 1 || row.owner_ambiguous !== (row.owner_count > 1) || request.lifecycle !== "all" && row.lifecycle !== (request.lifecycle ?? "open") || request.severity && row.severity !== request.severity || request.fixable !== undefined && row.fixable !== request.fixable) return false;
    if (row.attribution === "canonical") {
      if (row.target_ref !== workloadID || row.owner_count !== data.owner_count || row.owner_ambiguous && row.platform_role === "core" && !isPlatformNamespace(workloadID.split("/")[0])) return false;
    } else if (row.attribution === "pod") {
      const prefix = `${workloadID.split("/")[0]}/pod/`;
      if (row.owner_count !== 1 || !row.target_ref.startsWith(prefix) || !row.target_ref.slice(prefix.length) || /[/:]/.test(row.target_ref.slice(prefix.length))) return false;
    } else return false;
    identities.add(row.row_id);
  }
  return true;
}
