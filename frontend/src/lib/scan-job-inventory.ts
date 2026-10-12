import type { ScanJobInventoryParams, ScanJobInventoryResponse } from "@/api/client";

const targetTypes = ["image", "workload", "host", "platform", "registry", "repository", "serverless"];
const statuses = ["pending", "running", "paused", "completed", "failed", "canceled"];

/** A server page and its full matching counts must describe the same scope. */
export function scanJobInventoryResponseValid(data: ScanJobInventoryResponse, request: ScanJobInventoryParams, orgID?: string): boolean {
  const total = data.total;
  const offset = request.offset ?? 0;
  const limit = request.limit ?? 200;
  const scopeMatches = (actual: string | undefined, expected: string | undefined) => !expected || actual?.toLowerCase() === expected.toLowerCase();
  return Array.isArray(data.jobs)
    && Number.isSafeInteger(total) && total! >= 0
    && data.limit === limit && data.offset === offset
    && data.sort === (request.sort ?? "requested") && data.order === (request.order ?? "desc")
    && data.jobs.length === Math.min(limit, Math.max(0, total! - offset))
    && data.has_more === (offset + data.jobs.length < total!)
    && data.summary?.total === total
    && statuses.every(status => Number.isSafeInteger(data.summary?.[status]) && data.summary![status] >= 0)
    && statuses.reduce((sum, status) => sum + data.summary![status], 0) === total
    && data.jobs.every(job => Boolean(job.id) && statuses.includes(job.status) && targetTypes.includes(job.target_type)
      && (!orgID || !job.org_id || scopeMatches(job.org_id, orgID))
      && (!request.status || job.status === request.status)
      && (!request.target_type || job.target_type === request.target_type)
      && scopeMatches(job.target_cluster_id, request.cluster_id)
      && scopeMatches(job.registry_id, request.registry_id))
    && new Set(data.jobs.map(job => job.id)).size === data.jobs.length;
}
