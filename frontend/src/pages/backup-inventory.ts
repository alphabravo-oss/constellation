import type {
  BackupInventoryParams,
  BackupInventoryResponse,
  BackupInventoryRow,
} from "@/api/client";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
export const BACKUP_SORTS = ["when", "mode", "size", "status", "signer"];
export function backupFiltersValid(params: URLSearchParams) {
  const page = params.get("page");
  return (
    ["q", "status", "mode", "signed", "sort", "order", "page"].every(
      (key) => params.getAll(key).length < 2,
    ) &&
    (!page ||
      (/^\d+$/.test(page) &&
        Number.isSafeInteger(Number(page)) &&
        Number(page) > 0 &&
        Number(page) <= INVENTORY_MAX_PAGE)) &&
    ["", "all", "running", "succeeded", "failed"].includes(
      params.get("status") || "",
    ) &&
    ["", "all", "org-backup", "pg-dump"].includes(params.get("mode") || "") &&
    ["", "all", "true", "false"].includes(params.get("signed") || "") &&
    BACKUP_SORTS.includes(params.get("sort") || "when") &&
    ["asc", "desc"].includes(params.get("order") || "desc")
  );
}
function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
export function backupRowValid(
  value: unknown,
  org?: string,
): value is BackupInventoryRow {
  return (
    record(value) &&
    typeof value.id === "string" &&
    !!value.id &&
    (!org || value.org_id === org) &&
    ["org-backup", "pg-dump"].includes(value.mode as string) &&
    ["running", "succeeded", "failed"].includes(value.status as string) &&
    typeof value.started_at === "string" &&
    Number.isFinite(Date.parse(value.started_at)) &&
    (value.finished_at === undefined ||
      (typeof value.finished_at === "string" &&
        Number.isFinite(Date.parse(value.finished_at)))) &&
    Number.isSafeInteger(value.size_bytes) &&
    Number(value.size_bytes) >= 0 &&
    typeof value.signed === "boolean" &&
    ["sha256", "signer_identity", "format_version", "s3_uri", "error"].every(
      (key) => value[key] === undefined || typeof value[key] === "string",
    ) &&
    (value.tables_included === undefined ||
      (Array.isArray(value.tables_included) &&
        value.tables_included.every((item) => typeof item === "string")))
  );
}
export function backupInventoryValid(
  value: unknown,
  request: BackupInventoryParams,
  org: string,
): value is BackupInventoryResponse {
  if (
    !record(value) ||
    !record(value.summary) ||
    !record(value.filters) ||
    !Array.isArray(value.backups)
  )
    return false;
  if (!value.backups.every((row) => backupRowValid(row, org))) return false;
  const data = value as unknown as BackupInventoryResponse,
    total = data.total,
    rows = data.backups;
  return (
    data.org_id === org &&
    data.source_complete === true &&
    data.summary_scope === "matching_owned_backup_runs" &&
    Number.isSafeInteger(total) &&
    total >= 0 &&
    data.limit === request.limit &&
    data.offset === request.offset &&
    data.sort === request.sort &&
    data.order === request.order &&
    ["q", "status", "mode", "signed"].every(
      (key) =>
        data.filters[key as keyof typeof data.filters] ===
        (request[key as keyof BackupInventoryParams] || ""),
    ) &&
    ["total", "running", "succeeded", "failed", "signed", "size_bytes"].every(
      (key) =>
        Number.isSafeInteger(data.summary[key]) && data.summary[key] >= 0,
    ) &&
    data.summary.total === total &&
    data.summary.running + data.summary.succeeded + data.summary.failed ===
      total &&
    data.summary.signed <= total &&
    ["running", "succeeded", "failed"].every(
      (status) =>
        data.summary[status] >=
        rows.filter((row) => row.status === status).length,
    ) &&
    data.summary.signed >= rows.filter((row) => row.signed).length &&
    rows.length ===
      Math.min(request.limit!, Math.max(0, total - request.offset!)) &&
    data.has_more === request.offset! + rows.length < total &&
    new Set(rows.map((row) => row.id)).size === rows.length &&
    rows.every(
      (row) =>
        backupRowValid(row, org) &&
        (!request.status || row.status === request.status) &&
        (!request.mode || row.mode === request.mode) &&
        (!request.signed || row.signed === (request.signed === "true")),
    ) &&
    (data.latest_success === null ||
      (backupRowValid(data.latest_success, org) &&
        data.latest_success.status === "succeeded"))
  );
}
