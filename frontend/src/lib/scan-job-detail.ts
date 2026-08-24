import type { ScanJob } from "@/api/client";

export type ScanJobRetryTone = "neutral" | "success" | "warning" | "error" | "info" | "pending";

export interface ScanJobRetryState {
  label: string;
  tone: ScanJobRetryTone;
  detail: string;
}

export interface ScanJobDetailRow {
  label: string;
  value: string;
}

export function scanJobRetryState(job: Pick<ScanJob, "status" | "attempt_count" | "max_attempts" | "next_attempt_at">): ScanJobRetryState {
  const attempts = `${job.attempt_count}/${job.max_attempts}`;
  if (job.status === "completed") {
    return { label: "Complete", tone: "success", detail: `${attempts} attempts used` };
  }
  if (job.status === "running") {
    return { label: "Running", tone: "info", detail: `attempt ${attempts}` };
  }
  if (job.status === "pending" && job.next_attempt_at) {
    return { label: "Retry scheduled", tone: "warning", detail: job.next_attempt_at };
  }
  if (job.status === "pending") {
    return { label: "Queued", tone: "pending", detail: `${attempts} attempts used` };
  }
  if (job.status === "paused") {
    return { label: "Paused", tone: "warning", detail: `${attempts} attempts used` };
  }
  if (job.status === "failed" && job.attempt_count >= job.max_attempts) {
    return { label: "Attempts exhausted", tone: "error", detail: `${attempts} attempts used` };
  }
  if (job.status === "failed") {
    return { label: "Manual retry available", tone: "error", detail: `${attempts} attempts used` };
  }
  if (job.status === "canceled") {
    return { label: "Canceled", tone: "neutral", detail: `${attempts} attempts used` };
  }
  return { label: job.status || "Unknown", tone: "neutral", detail: `${attempts} attempts used` };
}

export function scanJobTimingRows(job: ScanJob): ScanJobDetailRow[] {
  return [
    { label: "Requested", value: job.requested_at },
    { label: "Claimed", value: job.claimed_at ?? "" },
    { label: "Lease expires", value: job.lease_expires_at ?? "" },
    { label: "Last attempt", value: job.last_attempt_at ?? "" },
    { label: "Last error", value: job.last_error_at ?? "" },
    { label: "Next retry", value: job.next_attempt_at ?? "" },
    { label: "Finished", value: job.finished_at ?? "" },
  ].filter((row) => row.value);
}

export function scanJobTargetRows(job: ScanJob): ScanJobDetailRow[] {
  const rows: ScanJobDetailRow[] = [];
  pushRow(rows, "Job ID", job.id);
  pushRow(rows, "Target ID", job.target_id);
  pushRow(rows, "Cluster ID", job.target_cluster_id);
  pushRow(rows, "Target type", job.target_type);
  pushRow(rows, "Target ref", job.target_ref);
  pushRow(rows, "Source type", job.source_type);
  pushRow(rows, "Source ref", job.source_ref);
  pushRow(rows, "Image ref", job.image_ref);
  pushRow(rows, "Image digest", job.image_digest);
  pushRow(rows, "Platform", job.platform);
  pushRow(rows, "Registry ID", job.registry_id);
  pushRow(rows, "Inventory hash", job.inventory_hash);
  pushRow(rows, "Enqueue reason", job.enqueue_reason);
  pushRow(rows, "Registry policy hash", job.registry_policy_hash);
  pushRow(rows, "VulnDB version", job.vulndb_bundle_version);
  for (const row of scanJobMetadataRows(job.metadata)) {
    rows.push(row);
  }
  return rows;
}

export function scanJobMetadataRows(metadata: unknown, limit = 12): ScanJobDetailRow[] {
  if (!isRecord(metadata)) return [];
  return Object.entries(metadata)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(0, limit)
    .map(([key, value]) => ({ label: `metadata.${key}`, value: formatMetadataValue(value) }))
    .filter((row) => row.value);
}

export function scanJobBundleRows(job: ScanJob): ScanJobDetailRow[] {
  const bundle = job.bundle_metadata;
  if (!bundle) return [];
  const rows: ScanJobDetailRow[] = [];
  pushRow(rows, "Bundle version", bundle.bundle_version);
  pushRow(rows, "Schema", bundle.schema_version);
  pushRow(rows, "Producer", bundle.producer);
  pushRow(rows, "Media type", bundle.media_type);
  pushRow(rows, "Exported", bundle.exported_at);
  pushRow(rows, "Payload hash", bundle.payload_hash);
  pushRow(rows, "Records", typeof bundle.record_count === "number" ? bundle.record_count.toLocaleString() : "");
  return rows;
}

export function formatMetadataValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function pushRow(rows: ScanJobDetailRow[], label: string, value: unknown) {
  const formatted = formatMetadataValue(value);
  if (formatted) rows.push({ label, value: formatted });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
