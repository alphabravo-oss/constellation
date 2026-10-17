import type {
  BenchmarkExecutionAttempt,
  BenchmarkExecutionDetail,
  BenchmarkExecutionPage,
  BenchmarkExecutionRequest,
} from "@/api/client";

export const benchmarkUUID = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
    value,
  ) &&
  value !== "00000000-0000-0000-0000-000000000000";
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const timestamp = (value: unknown) =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T/.test(value) &&
  Number.isFinite(Date.parse(value));
const nullableTime = (value: unknown) => value === null || timestamp(value);
const integer = (value: unknown): value is number =>
  Number.isSafeInteger(value) && Number(value) >= 0;
const nullableUUID = (value: unknown) => value === null || benchmarkUUID(value);
const statuses = ["queued", "running", "succeeded", "failed", "interrupted"];
export const benchmarkValid = (value: string) =>
  value === "" || /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value);
export const benchmarkRetryable = (request: BenchmarkExecutionRequest) =>
  ["failed", "interrupted"].includes(request.status) &&
  request.attempt_count < 3 &&
  request.active_attempt !== null;

export function benchmarkAttemptValid(
  value: unknown,
  requestID: string,
  clusterID: string | null,
): value is BenchmarkExecutionAttempt {
  if (
    !record(value) ||
    !benchmarkUUID(value.id) ||
    value.request_id !== requestID ||
    !benchmarkUUID(value.cluster_id) ||
    clusterID !== value.cluster_id ||
    !benchmarkUUID(value.runner_id) ||
    !benchmarkUUID(value.claim_key) ||
    typeof value.node !== "string" ||
    !integer(value.number) ||
    value.number < 1 ||
    value.number > 3 ||
    !["running", "succeeded", "failed", "interrupted"].includes(
      String(value.status),
    ) ||
    !timestamp(value.started_at) ||
    !timestamp(value.lease_expires_at) ||
    !nullableTime(value.finished_at) ||
    typeof value.outcome !== "string" ||
    typeof value.report_sha256 !== "string" ||
    (value.report_sha256 !== "" &&
      !/^[a-f0-9]{64}$/.test(value.report_sha256)) ||
    !integer(value.rows_ingested) ||
    !record(value.controls)
  )
    return false;
  const counts = value.controls;
  return (
    ["total", "pass", "fail", "manual", "not_applicable"].every((key) =>
      integer(counts[key]),
    ) &&
    counts.total ===
      Number(counts.pass) +
        Number(counts.fail) +
        Number(counts.manual) +
        Number(counts.not_applicable)
  );
}

export function benchmarkRequestValid(
  value: unknown,
  clusterID: string,
  id?: string,
): value is BenchmarkExecutionRequest {
  if (
    !record(value) ||
    !benchmarkUUID(value.id) ||
    (id !== undefined && value.id !== id) ||
    !benchmarkUUID(value.request_key) ||
    !nullableUUID(value.requested_cluster_id) ||
    !nullableUUID(value.cluster_id) ||
    (value.cluster_id !== null && value.cluster_id !== clusterID) ||
    (value.requested_cluster_id !== null &&
      value.requested_cluster_id !== clusterID) ||
    value.profile !== "kube-bench" ||
    typeof value.benchmark !== "string" ||
    !benchmarkValid(value.benchmark) ||
    !statuses.includes(String(value.status)) ||
    typeof value.revision !== "string" ||
    !/^[1-9]\d*$/.test(value.revision) ||
    BigInt(value.revision) > 9223372036854775807n ||
    !integer(value.attempt_count) ||
    value.attempt_count > 3 ||
    !timestamp(value.requested_at) ||
    !nullableTime(value.completed_at)
  )
    return false;
  if (value.active_attempt === null) return value.status === "queued";
  return (
    benchmarkAttemptValid(
      value.active_attempt,
      value.id,
      value.cluster_id as string | null,
    ) &&
    value.active_attempt.number === value.attempt_count &&
    value.active_attempt.status === value.status
  );
}

export function benchmarkPageValid(
  value: unknown,
  clusterID: string,
  offset: number,
): value is BenchmarkExecutionPage {
  if (
    !record(value) ||
    !Array.isArray(value.requests) ||
    value.source !== "durable_v2_requests" ||
    value.legacy_requests_included !== false ||
    value.limit !== 100 ||
    value.offset !== offset ||
    !integer(value.total) ||
    value.requests.length !==
      Math.min(100, Math.max(0, value.total - offset)) ||
    value.has_more !== offset + value.requests.length < value.total ||
    !value.requests.every((row) => benchmarkRequestValid(row, clusterID))
  )
    return false;
  return (
    new Set(value.requests.map((row) => row.id)).size === value.requests.length
  );
}

export function benchmarkDetailValid(
  value: unknown,
  clusterID: string,
  id: string,
): value is BenchmarkExecutionDetail {
  if (
    !record(value) ||
    !benchmarkRequestValid(value.request, clusterID, id) ||
    !Array.isArray(value.attempts) ||
    value.attempts.length !== value.request.attempt_count
  )
    return false;
  const request = value.request;
  return (
    value.attempts.every(
      (attempt, index) =>
        benchmarkAttemptValid(attempt, id, request.cluster_id) &&
        attempt.number === index + 1,
    ) &&
    new Set(value.attempts.map((attempt) => attempt.id)).size ===
      value.attempts.length &&
    (!request.active_attempt ||
      value.attempts.some(
        (attempt) =>
          JSON.stringify(attempt) === JSON.stringify(request.active_attempt),
      ))
  );
}

/** A pending create key survives reload; reads never enqueue an execution. */
export function pendingBenchmarkKey(
  owner: string,
  clusterID: string,
  benchmark: string,
) {
  const key = `constellation:pending-benchmark:${JSON.stringify([owner, clusterID, benchmark])}`;
  const saved = sessionStorage.getItem(key);
  if (saved !== null && !benchmarkUUID(saved))
    throw new Error("Invalid pending request key");
  const requestKey = saved ?? crypto.randomUUID();
  sessionStorage.setItem(key, requestKey);
  if (sessionStorage.getItem(key) !== requestKey)
    throw new Error("Pending request key could not be retained");
  return requestKey;
}

export function confirmBenchmarkKey(
  owner: string,
  clusterID: string,
  benchmark: string,
  requestKey: string,
) {
  const key = `constellation:pending-benchmark:${JSON.stringify([owner, clusterID, benchmark])}`;
  try {
    if (sessionStorage.getItem(key) === requestKey)
      sessionStorage.removeItem(key);
  } catch {
    /* A confirmed receipt is safe; a retained key reconciles instead of duplicating. */
  }
}
