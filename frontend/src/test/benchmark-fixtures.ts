import type {
  BenchmarkExecutionDetail,
  BenchmarkExecutionPage,
  BenchmarkExecutionRequest,
} from "@/api/client";

export const benchCluster = "11111111-1111-4111-8111-111111111111";
export const benchOtherCluster = "22222222-2222-4222-8222-222222222222";
export const benchID = (value = 1) =>
  `33333333-3333-4333-8333-${String(value).padStart(12, "0")}`;
const at = "2026-10-17T10:00:00.123456Z";
export function benchRequest(
  index = 1,
  status = "queued",
): BenchmarkExecutionRequest {
  const request: BenchmarkExecutionRequest = {
    id: benchID(index),
    request_key: benchID(index + 10000),
    requested_cluster_id: benchCluster,
    cluster_id: benchCluster,
    profile: "kube-bench",
    benchmark: `benchmark-${index}`,
    status,
    revision: "1",
    attempt_count: 0,
    requested_at: at,
    completed_at: null,
    active_attempt: null,
  };
  if (status !== "queued") {
    request.attempt_count = 1;
    request.active_attempt = {
      id: benchID(index + 20000),
      request_id: request.id,
      cluster_id: benchCluster,
      runner_id: benchID(40000),
      claim_key: benchID(index + 50000),
      node: "worker-one",
      number: 1,
      status,
      started_at: at,
      lease_expires_at: at,
      finished_at: status === "running" || status === "interrupted" ? null : at,
      outcome:
        status === "succeeded"
          ? "report_received"
          : status === "failed"
            ? "interrupted"
            : "",
      report_sha256: status === "succeeded" ? "a".repeat(64) : "",
      rows_ingested: status === "succeeded" ? 5 : 0,
      controls:
        status === "succeeded"
          ? { total: 3, pass: 1, fail: 1, manual: 1, not_applicable: 0 }
          : { total: 0, pass: 0, fail: 0, manual: 0, not_applicable: 0 },
    };
  }
  return request;
}
export function benchDetail(
  request = benchRequest(1, "failed"),
): BenchmarkExecutionDetail {
  return {
    request,
    attempts: request.active_attempt ? [request.active_attempt] : [],
  };
}
export function benchPage(
  rows = [benchRequest()],
  offset = 0,
): BenchmarkExecutionPage {
  return {
    requests: rows.slice(offset, offset + 100),
    total: rows.length,
    limit: 100,
    offset,
    has_more: offset + 100 < rows.length,
    source: "durable_v2_requests",
    legacy_requests_included: false,
  };
}
