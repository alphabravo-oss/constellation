import { beforeEach, expect, it, vi } from "vitest";
import {
  benchCluster,
  benchOtherCluster,
  benchDetail,
  benchID,
  benchPage,
  benchRequest,
} from "@/test/benchmark-fixtures";
import {
  benchmarkDetailValid,
  benchmarkPageValid,
  benchmarkRequestValid,
  benchmarkRetryable,
  benchmarkValid,
  confirmBenchmarkKey,
  pendingBenchmarkKey,
} from "./benchmark-executions";

beforeEach(() => {
  sessionStorage.clear();
  vi.restoreAllMocks();
});
it("validates complete pages beyond the first hundred without inventing a summary", () => {
  const rows = Array.from({ length: 205 }, (_, i) => benchRequest(i + 1));
  expect(benchmarkPageValid(benchPage(rows, 200), benchCluster, 200)).toBe(
    true,
  );
  expect(
    benchmarkPageValid({ ...benchPage(rows), total: 99 }, benchCluster, 0),
  ).toBe(false);
  expect(
    benchmarkPageValid({ ...benchPage(), requests: [null] }, benchCluster, 0),
  ).toBe(false);
  expect(
    benchmarkPageValid({ ...benchPage([rows[0], rows[0]]) }, benchCluster, 0),
  ).toBe(false);
});
it("allows unassigned organization requests but rejects foreign or malformed scope", () => {
  expect(
    benchmarkRequestValid(
      { ...benchRequest(), cluster_id: null, requested_cluster_id: null },
      benchCluster,
    ),
  ).toBe(true);
  expect(
    benchmarkRequestValid(
      { ...benchRequest(), cluster_id: benchOtherCluster },
      benchCluster,
    ),
  ).toBe(false);
  expect(
    benchmarkRequestValid(
      { ...benchRequest(), requested_cluster_id: benchOtherCluster },
      benchCluster,
    ),
  ).toBe(false);
  expect(
    benchmarkRequestValid({ ...benchRequest(), revision: "01" }, benchCluster),
  ).toBe(false);
  expect(
    benchmarkRequestValid(
      { ...benchRequest(), revision: "9223372036854775808" },
      benchCluster,
    ),
  ).toBe(false);
  expect(
    benchmarkRequestValid(
      { ...benchRequest(), request_key: "key" },
      benchCluster,
    ),
  ).toBe(false);
});
it("retains failed controls in a received report and distinguishes attempts from evidence rows", () => {
  const detail = benchDetail(benchRequest(1, "succeeded"));
  expect(benchmarkDetailValid(detail, benchCluster, benchID())).toBe(true);
  expect(detail.attempts[0].controls.fail).toBe(1);
  expect(detail.attempts[0].rows_ingested).toBe(5);
  expect(benchmarkRetryable(detail.request)).toBe(false);
  const interrupted = benchDetail(benchRequest(1, "interrupted"));
  expect(benchmarkDetailValid(interrupted, benchCluster, benchID())).toBe(true);
  expect(benchmarkRetryable(interrupted.request)).toBe(true);
});
it.each([
  "missing history",
  "foreign attempt",
  "wrong claim",
  "bad control total",
  "wrong active attempt",
])("rejects %s without accepting partial detail", (condition) => {
  const detail = benchDetail();
  if (condition === "missing history") detail.attempts = [];
  if (condition === "foreign attempt")
    detail.attempts[0].cluster_id = benchOtherCluster;
  if (condition === "wrong claim") detail.attempts[0].claim_key = "";
  if (condition === "bad control total") detail.attempts[0].controls.total = 10;
  if (condition === "wrong active attempt")
    detail.request.active_attempt = { ...detail.attempts[0], id: benchID(999) };
  expect(benchmarkDetailValid(detail, benchCluster, benchID())).toBe(false);
});
it("validates optional benchmark identifiers using the server grammar", () => {
  for (const value of ["", "cis-1.9", "A".repeat(128), "eks_1.2"])
    expect(benchmarkValid(value)).toBe(true);
  for (const value of ["-bad", "with space", "../file", "A".repeat(129), "é"])
    expect(benchmarkValid(value)).toBe(false);
});
it("retains an unknown create key across reloads and isolates owner, cluster and selectors", () => {
  const key = pendingBenchmarkKey("org:user", benchCluster, "cis");
  expect(pendingBenchmarkKey("org:user", benchCluster, "cis")).toBe(key);
  expect(pendingBenchmarkKey("org:other", benchCluster, "cis")).not.toBe(key);
  expect(pendingBenchmarkKey("org:user", benchOtherCluster, "cis")).not.toBe(
    key,
  );
  expect(pendingBenchmarkKey("org:user", benchCluster, "eks")).not.toBe(key);
  confirmBenchmarkKey("org:user", benchCluster, "cis", key);
  expect(pendingBenchmarkKey("org:user", benchCluster, "cis")).not.toBe(key);
});
it("fails before a request when key persistence is unavailable or corrupted", () => {
  vi.stubGlobal("sessionStorage", {
    getItem: () => null,
    setItem: () => {
      throw new Error("denied");
    },
  });
  expect(() => pendingBenchmarkKey("owner", benchCluster, "")).toThrow();
  vi.unstubAllGlobals();
  sessionStorage.setItem(
    `constellation:pending-benchmark:${JSON.stringify(["owner", benchCluster, ""])}`,
    "corrupted",
  );
  expect(() => pendingBenchmarkKey("owner", benchCluster, "")).toThrow();
});
