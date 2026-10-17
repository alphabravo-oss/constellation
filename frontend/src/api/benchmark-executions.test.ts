import { afterEach, expect, it, vi } from "vitest";
import {
  benchCluster,
  benchDetail,
  benchID,
  benchPage,
  benchRequest,
} from "@/test/benchmark-fixtures";
import { api, compliance } from "./client";

afterEach(() => vi.restoreAllMocks());
it("sends exact cluster and server paging to durable execution reads", async () => {
  const get = vi
    .spyOn(api, "get")
    .mockResolvedValueOnce({ data: benchPage() })
    .mockResolvedValueOnce({ data: benchDetail() });
  await compliance.benchRequests({
    cluster_id: benchCluster,
    limit: 100,
    offset: 2000000,
  });
  await compliance.benchRequest(benchID(), benchCluster);
  expect(get).toHaveBeenNthCalledWith(1, "/compliance/bench/requests", {
    params: { cluster_id: benchCluster, limit: 100, offset: 2000000 },
  });
  expect(get).toHaveBeenNthCalledWith(
    2,
    `/compliance/bench/requests/${benchID()}`,
    { params: { cluster_id: benchCluster } },
  );
});
it("preserves the caller request UUID and decimal reviewed revision without generating retries", async () => {
  const post = vi
    .spyOn(api, "post")
    .mockResolvedValue({ data: { request: benchRequest() } });
  const body = {
    request_key: benchID(50),
    profile: "kube-bench" as const,
    benchmark: "cis-1.9",
  };
  await compliance.createBenchRequest(benchCluster, body);
  await compliance.retryBenchRequest(
    benchID(),
    benchCluster,
    "9223372036854775806",
  );
  expect(post).toHaveBeenNthCalledWith(1, "/compliance/bench/requests", body, {
    params: { cluster_id: benchCluster },
  });
  expect(post).toHaveBeenNthCalledWith(
    2,
    `/compliance/bench/requests/${benchID()}/retry`,
    { reviewed_revision: "9223372036854775806" },
    { params: { cluster_id: benchCluster } },
  );
  post.mockRejectedValueOnce({ response: { status: 409 } });
  await expect(
    compliance.retryBenchRequest(benchID(), benchCluster, "1"),
  ).rejects.toEqual({ response: { status: 409 } });
  expect(post).toHaveBeenCalledTimes(3);
});
