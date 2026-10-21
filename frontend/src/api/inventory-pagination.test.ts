import { afterEach, expect, it, vi } from "vitest";
import { api, clusters, groupsApi, policies, runtimePolicies } from "./client";

afterEach(() => vi.restoreAllMocks());

it.each([
  ["clusters", () => clusters.list(), "/clusters", "clusters"],
  ["groups", () => groupsApi.list(), "/groups", "groups"],
  ["policies", () => policies.list(), "/policies", "policies"],
  ["runtime policies", () => runtimePolicies.list("cluster"), "/runtime-policies", "policies"],
] as const)("preserves every %s page for pickers and existing tables", async (_name, list, path, key) => {
  const get = vi.spyOn(api, "get")
    .mockResolvedValueOnce({ data: { [key]: [{ id: "first" }], has_more: true } })
    .mockResolvedValueOnce({ data: { [key]: [{ id: "second" }], has_more: false } });
  const result = await list();
  expect(JSON.stringify(result)).toContain("first");
  expect(JSON.stringify(result)).toContain("second");
  expect(get).toHaveBeenNthCalledWith(1, path, { params: expect.objectContaining({ limit: 500, offset: 0 }) });
  expect(get).toHaveBeenNthCalledWith(2, path, { params: expect.objectContaining({ limit: 500, offset: 1 }) });
});
