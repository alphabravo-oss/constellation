import { afterEach, expect, it, vi } from "vitest";
import { api, containers } from "./client";
afterEach(() => vi.restoreAllMocks());
it("forwards exact literal source filters and continuation", async () => {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: { items: [] } });
  const params = {
    q: "tail%_",
    namespace: "prod",
    node: "node",
    platform_role: "none",
    hide_platform: true,
    sort: "risk",
    order: "desc" as const,
    limit: 100,
    offset: 3000,
  };
  await containers.list("cluster/id", params);
  expect(get).toHaveBeenCalledWith("/clusters/cluster%2Fid/containers", {
    params,
  });
});
it("exports all matching filters and confirms CSV metadata before download", async () => {
  const get = vi.spyOn(api, "get").mockResolvedValue({
    data: new Blob(["CSV"]),
    headers: {
      "x-export-total": "3005",
      "x-export-limit": "100000",
      "x-export-truncated": "false",
    },
  });
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export");
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  await expect(
    containers.exportCSV("cluster", {
      q: "tail",
      hide_platform: false,
      sort: "risk",
      order: "desc",
      limit: 100,
      offset: 3000,
    }),
  ).resolves.toEqual({
    total: 3005,
    exported: 3005,
    limit: 100000,
    truncated: false,
  });
  expect(get).toHaveBeenCalledWith("/clusters/cluster/containers.csv", {
    params: { q: "tail", hide_platform: false, sort: "risk", order: "desc" },
    responseType: "blob",
  });
  expect(click).toHaveBeenCalledOnce();
});
it.each([
  {},
  {
    "x-export-total": "",
    "x-export-limit": "100000",
    "x-export-truncated": "false",
  },
])("does not download ambiguous export evidence %j", async (headers) => {
  vi.spyOn(api, "get").mockResolvedValue({
    data: new Blob(["CSV"]),
    headers,
  });
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  await expect(containers.exportCSV("cluster")).rejects.toThrow(
    "scope could not be confirmed",
  );
  expect(click).not.toHaveBeenCalled();
});
