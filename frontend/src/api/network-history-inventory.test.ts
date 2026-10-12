import { afterEach, expect, it, vi } from "vitest";
import { api, network, runtimeEvents, runtimeThreats } from "./client";

afterEach(() => vi.restoreAllMocks());

it.each([
  ["/network/conversations.csv", network.conversationsCSV],
  ["/network/sessions.csv", network.sessionsCSV],
  ["/runtime-threats.csv", runtimeThreats.exportCSV],
  ["/events.csv", runtimeEvents.exportCSV],
] as const)("exports the full matching cohort through %s", async (path, download) => {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["CSV"]), headers: {
    "x-export-total": "100001", "x-export-limit": "100000", "x-export-truncated": "true",
  } });
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  const scope = { cluster_id: "cluster-a", sort: "severity", order: "desc" as const };
  await expect(download({ ...scope, limit: 100, offset: 1200 })).resolves.toEqual({ total: 100001, exported: 100000, limit: 100000, truncated: true });
  expect(get).toHaveBeenCalledWith(path, { params: scope, responseType: "blob" });
  expect(click).toHaveBeenCalledOnce();
  get.mockResolvedValue({ data: new Blob(["CSV"]), headers: {} });
  await expect(download(scope)).rejects.toThrow("Export scope could not be confirmed");
  expect(click).toHaveBeenCalledOnce();
});

it("preserves missing response metadata so an incomplete inventory cannot look complete", async () => {
  vi.spyOn(api, "get").mockImplementation(async (path) => ({ data: path === "/network/sessions" ? { sessions: [] } : { threats: [] } }));
  expect(await network.sessions({ cluster_id: "cluster-a" })).toEqual({ sessions: [] });
  expect(await runtimeThreats.page({ cluster_id: "cluster-a" })).toEqual({ threats: [] });
});
