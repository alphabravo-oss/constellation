import { afterEach, expect, it, vi } from "vitest";
import { api, registries } from "./client";
afterEach(() => vi.restoreAllMocks());
it("forwards exact literal source filters and continuation", async () => {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: { items: [] } });
  const params = {
    q: "tail%_",
    scan_status: "scanned",
    severity: "critical",

    sort: "vulnerabilities",
    order: "desc" as const,
    limit: 100,
    offset: 3000,
  };
  await registries.images("registry/id", params);
  expect(get).toHaveBeenCalledWith("/registries/registry%2Fid/images", {
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
    registries.imagesCSV("registry", {
      q: "tail",
      scan_status: "scanned",
      sort: "vulnerabilities",
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
  expect(get).toHaveBeenCalledWith("/registries/registry/images.csv", {
    params: {
      q: "tail",
      scan_status: "scanned",
      sort: "vulnerabilities",
      order: "desc",
    },
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
  await expect(registries.imagesCSV("registry")).rejects.toThrow(
    "scope could not be confirmed",
  );
  expect(click).not.toHaveBeenCalled();
});
