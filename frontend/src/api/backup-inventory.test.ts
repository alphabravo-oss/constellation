import { afterEach, expect, it, vi } from "vitest";
import { api, backupsApi } from "./client";
const receipt = {
  "x-export-total": "1",
  "x-export-limit": "100000",
  "x-export-truncated": "false",
  "x-export-org-id": "owned-org",
  "x-export-scope": "matching_owned_backup_runs",
};
afterEach(() => vi.restoreAllMocks());
it.each([
  { "x-export-org-id": undefined, "x-export-scope": undefined },
  { "x-export-org-id": undefined },
  { "x-export-org-id": "foreign-org" },
  { "x-export-org-id": "" },
  { "x-export-scope": undefined },
  { "x-export-scope": "all_backup_runs" },
  { "x-export-limit": "20" },
])(
  "rejects missing or mismatched backup CSV ownership/scope receipts before download: %j",
  async (overrides) => {
    vi.spyOn(api, "get").mockResolvedValue({
      data: new Blob(["id\nowned-run\n"]),
      headers: { ...receipt, ...overrides },
    });
    const createURL = vi
      .spyOn(URL, "createObjectURL")
      .mockReturnValue("blob:backup");
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    await expect(
      backupsApi.inventoryCSV({ status: "failed" }, "owned-org", () => true),
    ).rejects.toThrow("did not confirm");
    expect(createURL).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  },
);
it("downloads confirmed matching backup metadata with exact filters and independent page bounds", async () => {
  const get = vi
    .spyOn(api, "get")
    .mockResolvedValue({
      data: new Blob(["id\nowned-run\n"]),
      headers: receipt,
    });
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:backup");
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe("constellation-backup-metadata.csv");
    });
  await expect(
    backupsApi.inventoryCSV(
      {
        q: "needle%_",
        status: "failed",
        mode: "org-backup",
        signed: "false",
        sort: "size",
        order: "asc",
        limit: 100,
        offset: 200,
      },
      "owned-org",
      () => true,
    ),
  ).resolves.toEqual({
    total: 1,
    exported: 1,
    limit: 100000,
    truncated: false,
  });
  expect(get).toHaveBeenCalledExactlyOnceWith("/backups/inventory.csv", {
    params: {
      q: "needle%_",
      status: "failed",
      mode: "org-backup",
      signed: "false",
      sort: "size",
      order: "asc",
    },
    responseType: "blob",
  });
  expect(click).toHaveBeenCalledOnce();
});
it("requires an expected organization before dispatching a backup CSV request", async () => {
  const get = vi.spyOn(api, "get");
  await expect(backupsApi.inventoryCSV({}, "", () => true)).rejects.toThrow(
    "organization",
  );
  expect(get).not.toHaveBeenCalled();
});
it("keeps a valid backup CSV receipt from downloading after its reviewed source expires", async () => {
  vi.spyOn(api, "get").mockResolvedValue({
    data: new Blob(["id\nowned-run\n"]),
    headers: receipt,
  });
  const createURL = vi
    .spyOn(URL, "createObjectURL")
    .mockReturnValue("blob:backup");
  await expect(
    backupsApi.inventoryCSV({}, "owned-org", () => false),
  ).rejects.toThrow("Refresh the inventory");
  expect(createURL).not.toHaveBeenCalled();
});
