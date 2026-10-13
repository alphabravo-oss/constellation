import { afterEach, expect, it, vi } from "vitest";
import { api, networkRules } from "./client";
afterEach(() => vi.restoreAllMocks());
const headers = {
  "x-export-total": "5205",
  "x-export-limit": "100000",
  "x-export-truncated": "false",
};
function downloads() {
  const create = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:rules");
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  return { create, click };
}
it("uses additive inventory without falling back to the capped compatibility endpoint", async () => {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: { total: 5205 } });
  const params = {
    q: "literal_%",
    from: "team/app",
    status: "disabled",
    sort: "matches",
    order: "desc" as const,
    offset: 5200,
    limit: 100,
  };
  await networkRules.inventory("cluster/id", params);
  expect(get).toHaveBeenCalledExactlyOnceWith(
    "/clusters/cluster%2Fid/network-rules/inventory",
    { params },
  );
});
it("matching CSV carries exact filters and server order while omitting page bounds", async () => {
  const get = vi
    .spyOn(api, "get")
    .mockResolvedValue({ data: new Blob(["row_id,from\n"]), headers });
  const { click } = downloads();
  const params = {
    q: "literal_%",
    from: "team/app",
    to: "team/db",
    action: "deny",
    status: "disabled",
    cfg_type: "learned_override",
    hide_platform: true,
    sort: "matches",
    order: "desc" as const,
    limit: 100,
    offset: 5200,
  };
  await expect(
    networkRules.inventoryCSV("cluster", params, () => true),
  ).resolves.toEqual({
    total: 5205,
    exported: 5205,
    limit: 100000,
    truncated: false,
  });
  const { limit: _limit, offset: _offset, ...filters } = params;
  expect(get).toHaveBeenCalledWith(
    "/clusters/cluster/network-rules/inventory.csv",
    { params: filters, responseType: "blob" },
  );
  expect(click).toHaveBeenCalledOnce();
});
it.each([
  {},
  { ...headers, "x-export-total": "NaN" },
  { ...headers, "x-export-truncated": "true" },
])(
  "rejects missing or inconsistent matching export metadata",
  async (metadata) => {
    vi.spyOn(api, "get").mockResolvedValue({
      data: new Blob(),
      headers: metadata,
    });
    const { create, click } = downloads();
    await expect(
      networkRules.inventoryCSV("cluster", {}, () => true),
    ).rejects.toThrow("Export scope could not be confirmed");
    expect(create).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  },
);
it("withholds a returned CSV after the reviewed source becomes unavailable", async () => {
  let respond!: () => void;
  vi.spyOn(api, "get").mockImplementation(
    () =>
      new Promise((resolve) => {
        respond = () => resolve({ data: new Blob(), headers });
      }),
  );
  const { create, click } = downloads();
  let current = true;
  const exporting = networkRules.inventoryCSV(
    "cluster",
    { action: "deny" },
    () => current,
  );
  const rejected = expect(exporting).rejects.toThrow("Refresh the inventory");
  current = false;
  respond();
  await rejected;
  expect(create).not.toHaveBeenCalled();
  expect(click).not.toHaveBeenCalled();
});
