import { afterEach, expect, it, vi } from "vitest";
import { api, downloadLookaheadCSV } from "./client";

afterEach(() => vi.restoreAllMocks());
const headers = { "x-export-rows": "205", "x-export-limit": "100000", "x-export-truncated": "false" };
function downloads() {
  const create = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export");
  const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  return { create, revoke, click };
}
it.each([
  [headers, { exported: 205, limit: 100000, truncated: false }],
  [{ ...headers, "x-export-rows": "100000", "x-export-truncated": "true" }, { exported: 100000, limit: 100000, truncated: true }],
  [{ ...headers, "x-export-rows": "0" }, { exported: 0, limit: 100000, truncated: false }],
])("downloads matching records only with confirmed lookahead metadata", async (metadata, result) => {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["ID\n1\n"]), headers: metadata });
  const { click, revoke } = downloads();
  await expect(downloadLookaheadCSV("/audit/events.csv", { action: "login" }, "audit.csv", () => true)).resolves.toEqual(result);
  expect(get).toHaveBeenCalledWith("/audit/events.csv", { params: { action: "login" }, responseType: "blob" });
  expect(click).toHaveBeenCalledOnce(); expect(revoke).toHaveBeenCalledWith("blob:export");
});
it.each([
  {}, { ...headers, "x-export-rows": "-1" }, { ...headers, "x-export-rows": "9007199254740992" },
  { ...headers, "x-export-limit": "0" }, { ...headers, "x-export-limit": "20", "x-export-rows": "20" }, { ...headers, "x-export-rows": "100001" },
  { ...headers, "x-export-truncated": "unknown" }, { ...headers, "x-export-truncated": "true" },
])("rejects missing or inconsistent export evidence", async metadata => {
  vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(), headers: metadata });
  const { create, click } = downloads();
  await expect(downloadLookaheadCSV("/audit/events.csv", {}, "audit.csv", () => true)).rejects.toThrow("scope could not be confirmed");
  expect(create).not.toHaveBeenCalled(); expect(click).not.toHaveBeenCalled();
});
it("withholds a completed response if its reviewed evidence is no longer current", async () => {
  let respond!: () => void;
  vi.spyOn(api, "get").mockImplementation(() => new Promise(resolve => { respond = () => resolve({ data: new Blob(), headers }); }));
  const { create, click } = downloads();
  let current = true;
  const result = downloadLookaheadCSV("/audit/events.csv", {}, "audit.csv", () => current);
  const rejected = expect(result).rejects.toThrow("Refresh the inventory");
  current = false; respond(); await rejected;
  expect(create).not.toHaveBeenCalled(); expect(click).not.toHaveBeenCalled();
});
