import { afterEach, expect, it, vi } from "vitest";
import { api, findings } from "./client";

afterEach(() => { vi.restoreAllMocks(); });
it("passes paging, complete DSL, and global ordering through the findings client", async () => {
  const result = { findings: [], total: 901, has_more: true, limit: 100, offset: 600, lifecycle_counts: { open: 901 } };
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: result });
  const params = { cluster_id: "cluster", target_type: "image-workload", group_mode: "protect", id_scope: "all" as const, kind: "vulnerability" as const, lifecycle: "open" as const, q: "pkg:openssl !kev:true", fixable: true, limit: 100, offset: 600, sort: "age", order: "asc" as const };
  await expect(findings.list(params)).resolves.toEqual(result);
  expect(get).toHaveBeenCalledWith("/findings", { params: { ...params, fixable: "1" } });
});
it("preserves the DSL in the CVE rollup request", async () => {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: { cves: [], total: 901, limit: 100, offset: 600 } });
  await findings.byCVE({ cluster_id: "cluster", target_type: "image-workload", group_mode: "protect", id_scope: "all" as const, q: "package:openssl !kev:true", fixable: true, limit: 100, offset: 600 });
  expect(get).toHaveBeenCalledWith("/findings/by-cve", { params: { cluster_id: "cluster", target_type: "image-workload", group_mode: "protect", id_scope: "all" as const, q: "package:openssl !kev:true", fixable: "true", limit: 100, offset: 600 } });
});
it("encodes export filters safely and downloads the authenticated instance CSV", async () => {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["id,title\n1,title"], { type: "text/csv" }), headers: { "content-disposition": 'attachment; filename="findings.csv"' } });
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export"); const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  const anchor = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { expect(this.download).toBe("findings.csv"); });
  await findings.exportCSV({ cluster_id: "cluster", target_type: "image-workload", group_mode: "protect", id_scope: "all" as const, lifecycle: "accepted", q: 'package:"a&b" !kev:true', fixable: true, limit: 100000, offset: 0, sort: "title", order: "asc" });
  const [path, options] = get.mock.calls[0];
  const url = new URL(String(path), "https://example.test");
  expect(url.pathname).toBe("/findings.csv"); expect(Object.fromEntries(url.searchParams)).toEqual({ cluster_id: "cluster", target_type: "image-workload", group_mode: "protect", id_scope: "all" as const, lifecycle: "accepted", q: 'package:"a&b" !kev:true', fixable: "1", limit: "100000", offset: "0", sort: "title", order: "asc" });
  expect(options).toEqual({ responseType: "blob" }); expect(anchor).toHaveBeenCalledOnce(); expect(revoke).toHaveBeenCalledWith("blob:export");
});
it("does not trigger a download when the filtered export fails", async () => {
  vi.spyOn(api, "get").mockRejectedValue(new Error("export unavailable"));
  const anchor = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  await expect(findings.exportCSV({ q: "unknown:value" })).rejects.toThrow("export unavailable"); expect(anchor).not.toHaveBeenCalled();
});
it('uses exact observation paths and reviewed revisions without timestamp rounding or legacy fallback', async () => {
  const selector = { first_seen_at: '2026-01-01T00:00:00.123457Z', cluster_id: 'target' };
  const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { id: 'finding' } });
  const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { status: 'ok' } });
  await findings.instance('finding', selector); await findings.instanceComments('finding', selector);
  await findings.instanceSuppress('finding', selector, { reviewed_revision: '9223372036854775806', reason: 'Reviewed exact record' });
  expect(get).toHaveBeenNthCalledWith(1, '/finding-instances/finding', { params: selector }); expect(get).toHaveBeenNthCalledWith(2, '/finding-instances/finding/comments', { params: selector });
  expect(post).toHaveBeenCalledWith('/finding-instances/finding/suppress', { reviewed_revision: '9223372036854775806', reason: 'Reviewed exact record' }, { params: selector });
  get.mockRejectedValueOnce({ response: { status: 404 } }); await expect(findings.instance('finding', selector)).rejects.toEqual({ response: { status: 404 } }); expect(get.mock.calls.at(-1)?.[0]).toBe('/finding-instances/finding');
});
