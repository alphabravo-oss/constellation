import { afterEach, expect, it, vi } from "vitest";
import { api, imageScanResults, repositoryScans, serverlessFunctions } from "./client";
afterEach(() => vi.restoreAllMocks());
it.each(["images", "repositories", "serverless"])("preserves all %s server filters, ordering and continuation metadata", async family => {
 const response = { total: 250, has_more: true, summary: { total: 250 }, limit: 100, offset: 100 };
 const get = vi.spyOn(api, "get").mockResolvedValue({ data: response });
 const params = { q: "literal%_value", sort: "scan", order: "asc" as const, limit: 100, offset: 100 };
 if (family === "images") await expect(imageScanResults.list({ ...params, cluster_id: "cluster", severity: "critical" })).resolves.toEqual(response);
 else if (family === "repositories") await expect(repositoryScans.list({ ...params, status: "failed", branch: "main", workflow: "build" })).resolves.toEqual(response);
 else await expect(serverlessFunctions.list({ ...params, posture: "high", provider: "aws", account_id: "account", region: "region" })).resolves.toEqual(response);
 expect(get.mock.calls[0][1]?.params).toEqual(expect.objectContaining(params));
});
it.each(["images", "repositories", "serverless"])("exports all matching %s filters and order while omitting page bounds", async family => {
 const get = vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["ID\n1\n"], { type: "text/csv" }), headers: { "x-export-total": "250", "x-export-limit": "100000", "x-export-truncated": "false" } });
 vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:inventory"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
 const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 const params = { q: "literal%_value", sort: "scan", order: "asc" as const, limit: 100, offset: 900 };
 const result = family === "images" ? await imageScanResults.exportCSV({ ...params, severity: "critical", cluster_id: "cluster" }) : family === "repositories" ? await repositoryScans.exportCSV({ ...params, status: "failed" }) : await serverlessFunctions.exportCSV({ ...params, posture: "high" });
 expect(result).toEqual({ total: 250, exported: 250, limit: 100000, truncated: false });
 expect(get.mock.calls[0][0]).toContain("/export.csv"); const sent = get.mock.calls[0][1]?.params;
 expect(sent).toEqual(expect.objectContaining({ q: params.q, sort: "scan", order: "asc" })); expect(sent).not.toHaveProperty("offset"); expect(sent).not.toHaveProperty("limit"); expect(click).toHaveBeenCalledOnce();
});
it("reports an explicit matching-export cap", async () => {
 vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["ID\n"]), headers: { "x-export-total": "100001", "x-export-limit": "100000", "x-export-truncated": "true" } }); vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:inventory"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {}); vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 await expect(imageScanResults.exportCSV()).resolves.toEqual({ total: 100001, exported: 100000, limit: 100000, truncated: true });
});
it.each([{}, { "x-export-total": "250", "x-export-limit": "100000", "x-export-truncated": "true" }])("rejects unconfirmed export scope without initiating a download", async headers => {
 vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["ID\n"]), headers }); const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 await expect(imageScanResults.exportCSV()).rejects.toThrow("Export scope could not be confirmed"); expect(click).not.toHaveBeenCalled();
});
