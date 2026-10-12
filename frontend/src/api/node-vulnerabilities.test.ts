import { afterEach, expect, it, vi } from "vitest";
import { api, nodes } from "./client";

afterEach(() => vi.restoreAllMocks());
it("preserves exact node identity and forwards the full finding-instance inventory request", async () => {
 const get = vi.spyOn(api, "get").mockResolvedValue({ data: { items: [] } });
 const params = { q: "literal%_\\", severity: "critical", fixable: "true" as const, source: "scanner/type", sort: "package", order: "asc" as const, limit: 100, offset: 2000 };
 await nodes.vulnerabilities("cluster/id", "node%2Fname", params);
 expect(get).toHaveBeenCalledWith("/clusters/cluster%2Fid/nodes/node%252Fname/vulnerabilities", { params });
});
it("exports every matching instance independently of the currently loaded page", async () => {
 const get = vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["CSV"]), headers: { "x-export-total": "2053", "x-export-limit": "100000", "x-export-truncated": "false" } });
 vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:node-cves"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {}); const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 const params = { q: "literal%_\\", severity: "high", fixable: "false" as const, source: "grype", sort: "observed", order: "desc" as const, limit: 100, offset: 2000 };
 await expect(nodes.exportVulnerabilitiesCSV("cluster", "node%2Fname", params)).resolves.toEqual({ total: 2053, exported: 2053, limit: 100000, truncated: false });
 expect(get).toHaveBeenCalledWith("/clusters/cluster/nodes/node%252Fname/vulnerabilities.csv", { params: { q: "literal%_\\", severity: "high", fixable: "false", source: "grype", sort: "observed", order: "desc" }, responseType: "blob" }); expect(click).toHaveBeenCalledOnce();
});
it("withholds a CSV download when its completeness metadata is unavailable", async () => {
 vi.spyOn(api, "get").mockResolvedValue({ data: new Blob(["CSV"]), headers: {} }); const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 await expect(nodes.exportVulnerabilitiesCSV("cluster", "node")).rejects.toThrow("Export scope"); expect(click).not.toHaveBeenCalled();
});
