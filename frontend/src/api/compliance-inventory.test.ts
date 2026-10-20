import { afterEach, expect, it, vi } from "vitest";
import { api, compliance } from "./client";
afterEach(() => vi.restoreAllMocks());
it("preserves positional compliance callers and supports exact control lookup", async () => {
 const get = vi.spyOn(api,"get").mockResolvedValue({data:{checks:[]}});
 await compliance.checks("cis","cluster",{control_id:"late-control"});expect(get).toHaveBeenCalledWith("/compliance/checks",{params:{framework:"cis",cluster_id:"cluster",control_id:"late-control"}});
});
it("passes cross-framework cohort, literal search, sort and page unchanged", async () => {
 const get = vi.spyOn(api,"get").mockResolvedValue({data:{checks:[],total:205,has_more:true,summary:{pass:150,fail:55}}});
 const params = {framework:"all",cluster_id:"cluster",status:"graded",q:"literal%_",sort:"framework",order:"desc" as const,limit:100,offset:100};
 await expect(compliance.checks(params)).resolves.toEqual(expect.objectContaining({total:205}));expect(get).toHaveBeenCalledWith("/compliance/checks",{params});
});
it("exports the entire matching cohort and order, independent of visible page", async () => {
 const get = vi.spyOn(api,"get").mockResolvedValue({data:new Blob(["Evidence ID\n1\n"]),headers:{"x-export-total":"205","x-export-limit":"100000","x-export-truncated":"false"}});
 vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:compliance");vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{});const click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});
 await expect(compliance.exportChecksCSV({framework:"all",status:"graded",cluster_id:"cluster",q:"literal%_",sort:"control",order:"desc",profile:"profile",limit:100,offset:900})).resolves.toEqual({total:205,exported:205,limit:100000,truncated:false});
 expect(get).toHaveBeenCalledWith("/compliance/checks/export.csv",{params:{framework:"all",status:"graded",cluster_id:"cluster",q:"literal%_",sort:"control",order:"desc",profile:"profile"},responseType:"blob"});expect(click).toHaveBeenCalledOnce();
});
it.each([{}, {"x-export-total":"","x-export-limit":"100000","x-export-truncated":"false"},{"x-export-total":"205","x-export-limit":"100000","x-export-truncated":"true"}])("refuses unconfirmed or contradictory CSV metadata", async headers => {
 vi.spyOn(api,"get").mockResolvedValue({data:new Blob(["Evidence ID\n"]),headers});const click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});await expect(compliance.exportChecksCSV({status:"graded"})).rejects.toThrow("Compliance export scope could not be confirmed");expect(click).not.toHaveBeenCalled();
});
it("reports the matching export bound without claiming completeness", async () => {
 vi.spyOn(api,"get").mockResolvedValue({data:new Blob(["Evidence ID\n"]),headers:{"x-export-total":"100001","x-export-limit":"100000","x-export-truncated":"true"}});vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:compliance");vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{});vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});
 await expect(compliance.exportChecksCSV({status:"graded"})).resolves.toEqual({total:100001,exported:100000,limit:100000,truncated:true});
});
