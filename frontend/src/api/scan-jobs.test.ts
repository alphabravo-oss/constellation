import { afterEach, expect, it, vi } from "vitest";
import { api, scanJobs } from "./client";
afterEach(()=>vi.restoreAllMocks());
it("forwards all scan job filters and continuation",async()=>{
 const get=vi.spyOn(api,"get").mockResolvedValue({data:{jobs:[]}});
 const params={q:"literal%_",status:"failed",target_type:"image",cluster_id:"cluster",registry_id:"registry",sort:"findings",order:"asc" as const,limit:100,offset:600};
 await scanJobs.list(params);expect(get).toHaveBeenCalledWith("/scan-jobs",{params});
});
it("exports the matching job scope independently of the visible page",async()=>{
 const get=vi.spyOn(api,"get").mockResolvedValue({data:new Blob(["CSV"]),headers:{"x-export-total":"325","x-export-limit":"100000","x-export-truncated":"false"}});
 vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:jobs");vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{});const click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});
 await expect(scanJobs.exportCSV({q:"literal%_",status:"failed",sort:"requested",order:"desc",limit:100,offset:600})).resolves.toEqual({total:325,exported:325,limit:100000,truncated:false});
 expect(get).toHaveBeenCalledWith("/scan-jobs.csv",{params:{q:"literal%_",status:"failed",sort:"requested",order:"desc"},responseType:"blob"});expect(click).toHaveBeenCalledOnce();
});
it.each([{}, {"x-export-total":"","x-export-limit":"100000","x-export-truncated":"false"}, {"x-export-total":"1","x-export-limit":"100000","x-export-truncated":"true"}])("rejects ambiguous export metadata %j",async headers=>{
 vi.spyOn(api,"get").mockResolvedValue({data:new Blob(["CSV"]),headers});const click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});
 await expect(scanJobs.exportCSV()).rejects.toThrow("Export scope");expect(click).not.toHaveBeenCalled();
});
