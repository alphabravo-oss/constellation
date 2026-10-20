import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { baselines, type BaselineInventoryRow, type BaselineInventoryParams, type BaselineDetail } from "@/api/client";
import { TestRouter } from "@/test/router";
import { BaselinesPage } from "../BaselinesPage";
import { BaselineDetailPage } from "./BaselineDetailPage";
import { BaselineRuleFormPage } from "./BaselineRuleFormPage";
import { BaselineActionFormPage } from "./BaselineActionFormPage";
const scope=vi.hoisted(()=>({clusterId:"cluster" as string|undefined,cluster:{id:"cluster"} as {id:string}|undefined,isLoading:false,error:null as Error|null}));
vi.mock("@/hooks/useCluster",()=>({useCluster:()=>scope}));
vi.mock("@/api/client",()=>({baselines:{list:vi.fn(),inventory:vi.fn(),inventoryCSV:vi.fn(),get:vi.fn(),setMode:vi.fn(),createRule:vi.fn(),updateRule:vi.fn(),deleteRule:vi.fn()}}));
vi.mock("@/contexts/TablePreferencesContext",()=>({useTablePreferencesIdentity:()=>({org_id:"org",user_id:"operator"})}));
const fixture=():BaselineDetail=>({workload_id:"default/api",cluster_id:"cluster",namespace:"default",name:"api",mode:"learn",learned_processes_count:1,monitored_alerts_24h:2,enforced_blocks_24h:0,processes:[{name:"nginx",path:"/bin/nginx",args:["-g","daemon off"],observed_count:2,first_seen:"2026-10-01T00:00:00Z",last_seen:"2026-10-12T00:00:00Z"}],transitions:[],rules:[{rule_id:"rule",name:"nginx",path:"/bin/nginx",action:"deny",user:"1000",sha256:"abc",parent_name:"init",allow_update:true,enabled:false,description:"retained description",updated_at:"2026-10-12T00:00:00.123456Z"}]});
function inventory(profiles: BaselineDetail[], request: BaselineInventoryParams) {
 const rows = profiles.filter(p=>!request.q||`${p.namespace}/${p.name}`.toLowerCase().includes(request.q)).map(p=>({...p,cluster_id:"cluster",row_id:JSON.stringify(["cluster",p.workload_id]),owner_count:1,owner_ambiguous:false,platform_role:"",configured:true,rule_count:p.rules.length} satisfies BaselineInventoryRow));
 const total=rows.length,offset=request.offset??0;
 return {profiles:rows.slice(offset,offset+100),total,limit:100,offset,has_more:offset+100<total,sort:request.sort??"workload",order:request.order??"asc",cluster_id:"cluster",filters:{q:request.q??"",namespace:request.namespace??"",mode:request.mode??"",hide_platform:request.hide_platform??false},namespaces:["default"],source_complete:true,summary_scope:"matching_retained_process_events",summary:{total,learn:total,monitor:0,enforce:0,processes:total,alerts_24h:2*total,blocks_24h:0,rules:total,ambiguous_owners:0}};
}
let root:Root|undefined;let host:HTMLDivElement;let client:QueryClient;let history:RouterHistory;
beforeEach(()=>{(globalThis as typeof globalThis&{IS_REACT_ACT_ENVIRONMENT:boolean}).IS_REACT_ACT_ENVIRONMENT=true;Object.assign(scope,{clusterId:"cluster",cluster:{id:"cluster"},isLoading:false,error:null});vi.mocked(baselines.get).mockResolvedValue(fixture());vi.mocked(baselines.inventory).mockImplementation(async params=>inventory([fixture()],params));vi.mocked(baselines.list).mockResolvedValue({profiles:[fixture()],summary:{total:1,learn:1,monitor:0,enforce:0}});vi.mocked(baselines.setMode).mockImplementation(async(_w,body)=>({...fixture(),mode:body.mode}));vi.mocked(baselines.createRule).mockImplementation(async(_w,body)=>({...fixture().rules[0],...body,rule_id:"new-rule"}));vi.mocked(baselines.updateRule).mockImplementation(async(_w,id,body)=>({...fixture().rules[0],...body,rule_id:id}));vi.mocked(baselines.deleteRule).mockImplementation(async(_w,id)=>({deleted:id}));});
afterEach(()=>{act(()=>root?.unmount());root=undefined;client?.clear();host?.remove();vi.resetAllMocks();});
async function render(element:ReactNode,path:string,url:string){host=document.createElement("div");document.body.appendChild(host);root=createRoot(host);client=new QueryClient({defaultOptions:{queries:{retry:false}}});history=createMemoryHistory({initialEntries:[url]});await act(async()=>root!.render(<QueryClientProvider client={client}><TestRouter history={history} path={path} next={{path:"/clusters/$clusterId/runtime/baselines/$baselineId",element:<p>Returned baseline</p>}}>{element}</TestRouter></QueryClientProvider>));}
const rulePath="/clusters/$clusterId/runtime/baselines/$baselineId/rules/$ruleId/edit";
const newPath="/clusters/$clusterId/runtime/baselines/$baselineId/rules/new";
const actionPath="/clusters/$clusterId/runtime/baselines/$baselineId/actions/$action";
const base="/clusters/cluster/runtime/baselines/default%2Fapi";
async function edit(){await render(<BaselineRuleFormPage/>,rulePath,`${base}/rules/rule/edit`);await settled(()=>expect(host.querySelector("form")).not.toBeNull());}
async function settled(check:()=>void){await vi.waitFor(async()=>{await act(async()=>{});check();});}
const button=(name:string)=>[...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === name || b.getAttribute("aria-label") === name)!;
function field(label:string):HTMLInputElement|HTMLSelectElement{return [...host.querySelectorAll("label")].find(e=>e.querySelector("span")?.textContent===label)!.querySelector("input,select")!;}
async function input(label:string,value:string){await act(async()=>{const el=field(label);const type=el instanceof HTMLSelectElement?HTMLSelectElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(type,"value")!.set!.call(el,value);el.dispatchEvent(new Event(el instanceof HTMLSelectElement?"change":"input",{bubbles:true}));});}
async function submit(){await act(async()=>host.querySelector("form")!.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true})));}
const writes=()=>[baselines.setMode,baselines.createRule,baselines.updateRule,baselines.deleteRule];
it.each(["loading","foreign","error"])("gates list/detail/form queries for %s cluster",async condition=>{
 if(condition==="loading")scope.isLoading=true;if(condition==="foreign")scope.cluster={id:"other"};if(condition==="error")scope.error=new Error("cluster unavailable");
 await render(<><BaselinesPage/><BaselineDetailPage/><BaselineRuleFormPage/></>,newPath,`${base}/rules/new`);await settled(()=>expect(host.textContent).toContain(condition==="error"?"Could not resolve":"Resolving cluster"));expect(baselines.inventory).not.toHaveBeenCalled();expect(baselines.get).not.toHaveBeenCalled();for(const fn of writes())expect(fn).not.toHaveBeenCalled();
});
it("renders errors instead of zero coverage or empty healthy lifecycle columns",async()=>{
 vi.mocked(baselines.inventory).mockRejectedValue(new Error("source failed"));await render(<BaselinesPage/>,"/clusters/$clusterId/runtime/baselines","/clusters/cluster/runtime/baselines");await settled(()=>expect(host.textContent).toContain("Could not load or refresh process profiles"));expect(host.querySelector('[data-testid="baselines-table"]')).toBeNull();expect(host.querySelector('[data-testid="baselines-columns"]')).toBeNull();expect(host.textContent).toContain("evidence unavailable");
});
it("filters every returned profile beyond the former first-page range with URL state",async()=>{
 const profiles=Array.from({length:501},(_,i)=>({...fixture(),workload_id:`default/workload-${i}`,name:`workload-${i}`}));vi.mocked(baselines.inventory).mockImplementation(async params=>inventory(profiles,params));
 await render(<BaselinesPage/>,"/clusters/$clusterId/runtime/baselines","/clusters/cluster/runtime/baselines?q=workload-500");await settled(()=>expect(host.querySelector('[data-testid="baselines-card-default/workload-500"]')).not.toBeNull());expect(host.textContent).toContain("1 matching workload profiles");expect(baselines.inventory).toHaveBeenCalledWith(expect.objectContaining({q:"workload-500",limit:100,offset:0}));expect(host.querySelectorAll("tbody tr")).toHaveLength(1);expect(host.querySelector('a[href$="default%2Fworkload-500"]')).not.toBeNull();
});
it("suppresses cached inventory rows after refresh fails",async()=>{
 await render(<BaselinesPage/>,"/clusters/$clusterId/runtime/baselines","/clusters/cluster/runtime/baselines");await settled(()=>expect(host.querySelector("tbody tr")).not.toBeNull());vi.mocked(baselines.inventory).mockRejectedValue(new Error("refresh failed"));await act(async()=>{await client.invalidateQueries({queryKey:["baselines-inventory"]});});await settled(()=>expect(host.textContent).toContain("Could not load or refresh process profiles"));expect(host.querySelector("tbody")).toBeNull();
});
it.each(["cluster","workload"])("rejects foreign %s profile before exposing editor",async key=>{
 vi.mocked(baselines.get).mockResolvedValue({...fixture(),[key==="cluster"?"cluster_id":"workload_id"]:"other"});await render(<BaselineRuleFormPage/>,newPath,`${base}/rules/new`);await settled(()=>expect(host.textContent).toContain("unavailable for the exact workload"));expect(host.querySelector("form")).toBeNull();
});
it("preserves all supported expert matching fields on edit and passes exact revision/scope",async()=>{
 await edit();await input("Process name","edited-nginx");await submit();await settled(()=>expect(baselines.updateRule).toHaveBeenCalledWith("default/api","rule",{name:"edited-nginx",path:"/bin/nginx",action:"deny",user:"1000",sha256:"abc",parent_name:"init",allow_update:true,enabled:false,description:"retained description",expected_updated_at:"2026-10-12T00:00:00.123456Z"},{cluster_id:"cluster"}));await settled(()=>expect(history.location.search).toBe("?tab=rules"));
});
it("creates a distinct rule safely and Cancel returns to exact configured-rules tab without writing",async()=>{
 await render(<BaselineRuleFormPage/>,newPath,`${base}/rules/new`);await settled(()=>expect(host.querySelector("form")).not.toBeNull());expect(button("Save").disabled).toBe(true);await input("Executable path","/bin/new");await submit();await settled(()=>expect(baselines.createRule).toHaveBeenCalledWith("default/api",expect.objectContaining({name:"",path:"/bin/new",require_absent:true}),{cluster_id:"cluster"}));
});
it("Cancel preserves exact workload context and makes no mutation",async()=>{await edit();await input("Process name","draft");await act(async()=>button("Cancel").click());await settled(()=>expect(history.location.pathname).toBe(base));expect(history.location.search).toBe("?tab=rules");for(const fn of writes())expect(fn).not.toHaveBeenCalled();});
it("requires an adjacent reviewed mode and sends its server precondition",async()=>{
 await render(<BaselineActionFormPage/>,actionPath,`${base}/actions/mode?mode=monitor`);await settled(()=>expect(host.querySelector("form")).not.toBeNull());expect(button("Save").disabled).toBe(true);await input("Reason","validated observation");await submit();await settled(()=>expect(baselines.setMode).toHaveBeenCalledWith("default/api",{mode:"monitor",reason:"validated observation",expected_mode:"learn"},{cluster_id:"cluster"}));await settled(()=>expect(history.location.search).toBe("?tab=history"));
});
it("confirms exact rule removal with the current server timestamp",async()=>{
 await render(<BaselineActionFormPage/>,actionPath,`${base}/actions/delete-rule?rule=rule`);await settled(()=>expect(host.querySelector("form")).not.toBeNull());expect(button("Remove rule").disabled).toBe(true);await act(async()=>host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());await submit();await settled(()=>expect(baselines.deleteRule).toHaveBeenCalledWith("default/api","rule",{cluster_id:"cluster",expected_updated_at:"2026-10-12T00:00:00.123456Z"}));
});
it("retains editable draft on failed refresh and failed save",async()=>{
 await edit();await input("Process name","retained draft");vi.mocked(baselines.get).mockRejectedValue(new Error("refresh failed"));await act(async()=>{await client.invalidateQueries({queryKey:["baseline"]});});await settled(()=>expect(host.textContent).toContain("Your draft is preserved; refresh before saving"));expect(field("Process name").value).toBe("retained draft");expect(button("Save").disabled).toBe(true);vi.mocked(baselines.get).mockResolvedValue(fixture());await act(async()=>button("Retry").click());await settled(()=>expect(button("Save").disabled).toBe(false));vi.mocked(baselines.updateRule).mockRejectedValue(new Error("server revision conflict"));await submit();await settled(()=>expect(host.textContent).toContain("server revision conflict"));expect(field("Process name").value).toBe("retained draft");
});
it("retains draft when selected rule disappears and requires review of changed source",async()=>{
 await edit();await input("Process name","retained draft");await act(async()=>client.setQueryData(["baseline","default/api","cluster"],{...fixture(),rules:[]}));await settled(()=>expect(button("Save").disabled).toBe(true));expect(field("Process name").value).toBe("retained draft");expect(host.textContent).toContain("selected profile or rule");
});
it.each(["registry","invalidated","fetching","error","foreign","revision"])("rechecks %s at submit before React updates",async condition=>{
 await edit();await input("Process name","retained draft");await act(async()=>{const query=client.getQueryCache().find({queryKey:["baseline","default/api","cluster"],exact:true})!;if(condition==="registry")client.setQueryData(["clusters"],{clusters:[{id:"other"}]});if(condition==="invalidated")query.setState({isInvalidated:true});if(condition==="fetching")query.setState({fetchStatus:"fetching"});if(condition==="error")query.setState({status:"error",error:new Error("unavailable")});if(condition==="foreign")client.setQueryData(query.queryKey,{...fixture(),cluster_id:"other"});if(condition==="revision")client.setQueryData(query.queryKey,{...fixture(),mode:"monitor"});host.querySelector("form")!.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}));});await settled(()=>expect(host.querySelector('[data-testid="error-state"]')).not.toBeNull());expect(baselines.updateRule).not.toHaveBeenCalled();expect(field("Process name").value).toBe("retained draft");
});
it("keeps a failed refetch from presenting cached detail as current evidence",async()=>{
 await render(<BaselineDetailPage/>,"/clusters/$clusterId/runtime/baselines/$baselineId/view",`${base}/view?tab=rules`);await settled(()=>expect(host.querySelector('[data-testid="baseline-rules-table"]')).not.toBeNull());vi.mocked(baselines.get).mockRejectedValue(new Error("source offline"));await act(async()=>{await client.invalidateQueries({queryKey:["baseline"]});});await settled(()=>expect(host.textContent).toContain("Could not load or refresh this profile"));expect(host.querySelector('[data-testid="baseline-rules-table"]')).toBeNull();
});
it("requires explicit review after current configuration changes without replacing user draft",async()=>{
 await edit();await input("Process name","retain this draft");await act(async()=>client.setQueryData(["baseline","default/api","cluster"],{...fixture(),mode:"monitor"}));await settled(()=>expect(button("Save").disabled).toBe(true));await act(async()=>button("Review current state").click());expect(field("Process name").value).toBe("retain this draft");await settled(()=>expect(button("Save").disabled).toBe(false));await submit();await settled(()=>expect(baselines.updateRule).toHaveBeenCalledTimes(1));
});
it("blocks a duplicate match on the dedicated new rule page",async()=>{
 await render(<BaselineRuleFormPage/>,newPath,`${base}/rules/new`);await settled(()=>expect(host.querySelector("form")).not.toBeNull());await input("Process name","nginx");await input("Executable path","/bin/nginx");expect(button("Save").disabled).toBe(true);expect(host.textContent).toContain("already exists. Edit that rule");await submit();expect(baselines.createRule).not.toHaveBeenCalled();
});
it("does not submit twice while the reviewed write is pending",async()=>{
 let done!:()=>void;vi.mocked(baselines.updateRule).mockImplementation(()=>new Promise(resolve=>{done=()=>resolve({...fixture().rules[0],name:"once"});}));await edit();await input("Process name","once");await act(async()=>{const form=host.querySelector("form")!;form.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}));form.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}));});await settled(()=>expect(baselines.updateRule).toHaveBeenCalledTimes(1));await settled(()=>expect(button("Saving…")?.disabled).toBe(true));expect(button("Cancel").disabled).toBe(true);await act(async()=>done());await settled(()=>expect(host.textContent).toContain("Returned baseline"));
});
it("gates unavailable initial rules without loading an authoring form",async()=>{
 vi.mocked(baselines.get).mockResolvedValue({...fixture(),rules:[]});await render(<BaselineActionFormPage/>,actionPath,`${base}/actions/delete-rule?rule=rule`);await settled(()=>expect(host.textContent).toContain("unavailable for the exact workload"));expect(host.querySelector("form")).toBeNull();expect(baselines.deleteRule).not.toHaveBeenCalled();
});
it("does not redirect a later workspace when a pending reviewed save completes",async()=>{
 let done!:()=>void;vi.mocked(baselines.updateRule).mockImplementation(()=>new Promise(resolve=>{done=()=>resolve({...fixture().rules[0],name:"pending"});}));await edit();await input("Process name","pending");await submit();await settled(()=>expect(baselines.updateRule).toHaveBeenCalledTimes(1));await act(async()=>history.push(`${base}?tab=history`));await settled(()=>expect(host.textContent).toContain("Returned baseline"));await act(async()=>done());await settled(()=>expect(history.location.search).toBe("?tab=history"));
});
it.each(["rule-id","candidate"])("blocks duplicate writes after unconfirmed edit %s response",async condition=>{
 vi.mocked(baselines.updateRule).mockImplementation(async(_w,id,body)=>({...fixture().rules[0],...body,rule_id:condition==="rule-id"?"foreign":id,action:condition==="candidate"?"allow":body.action!}));await edit();await input("Process name","reviewed");await submit();await settled(()=>expect(host.textContent).toContain("response did not confirm"));expect(button("Save").disabled).toBe(true);expect(field("Process name").value).toBe("reviewed");await submit();expect(baselines.updateRule).toHaveBeenCalledTimes(1);expect(history.location.pathname).toContain("/rules/rule/edit");
});
it("blocks uncertain mode confirmation for a foreign cluster",async()=>{
 vi.mocked(baselines.setMode).mockResolvedValue({...fixture(),cluster_id:"other",mode:"monitor"});await render(<BaselineActionFormPage/>,actionPath,`${base}/actions/mode?mode=monitor`);await settled(()=>expect(host.querySelector("form")).not.toBeNull());await input("Reason","reviewed");await submit();await settled(()=>expect(host.textContent).toContain("response did not confirm"));expect(button("Save").disabled).toBe(true);expect(history.location.pathname).toContain("/actions/mode");
});
it("requires a returned identity when creating a new rule",async()=>{
 vi.mocked(baselines.createRule).mockImplementation(async(_w,body)=>({...fixture().rules[0],...body,rule_id:""}));await render(<BaselineRuleFormPage/>,newPath,`${base}/rules/new`);await settled(()=>expect(host.querySelector("form")).not.toBeNull());await input("Process name","new");await submit();await settled(()=>expect(host.textContent).toContain("response did not confirm"));expect(button("Save").disabled).toBe(true);await submit();expect(baselines.createRule).toHaveBeenCalledTimes(1);
});
it("checks exact deleted identity before acknowledging rule removal",async()=>{
 vi.mocked(baselines.deleteRule).mockResolvedValue({deleted:"other-rule"});await render(<BaselineActionFormPage/>,actionPath,`${base}/actions/delete-rule?rule=rule`);await settled(()=>expect(host.querySelector("form")).not.toBeNull());await act(async()=>host.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());await submit();await settled(()=>expect(host.textContent).toContain("response did not confirm"));expect(button("Remove rule").disabled).toBe(true);
});
it("confirms normalized executable hashes without misreporting a successful edit",async()=>{
 await edit();await act(async()=>host.querySelector<HTMLElement>("summary")!.click());await input("Executable SHA-256","ABCDEF");await submit();await settled(()=>expect(baselines.updateRule).toHaveBeenCalledWith("default/api","rule",expect.objectContaining({sha256:"abcdef"}),{cluster_id:"cluster"}));await settled(()=>expect(host.textContent).toContain("Returned baseline"));
});
