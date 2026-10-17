import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { componentsInventory, type ComponentInstance, type ComponentInventoryResponse, type ComponentsInventoryParams } from "@/api/client";
import { ComponentsPage } from "./ComponentsPage";
import { componentFixture } from "./components-inventory-fixture";
const scope=vi.hoisted(()=>({id:"cluster",resolved:"cluster",error:null as Error|null}));
vi.mock("@/hooks/useCluster",()=>({useCluster:()=>({clusterId:scope.id,cluster:{id:scope.resolved},isLoading:false,error:scope.error})}));
vi.mock("@/api/client",()=>({componentsInventory:{list:vi.fn(),get:vi.fn(),diagnostics:vi.fn(),exportCSV:vi.fn()},supportBundles:{createJob:vi.fn()}}));
let root:Root;let host:HTMLDivElement;let client:QueryClient;let history:RouterHistory;let identity={org_id:"org",user_id:"user"};
const component=(i:number):ComponentInstance=>({id:`instance-${i}`,cluster_id:scope.id,component:"runtime-agent",display_name:`Agent ${i}`,role:"enforcer",scope:"node",kind:"daemonset",hostname:`host-${i.toString().padStart(4,"0")}`,status:"healthy",version:`v${i}`,uptime_seconds:i,restart_count:0,metadata:{},first_seen_at:"2026-10-12T00:00:00Z",last_seen_at:"2026-10-12T00:00:00Z"});
function inventory(params:ComponentsInventoryParams):ComponentInventoryResponse{
 let components=Array.from({length:2005},(_,i)=>component(i));if(params.order==="desc")components=components.reverse();
 return componentFixture({components,summary:{generated_at:"2026-10-12T00:00:00Z",components:1,total_instances:2005,healthy:2005,degraded:0,stale:0,drift:0,crashlooping:0,missing:0},rollups:[{component:"scanner",display_name:"Scanner",role:"scanner",scope:"cluster",kind:"deployment",expected:true,status:"healthy",instances:1500,healthy:1500,degraded:0,stale:0,drift:0,crashlooping:0,missing:0,latest_version:"full-source-version",latest_commit:"full-source-commit",scanner_capacity:{active_jobs:3000,max_concurrent:6000,idle_capacity:3000}}]},params);
}
beforeEach(()=>{(globalThis as typeof globalThis&{IS_REACT_ACT_ENVIRONMENT:boolean}).IS_REACT_ACT_ENVIRONMENT=true;vi.clearAllMocks();localStorage.clear();Object.assign(scope,{id:"cluster",resolved:"cluster",error:null});identity={org_id:"org",user_id:"user"};vi.mocked(componentsInventory.list).mockImplementation(async params=>inventory(params!));vi.mocked(componentsInventory.exportCSV).mockResolvedValue({total:2005,exported:2005,limit:100000,truncated:false});vi.mocked(componentsInventory.get).mockRejectedValue(new Error("missing selected instance"));client=new QueryClient({defaultOptions:{queries:{retry:false},mutations:{retry:false}}});host=document.createElement("div");document.body.append(host);root=createRoot(host);});
afterEach(()=>{act(()=>root.unmount());client.clear();host.remove();vi.restoreAllMocks();localStorage.clear();});
async function render(search=""){history=createMemoryHistory({initialEntries:[`/clusters/cluster/components${search}`]});await rerender();}
async function rerender(){await act(async()=>root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{...identity}}><TestRouter history={history}><ComponentsPage /></TestRouter></TablePreferencesProvider></QueryClientProvider>));}
async function settle(check:()=>void){await vi.waitFor(async()=>{await act(async()=>{});check();});}
const rows=()=>host.querySelectorAll('[data-testid="component-inventory-table"] tbody tr');
const button=(label:string)=>[...host.querySelectorAll<HTMLButtonElement>("button")].find(item=>item.textContent?.trim()===label)!;
async function click(label:string){await act(async()=>{const target=button(label);if(target.getAttribute("role")==="tab")target.dispatchEvent(new MouseEvent("mousedown",{bubbles:true,button:0}));else target.click();});}
async function search(value:string){await act(async()=>{const input=host.querySelector<HTMLInputElement>('[aria-label="Search components"]')!;Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value")!.set!.call(input,value);input.dispatchEvent(new Event("input",{bubbles:true}));});}
it("continues beyond the old1000 cap with full health/role totals and matching export",async()=>{
 await render("?page=11&role=enforcer&context=keep");await settle(()=>expect(rows()).toHaveLength(100));expect(host.textContent).toContain("Agent 1000");expect(host.textContent).not.toContain("Agent 999");expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({offset:1000,limit:100,role:"enforcer"}));expect(host.querySelector('[data-testid="component-summary"]')!.textContent).toContain("2005");expect(host.textContent).toContain("2,005 instances match");
 await click("Export matching CSV");expect(componentsInventory.exportCSV).toHaveBeenCalledWith(expect.objectContaining({offset:1000,role:"enforcer"}), expect.any(Function));await settle(()=>expect(host.textContent).toContain("Exported all 2,005 matching records across pages"));await click("Next");await settle(()=>expect(host.textContent).toContain("Agent 1100"));expect(history.location.search).toContain("page=12");
});
it("queries a search match beyond the cap, resets page and retains repeated context/hash",async()=>{
 await render("?page=11&context=a&context=b#inventory");await settle(()=>expect(rows()).toHaveLength(100));const input=host.querySelector<HTMLInputElement>('[aria-label="Search components"]')!;input.focus();await search("host-2004");expect(host.querySelector('[aria-label="Search components"]')).toBe(input);expect(document.activeElement).toBe(input);await settle(()=>expect(rows()).toHaveLength(1));expect(host.textContent).toContain("Agent 2004");expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({q:"host-2004",offset:0}));const params=new URLSearchParams(history.location.search);expect(params.has("page")).toBe(false);expect(params.getAll("context")).toEqual(["a","b"]);expect(history.location.hash).toBe("#inventory");expect(host.querySelector('[data-testid="component-nv-role-enforcer"]')!.textContent).toContain("2005");
});
it("restores server sort and page on browser history with controlled headers",async()=>{
 await render("?page=11&sort=build&order=desc");await settle(()=>expect(rows()).toHaveLength(100));expect(host.querySelector('th[aria-sort="descending"]')!.textContent).toContain("Build");expect([...rows()][0].textContent).toContain("Agent 1004");await act(async()=>host.querySelector<HTMLButtonElement>('th[aria-sort="descending"] button')!.click());await settle(()=>expect(host.querySelector('th[aria-sort="ascending"]')).not.toBeNull());expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({sort:"build",order:"asc",offset:0}));await act(async()=>history.back());await settle(()=>expect(host.querySelector('th[aria-sort="descending"]')).not.toBeNull());expect(history.location.search).toContain("page=11");expect([...rows()][0].textContent).toContain("Agent 1004");
});
it("exposes hidden heartbeat sort rather than losing URL sort state",async()=>{
 await render("?sort=heartbeat&order=desc");await settle(()=>expect(rows()).toHaveLength(100));expect(host.textContent).toContain("Sorted by Last heartbeat (descending) · hidden column");
});
it("shows full version capacity independent of visible page and explicitly describes the24h source",async()=>{
 await render("?page=11&tab=versions");await settle(()=>expect(host.querySelector('[data-testid="component-version-matrix"]')).not.toBeNull());expect(host.textContent).toContain("3000/6000 active");expect(host.textContent).toContain("3000 idle");expect(host.textContent).toContain("full-source-version");expect(host.textContent).toContain("within the last 24 hours");expect(rows()).toHaveLength(0);
});
it("retains current rows/input during deferred refresh then hides failed evidence and CSV",async()=>{
 await render();await settle(()=>expect(rows()).toHaveLength(100));let reject!:(error:Error)=>void;vi.mocked(componentsInventory.list).mockImplementation(()=>new Promise((_resolve,no)=>{reject=no;}));let refresh!:Promise<void>;await act(async()=>{refresh=client.invalidateQueries({queryKey:["components-inventory"]});});await settle(()=>expect(host.textContent).toContain("Refreshing component inventory"));expect(rows()).toHaveLength(100);expect(button("Export matching CSV").disabled).toBe(true);await act(async()=>{reject(new Error("Inventory read failed"));await refresh;});await settle(()=>expect(host.textContent).toContain("Component inventory could not be loaded"));expect(rows()).toHaveLength(0);expect(host.querySelector('[data-testid="component-summary"]')).toBeNull();expect(button("Export matching CSV")).toBeUndefined();expect(host.textContent).not.toContain("No component instances match");
});
it.each(["page","scope","filter","duplicate ID","missing totals"])("withholds invalid %s evidence and export",async condition=>{
 vi.mocked(componentsInventory.list).mockImplementation(async params=>{const data=inventory(params!);if(condition==="page")data.offset=100;if(condition==="scope")data.components[0].cluster_id="foreign";if(condition==="filter")data.role="scanner";if(condition==="duplicate ID")data.components[1].id=data.components[0].id;if(condition==="missing totals")delete data.total;return data;});await render();await settle(()=>expect(host.textContent).toContain("Component inventory does not match the active cluster"));expect(rows()).toHaveLength(0);expect(host.querySelector('[data-testid="component-summary"]')).toBeNull();
});
it("keeps scope truthful across cluster and session owner transitions",async()=>{
 await render();await settle(()=>expect(rows()).toHaveLength(100));scope.id="other";await rerender();expect(rows()).toHaveLength(0);expect(componentsInventory.list).toHaveBeenCalledTimes(1);scope.resolved="other";await rerender();await settle(()=>expect(componentsInventory.list).toHaveBeenCalledTimes(2));await settle(()=>expect(rows()).toHaveLength(100));identity={org_id:"new-org",user_id:"new-user"};vi.mocked(componentsInventory.list).mockRejectedValue(new Error("Owner evidence unavailable"));await rerender();await settle(()=>expect(host.textContent).toContain("Component inventory could not be loaded"));expect(rows()).toHaveLength(0);
});
it("recovers an out-of-range URL page without pretending its full source is empty",async()=>{
 await render("?page=99");await settle(()=>expect(button("First page")).toBeDefined());expect(host.querySelector('[data-testid="component-summary"]')!.textContent).toContain("2005");expect(host.textContent).not.toContain("No component instances observed");await click("First page");await settle(()=>expect(rows()).toHaveLength(100));expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({offset:0}));
});
it("rejects unsupported filters without a request and preserves an exact off-page selection",async()=>{
 await render("?role=invalid&component=instance-2004&context=keep");await settle(()=>expect(host.textContent).toContain("Choose a supported component filter or sort"));expect(componentsInventory.list).not.toHaveBeenCalled();await click("Reset filters and sort");await settle(()=>expect(rows()).toHaveLength(100));await settle(()=>expect(componentsInventory.get).toHaveBeenCalledWith("instance-2004"));expect(new URLSearchParams(history.location.search).get("component")).toBe("instance-2004");expect(host.textContent).toContain("Selected component could not be loaded");
});
