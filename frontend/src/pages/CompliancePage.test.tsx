import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { compliance, type ComplianceCheck, type ComplianceChecksParams, type ComplianceChecksResponse } from "@/api/client";
import { CompliancePage } from "./CompliancePage";
import { benchPage } from "@/test/benchmark-fixtures";

/** Kit Select keeps a hidden native mirror right before its trigger. */
function nativeSelect(root: ParentNode, selector: string): HTMLSelectElement | null {
  const element = root.querySelector(selector);
  if (!element) return null;
  if (element.tagName === "SELECT") return element as HTMLSelectElement;
  const previous = element.previousElementSibling;
  return previous?.tagName === "SELECT" ? previous as HTMLSelectElement : null;
}
const scope = vi.hoisted(() => ({ id: "cluster", resolved: "cluster", loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: scope.id, cluster: { id: scope.resolved }, isLoading: scope.loading, error: scope.error }) }));
vi.mock("@/api/client", () => ({ compliance: { frameworks: vi.fn(), checks: vi.fn(), summary: vi.fn(), listExemptions: vi.fn(), revokeExemption: vi.fn(), evidence: vi.fn(), listDBSchedules: vi.fn(), exportChecksCSV: vi.fn(), benchRequests: vi.fn(), benchRequest: vi.fn() } }));
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
let identity = { org_id: "org", user_id: "user" };
const row = (id: number, status: string, framework = "cis"): ComplianceCheck => ({ id: `evidence-${id}`, cluster_id: scope.id, framework, control_id: "shared-control", title: `Evidence target ${id}`, description: "Collected control evidence", status: (status === "exempted" ? "fail" : status) as ComplianceCheck["status"], effective_status: status as ComplianceCheck["effective_status"], severity: "high", evidence: `Evidence ${id}`, evaluated_at: "2026-10-12T00:00:00Z" });
const source = () => [row(1,"pass"),row(2,"pass","pci"),row(3,"fail","pci"),row(4,"manual"),row(5,"exempted"),row(6,"not_applicable"),row(7,"unknown")];
function response(params: ComplianceChecksParams, all: ComplianceCheck[] = source()): ComplianceChecksResponse {
 const rows = all.filter(item => (!params.framework || params.framework === "all" || item.framework === params.framework) && (!params.control_id || item.control_id === params.control_id) && (!params.status || (params.status === "graded" ? ["pass","fail"].includes(item.effective_status) : params.status === "ungraded" ? !["pass","fail"].includes(item.effective_status) : item.effective_status === params.status)));
 const summary: Record<string,number> = { total: rows.length, pass: 0, fail: 0, manual: 0, exempted: 0, not_applicable: 0, graded: 0, ungraded: 0 };
 for (const item of rows) { if (item.effective_status in summary) summary[item.effective_status]++; summary[["pass","fail"].includes(item.effective_status) ? "graded" : "ungraded"]++; }
 const offset = params.offset || 0;
 return { checks: rows.slice(offset,offset+100), cluster_id: params.cluster_id, framework: params.framework === "all" ? "" : params.framework || "", profile: params.profile || "", control_id: params.control_id || "", status: params.status || "", q: params.q || "", sort: params.sort, order: params.order, limit: 100, offset, total: rows.length, has_more: offset+100<rows.length, summary };
}
beforeEach(() => {
 (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; vi.clearAllMocks(); localStorage.clear(); identity = { org_id: "org", user_id: "user" }; Object.assign(scope,{id:"cluster",resolved:"cluster",loading:false,error:null});
 vi.mocked(compliance.frameworks).mockResolvedValue({ frameworks: [{id:"cis",name:"CIS",category:"Security"},{id:"pci",name:"PCI",category:"Security"}] });
 vi.mocked(compliance.checks).mockImplementation(async params => response(params as ComplianceChecksParams));
 vi.mocked(compliance.summary).mockResolvedValue({frameworks:[{framework:"cis",total:5,pass:1,fail:0,manual:1,exempted:1,pass_pct:100},{framework:"pci",total:2,pass:1,fail:1,manual:0,exempted:0,pass_pct:50}]});
 vi.mocked(compliance.listExemptions).mockResolvedValue({exemptions:[]}); vi.mocked(compliance.exportChecksCSV).mockResolvedValue({ total: 3,exported:3,limit:100000,truncated:false });
 vi.mocked(compliance.evidence).mockResolvedValue({items:[],summary:{total:0,pass:0,fail:0,manual:0,exempted:0,not_applicable:0}});
 client=new QueryClient({defaultOptions:{queries:{retry:false},mutations:{retry:false}}});host=document.createElement("div");document.body.append(host);root=createRoot(host);
});
afterEach(()=>{act(()=>root.unmount());client.clear();host.remove();vi.restoreAllMocks();localStorage.clear();});
async function render(search="") {history=createMemoryHistory({initialEntries:[`/clusters/cluster/compliance${search}`]});await rerender();}
async function rerender(){await act(async()=>root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{...identity}}><TestRouter history={history}><CompliancePage /></TestRouter></TablePreferencesProvider></QueryClientProvider>));}
async function settle(check:()=>void){await vi.waitFor(async()=>{await act(async()=>{});check();});}
function rows(){return host.querySelectorAll('[data-testid="compliance-controls-table"] tbody tr');}
function button(text:string){return [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === text || item.getAttribute("aria-label") === text)!;}
async function select(selector:string,value:string){await act(async()=>{const input=nativeSelect(host, selector)!;Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,"value")!.set!.call(input,value);input.dispatchEvent(new Event("change",{bubbles:true}));});}
it("opens the dashboard graded cross-framework cohort with its exact denominator and duplicate control rows",async()=>{
 await render("?tab=controls&framework=all&status=graded");await settle(()=>expect(rows()).toHaveLength(3));
 expect(compliance.checks).toHaveBeenLastCalledWith(expect.objectContaining({framework:"all",status:"graded",cluster_id:"cluster",limit:100,offset:0}));
 const metrics=host.querySelector('[data-testid="compliance-summary"]')!;expect(metrics.textContent).toContain("67%");expect(metrics.textContent).toContain("Matching evidence rows3");expect(metrics.querySelector('[data-testid="verdict-numbers"]')!.children).toHaveLength(4);expect(metrics.textContent).toContain("Ungraded");
 expect(host.textContent).toContain("Evidence target 1");expect(host.textContent).toContain("Evidence target 2");expect(host.textContent).toContain("Evidence target 3");expect(host.textContent).not.toContain("Evidence target 4");expect(host.textContent).not.toContain("Evidence target 5");
 expect(nativeSelect(host, "#compliance-framework")!.value).toBe("all");expect(compliance.evidence).not.toHaveBeenCalled();expect(compliance.listDBSchedules).not.toHaveBeenCalled();
});
it("reads stable server pages, keeps full totals and exports the same cohort across pages",async()=>{
 vi.mocked(compliance.checks).mockImplementation(async params=>response(params as ComplianceChecksParams,Array.from({length:205},(_,i)=>row(i,i<150?"pass":"fail",i%2?"pci":"cis"))));
 await render("?framework=all&status=graded&page=2");await settle(()=>expect(rows()).toHaveLength(100));expect(host.textContent).toContain("Evidence target 100");expect(host.textContent).not.toContain("Evidence target 0");expect(host.querySelector('[data-testid="compliance-summary"]')!.textContent).toContain("Matching evidence rows205");
 await act(async()=>button("Matching rows").click());expect(compliance.exportChecksCSV).toHaveBeenCalledWith(expect.objectContaining({framework:"all",status:"graded",offset:100}), expect.any(Function));await settle(()=>expect(host.textContent).toContain("Exported all 3 matching records across pages"));
 await act(async()=>button("Next").click());await settle(()=>expect(rows()).toHaveLength(5));expect(history.location.search).toContain("page=3");
});
it("updates filter URL and restores the earlier cohort on Back without losing repeated context or hash",async()=>{
 await render("?framework=all&status=graded&context=a&context=b#controls");await settle(()=>expect(rows()).toHaveLength(3));
 await select("#compliance-status","pass");await settle(()=>expect(rows()).toHaveLength(2));expect(history.location.search).toContain("status=pass");expect(new URLSearchParams(history.location.search).getAll("context")).toEqual(["a","b"]);expect(history.location.hash).toBe("#controls");
 await act(async()=>history.back());await settle(()=>expect(rows()).toHaveLength(3));expect(nativeSelect(host, "#compliance-status")!.value).toBe("graded");
});
it("keeps server order and a controlled sorting header synchronized with URL history",async()=>{
 await render("?framework=all&status=graded&sort=framework&order=desc");await settle(()=>expect(rows()).toHaveLength(3));
 expect(host.querySelector('th[aria-sort="descending"]')!.textContent).toContain("Framework");
 let finishSort!:()=>void;
 vi.mocked(compliance.checks).mockImplementationOnce(params=>new Promise(resolve=>{finishSort=()=>resolve(response(params as ComplianceChecksParams));}));
 await act(async()=>host.querySelector<HTMLButtonElement>('th[aria-sort="descending"] button')!.click());await settle(()=>expect(compliance.checks).toHaveBeenLastCalledWith(expect.objectContaining({sort:"framework",order:"asc"})));
 // Dispatching a request does not mean its response has rendered the table.
 await settle(()=>expect(host.textContent).toContain("Loading controls"));
 expect(rows()).toHaveLength(0);
 await act(async()=>finishSort());
 await settle(()=>expect(host.querySelector('th[aria-sort="ascending"]')?.textContent).toContain("Framework"));
 await act(async()=>history.back());await settle(()=>expect(host.querySelector('th[aria-sort="descending"]')?.textContent).toContain("Framework"));
 expect([...rows()].map(item=>item.textContent)).toEqual(expect.arrayContaining([expect.stringContaining("Evidence target 1"),expect.stringContaining("Evidence target 2")]));
});
it("retains current successful reads during refresh then withholds failed evidence and export",async()=>{
 await render("?status=graded");await settle(()=>expect(rows()).toHaveLength(3));let reject!:(reason:Error)=>void;vi.mocked(compliance.checks).mockImplementation(()=>new Promise((_resolve,no)=>{reject=no;}));
 let refresh!:Promise<void>;await act(async()=>{refresh=client.invalidateQueries({queryKey:["compliance","checks"]});});await settle(()=>expect(host.textContent).toContain("Refreshing control evidence"));expect(rows()).toHaveLength(3);expect(button("Matching rows").disabled).toBe(true);
 await act(async()=>{reject(new Error("private failure"));await refresh;});await settle(()=>expect(host.textContent).toContain("Controls could not be loaded or refreshed"));expect(rows()).toHaveLength(0);expect(host.querySelector('[data-testid="compliance-summary"]')!.textContent).not.toContain("67%");expect(button("Matching rows")).toBeUndefined();expect(host.textContent).not.toContain("private failure");expect(host.textContent).not.toContain("No evaluated controls match");
});
it.each(["mismatched scope","mismatched filter","duplicated row identity","wrong page"])("withholds %s response instead of accepting evidence",async condition=>{
 vi.mocked(compliance.checks).mockImplementation(async params=>{const data=response(params as ComplianceChecksParams);if(condition==="mismatched scope")data.checks[0].cluster_id="foreign";if(condition==="mismatched filter")data.status="fail";if(condition==="duplicated row identity")data.checks[1].id=data.checks[0].id;if(condition==="wrong page")data.offset=100;return data;});
 await render("?status=graded");await settle(()=>expect(host.textContent).toContain("Controls could not be loaded or refreshed"));expect(rows()).toHaveLength(0);expect(button("Matching rows")).toBeUndefined();
});
it("clears old scope evidence on cluster change and rejects unresolved cluster reads",async()=>{
 await render("?status=graded");await settle(()=>expect(rows()).toHaveLength(3));scope.id="other";scope.resolved="cluster";await rerender();expect(rows()).toHaveLength(0);expect(compliance.checks).toHaveBeenCalledTimes(1);
 scope.resolved="other";vi.mocked(compliance.checks).mockRejectedValue(new Error("offline"));await rerender();await settle(()=>expect(compliance.checks).toHaveBeenCalledTimes(2));await settle(()=>expect(host.textContent).toContain("Controls could not be loaded or refreshed"));expect(host.textContent).not.toContain("Evidence target 1");
});
it("does not reuse compliance evidence after session owner changes",async()=>{
 await render("?status=graded");await settle(()=>expect(rows()).toHaveLength(3));identity={org_id:"other",user_id:"new-user"};vi.mocked(compliance.checks).mockRejectedValue(new Error("offline"));await rerender();await settle(()=>expect(host.textContent).toContain("Controls could not be loaded or refreshed"));expect(rows()).toHaveLength(0);
});
it("does not claim a passing percentage when the cohort contains no graded rows",async()=>{
 await render("?status=ungraded");await settle(()=>expect(rows()).toHaveLength(4));expect(host.textContent).toContain("No graded controls in this cohort");expect(host.querySelector('[data-testid="compliance-summary"]')!.textContent).not.toContain("100%");expect(host.querySelector('[data-testid="compliance-summary"]')!.textContent).toContain("Graded pass—");
});
it("preserves reported custom frameworks and rejects invalid status without fetching or a loading claim",async()=>{
 vi.mocked(compliance.checks).mockImplementation(async params=>response(params as ComplianceChecksParams,[row(1,"fail","custom")]));await render("?framework=custom");await settle(()=>expect(rows()).toHaveLength(1));expect(nativeSelect(host, "#compliance-framework")!.value).toBe("custom");
 await act(async()=>history.push("/clusters/cluster/compliance?status=invalid"));await settle(()=>expect(host.textContent).toContain("Choose a supported status or sort"));expect(compliance.checks).toHaveBeenCalledTimes(1);expect(host.textContent).not.toContain("Loading controls");
});

it("keeps the Controls verdict and metrics scoped to its own tab",async()=>{
 vi.mocked(compliance.evidence).mockImplementation(async params=>({ ...params, items:[],summary:{total:0,pass:0,fail:0,manual:0,exempted:0,not_applicable:0},total:0,limit:100,offset:0,has_more:false }));
 await render("?tab=evidence&status=graded");
 await settle(()=>expect(host.textContent).toContain("0 source evidence rows match these filters"));
 expect(host.querySelector('[data-testid="compliance-summary"]')).toBeNull();
 expect(host.textContent).not.toContain("failing evidence rows need review");
 await act(async()=>button("Controls").dispatchEvent(new window.MouseEvent("mousedown",{bubbles:true,button:0})));
 await settle(()=>expect(host.querySelector('[data-testid="compliance-summary"]')).not.toBeNull());
 expect(host.textContent).toContain("1 failing evidence rows need review");
 expect(host.querySelector('[data-testid="compliance-summary"]')!.textContent).toContain("Matching evidence rows3");
 await act(async()=>history.back());
 await settle(()=>expect(host.querySelector('[data-testid="compliance-evidence-panel"]')).not.toBeNull());
 expect(host.querySelector('[data-testid="compliance-summary"]')).toBeNull();
});

it("opens dedicated benchmark history through URL tabs without showing control verdicts", async () => {
 vi.mocked(compliance.benchRequests).mockResolvedValue(benchPage([]));
 await render("?tab=benchmarks&context=keep#requests");
 await settle(() => expect(host.textContent).toContain("0 durable requests"));
 expect(host.querySelector('[data-testid="compliance-summary"]')).toBeNull();
 expect(host.querySelector('[data-testid="benchmarks-workspace"]')).not.toBeNull();
 await act(async () => button("Controls").dispatchEvent(new window.MouseEvent("mousedown", { bubbles: true, button: 0 })));
 await settle(() => expect(host.querySelector('[data-testid="compliance-summary"]')).not.toBeNull());
 await act(async () => history.back());
 await settle(() => expect(host.querySelector('[data-testid="benchmarks-workspace"]')).not.toBeNull());
 expect(history.location.search).toContain("context=keep");
 expect(history.location.hash).toBe("#requests");
});
