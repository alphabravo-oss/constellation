import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { TestRouter } from "@/test/router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { downloadCsv } from "@/lib/csv";
import { clusters, componentsInventory, systemConfigApi, type ComponentInstance, type ComponentsInventoryParams } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { EffectiveConfigPage } from "./EffectiveConfigPage";

vi.mock("@/api/client", () => ({
  systemConfigApi: { get: vi.fn() },
  componentsInventory: { list: vi.fn(), exportCSV: vi.fn() },
  clusters: { list: vi.fn() },
}));

vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
let history: RouterHistory;
let root: Root | undefined;
let host: HTMLDivElement;
let queryClient: QueryClient;
let identity = { org_id: "org", user_id: "user" };
beforeEach(() => { (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; identity = { org_id: "org", user_id: "user" }; vi.mocked(clusters.list).mockResolvedValue({ clusters: [{ id: "cluster", name: "Test cluster" }] } as Awaited<ReturnType<typeof clusters.list>>); vi.mocked(componentsInventory.exportCSV).mockResolvedValue({total:2105,exported:2105,limit:100000,truncated:false}); });

afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  queryClient?.clear();
  vi.resetAllMocks();
});

async function render(search = "") {
  history = createMemoryHistory({ initialEntries: [`/settings/effective-config${search}`] });
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root!.render(
    <QueryClientProvider client={queryClient}><TablePreferencesProvider identity={identity}><TestRouter history={history}><EffectiveConfigPage /></TestRouter></TablePreferencesProvider></QueryClientProvider>,
  ));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 25)); });
}

function component(name: string, metadata: Record<string, unknown>): ComponentInstance {
  return {
    id: name,
    component: name,
    display_name: name,
    role: "scanner", scope: "cluster", kind: "service", status: "healthy", cluster_id: "cluster", cluster_name: "Test cluster", version: "1.0", commit: "fixture", uptime_seconds: 3600, restart_count: 0, first_seen_at: "2026-10-12T00:00:00Z",
    hostname: name,
    last_seen_at: "2026-10-12T00:00:00Z",
    metadata,
  } as ComponentInstance;
}

function inventory(source: ComponentInstance[], params: ComponentsInventoryParams = {}) {
 const scope = source.filter(row=>!params.cluster_id || row.cluster_id===params.cluster_id);
 const matching = scope.filter(row=>(!params.q || [row.hostname,row.display_name,row.component].some(value=>value.includes(params.q!))) && (!params.role || row.role===params.role) && (!params.status || row.status===params.status));
 matching.sort((a,b)=>(params.sort==="hostname"?a.hostname:a.display_name || a.component).localeCompare(params.sort==="hostname"?b.hostname:b.display_name || b.component));if(params.order==="desc")matching.reverse();
 const offset=params.offset||0;return {components:matching.slice(offset,offset+100),rollups:[],summary:{generated_at:"2026-10-12T00:00:00Z",components:scope.length?1:0,total_instances:scope.length,healthy:scope.length,degraded:0,stale:0,drift:0,crashlooping:0,missing:0},cluster_id:params.cluster_id||null,q:params.q||"",component:"",role:params.role||"",status:params.status||"",sort:params.sort||"component",order:params.order||"asc",limit:100,offset,total:matching.length,has_more:offset+100<matching.length,source_window_hours:24,role_counts:{all:scope.length,scanner:scope.length,controller:0,enforcer:0,admission:0,discoverer:0,other:0}};
}
const reportsSource=()=>Array.from({length:2105},(_,i)=>component(`component-${String(i).padStart(4,"0")}`,i%3?{system_config_revision:9}:{config_revision:9}));
function mockReports(source=reportsSource()){vi.mocked(componentsInventory.list).mockImplementation(async params=>inventory(source,params));}
async function settled(check:()=>void){await vi.waitFor(async()=>{await act(async()=>{});check();});}
const button=(label:string)=>[...host.querySelectorAll<HTMLButtonElement>("button")].find(value=>value.textContent?.trim()===label)!;
async function click(label:string){await act(async()=>button(label).click());}
const reportRows=()=>host.querySelectorAll('[data-testid="effective-config-applied-revisions"] tbody tr');
async function field(label:string,value:string){await act(async()=>{const input=host.querySelector<HTMLInputElement|HTMLSelectElement>(`[aria-label="${label}"]`)!;Object.getOwnPropertyDescriptor(input.tagName==="SELECT"?HTMLSelectElement.prototype:HTMLInputElement.prototype,"value")!.set!.call(input,value);input.dispatchEvent(new Event(input.tagName==="SELECT"?"change":"input",{bubbles:true}));});}

it("uses backend sources even for default-valued writes and distinguishes provider from component reports", async () => {
  vi.mocked(systemConfigApi.get).mockResolvedValue({
    config: { tls_verify: true, nvd_api_key: "***REDACTED***", scanner_offline_db: false },
    revision: 9,
    source: "system_config",
    provenance: {
      tls_verify: { source: "database", redacted: false },
      nvd_api_key: { source: "environment_bootstrap", redacted: true },
    },
    applied: {
      provider: { component: "system_config_provider", scope: "serving_replica", revision: 7, status: "behind" },
    },
  } as Awaited<ReturnType<typeof systemConfigApi.get>>);
  mockReports([component("unrelated-revision", { config_revision: 9 }), component("explicit-report", { system_config_revision: 8 })]);
  await render("?tab=sources");
  const provenance = host.querySelector('[data-testid="effective-config-default-diff"]')!;
  const rows = Array.from(provenance.querySelectorAll("tbody tr"));
  expect(rows.find((row) => row.textContent?.includes("tls_verify"))?.textContent).toContain("Database");
  expect(rows.find((row) => row.textContent?.includes("nvd_api_key"))?.textContent).toContain("Environment bootstrap");
  expect(rows.find((row) => row.textContent?.includes("nvd_api_key"))?.textContent).toContain("Redacted");
  await tab("Revision reports");
  const provider = host.querySelector('[data-testid="effective-config-provider-applied"]')!;
  expect(provider.textContent).toContain("serving_replica");
  expect(provider.textContent).toContain("Behind");
  expect(provider.textContent).toContain("7");
  expect(provider.textContent).toContain("does not confirm scanner");
  await settled(()=>expect(reportRows()).toHaveLength(2));
  const reports = Array.from(host.querySelectorAll('[data-testid="effective-config-applied-revisions"] tbody tr'));
  expect(reports.find((row) => row.textContent?.includes("unrelated-revision"))?.textContent).toContain("Unknown");
  expect(reports.find((row) => row.textContent?.includes("explicit-report"))?.textContent).toContain("Behind");
});

it("reports missing provenance and failed component inventory as unknown or unavailable", async () => {
  vi.mocked(systemConfigApi.get).mockResolvedValue({ config: { tls_verify: true }, revision: 0, source: "default" });
  vi.mocked(componentsInventory.list).mockRejectedValue(new Error("inventory offline"));
  await render("?tab=reports");
  expect(host.querySelector('[data-testid="effective-config-provider-applied"]')?.textContent).toContain("Unavailable");
  await settled(()=>expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')?.textContent).toContain("unavailable"));
  expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')?.textContent).not.toContain("No component heartbeats");
  await tab("Provenance");
  expect(host.querySelector('[data-testid="effective-config-source-summary"]')?.textContent).toContain("Unknown");
});

async function tab(label: string) { await act(async () => [...host.querySelectorAll('[role="tab"]')].find(t => t.textContent === label)!.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, button: 0 }))); await vi.waitFor(() => expect(host.querySelector('[role="tab"][data-state="active"]')?.textContent).toBe(label)); }
it("continues revision reports beyond1000 with page CSV and URL/history disclosure", async () => {
 vi.mocked(systemConfigApi.get).mockResolvedValue({ config: { tls_verify: true }, revision: 9, source: "system_config" });
 mockReports();
 await render("?context=kept#proof"); expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')).toBeNull(); await tab("Revision reports"); expect(history.location.search).toContain("tab=reports"); expect(history.location.search).toContain("context=kept"); expect(history.location.hash).toBe("#proof");
 await settled(()=>expect(reportRows()).toHaveLength(100)); await click("Next"); await settled(()=>expect(host.textContent).toContain("component-0100")); await click("Export this page CSV"); expect(vi.mocked(downloadCsv).mock.calls.at(-1)?.[2]).toHaveLength(100); expect(host.textContent).toContain("2,105 matching component records"); expect(host.textContent).not.toContain("Server fetch limit: 1,000");
 await act(async () => history.back()); await settled(()=>expect(host.textContent).toContain("component-0000")); await act(async () => history.back()); await vi.waitFor(() => expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')).toBeNull()); await act(async () => history.forward()); await vi.waitFor(() => expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')).not.toBeNull());
});
it("suppresses stale component and configuration evidence after failed refreshes", async () => {
 vi.mocked(systemConfigApi.get).mockResolvedValue({ config: { tls_verify: true }, revision: 9, source: "system_config" }); mockReports([component("reported-component",{system_config_revision:9})]);
 await render("?tab=reports"); await settled(()=>expect(host.textContent).toContain("reported-component")); vi.mocked(componentsInventory.list).mockRejectedValue(new Error("offline")); await act(async () => { await queryClient.invalidateQueries({ queryKey: ["components-inventory"] }); }); await vi.waitFor(() => expect(host.textContent).toContain("Component inventory unavailable")); expect(host.textContent).not.toContain("reported-component");
 vi.mocked(systemConfigApi.get).mockRejectedValue(new Error("offline")); await act(async () => { await queryClient.invalidateQueries({ queryKey: ["system-config"] }); }); await vi.waitFor(() => expect(host.textContent).toContain("Failed to load system config")); expect(host.querySelector('[role="tab"]')).toBeNull();
});

it("restores deep report pages and server sorting and exports matching revision evidence",async()=>{
 vi.mocked(systemConfigApi.get).mockResolvedValue({config:{},revision:9,source:"system_config"});mockReports();await render("?tab=reports&report_page=21&report_sort=hostname&report_order=asc&context=keep#reports");await settled(()=>expect(reportRows()).toHaveLength(100));expect(reportRows()[0].textContent).toContain("component-2000");expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({offset:2000,limit:100,sort:"hostname",order:"asc"}));
 await click("Export matching CSV");expect(componentsInventory.exportCSV).toHaveBeenCalledWith(expect.objectContaining({offset:2000,sort:"hostname",order:"asc"}),expect.any(Function));await settled(()=>expect(host.textContent).toContain("Exported all 2,105 matching records"));
 await act(async()=>host.querySelector<HTMLButtonElement>('th[data-column-id="hostname"] button')!.click());await settled(()=>{expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({sort:"component",order:"asc",offset:0}));expect(host.querySelector('th[data-column-id="component"]')?.getAttribute("aria-sort")).toBe("ascending");});await act(async()=>host.querySelector<HTMLButtonElement>('th[data-column-id="hostname"] button')!.click());await settled(()=>expect(host.querySelector('th[data-column-id="hostname"]')?.getAttribute("aria-sort")).toBe("descending"));expect(new URLSearchParams(history.location.search).has("report_page")).toBe(false);await act(async()=>history.back());await settled(()=>expect(host.querySelector('th[data-column-id="component"]')?.getAttribute("aria-sort")).toBe("ascending"));await act(async()=>history.back());await settled(()=>expect(reportRows()[0].textContent).toContain("component-2000"));expect(history.location.hash).toBe("#reports");
});
it("searches and filters report sources before pagination and preserves unrelated URL context",async()=>{
 vi.mocked(systemConfigApi.get).mockResolvedValue({config:{},revision:9});mockReports();await render("?tab=reports&report_page=21&context=a&context=b");await settled(()=>expect(reportRows()).toHaveLength(100));await field("Search component revision reports","component-2104");await settled(()=>expect(reportRows()).toHaveLength(1));expect(host.textContent).toContain("1 matching component records");expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({q:"component-2104",offset:0}));
 await field("Report cluster","cluster");await settled(()=>expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({cluster_id:"cluster",q:"component-2104",offset:0})));await field("Report role","scanner");await settled(()=>expect(componentsInventory.list).toHaveBeenLastCalledWith(expect.objectContaining({role:"scanner"})));expect(new URLSearchParams(history.location.search).getAll("context")).toEqual(["a","b"]);await act(async()=>history.back());await settled(()=>expect(host.querySelector<HTMLSelectElement>('[aria-label="Report role"]')!.value).toBe(""));
});
it.each(["report_q=one&report_q=two","report_cluster=cluster&report_cluster=other","report_sort=revision","report_page=abc"])("rejects and recovers invalid report URL %s",async search=>{
 vi.mocked(systemConfigApi.get).mockResolvedValue({config:{},revision:9});mockReports();await render(`?tab=reports&context=keep&${search}`);await settled(()=>expect(host.textContent).toContain("Choose supported report filters"));expect(componentsInventory.list).not.toHaveBeenCalled();await click("Reset report filters and page");await settled(()=>expect(reportRows()).toHaveLength(100));expect(new URLSearchParams(history.location.search).get("context")).toBe("keep");
});
it("never manually reads an unavailable cluster after its filter gate rejected scope",async()=>{
 vi.mocked(systemConfigApi.get).mockResolvedValue({config:{},revision:9});mockReports();await render("?tab=reports&report_cluster=foreign");await settled(()=>expect(host.textContent).toContain("requested report cluster is unavailable"));expect(button("Refresh inventory").disabled).toBe(true);await act(async()=>button("Refresh inventory").click());expect(componentsInventory.list).not.toHaveBeenCalled();await field("Report cluster","");await settled(()=>expect(reportRows()).toHaveLength(100));
});
it("keeps successful reports during a deferred refresh then hides failed rows and exports",async()=>{
 vi.mocked(systemConfigApi.get).mockResolvedValue({config:{},revision:9});mockReports();await render("?tab=reports");await settled(()=>expect(reportRows()).toHaveLength(100));let reject!:(error:Error)=>void;vi.mocked(componentsInventory.list).mockImplementationOnce(()=>new Promise((_ok,no)=>{reject=no;}));let pending!:Promise<void>;await act(async()=>{pending=queryClient.invalidateQueries({queryKey:["components-inventory"]});});await settled(()=>expect(host.textContent).toContain("Refreshing component reports"));expect(reportRows()).toHaveLength(100);expect(button("Export matching CSV").disabled).toBe(true);await act(async()=>{reject(new Error("private read"));await pending;});await settled(()=>expect(button("Retry inventory")).toBeDefined());expect(reportRows()).toHaveLength(0);expect(button("Export matching CSV")).toBeUndefined();expect(host.textContent).not.toContain("No components match");
});
it.each(["wrong scope","wrong page","missing summary","duplicate IDs","malformed display"])("hides invalid %s inventory metadata",async defect=>{
 vi.mocked(systemConfigApi.get).mockResolvedValue({config:{},revision:9});vi.mocked(componentsInventory.list).mockImplementation(async params=>{const data=inventory(reportsSource(),params);if(defect==="wrong scope")data.cluster_id="foreign";if(defect==="wrong page")data.offset=100;if(defect==="missing summary")delete (data as Partial<typeof data>).summary;if(defect==="duplicate IDs")data.components[1].id=data.components[0].id;if(defect==="malformed display")data.components[0].display_name={} as unknown as string;return data;});await render("?tab=reports");await settled(()=>expect(button("Retry inventory")).toBeDefined());expect(reportRows()).toHaveLength(0);expect(button("Export matching CSV")).toBeUndefined();
});
it("keeps a pending matching export cancelled through a cache-only invalidation and recovery",async()=>{
 vi.mocked(systemConfigApi.get).mockResolvedValue({config:{},revision:9});mockReports();let finish!:(value:{total:number;exported:number;limit:number;truncated:boolean})=>void;vi.mocked(componentsInventory.exportCSV).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));await render("?tab=reports");await settled(()=>expect(reportRows()).toHaveLength(100));await click("Export matching CSV");await settled(()=>expect(componentsInventory.exportCSV).toHaveBeenCalledOnce());const guard=vi.mocked(componentsInventory.exportCSV).mock.calls[0][1]!;
 const query=queryClient.getQueryCache().find({queryKey:["components-inventory"],exact:false})!;await act(async()=>{void queryClient.invalidateQueries({queryKey:query.queryKey,exact:true,refetchType:"none"});queryClient.setQueryData(query.queryKey,query.state.data);});expect(guard()).toBe(false);await act(async()=>finish({total:2105,exported:2105,limit:100000,truncated:false}));await settled(()=>expect(host.textContent).toContain("Matching CSV could not be exported"));expect(host.textContent).not.toContain("Exported all 2,105");
});


it("blocks reviewed Component page and pending matching exports when cache rows change before rerender",async()=>{
 vi.mocked(systemConfigApi.get).mockResolvedValue({config:{},revision:9});mockReports();
 let finish!:(value:{total:number;exported:number;limit:number;truncated:boolean})=>void;
 vi.mocked(componentsInventory.exportCSV).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));
 await render("?tab=reports");await settled(()=>expect(reportRows()).toHaveLength(100));await click("Export matching CSV");
 await settled(()=>expect(componentsInventory.exportCSV).toHaveBeenCalledOnce());
 const guard=vi.mocked(componentsInventory.exportCSV).mock.calls[0][1]!;
 const query=queryClient.getQueryCache().find({queryKey:["components-inventory"],exact:false})!;
 const reviewed=query.state.data as ReturnType<typeof inventory>;
 const pageExport=button("Export this page CSV");
 await act(async()=>{
  queryClient.setQueryData(query.queryKey,{...reviewed,components:reviewed.components.map((row,index)=>index===0?{...row,metadata:{system_config_revision:8}}:row)});
  expect(query.state.data).not.toBe(reviewed);
  pageExport.click();
  expect(downloadCsv).not.toHaveBeenCalled();
  expect(guard()).toBe(false);
 });
 await settled(()=>expect(reportRows()[0].textContent).toContain("Behind"));
 await click("Export this page CSV");expect(downloadCsv).toHaveBeenCalledOnce();expect(guard()).toBe(false);
 await act(async()=>finish({total:2105,exported:2105,limit:100000,truncated:false}));
 await settled(()=>expect(host.textContent).toContain("Matching CSV could not be exported"));
 expect(host.textContent).not.toContain("Exported all 2,105");
});
