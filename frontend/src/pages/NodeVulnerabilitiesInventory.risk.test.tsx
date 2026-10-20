import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, useParams, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { nodes, type NodeDetail, type NodeVulnerability, type NodeVulnerabilityParams, type NodeVulnerabilityResponse } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { NodeVulnerabilitiesInventory } from "./NodeVulnerabilitiesInventory";
const scope = vi.hoisted(() => ({ resolved: "", loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", async () => { const router = await vi.importActual<typeof import("@tanstack/react-router")>("@tanstack/react-router"); return { useCluster: () => { const { id } = router.useParams({ strict: false }); return { clusterId: id, cluster: { id: scope.resolved || id }, isLoading: scope.loading, error: scope.error }; } }; });
vi.mock("@/api/client", () => ({ nodes: { get: vi.fn(), vulnerabilities: vi.fn(), exportVulnerabilitiesCSV: vi.fn(), scan: vi.fn() } }));
vi.mock("@/lib/csv", async original => ({ ...await original<typeof import("@/lib/csv")>(), downloadCsv: vi.fn() }));
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory; let identity: { org_id: string; user_id: string } | null;
const at = "2026-10-12T00:00:00Z";
const detail = (cluster = "cluster", name = "node"): NodeDetail => ({ node: { node: name, cluster_id: cluster, runtime_agent_status: "healthy", scan_status: "completed", last_scanned_at: at, last_seen_at: at, package_count: 7, container_count: 2, process_count: 8, cis_passed: 1, cis_failed: 0, cis_warned: 0, cis_skipped: 0, critical_vulns: 1053, high_vulns: 1052, medium_vulns: 0, low_vulns: 0, open_vulns: 2105, packages_observed_at: at, containers_observed_at: at, processes_observed_at: at, cis_observed_at: at }, vulnerabilities: [] });
const finding = (i: number, cluster = "cluster", name = "node"): NodeVulnerability => ({ id: `finding-${i}`, row_id: `finding-${i}:1791763200.000000`, first_seen_at: at, node: name, cluster_id: cluster, source_cluster_id: cluster, vuln_id: "CVE-shared", package_name: `package-${i.toString().padStart(4, "0")}`, package_version: "1.0", severity: i % 2 ? "high" : "critical", fixed_version: i % 3 ? "false" : "2.0", fixable: i % 3 === 0, source: i % 2 ? "grype" : "trivy", observed_at: at, risk_score: 80 });
function response(cluster: string, name: string, params: NodeVulnerabilityParams = {}, source = Array.from({ length: 2105 }, (_, i) => finding(i, cluster, name))): NodeVulnerabilityResponse {
 const matches = source.filter(item => (!params.q || [item.id, item.package_name, item.vuln_id, item.source].some(value => value.includes(params.q!))) && (!params.severity || item.severity === params.severity) && (!params.fixable || item.fixable === (params.fixable === "true")) && (!params.source || item.source === params.source));
 if (params.sort === "package") matches.sort((a, b) => a.package_name.localeCompare(b.package_name)); if (params.order === "desc") matches.reverse(); const offset = params.offset || 0;
 return { node: name, cluster_id: cluster, items: matches.slice(offset, offset + 100), total: matches.length, limit: 100, offset, has_more: offset + 100 < matches.length, q: params.q || "", severity: params.severity || "", fixable: params.fixable || "", source: params.source || "", sort: params.sort || "risk", order: params.order || "desc", summary: { total: matches.length, critical: matches.filter(item => item.severity === "critical").length, high: matches.filter(item => item.severity === "high").length, fixable: matches.filter(item => item.fixable).length, unique_cves: new Set(matches.map(item => item.vuln_id).filter(Boolean)).size } };
}
beforeEach(() => {
 (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; vi.resetAllMocks(); localStorage.clear(); Object.assign(scope, { resolved: "", loading: false, error: null }); identity = { org_id: "org", user_id: "user" };
 vi.mocked(nodes.get).mockImplementation(async (cluster, name) => detail(cluster, name)); vi.mocked(nodes.vulnerabilities).mockImplementation(async (cluster, name, params) => response(cluster, name, params)); vi.mocked(nodes.exportVulnerabilitiesCSV).mockResolvedValue({ total: 2105, exported: 2105, limit: 100000, truncated: false });
 client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); localStorage.clear(); vi.restoreAllMocks(); });
function Harness() {
 const { id = "", entityId = "" } = useParams({ strict: false });
 const owner = identity ? `${identity.org_id}:${identity.user_id}` : "";
 const key = ["risk-entity", owner, id, "node", entityId];
 const source = useQuery({ queryKey: key, enabled: !!owner && !scope.loading && !scope.error && (!scope.resolved || scope.resolved === id), queryFn: async () => ({ type: "node", data: await nodes.get(id, entityId) }) });
 return <NodeVulnerabilitiesInventory clusterId={id} nodeName={entityId} sourceQueryKey={key} sourceKind="risk" sourceReady={source.isSuccess && !scope.loading && !scope.error} nodeRefreshing={source.isFetching} paramPrefix="findings_" />;
}
const tree = () => <QueryClientProvider client={client}><TablePreferencesProvider identity={identity ? { ...identity } : null}><TestRouter path="/clusters/$id/risk/node/$entityId" history={history}><Harness /></TestRouter></TablePreferencesProvider></QueryClientProvider>;
async function render(search = "") { history = createMemoryHistory({ initialEntries: [`/clusters/cluster/risk/node/node${search}`] }); await act(async () => root.render(tree())); }
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
const rows = () => host.querySelectorAll('[data-testid="node-host-findings-table"] tbody tr');
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label || item.getAttribute("data-export-label") === label)!;
async function click(label: string) { await act(async () => button(label).click()); }
async function field(selector: string, value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement | HTMLSelectElement>(selector)!; Object.getOwnPropertyDescriptor(input.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event(input.tagName === "SELECT" ? "change" : "input", { bubbles: true })); }); }


it("Risk node findings traverse beyond the legacy2000 sample and export complete matching scope", async () => {
 await render("?tab=findings&findings_page=21&findings_sort=package&findings_order=asc&q=unrelated&context=keep#risk");
 await settle(() => expect(rows()).toHaveLength(100)); expect(rows()[0].textContent).toContain("package-2000"); expect(host.textContent).toContain("2,105 matching finding instances"); expect(host.textContent).not.toContain("2,000 records");
 expect(nodes.vulnerabilities).toHaveBeenLastCalledWith("cluster","node",expect.objectContaining({offset:2000,sort:"package",order:"asc",q:undefined}));
 await click("Export this page CSV"); expect(vi.mocked(downloadCsv).mock.calls.at(-1)?.[2]).toHaveLength(100);
 await click("Export matching CSV"); expect(nodes.exportVulnerabilitiesCSV).toHaveBeenCalledWith("cluster","node",expect.objectContaining({offset:2000}),expect.any(Function));
 await click("Next"); await settle(() => expect(rows()).toHaveLength(5)); expect(rows()[0].textContent).toContain("package-2100"); expect(history.location.search).toContain("findings_page=22"); expect(history.location.search).toContain("q=unrelated"); expect(history.location.search).toContain("tab=findings");
 await act(async()=>history.back()); await settle(()=>expect(rows()).toHaveLength(100)); expect(history.location.hash).toBe("#risk");
});
it("searches and filters the complete node source without overwriting peer URL state", async () => {
 await render("?tab=findings&findings_page=21&findings_sort=package&findings_order=asc&q=global&context=keep"); await settle(()=>expect(rows()).toHaveLength(100));
 await field('[aria-label="Search node host findings"]',"package-2104"); await settle(()=>expect(rows()).toHaveLength(1)); expect(rows()[0].textContent).toContain("package-2104"); expect(nodes.vulnerabilities).toHaveBeenLastCalledWith("cluster","node",expect.objectContaining({q:"package-2104",offset:0}));
 const params=new URLSearchParams(history.location.search); expect(params.get("q")).toBe("global"); expect(params.get("findings_q")).toBe("package-2104"); expect(params.get("context")).toBe("keep"); expect(params.has("findings_page")).toBe(false);
 await field('[aria-label="Host finding severity"]',"high"); await settle(()=>expect(host.textContent).toContain("0 matching finding instances")); await act(async()=>history.back()); await settle(()=>expect(rows()).toHaveLength(1));
});
it("keeps exact physical selection instead of substituting another recurrence", async () => {
 await render("?findings_selected=finding-204%3A1791763200.000000&findings_sort=package&findings_order=asc"); await settle(()=>expect(rows()).toHaveLength(100)); expect(host.textContent).toContain("no other finding has been substituted");
 await click("Next"); await click("Next"); await settle(()=>expect(host.querySelector("dl")?.textContent).toContain("finding-204")); expect(new URLSearchParams(history.location.search).get("findings_selected")).toBe("finding-204:1791763200.000000");
});
it("retains rows during deferred inventory refresh then hides actual failure and selection", async () => {
 await render("?findings_selected=finding-0%3A1791763200.000000&findings_order=asc"); await settle(()=>expect(rows()).toHaveLength(100)); let reject!:(error:Error)=>void;vi.mocked(nodes.vulnerabilities).mockImplementationOnce(()=>new Promise((_ok,no)=>{reject=no;}));
 let pending!:Promise<void>;await act(async()=>{pending=client.invalidateQueries({queryKey:["node-vulnerabilities"]});});await settle(()=>expect(host.textContent).toContain("Refreshing host findings"));expect(rows()).toHaveLength(100);expect(button("Export matching CSV").disabled).toBe(true);
 await act(async()=>{reject(new Error("private"));await pending;});await settle(()=>expect(button("Retry host findings")).toBeDefined());expect(rows()).toHaveLength(0);expect(host.querySelector("dl")).toBeNull();expect(host.textContent).not.toContain("0 matching finding instances");
});
it("pauses reads and hides old findings when exact node or owner scope fails", async () => {
 await render();await settle(()=>expect(rows()).toHaveLength(100));identity={org_id:"other",user_id:"user"};vi.mocked(nodes.get).mockRejectedValue(new Error("scope unavailable"));await act(async()=>root.render(tree()));await settle(()=>expect(host.textContent).toContain("Current node evidence is unavailable"));expect(rows()).toHaveLength(0);expect(nodes.vulnerabilities).toHaveBeenCalledTimes(1);
});
it.each(["missing advisory","malformed aliases","foreign cluster","duplicate row"])("rejects %s metadata as unavailable evidence", async defect => {
 vi.mocked(nodes.vulnerabilities).mockImplementation(async(cluster,name,params)=>{const data=response(cluster,name,params);if(defect==="missing advisory")delete (data.items[0] as Partial<NodeVulnerability>).vuln_id;if(defect==="malformed aliases")data.items[0].aliases=[42] as unknown as string[];if(defect==="foreign cluster"){data.items[0].cluster_id="other";data.items[0].source_cluster_id="other";}if(defect==="duplicate row")data.items[1].row_id=data.items[0].row_id;return data;});await render();await settle(()=>expect(button("Retry host findings")).toBeDefined());expect(rows()).toHaveLength(0);
});
it("accepts valid no-fix rows with omitted optional metadata", async () => {
 vi.mocked(nodes.vulnerabilities).mockImplementation(async(cluster,name,params)=>{const data=response(cluster,name,params);for(const row of data.items){row.fixable=false;delete row.fixed_version;}data.summary.fixable=0;return data;});await render();await settle(()=>expect(rows()).toHaveLength(100));expect(rows()[0].textContent).toContain("No reported fix");
});
it("rejects unsupported or duplicate URL values and recovers through Reset", async () => {
 await render("?findings_q=first&findings_q=second&context=keep");await settle(()=>expect(host.textContent).toContain("Choose supported host finding filters"));expect(nodes.vulnerabilities).not.toHaveBeenCalled();await click("Reset host finding filters");await settle(()=>expect(rows()).toHaveLength(100));expect(new URLSearchParams(history.location.search).get("context")).toBe("keep");
});


it("blocks reviewed Node page and pending matching exports when cache rows change before rerender", async () => {
 let finish!:(value:{total:number;exported:number;limit:number;truncated:boolean})=>void;
 vi.mocked(nodes.exportVulnerabilitiesCSV).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));
 await render();await settle(()=>expect(rows()).toHaveLength(100));await click("Export matching CSV");
 await settle(()=>expect(nodes.exportVulnerabilitiesCSV).toHaveBeenCalledOnce());
 const guard=vi.mocked(nodes.exportVulnerabilitiesCSV).mock.calls[0][3]!;
 const query=client.getQueryCache().find({queryKey:["node-vulnerabilities"],exact:false})!;
 const reviewed=query.state.data as NodeVulnerabilityResponse;
 const pageExport=button("Export this page CSV");
 await act(async()=>{
  client.setQueryData(query.queryKey,{...reviewed,items:reviewed.items.map((row,index)=>index===0?{...row,package_version:"reviewed-replacement"}:row)});
  expect(query.state.data).not.toBe(reviewed);
  pageExport.click();
  expect(downloadCsv).not.toHaveBeenCalled();
  expect(guard()).toBe(false);
 });
 await settle(()=>expect(rows()[0].textContent).toContain("reviewed-replacement"));
 // A newly reviewed table may export, but the earlier pending request stays cancelled.
 await click("Export this page CSV");expect(downloadCsv).toHaveBeenCalledOnce();expect(guard()).toBe(false);
 await act(async()=>finish({total:2105,exported:2105,limit:100000,truncated:false}));
 await settle(()=>expect(host.textContent).toContain("Matching CSV could not be exported"));
 expect(host.textContent).not.toContain("Exported all 2,105");
});
