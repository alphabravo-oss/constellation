import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { nodes, type NodeDetail, type NodeVulnerability, type NodeVulnerabilityParams, type NodeVulnerabilityResponse } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { NodeDetailPage } from "./NodeDetailPage";
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
const tree = () => <QueryClientProvider client={client}><TablePreferencesProvider identity={identity ? { ...identity } : null}><TestRouter path="/clusters/$id/nodes/$nodeName" history={history}><NodeDetailPage /></TestRouter></TablePreferencesProvider></QueryClientProvider>;
async function render(search = "") { history = createMemoryHistory({ initialEntries: [`/clusters/cluster/nodes/node${search}`] }); await act(async () => root.render(tree())); }
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
const rows = () => host.querySelectorAll('[data-testid="node-host-findings-table"] tbody tr');
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label || item.getAttribute("data-export-label") === label)!;
async function click(label: string) { await act(async () => button(label).click()); }
async function field(selector: string, value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement | HTMLSelectElement>(selector)!; Object.getOwnPropertyDescriptor(input.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event(input.tagName === "SELECT" ? "change" : "input", { bubbles: true })); }); }
const header = (id: string) => host.querySelector(`th[data-column-id="${id}"]`)!;

async function showIdentifiers() {
 await act(async () => { host.querySelector<HTMLButtonElement>('[aria-label="Columns"]')!.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, button: 0 })); });
 for (const name of ["Instance row ID", "Finding ID"]) {
  const item = [...document.querySelectorAll<HTMLElement>('[role="menuitemcheckbox"]')].find((value) => value.textContent === name || value.getAttribute("aria-label") === name || value.getAttribute("data-export-label") === name)!;
  expect(item).toBeDefined();
  await act(async () => item.click());
 }
 await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })));
}

it("continues past 2000 findings with honest instance/advisory units and server-page CSV", async () => {
 await render("?page=21&sort=package&order=asc"); await settle(() => expect(rows()).toHaveLength(100)); expect(nodes.vulnerabilities).toHaveBeenLastCalledWith("cluster", "node", expect.objectContaining({ offset: 2000, limit: 100 })); expect(rows()[0].textContent).toContain("package-2000"); expect(host.textContent).toContain("2,105 matching finding instances"); expect(host.textContent).toContain("1 unique CVE / advisory IDs"); expect(host.textContent).not.toContain("Server fetch limit: 2,000"); expect(host.querySelector('[data-testid="node-stats"] [data-testid="verdict-numbers"]')!.children).toHaveLength(4); expect(host.textContent).toContain("Open host findings");
 await click("Export this page CSV"); const [, , exported] = vi.mocked(downloadCsv).mock.calls[0]; expect(exported).toHaveLength(100); expect(exported.flat()).toContain("package-2000"); expect(exported.flat()).not.toContain("package-2100"); await click("Next"); await settle(() => expect(rows()).toHaveLength(5)); expect(rows()[0].textContent).toContain("package-2100");
});
it("searches the server tail and filters before paging while retaining URL context and focus", async () => {
 await render("?page=21&sort=package&order=asc&context=a&context=b#host"); await settle(() => expect(rows()).toHaveLength(100)); const input = host.querySelector<HTMLInputElement>('[aria-label="Search node host findings"]')!; input.focus(); await field('[aria-label="Search node host findings"]', "package-2104"); expect(document.activeElement).toBe(input); await settle(() => expect(rows()).toHaveLength(1)); expect(nodes.vulnerabilities).toHaveBeenLastCalledWith("cluster", "node", expect.objectContaining({ q: "package-2104", offset: 0 })); const params = new URLSearchParams(history.location.search); expect(params.has("page")).toBe(false); expect(params.getAll("context")).toEqual(["a", "b"]); expect(history.location.hash).toBe("#host");
});
it("restores severity, fixability, exact source and sorting through URL history", async () => {
 await render("?sort=package&order=desc&page=3&context=keep");
 await settle(() => {
  expect(rows()).toHaveLength(100);
  expect(header("package").getAttribute("aria-sort")).toBe("descending");
 });
 await field('[aria-label="Host finding severity"]', "critical");
 await settle(() => expect(nodes.vulnerabilities).toHaveBeenLastCalledWith("cluster", "node", expect.objectContaining({ severity: "critical", offset: 0 })));
 await field('[aria-label="Host finding fixability"]', "true");
 await settle(() => {
  expect(rows()).toHaveLength(100);
  expect(host.textContent).toContain("351 matching finding instances");
 });
 await field('[aria-label="Host finding source"]', "trivy");
 // Request dispatch precedes React Query's result notification. Wait for the
 // filtered table to render before interacting with its sorting control.
 await settle(() => {
  expect(nodes.vulnerabilities).toHaveBeenLastCalledWith("cluster", "node", expect.objectContaining({ severity: "critical", fixable: "true", source: "trivy" }));
  expect(rows()).toHaveLength(100);
  expect(header("package").getAttribute("aria-sort")).toBe("descending");
 });
 await act(async () => header("package").querySelector<HTMLButtonElement>("button")!.click());
 await settle(() => {
  expect(header("package").getAttribute("aria-sort")).toBe("ascending");
  expect(rows()[0].textContent).toContain("package-0000");
 });
 await act(async () => history.back());
 await settle(() => expect(header("package").getAttribute("aria-sort")).toBe("descending"));
 await act(async () => history.back());
 await settle(() => expect(host.querySelector<HTMLSelectElement>('[aria-label="Host finding fixability"]')!.value).toBe(""));
 expect(history.location.search).toContain("context=keep");
});

it("keeps exact selected finding identity across pages without substituting identical CVE/package rows", async () => {
 const items = Array.from({ length: 205 }, (_, i) => ({ ...finding(i), package_name: "identical-package" })); vi.mocked(nodes.vulnerabilities).mockImplementation(async (cluster, name, params) => response(cluster, name, params, items)); await render("?selected=finding-204%3A1791763200.000000"); await settle(() => expect(host.querySelector("dl:not([data-testid=verdict-numbers])")?.textContent).toContain("finding-204")); expect(rows()).toHaveLength(100); await click("Next"); await settle(() => expect(rows()).toHaveLength(100)); expect(host.querySelector("dl:not([data-testid=verdict-numbers])")).toBeNull(); expect(host.textContent).toContain("no other finding has been substituted"); expect(new URLSearchParams(history.location.search).get("selected")).toBe("finding-204:1791763200.000000"); await act(async () => history.back()); await settle(() => expect(host.querySelector("dl:not([data-testid=verdict-numbers])")?.textContent).toContain("finding-204"));
});
it("accepts source-only and target-only rows and discloses their actual distinct cluster identities", async () => {
 const items = [{ ...finding(0), cluster_id: "sibling" }, { ...finding(1), source_cluster_id: "sibling" }]; const initial = detail(); initial.vulnerabilities = [items[0]]; vi.mocked(nodes.get).mockResolvedValue(initial); vi.mocked(nodes.vulnerabilities).mockImplementation(async (cluster, name, params) => response(cluster, name, params, items)); await render("?selected=finding-0%3A1791763200.000000&order=asc"); await settle(() => expect(rows()).toHaveLength(2)); expect(host.querySelector("dl:not([data-testid=verdict-numbers])")?.textContent).toContain("Source cluster IDcluster"); expect(host.querySelector("dl:not([data-testid=verdict-numbers])")?.textContent).toContain("Effective target cluster IDsibling"); expect(rows()[0].querySelector<HTMLAnchorElement>("a")?.getAttribute("href")).toBe("/clusters/cluster/cve/CVE-shared");
});
it("exports matching scope and filters across pages with cap/error feedback", async () => {
 await render("?q=package&severity=high&fixable=true&source=grype&sort=package&order=asc&page=3"); await settle(() => expect(rows()).toHaveLength(100)); await click("Export matching CSV"); expect(nodes.exportVulnerabilitiesCSV).toHaveBeenCalledWith("cluster", "node", expect.objectContaining({ q: "package", severity: "high", fixable: "true", source: "grype", sort: "package", order: "asc", offset: 200 }), expect.any(Function)); await settle(() => expect(host.textContent).toContain("Exported all 2,105 matching records across pages")); vi.mocked(nodes.exportVulnerabilitiesCSV).mockResolvedValueOnce({ total: 100001, exported: 100000, limit: 100000, truncated: true }); await click("Export matching CSV"); await settle(() => expect(host.textContent).toContain("Export capped at 100,000 of 100,001")); vi.mocked(nodes.exportVulnerabilitiesCSV).mockRejectedValueOnce(new Error("private error")); await click("Export matching CSV"); await settle(() => expect(host.textContent).toContain("Matching CSV could not be exported")); expect(host.textContent).not.toContain("private error");
});
it("retains current evidence during refresh but hides failed inventory and selection, with Retry", async () => {
 await render("?selected=finding-2104%3A1791763200.000000"); await settle(() => expect(rows()).toHaveLength(100)); let reject!: (reason: Error) => void; vi.mocked(nodes.vulnerabilities).mockImplementationOnce(() => new Promise((_yes, no) => { reject = no; })); let pending!: Promise<void>; await act(async () => { pending = client.invalidateQueries({ queryKey: ["node-vulnerabilities"] }); }); await settle(() => expect(host.textContent).toContain("Refreshing host findings")); expect(rows()).toHaveLength(100); expect(button("Export matching CSV").disabled).toBe(true); await act(async () => { reject(new Error("private fetch failure")); await pending; }); await settle(() => expect(button("Retry host findings")).toBeDefined()); expect(rows()).toHaveLength(0); expect(host.querySelector("dl:not([data-testid=verdict-numbers])")).toBeNull(); expect(button("Export matching CSV")).toBeUndefined(); expect(host.textContent).not.toContain("0 matching finding instances"); expect(host.textContent).not.toContain("private fetch failure"); await click("Retry host findings"); await settle(() => expect(rows()).toHaveLength(100));
});
it("refreshes both node posture and its independent full finding inventory", async () => {
 await render(); await settle(() => expect(rows()).toHaveLength(100)); await click("Refresh"); await settle(() => expect(nodes.get).toHaveBeenCalledTimes(2)); await settle(() => expect(nodes.vulnerabilities).toHaveBeenCalledTimes(2));
});
it.each(["cluster", "node", "row scope", "row node", "IDs", "metadata", "summary", "page", "filter"])("withholds %s mismatches instead of treating them as an empty successful scan", async defect => {
 vi.mocked(nodes.vulnerabilities).mockImplementation(async (cluster, name, params) => { const data = response(cluster, name, params); if (defect === "cluster") data.cluster_id = "other"; if (defect === "node") data.node = "other"; if (defect === "row scope") data.items[0].cluster_id = data.items[0].source_cluster_id = "other"; if (defect === "row node") data.items[0].node = "other"; if (defect === "IDs") data.items[1].row_id = data.items[0].row_id; if (defect === "metadata") data.total = 1; if (defect === "summary") delete (data as Partial<NodeVulnerabilityResponse>).summary; if (defect === "page") data.offset = 100; if (defect === "filter") data.severity = "critical"; return data; }); await render(); await settle(() => expect(button("Retry host findings")).toBeDefined()); expect(rows()).toHaveLength(0); expect(button("Export matching CSV")).toBeUndefined(); expect(host.textContent).not.toContain("No matching host finding instances returned");
});
it.each(["0", "bad", String(INVENTORY_MAX_PAGE + 1)])("rejects URL page %s before fetching a different page", async page => {
 await render(`?page=${page}&context=keep`); await settle(() => expect(host.textContent).toContain("Choose supported host finding filters")); expect(nodes.vulnerabilities).not.toHaveBeenCalled(); await click("Reset host finding filters"); await settle(() => expect(rows()).toHaveLength(100)); expect(history.location.search).toContain("context=keep");
});
it("recovers an out-of-range server page while retaining full matching totals and exact selection", async () => {
 await render("?page=99&selected=finding-2104%3A1791763200.000000"); await settle(() => expect(button("First page")).toBeDefined()); expect(host.textContent).toContain("2,105 matching finding instances"); expect(host.textContent).toContain("Showing 0–0 of 2,105"); expect(host.textContent).toContain("no other finding has been substituted"); await click("First page"); await settle(() => expect(rows()).toHaveLength(100)); expect(host.querySelector("dl:not([data-testid=verdict-numbers])")?.textContent).toContain("finding-2104");
});
it.each(["foreign", "loading", "error", "identity"])("does not read node or findings until %s scope resolves", async condition => {
 if (condition === "foreign") scope.resolved = "other"; if (condition === "loading") scope.loading = true; if (condition === "error") scope.error = new Error("scope failed"); if (condition === "identity") identity = null; await render(); expect(nodes.get).not.toHaveBeenCalled(); expect(nodes.vulnerabilities).not.toHaveBeenCalled(); expect(rows()).toHaveLength(0);
});
it("does not reuse finding evidence after node, cluster or owner navigation", async () => {
 await render("?selected=finding-2104%3A1791763200.000000"); await settle(() => expect(rows()).toHaveLength(100)); await act(async () => history.push("/clusters/other/nodes/node%252Fa")); await settle(() => expect(nodes.vulnerabilities).toHaveBeenLastCalledWith("other", "node%2Fa", expect.anything())); await settle(() => expect(rows()).toHaveLength(100)); expect(host.querySelector('a[href^="/clusters/cluster/"]')).toBeNull(); identity = { org_id: "new-org", user_id: "new-user" }; vi.mocked(nodes.get).mockRejectedValueOnce(new Error("new owner unavailable")); await act(async () => root.render(tree())); await settle(() => expect(button("Retry node")).toBeDefined()); expect(rows()).toHaveLength(0); expect(button("Export matching CSV")).toBeUndefined();
});
it("loads host inventory only in its URL tab and restores it after peer evidence browsing", async () => {
 await render("?tab=cis&context=keep"); await settle(() => expect(host.textContent).toContain("No CIS benchmark results")); expect(nodes.vulnerabilities).not.toHaveBeenCalled(); const tab = [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((item) => item.textContent === "Host vulnerabilities" || item.getAttribute("aria-label") === "Host vulnerabilities" || item.getAttribute("data-export-label") === "Host vulnerabilities")!; await act(async () => tab.focus()); await settle(() => expect(rows()).toHaveLength(100)); expect(history.location.search).toContain("context=keep"); await act(async () => history.back()); await settle(() => expect(host.textContent).toContain("No CIS benchmark results")); expect(rows()).toHaveLength(0);
});

it("hides malformed cached finding rows before any refresh can label them current evidence", async () => {
 await render("?selected=finding-2104%3A1791763200.000000"); await settle(() => expect(rows()).toHaveLength(100)); const key = client.getQueriesData<NodeVulnerabilityResponse>({ queryKey: ["node-vulnerabilities"] })[0][0];
 await act(async () => client.setQueryData<NodeVulnerabilityResponse>(key, data => ({ ...data!, items: undefined as unknown as NodeVulnerability[] })));
 await settle(() => expect(button("Retry host findings")).toBeDefined()); expect(rows()).toHaveLength(0); expect(host.querySelector("dl:not([data-testid=verdict-numbers])")).toBeNull(); expect(button("Export matching CSV")).toBeUndefined(); expect(host.textContent).not.toContain("No matching host finding instances returned");
});

it("keeps both instances of one finding UUID at distinct first-seen timestamps selectable and exportable", async () => {
 const items = [{ ...finding(0), id: "same-finding", row_id: "same-finding:1791763200.000000" }, { ...finding(0), id: "same-finding", row_id: "same-finding:1791763200.000001", first_seen_at: "2026-10-12T00:00:00.000001Z" }];
 vi.mocked(nodes.vulnerabilities).mockImplementation(async (cluster, name, params) => response(cluster, name, params, items)); await render("?order=asc"); await settle(() => expect(rows()).toHaveLength(2)); expect(host.textContent).toContain("2 matching finding instances");
 await act(async () => (rows()[0] as HTMLElement).click()); await settle(() => expect(new URLSearchParams(history.location.search).get("selected")).toBe(items[0].row_id));
 await act(async () => (rows()[1] as HTMLElement).click()); await settle(() => expect(new URLSearchParams(history.location.search).get("selected")).toBe(items[1].row_id)); expect(host.querySelector("dl:not([data-testid=verdict-numbers])")?.textContent).toContain("Finding IDsame-finding");
 await showIdentifiers(); await click("Export this page CSV"); const [, headers, exported] = vi.mocked(downloadCsv).mock.calls[0]; const rowID = headers.indexOf("Instance row ID"), findingID = headers.indexOf("Finding ID"); expect(exported).toHaveLength(2); expect(exported[0][findingID]).toBe(exported[1][findingID]); expect(exported[0][rowID]).not.toBe(exported[1][rowID]);
});

it("keeps both identifier columns opt-in while preserving matching CSV and explicit saved visibility", async () => {
 await render(); await settle(() => expect(rows()).toHaveLength(100)); expect(host.querySelector('th[data-column-id="row_id"]')).toBeNull(); expect(host.querySelector('th[data-column-id="id"]')).toBeNull();
 await click("Export matching CSV"); await settle(() => expect(nodes.exportVulnerabilitiesCSV).toHaveBeenCalledWith("cluster", "node", expect.anything(), expect.any(Function)));
 await showIdentifiers(); expect(host.querySelector('th[data-column-id="row_id"]')).not.toBeNull(); expect(host.querySelector('th[data-column-id="id"]')).not.toBeNull();
 await click("Next"); await settle(() => expect(rows()).toHaveLength(100)); expect(host.querySelector('th[data-column-id="row_id"]')).not.toBeNull(); expect(host.querySelector('th[data-column-id="id"]')).not.toBeNull();
 const saved = [...Array.from({ length: localStorage.length }, (_, i) => localStorage.key(i))].find(key => key?.includes("node-host-vulnerabilities"))!; expect(JSON.parse(localStorage.getItem(saved)!).hiddenColumnIds).toEqual([]);
});
it("removes repeated advisory descriptions, retains distinct aliases and collapses supporting inventory context", async () => {
 const items = [{ ...finding(0), summary: " CVE-shared ", aliases: ["CVE-shared"] }, { ...finding(1), summary: "CVE-shared", aliases: ["CVE-shared", "GHSA-distinct"] }, { ...finding(2), summary: "A useful vulnerability explanation" }];
 vi.mocked(nodes.vulnerabilities).mockImplementation(async (cluster, name, params) => response(cluster, name, params, items)); await render("?order=asc"); await settle(() => expect(rows()).toHaveLength(3));
 expect(rows()[0].querySelector('td[data-column-id="cve"]')!.textContent).toBe("CVE-shared"); expect(rows()[1].querySelector('td[data-column-id="cve"]')!.textContent).toBe("CVE-sharedGHSA-distinct"); expect(rows()[2].textContent).toContain("A useful vulnerability explanation");
 const summary = [...host.querySelectorAll("summary")].find((item) => item.textContent === "Inventory details" || item.getAttribute("aria-label") === "Inventory details" || item.getAttribute("data-export-label") === "Inventory details")!; expect(summary).toBeDefined(); expect(summary.parentElement?.getAttribute("open")).toBeNull(); expect(host.textContent).toContain("3 matching finding instances");
});
