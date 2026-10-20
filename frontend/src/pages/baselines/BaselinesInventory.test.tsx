import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { baselines, type BaselineInventoryParams, type BaselineInventoryResponse, type BaselineInventoryRow } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { chooseExport, exportItem, exportTriggers, openExportMenu } from "@/test/export-menu";
import { setIncludeSystemPreference } from "@/lib/system-scope";
import { BaselinesPage } from "../BaselinesPage";

const context = vi.hoisted(() => ({ clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null as Error | null, org: "org", user: "operator" }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => context }));
vi.mock("@/api/client", () => ({ baselines: { inventory: vi.fn(), inventoryCSV: vi.fn(), list: vi.fn() } }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
const profile = (i: number): BaselineInventoryRow => ({
  cluster_id: "cluster", workload_id: `default/workload-${i.toString().padStart(4, "0")}`, row_id: JSON.stringify(["cluster", `default/workload-${i.toString().padStart(4, "0")}`]), namespace: "default", name: `workload-${i.toString().padStart(4, "0")}`, mode: i === 550 ? "monitor" : i === 600 ? "enforce" : "learn", owner_count: 1, owner_ambiguous: false, configured: true, platform_role: i === 0 ? "core" : "", learned_processes_count: 1, monitored_alerts_24h: 2, enforced_blocks_24h: 0, rule_count: 1,
  top_processes: ["nginx"], learn_started_at: "2026-09-01T00:00:00Z", last_new_process_at: "2026-10-01T00:00:00Z",
});
const cohort = () => Array.from({ length: 601 }, (_, i) => profile(i));
function response(request: BaselineInventoryParams, source = cohort()): BaselineInventoryResponse {
  const rows = source.filter(p => (!request.q || `${p.namespace}/${p.name}`.includes(request.q)) && (!request.namespace || p.namespace === request.namespace) && (!request.mode || p.mode === request.mode) && (!request.hide_platform || p.platform_role !== "core"));
  const offset = request.offset ?? 0;
  return { profiles: rows.slice(offset, offset + 100), total: rows.length, has_more: offset + 100 < rows.length, limit: 100, offset, sort: request.sort ?? "workload", order: request.order ?? "asc", cluster_id: request.cluster_id, filters: { q: request.q ?? "", namespace: request.namespace ?? "", mode: request.mode ?? "", hide_platform: request.hide_platform ?? false }, namespaces: ["default"], source_complete: true, summary_scope: "matching_retained_process_events", summary: { total: rows.length, learn: rows.filter(p => p.mode === "learn").length, monitor: rows.filter(p => p.mode === "monitor").length, enforce: rows.filter(p => p.mode === "enforce").length, processes: rows.length, alerts_24h: rows.length * 2, blocks_24h: 0, rules: rows.length, ambiguous_owners: 0 } };
}
let root: Root, host: HTMLDivElement, client: QueryClient, history: RouterHistory;
const tree = () => <QueryClientProvider client={client}><TablePreferencesProvider identity={{org_id:context.org,user_id:context.user}}><TestRouter path="/clusters/$id/runtime/baselines" history={history}><BaselinesPage /></TestRouter></TablePreferencesProvider></QueryClientProvider>;
beforeEach(() => {
  (globalThis as typeof globalThis & {IS_REACT_ACT_ENVIRONMENT:boolean}).IS_REACT_ACT_ENVIRONMENT=true;
  localStorage.clear(); setIncludeSystemPreference(true); Object.assign(context, { clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null, org: "org", user: "operator" });
  vi.mocked(baselines.inventory).mockImplementation(async request => response(request));
  vi.mocked(baselines.inventoryCSV).mockResolvedValue({ total: 601, exported: 601, limit: 100000, truncated: false });
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.restoreAllMocks(); localStorage.clear(); });
async function render(search = "") {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); history = createMemoryHistory({ initialEntries: [`/clusters/cluster/runtime/baselines${search}`] });
  await act(async () => root.render(tree()));
}
async function settled(check: () => void | Promise<void>) { await vi.waitFor(async () => { await act(async () => {}); await check(); }); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent?.trim() === label || b.getAttribute("aria-label") === label)!;
async function click(label: string) { await act(async () => button(label).click()); }
async function choose(label: string, value: string) { await act(async () => { const input = host.querySelector<HTMLSelectElement>(`select[aria-label="${label}"]`)!; Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("change", { bubbles: true })); }); }
async function search(value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement>('[aria-label="Search workloads"]')!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function tab(label: string) { await act(async () => [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((t) => t.textContent === label || t.getAttribute("aria-label") === label)!.focus()); }

it("uses full-cohort KPIs and fetches beyond500 while lifecycle cards remain page-scoped", async () => {
  await render("?page=6&custom=keep"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(100));
  expect(baselines.inventory).toHaveBeenLastCalledWith(expect.objectContaining({ cluster_id: "cluster", offset: 500, limit: 100, sort: "workload", order: "asc" })); expect(baselines.list).not.toHaveBeenCalled();
  expect(host.textContent).toContain("601 matching workload profiles"); expect([...host.querySelectorAll('.app-stat-value')].map(e => e.textContent)).toEqual(["601", "599", "1", "1"]);
  await click("Next"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1)); expect(history.location.search).toContain("page=7"); expect(history.location.search).toContain("custom=keep"); expect(host.querySelector('a[href$="default%2Fworkload-0600"]')).not.toBeNull();
  await tab("Lifecycle"); await settled(() => expect(host.querySelector('[data-testid="baselines-columns"]')).not.toBeNull()); expect(host.textContent).toContain("Current server page: 1 of 601 matching profiles"); expect(host.querySelectorAll('[data-testid^="baselines-card-default/"]')).toHaveLength(1);
  await act(async () => history.back()); await settled(() => expect(host.querySelector('[data-testid="baselines-table"]')).not.toBeNull()); expect(history.location.search).toContain("page=7");
  await act(async () => history.back()); await settled(() => expect(baselines.inventory).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 500 })));
});
it("normalizes literal query and exact namespace and restores filter history", async () => {
  await render("?q=%20WORKLOAD-0550%20&namespace=%20default%20&mode=monitor&hide_platform=true&sort=rules&order=desc&custom=keep");
  await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1)); expect(baselines.inventory).toHaveBeenLastCalledWith(expect.objectContaining({ q: "workload-0550", namespace: "default", mode: "monitor", hide_platform: true, sort: "rules", order: "desc" }));
  await choose("Mode", "enforce"); await settled(() => expect(baselines.inventory).toHaveBeenLastCalledWith(expect.objectContaining({ mode: "enforce", offset: 0 })));
  await act(async () => history.back()); await settled(() => expect(baselines.inventory).toHaveBeenLastCalledWith(expect.objectContaining({ mode: "monitor" })));
  await search("workload-0600"); expect(button("Refresh").disabled).toBe(true); await settled(() => expect(baselines.inventory).toHaveBeenLastCalledWith(expect.objectContaining({ q: "workload-0600", mode: "monitor" }))); expect(history.location.search).toContain("custom=keep");
});
it("keeps server row order and sends shared table sorting to URL/server", async () => {
  vi.mocked(baselines.inventory).mockImplementation(async request => response(request, [profile(600), profile(500)]));
  await render(); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(2)); expect(host.querySelector("tbody tr")?.textContent).toContain("workload-0600");
  await act(async () => [...host.querySelectorAll<HTMLButtonElement>("thead button")].find(b => b.textContent?.includes("Workload"))!.click());
  await settled(() => expect(baselines.inventory).toHaveBeenLastCalledWith(expect.objectContaining({ sort: "workload", order: "desc", offset: 0 }))); expect(history.location.search).toContain("order=desc");
});
it("exports the full matching cohort separately from current-page visible columns", async () => {
  await render("?page=7"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1)); await chooseExport("Matching rows", host);
  await settled(() => expect(baselines.inventoryCSV).toHaveBeenCalledWith(expect.objectContaining({ cluster_id: "cluster", offset: 600, hide_platform: false }), expect.any(Function)));
  await settled(() => expect(host.textContent).toContain("Exported all 601 matching records across pages"));
  await chooseExport("This table", host); const [, headers, rows] = vi.mocked(downloadCsv).mock.calls.at(-1)!; expect(rows).toHaveLength(1); expect(rows[0][headers.indexOf("Workload")]).toBe("default/workload-0600"); expect(headers).not.toContain("Platform role");
});
it("suppresses failed-refresh rows, totals and exports and recovers without dropping filters", async () => {
  await render("?namespace=default&page=7"); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); vi.mocked(baselines.inventory).mockRejectedValue(new Error("private failed source"));
  await act(async () => client.invalidateQueries({ queryKey: ["baselines-inventory"] })); await settled(() => expect(host.textContent).toContain("Could not load or refresh process profiles")); expect(host.querySelector("tbody")).toBeNull(); expect(host.textContent).not.toContain("601 matching workload profiles"); expect(exportTriggers(host)).toHaveLength(0); expect(host.textContent).not.toContain("private failed source");
  vi.mocked(baselines.inventory).mockImplementation(async request => response(request)); await click("Retry"); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); expect(history.location.search).toContain("page=7");
});
it.each(["loading", "foreign", "error", "empty-owner"])("gates unresolved %s scope", async condition => {
  if (condition === "loading") context.isLoading = true; if (condition === "foreign") context.cluster = { id: "other" }; if (condition === "error") context.error = new Error("scope unavailable"); if (condition === "empty-owner") context.org = "";
  await render(); expect(baselines.inventory).not.toHaveBeenCalled(); expect(host.querySelector("tbody")).toBeNull();
});
it("isolates account inventories and blocks a retained export control after owner/scope change", async () => {
  await render("?page=7"); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); await openExportMenu(host); const oldExport = exportItem("Matching rows")!;
  vi.mocked(baselines.inventory).mockRejectedValue(new Error("new account unavailable")); context.org = "other-org"; await act(async () => root.render(tree()));
  await settled(() => expect(host.textContent).toContain("Could not load or refresh process profiles")); expect(host.querySelector("tbody")).toBeNull(); expect(client.getQueryCache().findAll({ queryKey: ["baselines-inventory"] })).toHaveLength(2);
  await act(async () => oldExport.click()); expect(baselines.inventoryCSV).not.toHaveBeenCalled();
  context.clusterId = "sibling"; context.cluster = { id: "cluster" }; await act(async () => root.render(tree())); expect(host.querySelector("tbody")).toBeNull(); expect(baselines.inventoryCSV).not.toHaveBeenCalled();
});
it.each(["invalidated", "fetching", "error", "foreign", "cluster-cache"])("rejects %s state at export click before rerender", async condition => {
  await render(); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); await openExportMenu(host); const exportButton=exportItem("Matching rows")!;
  await act(async () => { const q = client.getQueryCache().findAll({ queryKey: ["baselines-inventory"] })[0]!; if (condition === "invalidated") q.setState({ isInvalidated: true }); if (condition === "fetching") q.setState({ fetchStatus: "fetching" }); if (condition === "error") q.setState({ status: "error", error: new Error("source unavailable") }); if (condition === "foreign") client.setQueryData(q.queryKey, { ...q.state.data as BaselineInventoryResponse, cluster_id: "foreign" }); if(condition==="cluster-cache")client.setQueryData(["clusters"],{clusters:[{id:"other"}]}); exportButton.click(); });
  await settled(() => expect(host.querySelector("tbody")).toBeNull()); expect(exportTriggers(host)).toHaveLength(0); expect(baselines.inventoryCSV).not.toHaveBeenCalled();
});
it.each(["null", "foreign", "duplicate", "count", "missing-name", "identity", "source", "filters"])("rejects malformed %s evidence", async condition => {
  vi.mocked(baselines.inventory).mockImplementation(async request => { const value = response(request); if (condition === "null") value.profiles[0] = null as unknown as BaselineInventoryRow; if (condition === "foreign") value.profiles[0].cluster_id = "foreign"; if (condition === "duplicate") value.profiles[1] = { ...value.profiles[0] }; if (condition === "count") value.summary.total = 0; if (condition === "missing-name") delete (value.profiles[0] as Partial<BaselineInventoryRow>).name; if (condition === "identity") value.profiles[0].row_id = '["cluster","different"]'; if (condition === "source") value.source_complete = false; if (condition === "filters") value.filters.mode = "enforce"; return value; });
  await render(); await settled(() => expect(host.textContent).toContain("Could not load or refresh process profiles")); expect(host.querySelector("tbody")).toBeNull(); expect(host.textContent).not.toContain("0 matching workload profiles");
});
it.each(["?mode=invalid", "?sort=unsafe", "?order=sideways", "?hide_platform=maybe", "?page=0", "?page=1.5", `?page=${INVENTORY_MAX_PAGE + 1}`, "?namespace=a&namespace=b"])("rejects unsupported URL %s", async url => {
  await render(url); await settled(() => expect(host.textContent).toContain("Choose supported profile filters")); expect(baselines.inventory).not.toHaveBeenCalled();
});
it("supports the continuation ceiling and recovers an empty page", async () => {
  await render(`?page=${INVENTORY_MAX_PAGE}`); await settled(() => expect(button("First page")).toBeDefined()); expect(baselines.inventory).toHaveBeenLastCalledWith(expect.objectContaining({ offset: (INVENTORY_MAX_PAGE - 1) * 100 }));
  await click("First page"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(100)); expect(new URLSearchParams(history.location.search).has("page")).toBe(false);
});
it("filters core workloads before pagination while allowing the complete collection", async () => {
  await render("?hide_platform=true"); await settled(() => expect(host.textContent).toContain("600 matching workload profiles")); expect(host.querySelector("tbody")?.textContent).not.toContain("workload-0000");
  await act(async () => { history.push(`${history.location.pathname}`); }); await settled(() => expect(host.textContent).toContain("601 matching workload profiles")); expect(host.querySelector("tbody")?.textContent).toContain("workload-0000");
});

it("retains repeated top process names from different executable identities without duplicate keys", async () => {
 const errors=vi.spyOn(console,"error");const row=profile(600);row.top_processes=["nginx","nginx"];
 vi.mocked(baselines.inventory).mockImplementation(async request=>response(request,[row]));
 await render("?tab=lifecycle");await settled(()=>expect(host.querySelectorAll('[data-testid="baselines-card-hover-procs"] span')).toHaveLength(2));
 expect(errors.mock.calls.flat().join(" ")).not.toContain("same key");
});
