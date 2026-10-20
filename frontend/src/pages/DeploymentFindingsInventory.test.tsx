import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { deployments, type DeploymentDetail, type DeploymentFindingsResponse, type DeploymentFindingInventoryRow } from "@/api/client";
import { TablePreferencesProvider, useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { downloadCsv } from "@/lib/csv";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { TestRouter } from "@/test/router";
import { DeploymentFindingsInventory } from "./DeploymentFindingsInventory";
import { fixtureDeployment } from "./deployment-detail/test-fixtures";
import { deploymentFindingFixture, deploymentFindingPage } from "./deployment-findings/test-fixtures";

const scope = vi.hoisted(() => ({ clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({ deployments: { findings: vi.fn(), findingsCSV: vi.fn() } }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
let root: Root, host: HTMLDivElement, client: QueryClient, history: RouterHistory, detail: DeploymentDetail;
const owner = { org_id: "org", user_id: "operator" };
const sourceKey = ["deployment", "cluster", "deployment"];
const inventoryQueries = () => client.getQueryCache().findAll({ queryKey: ["deployment-findings-inventory"] });
const corpus = () => Array.from({ length: 1305 }, (_, i) => deploymentFindingFixture(i));
function Harness() { useTablePreferencesIdentity(); return <DeploymentFindingsInventory deployment={detail} sourceQueryKey={sourceKey} sourceKind="detail" sourceReady />; }
const tree = () => <QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...owner }}><TestRouter path="/clusters/$id/deployments/$did" history={history}><Harness /></TestRouter></TablePreferencesProvider></QueryClientProvider>;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear(); Object.assign(owner, { org_id: "org", user_id: "operator" }); Object.assign(scope, { clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null }); detail = fixtureDeployment();
  vi.mocked(deployments.findings).mockImplementation(async (id, params) => deploymentFindingPage(params, corpus(), id));
  vi.mocked(deployments.findingsCSV).mockResolvedValue({ total: 1305, exported: 1305, limit: 100000, truncated: false });
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.restoreAllMocks(); localStorage.clear(); });
async function render(search = "", seed?: (client: QueryClient) => void) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); client.setQueryData(sourceKey, detail); seed?.(client); history = createMemoryHistory({ initialEntries: [`/clusters/cluster/deployments/deployment${search}`] }); await act(async () => root.render(tree()));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((b) => b.textContent?.trim() === label || b.getAttribute("aria-label") === label || b.getAttribute("data-export-label") === label)!;
async function click(label: string) { await act(async () => button(label).click()); }
async function search(value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement>('[aria-label="Search deployment findings"]')!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function choose(label: string, value: string) { await act(async () => { const input = host.querySelector<HTMLSelectElement>(`[aria-label="${label}"]`)!; Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("change", { bubbles: true })); }); }
async function inspect(index = 0) { const trigger = host.querySelectorAll<HTMLButtonElement>("tbody td button")[index]; await act(async () => { trigger.focus(); trigger.click(); }); await settled(() => expect(document.querySelector('[data-testid="deployment-finding-record"]')).not.toBeNull()); return trigger; }

it("queries the full cohort beyond1000 with totals and server paging while preserving parent URL context", async () => {
  await render("?tab=findings&findings_page=13&hours=24&custom=keep"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(100)); expect(host.textContent).toContain("1,305 matching workload finding records");
  expect(deployments.findings).toHaveBeenLastCalledWith("deployment", expect.objectContaining({ cluster_id: "cluster", offset: 1200, limit: 100, lifecycle: "open", sort: "risk", order: "desc" }));
  await click("Next"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(5)); expect(host.querySelector("tbody")?.textContent).toContain("Workload finding 1304"); expect(history.location.search).toContain("findings_page=14"); expect(history.location.search).toContain("custom=keep"); expect(history.location.search).toContain("hours=24");
  await act(async () => history.back()); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(100)); expect(history.location.search).toContain("findings_page=13");
});
it("finds tail records on the server, debounces search, resets page and replaces text history", async () => {
  await render("?tab=findings&findings_page=14&custom=keep"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(5));
  await search("  WORKLOAD FINDING 1304  "); expect(host.querySelector("tbody")).toBeNull(); expect(new URLSearchParams(history.location.search).has("findings_page")).toBe(false);
  await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1)); expect(deployments.findings).toHaveBeenLastCalledWith("deployment", expect.objectContaining({ q: "workload finding 1304", offset: 0 })); expect(history.location.search).toContain("tab=findings"); expect(history.location.search).toContain("custom=keep");
});
it("sends lifecycle/severity/fixability and sorting before pagination without resorting returned rows", async () => {
  const rows = [deploymentFindingFixture(9), { ...deploymentFindingFixture(1), lifecycle: "accepted" as const }];
  vi.mocked(deployments.findings).mockImplementation(async (id, params) => deploymentFindingPage(params, rows, id));
  await render("?tab=findings&findings_lifecycle=all&findings_severity=high&findings_fixable=true&findings_sort=finding&findings_order=asc"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(2)); expect(host.querySelector("tbody tr")?.textContent).toContain("finding 9");
  await choose("Deployment finding lifecycle", "accepted"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1)); expect(deployments.findings).toHaveBeenLastCalledWith("deployment", expect.objectContaining({ lifecycle: "accepted", severity: "high", fixable: true }));
  await act(async () => history.back()); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(2));
  await act(async () => [...host.querySelectorAll<HTMLButtonElement>("thead button")].find((b) => b.textContent === "Risk" || b.getAttribute("aria-label") === "Risk" || b.getAttribute("data-export-label") === "Risk")!.click()); await settled(() => expect(deployments.findings).toHaveBeenLastCalledWith("deployment", expect.objectContaining({ sort: "risk", order: "desc", offset: 0 })));
});
it("exports all matching records separately from the selected visible columns on this page", async () => {
  await render("?tab=findings&findings_page=14"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(5)); await click("Export matching CSV"); await settled(() => expect(host.textContent).toContain("Exported all 1,305 matching records across pages"));
  expect(deployments.findingsCSV).toHaveBeenCalledWith("deployment", expect.objectContaining({ cluster_id: "cluster", offset: 1300, limit: 100 }), expect.any(Function));
  await click("Export this page CSV"); const [, headers, rows] = vi.mocked(downloadCsv).mock.calls.at(-1)!; expect(rows).toHaveLength(5); expect(headers).not.toContain("Platform role"); expect(rows[4][headers.indexOf("Finding")]).toBe("Workload finding 1304");
});
it("reports matching export failure without losing rows, filters or retryability", async () => {
  vi.mocked(deployments.findingsCSV).mockRejectedValue(new Error("private export details")); await render("?findings_page=14"); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); await click("Export matching CSV"); await settled(() => expect(host.textContent).toContain("Matching CSV could not be exported")); expect(host.querySelectorAll("tbody tr")).toHaveLength(5); expect(history.location.search).toContain("findings_page=14"); expect(host.textContent).not.toContain("private export details");
});
it("distinguishes same UUID historical observations by full timestamp and uses read-only meaningful inspection", async () => {
  const first = deploymentFindingFixture(), second = { ...first, row_id: `${first.id}:1791842400.000001`, first_seen_at: "2026-10-12T22:00:00.000001Z", title: "Later retained observation", source_cluster_id: "reporter-cluster", target_cluster_id: "cluster" };
  vi.mocked(deployments.findings).mockImplementation(async (id, params) => deploymentFindingPage(params, [first, second], id)); await render(); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(2));
  expect(host.querySelector('a[href*="/findings/"]')).toBeNull(); await inspect(1); const dialog = document.querySelector('[data-testid="deployment-finding-record"]')!; expect(dialog.textContent).toContain("Reported from another cluster");
  expect(dialog.querySelector("dt")?.textContent).toBe("Severity"); expect(document.querySelector('summary')?.textContent).toBe("Source details"); await act(async () => document.querySelector<HTMLElement>('summary')!.click()); expect(dialog.textContent).toContain(second.row_id); expect(dialog.textContent).toContain(second.first_seen_at); expect(dialog.querySelector('[data-testid="deployment-finding-open"]')?.getAttribute('href')).toBe(`/clusters/cluster/findings/${second.id}?${new URLSearchParams({ first_seen_at: second.first_seen_at })}`);
});
it("closes inspection on Escape and returns focus to its keyboard trigger", async () => {
  await render(); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); const trigger = await inspect(); await act(async () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })));
  await settled(() => expect(document.querySelector('[data-testid="deployment-finding-record"]')).toBeNull()); await settled(() => expect(document.activeElement).toBe(trigger));
});
it.each(["inventory", "source", "scope", "filters"])("clears the selected observation when %s changes", async cause => {
  await render(); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); await inspect();
  await act(async () => { if (cause === "inventory") inventoryQueries()[0].setState({ isInvalidated: true }); if (cause === "source") client.getQueryCache().find({ queryKey: sourceKey, exact: true })!.setState({ isInvalidated: true }); if (cause === "scope") { owner.org_id = "other"; root.render(tree()); } if (cause === "filters") history.push("/clusters/cluster/deployments/deployment?findings_severity=critical"); });
  await settled(() => expect(document.querySelector('[data-testid="deployment-finding-record"]')).toBeNull());
});
it("never substitutes a different observation when the selected physical row disappears", async () => {
  await render(); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); await inspect(); await act(async () => client.setQueryData(inventoryQueries()[0].queryKey, deploymentFindingPage({ cluster_id: "cluster", lifecycle: "open", sort: "risk", order: "desc", limit: 100, offset: 0 }, [deploymentFindingFixture(22)])));
  await settled(() => expect(document.querySelector('[data-testid="deployment-finding-record"]')).toBeNull()); expect(host.textContent).toContain("Workload finding 22");
});
it.each(["null", "duplicate", "first-seen", "missing-target", "foreign-target", "source-role", "filters", "summary", "collection", "pod-owner"])("rejects malformed %s inventory safely", async condition => {
  vi.mocked(deployments.findings).mockImplementation(async (id, params) => { const value = deploymentFindingPage(params, corpus(), id); if (condition === "null") value.items[0] = null as unknown as DeploymentFindingInventoryRow; if (condition === "duplicate") value.items[1] = { ...value.items[0] }; if (condition === "first-seen") value.items[0].first_seen_at = "2026-10-12T22:00:00.000001Z"; if (condition === "missing-target") delete (value.items[0] as Partial<DeploymentFindingInventoryRow>).target_ref; if (condition === "foreign-target") value.items[0].effective_target_cluster_id = "foreign"; if (condition === "source-role") { value.items[0].source_cluster_id = "other"; value.items[0].target_cluster_id = "cluster"; value.items[0].platform_role = "core"; } if (condition === "filters") value.filters.lifecycle = "all"; if (condition === "summary") value.summary.open = 0; if (condition === "collection") value.source_complete = false; if (condition === "pod-owner") { value.items[0].attribution = "pod"; value.items[0].target_ref = "payments/pod/app-abc"; value.items[0].owner_count = 2; value.items[0].owner_ambiguous = true; } return value; });
  await render(); await settled(() => expect(host.textContent).toContain("Deployment workload findings are unavailable")); expect(host.querySelector("tbody")).toBeNull(); expect(button("Export matching CSV")).toBeUndefined();
});
it("withholds cached rows on failed refresh, then recovers the requested page", async () => {
  await render("?findings_page=14"); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); vi.mocked(deployments.findings).mockRejectedValue(new Error("refresh failed")); await act(async () => client.invalidateQueries({ queryKey: ["deployment-findings-inventory"] })); await settled(() => expect(host.textContent).toContain("Deployment workload findings are unavailable")); expect(host.querySelector("tbody")).toBeNull();
  vi.mocked(deployments.findings).mockImplementation(async (id, params) => deploymentFindingPage(params, corpus(), id)); await click("Retry findings"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(5)); expect(history.location.search).toContain("findings_page=14");
});
it.each(["invalidated", "fetching", "error", "foreign", "parent", "registry"])("blocks matching export against %s cache before rerender", async condition => {
  await render(); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); const action = button("Export matching CSV");
  await act(async () => { const query = inventoryQueries()[0]; if (condition === "invalidated") query.setState({ isInvalidated: true }); if (condition === "fetching") query.setState({ fetchStatus: "fetching" }); if (condition === "error") query.setState({ status: "error", error: new Error("unavailable") }); if (condition === "foreign") client.setQueryData(query.queryKey, { ...query.state.data as DeploymentFindingsResponse, deployment_id: "foreign" }); if (condition === "parent") client.getQueryCache().find({ queryKey: sourceKey, exact: true })!.setState({ isInvalidated: true }); if (condition === "registry") client.setQueryData(["clusters"], { clusters: [{ id: "other" }] }); action.click(); });
  await settled(() => expect(host.querySelector("tbody")).toBeNull()); expect(deployments.findingsCSV).not.toHaveBeenCalled();
});
it("isolates operator inventories and suppresses a retained export button after owner and deployment changes", async () => {
  await render(); await settled(() => expect(host.querySelector("tbody tr")).not.toBeNull()); const old = button("Export matching CSV"); vi.mocked(deployments.findings).mockRejectedValue(new Error("new account unavailable")); owner.org_id = "other-org"; await act(async () => root.render(tree()));
  await settled(() => expect(host.textContent).toContain("Deployment workload findings are unavailable")); expect(inventoryQueries()).toHaveLength(2); expect(host.querySelector("tbody")).toBeNull(); await act(async () => old.click()); expect(deployments.findingsCSV).not.toHaveBeenCalled();
  detail = { ...detail, id: "different-deployment" }; await act(async () => root.render(tree())); expect(host.querySelector("tbody")).toBeNull();
});
it.each(["?findings_page=0", "?findings_page=1.5", `?findings_page=${INVENTORY_MAX_PAGE + 1}`, "?findings_sort=bad", "?findings_order=bad", "?findings_lifecycle=bad", "?findings_severity=bad", "?findings_fixable=bad", "?findings_q=a&findings_q=b"])("rejects unsafe URL %s before querying", async query => {
  await render(query); expect(host.textContent).toContain("Choose supported deployment finding filters"); expect(deployments.findings).not.toHaveBeenCalled();
});
it("supports the continuation ceiling and recovers an empty page", async () => {
  await render(`?findings_page=${INVENTORY_MAX_PAGE}`); await settled(() => expect(button("First page")).toBeDefined()); expect(deployments.findings).toHaveBeenLastCalledWith("deployment", expect.objectContaining({ offset: (INVENTORY_MAX_PAGE - 1) * 100 })); await click("First page"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(100));
});

it("retains legacy lifecycle observations under all without claiming a healthy or completed status", async () => {
 const row={...deploymentFindingFixture(),lifecycle:"legacy-retained-state"};vi.mocked(deployments.findings).mockImplementation(async(id,params)=>deploymentFindingPage(params,[row],id));
 await render("?findings_lifecycle=all");await settled(()=>expect(host.querySelector("tbody")?.textContent).toContain("Legacy retained state"));expect(host.textContent).toContain("1 matching workload finding records");
 await inspect();expect(document.querySelector('[data-testid="deployment-finding-record"]')?.textContent).toContain("legacy-retained-state");
});

it("preserves uniquely owned pod observations when the canonical workload name is ambiguous", async () => {
 const row={...deploymentFindingFixture(),target_ref:"payments/pod/app-abc",attribution:"pod" as const,platform_role:"core"};
 vi.mocked(deployments.findings).mockImplementation(async(id,params)=>({...deploymentFindingPage(params,[row],id),owner_count:2,owner_ambiguous:true}));
 await render();await settled(()=>expect(host.querySelector("tbody tr")).not.toBeNull());await inspect();expect(document.querySelector('[data-testid="deployment-finding-record"]')?.textContent).toContain("Exact owned pod");
});
it("rejects invented core classification for ambiguous custom-namespace workload ownership", async () => {
 const row={...deploymentFindingFixture(),owner_count:2,owner_ambiguous:true,platform_role:"core"};
 vi.mocked(deployments.findings).mockImplementation(async(id,params)=>({...deploymentFindingPage(params,[row],id),owner_count:2,owner_ambiguous:true}));
 await render();await settled(()=>expect(host.textContent).toContain("Deployment workload findings are unavailable"));expect(host.querySelector("tbody")).toBeNull();
});
