import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { componentsInventory, supportBundles, type ComponentInstance, type ComponentDiagnostics, type ComponentInventoryResponse } from "@/api/client";
import { TestRouter } from "@/test/router";
import { ComponentsPage } from "./ComponentsPage";
import { componentFixture } from "./components-inventory-fixture";
const scope = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster" } as { id: string } | undefined, loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: scope.clusterId, cluster: scope.cluster, isLoading: scope.loading, error: scope.error }) }));
vi.mock("@/api/client", () => ({ componentsInventory: { list: vi.fn(), exportCSV: vi.fn(), get: vi.fn(), diagnostics: vi.fn() }, supportBundles: { createJob: vi.fn() } }));
const component = (id = "scanner", cluster = "cluster"): ComponentInstance => ({ id, cluster_id: cluster, component: id, display_name: `Component ${id}`, role: id === "scanner" ? "scanner" : "controller", scope: "cluster", kind: "deployment", hostname: `${id}-host`, status: id === "scanner" ? "crashlooping" : "healthy", version: "1.0", uptime_seconds: 10, restart_count: 5, first_seen_at: "2026-10-12T00:00:00Z", last_seen_at: "2026-10-12T00:00:00Z", metadata: {} });
const inventory = (cluster = "cluster"): ComponentInventoryResponse => ({ summary: { generated_at: "2026-10-12T00:00:00Z", components: 2, total_instances: 2, healthy: 1, degraded: 0, stale: 0, drift: 0, crashlooping: 1, missing: 0 }, components: [component("scanner", cluster), component("controller", cluster)], rollups: [{ component: "scanner", display_name: "Scanner family", role: "scanner", scope: "cluster", kind: "deployment", expected: true, status: "crashlooping", instances: 1, healthy: 0, degraded: 0, stale: 0, drift: 0, crashlooping: 1, missing: 0 }] });
const diagnostic = (id = "scanner", cluster = "cluster"): ComponentDiagnostics => ({ component: component(id, cluster), generated_at: "2026-10-12T00:00:00Z", admin_gate: "global admin", status: { state: "crashlooping", stale: false, drift: false, crashlooping: true, degraded: false, uptime_seconds: 10, restart_count: 5, first_seen_at: "2026-10-12T00:00:00Z", last_seen_at: "2026-10-12T00:00:00Z" }, diagnostics: [{ key: "actual", label: "Actual diagnosis", status: "warning", evidence: `Evidence for ${id}` }], counters: [], config: [], debug: { profiling_enabled: false, live_logs_enabled: false, support_bundle_enabled: true } });
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  vi.mocked(componentsInventory.list).mockImplementation(async (params) => componentFixture(inventory(params?.cluster_id), params));
  vi.mocked(componentsInventory.get).mockImplementation(async (id) => ({ component: component(id, scope.clusterId) }));
  vi.mocked(componentsInventory.diagnostics).mockImplementation(async (id) => diagnostic(id, scope.clusterId));
  vi.mocked(supportBundles.createJob).mockResolvedValue({ id: "org-job", status: "queued", created_at: "2026-10-12T00:00:00Z" });
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); scope.clusterId = "cluster"; scope.cluster = { id: "cluster" }; scope.loading = false; scope.error = null; });
async function renderPage(search = "", beforeRender?: (queryClient: QueryClient) => void | Promise<void>) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); history = createMemoryHistory({ initialEntries: [`/clusters/cluster/components${search ? `?${search}` : ""}`] });
  client = new QueryClient({ defaultOptions: { queries: { retry: false, retryDelay: 0 }, mutations: { retry: false } } });
  await beforeRender?.(client);
  await act(async () => root.render(<QueryClientProvider client={client}><TestRouter history={history}><ComponentsPage /></TestRouter></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }, { timeout: 3000 }); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label || item.getAttribute("data-export-label") === label)!;
async function click(label: string) { await act(async () => { const element = button(label); if (element.getAttribute("role") === "tab") element.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, button: 0 })); else element.click(); }); }
async function selectComponent(id: string) { const row = [...host.querySelectorAll<HTMLTableRowElement>('[data-testid="component-inventory-table"] tbody tr')].find((item) => item.textContent?.includes(`Component ${id}`))!; await act(async () => row.click()); }
async function search(value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement>('[aria-label="Search components"]')!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function status(value: string) { await act(async () => { const select = host.querySelector<HTMLSelectElement>('[aria-label="Component status"]')!; select.value = value; select.dispatchEvent(new Event("change", { bubbles: true })); }); }
const params = () => new URLSearchParams(history.location.search);

it("shows the inventory as primary, four inline health numbers (missing in Details) and crashlooping attention, without automatic inspection", async () => {
  await renderPage(); await settled(() => expect(host.querySelector('[data-testid="component-inventory-table"]')).not.toBeNull());
  expect(host.querySelector('[data-testid="component-summary"] [data-testid="verdict-numbers"]')!.children).toHaveLength(4);
  expect(host.querySelector('[data-testid="component-summary"]')!.textContent).toContain("Missing");
  expect(host.textContent).toContain("1 component needs attention"); expect(host.textContent).toContain("Crashlooping1");
  expect(host.querySelector('[data-testid="component-version-matrix"]')).toBeNull(); expect(host.querySelector('[data-testid="component-rollups"]')).toBeNull();
  expect(componentsInventory.get).not.toHaveBeenCalled(); expect(componentsInventory.diagnostics).not.toHaveBeenCalled();
  expect(host.querySelector('[data-testid="component-preview"]')!.textContent).toContain("Select a component");
});
it("restores query/status/role/selection directly from the URL and preserves all values after reload", async () => {
  const initial = "q=scanner&status=crashlooping&role=scanner&component=scanner&context=keep";
  await renderPage(initial); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  expect(host.querySelector<HTMLInputElement>('[aria-label="Search components"]')!.value).toBe("scanner"); expect(host.querySelector<HTMLSelectElement>('[aria-label="Component status"]')!.value).toBe("crashlooping");
  expect(host.querySelectorAll('[data-testid="component-inventory-table"] tbody tr')).toHaveLength(1);
  expect(componentsInventory.get).toHaveBeenCalledWith("scanner"); expect(componentsInventory.diagnostics).toHaveBeenCalledWith("scanner");
  const saved = history.location.search.slice(1); await act(async () => root.unmount()); client.clear(); host.remove();
  await renderPage(saved); await settled(() => expect(host.textContent).toContain("Evidence for scanner")); expect(params().get("context")).toBe("keep");
});
it("pushes component selection so Back and Forward restore the exact instance", async () => {
  await renderPage(); await settled(() => expect(host.querySelectorAll('[data-testid="component-inventory-table"] tbody tr')).toHaveLength(2));
  await selectComponent("scanner"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  await selectComponent("controller"); await settled(() => expect(host.textContent).toContain("Evidence for controller"));
  await act(async () => history.back()); await settled(() => expect(host.textContent).toContain("Evidence for scanner")); expect(params().get("component")).toBe("scanner");
  await act(async () => history.forward()); await settled(() => expect(host.textContent).toContain("Evidence for controller")); expect(params().get("component")).toBe("controller");
});
it("uses shared URL tabs with history and keeps inventory filters intact", async () => {
  await renderPage("q=scanner&status=crashlooping&context=keep"); await settled(() => expect(host.querySelector('[data-testid="component-inventory-table"]')).not.toBeNull());
  await click("Versions"); await settled(() => expect(host.querySelector('[data-testid="component-version-matrix"]')).not.toBeNull()); expect(params().get("tab")).toBe("versions");
  await click("Families"); await settled(() => expect(host.querySelector('[data-testid="component-rollups"]')).not.toBeNull());
  await act(async () => history.back()); await settled(() => expect(host.querySelector('[data-testid="component-version-matrix"]')).not.toBeNull());
  await act(async () => history.back()); await settled(() => expect(host.querySelector('[data-testid="component-inventory-table"]')).not.toBeNull()); expect(params().get("q")).toBe("scanner"); expect(params().get("context")).toBe("keep");
});
it("writes search and status to the URL without dropping context or selected identity", async () => {
  await renderPage("component=scanner&context=keep"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  await search("controller"); await settled(() => expect(host.textContent).toContain("Selected component is outside the active filters"));
  expect(params().get("component")).toBe("scanner"); expect(params().get("q")).toBe("controller"); expect(params().get("context")).toBe("keep");
  expect(host.querySelector('[data-testid="component-preview"]')).toBeNull();
  await search(""); await status("healthy"); await settled(() => expect(host.textContent).toContain("Selected component is outside the active filters")); expect(params().get("status")).toBe("healthy");
});
it("preserves a selected component when changing roles and never substitutes a matching neighbor", async () => {
  await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  await act(async () => host.querySelector<HTMLButtonElement>('[data-testid="component-nv-role-controller"]')!.click());
  await settled(() => expect(host.textContent).toContain("Selected component is outside the active filters"));
  expect(params().get("role")).toBe("controller"); expect(params().get("component")).toBe("scanner"); expect(host.querySelector('[data-testid="component-preview"]')).toBeNull();
});
it.each(["wrong-id", "foreign", "org-wide"])("rejects a selected detail that is %s", async (scenario) => {
  vi.mocked(componentsInventory.get).mockResolvedValue({ component: { ...component(), ...(scenario === "wrong-id" ? { id: "neighbor" } : { cluster_id: scenario === "foreign" ? "foreign" : undefined }) } });
  await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Selected component is unavailable in the active cluster"));
  expect(host.querySelector('[data-testid="component-preview"]')).toBeNull(); expect(componentsInventory.diagnostics).not.toHaveBeenCalled();
});
it("shows a missing selected detail error, retains its URL and retries without substituting the first row", async () => {
  vi.mocked(componentsInventory.get).mockRejectedValueOnce({ response: { status: 404 } });
  await renderPage("component=missing"); await settled(() => expect(host.textContent).toContain("Selected component could not be loaded")); expect(params().get("component")).toBe("missing"); expect(componentsInventory.diagnostics).not.toHaveBeenCalled();
  await click("Retry component"); await settled(() => expect(host.textContent).toContain("Evidence for missing"));
});
it.each(["foreign", "wrong-id"])("rejects diagnostics bound to a %s component", async (scenario) => {
  vi.mocked(componentsInventory.diagnostics).mockResolvedValue(diagnostic(scenario === "wrong-id" ? "neighbor" : "scanner", scenario === "foreign" ? "foreign" : "cluster"));
  await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Component diagnostics could not be loaded"));
  expect(host.textContent).not.toContain("Evidence for neighbor"); expect(host.querySelector('[data-testid="component-support-bundle"]')).toBeNull(); expect(supportBundles.createJob).not.toHaveBeenCalled();
});
it.each([403, 500])("shows an explicit diagnostics %s failure with Retry", async (code) => {
  vi.mocked(componentsInventory.diagnostics).mockRejectedValue({ response: { status: code } }); await renderPage("component=scanner");
  await settled(() => expect(host.textContent).toContain(code === 403 ? "Global admin access required" : "Component diagnostics could not be loaded"));
  vi.mocked(componentsInventory.diagnostics).mockResolvedValue(diagnostic()); await click("Retry diagnostics"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
});
it("replaces stale diagnostics with refresh loading/error and permits an explicit retry", async () => {
  await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Evidence for scanner")); let reject!: (error: Error) => void;
  vi.mocked(componentsInventory.diagnostics).mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; })).mockRejectedValue(new Error("refresh failed"));
  await act(async () => { void client.invalidateQueries({ queryKey: ["component-diagnostics"] }); }); await settled(() => expect(host.textContent).toContain("Loading or refreshing diagnostics"));
  expect(host.querySelector('[data-testid="component-support-bundle"]')).toBeNull();
  await act(async () => reject(new Error("private failure"))); await settled(() => expect(host.textContent).toContain("Component diagnostics could not be loaded"));
  expect(host.textContent).not.toContain("private failure"); expect(host.textContent).not.toContain("Evidence for scanner");
  vi.mocked(componentsInventory.diagnostics).mockResolvedValue(diagnostic()); await click("Retry diagnostics"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
});
it("shows detail refresh failures instead of rendering cached component evidence", async () => {
  await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  vi.mocked(componentsInventory.get).mockRejectedValue(new Error("detail unavailable")); await act(async () => { await client.invalidateQueries({ queryKey: ["component-instance"] }); });
  await settled(() => expect(host.textContent).toContain("Selected component could not be loaded")); expect(host.querySelector('[data-testid="component-preview"]')).toBeNull();
});
it.each(["missing", "foreign", "loading", "error-stale"])("never queries a %s cluster scope", async (scenario) => {
  if (scenario === "missing") scope.clusterId = undefined; if (scenario === "foreign") scope.cluster = { id: "foreign" }; if (scenario === "loading") scope.loading = true; if (scenario === "error-stale") scope.error = new Error("scope failed");
  await renderPage("component=scanner"); expect(componentsInventory.list).not.toHaveBeenCalled(); expect(componentsInventory.get).not.toHaveBeenCalled(); expect(componentsInventory.diagnostics).not.toHaveBeenCalled();
});
it("waits for a cached cluster registry refresh before any scoped component request", async () => {
  let resolve!: (value: { clusters: Array<{ id: string }> }) => void;
  await renderPage("component=scanner", (queryClient) => { queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] }); void queryClient.fetchQuery({ queryKey: ["clusters"], queryFn: () => new Promise<{ clusters: Array<{ id: string }> }>((done) => { resolve = done; }) }).catch(() => {}); });
  expect(componentsInventory.list).not.toHaveBeenCalled(); expect(componentsInventory.get).not.toHaveBeenCalled();
  await act(async () => resolve({ clusters: [{ id: "cluster" }] })); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
});
it("does not render foreign records returned by an inventory response", async () => {
  vi.mocked(componentsInventory.list).mockResolvedValue(componentFixture(inventory("foreign"))); await renderPage("component=scanner");
  await settled(() => expect(host.textContent).toContain("Component inventory does not match the active cluster")); expect(host.querySelector('[data-testid="component-inventory-table"]')).toBeNull(); expect(componentsInventory.diagnostics).not.toHaveBeenCalled();
});
it("labels support bundles as org-wide and surfaces queuing failure", async () => {
  vi.mocked(supportBundles.createJob).mockRejectedValue(new Error("private job failure")); await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  expect(button("Create org-wide bundle").disabled).toBe(false); expect(host.textContent).toContain("Support bundles cover the organization");
  await click("Create org-wide bundle"); await settled(() => expect(host.textContent).toContain("Could not queue an organization support bundle")); expect(host.textContent).not.toContain("private job failure");
});
it("blocks an org-wide bundle if diagnostics become stale before observer notification", async () => {
  await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Evidence for scanner")); const bundle = button("Create org-wide bundle");
  await act(async () => { client.setQueryData(["component-diagnostics", "cluster", "scanner", "undefined:undefined"], diagnostic("scanner", "foreign")); bundle.click(); });
  await settled(() => expect(host.textContent).toContain("Component diagnostics could not be loaded")); expect(supportBundles.createJob).not.toHaveBeenCalled();
});
it("preserves confirmed inspection and queued org job through a periodic inventory refresh", async () => {
  await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  await click("Create org-wide bundle"); await settled(() => expect(host.querySelector('[data-testid="component-support-bundle-feedback"]')!.textContent).toContain("org-job"));
  let resolve!: (value: ComponentInventoryResponse) => void;
  vi.mocked(componentsInventory.list).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
  await act(async () => { void client.invalidateQueries({ queryKey: ["components-inventory"] }); });
  await settled(() => expect(host.textContent).toContain("Refreshing selected component"));
  expect(host.querySelector('[data-testid="component-preview"]')).not.toBeNull(); expect(host.querySelector('[data-testid="component-support-bundle-feedback"]')!.textContent).toContain("org-job");
  expect(button("Create org-wide bundle").disabled).toBe(true); await act(async () => button("Create org-wide bundle").click()); expect(supportBundles.createJob).toHaveBeenCalledOnce();
  await act(async () => resolve(componentFixture(inventory()))); await settled(() => expect(button("Create org-wide bundle").disabled).toBe(false));
  expect(host.querySelector('[data-testid="component-support-bundle-feedback"]')!.textContent).toContain("org-job");
});
it("preserves confirmed inspection and queued org job through a periodic detail refresh", async () => {
  await renderPage("component=scanner"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  await click("Create org-wide bundle"); await settled(() => expect(host.querySelector('[data-testid="component-support-bundle-feedback"]')!.textContent).toContain("org-job"));
  let resolve!: (value: { component: ComponentInstance }) => void;
  vi.mocked(componentsInventory.get).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
  await act(async () => { void client.invalidateQueries({ queryKey: ["component-instance"] }); });
  await settled(() => expect(host.textContent).toContain("Refreshing selected component"));
  expect(host.querySelector('[data-testid="component-preview"]')).not.toBeNull(); expect(host.querySelector('[data-testid="component-support-bundle-feedback"]')!.textContent).toContain("org-job"); expect(button("Create org-wide bundle").disabled).toBe(true);
  await act(async () => resolve({ component: component() })); await settled(() => expect(button("Create org-wide bundle").disabled).toBe(false));
  expect(host.querySelector('[data-testid="component-support-bundle-feedback"]')!.textContent).toContain("org-job");
});
it("waits for an initial selected component refresh rather than exposing unconfirmed cached details", async () => {
  let resolve!: (value: { component: ComponentInstance }) => void;
  vi.mocked(componentsInventory.get).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
  await renderPage("component=scanner", (queryClient) => { queryClient.setQueryData(["component-instance", "cluster", "scanner", "undefined:undefined"], { component: component() }); });
  await settled(() => expect(host.textContent).toContain("Refreshing selected component")); expect(host.querySelector('[data-testid="component-preview"]')).toBeNull(); expect(componentsInventory.diagnostics).not.toHaveBeenCalled();
  await act(async () => resolve({ component: component() })); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
});
it("clears inspection explicitly and Back restores the same component", async () => {
  await renderPage("component=scanner&context=keep"); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
  await click("Clear inspection"); await settled(() => expect(params().has("component")).toBe(false)); expect(params().get("context")).toBe("keep");
  expect(host.querySelector('[data-testid="component-preview"]')!.textContent).toContain("Select a component");
  await act(async () => history.back()); await settled(() => expect(host.textContent).toContain("Evidence for scanner"));
});
