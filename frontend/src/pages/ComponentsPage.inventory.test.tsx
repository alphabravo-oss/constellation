import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { componentsInventory } from "@/api/client";
import { TestRouter } from "@/test/router";
import { ComponentsPage } from "./ComponentsPage";
import { componentFixture } from "./components-inventory-fixture";

const scope = vi.hoisted(() => ({ clusterId: "cluster-1", cluster: { id: "cluster-1" } as { id: string } | undefined, isLoading: false, error: null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({ componentsInventory: { list: vi.fn(), exportCSV: vi.fn(), get: vi.fn(), diagnostics: vi.fn() }, supportBundles: { createJob: vi.fn() } }));
const emptyInventory = {
  summary: { generated_at: "2026-10-12T00:00:00Z", components: 0, total_instances: 0, healthy: 0, degraded: 0, stale: 0, drift: 0, crashlooping: 0, missing: 0 },
  components: [], rollups: [],
};
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;

beforeEach(() => { (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; scope.cluster = { id: "cluster-1" }; });
afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  client?.clear();
  vi.resetAllMocks();
});
async function settle() { await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); }); }
async function render() {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><TestRouter><ComponentsPage /></TestRouter></QueryClientProvider>));
  await settle();
}

it("shows an inventory error without zero statistics or empty-state claims, and retries", async () => {
  vi.mocked(componentsInventory.list).mockRejectedValueOnce(new Error("Request failed with status code 500")).mockResolvedValue(componentFixture(emptyInventory,{cluster_id:"cluster-1"}));
  await render();
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("Component inventory could not be loaded");
  expect(host.querySelector('[data-testid="component-summary"]')).toBeNull();
  expect(host.querySelector('[data-testid="component-inventory-table"]')).toBeNull();
  expect(host.textContent).not.toContain("No component instances");
  const retry = [...host.querySelectorAll('button')].find((button) => button.textContent === "Retry")!;
  await act(async () => retry.click());
  await settle();
  expect(componentsInventory.list).toHaveBeenCalledTimes(2);
  expect(host.querySelector('[role="alert"]')).toBeNull();
  expect(host.querySelector('[data-testid="component-summary"]')).not.toBeNull();
  expect(host.textContent).toContain("No component instances match the current filters");
});

it("shows loading until the inventory request succeeds", async () => {
  vi.mocked(componentsInventory.list).mockImplementation(() => new Promise(() => {}));
  await render();
  expect(host.querySelector('[role="status"]')?.textContent).toContain("Loading component inventory");
  expect(host.querySelector('[data-testid="component-summary"]')).toBeNull();
  expect(host.textContent).not.toContain("No component instances");
});

it("surfaces refresh failure instead of presenting cached inventory as current", async () => {
  vi.mocked(componentsInventory.list).mockResolvedValueOnce(componentFixture(emptyInventory,{cluster_id:"cluster-1"})).mockRejectedValue(new Error("Refresh unavailable"));
  await render();
  expect(host.querySelector('[data-testid="component-summary"]')).not.toBeNull();
  await act(async () => { await client.refetchQueries({ queryKey: ["components-inventory", "cluster-1"] }); });
  await settle();
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("Refresh unavailable");
  expect(host.querySelector('[data-testid="component-summary"]')).toBeNull();
  expect(host.textContent).not.toContain("No component instances");
});

it("does not fetch inventories or details until the requested cluster resolves", async () => {
  scope.cluster = { id: "another-cluster" };
  await render();
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("Cluster could not be resolved");
  expect(componentsInventory.list).not.toHaveBeenCalled();
  expect(componentsInventory.get).not.toHaveBeenCalled();
  expect(componentsInventory.diagnostics).not.toHaveBeenCalled();
});
