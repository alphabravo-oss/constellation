import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { componentsInventory, supportBundles, type ComponentDiagnostics, type ComponentInstance } from "@/api/client";
import { ComponentsPage } from "./ComponentsPage";

vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster-1", isLoading: false }) }));
vi.mock("@/api/client", () => ({
  componentsInventory: { list: vi.fn(), get: vi.fn(), diagnostics: vi.fn() },
  supportBundles: { createJob: vi.fn() },
}));

const component = {
  id: "scanner-1", component: "scanner", display_name: "Scanner", role: "scanner", scope: "cluster", kind: "deployment",
  hostname: "scanner-host", status: "healthy", last_seen_at: "2026-09-26T00:00:00Z", metadata: {},
} as ComponentInstance;

let root: Root | undefined;
let host: HTMLDivElement;
let queryClient: QueryClient;

afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  queryClient?.clear();
  vi.resetAllMocks();
});

it("queues a diagnostic bundle and links to persisted job history without downloading", async () => {
  vi.mocked(componentsInventory.list).mockResolvedValue({
    summary: { generated_at: "2026-09-26T00:00:00Z", components: 1, total_instances: 1, healthy: 1, degraded: 0, stale: 0, drift: 0, crashlooping: 0, missing: 0 },
    components: [component], rollups: [],
  });
  vi.mocked(componentsInventory.diagnostics).mockResolvedValue({
    component, generated_at: "2026-09-26T00:00:00Z", admin_gate: "global admin",
    status: { state: "healthy", stale: false, drift: false, crashlooping: false, degraded: false, uptime_seconds: 10, restart_count: 0, first_seen_at: "2026-09-26T00:00:00Z", last_seen_at: "2026-09-26T00:00:00Z" },
    diagnostics: [], counters: [], config: [],
    debug: { profiling_enabled: false, live_logs_enabled: false, support_bundle_enabled: true },
  } as ComponentDiagnostics);
  vi.mocked(supportBundles.createJob).mockResolvedValue({ id: "job-1", status: "queued", created_at: "2026-09-26T00:00:00Z" });
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => root!.render(
    <QueryClientProvider client={queryClient}><MemoryRouter><ComponentsPage /></MemoryRouter></QueryClientProvider>,
  ));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
  const button = host.querySelector<HTMLButtonElement>('[data-testid="component-support-bundle"]')!;
  expect(button.disabled).toBe(false);
  await act(async () => button.click());
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
  expect(supportBundles.createJob).toHaveBeenCalledOnce();
  expect(host.querySelector('[data-testid="component-support-bundle-feedback"]')?.textContent).toContain("job-1 queued");
  expect(host.querySelector<HTMLAnchorElement>('[data-testid="component-support-bundle-feedback"] a')?.getAttribute("href")).toBe("/settings/health?tab=bundles");
});
