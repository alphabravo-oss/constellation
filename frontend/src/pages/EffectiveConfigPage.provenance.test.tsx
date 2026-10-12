import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { TestRouter } from "@/test/router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { downloadCsv } from "@/lib/csv";
import { componentsInventory, systemConfigApi, type ComponentInstance } from "@/api/client";
import { EffectiveConfigPage } from "./EffectiveConfigPage";

vi.mock("@/api/client", () => ({
  systemConfigApi: { get: vi.fn() },
  componentsInventory: { list: vi.fn() },
}));

vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
let history: RouterHistory;
let root: Root | undefined;
let host: HTMLDivElement;
let queryClient: QueryClient;

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
    <QueryClientProvider client={queryClient}><TestRouter history={history}><EffectiveConfigPage /></TestRouter></QueryClientProvider>,
  ));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 25)); });
}

function component(name: string, metadata: Record<string, unknown>): ComponentInstance {
  return {
    id: name,
    component: name,
    display_name: name,
    role: "scanner",
    hostname: "test-host",
    last_seen_at: "2026-09-26T00:00:00Z",
    metadata,
  } as ComponentInstance;
}

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
  vi.mocked(componentsInventory.list).mockResolvedValue({
    summary: { generated_at: "2026-09-26T00:00:00Z", components: 2, total_instances: 2, healthy: 2, degraded: 0, stale: 0, drift: 0, crashlooping: 0, missing: 0 },
    rollups: [],
    components: [component("unrelated-revision", { config_revision: 9 }), component("explicit-report", { system_config_revision: 8 })],
  });
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
  const reports = Array.from(host.querySelectorAll('[data-testid="effective-config-applied-revisions"] tbody tr'));
  expect(reports.find((row) => row.textContent?.includes("unrelated-revision"))?.textContent).toContain("Unknown");
  expect(reports.find((row) => row.textContent?.includes("explicit-report"))?.textContent).toContain("Behind");
});

it("reports missing provenance and failed component inventory as unknown or unavailable", async () => {
  vi.mocked(systemConfigApi.get).mockResolvedValue({ config: { tls_verify: true }, revision: 0, source: "default" });
  vi.mocked(componentsInventory.list).mockRejectedValue(new Error("inventory offline"));
  await render("?tab=reports");
  expect(host.querySelector('[data-testid="effective-config-provider-applied"]')?.textContent).toContain("Unavailable");
  expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')?.textContent).toContain("unavailable");
  expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')?.textContent).not.toContain("No component heartbeats");
  await tab("Provenance");
  expect(host.querySelector('[data-testid="effective-config-source-summary"]')?.textContent).toContain("Unknown");
});

async function tab(label: string) { await act(async () => [...host.querySelectorAll('[role="tab"]')].find(t => t.textContent === label)!.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, button: 0 }))); await vi.waitFor(() => expect(host.querySelector('[role="tab"][data-state="active"]')?.textContent).toBe(label)); }
it("exposes all returned revision reports with bounded CSV and URL/history disclosure", async () => {
 vi.mocked(systemConfigApi.get).mockResolvedValue({ config: { tls_verify: true }, revision: 9, source: "system_config" });
 vi.mocked(componentsInventory.list).mockResolvedValue({ components: Array.from({ length: 150 }, (_, i) => component(`component-${String(i).padStart(3, "0")}`, { system_config_revision: 9 })), rollups: [], summary: {} } as unknown as Awaited<ReturnType<typeof componentsInventory.list>>);
 await render("?context=kept#proof"); expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')).toBeNull(); await tab("Revision reports"); expect(history.location.search).toContain("tab=reports"); expect(history.location.search).toContain("context=kept"); expect(history.location.hash).toBe("#proof");
 const button = (name: string) => [...host.querySelectorAll("button")].find(b => b.textContent?.trim() === name)!;
 expect(host.querySelectorAll("tbody tr")).toHaveLength(100); await act(async () => button("Next").click()); expect(host.textContent).toContain("component-149"); await act(async () => button("Export loaded reports CSV").click()); expect(vi.mocked(downloadCsv).mock.calls.at(-1)?.[2]).toHaveLength(150); expect(host.textContent).toContain("1,000");
 await act(async () => history.back()); await vi.waitFor(() => expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')).toBeNull()); await act(async () => history.forward()); await vi.waitFor(() => expect(host.querySelector('[data-testid="effective-config-applied-revisions"]')).not.toBeNull());
});
it("suppresses stale component and configuration evidence after failed refreshes", async () => {
 vi.mocked(systemConfigApi.get).mockResolvedValue({ config: { tls_verify: true }, revision: 9, source: "system_config" }); vi.mocked(componentsInventory.list).mockResolvedValue({ components: [component("reported-component", { system_config_revision: 9 })], rollups: [], summary: {} } as unknown as Awaited<ReturnType<typeof componentsInventory.list>>);
 await render("?tab=reports"); expect(host.textContent).toContain("reported-component"); vi.mocked(componentsInventory.list).mockRejectedValue(new Error("offline")); await act(async () => { await queryClient.invalidateQueries({ queryKey: ["components-inventory"] }); }); await vi.waitFor(() => expect(host.textContent).toContain("Component inventory unavailable")); expect(host.textContent).not.toContain("reported-component");
 vi.mocked(systemConfigApi.get).mockRejectedValue(new Error("offline")); await act(async () => { await queryClient.invalidateQueries({ queryKey: ["system-config"] }); }); await vi.waitFor(() => expect(host.textContent).toContain("Failed to load system config")); expect(host.querySelector('[role="tab"]')).toBeNull();
});
