import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { scanJobs, scannerOperations, systemConfigApi, systemHealth } from "@/api/client";
import { ScannerSourcesPage } from "./ScannerSourcesPage";

const route = vi.hoisted(() => ({ tab: "jobs" }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams({ tab: route.tab }), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn(), Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
vi.mock("@/api/client", () => ({ scanJobs: { list: vi.fn(), attempts: vi.fn() }, scanJobsAdmin: {}, scannerOperations: { status: vi.fn(), workers: vi.fn(), cacheStat: vi.fn() }, systemConfigApi: { get: vi.fn() }, systemHealth: { overview: vi.fn() } }));

let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); route.tab = "jobs"; });

async function renderPage(failed = false) {
  vi.mocked(systemConfigApi.get).mockResolvedValue({ config: { nvd_enabled: true }, revision: 1 } as Awaited<ReturnType<typeof systemConfigApi.get>>);
  vi.mocked(systemHealth.overview).mockResolvedValue({ heartbeats: [] } as unknown as Awaited<ReturnType<typeof systemHealth.overview>>);
  vi.mocked(scannerOperations.status).mockResolvedValue({ scanned: 2, scheduled: 0, scanning: 0, failed: 0 } as Awaited<ReturnType<typeof scannerOperations.status>>);
  vi.mocked(scannerOperations.workers).mockResolvedValue([]);
  if (failed) vi.mocked(scanJobs.list).mockRejectedValue(new Error("unavailable"));
  else vi.mocked(scanJobs.list).mockResolvedValue({ jobs: [], queue_metrics: [] });
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><ScannerSourcesPage /></QueryClientProvider>));
  await vi.waitFor(async () => {
    await act(async () => {});
    expect(host.textContent).toContain(failed ? "Some scanner status could not be loaded" : "No scanner workers reported");
  });
}

it("opens jobs with five metrics and hides peer sections", async () => {
  await renderPage();
  expect(host.querySelector('[data-testid="scanner-operator-summary"]')?.children).toHaveLength(5);
  expect(host.textContent).toContain("Paused count unavailable");
  expect(host.textContent).not.toContain("undefined paused");
  expect(host.querySelector('[data-testid="scanner-recent-jobs"]')).not.toBeNull();
  expect(host.querySelector('[data-testid="scanner-workers"]')).toBeNull();
  expect(host.querySelector('[data-testid="scanner-db-refresh-minutes"]')).toBeNull();
});

it("shows unavailable queue data instead of claiming no queued work", async () => {
  await renderPage(true);
  expect(host.textContent).toContain("Queue status could not be loaded.");
  expect(host.textContent).not.toContain("No queued scan work.");
});

it("opens the URL-selected sources without claiming verified feed delivery", async () => {
  route.tab = "sources";
  await renderPage();
  expect(host.textContent).toContain("Delivery not verified");
  expect(host.textContent).toContain("Enabled");
  expect(host.textContent).not.toContain("Live");
  expect(host.querySelector('[data-testid="scanner-recent-jobs"]')).toBeNull();
});

it("falls back to jobs for an unknown tab", async () => {
  route.tab = "unknown";
  await renderPage();
  expect(host.querySelector('[data-testid="scanner-recent-jobs"]')).not.toBeNull();
});
