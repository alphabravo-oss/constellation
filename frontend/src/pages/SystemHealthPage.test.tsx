import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { supportBundles, systemHealth, type SupportBundleJob, type SystemHealth } from "@/api/client";
import { downloadJson } from "@/lib/download";
import { SystemHealthPage } from "./SystemHealthPage";

vi.mock("@/api/client", () => ({
  systemHealth: { overview: vi.fn() },
  supportBundles: { createJob: vi.fn(), listJobs: vi.fn(), downloadJob: vi.fn() },
}));
vi.mock("@/lib/download", () => ({ downloadJson: vi.fn() }));

const overview = {
  summary: { status: "ok", generated_at: "2026-09-26T00:00:00Z", components_total: 0, components_by_status: {}, active_incidents: 0, open_actions: 0, degraded_components: [] },
  components: [], incidents: [], remediation_actions: [],
} satisfies SystemHealth;

const job = (id: string, status: SupportBundleJob["status"], error?: string): SupportBundleJob => ({ id, status, created_at: "2026-09-26T00:00:00Z", error });
let root: Root | undefined;
let host: HTMLDivElement;
let queryClient: QueryClient;

afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  queryClient?.clear();
  vi.resetAllMocks();
});

async function render(path = "/settings/health?tab=bundles") {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  vi.mocked(systemHealth.overview).mockResolvedValue(overview);
  await act(async () => root!.render(
    <QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[path]}><SystemHealthPage /></MemoryRouter></QueryClientProvider>,
  ));
  await flush();
}

async function flush() {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
}

function button(testId: string) {
  return host.querySelector<HTMLButtonElement>(`[data-testid="${testId}"]`)!;
}

it("shows bounded job history with ready-only downloads and failure explanations", async () => {
  vi.mocked(supportBundles.listJobs).mockResolvedValue({ items: [job("queued", "queued"), { ...job("ready", "ready"), audit_event_id: 42 }, job("failed", "failed", "worker unavailable"), job("expired", "expired")], next_cursor: "" });
  vi.mocked(supportBundles.downloadJob).mockResolvedValue({ schema_version: "v1", bundle_id: "bundle", generated_at: "2026-09-26T00:00:00Z", org_id: "org", format: "json", redaction: { applied: true, marker: "redacted", rules: [] }, integrity: { algorithm: "sha256", scope: "sections", sha256: "hash", signed: false }, sections: {} });
  await render();
  expect(supportBundles.listJobs).toHaveBeenCalledWith(undefined);
  expect(host.textContent).toContain("worker unavailable");
  expect(host.textContent).toContain("expired and cannot be downloaded");
  expect(Array.from(host.querySelectorAll("button")).find((item) => item.textContent === "Older")).toBeUndefined();
  expect(host.querySelectorAll('[data-testid^="support-bundle-download-"]')).toHaveLength(1);
  await act(async () => button("support-bundle-download-ready").click());
  await flush();
  expect(vi.mocked(supportBundles.downloadJob).mock.calls[0][0]).toBe("ready");
  expect(downloadJson).toHaveBeenCalledOnce();
});

it("queues a job without downloading and opens the job history", async () => {
  vi.mocked(supportBundles.listJobs).mockResolvedValue({ items: [], next_cursor: null });
  vi.mocked(supportBundles.createJob).mockResolvedValue(job("new", "queued"));
  await render("/settings/health");
  await act(async () => button("system-health-support-bundle").click());
  await flush();
  expect(supportBundles.createJob).toHaveBeenCalledOnce();
  expect(supportBundles.downloadJob).not.toHaveBeenCalled();
  expect(downloadJson).not.toHaveBeenCalled();
  expect(host.querySelector('[data-testid="system-health-bundle-jobs"]')).not.toBeNull();
});

it("uses the server cursor for older jobs and returns to newest", async () => {
  vi.mocked(supportBundles.listJobs).mockImplementation(async (cursor) => cursor
    ? { items: [job("old", "expired")], next_cursor: null }
    : { items: [job("new", "ready")], next_cursor: "cursor-2" });
  await render();
  await act(async () => Array.from(host.querySelectorAll("button")).find((item) => item.textContent === "Older")!.click());
  await flush();
  expect(supportBundles.listJobs).toHaveBeenCalledWith("cursor-2");
  expect(host.querySelector('[data-testid="support-bundle-job-old"]')).not.toBeNull();
  await act(async () => Array.from(host.querySelectorAll("button")).find((item) => item.textContent === "Newer")!.click());
  await flush();
  expect(host.querySelector('[data-testid="support-bundle-job-new"]')).not.toBeNull();
});
