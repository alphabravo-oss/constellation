import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { scanJobs, scannerOperations, systemConfigApi, systemHealth, type ScanJob, type ScanJobAttempt, type SystemConfigResponse } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { ScannerDatabaseSettingsFormPage, ScannerSourcesPage } from "./ScannerSourcesPage";

vi.mock("@/api/client", () => ({ scanJobs: { list: vi.fn(), attempts: vi.fn() }, scanJobsAdmin: { pause: vi.fn(), resume: vi.fn(), retry: vi.fn(), cancel: vi.fn() }, scannerOperations: { status: vi.fn(), workers: vi.fn(), cacheStat: vi.fn() }, systemConfigApi: { get: vi.fn(), patch: vi.fn(), refreshScanner: vi.fn() }, systemHealth: { overview: vi.fn() } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
let host: HTMLDivElement; let root: Root; let client: QueryClient; let history: RouterHistory;
const settings = (revision = 4, minutes = 360): SystemConfigResponse => ({ revision, config: { scanner_db_refresh_minutes: minutes, nvd_enabled: true, arbitrary_setting: "preserve" } });
const job = (id = "job-a"): ScanJob => ({ id, target_id: `target-${id}`, target_type: "image", target_ref: `registry.test/${id}:latest`, status: "failed", attempt_count: 2, max_attempts: 3, requested_at: "2026-10-12T08:00:00Z" });
const attempt = (job_id = "job-a"): ScanJobAttempt => ({ id: `attempt-${job_id}`, job_id, attempt_number: 2, status: "failed", worker_id: "worker-with-full-identity", started_at: "2026-10-12T08:01:00Z", next_attempt_at: "2026-10-12T08:05:00Z", error: "Scanner could not fetch package metadata" });
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (reason: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.mocked(systemConfigApi.get).mockResolvedValue(settings());
  vi.mocked(systemConfigApi.patch).mockImplementation(async body => settings(5, body.scanner_db_refresh_minutes as number));
  vi.mocked(systemHealth.overview).mockResolvedValue({ heartbeats: [] } as unknown as Awaited<ReturnType<typeof systemHealth.overview>>);
  vi.mocked(scannerOperations.status).mockResolvedValue({ scanned: 2, scheduled: 0, scanning: 0, failed: 1 } as Awaited<ReturnType<typeof scannerOperations.status>>);
  vi.mocked(scannerOperations.workers).mockResolvedValue([]);
  vi.mocked(scanJobs.list).mockResolvedValue({ jobs: [job()], queue_metrics: [] });
  vi.mocked(scanJobs.attempts).mockResolvedValue([attempt()]);
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.unstubAllGlobals(); });
async function settled(assertion: () => void) { await vi.waitFor(async () => { await act(async () => {}); assertion(); }); }
async function render(kind: "form" | "list" = "form", entry = kind === "form" ? "/settings/scanner/databases/edit" : "/settings/scanner", seed?: SystemConfigResponse, identity: { org_id: string; user_id: string } | null = { org_id: "org-a", user_id: "user-a" }) {
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  if (seed) client.setQueryData(["system-config"], seed);
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  history = createMemoryHistory({ initialEntries: [entry] });
  await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}><TestRouter history={history} path={kind === "form" ? "/settings/scanner/databases/edit" : "/settings/scanner"} next={kind === "form" ? { path: "/settings/scanner", element: <div data-testid="scanner-return">Scanner return</div> } : undefined}>{kind === "form" ? <ScannerDatabaseSettingsFormPage /> : <ScannerSourcesPage />}</TestRouter></TablePreferencesProvider></QueryClientProvider>));
}
function input() { return host.querySelector<HTMLInputElement>('[data-testid="scanner-db-refresh-minutes"]')!; }
function save() { return host.querySelector<HTMLButtonElement>('[data-testid="scanner-db-refresh-save"]')!; }
async function edit(value: string) { await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input(), value); input().dispatchEvent(new Event("input", { bubbles: true })); }); }
async function click(label: string) { const button = [...document.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent === label || item.getAttribute("aria-label") === label)!; expect(button).toBeDefined(); await act(async () => button.click()); }
async function openJob() { await settled(() => expect(host.querySelector('[aria-label="Inspect scan job"]')).not.toBeNull()); await click("Inspect scan job"); }

it("shows read-only database configuration with a dedicated edit link", async () => {
  await render("list", "/settings/scanner?tab=databases&context=keep"); await settled(() => expect(host.textContent).toContain("360 minutes"));
  expect(input()).toBeNull(); const href = host.querySelector<HTMLAnchorElement>('[data-testid="scanner-db-refresh-edit"]')!.getAttribute("href")!;
  expect(href).toContain("/settings/scanner/databases/edit?"); expect(new URLSearchParams(href.split("?")[1]).get("return_to")).toBe("/settings/scanner?tab=databases&context=keep");
  expect(systemConfigApi.patch).not.toHaveBeenCalled();
});
it("changes nothing on blur and saves only the interval with the reviewed revision", async () => {
  await render(); await settled(() => expect(input()?.value).toBe("360")); await edit("120"); await act(async () => input().dispatchEvent(new Event("blur", { bubbles: true })));
  expect(systemConfigApi.patch).not.toHaveBeenCalled(); await click("Save interval");
  await settled(() => expect(systemConfigApi.patch).toHaveBeenCalledExactlyOnceWith({ scanner_db_refresh_minutes: 120 }, 4));
  await settled(() => expect(host.textContent).toContain("Scanner return")); expect(history.location.href).toBe("/settings/scanner?tab=databases"); expect(systemConfigApi.refreshScanner).not.toHaveBeenCalled();
});
it("Cancel preserves the safe return context and performs no write", async () => {
  await render("form", "/settings/scanner/databases/edit?return_to=" + encodeURIComponent("/settings/scanner?tab=databases&context=keep")); await settled(() => expect(input()).not.toBeNull()); await edit("75");
  expect(host.querySelector<HTMLAnchorElement>("a")!.getAttribute("href")).toBe("/settings/scanner?tab=databases&context=keep"); await click("Cancel"); await settled(() => expect(history.location.href).toBe("/settings/scanner?tab=databases&context=keep")); expect(systemConfigApi.patch).not.toHaveBeenCalled();
});
it("rejects an external return destination and unavailable session", async () => {
  await render("form", "/settings/scanner/databases/edit?return_to=https%3A%2F%2Fevil.test", undefined, null); await settled(() => expect(host.textContent).toContain("An available organization and user session are required"));
  expect(host.querySelector<HTMLAnchorElement>("a")!.getAttribute("href")).toBe("/settings/scanner?tab=databases"); expect(systemConfigApi.get).not.toHaveBeenCalled(); expect(systemConfigApi.patch).not.toHaveBeenCalled();
});
it.each(["", "-1", "1.5"])("rejects invalid interval %j", async value => { await render(); await settled(() => expect(input()).not.toBeNull()); await edit(value); expect(save().disabled).toBe(true); await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); expect(systemConfigApi.patch).not.toHaveBeenCalled(); });
it("does not capture cached settings until the current read settles", async () => {
  const read = deferred<SystemConfigResponse>(); vi.mocked(systemConfigApi.get).mockReturnValue(read.promise); await render("form", undefined, settings(1, 1));
  await settled(() => expect(host.textContent).toContain("Loading scanner database settings")); expect(input()).toBeNull(); await act(async () => read.resolve(settings(4, 120))); await settled(() => expect(input()?.value).toBe("120"));
});
it("retains the draft during refresh, hides failed read evidence and blocks Save", async () => {
  await render(); await settled(() => expect(input()).not.toBeNull()); await edit("75"); const read = deferred<SystemConfigResponse>(); vi.mocked(systemConfigApi.get).mockReturnValue(read.promise);
  await act(async () => { void client.refetchQueries({ queryKey: ["system-config"] }); }); await settled(() => expect(host.textContent).toContain("saving is paused")); expect(input().value).toBe("75"); expect(save().disabled).toBe(true);
  await act(async () => read.reject(new Error("refresh failed"))); await settled(() => expect(host.textContent).toContain("Could not refresh scanner settings")); expect(input().value).toBe("75"); expect(save().disabled).toBe(true); expect(systemConfigApi.patch).not.toHaveBeenCalled();
});
it.each([409, 412])("preserves the draft on revision conflict %s and prohibits retrying a stale revision", async status => {
  vi.mocked(systemConfigApi.patch).mockRejectedValue({ response: { status } }); await render(); await settled(() => expect(input()).not.toBeNull()); await edit("75"); vi.mocked(systemConfigApi.get).mockResolvedValue(settings(5, 600)); await click("Save interval");
  await settled(() => expect(host.textContent).toContain("System configuration changed elsewhere")); expect(input().value).toBe("75"); expect(save().disabled).toBe(true); expect(systemConfigApi.patch).toHaveBeenCalledTimes(1); expect(host.querySelector('[data-testid="scanner-return"]')).toBeNull();
});
it("rechecks invalidated cache before issuing a Save", async () => {
  await render(); await settled(() => expect(input()).not.toBeNull()); await edit("75");
  await act(async () => { void client.invalidateQueries({ queryKey: ["system-config"], refetchType: "none" }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Could not save scanner settings")); expect(systemConfigApi.patch).not.toHaveBeenCalled(); expect(input().value).toBe("75");
});
it("locks an unconfirmed save response rather than navigating or repeating the write", async () => {
  vi.mocked(systemConfigApi.patch).mockResolvedValue(settings(5, 999)); await render(); await settled(() => expect(input()).not.toBeNull()); await edit("75"); await click("Save interval");
  await settled(() => expect(host.textContent).toContain("Save outcome is unconfirmed")); expect(input().value).toBe("75"); expect(save().disabled).toBe(true); expect(systemConfigApi.patch).toHaveBeenCalledTimes(1); expect(host.querySelector('[data-testid="scanner-return"]')).toBeNull();
});
it("never navigates after a save completes for an unmounted form", async () => {
  const write = deferred<SystemConfigResponse>(); vi.mocked(systemConfigApi.patch).mockReturnValue(write.promise); await render(); await settled(() => expect(input()).not.toBeNull()); await edit("75"); await click("Save interval"); await settled(() => expect(systemConfigApi.patch).toHaveBeenCalledTimes(1));
  await act(async () => history.push("/settings/scanner?context=newer")); await settled(() => expect(host.textContent).toContain("Scanner return")); await act(async () => write.resolve(settings(5, 75))); await settled(() => expect(client.getQueryState(["system-config"])?.isInvalidated).toBe(true)); expect(history.location.href).toBe("/settings/scanner?context=newer");
});
it("uses the shared sortable attempt ledger with complete error and distinct retry evidence", async () => {
  await render("list"); await openJob(); await settled(() => expect(document.querySelector('[data-testid="scanner-job-attempts"]')).not.toBeNull());
  const table = document.querySelector('[data-testid="scanner-job-attempts"]')!; expect(table.querySelector('th[data-column-id="attempt"] button')).not.toBeNull(); expect(table.textContent).toContain("worker-with-full-identity"); expect(table.textContent).toContain("Scanner could not fetch package metadata"); expect(table.querySelector('td[data-column-id="finished"]')?.textContent).toBe("—"); expect(table.querySelector('td[data-column-id="retry"]')?.textContent).not.toBe("—"); expect(document.body.textContent).toContain("endpoint supplies no total or truncation indicator");
});
it("keeps the current ledger during a deferred refresh then hides it after failure", async () => {
  await render("list"); await openJob(); await settled(() => expect(document.querySelector('[data-testid="scanner-job-attempts"]')).not.toBeNull()); const read = deferred<ScanJobAttempt[]>(); vi.mocked(scanJobs.attempts).mockReturnValue(read.promise);
  await act(async () => { void client.refetchQueries({ queryKey: ["scan-job-attempts", "job-a"] }); }); await settled(() => expect(document.body.textContent).toContain("Refreshing attempts")); expect(document.querySelector('[data-testid="scanner-job-attempts"]')).not.toBeNull();
  await act(async () => read.reject(new Error("ledger failed"))); await settled(() => expect(document.body.textContent).toContain("Attempt history is unavailable")); expect(document.querySelector('[data-testid="scanner-job-attempts"]')).toBeNull(); expect(document.body.textContent).not.toContain("No attempt ledger recorded");
});
it("rejects another job's attempt ledger and permits Retry for the selected job", async () => {
  vi.mocked(scanJobs.attempts).mockResolvedValue([attempt("job-b")]); await render("list"); await openJob(); await settled(() => expect(document.body.textContent).toContain("Attempt history is unavailable")); expect(document.querySelector('[data-testid="scanner-job-attempts"]')).toBeNull();
  vi.mocked(scanJobs.attempts).mockResolvedValue([attempt("job-a")]); await click("Retry attempts"); await settled(() => expect(document.querySelector('[data-testid="scanner-job-attempts"]')).not.toBeNull()); expect(scanJobs.attempts).toHaveBeenLastCalledWith("job-a");
});
it("hides failed cached jobs instead of presenting successful empty inventory", async () => {
  await render("list"); await settled(() => expect(host.textContent).toContain("registry.test/job-a:latest")); vi.mocked(scanJobs.list).mockRejectedValue(new Error("refresh failed")); await act(async () => { await client.refetchQueries({ queryKey: ["scan-jobs", "scanner-sources"] }); }); await settled(() => expect(host.textContent).toContain("Scan jobs could not be loaded")); expect(host.textContent).not.toContain("registry.test/job-a:latest"); expect(host.textContent).not.toContain("No scan jobs match this view");
});
