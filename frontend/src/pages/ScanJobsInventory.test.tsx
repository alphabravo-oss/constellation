/* global HTMLSelectElement */
import { act } from "react";
import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { scanJobs, scanJobsAdmin, type ScanJob, type ScanJobInventoryParams, type ScanJobInventoryResponse } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { downloadCsv } from "@/lib/csv";
import { ScanJobsInventory } from "./ScanJobsInventory";
vi.mock("@/api/client", () => ({ scanJobs: { list: vi.fn(), exportCSV: vi.fn() }, scanJobsAdmin: { pause: vi.fn(), resume: vi.fn(), retry: vi.fn(), cancel: vi.fn() } }));
vi.mock("@/lib/csv", async original => ({ ...await original<typeof import("@/lib/csv")>(), downloadCsv: vi.fn() }));
const statuses = ["pending", "running", "paused", "completed", "failed", "canceled"];
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory; let identity: { org_id: string; user_id: string } | null = { org_id: "org", user_id: "user" };
const job = (i: number): ScanJob => ({ id: `job-${i}`, target_id: `target-${i}`, target_ref: `Repository ${i.toString().padStart(4, "0")}`, target_type: "repository", target_cluster_id: "cluster", registry_id: "registry", status: statuses[i % 6], attempt_count: 1, max_attempts: 3, requested_at: "2026-10-12T00:00:00Z", worker_id: `worker-${i}`, finding_count: i });
function response(params: ScanJobInventoryParams = {}, source = Array.from({ length: 350 }, (_, i) => job(i))): ScanJobInventoryResponse {
 const matching = source.filter(j => (!params.q || j.target_ref.includes(params.q) || j.worker_id?.includes(params.q)) && (!params.status || j.status === params.status) && (!params.target_type || j.target_type === params.target_type) && (!params.cluster_id || j.target_cluster_id === params.cluster_id) && (!params.registry_id || j.registry_id === params.registry_id));
 if (params.sort === "target") matching.sort((a, b) => a.target_ref.localeCompare(b.target_ref)); if (params.order === "desc") matching.reverse();
 const summary: Record<string, number> = { total: matching.length, pending: 0, running: 0, paused: 0, completed: 0, failed: 0, canceled: 0 }; for (const j of matching) summary[j.status]++;
 const offset = params.offset || 0; return { jobs: matching.slice(offset, offset + 100), total: matching.length, limit: 100, offset, has_more: offset + 100 < matching.length, sort: params.sort || "requested", order: params.order || "desc", summary };
}
beforeEach(() => {
 (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; vi.resetAllMocks(); localStorage.clear(); identity = { org_id: "org", user_id: "user" };
 vi.mocked(scanJobs.list).mockImplementation(async params => response(params)); vi.mocked(scanJobs.exportCSV).mockResolvedValue({ total: 350, exported: 350, limit: 100000, truncated: false });
 for (const action of ["pause", "resume", "retry", "cancel"] as const) vi.mocked(scanJobsAdmin[action]).mockResolvedValue({ status: "accepted" });
 client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); vi.restoreAllMocks(); localStorage.clear(); });
const tree = () => <QueryClientProvider client={client}><TablePreferencesProvider identity={identity ? { ...identity } : null}><TestRouter history={history}><ScanJobsInventory /></TestRouter></TablePreferencesProvider></QueryClientProvider>;
async function render(search = "") { history = createMemoryHistory({ initialEntries: [`/settings/connectors?tab=scan-jobs${search}`] }); await act(async () => root.render(tree())); }
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
const rows = () => host.querySelectorAll('[data-testid="scan-jobs-table"] tbody tr');
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>("button")].find(b => b.textContent?.trim() === label)!;
async function click(label: string) { await act(async () => button(label).click()); }
async function field(selector: string, value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement | HTMLSelectElement>(selector)!; Object.getOwnPropertyDescriptor(input.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event(input.tagName === "SELECT" ? "change" : "input", { bubbles: true })); }); }
const header = (id: string) => host.querySelector(`th[data-column-id="${id}"]`)!;
const cacheKey = () => client.getQueriesData<ScanJobInventoryResponse>({ queryKey: ["scan-jobs"] })[0][0];
it("continues beyond 200 jobs with matching totals and clearly page-scoped CSV", async () => {
 await render("&page=3&sort=target&order=asc&context=keep#jobs"); await settle(() => expect(rows()).toHaveLength(100)); expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 100, offset: 200, sort: "target", order: "asc" })); expect(rows()[0].textContent).toContain("Repository 0200"); expect(host.textContent).toContain("350 matching jobs"); expect(host.textContent).toContain("Page 3 of 4");
 await click("Export this page CSV"); expect(downloadCsv).toHaveBeenCalledOnce(); const [, , exported] = vi.mocked(downloadCsv).mock.calls[0]; expect(exported).toHaveLength(100); expect(exported[0][0]).toBe("Repository 0200"); expect(exported.flat()).not.toContain("Repository 0300");
 await click("Next"); await settle(() => expect(rows()).toHaveLength(50)); expect(rows()[0].textContent).toContain("Repository 0300"); expect(history.location.search).toContain("page=4"); expect(history.location.search).toContain("context=keep"); expect(history.location.hash).toBe("#jobs"); expect(button("Next").disabled).toBe(true);
});
it("searches the server tail and resets page while retaining URL context and focus", async () => {
 await render("&page=3&selected=job-200&context=a&context=b#jobs"); await settle(() => expect(rows()).toHaveLength(100)); const input = host.querySelector<HTMLInputElement>('[aria-label="Search scan jobs"]')!; input.focus(); await field('[aria-label="Search scan jobs"]', "Repository 0349"); expect(document.activeElement).toBe(input); await settle(() => expect(rows()).toHaveLength(1)); expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({ q: "Repository 0349", offset: 0 })); expect(rows()[0].textContent).toContain("Repository 0349"); expect(host.textContent).toContain("1 matching jobs");
 const params = new URLSearchParams(history.location.search); expect(params.has("page")).toBe(false); expect(params.has("selected")).toBe(false); expect(params.getAll("context")).toEqual(["a", "b"]); expect(history.location.hash).toBe("#jobs");
});
it("restores status, target type, page and controlled sorting through browser history", async () => {
 await render("&page=3&sort=target&order=desc&context=keep"); await settle(() => expect(rows()).toHaveLength(100)); expect(header("target").getAttribute("aria-sort")).toBe("descending"); await field('[aria-label="Scan job status"]', "failed"); await settle(() => expect(rows()).toHaveLength(58)); expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({ status: "failed", offset: 0 }));
 await field('[aria-label="Scan target type"]', "host"); await settle(() => expect(host.textContent).toContain("0 matching jobs")); expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({ status: "failed", target_type: "host" })); await act(async () => history.back()); await settle(() => expect(rows()).toHaveLength(58)); expect(host.querySelector<HTMLSelectElement>('[aria-label="Scan target type"]')!.value).toBe(""); await act(async () => history.back()); await settle(() => expect(rows()).toHaveLength(100)); expect(history.location.search).toContain("page=3");
 await act(async () => header("target").querySelector<HTMLButtonElement>("button")!.click()); await settle(() => expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({ sort: "target", order: "asc", offset: 0 }))); await settle(() => expect(header("target").getAttribute("aria-sort")).toBe("ascending")); expect(rows()[0].textContent).toContain("Repository 0000"); await act(async () => history.back()); await settle(() => expect(header("target").getAttribute("aria-sort")).toBe("descending")); expect(history.location.search).toContain("page=3");
});
it("does not substitute another job for an off-page URL selection and restores selection on Back", async () => {
 await render("&page=3&sort=target&order=asc&selected=job-0"); await settle(() => expect(rows()).toHaveLength(100)); expect(host.textContent).toContain("The selected job is outside this page or filter."); expect(host.querySelector("dl")).toBeNull(); await act(async () => (rows()[0] as HTMLElement).click()); await settle(() => expect(host.querySelector("dl")?.textContent).toContain("Job IDjob-200")); expect(new URLSearchParams(history.location.search).get("selected")).toBe("job-200"); await act(async () => history.back()); await settle(() => expect(host.querySelector("dl")).toBeNull()); expect(host.textContent).toContain("outside this page or filter"); expect(new URLSearchParams(history.location.search).get("selected")).toBe("job-0");
});
it("exports all matching filters and source scope, with honest cap and failure feedback", async () => {
 await render("&page=3&status=failed&target_type=repository&cluster_id=cluster&registry_id=registry&q=Repository&sort=target&order=asc"); await settle(() => expect(button("Export matching CSV")).toBeDefined()); await click("Export matching CSV"); expect(scanJobs.exportCSV).toHaveBeenCalledWith(expect.objectContaining({ q: "Repository", status: "failed", target_type: "repository", cluster_id: "cluster", registry_id: "registry", sort: "target", order: "asc", offset: 200 })); await settle(() => expect(host.textContent).toContain("Exported all 350 matching records across pages"));
 vi.mocked(scanJobs.exportCSV).mockResolvedValueOnce({ total: 100001, exported: 100000, limit: 100000, truncated: true }); await click("Export matching CSV"); await settle(() => expect(host.textContent).toContain("Export capped at 100,000 of 100,001")); vi.mocked(scanJobs.exportCSV).mockRejectedValueOnce(new Error("private export failure")); await click("Export matching CSV"); await settle(() => expect(host.textContent).toContain("Matching CSV could not be exported")); expect(host.textContent).not.toContain("private export failure");
});
it("withholds evidence and actions during refresh, reports failure and recovers with Retry", async () => {
 await render("&sort=target&order=asc&selected=job-0"); await settle(() => expect(host.querySelector("dl")).not.toBeNull()); let reject!: (reason: Error) => void; vi.mocked(scanJobs.list).mockImplementationOnce(() => new Promise((_yes, no) => { reject = no; })); let refresh!: Promise<void>; await act(async () => { refresh = client.invalidateQueries({ queryKey: ["scan-jobs"] }); }); await settle(() => expect(host.textContent).toContain("Loading scan jobs")); expect(rows()).toHaveLength(0); expect(host.querySelector("dl")).toBeNull(); expect(button("Export matching CSV")).toBeUndefined(); expect(button("Pause")).toBeUndefined();
 await act(async () => { reject(new Error("private refresh failure")); await refresh; }); await settle(() => expect(button("Retry scan jobs")).toBeDefined()); expect(host.textContent).not.toContain("No scan jobs match"); expect(host.textContent).not.toContain("350 matching jobs"); expect(host.textContent).not.toContain("private refresh failure"); await click("Retry scan jobs"); await settle(() => expect(rows()).toHaveLength(100)); expect(host.querySelector("dl")?.textContent).toContain("Job IDjob-0");
});
it.each(["metadata", "offset", "duplicates", "filter", "cluster", "registry", "organization"])("withholds %s response mismatches rather than exposing actions or successful empty state", async defect => {
 vi.mocked(scanJobs.list).mockImplementation(async params => { const data = response(params); if (defect === "metadata") delete data.summary; if (defect === "offset") data.offset = 100; if (defect === "duplicates") data.jobs[1].id = data.jobs[0].id; if (defect === "filter") data.jobs[0].status = "completed"; if (defect === "cluster") data.jobs[0].target_cluster_id = "other"; if (defect === "registry") data.jobs[0].registry_id = "other"; if (defect === "organization") data.jobs[0].org_id = "other"; return data; }); await render("&status=failed&cluster_id=cluster&registry_id=registry"); await settle(() => expect(button("Retry scan jobs")).toBeDefined()); expect(rows()).toHaveLength(0); expect(button("Export matching CSV")).toBeUndefined(); expect(button("Retry")).toBeUndefined(); expect(host.textContent).not.toContain("No scan jobs match");
});
it.each(["0", "-1", "bad", "10001"])("rejects unsupported URL page %s before silently substituting the first page", async page => {
 await render(`&page=${page}&context=keep`); await settle(() => expect(host.textContent).toContain("Choose supported scan job filters and sorting")); expect(scanJobs.list).not.toHaveBeenCalled(); await click("Reset filters"); await settle(() => expect(rows()).toHaveLength(100)); expect(history.location.search).toContain("context=keep"); expect(new URLSearchParams(history.location.search).has("page")).toBe(false);
});
it("discloses image digests separately and exports their full exact target identity", async () => {
 const digest = `sha256:${"a".repeat(64)}`; const target = `registry.example/payments:release@${digest}`; vi.mocked(scanJobs.list).mockImplementation(async params => response(params, [{ ...job(0), target_type: "image", target_ref: target }])); await render(); await settle(() => expect(rows()).toHaveLength(1)); const cell = rows()[0].querySelector('td[data-column-id="target"]')!; expect(cell.textContent).toContain("registry.example/payments:release"); const details = cell.querySelector("details")!; expect(details.open).toBe(false); expect(details.querySelector("summary")!.textContent).toBe("Show digest"); expect(details.querySelector("code")!.textContent).toBe(digest); await click("Export this page CSV"); expect(vi.mocked(downloadCsv).mock.calls[0][2][0][0]).toBe(target);
});
it.each(["pause", "resume", "retry", "cancel"] as const)("runs %s only for the exact confirmed job and refreshes the ledger", async action => {
 const status = { pause: "pending", resume: "paused", retry: "failed", cancel: "running" }[action]; vi.mocked(scanJobs.list).mockImplementation(async params => response(params, [{ ...job(42), status }])); await render(); await settle(() => expect(rows()).toHaveLength(1)); await click(action[0].toUpperCase() + action.slice(1)); await settle(() => expect(scanJobsAdmin[action]).toHaveBeenCalledWith("job-42")); await settle(() => expect(scanJobs.list).toHaveBeenCalledTimes(2)); expect(new URLSearchParams(history.location.search).has("selected")).toBe(false);
});
it.each(["updated", "invalidated", "fetching"])("rejects actions when the visible cache is %s before query observers rerender", async condition => {
 vi.mocked(scanJobs.list).mockImplementation(async params => response(params, [{ ...job(0), status: "pending" }])); await render(); await settle(() => expect(button("Pause")).toBeDefined()); const pause = button("Pause"); const key = cacheKey(); let finish: (() => void) | undefined;
 await act(async () => { if (condition === "updated") client.setQueryData<ScanJobInventoryResponse>(key, data => ({ ...data!, jobs: [{ ...data!.jobs[0], status: "completed" }] })); if (condition === "invalidated") void client.invalidateQueries({ queryKey: key, exact: true, refetchType: "none" }); if (condition === "fetching") { const data = client.getQueryData<ScanJobInventoryResponse>(key)!; vi.mocked(scanJobs.list).mockImplementationOnce(() => new Promise(resolve => { finish = () => resolve(data); })); void client.refetchQueries({ queryKey: key, exact: true }); } pause.click(); });
 await settle(() => expect(host.textContent).toContain("The scan job action failed")); expect(scanJobsAdmin.pause).not.toHaveBeenCalled(); if (finish) await act(async () => finish!());
});
it("rejects a queued action after organization/user changes and hides the old owner's evidence", async () => {
 vi.mocked(scanJobs.list).mockImplementation(async params => response(params, [{ ...job(0), status: "pending" }])); await render(); await settle(() => expect(button("Pause")).toBeDefined()); const pause = button("Pause"); vi.mocked(scanJobs.list).mockRejectedValue(new Error("new owner unavailable")); await act(async () => { pause.click(); identity = { org_id: "other-org", user_id: "other-user" }; flushSync(() => root.render(tree())); }); await settle(() => expect(button("Retry scan jobs")).toBeDefined()); expect(scanJobsAdmin.pause).not.toHaveBeenCalled(); expect(rows()).toHaveLength(0); expect(host.textContent).not.toContain("Repository 0000"); expect(button("Export matching CSV")).toBeUndefined();
});
it("reports lifecycle failure without changing selection or exposing private backend errors", async () => {
 vi.mocked(scanJobs.list).mockImplementation(async params => response(params, [{ ...job(0), status: "pending" }])); vi.mocked(scanJobsAdmin.pause).mockRejectedValue(new Error("private mutation failure")); await render("&selected=job-0"); await settle(() => expect(button("Pause")).toBeDefined()); await click("Pause"); await settle(() => expect(host.textContent).toContain("The scan job action failed")); expect(host.querySelector("dl")?.textContent).toContain("Job IDjob-0"); expect(rows()[0].textContent).toContain("pending"); expect(host.textContent).not.toContain("private mutation failure");
});

it.each([null, { org_id: "", user_id: "user" }, { org_id: "org", user_id: "" }])("does not read or mutate scan jobs with unresolved identity %j", async unresolved => {
 identity = unresolved; await render(); expect(scanJobs.list).not.toHaveBeenCalled(); expect(rows()).toHaveLength(0); expect(button("Refresh jobs").disabled).toBe(true); expect(button("Export matching CSV")).toBeUndefined(); expect(scanJobsAdmin.pause).not.toHaveBeenCalled();
});
it("rejects a queued action when its workspace unmounts before mutation dispatch", async () => {
 vi.mocked(scanJobs.list).mockImplementation(async params => response(params, [{ ...job(0), status: "pending" }])); await render(); await settle(() => expect(button("Pause")).toBeDefined()); const pause = button("Pause");
 await act(async () => { pause.click(); flushSync(() => root.render(<div>Different workspace</div>)); }); await settle(() => expect(host.textContent).toBe("Different workspace")); expect(scanJobsAdmin.pause).not.toHaveBeenCalled();
});
it("late action success refreshes only the original owner's ledger consumers", async () => {
 vi.mocked(scanJobs.list).mockImplementation(async params => response(params, [{ ...job(0), status: "pending" }])); let complete!: (value: { status: string }) => void; vi.mocked(scanJobsAdmin.pause).mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
 const originalConsumer = ["scan-jobs", "scanner-source", "org:user"];
 const newConsumer = ["scan-jobs", "scanner-source", "other-org:other-user"];
 const originalCoverage = ["connector-coverage", "org:user"];
 const newCoverage = ["connector-coverage", "other-org:other-user"];
 for (const key of [originalConsumer, newConsumer, originalCoverage, newCoverage]) client.setQueryData(key, { marker: "unchanged" });
 await render(); await settle(() => expect(button("Pause")).toBeDefined()); await click("Pause"); await settle(() => expect(scanJobsAdmin.pause).toHaveBeenCalledWith("job-0"));
 identity = { org_id: "other-org", user_id: "other-user" }; await act(async () => root.render(tree())); await settle(() => expect(rows()).toHaveLength(1));
 await act(async () => complete({ status: "accepted" })); await settle(() => expect(client.getQueryState(originalConsumer)?.isInvalidated).toBe(true)); expect(client.getQueryState(originalCoverage)?.isInvalidated).toBe(true); expect(client.getQueryState(newConsumer)?.isInvalidated).toBe(false); expect(client.getQueryState(newCoverage)?.isInvalidated).toBe(false); expect(scanJobs.list).toHaveBeenCalledTimes(2); expect(host.textContent).not.toContain("The scan job action failed");
});
it("a late failure from the previous owner's action never becomes the new owner's error", async () => {
 vi.mocked(scanJobs.list).mockImplementation(async params => response(params, [{ ...job(0), status: "pending" }])); let reject!: (error: Error) => void; vi.mocked(scanJobsAdmin.pause).mockImplementationOnce(() => new Promise((_resolve, no) => { reject = no; })); await render(); await settle(() => expect(button("Pause")).toBeDefined()); await click("Pause"); await settle(() => expect(scanJobsAdmin.pause).toHaveBeenCalled());
 identity = { org_id: "other-org", user_id: "other-user" }; await act(async () => root.render(tree())); await settle(() => expect(rows()).toHaveLength(1)); await act(async () => reject(new Error("private previous owner failure"))); await settle(() => expect(button("Pause").disabled).toBe(false)); expect(host.textContent).not.toContain("The scan job action failed"); expect(host.textContent).not.toContain("private previous owner failure");
});
