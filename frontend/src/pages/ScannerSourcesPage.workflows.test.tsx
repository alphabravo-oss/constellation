import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { scanJobs, scanJobsAdmin, scannerOperations, systemConfigApi, systemHealth, type ScanJob, type ScanJobAttempt, type ScanJobInventoryParams, type SystemConfigResponse } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { ScannerDatabaseSettingsFormPage, ScannerSourcesPage } from "./ScannerSourcesPage";

vi.mock("@/api/client", () => ({ scanJobs: { list: vi.fn(), attempts: vi.fn(), exportCSV: vi.fn() }, scanJobsAdmin: { pause: vi.fn(), resume: vi.fn(), retry: vi.fn(), cancel: vi.fn() }, scannerOperations: { status: vi.fn(), workers: vi.fn(), cacheStat: vi.fn() }, systemConfigApi: { get: vi.fn(), patch: vi.fn(), refreshScanner: vi.fn() }, systemHealth: { overview: vi.fn() } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
let host: HTMLDivElement; let root: Root; let client: QueryClient; let history: RouterHistory;
const settings = (revision = 4, minutes = 360): SystemConfigResponse => ({ revision, config: { scanner_db_refresh_minutes: minutes, nvd_enabled: true, arbitrary_setting: "preserve" } });
const job = (id = "job-a"): ScanJob => ({ id, target_id: `target-${id}`, target_type: "image", target_ref: `registry.test/${id}:latest`, status: "failed", attempt_count: 2, max_attempts: 3, requested_at: "2026-10-12T08:00:00Z" });
const attempt = (job_id = "job-a"): ScanJobAttempt => ({ id: `attempt-${job_id}`, job_id, attempt_number: 2, status: "failed", worker_id: "worker-with-full-identity", started_at: "2026-10-12T08:01:00Z", next_attempt_at: "2026-10-12T08:05:00Z", error: "Scanner could not fetch package metadata" });
function inventory(jobs: ScanJob[] = [job()], request: ScanJobInventoryParams = {}, matching: ScanJob[] = jobs) {
  const total = matching.length;
  const summary = { total, pending: 0, running: 0, paused: 0, completed: 0, failed: 0, canceled: 0 };
  for (const item of matching) summary[item.status as keyof typeof summary]++;
  return { jobs, queue_metrics: [], total, summary, limit: request.limit ?? 100, offset: request.offset ?? 0, sort: request.sort ?? "requested", order: request.order ?? "desc", has_more: (request.offset ?? 0) + jobs.length < total };
}
function serverJobs(rows: ScanJob[]) {
  vi.mocked(scanJobs.list).mockImplementation(async (request = {}) => {
    let matching = rows.filter(row => (!request.status || row.status === request.status) && (!request.target_type || row.target_type === request.target_type) && (!request.cluster_id || row.target_cluster_id === request.cluster_id) && (!request.registry_id || row.registry_id === request.registry_id) && (!request.q || [row.id,row.target_ref,row.target_type,row.source_type,row.source_ref,row.worker_id,row.error].join(" ").toLowerCase().includes(request.q.toLowerCase())));
    if (request.sort === "target") matching = [...matching].sort((a,b) => a.target_ref.localeCompare(b.target_ref) * (request.order === "asc" ? 1 : -1));
    return inventory(matching.slice(request.offset ?? 0, (request.offset ?? 0) + (request.limit ?? 100)), request, matching);
  });
}
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (reason: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.mocked(systemConfigApi.get).mockResolvedValue(settings());
  vi.mocked(systemConfigApi.patch).mockImplementation(async body => settings(5, body.scanner_db_refresh_minutes as number));
  vi.mocked(systemHealth.overview).mockResolvedValue({ heartbeats: [] } as unknown as Awaited<ReturnType<typeof systemHealth.overview>>);
  vi.mocked(scannerOperations.status).mockResolvedValue({ scanned: 2, scheduled: 0, scanning: 0, failed: 1 } as Awaited<ReturnType<typeof scannerOperations.status>>);
  vi.mocked(scannerOperations.workers).mockResolvedValue([]);
  vi.mocked(scanJobs.list).mockImplementation(async request => inventory([job()], request));
  vi.mocked(scanJobsAdmin.retry).mockResolvedValue({ status: "pending" });
  vi.mocked(scanJobs.exportCSV).mockResolvedValue({ total: 1, limit: 100000, exported: 1, truncated: false });
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
  await act(async () => { void client.refetchQueries({ queryKey: ["scan-job-attempts", "org-a:user-a", "job-a"] }); }); await settled(() => expect(document.body.textContent).toContain("Refreshing attempts")); expect(document.querySelector('[data-testid="scanner-job-attempts"]')).not.toBeNull();
  await act(async () => read.reject(new Error("ledger failed"))); await settled(() => expect(document.body.textContent).toContain("Attempt history is unavailable")); expect(document.querySelector('[data-testid="scanner-job-attempts"]')).toBeNull(); expect(document.body.textContent).not.toContain("No attempt ledger recorded");
});
it("rejects another job's attempt ledger and permits Retry for the selected job", async () => {
  vi.mocked(scanJobs.attempts).mockResolvedValue([attempt("job-b")]); await render("list"); await openJob(); await settled(() => expect(document.body.textContent).toContain("Attempt history is unavailable")); expect(document.querySelector('[data-testid="scanner-job-attempts"]')).toBeNull();
  vi.mocked(scanJobs.attempts).mockResolvedValue([attempt("job-a")]); await click("Retry attempts"); await settled(() => expect(document.querySelector('[data-testid="scanner-job-attempts"]')).not.toBeNull()); expect(scanJobs.attempts).toHaveBeenLastCalledWith("job-a");
});
it("hides failed cached jobs instead of presenting successful empty inventory", async () => {
  await render("list"); await settled(() => expect(host.textContent).toContain("registry.test/job-a:latest")); vi.mocked(scanJobs.list).mockRejectedValue(new Error("refresh failed")); await act(async () => { await client.refetchQueries({ queryKey: ["scan-jobs", "scanner-sources"] }); }); await settled(() => expect(host.textContent).toContain("Scan jobs could not be loaded")); expect(host.textContent).not.toContain("registry.test/job-a:latest"); expect(host.textContent).not.toContain("No scan jobs match this view");
});

it("continues beyond 200 jobs using URL server pages and restores them with Back", async () => {
  serverJobs(Array.from({length:305},(_,index)=>job(`job-${index+1}`)));
  await render("list"); await settled(()=>expect(host.textContent).toContain("305 matching jobs"));
  expect(host.querySelectorAll('[data-testid="scanner-recent-jobs"] tbody tr')).toHaveLength(100);
  await click("Next"); await settled(()=>expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({limit:100,offset:100})));
  await settled(()=>expect(host.textContent).toContain("registry.test/job-101:latest"));
  await click("Next"); await settled(()=>expect(host.textContent).toContain("registry.test/job-201:latest"));
  expect(history.location.href).toContain("page=3");
  await act(async()=>history.back()); await settled(()=>expect(host.textContent).toContain("registry.test/job-101:latest"));
  expect(history.location.href).toContain("page=2");
});
it("sends literal search and server status/type sorting while preserving tab and history", async () => {
  const needle={...job("late"),target_ref:"registry.test/%_needle:latest"};serverJobs([...Array.from({length:250},(_,index)=>job(`job-${index}`)),needle]);
  await render("list","/settings/scanner?tab=jobs&page=3&context=keep");
  await settled(()=>expect(host.querySelector<HTMLInputElement>('[aria-label="Search scan jobs"]')).not.toBeNull());
  const search=host.querySelector<HTMLInputElement>('[aria-label="Search scan jobs"]')!;
  await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value")!.set!.call(search,"%_needle");search.dispatchEvent(new Event("input",{bubbles:true}));});
  await settled(()=>expect(host.textContent).toContain("1 matching jobs"));
  expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({q:"%_needle",offset:0}));
  expect(history.location.href).toContain("context=keep");expect(history.location.href).toContain("tab=jobs");expect(history.location.href).not.toContain("page=");
  await click("failed");await settled(()=>expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({status:"failed",q:"%_needle"})));
  await settled(()=>expect(host.querySelector('[data-testid="scanner-recent-jobs"]')).not.toBeNull());
  const table=host.querySelector('[data-testid="scanner-recent-jobs"]')!;
  await act(async()=>[...table.querySelectorAll<HTMLButtonElement>('th[data-column-id="target"] button')].find((button) => button.textContent === "Target" || button.getAttribute("aria-label") === "Target")!.click());
  await settled(()=>expect(scanJobs.list).toHaveBeenLastCalledWith(expect.objectContaining({sort:"target",order:"desc"})));
  await settled(()=>expect(host.querySelector('[data-testid="scanner-recent-jobs"]')).not.toBeNull());
  expect(host.querySelector('[data-testid="scanner-recent-jobs"] th[data-column-id="worker"] [aria-sort]')).toBeNull();
  await act(async()=>history.back());await settled(()=>expect(history.location.href).not.toContain("sort="));
});
it("retains an off-page exact selection without substituting another job or fetching its attempts", async () => {
  serverJobs(Array.from({length:305},(_,index)=>job(`job-${index+1}`)));
  await render("list","/settings/scanner?page=3&selected=job-a");
  await settled(()=>expect(document.body.textContent).toContain("selected job is outside this page or filter"));
  expect(document.querySelector('[data-testid="scan-job-detail-drawer"]')).toBeNull();expect(scanJobs.attempts).not.toHaveBeenCalled();
  expect(history.location.href).toContain("selected=job-a");
});
it("exports matching jobs across pages with exact filters and visible failure feedback", async () => {
  const cluster="11111111-1111-4111-8111-111111111111",registry="22222222-2222-4222-8222-222222222222";
  const rows=Array.from({length:205},(_,index)=>({...job(`job-${index+1}`),target_cluster_id:cluster,registry_id:registry}));serverJobs(rows);
  vi.mocked(scanJobs.exportCSV).mockRejectedValueOnce(new Error("download failed")).mockResolvedValue({total:205,limit:100000,exported:205,truncated:false});
  await render("list",`/settings/scanner?status=failed&target_type=image&cluster_id=${cluster}&registry_id=${registry}&page=3`);
  await settled(()=>expect(host.textContent).toContain("205 matching jobs"));await click("Export matching CSV");
  await settled(()=>expect(host.textContent).toContain("Matching CSV could not be exported"));
  expect(scanJobs.exportCSV).toHaveBeenLastCalledWith(expect.objectContaining({cluster_id:cluster,registry_id:registry,status:"failed",target_type:"image",sort:"requested",order:"desc",offset:200}), expect.any(Function));
  await click("Export matching CSV");await settled(()=>expect(host.textContent).toContain("Exported all 205 matching records across pages"));
});
it("blocks a stale action from invalidated cache before React rerenders", async () => {
  await render("list");await settled(()=>expect(host.querySelector('[aria-label="Retry"]')).not.toBeNull());
  const retry=host.querySelector<HTMLButtonElement>('[aria-label="Retry"]')!;
  await act(async()=>{void client.invalidateQueries({queryKey:["scan-jobs","scanner-sources","org-a:user-a"],refetchType:"none"});retry.click();});
  await settled(()=>expect(host.textContent).toContain("Could not update scan job job-a"));expect(scanJobsAdmin.retry).not.toHaveBeenCalled();
});
it("hides refreshed queue and selected evidence on failure while preserving selection for Retry", async () => {
  const queue={target_type:"image",pending:9,retry_delayed:0,running:0,stale_running:0,exhausted:0,failed:0,paused:0,canceled:0,completed_last_hour:0,oldest_pending_seconds:5};
  vi.mocked(scanJobs.list).mockImplementation(async request=>({...inventory([job()],request),queue_metrics:[queue]}));
  await render("list");await openJob();await act(async()=>[...host.querySelectorAll<HTMLElement>("summary")].find((item) => item.textContent === "Queue depth by target type" || item.getAttribute("aria-label") === "Queue depth by target type")!.click());await settled(()=>expect(host.querySelector('[data-testid="scanner-queue-metrics"] tbody')?.textContent).toContain("9"));
  const read=deferred<Awaited<ReturnType<typeof scanJobs.list>>>();vi.mocked(scanJobs.list).mockReturnValue(read.promise);
  await act(async()=>{void client.refetchQueries({queryKey:["scan-jobs","scanner-sources","org-a:user-a"]});});
  await settled(()=>expect(host.querySelector('[data-testid="scanner-queue-metrics"] tbody')?.textContent).not.toContain("9"));
  expect(document.querySelector('[data-testid="scan-job-detail-drawer"]')).toBeNull();
  await act(async()=>read.reject(new Error("refresh failed")));await settled(()=>expect(document.body.textContent).toContain("selected job could not be refreshed"));
  expect(history.location.href).toContain("selected=job-a");expect(document.querySelector('[data-testid="scanner-job-attempts"]')).toBeNull();
});
it("keeps image digests closed in target cells while preserving exact CSV evidence", async () => {
  const digest=`sha256:${"a".repeat(64)}`;const image={...job(),target_ref:`registry.test/app@${digest}`};serverJobs([image]);await render("list");
  await settled(()=>expect(host.querySelector('td[data-column-id="target"] details')).not.toBeNull());
  const cell=host.querySelector('td[data-column-id="target"]')!;expect(cell.querySelector("details")!.open).toBe(false);expect(cell.querySelector('[title]')?.getAttribute("title")).toBe("registry.test/app");expect(cell.querySelector("code")?.textContent).toBe(digest);
});
it("rejects foreign job evidence and malformed or out-of-range URL state before offering actions", async () => {
  vi.mocked(scanJobs.list).mockImplementation(async request=>inventory([{...job(),org_id:"foreign"}],request));await render("list");
  await settled(()=>expect(host.textContent).toContain("Scan jobs could not be loaded"));expect(host.querySelector('[aria-label="Retry"]')).toBeNull();
  vi.mocked(scanJobs.list).mockClear();await act(async()=>history.push("/settings/scanner?page=10001"));
  await settled(()=>expect(host.textContent).toContain("Choose supported scan job filters"));expect(scanJobs.list).not.toHaveBeenCalled();
});
it("requires an organization and user owner for the job inventory", async () => {
  await render("list","/settings/scanner",undefined,null);await settled(()=>expect(host.textContent).toContain("An available organization and user session are required to load scan jobs"));expect(scanJobs.list).not.toHaveBeenCalled();expect(scanJobs.attempts).not.toHaveBeenCalled();
});

it("isolates cached jobs and attempts when the organization owner changes", async () => {
  await render("list");await openJob();await settled(()=>expect(document.body.textContent).toContain("worker-with-full-identity"));
  const read=deferred<Awaited<ReturnType<typeof scanJobs.list>>>();vi.mocked(scanJobs.list).mockReturnValue(read.promise);
  await act(async()=>root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{org_id:"org-b",user_id:"user-a"}}><TestRouter history={history} path="/settings/scanner"><ScannerSourcesPage/></TestRouter></TablePreferencesProvider></QueryClientProvider>));
  await settled(()=>expect(document.querySelector('[data-testid="scan-job-detail-drawer"]')).toBeNull());
  expect(document.body.textContent).not.toContain("worker-with-full-identity");
  expect(client.getQueryCache().findAll({queryKey:["scan-jobs","scanner-sources","org-b:user-a"]})).toHaveLength(1);
  const scopedJob={...job(),org_id:"org-b",target_ref:"registry.test/new-owner:latest"};vi.mocked(scanJobs.attempts).mockRejectedValue(new Error("new-owner ledger failed"));
  await act(async()=>read.resolve(inventory([scopedJob])));await settled(()=>expect(document.body.textContent).toContain("Attempt history is unavailable"));
  expect(document.body.textContent).not.toContain("worker-with-full-identity");expect(scanJobs.attempts).toHaveBeenCalledTimes(2);
});
it.each([
 ["pending","Pause","pause"], ["paused","Resume","resume"], ["failed","Retry","retry"], ["running","Cancel","cancel"],
] as const)("preserves eligible %s job %s actions with fresh reviewed identity",async(status,label,action)=>{
 const candidate={...job(),status};serverJobs([candidate]);vi.mocked(scanJobsAdmin[action]).mockResolvedValue({status});await render("list");await settled(()=>expect(host.querySelector(`[aria-label="${label}"]`)).not.toBeNull());await click(label);await settled(()=>expect(scanJobsAdmin[action]).toHaveBeenCalledWith("job-a"));
});

it.each([{org_id:"",user_id:"user-a"},{org_id:"org-a",user_id:""}])("rejects a partial organization/user identity %j",async identity=>{
 await render("list","/settings/scanner",undefined,identity);await settled(()=>expect(host.textContent).toContain("An available organization and user session are required to load scan jobs"));expect(scanJobs.list).not.toHaveBeenCalled();expect(scanJobs.attempts).not.toHaveBeenCalled();
});
