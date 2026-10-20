import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { enterprise, runtimeEvents, type RuntimeEvent, type RuntimeOverview, type RuntimeEventsParams, type RuntimeEventsResponse } from "@/api/client";
import { TestRouter } from "@/test/router";
import { downloadCsv } from "@/lib/csv";
vi.mock("@/lib/csv",()=>({downloadCsv:vi.fn()}));
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { RuntimePage } from "./RuntimePage";

const scope = vi.hoisted(() => ({ available: true, resolvedId: "", loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", async () => {
  const router = await vi.importActual<typeof import("@tanstack/react-router")>("@tanstack/react-router");
  return { useCluster: () => {
    const { id } = router.useParams({ strict: false });
    return { clusterId: id, cluster: scope.available ? { id: scope.resolvedId || id } : undefined, isLoading: scope.loading, error: scope.error };
  } };
});
vi.mock("@/api/client", () => ({ enterprise: { runtime: vi.fn() }, runtimeEvents: { list: vi.fn(), exportCSV: vi.fn() } }));
const evidenceEvent = (cluster = "cluster-a", id = "event-a") => ({ id, cluster_id: cluster, cluster_name: cluster, workload_id: `${cluster}/api`, at: "2026-10-12T12:00:00Z", source: "Falco", kind: "process", severity: "high", verdict: "alert", attack_techniques: ["T1059"], message: `Evidence for ${id}`, rule_id: "rule-a", rule_name: "Shell activity" } as RuntimeOverview["recent_events"][number]);
const overview = (cluster = "cluster-a", hours = 24): RuntimeOverview => ({
  summary: { window_hours: hours, events: 42, alerts: 7, blocks: 3, quarantines: 2, affected_workloads: 8, techniques: 9 },
  subsystems: [{ id: "falco", name: "Falco capability", status: "ready", mode: "monitor", evidence: "Parser available" }],
  modes: [{ id: "monitor", label: "Monitor", blocks: false, description: "Observe and alert" }],
  rules: [{ id: "rule-a", name: "Shell activity", source: "Falco", severity: "high", techniques: ["T1059"], mode: "monitor", event_count: 7, affected_workloads: 2, last_triggered_at: "2026-10-12T12:00:00Z" }],
  recent_events: [evidenceEvent(cluster), evidenceEvent(cluster, "event-b")],
  workloads: [{ workload_id: `${cluster}/api`, events: 42, alerts: 7, blocks: 3, highest_severity: "high", last_seen_at: "2026-10-12T12:00:00Z", sources: ["Falco"], techniques: ["T1059"] }],
});
const rawEvent = (cluster = "cluster-a"): RuntimeEvent => ({ id: `raw-${cluster}`, at: "2026-10-10T12:00:00Z", workload_id: `${cluster}/raw`, kind: "exec", source: "runtime-agent", severity: "critical", verdict: "alert", node_id: "node", namespace: cluster, container_id: "container-id", attack_techniques: ["T1059"], payload: { pod: "raw-pod" } });
function historyResponse(params: RuntimeEventsParams = {}, supplied?: RuntimeEvent[]): RuntimeEventsResponse {
 const events=(supplied || [rawEvent(params.cluster_id)]).map(event=>({...event,cluster_id:event.cluster_id || params.cluster_id || "cluster-a",row_id:`${event.id}@${event.at}`}));
 const total=events.length;
 return { ...params, events:events.slice(params.offset || 0,(params.offset || 0)+100), limit:100,offset:params.offset || 0,sort:params.sort || "at",order:params.order || "desc",cluster_id:params.cluster_id || "cluster-a",total,has_more:total>(params.offset || 0)+100,summary:{total,alerting:events.filter(event=>["alert","block","quarantine"].includes(event.verdict)).length,blocks:events.filter(event=>event.verdict==="block").length,quarantines:events.filter(event=>event.verdict==="quarantine").length,affected_workloads:new Set(events.map(event=>event.cluster_id+":"+event.workload_id)).size,observed:events.filter(event=>event.verdict==="observed").length} };
}
let identity: {org_id:string;user_id:string}|null={org_id:"org",user_id:"user"};
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  identity={org_id:"org",user_id:"user"};
  scope.available = true; scope.resolvedId = ""; scope.loading = false; scope.error = null;
  vi.mocked(enterprise.runtime).mockImplementation(async (params) => overview(params?.cluster_id, params?.hours));
  vi.mocked(runtimeEvents.list).mockImplementation(async (params) => historyResponse(params));
  vi.mocked(runtimeEvents.exportCSV).mockResolvedValue({total:1,exported:1,limit:100000,truncated:false});
});
afterEach(() => { act(() => root?.unmount()); host?.remove(); client?.clear(); vi.resetAllMocks(); });
// The first route mounts two asynchronous queries; allow the same bounded
// render budget under concurrent CI load as the other inventory workflows.
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }, { timeout: 3000 }); }
async function render(url = "/clusters/cluster-a/runtime", seed?: (client: QueryClient) => void) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); seed?.(client);
  history = createMemoryHistory({ initialEntries: [url] });
  await rerender();
}
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}><TestRouter path="/clusters/$id/runtime" history={history}><RuntimePage /></TestRouter></TablePreferencesProvider></QueryClientProvider>)); }
async function tab(label: string) {
  const trigger = [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((item) => item.textContent === label || item.getAttribute("aria-label") === label)!;
  await act(async () => trigger.focus());
  await settled(() => expect(trigger.getAttribute('aria-selected')).toBe("true"));
}
async function windowHours(hours: number) {
  await act(async () => { const select = host.querySelector<HTMLSelectElement>('[data-testid="runtime-window-select"]')!; select.value = String(hours); select.dispatchEvent(new Event("change", { bubbles: true })); });
}
const summaryValues = () => [...host.querySelectorAll('[data-testid="runtime-summary"] .app-stat-value')].map((item) => item.textContent);

it("shows five matching-history KPIs and the event inventory as the sole default workspace", async () => {
  await render(); await settled(() => expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());
  expect(summaryValues()).toEqual(["1", "1", "0", "0", "1"]);
  expect(host.querySelector('[data-testid="runtime-summary"]')!.children).toHaveLength(5);
  expect(host.textContent).toContain("1 alerting events match these filters");
  expect(host.textContent).toContain("Runtime event history"); expect(host.textContent).toContain("separate from the evidence time window");
  expect(host.textContent).toContain("cluster-a/raw"); expect(host.textContent).toContain("runtime-agent"); expect(host.textContent).toContain("alert");
  expect(host.querySelector('[data-testid="runtime-subsystems"]')).toBeNull(); expect(host.querySelector('[data-testid="runtime-event-evidence"]')).toBeNull(); expect(host.querySelector('[data-testid="runtime-event-inspector"]')).toBeNull();
  expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 24, cluster_id: "cluster-a" }); expect(runtimeEvents.list).toHaveBeenCalledWith(expect.objectContaining({ limit: 100, cluster_id: "cluster-a",offset:0,sort:"at",order:"desc" }));
});
it("never calls either endpoint while the cluster is loading, missing or mismatched", async () => {
  scope.loading = true; await render(); expect(host.textContent).toContain("Resolving runtime cluster"); expect(enterprise.runtime).not.toHaveBeenCalled(); expect(runtimeEvents.list).not.toHaveBeenCalled();
  scope.loading = false; scope.available = false; await act(async () => history.push("/clusters/cluster-a/runtime?context=unavailable")); await settled(() => expect(host.textContent).toContain("cluster could not be resolved"));
  scope.available = true; scope.resolvedId = "another"; await act(async () => history.push("/clusters/cluster-a/runtime?context=mismatched")); await settled(() => expect(host.textContent).toContain("cluster could not be resolved")); expect(enterprise.runtime).not.toHaveBeenCalled(); expect(runtimeEvents.list).not.toHaveBeenCalled();
});
it("does not treat cached cluster identity as settled while registry refresh is pending or failed", async () => {
  await render(undefined, (qc) => qc.setQueryData(["clusters"], { clusters: [{ id: "cluster-a" }] })); await settled(() => expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());
  let fail!: (error: Error) => void; const pending = new Promise((_, reject) => { fail = reject; }); let fetch!: Promise<unknown>;
  await act(async () => { fetch = client.fetchQuery({ queryKey: ["clusters"], queryFn: () => pending }).catch(() => {}); });
  await settled(() => expect(host.textContent).toContain("Resolving runtime cluster")); expect(host.querySelector('[data-testid="runtime-summary"]')).toBeNull();
  await act(async () => { fail(new Error("Registry unavailable")); await fetch; }); await settled(() => expect(host.textContent).toContain("cluster could not be resolved"));
  expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});
it("keeps pending data distinct from zero counts and successful empty inventories", async () => {
  vi.mocked(enterprise.runtime).mockImplementation(() => new Promise(() => {})); vi.mocked(runtimeEvents.list).mockImplementation(() => new Promise(() => {}));
  await render(); await settled(() => expect(host.querySelector('[data-testid="runtime-summary"]')).not.toBeNull()); expect(summaryValues()).toEqual(["—", "—", "—", "—", "—"]);
  expect(host.textContent).toContain("Loading runtime events"); expect(host.textContent).not.toContain("No runtime events"); expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});
it("surfaces overview and live errors with retry instead of empty success", async () => {
  vi.mocked(enterprise.runtime).mockRejectedValueOnce(new Error("Overview failed")).mockResolvedValue(overview());
  vi.mocked(runtimeEvents.list).mockRejectedValueOnce(new Error("Feed failed")).mockResolvedValue(historyResponse());
  await render(); await settled(() => expect(host.textContent).toContain("Feed failed")); expect(host.textContent).not.toContain("Overview failed"); expect(summaryValues()).toEqual(["—", "—", "—", "—", "—"]); expect(host.textContent).not.toContain("No runtime events");
  const retries = [...host.querySelectorAll<HTMLButtonElement>('button')].filter((item) => item.textContent?.startsWith("Retry")); await act(async () => { retries.forEach((button) => button.click()); });
  await settled(() => expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull()); await settled(() => expect(summaryValues()[0]).toBe("1"));
});
it("shows refresh failures even with cached success and stops presenting stale totals as current", async () => {
  await render(); await settled(() => expect(summaryValues()[0]).toBe("1")); vi.mocked(enterprise.runtime).mockRejectedValue(new Error("Overview refresh failed")); vi.mocked(runtimeEvents.list).mockRejectedValue(new Error("Feed refresh failed"));
  await act(async () => { await Promise.all([client.refetchQueries({ queryKey: ["runtime-overview"] }), client.refetchQueries({ queryKey: ["runtime-events-live"] })]); });
  await settled(() => expect(host.textContent).toContain("Feed refresh failed")); expect(host.textContent).not.toContain("Overview refresh failed"); expect(summaryValues()).toEqual(["—", "—", "—", "—", "—"]); expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});
it("shares hours and workspace through the URL while keeping the live cohort unchanged", async () => {
  await render("/clusters/cluster-a/runtime?tab=evidence&hours=6&context=dashboard#evidence"); await settled(() => expect(summaryValues()[0]).toBe("42"));
  expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 6, cluster_id: "cluster-a" }); await windowHours(72); await settled(() => expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 72, cluster_id: "cluster-a" }));
  expect(new URLSearchParams(history.location.search).get("hours")).toBe("72"); expect(history.location.hash).toBe("#evidence"); expect(runtimeEvents.list).toHaveBeenCalledTimes(1);
  await tab("Subsystems"); expect(new URLSearchParams(history.location.search).get("tab")).toBe("subsystems"); expect(new URLSearchParams(history.location.search).get("context")).toBe("dashboard");
  expect(host.textContent).toContain("ready feature does not confirm"); expect(host.querySelector('table')).not.toBeNull(); expect(host.querySelector('details')?.open).toBe(false);
  await act(async () => history.back()); await settled(() => expect(host.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Window evidence"));
});
it("loads the exact URL event and never substitutes another event when it is absent", async () => {
  await render("/clusters/cluster-a/runtime?tab=evidence&event=event-b&hours=6"); await settled(() => expect(host.querySelector('[data-testid="runtime-event-inspector"]')?.textContent).toContain("Evidence for event-b"));
  await act(async () => history.push("/clusters/cluster-a/runtime?tab=evidence&event=missing&hours=6")); await settled(() => expect(host.textContent).toContain("No other event has been substituted"));
  expect(host.querySelector('[data-testid="runtime-event-inspector"]')).toBeNull(); expect(new URLSearchParams(history.location.search).get("event")).toBe("missing");
});
it("writes event selection once into history and restores it through Back and Forward", async () => {
  await render("/clusters/cluster-a/runtime?tab=evidence&hours=24"); await settled(() => expect(host.querySelectorAll('[data-testid="runtime-event-row"]')).toHaveLength(2));
  const row = host.querySelector('[data-testid="runtime-event-row"]')!; await act(async () => row.querySelector<HTMLButtonElement>('button')!.click()); await settled(() => expect(new URLSearchParams(history.location.search).get("event")).toBe("event-a"));
  expect(host.querySelector('[data-testid="runtime-event-inspector"]')?.textContent).toContain("Evidence for event-a");
  await act(async () => history.back()); await settled(() => expect(new URLSearchParams(history.location.search).has("event")).toBe(false)); expect(host.querySelector('[data-testid="runtime-event-inspector"]')).toBeNull();
  await act(async () => history.forward()); await settled(() => expect(host.querySelector('[data-testid="runtime-event-inspector"]')?.textContent).toContain("Evidence for event-a"));
});
it("does not expose a sibling cluster’s returned event in a selected detail", async () => {
  vi.mocked(enterprise.runtime).mockResolvedValue({ ...overview(), recent_events: [evidenceEvent("cluster-b", "foreign-event")] });
  await render("/clusters/cluster-a/runtime?tab=evidence&event=foreign-event"); await settled(() => expect(host.textContent).toContain("selected event cannot be resolved uniquely"));
  expect(host.querySelector('[data-testid="runtime-event-inspector"]')).toBeNull(); expect(host.textContent).not.toContain("Evidence for foreign-event");
});
it("changes cluster query keys and never renders a late response from the previous cluster", async () => {
  let release!: (value: RuntimeOverview) => void; vi.mocked(enterprise.runtime).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; }));
  await render("/clusters/cluster-a/runtime?tab=evidence&event=event-a"); await settled(() => expect(release).toBeDefined());
  await act(async () => history.push("/clusters/cluster-b/runtime?tab=evidence&event=event-b")); await settled(() => expect(host.querySelector('[data-testid="runtime-event-inspector"]')?.textContent).toContain("cluster-b/api"));
  await act(async () => release(overview("cluster-a"))); expect(host.querySelector('[data-testid="runtime-event-inspector"]')?.textContent).not.toContain("cluster-a/api");
  expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 24, cluster_id: "cluster-b" }); expect(runtimeEvents.list).toHaveBeenCalledWith(expect.objectContaining({ limit: 100, cluster_id: "cluster-b" }));
});
it("retains complete workloads and rule evidence behind shared tables with clear response bounds", async () => {
  await render("/clusters/cluster-a/runtime?tab=workloads"); await settled(() => expect(host.querySelector('[data-testid="runtime-workloads"]')?.textContent).toContain("cluster-a/api"));
  expect(host.textContent).toContain("Top 10 workloads"); expect(host.textContent).toContain("T1059"); expect(host.querySelector('table')).not.toBeNull();
  await tab("Rule catalog"); expect(host.textContent).toContain("Shell activity"); expect(host.textContent).toContain("selected 24h window"); expect(host.textContent).toContain("Last triggered");
});
it("uses 24h for malformed hours and rejects mismatched window responses without reporting zero", async () => {
  vi.mocked(enterprise.runtime).mockResolvedValue(overview("cluster-a", 6)); await render("/clusters/cluster-a/runtime?tab=evidence&hours=invalid");
  await settled(() => expect(host.textContent).toContain("does not match the selected time window")); expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 24, cluster_id: "cluster-a" }); expect(summaryValues()).toEqual(["—", "—", "—", "—", "—"]);
});

it("retains table rows and focus during a routine poll, then hides them on refresh failure", async () => {
  await render(); await settled(() => expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());
  const table = host.querySelector('[data-testid="runtime-live-table"]')!;
  const control = table.querySelector<HTMLButtonElement>('button')!;
  await act(async () => control.focus());
  let fail!: (error: Error) => void; vi.mocked(runtimeEvents.list).mockImplementationOnce(() => new Promise((_, reject) => { fail = reject; })); let refresh!: Promise<void>;
  await act(async () => { refresh = client.refetchQueries({ queryKey: ["runtime-events-live"] }); });
  await settled(() => expect(host.querySelector('[data-testid="runtime-live-status"]')?.textContent).toBe("Refreshing"));
  expect(host.querySelector('[data-testid="runtime-live-table"]')).toBe(table); expect(host.textContent).toContain("cluster-a/raw"); expect(document.activeElement).toBe(control); expect(summaryValues()[0]).toBe("1");
  await act(async () => { fail(new Error("Poll failed")); await refresh; }); await settled(() => expect(host.textContent).toContain("Poll failed")); expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});

it("links the complete alerting cohort with the source's precise lower boundary",async()=>{
 const data=overview();data.summary.window_start="2026-10-11T12:34:56.123456Z";vi.mocked(enterprise.runtime).mockResolvedValue(data);
 await render("/clusters/cluster-a/runtime?tab=evidence&hours=24");await settled(()=>expect(host.querySelector('[data-testid="runtime-alert-events-link"]')).not.toBeNull());
 const url=new URL(host.querySelector<HTMLAnchorElement>('[data-testid="runtime-alert-events-link"]')!.getAttribute("href")!,"https://example.com");expect(url.pathname).toBe("/clusters/cluster-a/timeline");expect(url.searchParams.get("tab")).toBe("event");expect(url.searchParams.get("after")).toBe(data.summary.window_start);expect(url.searchParams.get("verdict")).toBe("alert,block,quarantine");expect(url.searchParams.has("hours")).toBe(false);
});

it.each(["live","evidence","workloads"])("retains server role metadata and explicit unknown values in %s CSV",async workspace=>{
 const data=overview();data.recent_events=[{...evidenceEvent(),platform_role:"core"},{...evidenceEvent("cluster-a","unknown"),platform_role:""}];data.workloads=[{...data.workloads[0],platform_role:"core"},{...data.workloads[0],workload_id:"prod/customer",platform_role:""}];
 vi.mocked(enterprise.runtime).mockResolvedValue(data);vi.mocked(runtimeEvents.list).mockResolvedValue(historyResponse({},[{...rawEvent(),cluster_id:"cluster-a",platform_role:"core"},{...rawEvent(),id:"unknown",workload_id:"prod/customer",platform_role:""}]));
 await render(`/clusters/cluster-a/runtime?tab=${workspace}`);await settled(()=>expect(host.textContent).toContain("core"));
 const exportButton=[...host.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent === "Export CSV" || button.getAttribute("aria-label") === "Export CSV")!;await act(async()=>exportButton.click());
 const [,headers,rows]=vi.mocked(downloadCsv).mock.calls.at(-1)!;const column=headers.indexOf("platform_role");expect(column).toBeGreaterThanOrEqual(0);expect(rows.map(row=>row[column])).toEqual(["core",""]);expect(rows.flat()).not.toContain("Not classified");
});
it("rejects foreign-cluster raw event metadata instead of exporting it",async()=>{
 vi.mocked(runtimeEvents.list).mockResolvedValue(historyResponse({},[{...rawEvent(),cluster_id:"other",platform_role:"core"}]));await render();await settled(()=>expect(host.textContent).toContain("Runtime events do not match the selected scope, filters or page"));expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();expect(host.textContent).not.toContain("raw-cluster-a");
});
it("lets the operator change the initially compact live-event density",async()=>{
 await render();await settled(()=>expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());const table=host.querySelector('[data-testid="runtime-live-table"]')!;const cell=()=>table.querySelector<HTMLElement>('tbody td')!;
 expect(cell().className).toContain("py-0.5");await act(async()=>table.querySelector<HTMLButtonElement>('[aria-label="comfy density"]')!.click());expect(cell().className).toContain("py-2");
});

const historyRows = () => Array.from({length:205},(_,index)=>({...rawEvent(),id:index<2?"shared-uuid":`event-${index}`,at:new Date(Date.UTC(2026,9,10,12,0,index)).toISOString(),workload_id:`operations/service-${index}`,namespace:"operations",kind:index%2?"file_open":"exec",source:"ebpf",verdict:index%2?"observed":"alert",severity:"high" as const,payload:{message:`Evidence ${index}`}}));
const findButton=(text:string)=>[...host.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent?.trim() === text || button.getAttribute("aria-label") === text)!;
async function selectHistory(id:string,value:string){await act(async()=>{const input=host.querySelector<HTMLSelectElement>(id)!;Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,"value")!.set!.call(input,value);input.dispatchEvent(new Event("change",{bubbles:true}));});}
it("continues beyond the old latest100 cap and exports every matching record with server page counts",async()=>{
 vi.mocked(runtimeEvents.list).mockImplementation(async request=>historyResponse(request,historyRows()));
 vi.mocked(runtimeEvents.exportCSV).mockResolvedValue({total:205,exported:205,limit:100000,truncated:false});
 await render("/clusters/cluster-a/runtime?page=3&hours=6&context=a&context=b#runtime");
 await settled(()=>expect(host.querySelectorAll('[data-testid="runtime-live-table"] tbody tr')).toHaveLength(5));
 expect(summaryValues()).toEqual(["205","103","0","0","205"]);expect(host.textContent).toContain("operations/service-200");expect(host.textContent).not.toContain("operations/service-0");
 expect(runtimeEvents.list).toHaveBeenLastCalledWith(expect.objectContaining({offset:200,limit:100,sort:"at",order:"desc"}));
 await act(async()=>findButton("Export matching CSV").click());expect(runtimeEvents.exportCSV).toHaveBeenCalledWith(expect.objectContaining({offset:200,cluster_id:"cluster-a"}), expect.any(Function));
 await settled(()=>expect(host.textContent).toContain("Exported all 205 matching records across pages"));
 await act(async()=>findButton("Prev").click());await settled(()=>expect(host.querySelectorAll('[data-testid="runtime-live-table"] tbody tr')).toHaveLength(100));
 expect(new URLSearchParams(history.location.search).getAll("context")).toEqual(["a","b"]);expect(history.location.hash).toBe("#runtime");
 await act(async()=>history.back());await settled(()=>expect(host.querySelectorAll('[data-testid="runtime-live-table"] tbody tr')).toHaveLength(5));
});
it("pushes server filter/sort history, restores Back and leaves window scope unchanged",async()=>{
 vi.mocked(runtimeEvents.list).mockImplementation(async request=>historyResponse(request,historyRows().filter(event=>!request?.verdict||event.verdict===request.verdict)));
 await render("/clusters/cluster-a/runtime?page=2&hours=6&context=original");await settled(()=>expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());
 await selectHistory("#runtime-event-verdict","alert");await settled(()=>expect(runtimeEvents.list).toHaveBeenLastCalledWith(expect.objectContaining({verdict:"alert",offset:0})));
 expect(history.location.search).toContain("hours=6");expect(history.location.search).not.toContain("page=2");
 await act(async()=>host.querySelector<HTMLButtonElement>('th[aria-sort="descending"] button')!.click());await settled(()=>expect(runtimeEvents.list).toHaveBeenLastCalledWith(expect.objectContaining({sort:"at",order:"asc"})));
 await act(async()=>history.back());await settled(()=>expect(host.querySelector('th[aria-sort="descending"]')).not.toBeNull());
 await act(async()=>history.back());await settled(()=>expect(host.querySelector<HTMLSelectElement>("#runtime-event-verdict")!.value).toBe(""));expect(history.location.search).toContain("page=2");
 expect(enterprise.runtime).toHaveBeenCalledTimes(1);
});
it("keeps exact timestamp bounds through requests and rejects reversed microsecond windows before fetching",async()=>{
 vi.mocked(runtimeEvents.list).mockImplementation(async request=>historyResponse(request,[{...rawEvent(),at:request?.after || rawEvent().at}]));
 await render("/clusters/cluster-a/runtime?after=2026-10-10T12%3A00%3A00.123456Z&before=2026-10-10T12%3A00%3A00.123457Z");
 await settled(()=>expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());
 expect(runtimeEvents.list).toHaveBeenLastCalledWith(expect.objectContaining({after:"2026-10-10T12:00:00.123456Z",before:"2026-10-10T12:00:00.123457Z"}));
 await act(async()=>history.push("/clusters/cluster-a/runtime?after=2026-10-10T12:00:00.123457Z&before=2026-10-10T12:00:00.123456Z"));
 await settled(()=>expect(host.textContent).toContain("requested runtime event filters or page are invalid"));expect(runtimeEvents.list).toHaveBeenCalledTimes(1);expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});
it("isolates the owner cache and withholds history/export during account changes or failed reads",async()=>{
 await render();await settled(()=>expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());
 identity={org_id:"other-org",user_id:"other-user"};vi.mocked(runtimeEvents.list).mockRejectedValue(new Error("New owner unavailable"));await rerender();await settled(()=>expect(host.textContent).toContain("New owner unavailable"));
 expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();expect(summaryValues()).toEqual(["—","—","—","—","—"]);expect(findButton("Export matching CSV")).toBeUndefined();
 expect(client.getQueryCache().getAll().filter(query=>query.queryKey[0]==="runtime-events-live").map(query=>query.queryKey[1])).toEqual(["org:user","other-org:other-user"]);
 identity=null;await rerender();expect(host.textContent).toContain("Resolve the current account");expect(runtimeEvents.list).toHaveBeenCalledTimes(2);
});
it.each(["null-row","missing-workload","bad-summary","duplicate-row-id","wrong-page","wrong-time","object-bound"])("withholds malformed %s history rather than crashing or exposing an unconfirmed export",async scenario=>{
 vi.mocked(runtimeEvents.list).mockImplementation(async request=>{const data=historyResponse(request,[rawEvent(),{...rawEvent(),id:"second"}]);if(scenario==="object-bound")data.after={} as unknown as string;else if(scenario==="wrong-time")data.events[0]={...data.events[0],at:"2026-10-10T12:00:00.000001Z",row_id:`${data.events[0].id}@2026-10-10T12:00:00.000001Z`};else if(scenario==="bad-summary")data.summary!.total=20;else if(scenario==="wrong-page")data.offset=100;else if(scenario==="duplicate-row-id")data.events[1].row_id=data.events[0].row_id;else data.events[0]=(scenario==="null-row"?null:{...data.events[0],workload_id:undefined}) as unknown as RuntimeEvent;return data;});
 await render(["wrong-time","object-bound"].includes(scenario)?"/clusters/cluster-a/runtime?after=2026-10-10T12:00:00.000002Z":undefined);await settled(()=>expect(host.textContent).toContain("Runtime events do not match the selected scope, filters or page"));expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();expect(findButton("Export matching CSV")).toBeUndefined();
});
it("reports a capped matching export and a retryable download failure",async()=>{
 vi.mocked(runtimeEvents.exportCSV).mockResolvedValueOnce({total:100005,exported:100000,limit:100000,truncated:true}).mockRejectedValueOnce(new Error("Download failed"));
 await render();await settled(()=>expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());await act(async()=>findButton("Export matching CSV").click());
 await settled(()=>expect(host.textContent).toContain("Export capped at 100,000 of 100,005"));await act(async()=>findButton("Export matching CSV").click());await settled(()=>expect(host.textContent).toContain("Matching CSV could not be exported"));
});

it("keeps repeated event UUIDs distinct by timestamp and refuses an ambiguous legacy selection",async()=>{
 const data=overview();const first=evidenceEvent("cluster-a","reused-uuid"),second={...first,at:"2026-10-12T12:00:00.123456Z",message:"Exact later physical record"};data.recent_events=[first,second];vi.mocked(enterprise.runtime).mockResolvedValue(data);
 await render("/clusters/cluster-a/runtime?tab=evidence&event=reused-uuid");await settled(()=>expect(host.textContent).toContain("cannot be resolved uniquely"));expect(host.querySelector('[data-testid="runtime-event-inspector"]')).toBeNull();
 const rows=host.querySelectorAll('[data-testid="runtime-event-row"]');expect(rows).toHaveLength(2);
 await act(async()=>rows[1].querySelector<HTMLButtonElement>("button")!.click());await settled(()=>expect(host.querySelector('[data-testid="runtime-event-inspector"]')!.textContent).toContain("Exact later physical record"));
 expect(new URLSearchParams(history.location.search).get("event_at")).toBe(second.at);
 await act(async()=>history.back());await settled(()=>expect(host.querySelector('[data-testid="runtime-event-inspector"]')).toBeNull());
});

it("continues a two-million-record runtime inventory on URL page20001 without clamping to the first page",async()=>{
 vi.mocked(runtimeEvents.list).mockImplementation(async request=>{
  const offset=request?.offset || 0,total=2025049;
  const events=Array.from({length:Math.min(100,Math.max(0,total-offset))},(_,index)=>({...rawEvent(),id:`deep-${offset+index}`,workload_id:`operations/record-${offset+index}`}));
  return {...historyResponse({...request,offset:0},events),offset,total,has_more:offset+events.length<total,summary:{total,alerting:total,blocks:0,quarantines:0,affected_workloads:total,observed:0}};
 });
 await render("/clusters/cluster-a/runtime?page=20001&context=deep-history");await settled(()=>expect(host.querySelectorAll('[data-testid="runtime-live-table"] tbody tr')).toHaveLength(100));
 expect(runtimeEvents.list).toHaveBeenLastCalledWith(expect.objectContaining({offset:2000000,limit:100}));expect(host.textContent).toContain("operations/record-2000000");expect(host.textContent).toContain("Page 20001 of 20,251");
 await act(async()=>findButton("Next").click());await settled(()=>expect(runtimeEvents.list).toHaveBeenLastCalledWith(expect.objectContaining({offset:2000100})));expect(history.location.search).toContain("page=20002");
 await act(async()=>history.back());await settled(()=>expect(host.textContent).toContain("operations/record-2000000"));expect(history.location.search).toContain("page=20001");
});
it.each(["21474838","99999999999999999999"])("rejects over-cap runtime page%s before requesting a clamped source page",async page=>{
 await render(`/clusters/cluster-a/runtime?page=${page}`);expect(runtimeEvents.list).not.toHaveBeenCalled();expect(host.textContent).toContain("requested runtime event filters or page are invalid");expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});
