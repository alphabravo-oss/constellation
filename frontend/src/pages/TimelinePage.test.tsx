import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { securityTimeline, type TimelineItem } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import { TestRouter } from "@/test/router";
import { downloadCsv } from "@/lib/csv";
vi.mock("@/lib/csv",()=>({downloadCsv:vi.fn()}));
import { TimelinePage } from "./TimelinePage";
import { chooseExport, exportAvailable } from "@/test/export-menu";

const scope = vi.hoisted(() => ({ clusterId: "cluster", cluster: { id: "cluster", name: "Primary" }, isLoading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({ securityTimeline: { list: vi.fn(), exportCSV: vi.fn() } }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
let history: RouterHistory;
const item: TimelineItem = { id: "same-id", source: "runtime_event", severity: "high", at: "2026-10-12T00:00:00Z", title: "Process observed", cluster_id: "cluster" };
const response = { items: [item], limit: 100, offset: 0, has_more: true, from: "2026-10-11T00:00:00Z", to: "2026-10-12T00:00:00Z" };

beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  vi.clearAllMocks(); localStorage.clear();
  Object.assign(scope, { clusterId: "cluster", cluster: { id: "cluster", name: "Primary" }, isLoading: false, error: null });
  vi.mocked(securityTimeline.list).mockImplementation(async params=>({...response,offset:params?.offset??0}));
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); });
async function render(url = "/clusters/cluster/timeline") {
  history = createMemoryHistory({ initialEntries: [url] });
  await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ org_id: "org", user_id: "user" }}><TestRouter history={history}><TimelinePage /></TestRouter></TablePreferencesProvider></QueryClientProvider>));
  await act(async () => new Promise(resolve => setTimeout(resolve, 20)));
}
async function settled(check: () => void | Promise<void>) { await vi.waitFor(async () => { await act(async () => {}); await check(); }); }
function click(label: string) { const button = [...host.querySelectorAll("button")].find((el) => el.textContent?.trim() === label || el.getAttribute("aria-label") === label)!; act(() => { if (label.startsWith("Views (")) button.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true })); else button.click(); }); }

it("restores source, severity, text, time and page filters from a shared URL", async () => {
  await render("/clusters/cluster/timeline?tab=custom&type=audit,runtime_event&severity=critical,high&q=exec&namespace=prod&workload=api&ref=rule&from=2026-10-10T00:00&to=2026-10-12T00:00&page=3");
  expect(securityTimeline.list).toHaveBeenLastCalledWith({ cluster_id: "cluster", type: "runtime_event,audit", severity: "critical,high", q: "exec", namespace: "prod", workload: "api", ref: "rule", from: "2026-10-10T00:00:00.000Z", to: "2026-10-12T00:00:00.000Z", limit: 100, offset: 200 });
  await settled(() => expect(host.querySelector('[data-testid="timeline-page-scope"]')?.textContent).toContain("201–201"));
});

it("pushes category/page history, clears the page on filter changes and preserves unrelated context", async () => {
  await render("/clusters/cluster/timeline?context=dashboard#event");
  await settled(() => expect(host.querySelector('[data-testid="timeline-event-row"]')).not.toBeNull());
  click("Next");
  await settled(() => expect(history.location.search).toContain("page=2"));
  act(() => host.querySelector<HTMLButtonElement>('[data-testid="timeline-category-audit"]')!.click());
  await settled(() => expect(history.location.search).toContain("tab=audit"));
  expect(history.location.search).not.toContain("page=");
  expect(history.location.search).toContain("context=dashboard"); expect(history.location.hash).toBe("#event");
  await act(async () => history.back());
  await settled(() => expect(history.location.search).toContain("page=2"));
  expect(securityTimeline.list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 100 }));
});

it.each(["missing", "mismatched", "failed"])("does not fetch any cluster when its scope is %s", async condition => {
  if (condition === "missing") scope.clusterId = "";
  if (condition === "mismatched") scope.cluster = { id: "other", name: "Other" };
  if (condition === "failed") scope.error = new Error("unavailable");
  await render();
  expect(securityTimeline.list).not.toHaveBeenCalled();
  expect(host.textContent).toContain("Cluster could not be resolved");
});

it("blocks unresolved cluster loads", async () => {
  scope.isLoading = true;
  await render();
  expect(securityTimeline.list).not.toHaveBeenCalled();
  expect(host.textContent).toContain("Loading cluster");
});

it("does not silently broaden an invalid or inverted time window", async () => {
  await render("/clusters/cluster/timeline?from=2026-10-12T00:00&to=2026-10-10T00:00");
  expect(securityTimeline.list).not.toHaveBeenCalled();
  expect(host.textContent).toContain("Choose valid dates");
  expect(host.querySelector('[data-testid="timeline-summary"]')).toBeNull();
});

it("preserves an empty custom source selection across reloads", async () => {
  await render("/clusters/cluster/timeline?tab=custom&type=none");
  expect(securityTimeline.list).not.toHaveBeenCalled();
  expect(host.textContent).toContain("Choose an event source");
});

it("uses source plus ID for exact detail selection and never substitutes a missing event", async () => {
  await render("/clusters/cluster/timeline?event=audit:same-id");
  await settled(() => expect(host.textContent).toContain("Selected event is unavailable"));
  expect(document.querySelector('[data-testid="timeline-detail-drawer"]')).toBeNull();
  act(() => host.querySelector<HTMLButtonElement>('[data-testid="timeline-event-row"]')!.click());
  await settled(() => expect(new URLSearchParams(history.location.search).get("event")).toBe("runtime_event:same-id"));
  expect(document.querySelector('[data-testid="timeline-detail-drawer"]')?.textContent).toContain("Process observed");
});

it("hides stale counts and detail when a refresh fails and offers Retry", async () => {
  await render("/clusters/cluster/timeline?event=runtime_event:same-id");
  await settled(() => expect(host.querySelector('[data-testid="timeline-summary"]')).not.toBeNull());
  vi.mocked(securityTimeline.list).mockRejectedValue(new Error("unavailable"));
  await act(async () => { await client.invalidateQueries({ queryKey: ["security-timeline"] }); });
  await settled(() => expect(host.textContent).toContain("Failed to load the incident timeline"));
  expect(host.querySelector('[data-testid="timeline-summary"]')).toBeNull();
  expect(document.querySelector('[data-testid="timeline-detail-drawer"]')).toBeNull();
  expect([...host.querySelectorAll("button")].some(button => button.textContent === "Retry")).toBe(true);
});

it("opens a dedicated saved-view form with complete filter, page, selected event and hash context", async () => {
  await render("/clusters/cluster/timeline?tab=custom&type=runtime_event&severity=high&q=api&namespace=prod&page=3&event=runtime_event:same-id&context=keep#evidence");
  click("Save view"); await settled(() => expect(history.location.pathname).toBe("/clusters/cluster/timeline/views/new"));
  const params = new URLSearchParams(history.location.search); expect(params.get("q")).toBe("api"); expect(params.get("page")).toBe("3"); expect(params.get("event")).toBe("runtime_event:same-id"); expect(params.get("context")).toBe("keep"); expect(history.location.hash).toBe("#evidence");
});
it("ignores malformed timeline payloads and applies validated advanced filters", async () => {
  const key = operatorStorageKey("constellation.timeline.views.v1", { org_id: "org", user_id: "user" })!;
  localStorage.setItem(key, JSON.stringify([{ id: "valid", name: "Named investigation", category: "custom", sources: ["runtime_event"], severities: ["high"], query: "api", namespace: "prod", workload: "web", reference: "rule", from: "2026-10-10T00:00", to: "2026-10-12T00:00" }, { id: "bad", name: "Malformed", category: "custom", sources: {}, query: [] }]));
  await render(); click("Views (1)"); expect(host.textContent).not.toContain("Malformed");
  expect(host.textContent).toContain("1 saved view record was rejected");
  const apply = [...document.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent?.startsWith("Named investigation"))!; await act(async () => apply.click());
  await settled(() => expect(securityTimeline.list).toHaveBeenLastCalledWith(expect.objectContaining({ type: "runtime_event", severity: "high", q: "api", namespace: "prod", workload: "web", ref: "rule", from: "2026-10-10T00:00:00.000Z", to: "2026-10-12T00:00:00.000Z", offset: 0 })));
});
it("retains ISO timestamp offsets and milliseconds when applying a saved view", async () => {
  const from = "2026-10-10T12:34:56.789+05:30"; const to = "2026-10-10T12:35:01.123+05:30";
  const key = operatorStorageKey("constellation.timeline.views.v1", { org_id: "org", user_id: "user" })!;
  localStorage.setItem(key, JSON.stringify([{ id: "precise", name: "Exact interval", category: "audit", sources: ["audit"], severities: [], query: "", namespace: "", workload: "", reference: "", from, to }]));
  await render(); click("Views (1)");
  const apply = [...document.querySelectorAll<HTMLButtonElement>("button")].find(button => button.textContent?.startsWith("Exact interval"))!;
  await act(async () => apply.click());
  await settled(() => expect(securityTimeline.list).toHaveBeenLastCalledWith(expect.objectContaining({ type: "audit", from: "2026-10-10T07:04:56.789Z", to: "2026-10-10T07:05:01.123Z" })));
  const params = new URLSearchParams(history.location.search); expect(params.get("from")).toBe(from); expect(params.get("to")).toBe(to);
});

const boundary="2026-10-11T12:34:56.123456Z";
function exactResponse(offset=0,total=250,exclusive=false) {return {items:Array.from({length:Math.min(100,Math.max(0,total-offset))},(_,index)=>({...item,id:`event-${offset+index}`,title:`Alert event ${offset+index}`,verdict:"alert"})),limit:100,offset,total,has_more:offset+100<total,from:boundary,to:"2026-10-12T00:00:00Z",lower_only:true,after_exclusive:exclusive};}
it("keeps exact runtime source precision, filtered totals and page history beyond the first 100 events",async()=>{
 vi.mocked(securityTimeline.list).mockImplementation(async params=>exactResponse(params?.offset));
 await render(`/clusters/cluster/timeline?tab=event&after=${encodeURIComponent(boundary)}&verdict=alert,block,quarantine&context=dashboard#proof`);
 await settled(()=>expect(host.textContent).toContain("250 matching event records"));
 expect(securityTimeline.list).toHaveBeenLastCalledWith(expect.objectContaining({type:"runtime_event",after:boundary,verdict:"alert,block,quarantine",offset:0}));
 expect(host.textContent).toContain("no upper time bound");click("Next");
 await settled(()=>expect(host.textContent).toContain("Alert event 199"));
 expect(securityTimeline.list).toHaveBeenLastCalledWith(expect.objectContaining({after:boundary,offset:100}));
 expect(new URLSearchParams(history.location.search).get("context")).toBe("dashboard");expect(history.location.hash).toBe("#proof");
 await act(async()=>history.back());await settled(()=>expect(host.textContent).toContain("Alert event 0"));
 expect(new URLSearchParams(history.location.search).get("after")).toBe(boundary);
});
it("pins a rolling fallback with replace history and preserves strict 14-day semantics",async()=>{
 vi.mocked(securityTimeline.list).mockImplementation(async params=>exactResponse(params?.offset,250,true));
 await render("/clusters/cluster/timeline?tab=event&hours=336&severity=high,critical&after_exclusive=true");
 await settled(()=>expect(new URLSearchParams(history.location.search).get("after")).toBe(boundary));
 expect(history.location.search).not.toContain("hours=");
 await settled(()=>expect(securityTimeline.list).toHaveBeenLastCalledWith(expect.objectContaining({after:boundary,severity:"critical,high",after_exclusive:true})));
 await settled(()=>expect(host.textContent).toContain("Strictly after"));
 click("Next");await settled(()=>expect(new URLSearchParams(history.location.search).get("page")).toBe("2"));
 await act(async()=>history.back());await settled(()=>expect(new URLSearchParams(history.location.search).has("page")).toBe(false));expect(history.location.search).not.toContain("hours=");
});
it.each(["after=garbage","hours=0","hours=2161","hours=24&after=2026-10-10T00:00:00Z","after_exclusive=true","page=10002","verdict=unknown","tab=audit&verdict=alert"])("blocks invalid exact cohort %s without broadening",async filters=>{
 const params=new URLSearchParams(filters);if(!params.has("tab"))params.set("tab","event");await render(`/clusters/cluster/timeline?${params}`);expect(securityTimeline.list).not.toHaveBeenCalled();expect(host.textContent).toContain("Choose valid dates and event filters");
});
it("clears event-only verdicts when switching source tabs and restores the cohort on Back",async()=>{
 vi.mocked(securityTimeline.list).mockImplementation(async params=>({...exactResponse(),items:params?.type==="audit"?[]:exactResponse().items}));
 await render(`/clusters/cluster/timeline?tab=event&after=${encodeURIComponent(boundary)}&verdict=alert,block,quarantine`);
 await settled(()=>expect(host.textContent).toContain("Alert event 0"));act(()=>host.querySelector<HTMLButtonElement>('[data-testid="timeline-category-audit"]')!.click());
 await settled(()=>expect(new URLSearchParams(history.location.search).get("tab")).toBe("audit"));expect(history.location.search).not.toContain("verdict=");
 await act(async()=>history.back());await settled(()=>expect(new URLSearchParams(history.location.search).get("verdict")).toBe("alert,block,quarantine"));
});
it.each(["cluster","boundary"])("rejects wrong %s evidence and disables matching export",async mismatch=>{
 vi.mocked(securityTimeline.list).mockResolvedValue({...exactResponse(),...(mismatch==="cluster"?{items:[{...item,cluster_id:"other"}]}:{from:"2026-10-11T12:34:56.123455Z"})});
 await render(`/clusters/cluster/timeline?tab=event&after=${encodeURIComponent(boundary)}`);
 await settled(()=>expect(host.textContent).toContain("does not match the selected cluster and event window"));expect(host.querySelector('[data-testid="timeline-summary"]')).toBeNull();
 expect(await exportAvailable("Matching events",host)).toBe(false);
});
it("reports full matching export caps and errors, and blocks duplicate requests while downloading",async()=>{
 vi.mocked(securityTimeline.list).mockResolvedValue(exactResponse(200,12000));
 await render(`/clusters/cluster/timeline?tab=event&after=${encodeURIComponent(boundary)}&verdict=alert,block,quarantine&page=3`);
 await settled(()=>expect(host.textContent).toContain("12,000 matching event records"));
 let resolve!: (value:{total:number;exported:number;limit:number;truncated:boolean})=>void;
 vi.mocked(securityTimeline.exportCSV).mockReturnValue(new Promise(done=>{resolve=done;}));
 await chooseExport("Matching events",host);expect(securityTimeline.exportCSV).toHaveBeenCalledTimes(1);expect(await exportAvailable("Matching events",host)).toBe(false);
 expect(securityTimeline.exportCSV).toHaveBeenCalledWith(expect.objectContaining({cluster_id:"cluster",type:"runtime_event",after:boundary,verdict:"alert,block,quarantine"}), expect.any(Function));
 await act(async()=>resolve({total:12000,exported:10000,limit:10000,truncated:true}));
 await settled(()=>expect(host.textContent).toContain("Exported 10,000 of 12,000 matching records"));
 vi.mocked(securityTimeline.exportCSV).mockRejectedValue(new Error("offline"));await chooseExport("Matching events",host);await settled(()=>expect(host.textContent).toContain("Matching event export failed"));expect(host.textContent).toContain("offline");
});
it("does not fetch or export while the cluster registry is invalidated",async()=>{
 client.setQueryData(["clusters"],{clusters:[{id:"cluster"}]});await client.invalidateQueries({queryKey:["clusters"],refetchType:"none"});
 await render(`/clusters/cluster/timeline?tab=event&after=${encodeURIComponent(boundary)}`);expect(securityTimeline.list).not.toHaveBeenCalled();expect(securityTimeline.exportCSV).not.toHaveBeenCalled();
});

it("exports applicable runtime/threat roles and retains one precise lower-bound caption",async()=>{
 vi.mocked(securityTimeline.list).mockResolvedValue({...exactResponse(0,2,true),items:[{...item,platform_role:"core",verdict:"alert"},{...item,id:"unknown",source:"dpi_threat",platform_role:""}]});
 await render(`/clusters/cluster/timeline?tab=custom&type=runtime_event,dpi_threat&after=${encodeURIComponent(boundary)}&after_exclusive=true`);await settled(()=>expect(host.textContent).toContain("Process observed"));
 expect(host.textContent?.match(/Strictly after/g)).toHaveLength(1);await chooseExport("This page",host);const [,headers,rows]=vi.mocked(downloadCsv).mock.calls.at(-1)!;expect(rows.map(row=>row[headers.indexOf("platform_role")])).toEqual(["core",""]);expect(new URLSearchParams(history.location.search).get("after")).toBe(boundary);
});

it("blocks a pending timeline CSV when source refresh completes before its response", async () => {
  let complete!: () => void;
  let guard!: () => boolean;
  vi.mocked(securityTimeline.exportCSV).mockImplementation((_params, shouldDownload) => new Promise(resolve => {
    guard = shouldDownload!;
    complete = () => resolve({ total: 42, exported: 42, limit: 10000, truncated: false });
  }));
  await render("/clusters/cluster/timeline?tab=event");
  await settled(() => expect(host.querySelector('[data-testid="timeline-event-row"]')).not.toBeNull());
  await chooseExport("Matching events", host);
  expect(guard()).toBe(true);
  await act(async () => client.invalidateQueries({ queryKey: ["security-timeline"] }));
  await settled(() => expect(client.isFetching()).toBe(0));
  expect(guard()).toBe(false);
  await act(async () => complete());
  expect(host.textContent).not.toContain("Exported all 42");
});
