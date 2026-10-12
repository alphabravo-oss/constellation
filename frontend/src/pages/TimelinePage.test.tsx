import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { securityTimeline, type TimelineItem } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import { TestRouter } from "@/test/router";
import { TimelinePage } from "./TimelinePage";

const scope = vi.hoisted(() => ({ clusterId: "cluster", cluster: { id: "cluster", name: "Primary" }, isLoading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({ securityTimeline: { list: vi.fn() } }));
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
  vi.mocked(securityTimeline.list).mockResolvedValue(response);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); });
async function render(url = "/clusters/cluster/timeline") {
  history = createMemoryHistory({ initialEntries: [url] });
  await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ org_id: "org", user_id: "user" }}><TestRouter history={history}><TimelinePage /></TestRouter></TablePreferencesProvider></QueryClientProvider>));
  await act(async () => new Promise(resolve => setTimeout(resolve, 20)));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
function click(label: string) { const button = [...host.querySelectorAll("button")].find(el => el.textContent?.trim() === label)!; act(() => button.click()); }

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
  const apply = [...host.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent?.startsWith("Named investigation"))!; await act(async () => apply.click());
  await settled(() => expect(securityTimeline.list).toHaveBeenLastCalledWith(expect.objectContaining({ type: "runtime_event", severity: "high", q: "api", namespace: "prod", workload: "web", ref: "rule", from: "2026-10-10T00:00:00.000Z", to: "2026-10-12T00:00:00.000Z", offset: 0 })));
});
it("retains ISO timestamp offsets and milliseconds when applying a saved view", async () => {
  const from = "2026-10-10T12:34:56.789+05:30"; const to = "2026-10-10T12:35:01.123+05:30";
  const key = operatorStorageKey("constellation.timeline.views.v1", { org_id: "org", user_id: "user" })!;
  localStorage.setItem(key, JSON.stringify([{ id: "precise", name: "Exact interval", category: "audit", sources: ["audit"], severities: [], query: "", namespace: "", workload: "", reference: "", from, to }]));
  await render(); click("Views (1)");
  const apply = [...host.querySelectorAll<HTMLButtonElement>("button")].find(button => button.textContent?.startsWith("Exact interval"))!;
  await act(async () => apply.click());
  await settled(() => expect(securityTimeline.list).toHaveBeenLastCalledWith(expect.objectContaining({ type: "audit", from: "2026-10-10T07:04:56.789Z", to: "2026-10-10T07:05:01.123Z" })));
  const params = new URLSearchParams(history.location.search); expect(params.get("from")).toBe(from); expect(params.get("to")).toBe(to);
});
