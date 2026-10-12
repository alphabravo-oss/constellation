import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { enterprise, runtimeEvents, type RuntimeEvent, type RuntimeOverview } from "@/api/client";
import { TestRouter } from "@/test/router";
import { RuntimePage } from "./RuntimePage";

const scope = vi.hoisted(() => ({ available: true, resolvedId: "", loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", async () => {
  const router = await vi.importActual<typeof import("@tanstack/react-router")>("@tanstack/react-router");
  return { useCluster: () => {
    const { id } = router.useParams({ strict: false });
    return { clusterId: id, cluster: scope.available ? { id: scope.resolvedId || id } : undefined, isLoading: scope.loading, error: scope.error };
  } };
});
vi.mock("@/api/client", () => ({ enterprise: { runtime: vi.fn() }, runtimeEvents: { list: vi.fn() } }));
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
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  scope.available = true; scope.resolvedId = ""; scope.loading = false; scope.error = null;
  vi.mocked(enterprise.runtime).mockImplementation(async (params) => overview(params?.cluster_id, params?.hours));
  vi.mocked(runtimeEvents.list).mockImplementation(async (params) => ({ events: [rawEvent(params?.cluster_id)], limit: 100 }));
});
afterEach(() => { act(() => root?.unmount()); host?.remove(); client?.clear(); vi.resetAllMocks(); });
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function render(url = "/clusters/cluster-a/runtime", seed?: (client: QueryClient) => void) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); seed?.(client);
  history = createMemoryHistory({ initialEntries: [url] });
  await rerender();
}
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}><TestRouter path="/clusters/$id/runtime" history={history}><RuntimePage /></TestRouter></QueryClientProvider>)); }
async function tab(label: string) {
  const trigger = [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((item) => item.textContent === label)!;
  await act(async () => trigger.focus());
  await settled(() => expect(trigger.getAttribute('aria-selected')).toBe("true"));
}
async function windowHours(hours: number) {
  await act(async () => { const select = host.querySelector('select')!; select.value = String(hours); select.dispatchEvent(new Event("change", { bubbles: true })); });
}
const summaryValues = () => [...host.querySelectorAll('[data-testid="runtime-summary"] .app-stat-value')].map((item) => item.textContent);

it("shows five authoritative window KPIs and the latest feed as the sole default workspace", async () => {
  await render(); await settled(() => expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());
  expect(summaryValues()).toEqual(["42", "7", "3", "2", "8"]);
  expect(host.querySelector('[data-testid="runtime-summary"]')!.children).toHaveLength(5);
  expect(host.textContent).toContain("7 alerting events in the selected 24h window");
  expect(host.textContent).toContain("Latest 100 reported events"); expect(host.textContent).toContain("not filtered by the evidence time window");
  expect(host.textContent).toContain("cluster-a/raw"); expect(host.textContent).toContain("runtime-agent"); expect(host.textContent).toContain("alert");
  expect(host.querySelector('[data-testid="runtime-subsystems"]')).toBeNull(); expect(host.querySelector('[data-testid="runtime-event-evidence"]')).toBeNull(); expect(host.querySelector('[data-testid="runtime-event-inspector"]')).toBeNull();
  expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 24, cluster_id: "cluster-a" }); expect(runtimeEvents.list).toHaveBeenCalledWith({ limit: 100, cluster_id: "cluster-a" });
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
  expect(host.textContent).toContain("Loading latest runtime events"); expect(host.textContent).not.toContain("No runtime events"); expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});
it("surfaces overview and live errors with retry instead of empty success", async () => {
  vi.mocked(enterprise.runtime).mockRejectedValueOnce(new Error("Overview failed")).mockResolvedValue(overview());
  vi.mocked(runtimeEvents.list).mockRejectedValueOnce(new Error("Feed failed")).mockResolvedValue({ events: [rawEvent()], limit: 100 });
  await render(); await settled(() => expect(host.textContent).toContain("Feed failed")); expect(host.textContent).toContain("Overview failed"); expect(summaryValues()).toEqual(["—", "—", "—", "—", "—"]); expect(host.textContent).not.toContain("No runtime events");
  const retries = [...host.querySelectorAll<HTMLButtonElement>('button')].filter((item) => item.textContent?.startsWith("Retry")); await act(async () => { retries.forEach((button) => button.click()); });
  await settled(() => expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull()); await settled(() => expect(summaryValues()[0]).toBe("42"));
});
it("shows refresh failures even with cached success and stops presenting stale totals as current", async () => {
  await render(); await settled(() => expect(summaryValues()[0]).toBe("42")); vi.mocked(enterprise.runtime).mockRejectedValue(new Error("Overview refresh failed")); vi.mocked(runtimeEvents.list).mockRejectedValue(new Error("Feed refresh failed"));
  await act(async () => { await Promise.all([client.refetchQueries({ queryKey: ["runtime-overview"] }), client.refetchQueries({ queryKey: ["runtime-events-live"] })]); });
  await settled(() => expect(host.textContent).toContain("Overview refresh failed")); expect(host.textContent).toContain("Feed refresh failed"); expect(summaryValues()).toEqual(["—", "—", "—", "—", "—"]); expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});
it("shares hours and workspace through the URL while keeping the live cohort unchanged", async () => {
  await render("/clusters/cluster-a/runtime?hours=6&context=dashboard#evidence"); await settled(() => expect(summaryValues()[0]).toBe("42"));
  expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 6, cluster_id: "cluster-a" }); await windowHours(72); await settled(() => expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 72, cluster_id: "cluster-a" }));
  expect(new URLSearchParams(history.location.search).get("hours")).toBe("72"); expect(history.location.hash).toBe("#evidence"); expect(runtimeEvents.list).toHaveBeenCalledTimes(1);
  await tab("Subsystems"); expect(new URLSearchParams(history.location.search).get("tab")).toBe("subsystems"); expect(new URLSearchParams(history.location.search).get("context")).toBe("dashboard");
  expect(host.textContent).toContain("ready feature does not confirm"); expect(host.querySelector('table')).not.toBeNull(); expect(host.querySelector('details')?.open).toBe(false);
  await act(async () => history.back()); await settled(() => expect(host.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe("Live events"));
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
  await render("/clusters/cluster-a/runtime?tab=evidence&event=foreign-event"); await settled(() => expect(host.textContent).toContain("selected event is not in the loaded cluster"));
  expect(host.querySelector('[data-testid="runtime-event-inspector"]')).toBeNull(); expect(host.textContent).not.toContain("Evidence for foreign-event");
});
it("changes cluster query keys and never renders a late response from the previous cluster", async () => {
  let release!: (value: RuntimeOverview) => void; vi.mocked(enterprise.runtime).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; }));
  await render("/clusters/cluster-a/runtime?tab=evidence&event=event-a"); await settled(() => expect(release).toBeDefined());
  await act(async () => history.push("/clusters/cluster-b/runtime?tab=evidence&event=event-b")); await settled(() => expect(host.querySelector('[data-testid="runtime-event-inspector"]')?.textContent).toContain("cluster-b/api"));
  await act(async () => release(overview("cluster-a"))); expect(host.querySelector('[data-testid="runtime-event-inspector"]')?.textContent).not.toContain("cluster-a/api");
  expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 24, cluster_id: "cluster-b" }); expect(runtimeEvents.list).toHaveBeenCalledWith({ limit: 100, cluster_id: "cluster-b" });
});
it("retains complete workloads and rule evidence behind shared tables with clear response bounds", async () => {
  await render("/clusters/cluster-a/runtime?tab=workloads"); await settled(() => expect(host.querySelector('[data-testid="runtime-workloads"]')?.textContent).toContain("cluster-a/api"));
  expect(host.textContent).toContain("Top 10 workloads"); expect(host.textContent).toContain("T1059"); expect(host.querySelector('table')).not.toBeNull();
  await tab("Rule catalog"); expect(host.textContent).toContain("Shell activity"); expect(host.textContent).toContain("selected 24h window"); expect(host.textContent).toContain("Last triggered");
});
it("uses 24h for malformed hours and rejects mismatched window responses without reporting zero", async () => {
  vi.mocked(enterprise.runtime).mockResolvedValue(overview("cluster-a", 6)); await render("/clusters/cluster-a/runtime?hours=invalid");
  await settled(() => expect(host.textContent).toContain("does not match the selected time window")); expect(enterprise.runtime).toHaveBeenCalledWith({ hours: 24, cluster_id: "cluster-a" }); expect(summaryValues()).toEqual(["—", "—", "—", "—", "—"]);
});

it("retains table rows and focus during a routine poll, then hides them on refresh failure", async () => {
  await render(); await settled(() => expect(host.querySelector('[data-testid="runtime-live-table"]')).not.toBeNull());
  const table = host.querySelector('[data-testid="runtime-live-table"]')!;
  const control = table.querySelector<HTMLButtonElement>('button')!;
  await act(async () => control.focus());
  let fail!: (error: Error) => void; vi.mocked(runtimeEvents.list).mockImplementationOnce(() => new Promise((_, reject) => { fail = reject; })); let refresh!: Promise<void>;
  await act(async () => { refresh = client.refetchQueries({ queryKey: ["runtime-events-live", "cluster-a"] }); });
  await settled(() => expect(host.querySelector('[data-testid="runtime-live-status"]')?.textContent).toBe("Refreshing"));
  expect(host.querySelector('[data-testid="runtime-live-table"]')).toBe(table); expect(host.textContent).toContain("cluster-a/raw"); expect(document.activeElement).toBe(control); expect(summaryValues()[0]).toBe("42");
  await act(async () => { fail(new Error("Poll failed")); await refresh; }); await settled(() => expect(host.textContent).toContain("Poll failed")); expect(host.querySelector('[data-testid="runtime-live-table"]')).toBeNull();
});
