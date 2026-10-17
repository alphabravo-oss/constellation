import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { NetworkPcapFormPage } from "./NetworkPcapFormPage";
const scope = vi.hoisted(() => ({ id: "cluster" as string | undefined, resolved: "cluster" as string | undefined, loading: false, error: null as Error | null }));
const mocks = vi.hoisted(() => ({ map: vi.fn(), start: vi.fn() }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: scope.id, cluster: scope.resolved ? { id: scope.resolved } : undefined, isLoading: scope.loading, error: scope.error }) }));
vi.mock("@/api/client", () => ({ network: { map: mocks.map }, runtimePcap: { start: mocks.start } }));
const map = () => ({ summary: { selected_cluster_id: "cluster" }, workloads: [{ id: "prod/api", cluster_id: "cluster", namespace: "prod", name: "api", kind: "Deployment" }] });
let identity: { org_id: string; user_id: string } | null;
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => { (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; identity = { org_id: "org", user_id: "user" }; mocks.map.mockResolvedValue(map()); mocks.start.mockResolvedValue({ id: "capture", cluster_id: "cluster", workload: "prod/api", status: "pending" }); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.restoreAllMocks(); vi.clearAllMocks(); scope.id = "cluster"; scope.resolved = "cluster"; scope.loading = false; scope.error = null; });
async function renderPage(search = "?workload=prod%2Fapi&context=keep#proof") {
  host = document.createElement("div"); document.body.append(host); root = createRoot(host); history = createMemoryHistory({ initialEntries: [`/clusters/cluster/network/pcap/new${search}`] }); client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); await rerender();
}
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity ? { ...identity } : null}><TestRouter history={history}><NetworkPcapFormPage /></TestRouter></TablePreferencesProvider></QueryClientProvider>)); }
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
const submitButton = () => host.querySelector<HTMLButtonElement>('button[type="submit"]')!;
async function field(id: string, value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement>(`#capture-${id}`)!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function submit() { await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }
it("queues an exact resolved workload with honest pending feedback and prevents repeat submission", async () => {
  await renderPage(); await settle(() => expect(submitButton().disabled).toBe(false)); expect(host.querySelector("details")!.open).toBe(false);
  await act(async () => { const form = host.querySelector("form")!; form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  expect(mocks.map).toHaveBeenCalledWith({ cluster_id: "cluster", hours: 24 }); expect(mocks.start).toHaveBeenCalledTimes(1); expect(mocks.start).toHaveBeenCalledWith(expect.objectContaining({ cluster_id: "cluster", workload: "prod/api", namespace: "prod", duration_s: 30, file_count: 1 }));
  await settle(() => expect(host.textContent).toContain("Status: pending")); expect(host.textContent).toContain("agent must claim and complete"); expect(submitButton().disabled).toBe(true); expect(host.querySelector('a')!.getAttribute('href')).toBe('/clusters/cluster/network?workload=prod%2Fapi&context=keep&tab=pcap#proof');
});
it.each([['duration', '0'], ['duration', '301'], ['duration', '5.5'], ['src', '999.1.2.3'], ['dst', 'not-ip'], ['port', '65536'], ['files', '21'], ['iface', 'bad interface'], ['bpf', 'tcp; rm']])("rejects invalid %s without sending capture", async (key, value) => {
  await renderPage(); await settle(() => expect(submitButton().disabled).toBe(false)); await field(key, value); await submit(); expect(mocks.start).not.toHaveBeenCalled(); expect(submitButton().disabled).toBe(true);
});
it("does not silently shrink rolling capture limits", async () => {
  await renderPage(); await settle(() => expect(submitButton().disabled).toBe(false)); await field('files', '20'); await field('size', '10'); await submit(); expect(mocks.start).not.toHaveBeenCalled(); expect(host.textContent).toContain('total no more than 100 MB'); await field('size', '5'); await submit(); expect(mocks.start).toHaveBeenCalledWith(expect.objectContaining({ file_count: 20, file_size_mb: 5 }));
});
it.each(['unresolved', 'foreign', 'session', 'error'])("blocks %s cluster context before fetching targets or sending capture", async condition => {
  if (condition === 'unresolved') scope.resolved = undefined; if (condition === 'foreign') scope.resolved = 'foreign'; if (condition === 'session') identity = null; if (condition === 'error') scope.error = new Error('scope failed');
  await renderPage(); await submit(); expect(mocks.map).not.toHaveBeenCalled(); expect(mocks.start).not.toHaveBeenCalled();
});
it.each(['wrong-cluster', 'missing', 'duplicate'])("rejects %s workload evidence", async condition => {
  const data = map(); if (condition === 'wrong-cluster') data.summary.selected_cluster_id = 'foreign'; if (condition === 'missing') data.workloads = []; if (condition === 'duplicate') data.workloads.push(data.workloads[0]); mocks.map.mockResolvedValue(data);
  await renderPage(); await settle(() => expect(mocks.map).toHaveBeenCalled()); await submit(); expect(mocks.start).not.toHaveBeenCalled();
});
it("rechecks cached target evidence synchronously before mutation", async () => {
  await renderPage(); await settle(() => expect(submitButton().disabled).toBe(false)); await act(async () => { client.setQueryData(['pcap-form-workloads', 'cluster'], { summary: { selected_cluster_id: 'foreign' }, workloads: [] }); host.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); }); expect(mocks.start).not.toHaveBeenCalled();
});
it("preserves the draft after refresh failure and failed request", async () => {
  await renderPage(); await settle(() => expect(submitButton().disabled).toBe(false)); await field('duration', '40'); mocks.start.mockRejectedValueOnce(new Error('request failed')); await submit(); await settle(() => expect(host.textContent).toContain('draft is preserved')); expect(host.querySelector<HTMLInputElement>('#capture-duration')!.value).toBe('40');
  scope.error = new Error('refresh failed'); await rerender(); expect(submitButton().disabled).toBe(true); expect(host.querySelector<HTMLInputElement>('#capture-duration')!.value).toBe('40'); scope.error = null; await rerender(); await settle(() => expect(submitButton().disabled).toBe(false)); await submit(); expect(mocks.start).toHaveBeenCalledTimes(2);
});
it("does not label a mismatched response as a matching capture", async () => {
  mocks.start.mockResolvedValue({ id: 'foreign', cluster_id: 'foreign', workload: 'prod/api', status: 'running' }); await renderPage(); await settle(() => expect(submitButton().disabled).toBe(false)); await submit(); await settle(() => expect(host.textContent).toContain('unexpected capture identity')); expect(submitButton().disabled).toBe(true);
});
it("resets a draft after owner change", async () => { await renderPage(); await field('duration', '90'); identity = { org_id: 'other', user_id: 'other' }; await rerender(); expect(host.querySelector<HTMLInputElement>('#capture-duration')!.value).toBe('30'); expect(mocks.start).not.toHaveBeenCalled(); });

it("blocks malformed carried filters instead of requesting a broader capture", async () => { await renderPage('?workload=prod%2Fapi&network_view=bad'); await settle(() => expect(mocks.map).toHaveBeenCalled()); await submit(); expect(mocks.start).not.toHaveBeenCalled(); expect(submitButton().disabled).toBe(true); expect(host.textContent).toContain('capture context is invalid'); });
