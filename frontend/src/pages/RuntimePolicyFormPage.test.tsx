import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { runtimePolicies, type RuntimePolicy } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { RuntimePolicyFormPage } from "./RuntimePolicyFormPage";

const route = vi.hoisted(() => ({ policyId: "policy", navigate: vi.fn() }));
const scope = vi.hoisted(() => ({ clusterId: "cluster", cluster: { id: "cluster" } as { id: string } | undefined, isLoading: false, error: null as Error | null }));
const operator = { org_id: "org", user_id: "user" };
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({ runtimePolicies: { get: vi.fn(), updateReviewed: vi.fn(), create: vi.fn(), simulate: vi.fn(), generate: vi.fn() } }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ id: "cluster", policyId: route.policyId }), useNavigate: () => route.navigate, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
const policy = { id: "policy", org_id: "org", revision: "1", version: 1, mode: "monitor", def_action: 2, apply_dir: 0, updated_at: "2026-10-12T00:00:00Z", cluster_id: "cluster", workload: "team/app", namespace: "team", name: "Original draft", rules: '[{"id":1,"action":2}]' } as RuntimePolicy;
beforeEach(() => { Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true }); Object.assign(scope, { clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null }); operator.org_id = "org"; operator.user_id = "user"; route.policyId = "policy"; localStorage.clear(); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function renderPage() {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...operator }}><RuntimePolicyFormPage /></TablePreferencesProvider></QueryClientProvider>));
}
async function settled(check: () => void) {
  await vi.waitFor(async () => { await act(async () => {}); check(); });
}
it.each(["failed", "other-cluster"])("does not open a blank editable form for a %s policy", async (scenario) => {
  if (scenario === "failed") vi.mocked(runtimePolicies.get).mockRejectedValue(new Error("unavailable"));
  else vi.mocked(runtimePolicies.get).mockResolvedValue({ ...policy, cluster_id: "other" });
  await renderPage();
  await settled(() => expect(host.textContent).toContain("could not be loaded for the selected cluster"));
  expect(host.querySelector("form")).toBeNull();
  expect(runtimePolicies.updateReviewed).not.toHaveBeenCalled();
});
it("preserves string-encoded rules and the draft across a background refresh", async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy);
  await renderPage();
  await settled(() => expect(host.querySelector("textarea")?.value).toBe(policy.rules));
  expect(host.querySelector("details")?.open).toBe(false);
  await act(async () => { client.setQueryData(["runtime-policy", "org:user", "cluster", "policy"], { ...policy, name: "Changed elsewhere", rules: [] }); });
  expect(host.querySelector("textarea")?.value).toBe(policy.rules);
  expect([...host.querySelectorAll("input")].map((input) => input.value)).toContain("Original draft");
});
it("keeps a loaded draft when refreshing the saved policy fails", async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValueOnce(policy).mockRejectedValue(new Error("unavailable"));
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { await client.invalidateQueries({ queryKey: ["runtime-policy", "org:user", "cluster", "policy"] }); });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(host.querySelector("textarea")?.value).toBe(policy.rules);
});
it("keeps a failed save on the form without exposing a transport error", async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy);
  vi.mocked(runtimePolicies.updateReviewed).mockRejectedValue(new Error("private transport details"));
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Could not save this policy"));
  expect(host.textContent).not.toContain("private transport details");
  expect(route.navigate).not.toHaveBeenCalled();
  expect(runtimePolicies.updateReviewed).toHaveBeenCalledWith("policy", { cluster_id: "cluster", expected_version: "1", name: "Original draft", rules: [{ id: 1, action: 2 }] });
});
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...operator }}><RuntimePolicyFormPage /></TablePreferencesProvider></QueryClientProvider>)); }
const saveButton = () => host.querySelector<HTMLButtonElement>('[data-testid="runtime-policies-editor-save"]')!;
async function submit() { await act(async () => host.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); }
const receipt = (revision = '2'): RuntimePolicy => ({ ...policy, rules: JSON.parse(policy.rules as string), revision, version: Number(revision) });
it('saves against actual reviewed cluster/revision on the fail-closed endpoint and returns to its scope', async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy); vi.mocked(runtimePolicies.updateReviewed).mockResolvedValue(receipt()); await renderPage(); await settled(() => expect(saveButton()).not.toBeNull()); await submit(); await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: '/clusters/cluster/runtime-policies' })); expect(runtimePolicies.updateReviewed).toHaveBeenCalledWith('policy', { cluster_id: 'cluster', expected_version: '1', name: policy.name, rules: JSON.parse(policy.rules as string) });
});
it.each(['loading', 'foreign', 'error', 'empty-owner'])('blocks initial authoring for %s scope', async reason => {
  if (reason === 'loading') scope.isLoading = true; if (reason === 'foreign') scope.cluster = { id: 'foreign' }; if (reason === 'error') scope.error = new Error('private scope detail'); if (reason === 'empty-owner') operator.org_id = ''; await renderPage(); expect(runtimePolicies.get).not.toHaveBeenCalled(); expect(host.querySelector('form')).toBeNull(); expect(runtimePolicies.updateReviewed).not.toHaveBeenCalled();
});
it('retains the draft but pauses Save during refresh and after a failed refresh until explicit review succeeds', async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy); await renderPage(); await settled(() => expect(saveButton().disabled).toBe(false)); let reject!: (error: Error) => void; vi.mocked(runtimePolicies.get).mockImplementationOnce(() => new Promise((_done, fail) => { reject = fail; }));
  await act(async () => { void client.invalidateQueries({ queryKey: ['runtime-policy'] }); }); await settled(() => expect(saveButton().disabled).toBe(true)); await submit(); expect(runtimePolicies.updateReviewed).not.toHaveBeenCalled(); await act(async () => reject(new Error('private read failure'))); await settled(() => expect(host.textContent).toContain('actions are paused')); expect(host.querySelector('textarea')?.value).toBe(policy.rules);
  await act(async () => [...host.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent === 'Refresh policy')!.click()); await settled(() => expect(saveButton().disabled).toBe(false)); expect(host.querySelector('textarea')?.value).toBe(policy.rules);
});
it('keeps a changed saved revision separate from the retained draft until explicitly reviewed', async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy); await renderPage(); await settled(() => expect(saveButton().disabled).toBe(false)); const latest = { ...receipt('3'), name: 'Current server name', rules: [] }; vi.mocked(runtimePolicies.get).mockResolvedValue(latest);
  await act(async () => { await client.invalidateQueries({ queryKey: ['runtime-policy'] }); }); await settled(() => expect(host.textContent).toContain('The saved policy changed')); expect(saveButton().disabled).toBe(true); await submit(); expect(runtimePolicies.updateReviewed).not.toHaveBeenCalled();
  await act(async () => [...host.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent === 'Review latest policy')!.click()); await settled(() => expect(saveButton().disabled).toBe(false)); expect(host.querySelector('textarea')?.value).toBe(policy.rules); expect(host.textContent).toContain('revision 3'); expect(host.textContent).toContain('Current server name');
  vi.mocked(runtimePolicies.updateReviewed).mockResolvedValue(receipt('4')); await submit(); await settled(() => expect(runtimePolicies.updateReviewed).toHaveBeenCalled()); expect(runtimePolicies.updateReviewed).toHaveBeenLastCalledWith('policy', expect.objectContaining({ expected_version: '3', name: policy.name }));
});
it('blocks a cached write invalidated before React observer notification', async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy); await renderPage(); await settled(() => expect(saveButton().disabled).toBe(false)); await act(async () => { client.getQueryCache().find({ queryKey: ['runtime-policy', 'org:user', 'cluster', 'policy'], exact: true })!.setState({ isInvalidated: true }); host.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); }); expect(runtimePolicies.updateReviewed).not.toHaveBeenCalled();
});
it('holds a stale CAS failure until current policy is explicitly fetched and reviewed', async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy); vi.mocked(runtimePolicies.updateReviewed).mockRejectedValueOnce({ response: { status: 409 } }); await renderPage(); await settled(() => expect(saveButton().disabled).toBe(false)); await submit(); await settled(() => expect(saveButton().disabled).toBe(true)); await submit(); expect(runtimePolicies.updateReviewed).toHaveBeenCalledOnce();
  vi.mocked(runtimePolicies.get).mockResolvedValue(receipt('3')); await act(async () => [...host.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent === 'Review latest policy')!.click()); await settled(() => expect(saveButton().disabled).toBe(false)); expect(host.querySelector('textarea')?.value).toBe(policy.rules);
});
it('prevents duplicate authoring after a successful response arrives through an invalidated/recovered source', async () => {
  let resolve!: (value: RuntimePolicy) => void; vi.mocked(runtimePolicies.get).mockResolvedValue(policy); vi.mocked(runtimePolicies.updateReviewed).mockImplementationOnce(() => new Promise(done => { resolve = done; })); await renderPage(); await settled(() => expect(saveButton().disabled).toBe(false)); await submit(); await settled(() => expect(runtimePolicies.updateReviewed).toHaveBeenCalledOnce()); await act(async () => { await client.invalidateQueries({ queryKey: ['runtime-policy'] }); }); await act(async () => resolve(receipt())); await settled(() => expect(host.textContent).toContain('Reload before another write')); expect(saveButton().disabled).toBe(true); await submit(); expect(runtimePolicies.updateReviewed).toHaveBeenCalledOnce(); expect(route.navigate).not.toHaveBeenCalled();
});
it('cannot redirect a later operator after a pending write returns', async () => {
  let resolve!: (value: RuntimePolicy) => void; vi.mocked(runtimePolicies.get).mockResolvedValue(policy); vi.mocked(runtimePolicies.updateReviewed).mockImplementationOnce(() => new Promise(done => { resolve = done; })); await renderPage(); await settled(() => expect(saveButton().disabled).toBe(false)); await submit(); await settled(() => expect(runtimePolicies.updateReviewed).toHaveBeenCalledOnce()); operator.user_id = 'other'; await rerender(); await settled(() => expect(host.querySelector('textarea')).not.toBeNull()); await act(async () => resolve(receipt())); expect(route.navigate).not.toHaveBeenCalled(); expect(saveButton().disabled).toBe(false);
});
it.each(['cluster', 'rules', 'revision'])('refuses an unconfirmed %s write receipt and keeps its draft', async field => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy); const value = receipt(); if (field === 'cluster') value.cluster_id = 'foreign'; if (field === 'rules') value.rules = []; if (field === 'revision') value.revision = '1'; vi.mocked(runtimePolicies.updateReviewed).mockResolvedValue(value); await renderPage(); await settled(() => expect(saveButton().disabled).toBe(false)); await submit(); await settled(() => expect(host.textContent).toContain('Reload before another write')); expect(route.navigate).not.toHaveBeenCalled(); expect(saveButton().disabled).toBe(true); expect(host.querySelector('textarea')?.value).toBe(policy.rules);
});
