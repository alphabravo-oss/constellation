import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { runtimePolicies, type RuntimePolicy } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { RuntimePoliciesPage } from "./RuntimePoliciesPage";

const scope = vi.hoisted(() => ({ clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({ runtimePolicies: { list: vi.fn(), matchStats: vi.fn(), promoteReviewed: vi.fn(), demoteReviewed: vi.fn(), removeReviewed: vi.fn() } }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ id: "cluster" }), useNavigate: () => vi.fn() }));
const identity = { org_id: "org", user_id: "user" };
const policy = { id: "policy", name: "Policy", workload: "team/app", namespace: "team", org_id: "org", cluster_id: "cluster", revision: "1", version: 1, mode: "enforce", rules: [], updated_at: "2026-10-12T00:00:00Z" } as unknown as RuntimePolicy;
beforeEach(() => { Object.assign(scope, { clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null }); identity.user_id = "user"; });
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function mountPage() {
  await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...identity }}><RuntimePoliciesPage /></TablePreferencesProvider></QueryClientProvider>));
}
async function renderPage(mode: "monitor" | "enforce" | "disabled", expectRow = true, overrides: Partial<RuntimePolicy> = {}) {
  vi.mocked(runtimePolicies.list).mockResolvedValue([{ id: "policy", name: "Policy", workload: "team/app", namespace: "team", org_id: "org", cluster_id: "cluster", revision: "1", version: 1, mode, rules: [], updated_at: "2026-10-12T00:00:00Z", ...overrides } as unknown as RuntimePolicy]);
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await mountPage();
  if (expectRow) await vi.waitFor(async () => { await act(async () => {}); expect(host.querySelector('[data-testid="runtime-policy-row-policy"]')).not.toBeNull(); });
}
it("blocks promotion when its match preview fails and shows a retry action", async () => {
  vi.mocked(runtimePolicies.matchStats).mockRejectedValue(new Error("unavailable"));
  await renderPage("monitor");
  await act(async () => { host.querySelector<HTMLButtonElement>('[data-testid="runtime-policy-promote-policy"]')!.click(); });
  await vi.waitFor(async () => { await act(async () => {}); expect(document.body.textContent).toContain("Match preview could not be loaded"); });
  expect(document.querySelector<HTMLButtonElement>('[data-testid="runtime-policy-promote-confirm"]')?.disabled).toBe(true);
  expect(document.body.textContent).toContain("Retry preview");
  expect(runtimePolicies.promoteReviewed).not.toHaveBeenCalled();
});
it("shows a demotion failure instead of silently leaving the row unchanged", async () => {
  vi.mocked(runtimePolicies.demoteReviewed).mockRejectedValue(new Error("private transport details"));
  await renderPage("enforce");
  await act(async () => { host.querySelector<HTMLButtonElement>('[data-testid="runtime-policy-demote-policy"]')!.click(); });
  await vi.waitFor(async () => { await act(async () => {}); expect(host.textContent).toContain("Action failed"); });
  expect(host.textContent).not.toContain("private transport details");
});

const rowKey = ["runtime-policies", "org:user", "cluster"];
async function settle(assertion: () => void) { await vi.waitFor(async () => { await act(async () => {}); assertion(); }, { timeout: 3000 }); }
function button(id: string) { return host.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`)!; }
it.each(["loading", "missing", "mismatch", "error"])("does not query or enable policy actions for %s cluster scope", async state => {
  if (state === "loading") scope.isLoading = true;
  if (state === "missing") scope.cluster = null as unknown as typeof scope.cluster;
  if (state === "mismatch") scope.cluster = { id: "other" };
  if (state === "error") scope.error = new Error("private") as unknown as typeof scope.error;
  await renderPage("enforce", false);
  expect(runtimePolicies.list).not.toHaveBeenCalled();
  expect(host.textContent).toContain("Retry cluster");
  expect(host.querySelector('[data-testid="runtime-policies-new"]')).toBeNull();
});
it("hides cached policies on failed refresh and enables actions only after successful recovery", async () => {
  await renderPage("enforce");
  vi.mocked(runtimePolicies.list).mockRejectedValueOnce(new Error("private"));
  await act(async () => { await client.refetchQueries({ queryKey: rowKey, exact: true }); });
  await settle(() => expect(host.textContent).toContain("could not be loaded or refreshed"));
  expect(host.querySelector('[data-testid="runtime-policy-row-policy"]')).toBeNull();
  expect(button("runtime-policies-new").disabled).toBe(true);
  await act(async () => { await client.refetchQueries({ queryKey: rowKey, exact: true }); });
  await settle(() => expect(button("runtime-policy-demote-policy").disabled).toBe(false));
});
it("blocks invalidated evidence before React rerenders", async () => {
  await renderPage("enforce");
  await act(async () => { await client.invalidateQueries({ queryKey: rowKey, exact: true, refetchType: "none" }); button("runtime-policy-demote-policy").click(); });
  expect(runtimePolicies.demoteReviewed).not.toHaveBeenCalled();
});
it("sends actual reviewed revision for demotion", async () => {
  await renderPage("enforce");
  vi.mocked(runtimePolicies.demoteReviewed).mockResolvedValue({ ...policy, mode: "monitor", revision: "2", version: 2 });
  await act(async () => button("runtime-policy-demote-policy").click());
  await settle(() => expect(runtimePolicies.demoteReviewed).toHaveBeenCalledWith("policy", { cluster_id: "cluster", expected_version: "1" }));
  expect(host.textContent).not.toContain("could not be confirmed");
});
it("blocks duplicate demotion after foreign response", async () => {
  await renderPage("enforce");
  vi.mocked(runtimePolicies.demoteReviewed).mockResolvedValue({ ...policy, mode: "monitor", revision: "2", cluster_id: "foreign" });
  await act(async () => button("runtime-policy-demote-policy").click());
  await settle(() => expect(host.textContent).toContain("Reload before another write"));
  expect(button("runtime-policy-demote-policy").disabled).toBe(true);
});
it("blocks pending response after invalidate-to-ready", async () => {
  await renderPage("enforce");
  let resolve!: (value: RuntimePolicy) => void;
  vi.mocked(runtimePolicies.demoteReviewed).mockImplementation(() => new Promise(done => { resolve = done; }));
  await act(async () => button("runtime-policy-demote-policy").click());
  await act(async () => { await client.invalidateQueries({ queryKey: rowKey, exact: true, refetchType: "none" }); client.setQueryData(rowKey, [{ ...policy }]); });
  await act(async () => resolve({ ...policy, mode: "monitor", revision: "2", version: 2 }));
  await settle(() => expect(host.textContent).toContain("Reload before another write"));
  expect(button("runtime-policy-demote-policy").disabled).toBe(true);
});
it("does not retain another operator's rows while their source is pending", async () => {
  await renderPage("enforce");
  vi.mocked(runtimePolicies.list).mockImplementation(() => new Promise(() => {}));
  identity.user_id = "next";
  await mountPage();
  expect(host.querySelector('[data-testid="runtime-policy-row-policy"]')).toBeNull();
  expect(button("runtime-policies-new").disabled).toBe(true);
  expect(client.getQueryState(["runtime-policies", "org:next", "cluster"])).toBeDefined();
});


it("re-enables a disabled policy in monitor mode using its exact decimal reviewed revision", async () => {
  const reviewed = { ...policy, mode: "disabled" as const, revision: "9007199254740993" };
  const receipt = { ...reviewed, mode: "monitor" as const, revision: "9007199254740994" };
  await renderPage("disabled", true, reviewed);
  vi.mocked(runtimePolicies.demoteReviewed).mockImplementation(async () => {
    vi.mocked(runtimePolicies.list).mockResolvedValue([receipt]);
    return receipt;
  });
  expect(button("runtime-policy-enable-policy").textContent).toBe("Enable in monitor mode");
  expect(host.querySelector('[data-testid="runtime-policy-promote-policy"]')).toBeNull();
  await act(async () => button("runtime-policy-enable-policy").click());
  await settle(() => expect(button("runtime-policy-promote-policy")?.disabled).toBe(false));
  expect(runtimePolicies.demoteReviewed).toHaveBeenCalledExactlyOnceWith("policy", { cluster_id: "cluster", expected_version: "9007199254740993" });
  expect(host.querySelector('[data-testid="runtime-policy-enable-policy"]')).toBeNull();
  expect(host.textContent).not.toContain("could not be confirmed");
  expect(runtimePolicies.promoteReviewed).not.toHaveBeenCalled();
});

it.each(["wrong-mode", "unchanged-revision", "foreign-cluster"])("does not confirm a disabled-policy re-enable with a %s receipt", async mismatch => {
  await renderPage("disabled");
  vi.mocked(runtimePolicies.demoteReviewed).mockResolvedValue({ ...policy, mode: mismatch === "wrong-mode" ? "enforce" : "monitor", revision: mismatch === "unchanged-revision" ? "1" : "2", cluster_id: mismatch === "foreign-cluster" ? "foreign" : "cluster" });
  await act(async () => button("runtime-policy-enable-policy").click());
  await settle(() => expect(host.textContent).toContain("Reload before another write"));
  expect(button("runtime-policy-enable-policy").disabled).toBe(true);
  await act(async () => button("runtime-policy-enable-policy").click());
  expect(runtimePolicies.demoteReviewed).toHaveBeenCalledOnce();
});

it("blocks re-enabling a disabled policy when its reviewed evidence invalidates before render", async () => {
  await renderPage("disabled");
  await act(async () => {
    await client.invalidateQueries({ queryKey: rowKey, exact: true, refetchType: "none" });
    button("runtime-policy-enable-policy").click();
  });
  expect(runtimePolicies.demoteReviewed).not.toHaveBeenCalled();
});
