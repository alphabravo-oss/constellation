import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { runtimePolicies, type RuntimePolicy } from "@/api/client";
import { RuntimePolicyFormPage } from "./RuntimePolicyFormPage";

const route = vi.hoisted(() => ({ policyId: "policy", navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ runtimePolicies: { get: vi.fn(), update: vi.fn(), create: vi.fn(), simulate: vi.fn(), generate: vi.fn() } }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ id: "cluster", policyId: route.policyId }), useNavigate: () => route.navigate, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
const policy = { id: "policy", cluster_id: "cluster", workload: "team/app", namespace: "team", name: "Original draft", rules: '[{"id":1,"action":2}]' } as RuntimePolicy;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function renderPage() {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><RuntimePolicyFormPage /></QueryClientProvider>));
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
  expect(runtimePolicies.update).not.toHaveBeenCalled();
});
it("preserves string-encoded rules and the draft across a background refresh", async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy);
  await renderPage();
  await settled(() => expect(host.querySelector("textarea")?.value).toBe(policy.rules));
  expect(host.querySelector("details")?.open).toBe(false);
  await act(async () => { client.setQueryData(["runtime-policy", "policy"], { ...policy, name: "Changed elsewhere", rules: [] }); });
  expect(host.querySelector("textarea")?.value).toBe(policy.rules);
  expect([...host.querySelectorAll("input")].map((input) => input.value)).toContain("Original draft");
});
it("keeps a loaded draft when refreshing the saved policy fails", async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValueOnce(policy).mockRejectedValue(new Error("unavailable"));
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { await client.invalidateQueries({ queryKey: ["runtime-policy", "policy"] }); });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(host.querySelector("textarea")?.value).toBe(policy.rules);
});
it("keeps a failed save on the form without exposing a transport error", async () => {
  vi.mocked(runtimePolicies.get).mockResolvedValue(policy);
  vi.mocked(runtimePolicies.update).mockRejectedValue(new Error("private transport details"));
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Could not save this policy"));
  expect(host.textContent).not.toContain("private transport details");
  expect(route.navigate).not.toHaveBeenCalled();
  expect(runtimePolicies.update).toHaveBeenCalledWith("policy", { name: "Original draft", rules: [{ id: 1, action: 2 }] });
});
