import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { policies, type Policy } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { PolicyFormPage } from "./PolicyFormPage";
const route = vi.hoisted(() => ({ navigate: vi.fn(), clusterId: "cluster", policyId: "policy" }));
vi.mock("@/api/client", () => ({ policies: { list: vi.fn(), update: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId }) }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams("from=admission"), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ policyId: route.policyId }), useNavigate: () => route.navigate, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
vi.mock("@monaco-editor/react", () => ({ default: ({ value, onChange }: { value: string; onChange: (value: string) => void }) => <textarea value={value} onChange={(e) => onChange(e.target.value)} /> }));
let owner = { org_id: "org", user_id: "user" };
let root: Root; let host: HTMLDivElement; let client: QueryClient;
const policy: Policy = { id: "policy", name: "Saved policy", description: "", engine: "constellation-admission", category: "admission", enabled: true, mode: "monitor", version: 1, spec_yaml: "rules: []" };
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  owner = { org_id: "org", user_id: "user" }; route.clusterId = "cluster"; route.policyId = "policy";
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function renderPage() { host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); await rerenderPage(); }
async function rerenderPage(show = true) { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...owner }}>{show ? <PolicyFormPage /> : <p>Outside policy editor</p>}</TablePreferencesProvider></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
it("blocks a failed policy load", async () => { vi.mocked(policies.list).mockRejectedValue(new Error("private")); await renderPage(); await settled(() => expect(host.textContent).toContain("could not be loaded for the selected cluster")); expect(host.querySelector("form")).toBeNull(); });
it("stages mode with YAML until Save and preserves the draft through refresh", async () => {
  vi.mocked(policies.list).mockResolvedValue({ policies: [policy] }); vi.mocked(policies.update).mockResolvedValue({ ...policy, mode: "enforce" });
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(host.querySelector("details")?.open).toBe(false);
  await act(async () => { const select = host.querySelector("select")!; select.value = "enforce"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  expect(policies.update).not.toHaveBeenCalled();
  await act(async () => { client.setQueryData(["policy-editor", "cluster", "policy"], { policies: [{ ...policy, spec_yaml: "changed remotely" }] }); });
  expect(host.querySelector("textarea")?.value).toBe("rules: []");
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/admission" }));
  expect(policies.update).toHaveBeenCalledWith("policy", { mode: "enforce", spec_yaml: "rules: []" });
});

async function beginHeldPolicyWrite() {
  let complete!: (value: Policy) => void;
  vi.mocked(policies.list).mockResolvedValue({ policies: [policy, { ...policy, id: "other", name: "Other policy", spec_yaml: "rules: other" }] });
  vi.mocked(policies.update).mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { const select = host.querySelector("select")!; select.value = "enforce"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
  await settled(() => { expect(policies.update).toHaveBeenCalledTimes(1); expect(client.isMutating()).toBe(1); });
  expect(policies.update).toHaveBeenCalledWith("policy", { mode: "enforce", spec_yaml: "rules: []" });
  return () => complete({ ...policy, mode: "enforce" });
}
async function newPolicyDraft(value: string) {
  await settled(() => expect(host.querySelector("textarea")?.value).toBe("rules: []"));
  await act(async () => {
    const input = host.querySelector("textarea")!;
    Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  expect(host.querySelector("textarea")?.value).toBe(value);
}
async function finishPolicyWrite(complete: () => void) {
  await act(async () => complete());
  await settled(() => expect(client.isMutating()).toBe(0));
}

it("keeps a later policy draft after a held write completes across a target roundtrip", async () => {
  const complete = await beginHeldPolicyWrite();
  route.policyId = "other"; await rerenderPage();
  await settled(() => expect(host.querySelector("textarea")?.value).toBe("rules: other"));
  route.policyId = "policy"; await rerenderPage(); await newPolicyDraft("rules: [later target visit]");
  await finishPolicyWrite(complete);
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.querySelector("textarea")?.value).toBe("rules: [later target visit]");
  expect(policies.update).toHaveBeenCalledTimes(1);
});

it("keeps a later policy draft after a held write completes across an owner roundtrip", async () => {
  const complete = await beginHeldPolicyWrite();
  owner = { org_id: "other-org", user_id: "other-user" }; await rerenderPage();
  await settled(() => expect(host.querySelector("textarea")?.value).toBe("rules: []"));
  owner = { org_id: "org", user_id: "user" }; await rerenderPage(); await newPolicyDraft("rules: [later owner visit]");
  await finishPolicyWrite(complete);
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.querySelector("textarea")?.value).toBe("rules: [later owner visit]");
  expect(policies.update).toHaveBeenCalledTimes(1);
});

it("does not navigate after leaving a pending policy editor and retains safe invalidations", async () => {
  const complete = await beginHeldPolicyWrite();
  const invalidate = vi.spyOn(client, "invalidateQueries");
  await rerenderPage(false); await finishPolicyWrite(complete);
  expect(host.textContent).toBe("Outside policy editor");
  expect(route.navigate).not.toHaveBeenCalled();
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["policies"] });
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["admission-rules"] });
});
