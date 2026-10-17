import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { policies, type Policy } from "@/api/client";
import { PolicyFormPage } from "./PolicyFormPage";
const route = vi.hoisted(() => ({ navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ policies: { list: vi.fn(), update: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster" }) }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams("from=admission"), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ policyId: "policy" }), useNavigate: () => route.navigate, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
vi.mock("@monaco-editor/react", () => ({ default: ({ value, onChange }: { value: string; onChange: (value: string) => void }) => <textarea value={value} onChange={(e) => onChange(e.target.value)} /> }));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
const policy: Policy = { id: "policy", name: "Saved policy", description: "", engine: "constellation-admission", category: "admission", enabled: true, mode: "monitor", version: 1, spec_yaml: "rules: []" };
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function renderPage() { host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); await act(async () => root.render(<QueryClientProvider client={client}><PolicyFormPage /></QueryClientProvider>)); }
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
