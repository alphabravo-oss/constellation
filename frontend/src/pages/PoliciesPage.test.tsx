import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { policies, type Policy } from "@/api/client";
import { PoliciesPage } from "./PoliciesPage";
import { TestRouter } from "@/test/router";
const cluster = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster" } as { id: string } | undefined, isLoading: false }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => cluster }));
vi.mock("@/api/client", () => ({ policies: { list: vi.fn(), update: vi.fn(), simulate: vi.fn() } }));
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const policy: Policy = { id: "policy", name: "Policy one", description: "An admission policy", category: "security", engine: "admission", mode: "monitor", enabled: true, version: 1, spec_yaml: "" };
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => { cluster.clusterId = "cluster"; cluster.cluster = { id: "cluster" }; cluster.isLoading = false; vi.mocked(policies.list).mockResolvedValue({ policies: [policy] }); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); localStorage.clear(); });
async function renderPage(search = "") {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); history = createMemoryHistory({ initialEntries: [`/clusters/cluster/policies${search}`] });
  await act(async () => root.render(<QueryClientProvider client={client}><TestRouter history={history} next={{ path: "/clusters/cluster/admission/import", element: <div>Import route</div> }}><PoliciesPage /></TestRouter></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
function button(label: string) { return [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === label)!; }
it.each(["loading", "missing"])("does not query policy data for a %s cluster", async (scenario) => {
  if (scenario === "loading") cluster.isLoading = true; else { cluster.clusterId = undefined; cluster.cluster = undefined; }
  await renderPage(); await settled(() => expect(host.querySelector("table")).toBeNull()); expect(policies.list).not.toHaveBeenCalled();
});
it("shows a retry error when the policy query fails", async () => {
  vi.mocked(policies.list).mockRejectedValue(new Error("private transport")); await renderPage(); await settled(() => expect(host.textContent).toContain("Could not load policies for this cluster")); expect(host.textContent).not.toContain("No policies"); expect(host.textContent).not.toContain("private transport"); expect(button("Retry")).toBeTruthy();
});
it("makes every loaded policy accessible using the shared table pagination", async () => {
  vi.mocked(policies.list).mockResolvedValue({ policies: Array.from({ length: 105 }, (_, i) => ({ ...policy, id: `policy-${i}`, name: `Policy ${i}` })) });
  await renderPage(); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(100)); await act(async () => button("Next").click()); expect(host.textContent).toContain("Policy 104"); expect(host.querySelectorAll("tbody tr")).toHaveLength(5); expect(host.querySelector('[aria-label="Export CSV"]')).not.toBeNull();
});
it("opens dedicated edit forms without autosaving policy status", async () => {
  await renderPage(); await settled(() => expect(host.textContent).toContain("Policy one")); expect(host.querySelector('input[type="checkbox"]')).toBeNull(); expect(host.textContent).toContain("They do not confirm enforcement");
  await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="Edit policy Policy one"]')!.click()); await settled(() => expect(history.location.pathname).toBe("/clusters/cluster/policies/policy")); expect(policies.update).not.toHaveBeenCalled();
});
it("redirects legacy profile tab links to the canonical import route", async () => {
  await renderPage("?tab=profiles&source=bundle&mode=monitor"); await settled(() => expect(history.location.pathname).toBe("/clusters/cluster/admission/import")); expect(new URLSearchParams(history.location.search).get("source")).toBe("bundle"); expect(new URLSearchParams(history.location.search).get("mode")).toBe("monitor"); expect(policies.list).not.toHaveBeenCalled();
});
it("preserves the simulator manifest after a failed review", async () => {
  vi.mocked(policies.simulate).mockRejectedValue(new Error("private")); await renderPage("?tab=simulator"); await settled(() => expect(host.querySelector("textarea")).not.toBeNull()); const manifest = host.querySelector("textarea")!.value; await act(async () => button("Run dry-run admission review").click()); await settled(() => expect(host.textContent).toContain("Your manifest is preserved")); expect(host.querySelector("textarea")?.value).toBe(manifest); expect(host.textContent).not.toContain("private"); expect(policies.simulate).toHaveBeenCalledWith({ manifest }, { cluster_id: "cluster" });
});
