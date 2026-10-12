import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { fileProfiles, type FileProfileDetail, type FileProfileRule } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { FileMonitorPage } from "./FileMonitorPage";
import { FileMonitorFormPage } from "./FileMonitorFormPage";

const route = vi.hoisted(() => ({ ruleId: undefined as string | undefined, search: "workload=workload", navigate: vi.fn(), setParams: vi.fn(), clusterId: "cluster" as string | undefined, cluster: { id: "cluster" } as { id: string } | undefined, loading: false }));
vi.mock("@/api/client", () => ({ fileProfiles: { get: vi.fn(), list: vi.fn(), inventory: vi.fn(), inventoryCSV: vi.fn(), createRule: vi.fn(), updateRule: vi.fn(), deleteRule: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId, cluster: route.cluster, isLoading: route.loading }) }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), route.setParams] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ ruleId: route.ruleId }), useNavigate: () => route.navigate, Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
const rule: FileProfileRule = { id: "rule", filter: "/etc/", path: "/etc/", regex: "", behavior: "monitor_change", recursive: true, enabled: false, applications: ["app"], description: "Existing description", created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-12T00:00:00.123456Z" };
const profile = { workload_id: "workload", cluster_id: "cluster", name: "Worker", namespace: "team", mode: "monitor", rule_count: 1, monitored_alerts_24h: 2, enforced_blocks_24h: 0, rules: [rule], files: [], exceptions: [], transitions: [], watched_files: [] } as unknown as FileProfileDetail;
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
beforeEach(() => { route.ruleId = undefined; route.search = "workload=workload"; route.clusterId = "cluster"; route.cluster = { id: "cluster" }; route.loading = false; vi.mocked(fileProfiles.get).mockResolvedValue(profile); vi.mocked(fileProfiles.inventory).mockImplementation(async params => ({ profiles: [], total: 0, limit: 100, offset: params.offset ?? 0, has_more: false, sort: params.sort ?? "workload", order: params.order ?? "asc", org_id: "org", cluster_id: "cluster", namespaces: ["team"], source: "retained_file_events", source_complete: true, summary_scope: "matching_shared_profiles", filters: { q: params.q ?? "", namespace: params.namespace ?? "", mode: params.mode ?? "", platform_role: params.platform_role ?? "", hide_platform: params.hide_platform ?? false }, summary: { total: 0, learn: 0, monitor: 0, enforce: 0, rules: 0, alerts: 0, blocks: 0, retained_events: 0, ambiguous: 0 } })); vi.mocked(fileProfiles.list).mockResolvedValue({ profiles: [profile], summary: { total: 1, learn: 0, monitor: 1, enforce: 0 } }); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); localStorage.clear(); });
async function renderPage(form = true) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ org_id: "org", user_id: "user" }}>{form ? <FileMonitorFormPage /> : <FileMonitorPage />}</TablePreferencesProvider></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => { }); check(); }); }
function button(label: string) { return [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === label)!; }
async function submit() { await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); }
async function changeFilter(value: string) { await act(async () => { const input = host.querySelector("input")!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); }); }

it.each([true, false])("does not fetch file data before cluster resolution (form: %s)", async (form) => {
  route.loading = true; await renderPage(form); expect(fileProfiles.get).not.toHaveBeenCalled(); expect(fileProfiles.list).not.toHaveBeenCalled();
});
it.each([true, false])("does not fetch file data without a selected cluster (form: %s)", async (form) => {
  route.clusterId = undefined; route.cluster = undefined; await renderPage(form); expect(fileProfiles.get).not.toHaveBeenCalled(); expect(fileProfiles.list).not.toHaveBeenCalled(); expect(host.textContent).toContain("selected cluster");
});
it("requires a workload before opening the new form", async () => {
  route.search = ""; await renderPage(); expect(host.querySelector("form")).toBeNull(); expect(fileProfiles.get).not.toHaveBeenCalled(); expect(host.textContent).toContain("Choose a workload");
});
it.each(["failed", "wrong-cluster", "wrong-workload", "missing-rule"])("does not open a blank editor for a %s target", async (scenario) => {
  route.ruleId = "rule";
  if(scenario === "failed") vi.mocked(fileProfiles.get).mockRejectedValue(new Error("private transport details"));
  else vi.mocked(fileProfiles.get).mockResolvedValue({ ...profile, ...(scenario === "wrong-cluster" ? { cluster_id: "other" } : scenario === "wrong-workload" ? { workload_id: "other" } : { rules: [] }) });
  await renderPage(); await settled(() => expect(host.textContent).toContain("could not be loaded for the selected workload and cluster"));
  expect(host.querySelector("form")).toBeNull(); expect(host.textContent).not.toContain("private transport details"); expect(fileProfiles.updateRule).not.toHaveBeenCalled();
});
it("keeps unsaved edits across background refetches and preserves existing advanced fields", async () => {
  route.ruleId = "rule"; await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await changeFilter("/var/draft/"); expect(host.querySelector("input")?.value).toBe("/var/draft/");
  await act(async () => { client.setQueryData(["file-monitor-detail", "cluster", "workload", "org:user"], { ...profile, rules: [{ ...rule, filter: "/changed/", enabled: true }] }); });
  expect(host.querySelector("input")?.value).toBe("/var/draft/"); expect(host.querySelector("details")?.open).toBe(false);
  await settled(() => expect(button("Save").disabled).toBe(true)); await act(async () => button("Review current configuration").click());
  vi.mocked(fileProfiles.updateRule).mockRejectedValue(new Error("private transport details")); await submit();
  await settled(() => expect(host.textContent).toContain("Could not save this rule. Your draft is preserved"));
  expect(fileProfiles.updateRule).toHaveBeenCalledWith("workload", "rule", expect.objectContaining({ filter: "/var/draft/", enabled: false, description: "Existing description", behavior: "monitor_change" }), { cluster_id: "cluster" });
  expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private transport details");
});
it("retains the draft and disables saving after a failed refresh", async () => {
  route.ruleId = "rule"; await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await changeFilter("/draft/");
  vi.mocked(fileProfiles.get).mockRejectedValue(new Error("unavailable")); await act(async () => { await client.invalidateQueries({ queryKey: ["file-monitor-detail", "cluster", "workload", "org:user"] }); });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved. Refresh before saving")); expect(host.querySelector("input")?.value).toBe("/draft/"); expect(button("Save").disabled).toBe(true); await submit(); expect(fileProfiles.updateRule).not.toHaveBeenCalled();
});
it("saves an observation rule and returns to the scoped workload list", async () => {
  vi.mocked(fileProfiles.createRule).mockImplementation(async (_workload, body) => ({ ...rule, ...body })); await renderPage(); await settled(() => expect(button("Save")?.disabled).toBe(false)); await submit();
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/file-monitor?workload=workload" }));
  expect(fileProfiles.createRule).toHaveBeenCalledWith("workload", expect.objectContaining({ behavior: "monitor_change", enabled: true }), { cluster_id: "cluster" });
});
it("does not substitute another workload for an unavailable exact selection", async () => {
  route.search = "workload=unknown"; vi.mocked(fileProfiles.get).mockRejectedValue(new Error("missing")); await renderPage(false); await settled(() => expect(host.textContent).toContain("Could not load or refresh rules for this workload")); expect(fileProfiles.get).toHaveBeenCalledWith("unknown", { cluster_id: "cluster" }); expect(button("Add rule").disabled).toBe(true);
});
it("renders a retry error instead of treating a failed rule query as no custom rules", async () => {
  vi.mocked(fileProfiles.get).mockRejectedValue(new Error("private transport details")); await renderPage(false); await settled(() => expect(host.textContent).toContain("Could not load or refresh rules for this workload")); expect(host.textContent).not.toContain("No custom rules"); expect(host.textContent).not.toContain("private transport details"); expect(button("Add rule").disabled).toBe(true);
});
it("uses dedicated scoped create/edit links and requires a delete confirmation", async () => {
  await renderPage(false); await settled(() => expect(host.querySelector('[data-testid="file-monitor-rules-table"]')).not.toBeNull());
  await act(async () => button("Add rule").click()); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/file-monitor/new?workload=workload" });
  await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="Edit rule /etc/"]')!.click()); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/file-monitor/rule?workload=workload" });
  await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="Delete rule /etc/"]')!.click()); expect(fileProfiles.deleteRule).not.toHaveBeenCalled();
  vi.mocked(fileProfiles.deleteRule).mockResolvedValue({ deleted: "rule" });
  await act(async () => button("Delete rule").click()); await settled(() => expect(fileProfiles.deleteRule).toHaveBeenCalledWith("workload", "rule", expect.anything(), { cluster_id: "cluster" }));
  expect(host.textContent).toContain("Profiles configure behavior"); expect([...host.querySelectorAll("button")].some(b => b.textContent?.includes("Export CSV"))).toBe(true);
});


it("preserves applications and custom reason in the canonical rule form", async () => {
  route.ruleId = "rule"; await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  const inputFor = (text: string) => [...host.querySelectorAll("label")].find(item => item.querySelector("span")?.textContent === text)!.querySelector("input")!;
  expect(inputFor("Applications, comma separated").value).toBe("app");
  await act(async () => {
    for(const [text, value] of [["Applications, comma separated", "shell, api, shell"], ["Reason", "ticket 321"]]) {
      const input = inputFor(text); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });
  await submit(); await settled(() => expect(fileProfiles.updateRule).toHaveBeenCalledWith("workload", "rule", expect.objectContaining({ applications: ["api", "shell"], reason: "ticket 321" }), { cluster_id: "cluster" }));
});

it("returns canonical rule cancellation to the requesting deployment files tab", async () => {
  const backTo = "/clusters/cluster/deployments/deployment?tab=files";
  route.search = new URLSearchParams({ workload: "workload", return_to: backTo }).toString(); await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => button("Cancel").click()); expect(route.navigate).toHaveBeenCalledWith({ href: backTo }); expect(fileProfiles.createRule).not.toHaveBeenCalled();
});

it("rejects a foreign deployment return URL", async () => {
  route.search = new URLSearchParams({ workload: "workload", return_to: "/clusters/other/deployments/foreign?tab=files" }).toString(); await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => button("Cancel").click()); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/file-monitor?workload=workload" });
});

it("blocks canonical rule save if the cached profile is invalidated before rerender", async () => {
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => {
    client.getQueryCache().find({ queryKey: ["file-monitor-detail", "cluster", "workload", "org:user"], exact: true })!.setState({ isInvalidated: true });
    host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await settled(() => expect(host.textContent).toContain("Could not save this rule. Your draft is preserved")); expect(fileProfiles.createRule).not.toHaveBeenCalled();
});

it("shows current-vs-draft changes before explicit review and sends the newly reviewed revision", async () => {
  route.ruleId = "rule"; await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await changeFilter("/my-draft/");
  const currentRule = { ...rule, filter: "/server-current/", behavior: "block_access" as const, recursive: false, enabled: true, applications: ["server-app"], description: "Server description", updated_at: "2026-10-12T00:00:01.123456Z" };
  await act(async () => client.setQueryData(["file-monitor-detail", "cluster", "workload", "org:user"], { ...profile, mode: "enforce", rules: [currentRule] }));
  await settled(() => expect(button("Save").disabled).toBe(true));
  const comparison = [...host.querySelectorAll("details")].find(d => d.querySelector("summary")?.textContent?.includes("Compare current configuration"))!;
  expect(comparison.open).toBe(true); for(const text of ["/server-current/", "/my-draft/", "block_access", "server-app", "Server description", "enforce"]) expect(comparison.textContent).toContain(text);
  vi.mocked(fileProfiles.updateRule).mockImplementation(async (_workload, _rule, body) => ({ ...rule, ...body, updated_at: "2026-10-12T00:00:02Z" }));
  await act(async () => button("Review current configuration").click()); expect(host.querySelector("input")?.value).toBe("/my-draft/"); await submit();
  await settled(() => expect(fileProfiles.updateRule).toHaveBeenCalledWith("workload", "rule", expect.objectContaining({ filter: "/my-draft/", expected_updated_at: currentRule.updated_at }), { cluster_id: "cluster" }));
});

it("provides a refresh after server conflict without replacing the draft", async () => {
  route.ruleId = "rule"; await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await changeFilter("/retained/"); vi.mocked(fileProfiles.updateRule).mockRejectedValue(new Error("Conflict")); await submit(); await settled(() => expect(button("Refresh current configuration")).toBeDefined());
  vi.mocked(fileProfiles.get).mockResolvedValue({ ...profile, rules: [{ ...rule, filter: "/other-editor/", updated_at: "2026-10-12T00:00:03Z" }] }); await act(async () => button("Refresh current configuration").click()); await settled(() => expect(host.textContent).toContain("/other-editor/")); expect(host.querySelector("input")?.value).toBe("/retained/"); expect(button("Save").disabled).toBe(true);
});

it("locks another write after an unconfirmed response and provides inspection", async () => {
  route.ruleId = "rule"; await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); vi.mocked(fileProfiles.updateRule).mockResolvedValue({ ...rule, id: "other-rule" }); await submit(); await settled(() => expect(host.textContent).toContain("Save response could not be confirmed")); expect(button("Save").disabled).toBe(true); expect([...host.querySelectorAll("a")].find(a => a.textContent === "Inspect current rules")?.getAttribute("href")).toBe("/clusters/cluster/file-monitor?workload=workload"); await submit(); expect(fileProfiles.updateRule).toHaveBeenCalledOnce();
});

it("does not navigate a later workspace when a pending reviewed save completes", async () => {
  let finish!: (value: typeof rule) => void; route.ruleId = "rule"; await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); vi.mocked(fileProfiles.updateRule).mockImplementation(() => new Promise(resolve => { finish = resolve; })); await submit(); await settled(() => expect(fileProfiles.updateRule).toHaveBeenCalledOnce()); await act(async () => root.render(<p>Different workspace</p>)); await act(async () => finish(rule)); expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).toBe("Different workspace");
});
