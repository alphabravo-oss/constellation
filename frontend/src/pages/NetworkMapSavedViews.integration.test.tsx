import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import { networkViewHref, networkViewSnapshotFromParams } from "@/lib/network-saved-view-route";
import { buildNetworkSavedViewSnapshot, networkActivitySavedViewsStorageKey } from "@/lib/network-saved-views";
import { parseURLSearch, stringifyURLSearch } from "@/lib/route-search";
import { network, groupsApi, runtimeThreats, policies, type RuntimeThreat } from "@/api/client";
import { NetworkMapPage } from "./NetworkMapPage";
import { NetworkSavedViewFormPage } from "./NetworkSavedViewFormPage";
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster", cluster: { id: "cluster", name: "Primary" }, isLoading: false, error: null }) }));
vi.mock("@/api/client", () => ({
  groupsApi: { list: vi.fn() }, network: { map: vi.fn(), conversations: vi.fn(), lifecycle: vi.fn(), sessions: vi.fn(), conversationEntries: vi.fn(), streamFlows: vi.fn(), killSession: vi.fn(), policyAction: vi.fn(), rollbackPolicy: vi.fn() },
  policies: { dpiThreatSettings: vi.fn(), updateDpiThreatSettings: vi.fn() }, runtimeThreats: { page: vi.fn() }, runtimePcap: { list: vi.fn(), remove: vi.fn(), download: vi.fn() },
}));
const snapshot = buildNetworkSavedViewSnapshot({ workspaceTab: "conversations", hours: 168, namespace: "prod", group: "group-id", verdict: "block", verdictsVisible: { allow: false, alert: true, block: true }, protocolFilter: ["HTTP"], namespaceFilter: ["prod"], hidePlatformComponents: false, hiddenKinds: ["external"], scopeMode: "external", sessionFilters: { protocol: "tcp", peer: "10.0.0.1", application: "https", port: "443", workload: "prod/api", node: "node-a" }, pcapFilters: { workload: "prod/api", bpf_filter: "tcp port 443" }, conversationFilters: { from: `prod/${"x".repeat(200)}`, to: "other/api", verdict_group: "blocked" } });
const context = new URLSearchParams({ tab: "conversations", hours: "168", namespace: "prod", group: "group-id", verdict: "block", conversation_page: "4", inspect_from: "prod/api", inspect_to: "other/api", flow: "flow-selected", workload: "prod/api", context: "dashboard", from: snapshot.conversation_filters!.from, to: "other/api", verdict_group: "blocked" });
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; vi.clearAllMocks(); localStorage.clear();
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [] });
  vi.mocked(network.map).mockResolvedValue({ summary: { window_hours: 168, workloads: 0, flows: 0 }, workloads: [], flows: [] });
  vi.mocked(network.conversations).mockResolvedValue({ conversations: [{ from: "prod/api", to: "other/api", bytes: 1, packets: 1, edges: 1, verdict: "block", apps: ["HTTPS"], last_seen: "2026-10-12T00:00:00Z" }], total: 450, nodes: [], node_kinds: {}, edges: [], window_hours: 168 });
  vi.mocked(network.lifecycle).mockResolvedValue({ items: [], summary: { total: 0, ready: 0, discover: 0, monitor: 0, protect: 0, rollback_ready: 0, pending_approval: 0 } }); vi.mocked(network.sessions).mockResolvedValue({ sessions: [], total: 0, has_more: false, limit: 100, offset: 0, cluster_id: "cluster", selected_group: "group-id", selected_group_members: 0 });
  vi.mocked(runtimeThreats.page).mockResolvedValue({ threats: [], total: 0, has_more: false, limit: 100, offset: 0 }); vi.mocked(policies.dpiThreatSettings).mockResolvedValue({ cluster_id: "cluster", weak_tls_enabled: false }); vi.mocked(network.streamFlows).mockReturnValue(() => {});
  vi.mocked(network.conversationEntries).mockResolvedValue({ from: "prod/api", to: "other/api", window_hours: 168, entries: [], totals: { bytes: 0, packets: 0, sessions: 0, client_bytes: 0, server_bytes: 0 } });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); history?.destroy(); localStorage.clear(); });
async function render(initialHref?: string) {
  history = createMemoryHistory({ initialEntries: [initialHref ?? networkViewHref("cluster", context, "#evidence", "network", snapshot)] });
  const routeRoot = createRootRoute({ component: Outlet });
  const workspace = createRoute({ getParentRoute: () => routeRoot, path: "/clusters/$id/network", component: NetworkMapPage });
  const form = createRoute({ getParentRoute: () => routeRoot, path: "/clusters/$id/network/views/new", component: NetworkSavedViewFormPage });
  const router = createRouter({ routeTree: routeRoot.addChildren([workspace, form]), history, parseSearch: parseURLSearch, stringifySearch: stringifyURLSearch });
  await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ org_id: "org", user_id: "user" }}><RouterProvider router={router} /></TablePreferencesProvider></QueryClientProvider>));
  if (!initialHref) await restored();
}
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
function button(testid: string) { return host.querySelector<HTMLButtonElement>(`[data-testid="${testid}"]`)!; }
async function restored(stage = "initial restoration", expected = snapshot) {
  await settle(() => {
    expect(history.location.pathname).toBe("/clusters/cluster/network"); expect(networkViewSnapshotFromParams(new URLSearchParams(history.location.search))).toEqual(expected);
    expect(host.querySelector<HTMLInputElement>('[data-testid="network-traffic-port"]')?.value, stage).toBe("443"); expect(host.querySelector<HTMLInputElement>('[data-testid="network-traffic-peer"]')?.value).toBe("10.0.0.1"); expect(host.querySelector<HTMLInputElement>('[data-testid="network-traffic-application"]')?.value).toBe("https");
    expect(host.querySelector('[data-testid="network-conversation-detail"]')?.textContent).toContain("prod/api → other/api");
    expect(network.conversations).toHaveBeenLastCalledWith(expect.objectContaining({ cluster_id: "cluster", offset: 300, limit: 100, hours: 168, namespace: "prod", group: "group-id", verdict: "block", port: 443, peer: "10.0.0.1", application: "https", from: snapshot.conversation_filters!.from, to: "other/api", verdict_group: "blocked" }));
    expect(network.sessions).toHaveBeenLastCalledWith(expect.objectContaining({ cluster_id: "cluster", group: "group-id", protocol: "tcp", port: 443, peer: "10.0.0.1", application: "https", workload: "prod/api", node: "node-a" }));
    const params = new URLSearchParams(history.location.search); for (const key of ["conversation_page", "inspect_from", "inspect_to", "flow", "workload", "context"]) expect(params.get(key)).toBe(context.get(key)); expect(history.location.hash).toBe("#evidence");
  });
  expect(network.killSession).not.toHaveBeenCalled(); expect(network.policyAction).not.toHaveBeenCalled(); expect(network.rollbackPolicy).not.toHaveBeenCalled(); expect(policies.updateDpiThreatSettings).not.toHaveBeenCalled();
}
async function openForm(expected = snapshot) { await act(async () => button("network-saved-view-save").click()); await settle(() => expect(history.location.pathname).toBe("/clusters/cluster/network/views/new")); await settle(() => expect(host.querySelector("#network-view-name"), `${host.textContent} snapshot=${new URLSearchParams(history.location.search).get("network_view")}`).not.toBeNull()); expect(history.location.pathname).toBe("/clusters/cluster/network/views/new"); expect(networkViewSnapshotFromParams(new URLSearchParams(history.location.search))).toEqual(expected); }
it("restores an exact snapshot without clearing server page, detail selection or non-URL filters", async () => { await render(); expect(network.conversationEntries).toHaveBeenCalledWith({ cluster_id: "cluster", from: "prod/api", to: "other/api", hours: 168 }); });
async function roundTrip(action: "Save" | "Cancel") {
  await render(); await openForm();
  await act(async () => [...host.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent === action)!.click()); await restored(`${action} return`);
  const key = operatorStorageKey(networkActivitySavedViewsStorageKey("cluster", "user"), { org_id: "org", user_id: "user" })!;
  if (action === "Save") expect(JSON.parse(localStorage.getItem(key)!)[0].filters).toEqual(snapshot); else expect(localStorage.getItem(key)).toBeNull();
}
it.each(["Save", "Cancel"] as const)("preserves filters/page/inspection/selection immediately after dedicated %s", async action => { await roundTrip(action); });
it.each(["Save", "Cancel"] as const)("preserves local filters through Back/Forward after dedicated %s", async action => {
  await roundTrip(action);
  await act(async () => history.back()); await settle(() => expect(host.querySelector("#network-view-name")).not.toBeNull()); expect(networkViewSnapshotFromParams(new URLSearchParams(history.location.search))).toEqual(snapshot);
  await act(async () => history.forward()); await restored(`${action} Forward return`);
});
it("restores local filters when Back returns from the dedicated form to its original workspace", async () => { await render(); await openForm(); await act(async () => history.back()); await restored("Back to original workspace"); });

it("keeps subsequent local presentation filters in the URL snapshot without changing page or selection", async () => {
  await render(); const updated = { ...snapshot, verdicts_visible: { ...snapshot.verdicts_visible, allow: true } };
  await act(async () => button("netchip-verdict-allow").click()); await restored("after local filter change", updated);
  await openForm(updated); await act(async () => history.back()); await restored("Back with changed local filters", updated);
});

it("uses explicit threat roles before legacy namespace fallback and restores hidden evidence by URL", async () => {
 const row = (id: string, namespace: string, platform_role?: string): RuntimeThreat => ({ id, org_id: "org", cluster_id: "cluster", namespace, workload_id: `${namespace}/${id}`, platform_role, threat_id: 2022, threat_name: id, severity: 2, action: 0, pkt_ingress: false, sess_ingress: false, at: "2026-10-12T00:00:00Z", reported_at: "2026-10-12T00:00:00Z" });
 vi.mocked(runtimeThreats.page).mockResolvedValue({ threats: [row("custom-install", "operations", "core"), row("namespace-legacy", "kube-system"), row("explicit-unclassified", "kube-system", ""), row("customer", "prod")], total: 4, has_more: false, limit: 100, offset: 0 });
 await render("/clusters/cluster/network?tab=threats&hours=168&hide_platform=true");
 await settle(() => expect(host.querySelector('[data-testid="network-threats-table"]')?.textContent).toContain("customer"));
 const table = () => host.querySelector('[data-testid="network-threats-table"]')!.textContent!;
 expect(table()).not.toContain("custom-install"); expect(table()).not.toContain("namespace-legacy"); expect(table()).toContain("explicit-unclassified");
 await act(async () => history.push("/clusters/cluster/network?tab=threats&hours=168&hide_platform=false"));
 await settle(() => expect(table()).toContain("custom-install")); expect(table()).toContain("namespace-legacy");
 expect(network.policyAction).not.toHaveBeenCalled(); expect(policies.updateDpiThreatSettings).not.toHaveBeenCalled();
});

it("withholds cached threat exports and names a failed refresh instead of reporting no threats", async () => {
 const threat = { id: "retained-threat", org_id: "org", cluster_id: "cluster", workload_id: "prod/api", namespace: "prod", platform_role: "", threat_name: "retained-threat", threat_id: 2022, severity: 2, action: 0, pkt_ingress: false, sess_ingress: false, at: "2026-10-12T00:00:00Z", reported_at: "2026-10-12T00:00:00Z" };
 vi.mocked(runtimeThreats.page).mockResolvedValue({ threats: [threat], total: 1, has_more: false, limit: 100, offset: 0 });
 await render("/clusters/cluster/network?tab=threats&hours=168&hide_platform=false");
 await settle(() => expect(host.querySelector('[data-testid="network-threats-table"]')?.textContent).toContain("retained-threat"));
 vi.mocked(runtimeThreats.page).mockRejectedValue(new Error("Role evidence unavailable"));
 await act(async () => { await client.invalidateQueries({ queryKey: ["runtime-threats"] }); });
 await settle(() => expect(host.textContent).toContain("Threat evidence could not be loaded or refreshed"));
 expect(host.querySelector('[data-testid="network-threats-table"]')).toBeNull(); expect(host.textContent).not.toContain("Export loaded threat page"); expect(host.textContent).not.toContain("No DPI threats");
});
