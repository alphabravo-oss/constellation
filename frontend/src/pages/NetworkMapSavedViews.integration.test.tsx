import { act } from "react";
import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import { networkViewHref, networkViewSnapshotFromParams } from "@/lib/network-saved-view-route";
import { buildNetworkSavedViewSnapshot, networkActivitySavedViewsStorageKey } from "@/lib/network-saved-views";
import { parseURLSearch, stringifyURLSearch } from "@/lib/route-search";
import { network, groupsApi, runtimeThreats, policies, type RuntimeThreat, type RuntimeThreatFilters, type RuntimeThreatPage, type NetworkConversation, type NetworkConversationFilters, type NetworkConversations, type NetworkSession, type NetworkSessionFilters, type NetworkSessionsResponse } from "@/api/client";
import { NetworkMapPage } from "./NetworkMapPage";
import { NetworkSavedViewFormPage } from "./NetworkSavedViewFormPage";
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster", cluster: { id: "cluster", name: "Primary" }, isLoading: false, error: null }) }));
vi.mock("@/api/client", () => ({
  groupsApi: { list: vi.fn() }, network: { map: vi.fn(), conversations: vi.fn(), lifecycle: vi.fn(), sessions: vi.fn(), conversationEntries: vi.fn(), streamFlows: vi.fn(), killSession: vi.fn(), conversationsCSV: vi.fn(), sessionsCSV: vi.fn(), policyAction: vi.fn(), rollbackPolicy: vi.fn() },
  policies: { dpiThreatSettings: vi.fn(), updateDpiThreatSettings: vi.fn() }, runtimeThreats: { page: vi.fn(), exportCSV: vi.fn() }, runtimePcap: { list: vi.fn(), remove: vi.fn(), download: vi.fn() },
}));
function threatPage(params: RuntimeThreatFilters = {}, rows: RuntimeThreat[] = []): RuntimeThreatPage {
 const matching = rows.filter(row => !params.hide_platform || row.platform_role !== "core"); const offset = params.offset ?? 0;
 return { threats: matching.slice(offset, offset + 100), total: matching.length, has_more: matching.length > offset + 100, limit: 100, offset, cluster_id: params.cluster_id ?? "cluster", window_hours: params.hours ?? 24, sort: params.sort ?? "at", order: params.order ?? "desc", filters: { group: params.group?.trim() ?? "", hide_platform: params.hide_platform ?? false, namespace: params.namespace?.trim() ?? "", port: params.port ?? 0, peer: params.peer?.trim().toLowerCase() ?? "", application: String(params.application ?? "").trim().toLowerCase(), severity_min: params.severity_min ?? 0, workload_id: params.workload_id?.trim() ?? "", category: params.category?.trim() ?? "", node: params.node?.trim() ?? "", q: params.q?.trim().toLowerCase() ?? "" }, summary: { total: matching.length, critical: matching.filter(r=>r.severity>=8).length, blocked: matching.filter(r=>[2,3,4].includes(r.action)).length, ips: matching.length, dlp: 0, waf: 0, workloads: matching.length } };
}
function conversationPage(params: NetworkConversationFilters = {}, source: NetworkConversation[] = []): NetworkConversations {
  const matching = source.filter(row => (!params.hide_platform || row.from_platform_role !== "core" && row.to_platform_role !== "core") && (!params.from || row.from === params.from) && (!params.to || row.to === params.to) && (!params.namespace || row.from.startsWith(`${params.namespace}/`) || row.to.startsWith(`${params.namespace}/`)) && (!params.verdict || row.verdict === params.verdict) && (!params.verdict_group || ["block", "deny"].includes(row.verdict ?? "")) && (!params.application || row.apps?.some(app => app.toLowerCase() === params.application?.toLowerCase())));
  const sort = params.sort ?? "last_seen", order = params.order ?? "desc", offset = params.offset ?? 0, limit = params.limit ?? 100;
  matching.sort((a, b) => { const av = a[sort as keyof NetworkConversation], bv = b[sort as keyof NetworkConversation]; const value = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv)); return (order === "asc" ? value : -value) || a.row_id!.localeCompare(b.row_id!); });
  return { conversations: matching.slice(offset, offset + limit), total: matching.length, has_more: offset + limit < matching.length, limit, offset, sort, order, cluster_id: params.cluster_id ?? "cluster", window_hours: params.hours ?? 24, source: "rollups", source_complete: true, summary_scope: "matching_rollups", nodes: [], node_kinds: {}, edges: [], filters: { hours: params.hours ?? 24, group: params.group?.trim() ?? "", hide_platform: params.hide_platform ?? false, namespace: params.namespace?.trim() ?? "", port: params.port ?? 0, peer: params.peer?.trim().toLowerCase() ?? "", application: params.application?.trim().toLowerCase() ?? "", verdict: params.verdict?.trim().toLowerCase() ?? "", from: params.from?.trim() ?? "", to: params.to?.trim() ?? "", verdict_group: params.verdict_group ?? "" }, summary: { total: matching.length, bytes: matching.reduce((n,r)=>n+r.bytes,0), packets: matching.reduce((n,r)=>n+r.packets,0), edges: matching.reduce((n,r)=>n+r.edges,0), blocked: matching.filter(r=>["block","deny"].includes(r.verdict ?? "")).length, violating: 0, nodes: new Set(matching.flatMap(r=>[r.from,r.to])).size } };
}
function sessionPage(params: NetworkSessionFilters = {}, source: NetworkSession[] = []): NetworkSessionsResponse {
  const matching = source.filter(row => (!params.hide_platform || row.platform_role !== "core") && (!params.workload || row.workload_id?.toLowerCase().includes(params.workload.toLowerCase())) && (!params.node || row.node.toLowerCase().includes(params.node.toLowerCase())) && (!params.protocol || row.ip_proto.toLowerCase() === params.protocol.toLowerCase()) && (!params.application || row.application.toLowerCase() === params.application.toLowerCase()) && (!params.port || row.client_port === params.port || row.server_port === params.port) && (!params.peer || row.client_ip === params.peer || row.server_ip === params.peer));
  const sort = params.sort ?? "bytes", order = params.order ?? "desc", offset = params.offset ?? 0, limit = params.limit ?? 100;
  const value = (row: NetworkSession) => sort === "bytes" ? row.client_bytes + row.server_bytes : sort === "workload" ? row.workload_id ?? "" : row[sort as keyof NetworkSession];
  matching.sort((a,b)=>{ const av = value(a), bv = value(b); const cmp = typeof av === "number" && typeof bv === "number" ? av-bv : String(av).localeCompare(String(bv)); return (order === "asc" ? cmp : -cmp) || a.row_id!.localeCompare(b.row_id!); });
  const clientBytes = matching.reduce((n,r)=>n+r.client_bytes,0), serverBytes = matching.reduce((n,r)=>n+r.server_bytes,0);
  return { sessions: matching.slice(offset, offset + limit), total: matching.length, has_more: offset + limit < matching.length, limit, offset, sort, order, cluster_id: params.cluster_id ?? "cluster", selected_group: params.group, selected_group_members: 0, filters: { cluster_id: params.cluster_id ?? null, group: params.group?.trim() ?? "", protocol: params.protocol ? ({tcp:6,udp:17,icmp:1,icmpv6:58}[params.protocol as "tcp"] ?? Number(params.protocol)) : null, port: params.port ?? null, application: params.application?.trim().toLowerCase() ?? "", peer: params.peer?.trim().toLowerCase() ?? "", workload: params.workload?.trim().toLowerCase() ?? "", node: params.node?.trim().toLowerCase() ?? "", hours: params.hours ?? 0, q: params.q?.trim().toLowerCase() ?? "", hide_platform: params.hide_platform ?? false }, summary: { total: matching.length, client_bytes: clientBytes, server_bytes: serverBytes, bytes: clientBytes + serverBytes, packets: matching.reduce((n,r)=>n+r.client_pkts+r.server_pkts,0), threats: matching.filter(r=>r.threat_id).length } };
}
const conversationRows = (): NetworkConversation[] => Array.from({ length: 405 }, (_, n) => { const from = `${n < 50 ? "core" : "prod"}/source-${String(n).padStart(3,"0")}`, to = "prod/service"; return { row_id: JSON.stringify([from,to]), from, to, from_platform_role: n < 50 ? "core" : "", to_platform_role: "", bytes: n+1, packets: 2, edges: 3, severity: 0, verdict: n % 2 ? "block" : "allow", apps: ["HTTPS"], last_seen: "2026-10-12T00:00:00Z" }; });
const sessionRows = (): NetworkSession[] => Array.from({ length: 405 }, (_, n) => { const node = `node-${n}`, id = 1; return { row_id: JSON.stringify(["cluster",node,id]), cluster_id: "cluster", id, node, workload_id: `${n < 50 ? "core" : "prod"}/api-${String(n).padStart(3,"0")}`, platform_role: n < 50 ? "core" : "", application: "HTTPS", ip_proto: "TCP", client_ip: "10.0.0.1", client_port: 5000+n, server_ip: "10.0.0.2", server_port: 443, client_state: "established", server_state: "established", client_bytes: n+1, server_bytes: n+1, client_pkts: 1, server_pkts: 2, age: n, idle: 0, severity: 0, ingress: false, updated_at: "2026-10-12T00:00:00Z" }; });
async function clickLabel(label: string, scope: HTMLElement = host) { const target = [...scope.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent === label); expect(target, label).toBeTruthy(); await act(async () => target!.click()); }
function tableRows(kind: "conversations" | "sessions") { return host.querySelectorAll(`[data-testid="network-${kind}-table"] tbody tr`); }
const snapshot = buildNetworkSavedViewSnapshot({ workspaceTab: "conversations", hours: 168, namespace: "prod", group: "group-id", verdict: "block", verdictsVisible: { allow: false, alert: true, block: true }, protocolFilter: ["HTTP"], namespaceFilter: ["prod"], hidePlatformComponents: false, hiddenKinds: ["external"], scopeMode: "external", sessionFilters: { protocol: "tcp", peer: "10.0.0.1", application: "https", port: "443", workload: "prod/api", node: "node-a" }, pcapFilters: { workload: "prod/api", bpf_filter: "tcp port 443" }, conversationFilters: { from: `prod/${"x".repeat(200)}`, to: "other/api", verdict_group: "blocked" } });
const context = new URLSearchParams({ tab: "conversations", hours: "168", namespace: "prod", group: "group-id", verdict: "block", conversation_page: "4", inspect_from: "prod/api", inspect_to: "other/api", flow: "flow-selected", workload: "prod/api", context: "dashboard", from: snapshot.conversation_filters!.from, to: "other/api", verdict_group: "blocked" });
let identity = { org_id: "org", user_id: "user" }; let rerender: () => void;
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; vi.clearAllMocks(); localStorage.clear(); identity = { org_id: "org", user_id: "user" };
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [] });
  vi.mocked(network.map).mockResolvedValue({ summary: { window_hours: 168, workloads: 0, flows: 0 }, workloads: [], flows: [] });
  vi.mocked(network.conversations).mockImplementation(async params => conversationPage(params));
  vi.mocked(network.lifecycle).mockResolvedValue({ items: [], summary: { total: 0, ready: 0, discover: 0, monitor: 0, protect: 0, rollback_ready: 0, pending_approval: 0 } }); vi.mocked(network.sessions).mockImplementation(async params => sessionPage(params));
  vi.mocked(runtimeThreats.page).mockImplementation(async params => threatPage(params)); vi.mocked(policies.dpiThreatSettings).mockResolvedValue({ cluster_id: "cluster", weak_tls_enabled: false }); vi.mocked(network.streamFlows).mockReturnValue(() => {});
  vi.mocked(network.conversationEntries).mockResolvedValue({ from: "prod/api", to: "other/api", window_hours: 168, entries: [], totals: { bytes: 0, packets: 0, sessions: 0, client_bytes: 0, server_bytes: 0 } });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); history?.destroy(); localStorage.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function render(initialHref?: string) {
  history = createMemoryHistory({ initialEntries: [initialHref ?? networkViewHref("cluster", context, "#evidence", "network", snapshot)] });
  const routeRoot = createRootRoute({ component: Outlet });
  const workspace = createRoute({ getParentRoute: () => routeRoot, path: "/clusters/$id/network", component: NetworkMapPage });
  const form = createRoute({ getParentRoute: () => routeRoot, path: "/clusters/$id/network/views/new", component: NetworkSavedViewFormPage });
  const router = createRouter({ routeTree: routeRoot.addChildren([workspace, form]), history, parseSearch: parseURLSearch, stringifySearch: stringifyURLSearch });
  rerender = () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...identity }}><RouterProvider router={router} /></TablePreferencesProvider></QueryClientProvider>);
  await act(async () => rerender());
  if (!initialHref) await restored();
}
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }, { timeout: 5000 }); }
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
  await render(); await act(async () => history.push(history.location.href.replace("tab=conversations", "tab=map")));
  await settle(() => expect(button("netchip-verdict-allow")).not.toBeNull());
  await act(async () => button("netchip-verdict-allow").click());
  await act(async () => history.push(history.location.href.replace("tab=map", "tab=conversations")));
  const updated = { ...snapshot, verdicts_visible: { ...snapshot.verdicts_visible, allow: true } }; await restored("after local filter change", updated);
  await openForm(updated); await act(async () => history.back()); await restored("Back with changed local filters", updated);
});

it("requests platform filtering before counts and restores the complete server cohort by URL", async () => {
 const row = (id: string, namespace: string, platform_role?: string): RuntimeThreat => ({ id, org_id: "org", cluster_id: "cluster", namespace, workload_id: `${namespace}/${id}`, platform_role, threat_id: 2022, threat_name: id, severity: 2, action: 0, pkt_ingress: false, sess_ingress: false, at: "2026-10-12T00:00:00Z", reported_at: "2026-10-12T00:00:00Z" });
 vi.mocked(runtimeThreats.page).mockImplementation(async params => threatPage(params, [row("custom-install", "operations", "core"), row("namespace-legacy", "kube-system", "core"), row("explicit-unclassified", "kube-system", ""), row("customer", "prod", "")]));
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
 vi.mocked(runtimeThreats.page).mockImplementation(async params => threatPage(params, [threat]));
 await render("/clusters/cluster/network?tab=threats&hours=168&hide_platform=false");
 await settle(() => expect(host.querySelector('[data-testid="network-threats-table"]')?.textContent).toContain("retained-threat"));
 vi.mocked(runtimeThreats.page).mockRejectedValue(new Error("Role evidence unavailable"));
 await act(async () => { await client.invalidateQueries({ queryKey: ["runtime-threats"] }); });
 await settle(() => expect(host.textContent).toContain("Threat evidence could not be loaded or refreshed"));
 expect(host.querySelector('[data-testid="network-threats-table"]')).toBeNull(); expect(host.textContent).not.toContain("Export this page CSV"); expect(host.textContent).not.toContain("No DPI threats");
});

it("keeps threat totals, server sort, continuation and matching exports on one URL scope", async () => {
 const rows: RuntimeThreat[] = Array.from({ length: 205 }, (_, n) => ({ id: `t-${n}`, org_id: "org", cluster_id: "cluster", workload_id: "prod/api", namespace: "prod", platform_role: "", threat_name: `threat-${n}`, threat_id: 2022, severity: n < 150 ? 8 : 2, action: 2, at: "2026-10-12T00:00:00Z", reported_at: "2026-10-12T00:00:00Z", pkt_ingress: false, sess_ingress: false }));
 vi.mocked(runtimeThreats.page).mockImplementation(async params => threatPage(params, rows));
 vi.mocked(runtimeThreats.exportCSV).mockResolvedValue({ total: 205, exported: 205, limit: 100000, truncated: false });
 await render("/clusters/cluster/network?tab=threats&hours=168&hide_platform=false&context=keep");
 await settle(() => expect(host.querySelectorAll('[data-testid="network-threats-table"] tbody tr')).toHaveLength(100));
 expect(host.querySelector('[data-testid="network-threats-tab"]')?.textContent).toContain("150");
 const click = async (label: string) => act(async () => [...host.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent===label)!.click());
 await click("Next"); await settle(() => expect(history.location.search).toContain("threat_page=2"));
 await settle(() => expect(host.querySelector('tbody')?.textContent).toContain("threat-100"));
 await click("Severity"); await settle(() => expect(runtimeThreats.page).toHaveBeenLastCalledWith(expect.objectContaining({ sort: "severity", offset: 0, hide_platform: false, hours: 168 })));
 await settle(() => expect(host.querySelectorAll('[data-testid="network-threats-table"] tbody tr')).toHaveLength(100));
 await click("Export matching CSV"); await settle(() => expect(runtimeThreats.exportCSV).toHaveBeenCalledWith(expect.objectContaining({ cluster_id: "cluster", sort: "severity", offset: 0, hide_platform: false }), expect.any(Function)));
 expect(history.location.search).toContain("context=keep");
 await act(async () => history.back()); await settle(() => expect(history.location.search).toContain("threat_page=2"));
 await settle(() => expect(host.querySelector('tbody')?.textContent).toContain("threat-100"));
 expect(network.killSession).not.toHaveBeenCalled();
});

it.each(["wrong-cluster", "wrong-sort", "platform-leak", "null-row"])("withholds malformed threat evidence and exports: %s", async failure => {
 const row: RuntimeThreat = { id: "wrong", org_id: "org", cluster_id: "cluster", platform_role: "", threat_id: 1, severity: 2, action: 0, at: "2026-10-12T00:00:00Z", reported_at: "2026-10-12T00:00:00Z", pkt_ingress: false, sess_ingress: false };
 vi.mocked(runtimeThreats.page).mockImplementation(async params => { const data = threatPage(params, [row]); if (failure === "wrong-cluster") data.cluster_id = "other"; if (failure === "wrong-sort") data.sort = "severity"; if (failure === "platform-leak") data.threats[0].platform_role = "core"; if (failure === "null-row") data.threats = [null as unknown as RuntimeThreat]; return data; });
 await render("/clusters/cluster/network?tab=threats&hide_platform=true");
 await settle(() => expect(host.textContent).toContain("Threat evidence could not be loaded"));
 expect(host.querySelector('[data-testid="network-threats-table"]')).toBeNull();
 expect([...host.querySelectorAll("button")].some(b=>b.textContent==="Export matching CSV")).toBe(false);
});

it("traverses full conversation cohorts with server sorting, matching export and URL history", async () => {
  const source = conversationRows();
  vi.mocked(network.conversations).mockImplementation(async params => conversationPage(params, source));
  vi.mocked(network.conversationsCSV).mockImplementation(async params => { const total = conversationPage(params,source).total!; return {total,exported:total,limit:100000,truncated:false}; });
  await render("/clusters/cluster/network?tab=conversations&hours=168&hide_platform=true&namespace=prod&verdict=block&context=keep&conversation_sort=bytes&conversation_order=desc");
  await settle(() => expect(tableRows("conversations")).toHaveLength(100));
  expect(tableRows("conversations")[0].textContent).toContain("prod/source-403");
  expect(host.querySelector('[data-testid="network-conversations-tab"]')?.textContent).toContain("177");
  expect(button("netchip-verdict-allow")).toBeNull();
  await clickLabel("Next");
  await settle(() => expect(tableRows("conversations")[0].textContent).toContain("prod/source-203"));
  expect(tableRows("conversations")).toHaveLength(77);
  expect(history.location.search).toContain("conversation_page=2");
  await clickLabel("Volume");
  await settle(() => expect(network.conversations).toHaveBeenLastCalledWith(expect.objectContaining({sort:"bytes",order:"asc",offset:0,hide_platform:true,namespace:"prod",verdict:"block"})));
  await settle(() => expect(tableRows("conversations")[0].textContent).toContain("prod/source-051"));
  expect(host.querySelector('[data-testid="network-conversations-table"] th[data-column-id="bytes"]')?.getAttribute("aria-sort")).toBe("ascending");
  await clickLabel("Export matching CSV");
  await settle(() => expect(network.conversationsCSV).toHaveBeenCalledWith(expect.objectContaining({sort:"bytes",order:"asc",offset:0,hide_platform:true,namespace:"prod",verdict:"block",hours:168,cluster_id:"cluster"}), expect.any(Function)));
  await settle(() => expect(host.textContent).toContain("177"));
  await act(async () => history.back());
  await settle(() => expect(tableRows("conversations")[0].textContent).toContain("prod/source-203"));
  expect(host.querySelector('[data-testid="network-conversations-table"] th[data-column-id="bytes"]')?.getAttribute("aria-sort")).toBe("descending");
  await act(async () => history.forward());
  await settle(() => expect(tableRows("conversations")[0].textContent).toContain("prod/source-051"));
  expect(history.location.search).toContain("context=keep");
}, 20000);

it("keeps full session summaries, distinct same-ID rows, server sort/export and history in one cohort", async () => {
  const source = sessionRows();
  vi.mocked(network.sessions).mockImplementation(async params => sessionPage(params, source));
  vi.mocked(network.sessionsCSV).mockImplementation(async params => { const total=sessionPage(params,source).total; return {total,exported:total,limit:100000,truncated:false}; });
  await render("/clusters/cluster/network?tab=sessions&hide_platform=true&session_sort=workload&session_order=desc&context=keep");
  await settle(() => expect(tableRows("sessions")).toHaveLength(100));
  expect(tableRows("sessions")[0].textContent).toContain("prod/api-404");
  expect(host.querySelector('[data-testid="network-sessions-tab"]')?.textContent).toContain("355");
  for (const label of ["Namespace filter", "Verdict filter", "Traffic window"]) expect(host.querySelector(`[aria-label="${label}"]`)).toBeNull();
  await clickLabel("Next");
  await settle(() => expect(tableRows("sessions")[0].textContent).toContain("prod/api-304"));
  expect(history.location.search).toContain("session_page=2");
  await clickLabel("Workload");
  await settle(() => expect(tableRows("sessions")[0].textContent).toContain("prod/api-050"));
  expect(host.querySelector('[data-testid="network-sessions-table"] th[data-column-id="workload"]')?.getAttribute("aria-sort")).toBe("ascending");
  await clickLabel("Export matching CSV");
  await settle(() => expect(network.sessionsCSV).toHaveBeenCalledWith(expect.objectContaining({cluster_id:"cluster",sort:"workload",order:"asc",hide_platform:true,offset:0}), expect.any(Function)));
  expect(vi.mocked(network.sessionsCSV).mock.calls[0][0]).not.toHaveProperty("hours");
  await act(async () => history.back());
  await settle(() => expect(tableRows("sessions")[0].textContent).toContain("prod/api-304"));
  expect(host.querySelector('[data-testid="network-sessions-table"] th[data-column-id="workload"]')?.getAttribute("aria-sort")).toBe("descending");
  await act(async () => history.forward());
  await settle(() => expect(tableRows("sessions")[0].textContent).toContain("prod/api-050"));
  // A restored server filter matches the entire inventory, not only the previous page.
  await act(async () => history.push(networkViewHref("cluster",new URLSearchParams("tab=sessions&hide_platform=true&context=keep"),"","network",buildNetworkSavedViewSnapshot({workspaceTab:"sessions",hours:24,namespace:"",verdict:"",verdictsVisible:{allow:true,alert:true,block:true},protocolFilter:[],namespaceFilter:[],hiddenKinds:[],scopeMode:"both",pcapFilters:{workload:"",bpf_filter:""},hidePlatformComponents:true,sessionFilters:{protocol:"tcp",application:"https",port:"443",peer:"10.0.0.1",workload:"prod/api-40",node:""}}))));
  await settle(() => expect(tableRows("sessions")).toHaveLength(5));
  await clickLabel("Export matching CSV");
  await settle(() => expect(network.sessionsCSV).toHaveBeenLastCalledWith(expect.objectContaining({workload:"prod/api-40",protocol:"tcp",application:"https",port:443,peer:"10.0.0.1",hide_platform:true,offset:0}), expect.any(Function)));
  expect(network.killSession).not.toHaveBeenCalled();
}, 20000);

it.each(["conversations", "sessions"] as const)("hides cached %s rows and exports after a failed refresh", async kind => {
  vi.mocked(network.conversations).mockImplementation(async params => conversationPage(params,conversationRows()));
  vi.mocked(network.sessions).mockImplementation(async params => sessionPage(params,sessionRows()));
  await render(`/clusters/cluster/network?tab=${kind}&hide_platform=false`);
  await settle(() => expect(tableRows(kind)).toHaveLength(100));
  if (kind === "conversations") vi.mocked(network.conversations).mockRejectedValue(new Error("Inventory source unavailable"));
  else vi.mocked(network.sessions).mockRejectedValue(new Error("Inventory source unavailable"));
  await act(async () => { await client.invalidateQueries({queryKey:[`network-${kind}`]}); });
  await settle(() => expect(host.querySelector(`[data-testid="network-${kind}-table"]`)).toBeNull());
  expect(host.textContent).toContain("could not be loaded or refreshed");
  expect([...host.querySelectorAll("button")].some(b=>b.textContent === "Export matching CSV")).toBe(false);
});

it.each(["conversations", "sessions"] as const)("rejects foreign scope and default filter broadening in %s metadata", async kind => {
  vi.mocked(network.conversations).mockImplementation(async params => { const data=conversationPage(params); data.cluster_id="foreign"; return data; });
  vi.mocked(network.sessions).mockImplementation(async params => { const data=sessionPage(params); data.filters!.node="unexpected-filter"; return data; });
  await render(`/clusters/cluster/network?tab=${kind}&hide_platform=true`);
  await settle(() => expect(host.textContent).toContain("could not be loaded"));
  expect(host.querySelector(`[data-testid="network-${kind}-table"]`)).toBeNull();
});

it("resets invalid session sorting while preserving URL filters and context", async () => {
  vi.mocked(network.sessions).mockImplementation(async params => sessionPage(params,sessionRows()));
  await render("/clusters/cluster/network?tab=sessions&hide_platform=true&session_sort=invalid&context=keep");
  await settle(() => expect(host.textContent).toContain("Reset sorting and page"));
  await clickLabel("Reset sorting and page");
  await settle(() => expect(tableRows("sessions")).toHaveLength(100));
  expect(history.location.search).toContain("context=keep"); expect(history.location.search).toContain("hide_platform=true");
});

it("rejects a queued session kill if the confirmed query is invalidated before dispatch", async () => {
  vi.mocked(network.sessions).mockImplementation(async params => sessionPage(params,sessionRows().slice(0,1)));
  await render("/clusters/cluster/network?tab=sessions&hide_platform=false");
  await settle(() => expect(tableRows("sessions")).toHaveLength(1));
  vi.stubGlobal("confirm",vi.fn(() => { void client.invalidateQueries({queryKey:["network-sessions"],refetchType:"none"}); return true; }));
  await act(async () => button("network-session-kill").click());
  await act(async () => {});
  expect(network.killSession).not.toHaveBeenCalled();
});

it("does not retarget a queued session kill after the operator scope changes", async () => {
  vi.mocked(network.sessions).mockImplementation(async params => sessionPage(params,sessionRows().slice(0,1)));
  await render("/clusters/cluster/network?tab=sessions&hide_platform=false");
  await settle(() => expect(tableRows("sessions")).toHaveLength(1));
  vi.stubGlobal("confirm",vi.fn(() => true));
  await act(async () => { button("network-session-kill").click(); identity = {org_id:"other-org",user_id:"other-user"}; flushSync(rerender); });
  await act(async () => {});
  expect(network.killSession).not.toHaveBeenCalled();
  expect(host.querySelector('[data-testid="network-session-kill-result"]')).toBeNull();
});

it("restores group, local filters, incoming page and exact inspected pair together through history", async () => {
  await render();
  const second = { ...snapshot, group: "second-group", session_filters: { ...snapshot.session_filters, peer: "10.0.0.9", workload: "prod/second", node: "node-b" } };
  const next = new URLSearchParams(context); next.set("group","second-group"); next.set("conversation_page","3"); next.set("inspect_from","prod/second"); next.set("inspect_to","prod/destination");
  await act(async () => history.push(networkViewHref("cluster",next,"#second","network",second)));
  await settle(() => {
    expect(network.conversations).toHaveBeenLastCalledWith(expect.objectContaining({group:"second-group",offset:200,peer:"10.0.0.9"}));
    expect(network.sessions).toHaveBeenLastCalledWith(expect.objectContaining({group:"second-group",peer:"10.0.0.9",workload:"prod/second",node:"node-b"}));
    expect(host.querySelector('[data-testid="network-conversation-detail"]')?.textContent).toContain("prod/second → prod/destination");
    expect(new URLSearchParams(history.location.search).get("conversation_page")).toBe("3");
  });
  await act(async () => history.back()); await restored("Back restores original group and page");
  await act(async () => history.forward());
  await settle(() => {
    expect(new URLSearchParams(history.location.search).get("conversation_page")).toBe("3");
    expect(network.conversations).toHaveBeenLastCalledWith(expect.objectContaining({group:"second-group",offset:200,peer:"10.0.0.9"}));
    expect(host.querySelector('[data-testid="network-conversation-detail"]')?.textContent).toContain("prod/second → prod/destination");
    expect(history.location.hash).toBe("#second");
  });
});

it("preserves the saved group name while resolving API identity and saving later local edits", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({groups:[{id:"group-id",name:"production-services",kind:"ground",comment:"",criteria:[],members:[],learned_from:"",cfg_type:"user",policy_mode:"monitor",profile_mode:"monitor"}]});
  const named = {...snapshot, group:"production-services"}; const params = new URLSearchParams(context); params.set("group",named.group);
  await render(networkViewHref("cluster",params,"#evidence","network",named));
  await settle(() => {
    expect(network.conversations).toHaveBeenLastCalledWith(expect.objectContaining({group:"group-id",offset:300}));
    expect(networkViewSnapshotFromParams(new URLSearchParams(history.location.search))?.group).toBe("production-services");
  });
  await act(async () => {
    const input=host.querySelector<HTMLInputElement>('[data-testid="network-traffic-peer"]')!;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value")!.set!.call(input,"10.0.0.8");
    input.dispatchEvent(new Event("input",{bubbles:true}));
  });
  await settle(() => {
    expect(network.conversations).toHaveBeenLastCalledWith(expect.objectContaining({group:"group-id",peer:"10.0.0.8",offset:0}));
    const restored=networkViewSnapshotFromParams(new URLSearchParams(history.location.search));
    expect(restored?.group).toBe("production-services"); expect(restored?.session_filters.peer).toBe("10.0.0.8");
    expect(new URLSearchParams(history.location.search).get("inspect_from")).toBeNull();
  });
}, 15000);

it.each(["conversations", "sessions"] as const)("accepts %s page 20001 without substituting an earlier page", async kind => {
  vi.mocked(network.conversations).mockImplementation(async params => conversationPage(params, conversationRows()));
  vi.mocked(network.sessions).mockImplementation(async params => sessionPage(params, sessionRows()));
  const prefix = kind === "conversations" ? "conversation" : "session";
  await render(`/clusters/cluster/network?tab=${kind}&hide_platform=false&${prefix}_page=20001&context=keep`);
  await settle(() => {
    const read = kind === "conversations" ? network.conversations : network.sessions;
    expect(read).toHaveBeenLastCalledWith(expect.objectContaining({ cluster_id: "cluster", offset: 2_000_000, limit: 100, hide_platform: false }));
    expect(host.querySelector(`[data-testid="network-${kind}-table"]`)).not.toBeNull();
    expect(host.querySelector(`[data-testid="network-${kind}-tab"]`)?.textContent).toContain("405");
    expect(host.textContent).toContain("0–0");
    expect(host.textContent).not.toContain("NaN");
  });
  expect(new URLSearchParams(history.location.search).get(`${prefix}_page`)).toBe("20001");
  expect(history.location.search).toContain("context=keep");
  expect([...host.querySelectorAll("button")].some(b => b.textContent === "First page")).toBe(true);
});

it.each(["21474838", "NaN"])("rejects session page %s and resets only sorting/page while preserving filters", async page => {
  vi.mocked(network.sessions).mockImplementation(async params => sessionPage(params, sessionRows()));
  await render(`/clusters/cluster/network?tab=sessions&hide_platform=true&group=group-id&session_page=${page}&session_sort=workload&session_order=asc&context=keep`);
  await settle(() => expect(host.textContent).toContain("Reset sorting and page"));
  expect(network.sessions).not.toHaveBeenCalled();
  expect(host.querySelector('[data-testid="network-sessions-table"]')).toBeNull();
  await clickLabel("Reset sorting and page");
  await settle(() => {
    expect(network.sessions).toHaveBeenLastCalledWith(expect.objectContaining({ cluster_id: "cluster", group: "group-id", offset: 0, hide_platform: true }));
    expect(tableRows("sessions")).toHaveLength(100);
  });
  const params = new URLSearchParams(history.location.search);
  expect(params.get("session_page")).toBeNull(); expect(params.get("session_sort")).toBeNull(); expect(params.get("session_order")).toBeNull();
  expect(params.get("group")).toBe("group-id"); expect(params.get("hide_platform")).toBe("true"); expect(params.get("context")).toBe("keep");
  expect(host.textContent).not.toContain("NaN");
  expect(vi.mocked(network.sessions).mock.calls.every(([request]) => Number.isSafeInteger(request?.offset))).toBe(true);
});
