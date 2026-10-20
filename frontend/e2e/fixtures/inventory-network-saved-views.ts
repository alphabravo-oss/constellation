import { expect, type Page } from "@playwright/test";
import type { NetworkSavedView, NetworkSavedViewSnapshot } from "../../src/lib/network-saved-views";
import { conversationInventory, networkFixtureCluster, notificationThreats, sessionInventory, threatInventory } from "./network-inventory";

export const savedViewCluster = networkFixtureCluster;
export const savedViewSnapshot: NetworkSavedViewSnapshot = {
  schema_version: 2,
  workspace_tab: "sessions",
  hours: 168,
  namespace: "prod",
  group: "",
  verdict: "block",
  verdicts_visible: { allow: false, alert: true, block: true },
  protocols: ["HTTPS"],
  namespaces: ["prod"],
  hide_platform_components: false,
  hidden_kinds: ["external"],
  scope_mode: "internal",
  session_filters: { protocol: "tcp", application: "7", port: "443", peer: "10.0.0.2", workload: "prod/api", node: "node-a" },
  pcap_filters: { status: "completed", workload: "prod/api", duration_s: 45, protocol: "tcp", src_ip: "10.0.0.1", dst_ip: "10.0.0.2", dst_port: "443", bpf_filter: "tcp port 443", interface: "eth0", file_count: "2", file_size_mb: "8" },
  conversation_filters: { from: "prod/client", to: "prod/api", verdict_group: "blocked" },
};
export interface SavedViewIdentity { org_id: string; user_id: string }
export function savedViewStorageKey(identity: SavedViewIdentity) {
  const key = `constellation:network-activity:saved-views:${savedViewCluster}:${identity.user_id}`;
  return `constellation.operator.${JSON.stringify([identity.org_id, identity.user_id, key])}`;
}
export function savedViewURL(snapshot = savedViewSnapshot) {
  const query = new URLSearchParams({ tab: snapshot.workspace_tab, hours: String(snapshot.hours), namespace: snapshot.namespace, verdict: snapshot.verdict, hide_platform: String(snapshot.hide_platform_components), from: snapshot.conversation_filters?.from ?? "", to: snapshot.conversation_filters?.to ?? "", verdict_group: snapshot.conversation_filters?.verdict_group ?? "", session_page: "3", conversation_page: "4", context: "dashboard", network_view: JSON.stringify(snapshot) });
  return `/clusters/${savedViewCluster}/network?${query}#evidence`;
}
export async function savedViewsFixture(page: Page) {
  const identity = { org_id: "org-a", user_id: "operator-a" };
  const requests: URL[] = [];
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url()), path = url.pathname.replace(/^\/api\/v1/, "");
    expect(route.request().method(), "Saved views must not mutate server policies or captures").toBe("GET");
    if (path === "/auth/me") return route.fulfill({ json: { ...identity, email: "operator@example.test", roles: ["GlobalAdmin"] } });
    if (path === "/clusters") return route.fulfill({ json: { clusters: [{ id: savedViewCluster, name: "Test cluster", state: "connected" }] } });
    if (path === "/groups") return route.fulfill({ json: { groups: [] } });
    if (["/network/map", "/network/conversations", "/network/sessions", "/network/policies/lifecycle", "/policies/dpi-threats"].includes(path) || path === "/runtime-threats" && url.searchParams.has("cluster_id")) {
      expect(url.searchParams.get("cluster_id"), `${path} scope`).toBe(savedViewCluster);
      requests.push(url);
    }
    if (path === "/network/map") return route.fulfill({ json: { summary: { window_hours: Number(url.searchParams.get("hours") || 24), selected_cluster_id: savedViewCluster, workloads: 0, flows: 0 }, workloads: [], flows: [], recent_flows: [] } });
    if (path === "/network/conversations") return route.fulfill({ json: conversationInventory(url, []) });
    if (path === "/network/sessions") return route.fulfill({ json: sessionInventory(url, []) });
    if (path === "/runtime-threats") return route.fulfill({ json: url.searchParams.has("cluster_id") ? threatInventory(url, []) : notificationThreats(url) });
    if (path === "/network/policies/lifecycle") return route.fulfill({ json: { summary: { selected_cluster_id: savedViewCluster, total: 0, ready: 0, discover: 0, monitor: 0, protect: 0, rollback_ready: 0, pending_approval: 0 }, items: [] } });
    if (path === "/policies/dpi-threats") return route.fulfill({ json: { cluster_id: savedViewCluster, weak_tls_enabled: false } });
    return route.fulfill({ status: 404, json: { error: `Unexpected saved-view fixture request: ${path}` } });
  });
  return { identity, requests };
}
export async function storedViews(page: Page, identity: SavedViewIdentity): Promise<NetworkSavedView[]> {
  return page.evaluate(key => JSON.parse(localStorage.getItem(key) || "[]"), savedViewStorageKey(identity));
}
export async function expectRestoredFilters(page: Page) {
  await expect(page.getByTestId("network-workspace-tab-sessions")).toHaveAttribute("data-state", "active");
  await expect(page.getByTestId("network-session-filter-protocol")).toHaveValue("tcp");
  await expect(page.getByTestId("network-session-filter-port")).toHaveValue("443");
  await expect(page.getByTestId("network-session-filter-peer")).toHaveValue("10.0.0.2");
  await expect(page.getByTestId("network-session-filter-workload")).toHaveValue("prod/api");
  await expect(page.getByTestId("network-session-filter-node")).toHaveValue("node-a");
  await expect(page.getByTestId("network-traffic-application")).toHaveValue("7");
  await expect.poll(() => JSON.parse(new URL(page.url()).searchParams.get("network_view") || "null")).toEqual(savedViewSnapshot);
}
export async function saveNamedView(page: Page, name: string) {
  await expect(page.getByTestId("network-saved-view-save")).toBeEnabled();
  await page.getByTestId("network-saved-view-save").click();
  await expect(page.getByRole("heading", { name: "Save network view", exact: true })).toBeVisible();
  await page.getByLabel(/^View name/).fill(name);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByTestId("network-saved-view-select").locator("option", { hasText: name })).toHaveCount(1);
}
