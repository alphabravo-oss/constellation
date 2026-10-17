import { expect, test } from "@playwright/test";
import { conversation, conversationInventory, networkFixtureCluster as clusterId, notificationThreats, session, sessionInventory, threat, threatInventory } from "./fixtures/network-inventory";

test("network activity uses shared filters and server pages", async ({ page }) => {
  const requests: URL[] = [];
  const pairs = Array.from({ length: 250 }, (_, index) => conversation(`default/client-${index}`, "default/server", { bytes: index + 1, apps: ["7"], port: 443, peers: ["10.0.0.2"] }));
  const sessions = Array.from({ length: 250 }, (_, index) => session(index + 1, `default/client-${index}`, { client_bytes: index + 1 }));
  const threats = Array.from({ length: 250 }, (_, index) => threat(index));
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url()), path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    else if (path === "/clusters") await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    else if (path === "/groups") await route.fulfill({ json: { groups: [] } });
    else if (path === "/network/map") { requests.push(url); expect(url.searchParams.get("cluster_id")).toBe(clusterId); await route.fulfill({ json: { summary: { window_hours: 24, selected_cluster_id: clusterId, workloads: 0, flows: 0 }, workloads: [], flows: [], recent_flows: [] } }); }
    else if (path === "/network/conversations") { requests.push(url); await route.fulfill({ json: conversationInventory(url, pairs) }); }
    else if (path === "/network/sessions") { requests.push(url); await route.fulfill({ json: sessionInventory(url, sessions) }); }
    else if (path === "/runtime-threats") { if (url.searchParams.has("cluster_id")) requests.push(url); await route.fulfill({ json: url.searchParams.has("cluster_id") ? threatInventory(url, threats) : notificationThreats(url) }); }
    else if (path === "/network/policies/lifecycle") await route.fulfill({ json: { summary: { total: 0, ready: 0, discover: 0, monitor: 0, protect: 0, rollback_ready: 0, pending_approval: 0 }, items: [] } });
    else if (path === "/policies/dpi-threats") await route.fulfill({ json: { cluster_id: clusterId, weak_tls_enabled: false } });
    else await route.fulfill({ status: 404, json: { error: `Unexpected fixture request ${path}` } });
  });

  await page.goto(`/clusters/${clusterId}/network?tab=sessions`);
  await page.getByTestId("network-traffic-port").fill("443");
  await page.getByTestId("network-traffic-peer").fill("10.0.0.2");
  await page.getByTestId("network-traffic-application").fill("7");
  const sessionView = page.getByTestId("network-sessions-tab");
  await expect(sessionView).toContainText("of 250");
  await expect(sessionView.locator("tbody tr")).toHaveCount(100);
  await sessionView.getByRole("button", { name: "Next", exact: true }).click();
  await expect(sessionView).toContainText("Page 2 of 3");
  await expect.poll(() => requests.some(url => url.pathname.endsWith("/network/sessions") && url.searchParams.get("offset") === "100" && url.searchParams.get("port") === "443" && url.searchParams.get("application") === "7" && url.searchParams.get("peer") === "10.0.0.2" && url.searchParams.get("sort") === "bytes")).toBe(true);

  await page.getByTestId("network-workspace-tab-conversations").click();
  const pairView = page.getByTestId("network-conversations-tab");
  await expect(pairView).toContainText("of 250");
  await pairView.getByRole("button", { name: "Next", exact: true }).click();
  await expect(pairView).toContainText("Page 2 of 3");
  await pairView.getByRole("button", { name: "Volume", exact: true }).click();
  await expect(pairView).toContainText("Page 1 of 3");
  await expect.poll(() => requests.some(url => url.pathname.endsWith("/network/conversations") && url.searchParams.get("sort") === "bytes" && url.searchParams.get("order") === "desc" && url.searchParams.get("offset") === "0")).toBe(true);
  await expect(pairView.locator("tbody tr").first()).toContainText("default/client-249");
  await pairView.getByRole("button", { name: "Volume", exact: true }).click();
  await expect.poll(() => requests.some(url => url.pathname.endsWith("/network/conversations") && url.searchParams.get("sort") === "bytes" && url.searchParams.get("order") === "asc" && url.searchParams.get("offset") === "0")).toBe(true);
  await expect(pairView.locator("tbody tr").first()).toContainText("default/client-0");
  await page.goBack();
  await expect(pairView.locator("tbody tr").first()).toContainText("default/client-249");
  await page.goBack();
  await expect(pairView).toContainText("Page 2 of 3");
  await expect.poll(() => new URL(page.url()).searchParams.get("conversation_page")).toBe("2");

  await page.getByTestId("network-workspace-tab-threats").click();
  const threatView = page.getByTestId("network-threats-tab");
  await expect(threatView).toContainText("of 250");
  await threatView.getByRole("button", { name: "Next", exact: true }).click();
  await expect(threatView).toContainText("Page 2 of 3");
  await expect(threatView.locator("tbody tr")).toHaveCount(100);
  for (const endpoint of ["/network/map", "/network/conversations", "/network/sessions", "/runtime-threats"]) expect(requests.some(url => url.pathname.endsWith(endpoint) && url.searchParams.get("cluster_id") === clusterId && url.searchParams.get("port") === "443" && url.searchParams.get("peer") === "10.0.0.2" && url.searchParams.get("application") === "7")).toBe(true);
  for (const [endpoint, sort] of [["/network/conversations", "last_seen"], ["/network/sessions", "bytes"], ["/runtime-threats", "at"]]) expect(requests.some(url => url.pathname.endsWith(endpoint) && url.searchParams.get("limit") === "100" && url.searchParams.get("sort") === sort && url.searchParams.get("order") === "desc")).toBe(true);
});
