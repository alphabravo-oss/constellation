import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { conversation, conversationInventory, networkCSV, networkFixtureCluster as clusterId, networkFixtureAt as now, notificationThreats, session, sessionInventory, threatInventory } from "./fixtures/network-inventory";

test("platform roles hide custom install namespaces and appear in inventory exports", async ({ page }) => {
  const requested: URL[] = [];
  const containers = [
    { row_id: JSON.stringify(["node", 1]), id: "platform", name: "platform-agent", namespace: "custom-install", platform_role: "core", node: "node", pod_name: "platform-pod", image: "platform:1", state: "CONTAINER_RUNNING", privileged: false, run_as_root: false, risk_score: 0, critical: 0, high: 0, observed_at: now },
    { row_id: JSON.stringify(["node", 2]), id: "app", name: "customer-app", namespace: "payments", platform_role: "", node: "node", pod_name: "app-pod", image: "app:1", state: "CONTAINER_RUNNING", privileged: false, run_as_root: false, risk_score: 0, critical: 0, high: 0, observed_at: now },
  ];
  const deployments = containers.map(row => ({ id: row.id, cluster_id: clusterId, namespace: row.namespace, platform_role: row.platform_role, name: row.name, kind: "Deployment", risk_score: 0, risk_factors: {}, finding_count: 0, critical_count: 0, high_count: 0, last_seen_at: now }));
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url()), path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    else if (path === "/clusters") await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    else if ([`/clusters/${clusterId}/containers`, `/clusters/${clusterId}/containers.csv`].includes(path)) {
      requested.push(url);
      const matching = containers.filter(row => url.searchParams.get("hide_platform") !== "true" || row.platform_role !== "core");
      if (path.endsWith(".csv")) { expect(url.searchParams.get("hide_platform")).toBe("false"); await route.fulfill({ contentType: "text/csv", headers: { "X-Export-Total": String(matching.length), "X-Export-Limit": "100000", "X-Export-Truncated": "false" }, body: ["Name,Platform role", ...matching.map(row => `${row.name},${row.platform_role}`)].join("\n") }); }
      else { expect(url.searchParams.get("limit")).toBe("100"); await route.fulfill({ json: { cluster_id: clusterId, items: matching, total: matching.length, limit: 100, offset: 0, has_more: false, sort: url.searchParams.get("sort") || "risk", order: url.searchParams.get("order") || "desc", summary: { total: matching.length, running: matching.length, privileged: 0, run_as_root: 0, platform_count: 1 } } }); }
    } else if (path === "/deployments") {
      requested.push(url); expect(url.searchParams.get("cluster_id")).toBe(clusterId);
      const matching = deployments.filter(row => url.searchParams.get("hide_platform") !== "true" || row.platform_role !== "core");
      await route.fulfill({ json: { deployments: matching, total: matching.length, limit: 100, offset: 0, has_more: false, platform_count: 1, summary: { total: matching.length, at_risk: 0, finding_count: 0, critical_count: 0, high_count: 0 } } });
    } else await route.fulfill({ status: 404, json: { error: `Unexpected fixture request ${path}` } });
  });
  await page.goto(`/clusters/${clusterId}/containers`);
  await expect(page.getByText("customer-app", { exact: true })).toBeVisible();
  await expect(page.getByText("platform-agent", { exact: true })).toHaveCount(0);
  await expect(page.getByTestId("platform-visibility-toggle")).toContainText("1");
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(page.getByText("platform-agent", { exact: true })).toBeVisible();
  const containerDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export matching containers CSV", exact: true }).click();
  const containerCSV = readFileSync(await (await containerDownload).path(), "utf8");
  expect(containerCSV).toContain("Platform role");
  expect(containerCSV).toContain("platform-agent,core");
  expect(containerCSV.trim().split(/\r?\n/)).toHaveLength(3);
  expect(requested.some(url => url.pathname === `/api/v1/clusters/${clusterId}/containers` && url.searchParams.get("hide_platform") === "true")).toBe(true);

  await page.goto(`/clusters/${clusterId}/deployments`);
  await expect(page.getByText("custom-install/platform-agent", { exact: true })).toBeVisible();
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(page.getByText("custom-install/platform-agent", { exact: true })).toHaveCount(0);
  await expect(page.getByText("payments/customer-app", { exact: true })).toBeVisible();
  expect(requested.some(url => url.pathname === "/api/v1/deployments" && url.searchParams.get("hide_platform") === "true")).toBe(true);
});

test("network sessions and conversations use API platform roles for visibility and CSV", async ({ page }) => {
  const platform = "custom-install/platform-agent", customer = "payments/customer-app";
  const pairs = [conversation(platform, customer, { from_platform_role: "core", bytes: 100 }), conversation(customer, "external/peer", { bytes: 200 })];
  const sessions = [session(1, platform, { platform_role: "core" }), session(2, customer)];
  const requested: URL[] = [];
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url()), path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    else if (path === "/clusters") await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    else if (path === "/groups") await route.fulfill({ json: { groups: [] } });
    else if (path === "/network/map") await route.fulfill({ json: { summary: { window_hours: 24, selected_cluster_id: clusterId, workloads: 0, flows: 0 }, workloads: [], flows: [], recent_flows: [] } });
    else if (path === "/network/conversations") { requested.push(url); await route.fulfill({ json: conversationInventory(url, pairs) }); }
    else if (path === "/network/sessions") { requested.push(url); await route.fulfill({ json: sessionInventory(url, sessions) }); }
    else if (path === "/network/conversations.csv") { requested.push(url); await networkCSV(route, url, "conversations", pairs); }
    else if (path === "/network/sessions.csv") { requested.push(url); await networkCSV(route, url, "sessions", sessions); }
    else if (path === "/network/policies/lifecycle") await route.fulfill({ json: { summary: { total: 0, ready: 0 }, items: [] } });
    else if (path === "/runtime-threats") await route.fulfill({ json: url.searchParams.has("cluster_id") ? threatInventory(url, []) : notificationThreats(url) });
    else if (path === "/policies/dpi-threats") await route.fulfill({ json: { cluster_id: clusterId, weak_tls_enabled: false } });
    else await route.fulfill({ status: 404, json: { error: `Unexpected fixture request ${path}` } });
  });
  await page.goto(`/clusters/${clusterId}/network?tab=conversations`);
  const conversations = page.getByTestId("network-conversations-table");
  await expect(conversations.locator("tbody tr")).toHaveCount(1);
  await expect(conversations).toContainText(customer);
  await expect(conversations).not.toContainText(platform);
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(conversations.locator("tbody tr")).toHaveCount(2);
  await expect(conversations).toContainText(platform);
  const conversationDownload = page.waitForEvent("download");
  await page.getByTestId("network-conversations-tab").getByRole("button", { name: "Export matching CSV", exact: true }).click();
  const conversationCSV = readFileSync(await (await conversationDownload).path(), "utf8");
  expect(conversationCSV).toContain("from_platform_role");
  expect(conversationCSV).toContain("core");

  await page.getByTestId("network-workspace-tab-sessions").click();
  const table = page.getByTestId("network-sessions-table");
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await expect(table).toContainText(platform);
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).not.toContainText(platform);
  await expect(table).toContainText(customer);
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(table.locator("tbody tr")).toHaveCount(2);
  const sessionDownload = page.waitForEvent("download");
  await page.getByTestId("network-sessions-tab").getByRole("button", { name: "Export matching CSV", exact: true }).click();
  const sessionCSV = readFileSync(await (await sessionDownload).path(), "utf8");
  expect(sessionCSV).toContain("platform_role"); expect(sessionCSV).toContain("core");
  expect(sessionCSV.trim().split(/\r?\n/)).toHaveLength(3);
  for (const endpoint of ["/network/conversations", "/network/sessions"]) expect(requested.some(url => url.pathname.endsWith(endpoint) && url.searchParams.get("hide_platform") === "true" && url.searchParams.get("cluster_id") === clusterId)).toBe(true);
  for (const endpoint of ["/network/conversations.csv", "/network/sessions.csv"]) expect(requested.some(url => url.pathname.endsWith(endpoint) && url.searchParams.get("hide_platform") === "false" && url.searchParams.get("cluster_id") === clusterId)).toBe(true);
});
