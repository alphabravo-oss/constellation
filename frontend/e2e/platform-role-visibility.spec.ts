import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";

test("platform roles hide custom install namespaces and appear in inventory exports", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    } else if (path === `/clusters/${clusterId}/containers`) {
      await route.fulfill({ json: { cluster_id: clusterId, items: [
        { id: "platform", name: "platform-agent", namespace: "custom-install", platform_role: "core", node: "node", pod_name: "platform-pod", image: "platform:1", state: "CONTAINER_RUNNING", privileged: false, run_as_root: false, risk_score: 0, critical: 0, high: 0, observed_at: "2026-09-26T00:00:00Z" },
        { id: "app", name: "customer-app", namespace: "payments", node: "node", pod_name: "app-pod", image: "app:1", state: "CONTAINER_RUNNING", privileged: false, run_as_root: false, risk_score: 0, critical: 0, high: 0, observed_at: "2026-09-26T00:00:00Z" },
      ], summary: { total: 2, running: 2, privileged: 0, run_as_root: 0 } } });
    } else if (path === "/deployments") {
      await route.fulfill({ json: { deployments: [
        { id: "platform", namespace: "custom-install", platform_role: "core", name: "platform-agent", kind: "Deployment", risk_score: 0, risk_factors: {}, finding_count: 0, critical_count: 0, high_count: 0, last_seen_at: "2026-09-26T00:00:00Z" },
        { id: "app", namespace: "payments", name: "customer-app", kind: "Deployment", risk_score: 0, risk_factors: {}, finding_count: 0, critical_count: 0, high_count: 0, last_seen_at: "2026-09-26T00:00:00Z" },
      ] } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });

  await page.goto(`/clusters/${clusterId}/containers`);
  await expect(page.getByText("customer-app")).toBeVisible();
  await expect(page.getByText("platform-agent")).toHaveCount(0);
  await expect(page.getByTestId("platform-visibility-toggle")).toContainText("1");
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(page.getByText("platform-agent")).toBeVisible();
  const containerDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export CSV" }).click();
  const containerCsv = readFileSync(await (await containerDownload).path(), "utf8");
  expect(containerCsv).toContain("Platform Role");
  expect(containerCsv).toContain("core");

  await page.goto(`/clusters/${clusterId}/deployments`);
  await expect(page.getByText("platform-agent")).toBeVisible();
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(page.getByText("platform-agent")).toHaveCount(0);
  await expect(page.getByText("customer-app")).toBeVisible();
});

test("network sessions and conversations use API platform roles for visibility and CSV", async ({ page }) => {
  const platform = "custom-install/platform-agent";
  const customer = "payments/customer-app";
  const now = "2026-09-26T00:00:00Z";
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    } else if (path === "/network/map") {
      await route.fulfill({ json: { summary: { window_hours: 24, workloads: 0, flows: 0 }, workloads: [], flows: [], recent_flows: [] } });
    } else if (path === "/network/conversations") {
      await route.fulfill({ json: { conversations: [
        { from: platform, from_platform_role: "core", to: customer, bytes: 100, packets: 1, edges: 1, last_seen: now },
        { from: customer, to: "external/peer", bytes: 200, packets: 2, edges: 1, last_seen: now },
      ], nodes: [], node_kinds: {}, edges: [], window_hours: 24 } });
    } else if (path === "/network/sessions") {
      const session = (id: number, workload_id: string, platform_role?: string) => ({
        id, node: "node", workload_id, platform_role, application: "http", ip_proto: "tcp",
        client_ip: "10.0.0.1", client_port: 1234, server_ip: "10.0.0.2", server_port: 80,
        client_state: "established", server_state: "established", client_bytes: 100,
        server_bytes: 200, client_pkts: 1, server_pkts: 2, age: 10, idle: 1,
        ingress: false, severity: 0,
      });
      await route.fulfill({ json: { sessions: [session(1, platform, "core"), session(2, customer)], total: 2, limit: 100, has_more: false } });
    } else if (path === "/network/policies/lifecycle") {
      await route.fulfill({ json: { summary: { total: 0, ready: 0 }, items: [] } });
    } else if (path === "/runtime-threats") {
      await route.fulfill({ json: { threats: [] } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });

  await page.goto(`/clusters/${clusterId}/network?tab=conversations`);
  const conversations = page.getByTestId("network-conversations-table");
  await expect(conversations).toContainText(customer);
  await expect(conversations).not.toContainText(platform);
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(conversations).toContainText(platform);
  const conversationsDownload = page.waitForEvent("download");
  await page.getByTestId("network-conversations-export").click();
  expect(readFileSync(await (await conversationsDownload).path(), "utf8")).toContain("from_platform_role");

  await page.getByTestId("network-workspace-tab-sessions").click();
  const sessions = page.getByTestId("network-sessions-table");
  await expect(sessions).toContainText(platform);
  await page.getByTestId("platform-visibility-toggle").click();
  await expect(sessions).not.toContainText(platform);
  await expect(sessions).toContainText(customer);
  await page.getByTestId("platform-visibility-toggle").click();
  const sessionsDownload = page.waitForEvent("download");
  await page.getByTestId("network-sessions-export").click();
  const csv = readFileSync(await (await sessionsDownload).path(), "utf8");
  expect(csv).toContain("platform_role");
  expect(csv).toContain("core");
});
