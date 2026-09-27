import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";

test("conversation table CSV retains endpoint roles and cluster-scoped visibility", async ({ page }) => {
  const requested: URL[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    } else if (path === "/network/map") {
      requested.push(url);
      await route.fulfill({ json: { summary: { window_hours: 24, workloads: 0, flows: 0 }, workloads: [], flows: [], recent_flows: [] } });
    } else if (path === "/network/conversations") {
      requested.push(url);
      await route.fulfill({ json: { conversations: [
        { from: "custom-install/agent", from_platform_role: "core", to: "payments/app", bytes: 10, packets: 1, edges: 1, last_seen: "2026-09-26T00:00:00Z" },
        { from: "kube-system/legacy", to: "payments/app", bytes: 20, packets: 2, edges: 1, last_seen: "2026-09-26T00:00:00Z" },
        { from: "kube-system/tenant", from_platform_role: "tenant", to: "payments/app", to_platform_role: "tenant", bytes: 30, packets: 3, edges: 1, last_seen: "2026-09-26T00:00:00Z" },
      ], nodes: [], node_kinds: {}, edges: [], window_hours: 24 } });
    } else if (path === "/network/sessions") {
      requested.push(url);
      await route.fulfill({ json: { sessions: [], total: 0, limit: 100, has_more: false } });
    } else if (path === "/network/policies/lifecycle") {
      requested.push(url);
      await route.fulfill({ json: { summary: { total: 0, ready: 0 }, items: [] } });
    } else if (path === "/runtime-threats") {
      await route.fulfill({ json: { threats: [] } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });

  await page.goto(`/clusters/${clusterId}/network?tab=conversations`);
  const table = page.getByTestId("network-conversations-table");
  await expect(table).toContainText("kube-system/tenant");
  await expect(table).not.toContainText("custom-install/agent");
  await expect(table).not.toContainText("kube-system/legacy");
  expect(requested.map((url) => url.pathname)).toEqual(expect.arrayContaining([
    "/api/v1/network/map", "/api/v1/network/conversations", "/api/v1/network/policies/lifecycle",
  ]));
  expect(requested.every((url) => url.searchParams.get("cluster_id") === clusterId)).toBe(true);

  await page.getByTestId("platform-visibility-toggle").click();
  await expect(table).toContainText("custom-install/agent");
  await expect(table).toContainText("kube-system/legacy");
  const downloadPromise = page.waitForEvent("download");
  await page.getByTestId("network-conversations-table-export-csv").click();
  const csv = readFileSync(await (await downloadPromise).path(), "utf8");
  const lines = csv.trim().split(/\r?\n/);
  expect(lines[0]).toContain("from_platform_role");
  expect(lines[0]).toContain("to_platform_role");
  expect(lines.find((line) => line.includes("custom-install/agent"))).toContain("core");
  expect(lines.find((line) => line.includes("kube-system/legacy"))).not.toContain("core");
  expect(lines.find((line) => line.includes("kube-system/tenant"))).toContain("tenant");
  expect(lines).toHaveLength(4);
});
