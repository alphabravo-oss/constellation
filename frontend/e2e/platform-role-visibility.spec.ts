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
