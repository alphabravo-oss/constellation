import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("System Health page shows components, incidents, and remediation actions", async ({ page }) => {
  await page.goto("/system-health");
  await expect(page.getByRole("heading", { name: "System Health" })).toBeVisible();
  await expect(page.getByTestId("system-health-fleet-tiles")).toContainText("Healthy components");
  await expect(page.getByTestId("system-health-clusters")).toContainText("prod-east");

  await page.getByRole("tab", { name: /Components/i }).click();
  await expect(page.getByTestId("system-health-heartbeats")).toContainText("scanner");

  await page.getByRole("tab", { name: /Incidents & Actions/i }).click();
  await expect(page.getByTestId("system-health-incidents")).toContainText(/No active incidents|EPSS enrichment/);
  await expect(page.getByTestId("system-health-actions")).toContainText(/No open actions|Replay EPSS importer/);
});
