import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("System Health page shows components, incidents, and remediation actions", async ({ page }) => {
  await page.goto("/system-health");
  await expect(page.getByRole("heading", { name: "System Health" })).toBeVisible();
  await expect(page.getByTestId("system-health-component")).toHaveCount(9);
  await expect(page.getByTestId("system-health-components")).toContainText("CVE bundle and importer");
  await expect(page.getByTestId("system-health-incidents")).toContainText("EPSS enrichment");
  await expect(page.getByTestId("system-health-actions")).toContainText("Replay EPSS importer");

  await page.getByTestId("system-health-filters").getByRole("button", { name: "notifications" }).click();
  await expect(page.getByTestId("system-health-component")).toHaveCount(1);
  await expect(page.getByText("Integrations delivery")).toBeVisible();
});
