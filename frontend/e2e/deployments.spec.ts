import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Risk Dashboard ranks deployments by risk score", async ({ page }) => {
  await page.goto("/deployments");
  await expect(page.getByRole("heading", { name: /Deployments at risk/i })).toBeVisible();
  await expect(page.getByTestId("deployments-table")).toBeVisible();

  // Seed has api-service at risk 92 + frontend at 71 → api-service should sort first.
  const firstRow = page.locator('[data-testid="deployment-row"]').first();
  await expect(firstRow).toContainText("api-service");
  await expect(firstRow).toContainText("92"); // risk score from seed
});

test("Drill into a deployment shows violation timeline", async ({ page }) => {
  await page.goto("/deployments");
  await page.locator('[data-testid="deployment-row"]').first().getByRole("link").click();
  await expect(page.getByRole("heading", { name: /default\/api-service/i })).toBeVisible();
  await expect(page.getByTestId("deployment-action-controls")).toBeVisible();
  await expect(page.getByTestId("deployment-policy-actions")).toBeVisible();
  await expect(page.getByTestId("deployment-quarantine-actions")).toBeVisible();
  await expect(page.getByTestId("deployment-threat-pivots")).toBeVisible();
  await expect(page.getByTestId("deployment-violations")).toBeVisible();
  await expect(page.getByTestId("deployment-process-baseline")).toBeVisible();
  await expect(page.getByTestId("deployment-process-baseline-actions")).toBeVisible();
  await expect(page.getByTestId("deployment-process-baseline-reason")).toBeVisible();
  await expect(page.getByTestId("deployment-file-profile")).toBeVisible();
  await expect(page.getByTestId("deployment-file-profile-actions")).toBeVisible();
  await expect(page.getByTestId("deployment-file-profile-reason")).toBeVisible();
  await expect(page.getByTestId("deployment-file-profile-rule-form")).toBeVisible();
  await expect(page.getByTestId("deployment-file-profile-rule-filter")).toBeVisible();
  await expect(page.getByTestId("deployment-file-profile-rule-behavior")).toBeVisible();
  await expect(page.getByTestId("deployment-file-profile-rule-reason")).toBeVisible();
  // Seed adds violations for api-service.
  await expect(page.locator('[data-testid="deployment-violations"] > div').first()).toBeVisible();
});
