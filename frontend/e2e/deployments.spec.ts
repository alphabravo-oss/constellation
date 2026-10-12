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

test("Deployment workspace tabs preserve evidence and dedicated authoring links", async ({ page }) => {
  await page.goto("/deployments");
  await page.locator('[data-testid="deployment-row"]').first().getByRole("link", { name: "default/api-service" }).click();
  await expect(page.getByRole("heading", { name: /default\/api-service/i })).toBeVisible();
  const deploymentPath = new URL(page.url()).pathname;
  await expect(page.getByRole("tab", { name: "Overview", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Network", exact: true }).click();
  await expect(page).toHaveURL(/\?tab=network$/);
  await expect(page.getByTestId("deployment-action-controls")).toBeVisible();
  await expect(page.getByTestId("deployment-policy-actions")).toBeVisible();
  await expect(page.getByTestId("deployment-quarantine-actions")).toBeVisible();
  await page.getByRole("tab", { name: "Runtime", exact: true }).click();
  await expect(page).toHaveURL(/\?tab=runtime$/);
  await expect(page.getByTestId("deployment-threat-pivots")).toBeVisible();
  await expect(page.getByTestId("deployment-process-baseline")).toBeVisible();
  await expect(page.getByTestId("deployment-process-baseline-actions")).toBeVisible();
  await expect(page.getByRole("link", { name: "Open process baseline detail" })).toHaveAttribute("href", /\/runtime\/baselines\//);
  await page.getByRole("tab", { name: "Files", exact: true }).click();
  await expect(page).toHaveURL(/\?tab=files$/);
  await expect(page.getByTestId("deployment-file-profile")).toBeVisible();
  await expect(page.getByTestId("deployment-file-profile-actions")).toBeVisible();
  const ruleLink = page.getByTestId("deployment-file-profile-rule-add");
  await expect(ruleLink).toHaveAttribute("href", /\/file-monitor\/new\?workload=.+&return_to=/);
  await ruleLink.click();
  await expect(page.getByTestId("file-monitor-form-page")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Add monitor rule", exact: true })).toBeVisible();
  await expect(page.getByRole("textbox", { name: /^Path filter/ })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Reason", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(`${deploymentPath}?tab=files`);
  await page.getByTestId("deployment-file-profile-exception-add").click();
  await expect(page.getByRole("heading", { name: "Add file monitor exception", exact: true })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Reason", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(`${deploymentPath}?tab=files`);
  await page.getByRole("tab", { name: "Compliance", exact: true }).click();
  await expect(page).toHaveURL(/\?tab=compliance$/);
  await expect(page.getByTestId("deployment-compliance-evidence")).toBeVisible();
  await expect(page.getByTestId("deployment-violations")).toBeVisible();
  // Seed adds violations for api-service.
  await expect(page.getByTestId("deployment-violations").locator("tbody tr").first()).toBeVisible();
});
