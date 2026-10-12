import { test, expect } from "@playwright/test";
import { login } from "./utils";
import { assetEvidenceCluster, assetEvidencePath, installAssetEvidenceFixture } from "./fixtures/asset-evidence";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Vulnerability exceptions page shows workflow, guardrails, and status filters", async ({ page }) => {
  await page.goto("/exceptions");
  await expect(page.getByRole("heading", { name: "Vulnerability Exceptions" })).toBeVisible();
  await expect(page.getByTestId("exceptions-list")).toBeVisible();
  await expect(page.getByTestId("exceptions-inventory-table")).toBeVisible();
  await expect(page.getByTestId("exception-workflow")).toContainText("Enforce expiration");
  await expect(page.getByTestId("exception-guardrails")).toContainText("Critical requires security approval");

  await page.getByTestId("exception-status-filters").getByRole("button", { name: "all" }).click();
  await page.getByTestId("exception-search").fill("admin@demo.test");
  await expect(page.getByRole("heading", { name: "Vulnerability Exceptions" })).toBeVisible();
});

test("Vulnerability exceptions inventory includes mocked dedicated image acceptances and revocation", async ({ page }) => {
  const writes = await installAssetEvidenceFixture(page);
  await page.goto(`${assetEvidencePath}?tab=acceptance`);
  await page.getByRole("link", { name: "Accept image risk", exact: true }).click();
  const until = new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  await page.getByLabel(/^Rationale/).fill("Temporary image exception for inventory evidence");
  await page.getByLabel(/^Accepted until/).fill(until);
  await page.getByRole("button", { name: "Save acceptance", exact: true }).click();
  await expect(page.getByTestId("image-acceptance-result")).toContainText("recorded");
  await page.getByRole("link", { name: "Back to asset", exact: true }).click();
  await expect(page.getByTestId("image-acceptance-card")).toContainText("active");
  await page.getByRole("link", { name: "Revoke", exact: true }).click();
  await expect(page).toHaveURL(/\/image-acceptance\/[^/]+\/revoke$/);
  await expect(page.getByRole("heading", { name: "Revoke image risk acceptance", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Revoke acceptance", exact: true }).click();
  await expect(page.getByTestId("image-acceptance-result")).toContainText("revoked");
  await page.getByRole("link", { name: "Back to asset", exact: true }).click();
  await expect(page.getByTestId("image-acceptance-card")).toContainText("revoked");
  await page.goto(`/clusters/${assetEvidenceCluster}/exceptions?status=revoked&target=image`);
  await expect(page.getByTestId("exceptions-inventory-table")).toContainText("Temporary image exception for inventory evidence");
  await expect(page.getByTestId("exceptions-inventory-table")).toContainText("image.accept-risk.revoke");
  expect(writes).toHaveLength(2);
});

test("Vulnerability exceptions inventory includes suppressed findings with detail audit", async ({ page }) => {
  await page.goto("/findings");
  await page.getByLabel("Kind").selectOption("iac");
  const firstRow = page.locator("tbody tr").first();
  await expect(firstRow).toBeVisible();
  await firstRow.getByRole("button", { name: /S3 bucket has no encryption/i }).click();
  await page.waitForURL(/\/findings\/[a-f0-9-]+/);
  await page.getByRole("button", { name: /^Suppress$/ }).click();
  await expect(page.getByText(/Suppressed/i).first()).toBeVisible({ timeout: 5000 });
  await expect(page.getByTestId("finding-exception-link")).toBeVisible();
  await page.getByTestId("finding-exception-link").click();
  await expect(page).toHaveURL(/\/exceptions\?status=suppressed&target=finding&finding=/);

  await expect(page.getByTestId("exceptions-inventory-table")).toContainText("finding.suppress");
  await expect(page.getByTestId("exception-detail-panel")).toContainText("No expiry");
  await expect(page.getByTestId("exception-detail-audit")).toContainText("finding.suppress");
  await expect(page.getByTestId("exception-detail-scope")).toContainText("manual review");
});
