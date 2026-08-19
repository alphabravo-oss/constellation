import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Vulnerability exceptions page shows workflow, guardrails, and status filters", async ({ page }) => {
  await page.goto("/exceptions");
  await expect(page.getByRole("heading", { name: "Vulnerability Exceptions" })).toBeVisible();
  await expect(page.getByTestId("exceptions-list").getByRole("heading", { name: "Payments API OpenSSL remediation window" })).toBeVisible();
  await expect(page.getByTestId("exceptions-inventory-table")).toContainText("payments-api");
  await expect(page.getByTestId("exception-workflow")).toContainText("Enforce expiration");
  await expect(page.getByTestId("exception-guardrails")).toContainText("Critical requires security approval");

  await page.getByTestId("exception-status-filters").getByRole("button", { name: "pending" }).click();
  await expect(page.getByTestId("exception-card")).toHaveCount(1);
  await expect(page.getByTestId("exceptions-list").getByRole("heading", { name: "Analytics notebook base image upgrade" })).toBeVisible();

  await page.getByTestId("exception-status-filters").getByRole("button", { name: "all" }).click();
  await page.getByTestId("exception-search").fill("log4j");
  await expect(page.getByTestId("exception-card")).toHaveCount(1);
  await expect(page.getByTestId("exceptions-list").getByRole("heading", { name: "Legacy staging Log4j exception" })).toBeVisible();
});

test("Vulnerability exceptions inventory includes revoked image acceptances", async ({ page }) => {
  await page.goto("/assets");
  await page.getByTestId("asset-row").filter({ hasText: "ghcr.io/demo/api" }).getByRole("link").click();

  const until = new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  await page.getByTestId("image-accept-rationale").fill("Temporary image exception for inventory evidence");
  await page.getByTestId("image-accept-until").fill(until);
  await page.getByTestId("image-accept-submit").click();
  await expect(page.getByTestId("image-acceptance-card")).toContainText("active");
  await page.getByTestId("image-accept-revoke").click();
  await expect(page.getByTestId("image-acceptance-card")).toContainText("revoked");

  await page.goto("/exceptions");
  await page.getByTestId("exception-status-filters").getByRole("button", { name: "revoked" }).click();
  await expect(page.getByTestId("exceptions-inventory-table")).toContainText("Temporary image exception for inventory evidence");
  await expect(page.getByTestId("exceptions-inventory-table")).toContainText("image.accept-risk.revoke");
});

test("Vulnerability exceptions inventory includes suppressed findings with detail audit", async ({ page }) => {
  await page.goto("/findings");
  await page.getByLabel("Kind").selectOption("iac");
  const firstRow = page.locator("tbody tr").first();
  await expect(firstRow).toBeVisible();
  await firstRow.locator("a").click();
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
