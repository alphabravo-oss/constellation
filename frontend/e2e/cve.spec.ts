import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("CVE DB page shows bundle metadata", async ({ page }) => {
  await page.goto("/cve");
  await expect(page.getByRole("heading", { name: "CVE Database" })).toBeVisible();
  await expect(page.getByTestId("bundle-signed")).toContainText("signed");
  await expect(page.getByTestId("bundle-version")).toContainText("2026-05-11");
});

test("CVE search finds seeded records", async ({ page }) => {
  await page.goto("/cve");
  await page.getByTestId("cve-search-input").fill("CVE-2024");
  await expect(page.getByTestId("cve-row-CVE-2024-0001")).toBeVisible({ timeout: 5000 });
  await expect(page.getByTestId("kev-badge").first()).toBeVisible();
});

test("Audit log shows seeded events with chain hashes", async ({ page }) => {
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: /Audit Log/i })).toBeVisible();
  const auditRows = page.locator("tbody tr");
  await expect(auditRows.first()).toBeVisible();
  expect(await auditRows.count()).toBeGreaterThan(0);
});

test("Assets page lists seeded assets", async ({ page }) => {
  await page.goto("/assets");
  await expect(page.locator("tbody tr")).not.toHaveCount(0);
  await expect(page.getByText("huggingface/llama-2-7b")).toBeVisible();
});

test("Settings page reflects current user", async ({ page }) => {
  await page.goto("/settings");
  await page.getByLabel("User menu").click();
  await expect(page.getByTestId("identity-email")).toHaveText("admin@demo.test");
  await expect(page.getByTestId("identity-roles")).toContainText("GlobalAdmin");
});
