import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Findings list renders seeded rows sorted by risk score", async ({ page }) => {
  await page.goto("/findings");
  await expect(page.getByRole("heading", { name: /^Findings$/i })).toBeVisible();
  await expect(page.getByTestId("finding-state-tabs")).toContainText("Observed");
  await expect(page.getByTestId("finding-state-tabs")).toContainText("Accepted");
  await expect(page.getByTestId("finding-state-tabs")).toContainText("Suppressed");
  const rows = page.locator("tbody tr");
  await expect(rows.first()).toBeVisible();
  // Default view is the NeuVector-style CVE rollup, sorted by Constellation risk.
  await expect(rows.first()).toContainText("CVE-2024-0001");
  await expect(rows.first()).toContainText("glibc");
});

test("Filter by kind narrows the list", async ({ page }) => {
  await page.goto("/findings");
  // Switch off the default Observed filter to ensure we see all rows regardless of
  // any suppressed/accepted state from prior tests.
  await expect(page.locator("tbody tr").first()).toBeVisible();
  const kindSelect = page.locator("main select").first();
  await kindSelect.selectOption("license");
  await page.waitForTimeout(300);
  // license seed: at most a couple of rows.
  const after = await page.locator("tbody tr").count();
  expect(after).toBeGreaterThanOrEqual(0);
  expect(after).toBeLessThanOrEqual(5);
});

test("Row drawer opens with triage actions", async ({ page }) => {
  await page.goto("/findings");
  await page.getByTestId("findings-view-instances").click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
  // Title cell is a button in the redesigned table.
  await page.locator("tbody tr").first().getByRole("button", { name: /glibc heap overflow/i }).click();
  // Drawer shows Suppress + Accept-risk action buttons.
  await expect(page.getByRole("button", { name: /^Suppress$/ }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /Accept risk/ }).first()).toBeVisible();
});

test("Query input supports DSL chips", async ({ page }) => {
  await page.goto("/findings");
  await page.getByTestId("findings-view-instances").click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
  const queryBox = page.locator("input[placeholder*='severity:']");
  await queryBox.fill("severity:critical");
  // Should narrow rows to critical seed (~15 with seed).
  await page.waitForTimeout(300);
  const count = await page.locator("tbody tr").count();
  expect(count).toBeGreaterThan(0);
  expect(count).toBeLessThanOrEqual(20);
});

test("Suppressed lifecycle tab loads", async ({ page }) => {
  await page.goto("/findings");
  await page.getByRole("button", { name: /Suppressed/ }).first().click();
  // Should render a table (possibly empty); just verify the heading stays.
  await expect(page.getByRole("heading", { name: /^Findings$/i })).toBeVisible();
});
