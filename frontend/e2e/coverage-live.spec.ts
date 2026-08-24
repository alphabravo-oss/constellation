import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.use({ viewport: { width: 1440, height: 1000 } });

test.beforeEach(async ({ page }) => {
  await login(page, { theme: "dark" });
});

test("screenshot · coverage-live", async ({ page }) => {
  await page.goto("/coverage");
  // Page hero
  await expect(page.getByRole("heading", { name: "Posture" })).toBeVisible({ timeout: 12_000 });
  await page.waitForLoadState("networkidle", { timeout: 12_000 }).catch(() => undefined);
  // Wait for the cluster picker to populate so cluster-scoped rows have data.
  const picker = page.getByTestId("coverage-cluster-picker");
  await expect(picker).toBeVisible();
  // Wait a beat for queries to settle (multiple parallel /api/v1 fetches).
  await page.waitForTimeout(1500);
  await page.screenshot({
    path: "e2e/screens-posture/coverage-live.png",
    fullPage: true,
    animations: "disabled",
  });
});
