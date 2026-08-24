// Wave L4 — screenshot the Process Baselines kanban + the card-detail drawer.
//
import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.use({ viewport: { width: 1600, height: 1000 } });

test.beforeEach(async ({ page }) => {
  await login(page, { theme: "dark" });
});

test("baselines page · main kanban + drawer", async ({ page }) => {
  // Resolve the first demo cluster id through the cluster picker.
  await page.goto("/clusters");
  await page.waitForLoadState("networkidle", { timeout: 12_000 }).catch(() => undefined);
  // Pick the first cluster card — it's "constellation" in the dev seed sort order.
  const firstClusterLink = page.locator("a[href*='/clusters/']").first();
  await firstClusterLink.waitFor({ timeout: 10_000 });
  const href = await firstClusterLink.getAttribute("href");
  const match = href?.match(/\/clusters\/([0-9a-f-]{36})/);
  const clusterId = match?.[1];
  if (!clusterId) throw new Error(`couldn't resolve cluster id from ${href}`);

  await page.goto(`/clusters/${clusterId}/runtime/baselines`);
  await page.waitForLoadState("networkidle", { timeout: 12_000 }).catch(() => undefined);
  await page.locator("[data-testid='baselines-columns']").waitFor({ timeout: 12_000 });
  await page.waitForTimeout(500);

  await page.screenshot({
    path: "e2e/screens-baseline/main.png",
    fullPage: true,
    animations: "disabled",
  });

  // Click the first card → drawer
  const firstCard = page.locator("[data-testid^='baselines-card-']").first();
  await firstCard.waitFor({ timeout: 10_000 });
  await firstCard.click();
  await page.locator("[data-testid='baselines-drawer-body']").waitFor({ timeout: 10_000 });
  await page.waitForTimeout(400);

  await page.screenshot({
    path: "e2e/screens-baseline/card-drawer.png",
    fullPage: true,
    animations: "disabled",
  });

  expect(true).toBeTruthy();
});
