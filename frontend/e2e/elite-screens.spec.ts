import { test, expect } from "@playwright/test";

/**
 * elite-screens — captures dashboard / findings / risk / network / cve screenshots
 * for the elite UX overhaul.
 */
import { login } from "./utils";

test.use({ viewport: { width: 1440, height: 900 } });

test.beforeEach(async ({ page }) => {
  await login(page, { theme: "dark" });
});

const pages: Array<{ name: string; path: string; waitFor?: string }> = [
  { name: "01-dashboard", path: "/dashboard", waitFor: "[data-testid='widget-severity-distribution'], h1" },
  { name: "02-findings",  path: "/findings",  waitFor: "[data-testid='finding-state-tabs'], h1" },
  { name: "03-cve-detail", path: "/cve/CVE-2024-3094", waitFor: "h1" },
  { name: "04-network",   path: "/network",   waitFor: "h1" },
  { name: "05-risk-detail", path: "/risk/asset/asset-prod-checkout-frontend", waitFor: "h1" },
];

for (const p of pages) {
  test(`screenshot · ${p.name}`, async ({ page }) => {
    await page.goto(p.path);
    await page.waitForLoadState("networkidle", { timeout: 12_000 }).catch(() => undefined);
    if (p.waitFor) {
      await page.locator(p.waitFor).first().waitFor({ timeout: 12_000 }).catch(() => undefined);
    }
    await page.waitForTimeout(800); // settle animations
    await page.screenshot({
      path: `e2e/screens-elite/${p.name}.png`,
      fullPage: true,
      animations: "disabled",
    });
    expect(true).toBeTruthy();
  });
}

test("screenshot · 06-command-palette", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle", { timeout: 12_000 }).catch(() => undefined);
  await page.waitForTimeout(600);
  await page.keyboard.press("Control+K");
  await page.waitForTimeout(300);
  // cmdk uses an input near the dialog
  const input = page.locator("input[placeholder*='Search']").first();
  if (await input.count()) await input.fill("find");
  await page.waitForTimeout(300);
  await page.screenshot({ path: "e2e/screens-elite/06-command-palette.png", animations: "disabled" });
});
