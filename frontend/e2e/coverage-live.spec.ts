import { test, expect } from "@playwright/test";

/**
 * coverage-live — screenshot the live Posture Maturity dashboard at /coverage
 * (Wave L3). Pointed at the dev server on :5173 directly (not Playwright's
 * webServer) so it works against the developer-seeded admin account.
 */
const BASE = "http://localhost:5173";
const API = process.env.VITE_API_URL ?? "http://localhost:18080";

const CREDS = {
  email: "admin@dev",
  password: "devpass123",
};

test.use({ baseURL: BASE, viewport: { width: 1440, height: 1000 } });

test.beforeEach(async ({ page }) => {
  const resp = await page.request.post(`${API}/api/v1/auth/login`, { data: CREDS });
  if (!resp.ok()) throw new Error(`login failed: ${resp.status()}`);
  const { token } = await resp.json();
  await page.addInitScript((t) => {
    localStorage.setItem("constellation.token", t);
    localStorage.setItem("constellation.theme", "dark");
  }, token);
});

test("screenshot · coverage-live", async ({ page }) => {
  await page.goto("/coverage");
  // Page hero
  await expect(page.getByRole("heading", { name: "Posture Maturity" })).toBeVisible({ timeout: 12_000 });
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
