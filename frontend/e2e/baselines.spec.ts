// Wave L4 — screenshot the Process Baselines kanban + the card-detail drawer.
//
// Uses the running dev server at :5173 (matches e2e/elite-screens.spec.ts pattern).
import { test, expect } from "@playwright/test";

const BASE = "http://localhost:5173";
const API  = process.env.VITE_API_URL ?? "http://localhost:18080";

const CREDS = {
  email: "admin@dev",
  password: "devpass123",
};

test.use({ baseURL: BASE, viewport: { width: 1600, height: 1000 } });

test.beforeEach(async ({ page }) => {
  const resp = await page.request.post(`${API}/api/v1/auth/login`, { data: CREDS });
  if (!resp.ok()) throw new Error(`login failed: ${resp.status()}`);
  const { token } = await resp.json();
  await page.addInitScript((t) => {
    localStorage.setItem("constellation.token", t);
    localStorage.setItem("constellation.theme", "dark");
  }, token);
});

test("baselines page · main kanban + drawer", async ({ page }) => {
  // Resolve the constellation cluster id (deterministic in dev seed).
  const clustersResp = await page.request.get(`${API}/api/v1/clusters`, {
    headers: { Authorization: `Bearer ${(await page.request.post(`${API}/api/v1/auth/login`, { data: CREDS })).json().then((d: any) => d.token)}` },
  }).catch(() => null);

  // simpler: login and call clusters via fetch in-page
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
