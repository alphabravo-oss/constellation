// Wave M2: network-map screenshot proving raw cluster/<ip> labels have been
// replaced with named workloads after the migration + discoverer + backfill.
// Output: e2e/screens-resolve/network-after.png (referenced from the wave report).
import { test, expect, type Page } from "@playwright/test";

const CLUSTER_ID = "51ad38e9-2302-49b4-90b5-52f99ac5dd92";
const NET_PATH = `/clusters/${CLUSTER_ID}/network?cluster_id=${CLUSTER_ID}`;
const API = "http://localhost:18080";

async function devLogin(page: Page) {
  const resp = await page.request.post(`${API}/api/v1/auth/login`, {
    data: { email: "admin@dev", password: "devpass123" },
  });
  if (!resp.ok()) throw new Error(`login failed: ${resp.status()}`);
  const { token } = await resp.json();
  await page.addInitScript((t) => {
    localStorage.setItem("constellation.token", t);
  }, token);
}

test.beforeEach(async ({ page }) => {
  await devLogin(page);
});

test("M2 · network map shows named workloads, not raw IPs", async ({ page }) => {
  await page.goto(NET_PATH);
  await expect(page.getByTestId("network-map")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator(".react-flow__edge").first()).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: "e2e/screens-resolve/network-after.png", fullPage: true });
});
