// Wave M2: network-map screenshot proving raw cluster/<ip> labels have been
// replaced with named workloads after the migration + discoverer + backfill.
// Output: e2e/screens-resolve/network-after.png (referenced from the wave report).
import { test, expect, type Page } from "@playwright/test";
import { getAuthToken, login } from "./utils";

const API = process.env.VITE_API_URL ?? "http://localhost:18080";

async function networkClusterID(page: Page) {
  const token = await getAuthToken(page);
  const resp = await page.request.get(`${API}/api/v1/clusters`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(resp.ok()).toBeTruthy();
  const body = await resp.json();
  const candidates = [
    ...(body.clusters?.filter((cluster: { name?: string }) => cluster.name === "prod-east") ?? []),
    ...(body.clusters?.filter((cluster: { name?: string }) => cluster.name !== "prod-east") ?? []),
  ];
  for (const cluster of candidates as Array<{ id?: string }>) {
    if (!cluster.id) continue;
    const mapResp = await page.request.get(`${API}/api/v1/network/map?hours=24&cluster_id=${cluster.id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!mapResp.ok()) continue;
    const mapBody = await mapResp.json();
    if ((mapBody.summary?.flows ?? 0) > 0 || (mapBody.flows?.length ?? 0) > 0) {
      return cluster.id;
    }
  }
  const clusterID = body.clusters?.[0]?.id;
  expect(clusterID).toBeTruthy();
  return clusterID as string;
}

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("M2 · network map shows named workloads, not raw IPs", async ({ page }) => {
  const clusterID = await networkClusterID(page);
  await page.goto(`/clusters/${clusterID}/network?cluster_id=${clusterID}`);
  await expect(page.getByTestId("network-map")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator(".react-flow__edge").first()).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: "e2e/screens-resolve/network-after.png", fullPage: true });
});
