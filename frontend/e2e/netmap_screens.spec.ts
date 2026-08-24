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

test("L2 network map · overview screenshot", async ({ page }) => {
  const clusterID = await networkClusterID(page);
  await page.goto(`/clusters/${clusterID}/network?cluster_id=${clusterID}`);
  await expect(page.getByTestId("network-map")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator(".react-flow__edge").first()).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("network-verdict-legend")).toBeVisible();
  await expect(page.getByTestId("network-filter-bar")).toBeVisible();
  // Wait for at least one query refresh so the canvas is settled.
  await page.waitForTimeout(750);
  await page.screenshot({ path: "e2e/screens-netmap/overview.png", fullPage: true });
});

test("L2 network map · edge click opens inspector popover", async ({ page }) => {
  const clusterID = await networkClusterID(page);
  await page.goto(`/clusters/${clusterID}/network?cluster_id=${clusterID}`);
  await expect(page.getByTestId("network-map")).toBeVisible({ timeout: 15_000 });
  const firstEdge = page.locator(".react-flow__edge").first();
  await expect(firstEdge).toBeVisible({ timeout: 15_000 });
  // ReactFlow draws edges as <g><path/></g>; click the path to fire onEdgeClick.
  await firstEdge.locator(".react-flow__edge-path").click({ force: true });
  await expect(page.getByTestId("network-flow-inspector")).toBeVisible();
  await expect(page.getByTestId("network-flow-inspector-tabs")).toBeVisible();
  await page.screenshot({ path: "e2e/screens-netmap/edge-popover.png", fullPage: true });

  // Sanity check the primary inspector tabs render.
  for (const t of ["threat", "policy", "history", "flow"]) {
    await page.getByTestId(`network-flow-inspector-tab-${t}`).click();
    await page.waitForTimeout(120);
  }
});

test("L2 network map · filter chips applied", async ({ page }) => {
  const clusterID = await networkClusterID(page);
  await page.goto(`/clusters/${clusterID}/network?cluster_id=${clusterID}`);
  await expect(page.getByTestId("network-filter-bar")).toBeVisible({ timeout: 15_000 });
  // Toggle "Allow" chip off to leave only alert/block edges, then flip the
  // scope segmented to External.
  await page.getByTestId("netchip-verdict-allow").click();
  await page.getByTestId("netchip-scope-external").click();
  // Click the verdict legend's "allow" entry to re-enable it (validates the
  // top-right canvas legend is wired to the same state).
  await page.getByTestId("network-legend-allow").click();
  await page.waitForTimeout(400);
  await page.screenshot({ path: "e2e/screens-netmap/filters-applied.png", fullPage: true });
});
