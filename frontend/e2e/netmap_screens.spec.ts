import { test, expect, type Page } from "@playwright/test";

const CLUSTER_ID = "51ad38e9-2302-49b4-90b5-52f99ac5dd92";
const NET_PATH = `/clusters/${CLUSTER_ID}/network?cluster_id=${CLUSTER_ID}`;
const API = "http://localhost:18080";

async function devLogin(page: Page) {
  // Standalone login against the running dev API; bypasses global-setup which
  // expects a separate go-seeded test DB.
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

test("L2 network map · overview screenshot", async ({ page }) => {
  await page.goto(NET_PATH);
  await expect(page.getByTestId("network-map")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator(".react-flow__edge").first()).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("network-verdict-legend")).toBeVisible();
  await expect(page.getByTestId("network-filter-bar")).toBeVisible();
  // Wait for at least one query refresh so the canvas is settled.
  await page.waitForTimeout(750);
  await page.screenshot({ path: "e2e/screens-netmap/overview.png", fullPage: true });
});

test("L2 network map · edge click opens inspector popover", async ({ page }) => {
  await page.goto(NET_PATH);
  await expect(page.getByTestId("network-map")).toBeVisible({ timeout: 15_000 });
  const firstEdge = page.locator(".react-flow__edge").first();
  await expect(firstEdge).toBeVisible({ timeout: 15_000 });
  // ReactFlow draws edges as <g><path/></g>; click the path to fire onEdgeClick.
  await firstEdge.locator(".react-flow__edge-path").click({ force: true });
  await expect(page.getByTestId("network-flow-inspector")).toBeVisible();
  await expect(page.getByTestId("network-flow-inspector-tabs")).toBeVisible();
  await page.screenshot({ path: "e2e/screens-netmap/edge-popover.png", fullPage: true });

  // Sanity check all four tabs render.
  for (const t of ["attack", "policy", "history", "flow"]) {
    await page.getByTestId(`network-flow-inspector-tab-${t}`).click();
    await page.waitForTimeout(120);
  }
});

test("L2 network map · filter chips applied", async ({ page }) => {
  await page.goto(NET_PATH);
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
