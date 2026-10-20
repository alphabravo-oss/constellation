import { expect, test } from "@playwright/test";
import { firstClusterId, settled } from "./helpers";

const H = { "X-Constellation-Client": "browser" };

test("theme choice is stored server-side (GET/PUT /me/preferences)", async ({ page }) => {
  const before = await (await page.request.get("/api/v1/me/preferences", { headers: H })).json() as { theme: string };
  await page.goto("/clusters");
  await settled(page);
  const toggle = page.getByRole("button", { name: /^Theme: / });
  await toggle.click();
  await expect.poll(async () => ((await (await page.request.get("/api/v1/me/preferences", { headers: H })).json()) as { theme: string }).theme).not.toBe(before.theme);
  // Restore the operator's original preference.
  await page.request.put("/api/v1/me/preferences", { headers: H, data: { theme: before.theme } });
});

test("cluster tiles show last-known counts with an as-of hint when inventory is stale", async ({ page }) => {
  const body = await (await page.request.get("/api/v1/clusters", { headers: H })).json() as { clusters: Array<{ id: string; exposure?: { inventory_status: string; current_critical: number; last_known?: { critical: number; high: number } } }> };
  await page.goto("/clusters");
  await settled(page);
  const cluster = body.clusters[0];
  const tile = page.getByTestId("cluster-tile-critical").first();
  if (cluster.exposure?.inventory_status !== "fresh" && cluster.exposure?.last_known) {
    // Counts move as the API recomputes; the tile must show a number, never "—".
    await expect(tile).toContainText(/\d/);
    await expect(page.getByTestId("cluster-tile-as-of").first()).toContainText("as of");
  } else {
    await expect(tile).toContainText(String(cluster.exposure?.current_critical ?? "—"));
  }
});

test("finding detail uses the API's asset_name in the affected-asset chip", async ({ page }) => {
  const id = await firstClusterId(page);
  await page.goto(`/clusters/${id}/findings?view=instances`);
  await settled(page);
  await page.getByTestId("findings-table").locator("tbody tr").first().click();
  await expect(page).toHaveURL(new RegExp(`/clusters/${id}/findings/[^/?]+`));
  await settled(page);
  const findingId = decodeURIComponent(new URL(page.url()).pathname.split("/").pop()!);
  const query = new URL(page.url()).search;
  const detail = await (await page.request.get(`/api/v1/findings/${encodeURIComponent(findingId)}${query}`, { headers: H })).json() as { asset_name?: string };
  const chip = page.getByTestId("finding-affected-asset-name");
  // A readable asset_name is shown as-is; a bare digest resolves to the image reference.
  if (detail.asset_name && !/^sha256:/i.test(detail.asset_name)) await expect(chip).toHaveText(detail.asset_name);
  else await expect(chip).not.toHaveText(/^(Asset|Loading asset…)$/);
});

test("API errors show the request id as the reference", async ({ page }) => {
  const id = await firstClusterId(page);
  await page.goto(`/clusters/${id}/findings/not-a-finding-id`);
  const reference = page.getByText(/^Reference/).first();
  await expect(reference).toBeVisible({ timeout: 30_000 });
  await expect(reference).toContainText(/\S+\/\S+-\d+/);
});
