import { expect, type Page } from "@playwright/test";

/** First cluster with data: the most active one listed in the org panel. */
export async function firstClusterId(page: Page): Promise<string> {
  const response = await page.request.get("/api/v1/clusters", { headers: { "X-Constellation-Client": "browser" } });
  expect(response.ok()).toBe(true);
  const body = (await response.json()) as { clusters: Array<{ id: string; stats?: { open_findings?: number } }> };
  expect(body.clusters.length).toBeGreaterThan(0);
  const sorted = [...body.clusters].sort((a, b) => (b.stats?.open_findings ?? 0) - (a.stats?.open_findings ?? 0));
  return sorted[0].id;
}

/** Wait until the page has no skeletons announcing a first load. */
export async function settled(page: Page) {
  await page.waitForLoadState("networkidle").catch(() => undefined);
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0, { timeout: 30_000 });
}

export const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
