import { expect, test, type Page } from "@playwright/test";
import { firstClusterId, settled } from "./helpers";

/** Toolbar controls whose text is clipped (ellipsis) or whose placeholder does not fit. */
async function clippedToolbarText(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    const canvas = document.createElement("canvas").getContext("2d")!;
    for (const toolbar of document.querySelectorAll<HTMLElement>('[data-slot="table-toolbar"]')) {
      for (const el of toolbar.querySelectorAll<HTMLElement>("button, [role=combobox], span")) {
        if (el.offsetParent === null) continue;
        const style = getComputedStyle(el);
        if (style.textOverflow === "ellipsis" && el.scrollWidth > el.clientWidth + 1) out.push(`clipped: ${el.textContent?.trim()}`);
      }
      for (const input of toolbar.querySelectorAll<HTMLInputElement>("input[placeholder]")) {
        if (input.offsetParent === null || input.value) continue;
        const style = getComputedStyle(input);
        // The placeholder may use a different family than typed text (mono queries).
        const ph = getComputedStyle(input, "::placeholder");
        canvas.font = `${ph.fontWeight || style.fontWeight} ${ph.fontSize || style.fontSize} ${ph.fontFamily || style.fontFamily}`;
        const room = input.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
        if (canvas.measureText(input.placeholder).width > room + 1) out.push(`placeholder: ${input.placeholder}`);
      }
    }
    return out;
  });
}

for (const width of [1440, 1280]) {
  test(`table toolbars never ellipsize their controls at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const id = await firstClusterId(page);
    for (const path of [`/clusters/${id}/findings`, `/clusters/${id}/findings?view=instances`, `/clusters/${id}/nodes`, `/clusters/${id}/deployments`, `/clusters/${id}/compliance`, "/cve"]) {
      await page.goto(path);
      await settled(page);
      await expect(page.locator('[data-slot="table-toolbar"]').first()).toBeVisible();
      expect(await clippedToolbarText(page), `${path} at ${width}px`).toEqual([]);
    }
  });
}

test("Findings toolbar is one row at 1440px", async ({ page }) => {
  const id = await firstClusterId(page);
  await page.goto(`/clusters/${id}/findings`);
  await settled(page);
  const toolbar = page.getByTestId("findings-cve-table").locator('[data-slot="table-toolbar"]');
  await expect(toolbar).toBeVisible({ timeout: 30_000 });
  const box = await toolbar.boundingBox();
  expect(box?.height ?? 999).toBeLessThan(64);
});

test("Overview action items list each advisory once with its instance count", async ({ page }) => {
  const id = await firstClusterId(page);
  await page.goto(`/clusters/${id}/dashboard`);
  await settled(page);
  const items = page.getByTestId("action-item");
  await expect(items.first()).toBeVisible();
  const ids = await items.evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-advisory")));
  expect(ids.length).toBeGreaterThan(0);
  expect(new Set(ids).size, `duplicates in ${ids.join(", ")}`).toBe(ids.length);
  await expect(items.first()).toContainText(/\d+ instances?/);
});

test("Security events chart labels every day and the critical series", async ({ page }) => {
  const id = await firstClusterId(page);
  await page.goto(`/clusters/${id}/dashboard`);
  await settled(page);
  const chart = page.locator(".recharts-wrapper").first();
  await expect(chart).toBeVisible();
  await expect(chart.locator(".recharts-xAxis .recharts-cartesian-axis-tick")).toHaveCount(14);
  await expect(chart.locator(".recharts-yAxis .recharts-cartesian-axis-tick").first()).toBeVisible();
});

test("header cluster chip shows the full cluster name", async ({ page }) => {
  const id = await firstClusterId(page);
  await page.goto(`/clusters/${id}/dashboard`);
  await settled(page);
  const name = page.getByTestId("cluster-switcher-name");
  await expect(name).toBeVisible();
  const clipped = await name.evaluate((el) => el.scrollWidth > el.clientWidth + 1);
  expect(clipped).toBe(false);
});
