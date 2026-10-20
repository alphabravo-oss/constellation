import { expect, test } from "@playwright/test";
import { firstClusterId, settled } from "./helpers";

test.describe("Findings (C1 table page)", () => {
  test("toolbar: severity filter narrows the table, one Export menu, table near the top", async ({ page }) => {
    const id = await firstClusterId(page);
    await page.goto(`/clusters/${id}/findings?view=instances`);
    await settled(page);
    const table = page.getByTestId("findings-table");
    await expect(table).toBeVisible();
    // The table starts in the first screen (C1: ~y 240 at 1440x900).
    const box = await table.boundingBox();
    expect(box?.y ?? 9999).toBeLessThan(320);
    // No legacy stat stack or "Try" chip rail.
    await expect(page.getByText("Rows on this page")).toHaveCount(0);
    await expect(page.getByText("Try", { exact: true })).toHaveCount(0);

    await table.getByRole("combobox", { name: "Severity" }).click();
    await page.getByRole("option", { name: "Critical" }).click();
    await expect(page).toHaveURL(/severity=critical/);
    await settled(page);
    const pills = table.locator("tbody [data-severity]");
    await expect(pills.first()).toBeVisible();
    const severities = await pills.evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-severity")));
    expect(new Set(severities)).toEqual(new Set(["critical"]));
    await expect(pills.first()).toHaveText("Critical");

    const exportTrigger = table.getByRole("button", { name: /^Export/ });
    await expect(exportTrigger).toHaveCount(1);
    await exportTrigger.click();
    const menu = page.getByRole("menu");
    await expect(menu.getByRole("menuitem", { name: /Matching instances/ })).toBeVisible();
    await expect(menu.getByRole("menuitem", { name: /This table/ })).toBeVisible();
    await page.keyboard.press("Escape");
  });

  test("header scope switch includes or hides system workloads", async ({ page }) => {
    const id = await firstClusterId(page);
    await page.goto(`/clusters/${id}/findings?view=instances`);
    await settled(page);
    const scope = page.getByRole("switch", { name: "Include system workloads" });
    await expect(scope).toBeVisible();
    if ((await scope.getAttribute("aria-checked")) === "true") {
      await scope.click();
      await settled(page);
    }
    const verdict = page.locator('[data-slot="page-status"]').first();
    const hidden = (await verdict.innerText()).match(/([\d,]+) matching/)?.[1];
    await scope.click();
    await expect(scope).toHaveAttribute("aria-checked", "true");
    await settled(page);
    const shown = (await verdict.innerText()).match(/([\d,]+) matching/)?.[1];
    expect(hidden).toBeTruthy();
    expect(shown).toBeTruthy();
    expect(Number(shown!.replace(/,/g, ""))).toBeGreaterThan(Number(hidden!.replace(/,/g, "")));
    // Restore the default for other specs.
    await scope.click();
    await expect(scope).toHaveAttribute("aria-checked", "false");
  });
});
