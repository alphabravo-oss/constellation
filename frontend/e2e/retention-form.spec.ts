import { expect, test } from "@playwright/test";

test("retention form blocks dirty link navigation and allows explicit discard", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/auth/me")) {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path.endsWith("/system/config")) {
      await route.fulfill({ json: { revision: 1, config: { network_flow_retention_days: 14, events_retention_days: 30, scan_job_retention_days: 7 } } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });
  await page.goto("/settings/retention");
  const flows = page.getByLabel("Keep raw flows for (days)");
  await flows.fill("45");
  const settings = page.locator('main a[href="/settings"]').first();
  page.once("dialog", (dialog) => dialog.dismiss());
  await settings.click();
  await expect(page).toHaveURL(/\/settings\/retention$/);
  await expect(flows).toHaveValue("45");
  page.once("dialog", (dialog) => dialog.accept());
  await settings.click();
  await expect(page).toHaveURL(/\/settings$/);
});

test("retention fields reject fractions and save zero without a dirty navigation prompt", async ({ page }) => {
  let patches = 0;
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/auth/me")) {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path.endsWith("/system/config")) {
      const patch = route.request().method() === "PATCH";
      if (patch) {
        patches++;
        expect(route.request().postDataJSON().network_flow_retention_days).toBe(0);
      }
      await route.fulfill({ json: { revision: patch ? 2 : 1, config: { network_flow_retention_days: patch ? 0 : 14, events_retention_days: 30, scan_job_retention_days: 7 } } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });
  await page.goto("/settings/retention");
  const flows = page.getByLabel("Keep raw flows for (days)");
  await flows.fill("1.5");
  await flows.press("Tab");
  await expect(flows).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByRole("button", { name: "Save retention settings" })).toBeDisabled();
  expect(patches).toBe(0);
  await flows.fill("0");
  await page.getByRole("button", { name: "Save retention settings" }).click();
  await expect(page.getByText("Retention settings saved", { exact: true })).toBeVisible();
  expect(patches).toBe(1);
  const dialogs: string[] = [];
  page.on("dialog", async (dialog) => { dialogs.push(dialog.message()); await dialog.dismiss(); });
  await page.locator('main a[href="/settings"]').first().click();
  await expect(page).toHaveURL(/\/settings$/);
  expect(dialogs).toEqual([]);
});
