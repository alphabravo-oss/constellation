// Process inventory, lifecycle view, and dedicated rule authoring (read-only Cancel).
//
import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.use({ viewport: { width: 1600, height: 1000 } });

test.beforeEach(async ({ page }) => {
  await login(page, { theme: "dark" });
});

test("baseline inventory and lifecycle link to dedicated scoped rule forms", async ({ page }) => {
  // Resolve the first demo cluster id through the cluster picker.
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
  await expect(page.getByTestId("baselines-table")).toBeVisible({ timeout: 12_000 });
  await page.getByRole("tab", { name: "Lifecycle", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/runtime/baselines\\?tab=lifecycle$`));
  await expect(page.getByTestId("baselines-columns")).toBeVisible();

  await page.screenshot({
    path: "e2e/screens-baseline/main.png",
    fullPage: true,
    animations: "disabled",
  });

  // Open the first exact workload profile from the lifecycle view.
  const firstCard = page.locator("[data-testid^='baselines-card-']").first();
  await firstCard.waitFor({ timeout: 10_000 });
  await firstCard.click();
  await page.locator("[data-testid='baselines-drawer-body']").waitFor({ timeout: 10_000 });
  await expect(page.getByTestId("baselines-drawer-process-table")).toBeVisible();
  const detailPath = new URL(page.url()).pathname;

  await page.screenshot({
    path: "e2e/screens-baseline/card-drawer.png",
    fullPage: true,
    animations: "disabled",
  });

  await page.getByRole("tab", { name: "Configured rules", exact: true }).click();
  await expect(page).toHaveURL(`${detailPath}?tab=rules`);
  await expect(page.getByTestId("baseline-rules-table")).toBeVisible();
  await page.getByTestId("baseline-rule-add").click();
  await expect(page.getByRole("heading", { name: "Add process rule", exact: true })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Process name", exact: true })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Executable path", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(`${detailPath}?tab=rules`);
  await expect(page.getByTestId("baseline-rules-table")).toBeVisible();
});
