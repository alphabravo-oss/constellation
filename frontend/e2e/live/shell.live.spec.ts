import { expect, test } from "@playwright/test";
import { firstClusterId, settled, UUID } from "./helpers";

test.describe("C1 shell", () => {
  test("org rail → cluster panel → back to all clusters", async ({ page }) => {
    await page.goto("/clusters");
    await expect(page.getByTestId("org-panel")).toBeVisible();
    for (const label of ["Clusters", "CVE database", "Posture", "Audit log", "Settings"]) {
      await expect(page.getByRole("link", { name: label }).first()).toBeVisible();
    }
    const id = await firstClusterId(page);
    await page.getByTestId(`org-panel-cluster-${id}`).click();
    await expect(page).toHaveURL(new RegExp(`/clusters/${id}/dashboard`));
    const panel = page.getByTestId("cluster-panel");
    await expect(panel).toBeVisible();
    for (const group of ["Inventory", "Vulnerabilities", "Runtime", "Network"]) {
      await expect(panel.getByText(group, { exact: true })).toBeVisible();
    }
    await expect(panel.getByRole("link")).toHaveCount(20);
    // Every group is visible at once (no one-open accordion).
    await expect(panel.getByRole("link", { name: "Nodes" })).toBeVisible();
    await expect(panel.getByRole("link", { name: "Findings" })).toBeVisible();
    await expect(panel.getByRole("link", { name: "Agents" })).toBeAttached();
    // Back out through the breadcrumb.
    await page.getByRole("navigation", { name: "Breadcrumb" }).getByRole("link", { name: "All clusters" }).click();
    await expect(page).toHaveURL(/\/clusters\/?$/);
    await expect(page.getByTestId("org-panel")).toBeVisible();
  });

  test("Policies is one item with Admission, Runtime, Network and Response tabs", async ({ page }) => {
    const id = await firstClusterId(page);
    await page.goto(`/clusters/${id}/dashboard`);
    await page.getByTestId("cluster-panel").getByRole("link", { name: "Policies" }).click();
    const hub = page.getByTestId("policies-hub");
    await expect(hub).toBeVisible();
    await expect(page.getByRole("heading", { level: 1, name: "Policies" })).toBeVisible();
    const tabs = page.getByRole("navigation", { name: "Policies sections" });
    for (const [label, path] of [["Runtime", "runtime-policies"], ["Network", "groups"], ["Response", "response-rules"], ["Admission", "admission"]] as const) {
      await tabs.getByRole("link", { name: label, exact: true }).click();
      await expect(page).toHaveURL(new RegExp(`/clusters/${id}/${path}`));
      await expect(tabs.getByRole("link", { name: label, exact: true })).toHaveAttribute("aria-current", "page");
      // The Policies nav item stays active on every tab.
      await expect(page.getByTestId("cluster-panel").getByRole("link", { name: "Policies" })).toHaveAttribute("aria-current", "page");
    }
  });

  test("command palette opens from the header, / and Ctrl+K, and navigates", async ({ page }) => {
    const id = await firstClusterId(page);
    await page.goto(`/clusters/${id}/dashboard`);
    await settled(page);
    await page.getByRole("button", { name: /search pages/i }).click();
    const dialog = page.getByRole("dialog", { name: "Command palette" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("This cluster", { exact: true })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await page.locator("main").click({ position: { x: 5, y: 5 } });
    await page.keyboard.press("/");
    await expect(dialog).toBeVisible();
    await page.keyboard.press("Escape");
    await page.keyboard.press("Control+k");
    await expect(dialog).toBeVisible();
    await dialog.getByRole("combobox").fill("vulnerability profiles");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`/clusters/${id}/vuln-profiles`));
  });

  test("unknown routes render the 404 inside the shell", async ({ page }) => {
    await page.goto("/this-page-does-not-exist");
    await expect(page.getByTestId("app-shell")).toBeVisible();
    await expect(page.getByTestId("route-not-found")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Page not found" }).or(page.getByText("Page not found"))).toBeVisible();
    const id = await firstClusterId(page);
    await page.goto(`/clusters/${id}/not-a-section`);
    await expect(page.getByTestId("cluster-panel")).toBeVisible();
    await expect(page.getByTestId("route-not-found")).toBeVisible();
  });

  test("breadcrumbs never show raw ids", async ({ page }) => {
    const id = await firstClusterId(page);
    await page.goto(`/clusters/${id}/findings?view=instances`);
    await settled(page);
    const row = page.getByTestId("findings-table").locator("tbody tr").first();
    await row.click();
    await expect(page).toHaveURL(new RegExp(`/clusters/${id}/findings/.+`));
    await settled(page);
    const crumbs = page.getByRole("navigation", { name: "Breadcrumb" });
    await expect(crumbs).toBeVisible();
    await expect(crumbs).not.toHaveText(UUID);
    await expect(crumbs.locator('[aria-current="page"]')).not.toHaveText("Finding");
    expect(await crumbs.innerText()).not.toMatch(/[0-9a-f]{8}-/i);
  });
});
