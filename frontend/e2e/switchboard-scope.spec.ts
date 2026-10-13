import { expect, test } from "@playwright/test";
import { aliasCluster, aliasSibling, installAliasFixture } from "./fixtures/canonical-aliases";

test("Switchboard keeps guidance collapsed and updates destinations when the cluster changes", async ({ page }) => {
  await installAliasFixture(page);
  await page.goto(`/clusters/${aliasCluster}/neuvector`);
  const workspace = page.getByTestId("neuvector-switchboard");
  await expect(workspace).toBeVisible();
  await expect(workspace.locator('[data-slot="page-status"]')).toContainText("Navigation reference");
  const guidance = workspace.locator("details").filter({ has: page.locator("summary", { hasText: "Advanced: operating concepts and migration guidance" }) });
  await expect(guidance).not.toHaveAttribute("open", "");
  await expect(workspace.getByRole("heading", { name: "Mode Vocabulary" })).not.toBeVisible();
  await page.getByTestId("cluster-switcher").click();
  await page.getByTestId(`cluster-switcher-option-${aliasSibling}`).click();
  await expect(page).toHaveURL(new RegExp(`/clusters/${aliasSibling}/neuvector$`));
  await expect(workspace.getByTestId("neuvector-map-link-workloads-services-workloads")).toHaveAttribute("href", `/clusters/${aliasSibling}/deployments`);
  const destinations = await workspace.locator('a[href^="/clusters/"]').evaluateAll(links => links.map(link => link.getAttribute("href")));
  expect(destinations.length).toBeGreaterThan(20);
  expect(destinations.every(href => href?.startsWith(`/clusters/${aliasSibling}/`))).toBe(true);
  await guidance.locator("summary").click();
  await expect(workspace.getByRole("heading", { name: "Mode Vocabulary" })).toBeVisible();
  await expect(workspace.getByRole("link", { name: "Verify components and agents" })).toHaveAttribute("href", `/clusters/${aliasSibling}/components`);
});
