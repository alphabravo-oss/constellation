import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Clusters picker lists cluster cards with 'Enter cluster' CTA", async ({ page }) => {
  await page.goto("/clusters");
  await expect(page.getByRole("heading", { name: "Clusters" })).toBeVisible();
  await expect(page.getByTestId("cluster-card").first()).toBeVisible();
  await expect(page.getByTestId("cluster-enter").first()).toBeVisible();
});

test("Cluster health page (deep route) renders sensor bundle", async ({ page }) => {
  await page.goto("/clusters");
  // Capture the first cluster id from the card's data attribute and visit its health page.
  const firstCard = page.getByTestId("cluster-card").first();
  const id = await firstCard.getAttribute("data-cluster-id");
  expect(id).toBeTruthy();
  await page.goto(`/clusters/${id}/health`);
  await expect(page.getByTestId("cluster-components-table")).toContainText("admission");
  await expect(page.getByTestId("cluster-health-gate").first()).toBeVisible();
  await expect(page.getByText("helm upgrade --install constellation deploy/charts/constellation")).toBeVisible();
});
