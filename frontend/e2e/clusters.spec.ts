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

test("Cluster health keeps the selected sensor scope in the URL", async ({ page }) => {
  await page.goto("/clusters");
  const cards = page.getByTestId("cluster-card");
  await expect(cards.nth(1)).toBeVisible();
  const firstID = await cards.first().getAttribute("data-cluster-id");
  const secondID = await cards.nth(1).getAttribute("data-cluster-id");
  expect(firstID).toBeTruthy();
  expect(secondID).toBeTruthy();

  await page.goto(`/clusters/${firstID}/health?source=bookmark#sensors`);
  await expect(page.getByRole("heading", { name: "Cluster Health" })).toBeVisible();
  const firstName = await page.getByTestId("cluster-health-card-name").first().innerText();
  const secondName = await page.getByTestId("cluster-health-card-name").nth(1).innerText();
  await expect(page.getByTestId("cluster-health-panel").getByRole("heading", { level: 2 }).first()).toHaveText(firstName);
  await page.getByTestId("cluster-card").nth(1).click();
  await expect(page).toHaveURL(`/clusters/${secondID}/health?source=bookmark#sensors`);
  await expect(page.getByTestId("cluster-health-panel").getByRole("heading", { level: 2 }).first()).toHaveText(secondName);
});
