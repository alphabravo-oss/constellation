import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Coverage page exposes reference feature decisions", async ({ page }) => {
  await page.goto("/coverage");
  await expect(page.getByRole("heading", { name: "Coverage" })).toBeVisible();
  await expect(page.getByTestId("coverage-table")).toBeVisible();
  await expect(page.getByTestId("coverage-row")).toHaveCount(11);
  await expect(page.getByText(/Traffic map, flow drill-down/i)).toBeVisible();
  await expect(page.getByText(/NeuVector/i).first()).toBeVisible();
  await expect(page.getByText(/StackRox/i).first()).toBeVisible();
});
