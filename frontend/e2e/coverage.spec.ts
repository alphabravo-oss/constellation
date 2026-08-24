import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Coverage page exposes reference feature decisions", async ({ page }) => {
  await page.goto("/coverage");
  await expect(page.getByRole("heading", { name: "Posture" })).toBeVisible();
  await expect(page.getByTestId("coverage-table")).toBeVisible();
  await expect(page.getByTestId("coverage-row")).toHaveCount(17);
  await expect(page.getByText("Network Map")).toBeVisible();
  await expect(page.getByText("CVE Intelligence")).toBeVisible();
  await expect(page.getByText("Cloud CSPM")).toBeVisible();
});
