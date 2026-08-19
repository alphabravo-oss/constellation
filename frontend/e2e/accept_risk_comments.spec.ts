import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

// These specs target an "open" finding so suppress/accept don't fight prior state. After
// the spec runs the suppress-test from findings.spec.ts may have already touched the
// first finding, so we navigate to a runtime-kind finding which is never suppressed by
// the other specs.
test("Accept Risk modal records rationale + expiry", async ({ page }) => {
  await page.goto("/findings");
  await page.getByLabel("Kind").selectOption("ml-model");
  await page.locator("tbody tr").first().locator("a").click();

  await expect(page.getByRole("button", { name: /^Accept Risk$/ })).toBeVisible();
  await page.getByRole("button", { name: /^Accept Risk$/ }).click();
  await expect(page.getByTestId("accept-risk-modal")).toBeVisible();

  await page.getByTestId("accept-risk-rationale").fill("compensating control: vendor patch ETA 30 days");
  await page.getByTestId("accept-risk-submit").click();
  await expect(page.getByText(/Risk accepted/i).first()).toBeVisible({ timeout: 5000 });
});

test("Comment thread accepts and renders a new comment", async ({ page }) => {
  await page.goto("/findings");
  await page.getByLabel("Kind").selectOption("compliance");
  await page.locator("tbody tr").first().locator("a").click();

  await expect(page.getByTestId("comments-section")).toBeVisible();
  const body = `e2e-test comment ${Date.now()}`;
  await page.getByTestId("comment-input").fill(body);
  await page.getByTestId("comment-submit").click();

  await expect(page.getByTestId("comment-item").last()).toContainText(body, { timeout: 5000 });
});
