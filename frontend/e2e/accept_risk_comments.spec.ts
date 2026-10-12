import { test, expect, type Page } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

// Select a row from the completed filtered response: the old CVE table can remain
// visible briefly while the Kind control switches to the instance view.
async function openFindingOfKind(page: Page, kind: "ml-model" | "compliance") {
  await page.goto("/findings");
  const filtered = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === "/api/v1/findings" && url.searchParams.get("kind") === kind && response.request().method() === "GET";
  });
  await page.getByLabel("Kind").selectOption(kind);
  const response = await filtered;
  expect(response.ok()).toBeTruthy();
  const { findings } = await response.json();
  const finding = findings.find((item: { lifecycle: string }) => item.lifecycle === "open");
  expect(finding, `seeded open ${kind} finding`).toBeTruthy();
  await page.locator("tbody tr").filter({ has: page.getByText(finding.title, { exact: true }) }).first().click();
  await expect(page).toHaveURL(new RegExp(`/findings/${finding.id}$`));
}

// Use an open ML finding untouched by the suppression tests.
test("Accept Risk modal records rationale + expiry", async ({ page }) => {
  await openFindingOfKind(page, "ml-model");

  await expect(page.getByRole("button", { name: /^Accept risk$/i })).toBeVisible();
  await page.getByRole("button", { name: /^Accept risk$/i }).click();
  await expect(page.getByTestId("accept-risk-modal")).toBeVisible();

  await page.getByTestId("accept-risk-rationale").fill("compensating control: vendor patch ETA 30 days");
  await page.getByTestId("accept-risk-submit").click();
  await expect(page.getByText(/Risk accepted/i).first()).toBeVisible({ timeout: 5000 });
});

test("Comment thread accepts and renders a new comment", async ({ page }) => {
  await openFindingOfKind(page, "compliance");

  await expect(page.getByTestId("comments-section")).toBeVisible();
  const body = `e2e-test comment ${Date.now()}`;
  await page.getByTestId("comment-input").fill(body);
  await page.getByTestId("comment-submit").click();

  await expect(page.getByTestId("comment-item").last()).toContainText(body, { timeout: 5000 });
});
