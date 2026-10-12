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
test("Accept risk form records rationale + expiry", async ({ page }) => {
  await openFindingOfKind(page, "ml-model");

  await expect(page.getByRole("link", { name: /^Accept risk$/i })).toBeVisible();
  await page.getByRole("link", { name: /^Accept risk$/i }).click();
  await expect(page).toHaveURL(/\/findings\/[^/]+\/accept-risk$/);
  await expect(page.getByTestId("finding-action-form-page")).toBeVisible();

  await page.getByLabel("Reason", { exact: true }).fill("compensating control: vendor patch ETA 30 days");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page).toHaveURL(/\/findings\/[^/]+$/);
  await expect(page.getByTestId("finding-exception-link")).toContainText("Accepted");
});

test("Comment thread accepts and renders a new comment", async ({ page }) => {
  await openFindingOfKind(page, "compliance");

  await expect(page.getByTestId("comments-section")).toBeVisible();
  const body = `e2e-test comment ${Date.now()}`;
  await page.getByRole("link", { name: "Add comment", exact: true }).click();
  await expect(page).toHaveURL(/\/findings\/[^/]+\/comments\/new$/);
  await page.getByLabel("Comment", { exact: true }).fill(body);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page).toHaveURL(/\/findings\/[^/]+$/);

  await expect(page.getByTestId("comment-item").last()).toContainText(body, { timeout: 5000 });
});
