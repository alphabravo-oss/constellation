// Live smoke test: real UI login, then the two pages every operator lands on. Works against the
// production-bundle preview (default webServer) and a Vite dev server
// (PLAYWRIGHT_BASE_URL=http://localhost:5173); both proxy /api to the Go API.
import { expect, test } from "@playwright/test";
import { CREDS } from "./utils";

// Start from a clean context so the login form is exercised instead of the shared storageState.
test.use({ storageState: { cookies: [], origins: [] } });

test.afterEach(async ({ page }, testInfo) => {
  if (testInfo.status === testInfo.expectedStatus) return;
  const file = testInfo.outputPath(`live-smoke-${testInfo.title.replace(/\W+/g, "-")}.png`);
  await page.screenshot({ path: file, fullPage: true }).catch(() => undefined);
  await testInfo.attach("failure-screenshot", { path: file, contentType: "image/png" }).catch(() => undefined);
});

test.describe("live smoke", () => {
  test("logs in through the UI and lands on the clusters list", async ({ page }) => {
    await page.goto("/auth/login");
    await page.locator("#login-email").fill(CREDS.email);
    await page.locator("#login-password").fill(CREDS.password);
    await page.getByRole("button", { name: /sign in/i }).click();

    await expect(page).toHaveURL(/\/clusters(?:[/?#]|$)/, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: /^Clusters$/ })).toBeVisible();
    await expect(page.getByTestId("clusters-landing-grid")).toBeVisible();
  });

  test("findings page renders for the default cluster", async ({ page }) => {
    await page.goto("/auth/login");
    await page.locator("#login-email").fill(CREDS.email);
    await page.locator("#login-password").fill(CREDS.password);
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page).toHaveURL(/\/clusters(?:[/?#]|$)/, { timeout: 30_000 });

    // /findings is a legacy alias that resolves to /clusters/:id/findings for the current cluster.
    await page.goto("/findings");
    await expect(page).toHaveURL(/\/clusters\/[^/]+\/findings/, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: /^Findings$/ })).toBeVisible();
    await expect(page.getByTestId("finding-state-tabs")).toBeVisible();
  });
});
