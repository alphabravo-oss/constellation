import { expect, test } from "@playwright/test";
import { LIVE_EMAIL, LIVE_PASSWORD, LIVE_STORAGE } from "./env";

// One real UI login; the session is saved as storageState for every live spec.
test("signs in through the login form and saves the session", async ({ page }) => {
  await page.goto("/auth/login");
  await expect(page.getByRole("heading", { name: "Sign in to Constellation" })).toBeVisible();
  await page.locator("#login-email").fill(LIVE_EMAIL);
  await page.locator("#login-password").fill(LIVE_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/clusters(?:[/?#]|$)/, { timeout: 30_000 });
  await expect(page.getByTestId("app-shell")).toBeVisible();
  await page.context().storageState({ path: LIVE_STORAGE });
});
