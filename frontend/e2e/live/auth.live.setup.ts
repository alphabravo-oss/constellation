import { expect, test } from "@playwright/test";
import { LIVE_EMAIL, LIVE_PASSWORD, LIVE_STORAGE } from "./env";

// Real authorization-code sign-in against the deployment's OIDC provider.
test("signs in through single sign-on and saves the session", async ({ page }) => {
  await page.goto("/auth/login");
  await expect(page.getByRole("heading", { name: "Sign in to Constellation" })).toBeVisible();
  await page.getByRole("button", { name: "Continue with SSO" }).click();
  await page.locator("#username").fill(LIVE_EMAIL);
  await page.locator("#password").fill(LIVE_PASSWORD);
  await page.locator("#kc-login").click();
  await expect(page).toHaveURL(/\/clusters(?:[/?#]|$)/, { timeout: 30_000 });
  await expect(page.getByTestId("app-shell")).toBeVisible();
  await page.context().storageState({ path: LIVE_STORAGE });
});
