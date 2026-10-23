import { expect, test } from "@playwright/test";
import { totp } from "./totp";
import { LIVE_EMAIL, LIVE_PASSWORD, LIVE_STORAGE } from "./env";

// Real authorization-code sign-in against the deployment's OIDC provider.
test("signs in using the configured normal login and saves the session", async ({ page }) => {
  await page.goto("/auth/login");
  await expect(page.getByRole("heading", { name: "Sign in to Constellation" })).toBeVisible();
  if(process.env.LIVE_TOTP_SECRET){
   await page.getByRole("textbox",{name:"Email",exact:true}).fill(LIVE_EMAIL);
   await page.getByLabel("Password",{exact:true}).fill(LIVE_PASSWORD);
   await page.getByLabel("Authenticator code").fill(totp(process.env.LIVE_TOTP_SECRET));
   await page.getByRole("button",{name:"Sign in",exact:true}).click();
  }else{
  await page.getByRole("button", { name: "Continue with SSO" }).click();
  await page.locator("#username").fill(LIVE_EMAIL);
  await page.locator("#password").fill(LIVE_PASSWORD);
  await page.locator("#kc-login").click();
  }
  await expect(page).toHaveURL(/\/clusters(?:[/?#]|$)/, { timeout: 30_000 });
  await expect(page.getByTestId("app-shell")).toBeVisible();
  await page.context().storageState({ path: LIVE_STORAGE });
});
