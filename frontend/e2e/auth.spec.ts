import { test, expect, type Response } from "@playwright/test";
import { waitForLoginCooldown } from "./utils";

const EMAIL = "admin@demo.test";
const PASSWORD = "Constellation!1";

test.describe("Authentication", () => {
  test("redirects to /auth/login when unauthenticated", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/auth\/login/);
    await expect(page.getByRole("heading", { name: /Constellation/i })).toBeVisible();
  });

  test("rejects bad credentials", async ({ page }) => {
    await page.goto("/auth/login");
    await page.getByLabel("Email").fill(EMAIL);
    await page.getByLabel("Password", { exact: true }).fill("wrong-password");
    await page.getByRole("button", { name: /^Sign in$/ }).click();
    await expect(page).toHaveURL(/\/auth\/login/);
    // Sonner toast appears with error
    await expect(page.getByText(/Login failed/i)).toBeVisible();
  });

  test("local login lands on clusters", async ({ page }) => {
    await page.goto("/auth/login");
    await page.getByLabel("Email").fill(EMAIL);
    await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
    await page.getByRole("button", { name: /^Sign in$/ }).click();
    await expect(page).toHaveURL(/\/clusters/);
    await expect(page.getByRole("heading", { name: /^Clusters$/i })).toBeVisible();
    await page.getByLabel("User menu").click();
    await expect(page.getByText(EMAIL)).toBeVisible();
    await expect(page.getByText(/GlobalAdmin/)).toBeVisible();
  });

  test("hides SSO when no provider is configured", async ({ page }) => {
    const deadline = Date.now() + 65_000;
    let providers: Response;
    while (true) {
      const requested = page.waitForResponse("**/api/v1/auth/providers");
      await page.goto("/auth/login");
      providers = await requested;
      // Provider discovery shares the real anonymous auth limiter with login.
      // Honor its cooldown; every other response still fails immediately.
      if (providers.status() !== 429 || !await waitForLoginCooldown(providers.headers()["retry-after"], deadline)) break;
    }
    expect(providers.ok()).toBe(true);
    expect(await providers.json()).toEqual({ oidc: false, saml: false });
    await expect(page.getByText("Enter your credentials to continue.")).toBeVisible();
    await expect(page.getByText(/Continue with SSO|continue with password/i)).toHaveCount(0);
  });
});
