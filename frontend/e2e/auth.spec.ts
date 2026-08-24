import { test, expect } from "@playwright/test";

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

  test("OIDC button shows graceful error (OIDC not configured)", async ({ page }) => {
    await page.goto("/auth/login");
    await page.getByRole("button", { name: /Continue with SSO/ }).click();
    await expect(page.getByText(/OIDC not configured/i)).toBeVisible();
  });
});
