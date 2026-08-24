import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Access Control page shows users, roles, providers, tokens, and guardrails", async ({ page }) => {
  await page.goto("/access-control");
  await expect(page.getByRole("heading", { name: "Access Control" })).toBeVisible();
  await expect(page.getByTestId("access-users")).toContainText("Ava Patel");

  await page.getByRole("tab", { name: /Roles & Permissions/ }).click();
  await expect(page.getByTestId("permission-matrix")).toContainText("Access control");
  await expect(page.getByTestId("access-roles")).toContainText("Global admin");
  await expect(page.getByTestId("access-bindings")).toContainText("GlobalAdmin");

  await page.getByRole("tab", { name: /SSO \/ Auth/ }).click();
  await expect(page.getByTestId("auth-providers")).toContainText("Okta Workforce");

  await page.getByRole("tab", { name: /Service Accounts/ }).click();
  await expect(page.getByTestId("service-tokens")).toContainText("CI scanner");

  await page.getByRole("tab", { name: /Guardrails/ }).click();
  await expect(page.getByTestId("access-guardrails")).toContainText("MFA required");
});
