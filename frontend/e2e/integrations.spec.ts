import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Settings links to integration delivery operations", async ({ page }) => {
  await page.goto("/settings");
  await expect(page.getByRole("link", { name: /Integrations & Routing/i })).toBeVisible();

  await page.getByRole("link", { name: /Integrations & Routing/i }).click();
  await expect(page).toHaveURL(/\/settings\/integrations$/);
  await expect(page.getByRole("heading", { name: "Notifier Integrations" })).toBeVisible();
});

test("Integration delivery page shows enterprise connector operations", async ({ page }) => {
  await page.goto("/settings/integrations?tab=operations");

  await expect(page.getByTestId("integration-connectors")).toContainText("Critical PagerDuty service");
  await expect(page.getByTestId("integration-connectors")).toContainText("SecOps Slack");
  await expect(page.getByTestId("integration-connectors")).toContainText("ServiceNow security queue");

  await expect(page.getByTestId("routing-rules")).toContainText("Saved notification routing tree");
  await expect(page.getByTestId("routing-rules")).toContainText("pagerduty-critical");
  await expect(page.getByTestId("delivery-history")).toContainText("finding.escalated");
  await expect(page.getByTestId("delivery-history")).toContainText("retrying");
  await expect(page.getByTestId("retry-queue")).toContainText("servicenow-sec-queue");
  await expect(page.getByTestId("retry-queue")).toContainText("DLQ");
  await expect(page.getByTestId("integration-guardrails")).toContainText("Secret redaction");
});

test("Integration test preview is read-only and does not send external traffic", async ({ page }) => {
  await page.goto("/settings/integrations?tab=operations");

  await page.getByTestId("integration-connectors").getByRole("button", { name: /preview routing/i }).first().click();
  await expect(page.getByTestId("routing-preview")).toContainText("Critical PagerDuty service");
  await expect(page.getByTestId("routing-preview")).toContainText("no receiver call");
  await expect(page.getByTestId("routing-preview")).toContainText("sends: no");
  await expect(page.getByTestId("routing-preview")).toContainText("persists: no");
});
