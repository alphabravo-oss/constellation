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

test("receiver and email settings open dedicated forms and Cancel returns without saving", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", (request) => {
    if (["POST", "PATCH", "DELETE"].includes(request.method()) && /\/api\/v1\/(integrations\/receivers|system\/config)/.test(request.url())) writes.push(request.url());
  });
  await page.goto("/settings/integrations");
  await page.getByTestId("receiver-add").click();
  await expect(page).toHaveURL(/\/integrations\/receivers\/new$/);
  await page.getByTestId("create-receiver-name").fill("Unsaved receiver draft");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/integrations$/);
  await page.getByRole("button", { name: "Edit email server", exact: true }).click();
  await expect(page.getByTestId("smtp-host")).toBeVisible();
  await page.reload();
  await expect(page.getByTestId("smtp-host")).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/integrations$/);
  expect(writes).toEqual([]);
});

test("routing editors preserve the list tab and reject unversioned child links", async ({ page }) => {
  await page.goto("/settings/integrations?tab=routes");
  await page.getByRole("button", { name: "Edit complete routing", exact: true }).click();
  await expect(page).toHaveURL(/\/integrations\/routing\/edit$/);
  await expect(page.getByRole("heading", { name: "Edit notification routing", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/integrations\?tab=routes$/);
  await page.goto("/settings/integrations/routes/0/edit");
  await expect(page.getByTestId("error-state")).toContainText("saved routing list");
  await expect(page.getByRole("button", { name: "Save route", exact: true })).toHaveCount(0);
});
