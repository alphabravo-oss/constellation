import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Response rules page shows catalog rules and filters by event type", async ({ page }) => {
  await page.goto("/response");
  await expect(page.getByRole("heading", { name: "Response Rules" })).toBeVisible();
  await expect(page.getByTestId("response-rules-table")).toBeVisible();
  await expect(page.getByTestId("response-rule-row")).toHaveCount(5);
  await expect(page.getByTestId("response-rules-table").getByText("Unauthorized external egress")).toBeVisible();
  await expect(page.getByTestId("response-rules-table").getByText("quarantine_workload")).toBeVisible();

  await page.getByTestId("response-rule-filters").getByRole("button", { name: "network" }).click();
  await expect(page.getByTestId("response-rule-row")).toHaveCount(1);
  await expect(page.getByTestId("response-rules-table").getByText("Unauthorized external egress")).toBeVisible();
});

test("Response rules can preview and persist governed runtime changes", async ({ page }) => {
  await page.goto("/response");
  await expect(page.getByTestId("response-rule-manager")).toBeVisible();
  await page.getByTestId("response-rule-filters").getByRole("button", { name: "dlp" }).click();
  await page.getByRole("button", { name: "Secret exfiltration pattern" }).first().click();
  await page.getByTestId("response-rule-mode-select").selectOption("enforce");
  await page.getByTestId("response-rule-enabled-toggle").check();
  await page.getByTestId("response-rule-reason").fill("pilot DLP enforcement in monitor-approved namespaces");
  await page.getByTestId("response-rule-preview").click();
  await expect(page.getByTestId("response-rule-preview-card")).toContainText("dry-run only");
  await expect(page.getByTestId("response-rule-preview-card")).toContainText("privileged Linux runtime agent");
  await page.getByTestId("response-rule-save").click();
  await expect(page.getByTestId("response-rule-action-state")).toContainText("saved and audited");
  await expect(page.getByTestId("response-rule-preview-card")).toContainText("persists and writes audit");
  await expect(page.getByTestId("response-rule-manager")).toContainText("enforce");
  await expect(page.getByTestId("response-rule-card").filter({ hasText: "Secret exfiltration pattern" }).first()).toContainText("pilot DLP enforcement");
});
