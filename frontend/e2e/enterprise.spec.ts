import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Runtime page shows subsystem and rule readiness", async ({ page }) => {
  await page.goto("/runtime");
  await expect(page.getByRole("heading", { name: "Runtime", exact: true })).toBeVisible();
  await expect(page.getByTestId("runtime-subsystems")).toBeVisible();
  await expect(page.getByText("Falco rules")).toBeVisible();
  await expect(page.getByText("WAF inline enforcement")).toBeVisible();
  await expect(page.getByTestId("runtime-rules")).toContainText("Terminal shell in container");
  await expect(page.getByTestId("runtime-evidence-summary")).toContainText("Runtime evidence");
  await expect(page.getByTestId("runtime-event-evidence")).toContainText("SQL injection payload blocked");
  await expect(page.getByTestId("runtime-event-evidence")).toContainText("T1190");
  await expect(page.getByTestId("runtime-event-inspector")).toContainText("Rule");
  await expect(page.getByTestId("runtime-rules")).toContainText("last triggered");
  await expect(page.getByTestId("runtime-rule-evidence").first()).toContainText("Events");
  await expect(page.getByTestId("runtime-workloads")).toContainText("default/api-service");
  await page.getByTestId("runtime-event-row").filter({ hasText: "SQL injection payload blocked" }).getByRole("button").click();
  await expect(page.getByTestId("runtime-event-inspector")).toContainText("SQL injection payload");
  await expect(page.getByTestId("runtime-event-inspector")).toContainText("block");
  await page.getByTestId("runtime-window-select").selectOption("1");
  await expect(page.getByTestId("runtime-evidence-summary")).toContainText("1h");
});

test("Settings exposes onboarding, integrations, migration, and AI controls", async ({ page }) => {
  await page.goto("/settings");
  await expect(page.getByTestId("onboarding-panel")).toContainText("Helm");
  await expect(page.getByTestId("integrations-panel")).toContainText("PagerDuty");
  await expect(page.getByTestId("migration-panel")).toContainText("StackRox");
  await expect(page.getByTestId("migration-panel")).toContainText("NeuVector");
  await expect(page.getByTestId("migration-preview-wizard")).toContainText("Preview Import");
  await page.getByTestId("migration-preview-submit").click();
  await expect(page.getByTestId("migration-preview-result")).toContainText("Read-only preview");
  await expect(page.getByTestId("migration-preview-policy").filter({ hasText: "nv-block-latest-tag" })).toBeVisible();
  await expect(page.getByTestId("migration-preview-yaml")).toContainText("ClusterPolicy");
  await expect(page.getByTestId("migration-rollback-bundle")).toContainText("restore previous policy versions");
  await page.getByTestId("migration-source-select").selectOption("stackrox");
  await page.getByTestId("migration-preview-submit").click();
  await expect(page.getByTestId("migration-preview-policy").filter({ hasText: "privileged-container" })).toBeVisible();
  await expect(page.getByTestId("ai-residency-panel")).toContainText("Non-AI fallback");
});
