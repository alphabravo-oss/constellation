import { test, expect } from "@playwright/test";
import { login } from "./utils";

const NEUVECTOR_EXPORT = `admission:
  rules:
    - id: 1001
      desc: Block latest tag
      criteria:
        - key: image_name
          op: regex
          value: latest
      action: deny
response:
  rules:
    - id: 2001
      event: process
      conditions: [process_baseline]
      actions: [alert, quarantine]
`;

const STACKROX_EXPORT = JSON.stringify({
  policies: [
    {
      id: "p-001",
      name: "Privileged Container",
      description: "Block privileged containers at deploy.",
      categories: ["Security Best Practices"],
      lifecycleStages: ["DEPLOY"],
      severity: "HIGH_SEVERITY",
      disabled: false,
      enforcementActions: ["SCALE_TO_ZERO_ENFORCEMENT"],
      policySections: [{
        sectionName: "container",
        policyGroups: [{ fieldName: "Privileged", booleanOperator: "OR", values: [{ value: "true" }] }],
      }],
    },
  ],
}, null, 2);

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
  await expect(page.getByRole("link", { name: /Connect a cluster/i })).toContainText("Register a Kubernetes cluster");
  await expect(page.getByRole("link", { name: /Integrations & Routing/i })).toBeVisible();
  await expect(page.getByRole("link", { name: /Migration Imports/i })).toBeVisible();

  await page.goto("/settings/integrations?tab=operations");
  await expect(page.getByTestId("integration-connectors")).toContainText("Critical PagerDuty service");

  await page.goto("/settings/migration");
  await expect(page.getByTestId("migration-preview-wizard")).toContainText("Preview import");
  await page.getByTestId("migration-export-input").fill(NEUVECTOR_EXPORT);
  await page.getByTestId("migration-preview-submit").click();
  await expect(page.getByTestId("migration-preview-result")).toContainText("Read-only preview");
  await expect(page.getByTestId("migration-preview-policy").filter({ hasText: "nv-1001-block-latest-tag" })).toBeVisible();
  await expect(page.getByTestId("migration-preview-yaml")).toContainText("AdmissionRule");
  await expect(page.getByTestId("migration-rollback-bundle")).toContainText("restore previous policy versions");
  await page.getByTestId("migration-source-select").selectOption("stackrox");
  await page.getByTestId("migration-export-input").fill(STACKROX_EXPORT);
  await page.getByTestId("migration-preview-submit").click();
  await expect(page.getByTestId("migration-preview-policy").filter({ hasText: "privileged-container" })).toBeVisible();

  await page.goto("/posture");
  await expect(page.getByRole("row", { name: /AI\/ML Workload Tagging/i })).toBeVisible();
});
