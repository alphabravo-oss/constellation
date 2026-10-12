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

test("Runtime keeps live events primary and deep-links secondary evidence", async ({ page }) => {
  const clusterID = "11111111-1111-4111-8111-111111111111";
  const at = "2026-10-12T12:00:00Z";
  await page.route(/\/api\/v1\/clusters(?:\?.*)?$/, (route) => route.fulfill({ json: { clusters: [{ id: clusterID, name: "Runtime fixture", distro: "k3s", state: "connected" }] } }));
  await page.route("**/api/v1/runtime/overview**", async (route) => {
    const url = new URL(route.request().url());
    expect(url.searchParams.get("cluster_id")).toBe(clusterID);
    const hours = Number(url.searchParams.get("hours"));
    await route.fulfill({ json: {
      summary: { window_hours: hours, events: 12, alerts: 2, blocks: 1, quarantines: 0, affected_workloads: 2, techniques: 1 },
      subsystems: [
        { id: "falco", name: "Falco rules", status: "ready", mode: "monitor", evidence: "Rule parser available" },
        { id: "waf", name: "WAF inline enforcement", status: "linux-agent-gated", mode: "learn", evidence: "Requires the agent" },
      ],
      modes: [{ id: "monitor", label: "Monitor", blocks: false, description: "Alert without blocking" }],
      rules: [{ id: "sql-rule", name: "SQL injection pattern", source: "WAF", severity: "critical", techniques: ["T1190"], mode: "learn", event_count: 1, affected_workloads: 1, last_triggered_at: at }],
      recent_events: [{ id: "runtime-event-1", at, cluster_id: clusterID, cluster_name: "Runtime fixture", workload_id: "default/api-service", source: "WAF", kind: "network", severity: "critical", verdict: "block", attack_techniques: ["T1190"], message: "SQL injection payload blocked", rule_id: "sql-rule", rule_name: "SQL injection pattern" }],
      workloads: [{ workload_id: "default/api-service", events: 12, alerts: 2, blocks: 1, highest_severity: "critical", last_seen_at: at, sources: ["WAF"], techniques: ["T1190"] }],
    } });
  });
  await page.route(/\/api\/v1\/events(?:\?.*)?$/, async (route) => {
    const url = new URL(route.request().url());
    expect(url.searchParams.get("cluster_id")).toBe(clusterID);
    expect(url.searchParams.has("hours")).toBe(false);
    await route.fulfill({ json: { limit: 100, events: [{ id: "raw-1", at, source: "runtime-agent", kind: "network", severity: "critical", verdict: "block", workload_id: "default/api-service", node_id: "node-1", namespace: "default", attack_techniques: ["T1190"], payload: {} }] } });
  });
  await page.goto(`/clusters/${clusterID}/runtime`);
  await expect(page.getByRole("heading", { name: "Runtime", exact: true })).toBeVisible();
  await expect(page.getByTestId("runtime-summary").locator(":scope > *")).toHaveCount(5);
  await expect(page.getByTestId("runtime-live-table")).toContainText("default/api-service");
  await expect(page.getByTestId("runtime-live-events")).toContainText("not filtered by the evidence time window");
  await expect(page.getByTestId("runtime-subsystems")).toBeHidden();
  await page.getByRole("tab", { name: "Subsystems", exact: true }).click();
  await expect(page).toHaveURL(/tab=subsystems/);
  await expect(page.getByTestId("runtime-subsystems")).toContainText("Falco rules");
  await expect(page.getByTestId("runtime-subsystems")).toContainText("WAF inline enforcement");
  await page.getByRole("tab", { name: "Rule catalog", exact: true }).click();
  await expect(page.getByTestId("runtime-rules")).toContainText("SQL injection pattern");
  await expect(page.getByTestId("runtime-rules")).toContainText("Last triggered");
  await page.getByRole("tab", { name: "Affected workloads", exact: true }).click();
  await expect(page.getByTestId("runtime-workloads")).toContainText("default/api-service");
  await page.getByRole("tab", { name: "Window evidence", exact: true }).click();
  await page.getByTestId("runtime-event-row").filter({ hasText: "SQL injection payload blocked" }).getByRole("button").click();
  await expect(page).toHaveURL(/event=runtime-event-1/);
  await expect(page.getByTestId("runtime-event-inspector")).toContainText("SQL injection payload blocked");
  await expect(page.getByTestId("runtime-event-inspector")).toContainText("block");
  await page.getByTestId("runtime-window-select").selectOption("1");
  await expect(page).toHaveURL(/hours=1/);
  await expect(page.getByTestId("runtime-event-evidence")).toContainText("Runtime evidence · 1h");
  await page.reload();
  await expect(page.getByTestId("runtime-event-inspector")).toContainText("SQL injection payload blocked");
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
  await expect(page.getByTestId("migration-preview-result")).toContainText("Preview persisted");
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
