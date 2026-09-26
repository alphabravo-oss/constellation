import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const importId = "22222222-2222-4222-8222-222222222222";
const groupId = "33333333-3333-4333-8333-333333333333";
const exportText = readFileSync(new URL("../../scripts/fixtures/neuvector-cutover-export.json", import.meta.url), "utf8");
const dlpName = "nv-dlp-cutover-pii-account-marker";
const wafName = "nv-waf-cutover-waf-probe-path";
const createdAt = "2026-09-26T10:00:00Z";

const summary = {
  source: "neuvector", total: 8, source_total: 8,
  source_counts: { groups: 2, network_rules: 1, vulnerability_profiles: 1, dpi_rules: 2, dpi_bindings: 2 },
  unaccounted_source: 0, create: 8, update: 0, unchanged: 0, enforce: 0, monitor: 2, enabled: 2,
  file_profiles: 0, process_profiles: 0, groups: 2, network_rules: 1, dpi_rules: 2, dpi_bindings: 2,
  vulnerability_profiles: 1, registries: 0, unsupported: 0, engines: {}, categories: {},
  read_only: true, rollback_hint: "Preview only; apply is separate.",
};

const preview = {
  import_id: importId,
  target_cluster_id: clusterId,
  summary,
  policies: [], file_profiles: [], process_profiles: [],
  groups: ["cutover.api.default", "cutover.db.default"].map((name) => ({
    name, cluster_id: clusterId, kind: "ground", policy_mode: "monitor", profile_mode: "monitor",
    criteria: [], diff_action: "create",
  })),
  network_rules: [{
    name: "Cutover API to database", cluster_id: clusterId, from_group: "cutover.api.default",
    to_group: "cutover.db.default", ports: [{ protocol: "tcp", port: 5432 }], mode: "monitor",
    priority: 10, diff_action: "create",
  }],
  dpi_rules: [
    { name: dlpName, cluster_id: clusterId, category: "dlp", apply_dir: 1, severity: 5, mode: "monitor",
      patterns: [{ pattern: "CUTOVER-ACCOUNT-[0-9]{4}", op: "regex" }], source_sensor: "cutover-pii",
      source_groups: ["cutover.api.default"], source_path: "dlp_sensors/cutover-pii/rules/account-marker", diff_action: "create" },
    { name: wafName, cluster_id: clusterId, category: "waf", apply_dir: 2, severity: 6, mode: "monitor",
      patterns: [{ pattern: "(?i)/cutover-probe", op: "regex", context: "uri" }], source_sensor: "cutover-waf",
      source_groups: ["cutover.api.default"], source_path: "waf_sensors/cutover-waf/rules/probe-path", diff_action: "create" },
  ],
  dpi_bindings: ["dlp", "waf"].map((sensor_kind) => ({
    source_group: "cutover.api.default", target_group_id: groupId, target_group_name: "cutover.api.default",
    sensor_kind, source_sensors: [sensor_kind === "dlp" ? "cutover-pii" : "cutover-waf"], diff_action: "create",
  })),
  vulnerability_profiles: [{ name: "cutover-vuln-profile", description: "", active: true, entries: [], domain_scope: {}, diff_action: "create" }],
  registries: [], unsupported: [], rollback_bundle: "{}",
};

function importedRule(category: "dlp" | "waf") {
  const source = preview.dpi_rules.find((rule) => rule.category === category)!;
  return {
    ...source, id: category === "dlp" ? "dlp-rule-id" : "waf-rule-id", dp_rule_id: category === "dlp" ? 101 : 102,
    org_id: "fixture-org", source: "neuvector", cfg_type: "imported", version: 1,
    created_at: createdAt, updated_at: createdAt,
  };
}

async function installFixture(page: Page) {
  let status: "none" | "previewed" | "applied" = "none";
  const unexpected: string[] = [];
  const importRecord = () => ({
    id: importId, source: "neuvector", status, target_cluster_id: clusterId, summary,
    applied_summary: status === "applied" ? { created: 8, updated: 0, groups: 2, network_rules: 1, vulnerability_profiles: 1, dpi_rules: 2, dpi_bindings: 2 } : undefined,
    unsupported: [], created_at: createdAt,
  });

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(/^\/api\/v1/, "");
    const method = request.method();
    let response: unknown;

    if (path === "/auth/me" && method === "GET") {
      response = { user_id: "fixture-user", org_id: "fixture-org", email: "fixture@example.test", roles: ["GlobalAdmin"] };
    } else if (path === "/clusters" && method === "GET") {
      response = { clusters: [{ id: clusterId, name: "MIG-1 Fixture", state: "connected" }] };
    } else if (path === "/migration/sources" && method === "GET") {
      response = { sources: [{ id: "neuvector", name: "NeuVector", status: "available", imports: [] }], workflow: [] };
    } else if (path === "/migration/preview" && method === "POST") {
      expect(request.postDataJSON()).toEqual({ source: "neuvector", cluster_id: clusterId, export: exportText });
      status = "previewed";
      response = preview;
    } else if (path === `/migration/imports/${importId}:apply` && method === "POST") {
      expect(status).toBe("previewed");
      status = "applied";
      response = { id: importId, status, applied: importRecord().applied_summary, unsupported: [] };
    } else if (path === "/migration/imports" && method === "GET") {
      response = { imports: status === "none" ? [] : [importRecord()], has_more: false };
    } else if (path === "/runtime-dlp-rules" && method === "GET") {
      expect(new URL(request.url()).searchParams.get("cluster_id")).toBe(clusterId);
      response = { rules: status === "applied" ? [importedRule("dlp")] : [] };
    } else if (path === "/runtime-signatures" && method === "GET") {
      expect(new URL(request.url()).searchParams.get("cluster_id")).toBe(clusterId);
      response = { signatures: status === "applied" ? [importedRule("waf")] : [] };
    } else if (path === "/runtime/dpi-sensor-bindings" && method === "GET") {
      response = { bindings: status === "applied" ? ["dlp", "waf"].map((sensor_kind) => ({
        id: `${sensor_kind}-binding`, org_id: "fixture-org", group_id: groupId, sensor_kind, sensor_id: "",
      })) : [] };
    } else if (path === "/groups" && method === "GET") {
      response = { groups: status === "applied" ? [{
        id: groupId, name: "cutover.api.default", kind: "ground", comment: "", criteria: [], members: [],
        learned_from: "", cfg_type: "imported", policy_mode: "monitor", profile_mode: "monitor", updated_at: createdAt,
      }] : [] };
    } else if (path === "/vuln-profiles" && method === "GET") {
      response = { profiles: [] };
    } else if (path === `/clusters/${clusterId}/network-rules` && method === "GET") {
      response = { cluster_id: clusterId, rules: [], summary: { total: 0, allow: 0, deny: 0, learned: 0, disabled: 0 } };
    } else if (path === "/findings" && method === "GET") {
      response = { findings: [] };
    } else if (path === "/runtime-threats" && method === "GET") {
      response = { threats: [] };
    } else {
      unexpected.push(`${method} ${path}`);
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
      return;
    }
    await route.fulfill({ status: 200, json: response });
  });
  return { unexpected, applied: () => status === "applied" };
}

test("MIG-1 imported DLP/WAF rules and group scope are visible across Migration and Policy Center", async ({ page }) => {
  const fixture = await installFixture(page);
  await page.goto("/settings/migration");
  await expect(page.getByRole("heading", { name: "Migration Imports" })).toBeVisible();
  await page.getByTestId("migration-target-cluster-select").selectOption(clusterId);
  await page.getByTestId("migration-export-input").fill(exportText);
  await page.getByTestId("migration-preview-submit").click();

  await expect(page.getByTestId("migration-import-id")).toHaveText(importId);
  await expect(page.getByTestId("migration-preview-dpi-rule")).toHaveCount(2);
  await expect(page.getByTestId("migration-preview-dpi-rule").filter({ hasText: dlpName })).toContainText("cutover-pii");
  await expect(page.getByTestId("migration-preview-dpi-rule").filter({ hasText: wafName })).toContainText("cutover-waf");
  await expect(page.getByTestId("migration-preview-dpi-binding")).toHaveCount(2);
  await expect(page.getByTestId("migration-preview-dpi-bindings")).toContainText("cutover.api.default");
  await expect(page.getByTestId("migration-import-history")).toContainText("previewed");

  await page.getByTestId("migration-import-apply-active").click();
  await expect.poll(fixture.applied).toBe(true);
  await expect(page.getByTestId("migration-import-history")).toContainText("applied");
  await expect(page.getByTestId("migration-import-apply-active")).toBeDisabled();

  await page.goto(`/clusters/${clusterId}/policy`);
  await expect(page.getByTestId("policy-center-page")).toBeVisible();
  await expect(page.getByTestId("policy-family-dlp-last-changed")).toContainText("Latest listed change:");
  await expect(page.getByTestId("policy-family-signatures-last-changed")).toContainText("Latest listed change:");
  await expect(page.getByTestId("policy-family-runtime-dlp").getByRole("link", { name: "Open DLP Rules" })).toHaveAttribute("href", `/clusters/${clusterId}/runtime-dlp`);
  await expect(page.getByTestId("policy-family-runtime-signatures").getByRole("link", { name: "Open WAF / DPI Signatures" })).toHaveAttribute("href", `/clusters/${clusterId}/runtime-signatures`);

  await page.getByTestId("policy-family-runtime-dlp").getByRole("link", { name: "Open DLP Rules" }).click();
  await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/runtime-dlp$`));
  await expect(page.getByRole("heading", { name: "DLP Rules", exact: true })).toBeVisible();
  await expect(page.getByTestId("runtime-dlp-row-dlp-rule-id")).toContainText("Promote");
  await expect(page.getByTestId("runtime-dlp-list")).toContainText(dlpName);
  await expect(page.getByTestId("runtime-dlp-list")).toContainText("NeuVector import");
  await expect(page.getByTestId("dlp-group-bindings-rows")).toContainText("cutover.api.default");
  await expect(page.getByTestId("runtime-dlp-nv-compatibility").getByRole("link", { name: "Migration Imports" })).toHaveAttribute("href", "/settings/migration");

  await page.goto(`/clusters/${clusterId}/policy`);
  await page.getByTestId("policy-family-runtime-signatures").getByRole("link", { name: "Open WAF / DPI Signatures" }).click();
  await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/runtime-signatures$`));
  await expect(page.getByRole("heading", { name: "DPI Signatures", exact: true })).toBeVisible();
  await expect(page.getByTestId("runtime-signature-row-waf-rule-id")).toContainText("Promote");
  await expect(page.getByTestId("runtime-signatures-list")).toContainText(wafName);
  await expect(page.getByTestId("runtime-signatures-list")).toContainText("WAF");
  await expect(page.getByTestId("runtime-signatures-list")).toContainText("ingress");
  await expect(page.getByTestId("runtime-signatures-list")).toContainText("NeuVector import");
  await expect(page.getByTestId("signature-group-bindings-rows")).toContainText("cutover.api.default");
  await expect(fixture.unexpected).toEqual([]);
});
