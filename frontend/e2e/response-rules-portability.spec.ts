import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const yaml = "api_version: constellation.io/v1\nkind: ResponseRules\nscope: cluster\nrules: []\n";

test("response-rule YAML controls use the cluster-scoped import contract", async ({ page }) => {
  let imported = false;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    } else if (path === "/response-rules-v2" && request.method() === "GET") {
      await route.fulfill({ json: { rules: imported ? [{ id: "rule", name: "Imported response", enabled: true, priority: 10, event_type: "runtime", conditions: [], actions: [], workload_match: {} }] : [] } });
    } else if (path === "/response-rules-v2:export") {
      expect(url.searchParams.get("cluster_id")).toBe(clusterId);
      await route.fulfill({ contentType: "application/yaml", body: yaml });
    } else if (path === "/response-rules-v2:import") {
      expect(url.searchParams.get("cluster_id")).toBe(clusterId);
      expect(request.headers()["content-type"]).toContain("application/yaml");
      expect(request.postData()).toBe(yaml);
      imported = true;
      await route.fulfill({ json: { created: 1, replaced: 0, skipped: 0, results: [{ name: "Imported response", status: "created" }] } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });

  await page.goto(`/clusters/${clusterId}/response-rules`);
  await expect(page.getByTestId("response-rules-page")).toBeVisible();
  await expect(page.getByText("organization-wide rules remain separate")).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export", exact: true }).click();
  expect(readFileSync(await (await download).path(), "utf8")).toBe(yaml);
  await page.locator('input[type="file"]').setInputFiles({ name: "response-rules.yaml", mimeType: "application/yaml", buffer: Buffer.from(yaml) });
  await expect(page.getByText("Imported response")).toBeVisible();
});
