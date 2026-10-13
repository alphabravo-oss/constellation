import { test, expect } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const root = `/clusters/${clusterId}/compliance`;
const schedule = { id: "schedule", name: "CIS production weekly", framework: "cis-k8s-1.9", cron_expression: "0 2 * * 1", timezone: "UTC", enabled: true, delivery: [{ kind: "file", target: "file:///reports/" }], report_format: "json", report_template: "compliance-detailed", last_status: "succeeded" };

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api\/v1/, "");
    let body: unknown;
    if (path === "/auth/me") body = { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] };
    else if (path === "/clusters") body = { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] };
    else if (path === "/compliance/frameworks") body = { frameworks: [{ id: "cis-k8s-1.9", name: "CIS Kubernetes 1.9", category: "kubernetes" }] };
    else if (path === "/compliance/summary") body = { frameworks: [] };
    else if (path === "/compliance/schedules" && route.request().method() === "POST") {
      expect(route.request().postDataJSON()).toMatchObject({ cluster_id: clusterId, name: "Draft schedule", report_format: "json", framework: "cis-k8s-1.9" });
      await route.fulfill({ status: 503, json: { error: "Fixture save failure" } }); return;
    }
    else if (path === "/compliance/schedules") body = { schedules: [schedule, { ...schedule, id: "local", name: "Local schedule", cluster_id: clusterId }], summary: { total: 2, enabled: 2, disabled: 0 }, frameworks: ["cis-k8s-1.9"], report_formats: ["pdf", "json", "sarif", "csv"] };
    else if (path === "/compliance/schedules/schedule/run-now") body = { schedule, queued: true, message: "queued" };
    else if (path === "/compliance/schedules/schedule/runs") body = { runs: [{ id: "run", framework: "cis-k8s-1.9", started_at: "2026-10-12T00:00:00Z", status: "succeeded", summary: { pass: 1, fail: 0, manual: 0 }, artifact_signature: "fixture-signature", artifact_uri: "fixture-artifact" }] };
    else if (path === "/compliance/runs/run/artifact") { await route.fulfill({ body: "{\"fixture\":true}", contentType: "application/json" }); return; }
    else { await route.fulfill({ status: 404, json: { error: `Unmocked ${path}` } }); return; }
    await route.fulfill({ json: body });
  });
});

test("Schedules workspace preserves inherited scope, run history and artifact downloads", async ({ page }) => {
  await page.goto(`${root}?tab=schedules`);
  await expect(page.getByRole("heading", { name: "Compliance", exact: true })).toBeVisible();
  await expect(page.getByTestId("schedule-schedule")).toContainText("Organization schedule · applies across clusters");
  await expect(page.getByTestId("schedule-local")).toContainText("Cluster schedule");
  await expect(page.locator("form")).toHaveCount(0);
  await page.getByTestId("schedule-run-schedule").click();
  await expect(page.getByRole("status").filter({ hasText: "Compliance run queued" })).toBeVisible();
  await page.getByTestId("schedule-runs-toggle-schedule").click();
  await expect(page.getByTestId("schedule-runs-schedule")).toContainText("Signature recorded");
  const artifact = page.waitForEvent("download");
  await page.getByTestId("run-download-run").click();
  await expect((await artifact).suggestedFilename()).toBeTruthy();
});

test("New schedule uses its own URL, retains failed drafts and cancels to the scoped tab", async ({ page }) => {
  await page.goto(`${root}?tab=schedules&filter=auditors`);
  await page.getByTestId("schedule-create-open").click();
  await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/compliance/schedules/new`));
  await expect(page.getByRole("heading", { name: "New compliance schedule" })).toBeVisible();
  await page.getByTestId("wizard-name").fill("Draft schedule");
  await page.getByLabel("Report format").selectOption("json");
  await page.getByRole("button", { name: "Create schedule", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Your draft is preserved" })).toBeVisible();
  await expect(page.getByTestId("wizard-name")).toHaveValue("Draft schedule");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(`${root}?tab=schedules&filter=auditors`);
  await expect(page.locator("form")).toHaveCount(0);
});
