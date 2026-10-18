import { test, expect } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const root = `/clusters/${clusterId}/compliance`;
const schedule = { id: "schedule", name: "CIS production weekly", framework: "cis-k8s-1.9", cron_expression: "0 2 * * 1", timezone: "UTC", enabled: true, delivery: [{ kind: "file", target: "file:///reports/" }], report_format: "pdf", report_template: "compliance-detailed", last_status: "succeeded" };

const requestMessage = "Run requested; processing is pending. A running report scheduler is required. Review History for execution and delivery.";

test.beforeEach(async ({ page }) => {
  let localEnabled = false;
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
    else if (path === "/compliance/schedules") body = { schedules: [schedule, { ...schedule, id: "local", name: "Local schedule", cluster_id: clusterId, enabled: localEnabled }], summary: { total: 2, enabled: localEnabled ? 2 : 1, disabled: localEnabled ? 0 : 1 }, frameworks: ["cis-k8s-1.9"], report_formats: ["html", "json", "csv", "sarif", "pdf"] };
    else if (path === "/compliance/schedules/schedule/run-now") { await route.fulfill({ status: 202, json: { schedule, queued: true, message: requestMessage } }); return; }
    else if (path === "/compliance/schedules/local/run-now") { localEnabled = true; await route.fulfill({ status: 202, json: { schedule: { ...schedule, id: "local", enabled: true }, queued: true, message: requestMessage } }); return; }
    else if (path === "/compliance/schedules/schedule/runs") body = { runs: [{ id: "run", org_id: "org", schedule_id: "schedule", framework: "cis-k8s-1.9", started_at: "2026-10-12T00:00:00Z", status: "succeeded", summary: { pass: 1, fail: 0, manual: 0 }, artifact_signature: "fixture-signature", artifact_uri: "file:///fixture-evidence.html", artifact_format: "html", artifact_media_type: "text/html; charset=utf-8", artifact_filename: "fixture-evidence.html", artifact_metadata_known: true }] };
    else if (path === "/compliance/runs/run/artifact") { await route.fulfill({ body: "<!doctype html><title>Compliance evidence</title>", contentType: "text/html", headers: { "content-disposition": 'attachment; filename="fixture-evidence.html"' } }); return; }
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
  await expect(page.getByTestId("schedule-run-schedule")).toHaveText("Request run");
  await page.getByTestId("schedule-run-schedule").click();
  await expect(page.locator('section[aria-live="polite"]').getByText(requestMessage, { exact: true })).toBeVisible();
  await page.getByTestId("schedule-runs-toggle-schedule").click();
  await expect(page.getByTestId("schedule-runs-schedule")).toContainText("Signature recorded");
  const artifact = page.waitForEvent("download");
  await page.getByTestId("run-download-run").click();
  await expect((await artifact).suggestedFilename()).toBe("fixture-evidence.html");
  await expect(page.getByTestId("schedule-runs-schedule")).toContainText("HTML");
});

test("New schedule uses its own URL, retains failed drafts and cancels to the scoped tab", async ({ page }) => {
  await page.goto(`${root}?tab=schedules&filter=auditors`);
  await page.getByTestId("schedule-create-open").click();
  await expect(page).toHaveURL(new RegExp(`/clusters/${clusterId}/compliance/schedules/new`));
  await expect(page.getByRole("heading", { name: "New compliance schedule" })).toBeVisible();
  await expect(page.getByLabel("Report format")).toHaveValue("html");
  await page.getByTestId("wizard-name").fill("Draft schedule");
  await page.getByLabel("Report format").selectOption("json");
  await page.getByRole("button", { name: "Create schedule", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Your draft is preserved" })).toBeVisible();
  await expect(page.getByTestId("wizard-name")).toHaveValue("Draft schedule");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(`${root}?tab=schedules&filter=auditors`);
  await expect(page.locator("form")).toHaveCount(0);
});

test("Disabled schedules disclose enabling before a pending run request", async ({ page }) => {
  await page.goto(`${root}?tab=schedules`);
  const action = page.getByTestId("schedule-run-local");
  await expect(action).toHaveText("Enable and request run");
  const requested = page.waitForRequest(request => request.method() === "POST" && new URL(request.url()).pathname === "/api/v1/compliance/schedules/local/run-now");
  await action.click();
  await requested;
  await expect(page.locator('section[aria-live="polite"]').getByText(requestMessage, { exact: true })).toBeVisible();
  await expect(action).toHaveText("Request run");
});

test("Schedule actions and long metadata fit narrow screens", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 900 });
  const name = "production".repeat(18);
  const template = "compliance".repeat(18);
  await page.route("**/api/v1/**", async route => {
    if (new URL(route.request().url()).pathname !== "/api/v1/compliance/schedules") return route.fallback();
    await route.fulfill({ json: { schedules: [{ ...schedule, id: "local", name, report_template: template, cluster_id: clusterId, enabled: false }], summary: { total: 1, enabled: 0, disabled: 1 }, frameworks: ["cis-k8s-1.9"], report_formats: ["html", "json", "csv", "sarif", "pdf"] } });
  });
  await page.goto(`${root}?tab=schedules`);
  const card = page.getByTestId("schedule-local");
  await expect(card).toContainText(name);
  await expect(card).toContainText(template);
  await expect(card.getByRole("button", { name: "Enable and request run" })).toBeVisible();
  await expect.poll(() => card.evaluate(element => {
    const bounds = element.getBoundingClientRect();
    return bounds.left >= -1 && bounds.right <= document.documentElement.clientWidth + 1 && element.scrollWidth <= element.clientWidth + 1 && Array.from(element.querySelectorAll("button")).every(button => {
      const action = button.getBoundingClientRect();
      return action.left >= bounds.left && action.right <= bounds.right;
    });
  })).toBe(true);
});


test("Schedule enabled state changes through PATCH without requesting a run", async ({ page }) => {
  let enabled = false;
  const patches: boolean[] = [];
  const runRequests: string[] = [];
  page.on("request", request => { if (new URL(request.url()).pathname.endsWith("/run-now")) runRequests.push(request.url()); });
  await page.route("**/api/v1/compliance/schedules**", async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path === "/api/v1/compliance/schedules" && request.method() === "GET") {
      await route.fulfill({ json: { schedules: [{ ...schedule, id: "local", org_id: "org", cluster_id: clusterId, enabled }], summary: { total: 1, enabled: enabled ? 1 : 0, disabled: enabled ? 0 : 1 }, frameworks: [schedule.framework], report_formats: ["html", "json", "csv", "sarif", "pdf"] } }); return;
    }
    if (path === "/api/v1/compliance/schedules/local" && request.method() === "PATCH") {
      const body = request.postDataJSON(); expect(body).toEqual({ enabled: !enabled });
      enabled = body.enabled; patches.push(enabled);
      await route.fulfill({ json: { ...schedule, id: "local", org_id: "org", cluster_id: clusterId, enabled } }); return;
    }
    await route.fallback();
  });
  await page.goto(`${root}?tab=schedules`);
  const card = page.getByTestId("schedule-local");
  await expect(page.getByTestId("schedule-enabled-local")).toHaveText("Disabled");
  await card.getByRole("button", { name: "Enable schedule", exact: true }).click();
  await expect(page.getByTestId("schedule-enabled-local")).toHaveText("Enabled");
  await expect(page.getByText("1 configured · 1 enabled · 0 disabled", { exact: true })).toBeVisible();
  await card.getByRole("button", { name: "Disable schedule", exact: true }).click();
  await expect(page.getByTestId("schedule-enabled-local")).toHaveText("Disabled");
  expect(patches).toEqual([true, false]); expect(runRequests).toEqual([]);
});
