import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const root = `/clusters/${clusterId}`;

const fixtureFindings = [
  { id: "critical-open", title: "Critical open finding", severity: "critical", lifecycle: "open", kind: "vulnerability", external_id: "CVE-2026-0001" },
  { id: "high-open", title: "High open finding", severity: "high", lifecycle: "open", kind: "vulnerability", external_id: "CVE-2026-0002" },
  { id: "critical-accepted", title: "Critical accepted finding", severity: "critical", lifecycle: "accepted", kind: "license" },
].map((finding, index) => ({
  ...finding,
  risk_score: 90 - index * 10,
  asset_id: `asset-${index}`,
  attack_techniques: [],
  first_seen_at: "2026-09-26T12:00:00Z",
  last_seen_at: "2026-09-26T12:00:00Z",
}));

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    let body: unknown;
    switch (path) {
      case "/auth/me":
        body = { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] };
        break;
      case "/clusters":
        body = { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] };
        break;
      case "/dashboard/summary":
        body = {
          findings_by_severity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
          findings_total: 3,
          open_findings: 2,
          accepted_risks: 1,
          recent_activity: [],
          posture: { security_score: 42, score_breakdown: {}, vulns_by_location: {}, vuln_signals: {}, hardening: {}, enforcement: {}, cves_by_mode: {}, exposed_by_mode: {}, top_vulnerable: [] },
        };
        break;
      case "/findings": {
        const lifecycle = url.searchParams.get("lifecycle");
        const severity = url.searchParams.get("q")?.match(/^severity:(critical|high)$/)?.[1];
        body = {
          findings: fixtureFindings.filter((finding) => (!lifecycle || finding.lifecycle === lifecycle) && (!severity || finding.severity === severity)),
          lifecycle_counts: { open: 2, accepted: 1, suppressed: 0, triaged: 0, in_progress: 0 },
          limit: 500,
          offset: 0,
        };
        break;
      }
      case "/findings/by-cve":
        body = { cves: [], total: 0, limit: 100, offset: 0 };
        break;
      default:
        await route.fulfill({ status: 404, json: { error: `Unmocked ${path}` } });
        return;
    }
    await route.fulfill({ json: body });
  });
});

test("dashboard severity and accepted tiles show filtered instance rows", async ({ page }) => {
  await page.goto(`${root}/dashboard`);
  const dashboard = page.getByTestId("dashboard-page");

  for (const [tile, query, title] of [
    ["Critical", "severity=critical", "Critical open finding"],
    ["High", "severity=high", "High open finding"],
    ["Accepted", "lifecycle=accepted", "Critical accepted finding"],
  ]) {
    const filteredRequest = page.waitForRequest((request) => {
      const url = new URL(request.url());
      return url.pathname === "/api/v1/findings"
        && url.searchParams.get("cluster_id") === clusterId
        && url.searchParams.get("lifecycle") === (tile === "Accepted" ? "accepted" : "open")
        && url.searchParams.get("q") === (tile === "Accepted" ? null : `severity:${tile.toLowerCase()}`);
    });
    await dashboard.locator("a").filter({ has: page.getByText(tile, { exact: true }) }).first().click();
    await filteredRequest;
    await expect(page).toHaveURL(`${root}/findings?${query}`);
    await expect(page.getByTestId("findings-view-instances")).toBeVisible();
    if (tile !== "Accepted") await expect(page.getByTestId("findings-view-cve")).toBeDisabled();
    await expect(page.getByTestId("findings-table")).toContainText(title);
    await expect(page.getByTestId("findings-table")).not.toContainText(tile === "High" ? "Critical open finding" : "High open finding");
    if (tile === "Accepted") {
      await expect(page.getByTestId("finding-state-tabs").getByRole("button", { name: /Accepted/ })).toHaveClass(/ring-1/);
    } else {
      await expect(page.getByRole("combobox", { name: "Severity" })).toHaveValue(tile.toLowerCase());
    }
    await page.goto(`${root}/dashboard`);
    await expect(dashboard).toBeVisible();
  }
});

test("filter controls update URL and browser history restores the list", async ({ page }) => {
  await page.goto(`${root}/findings?severity=critical`);
  const table = page.getByTestId("findings-table");
  const severity = page.getByRole("combobox", { name: "Severity" });
  await expect(table).toContainText("Critical open finding");
  await expect(page.getByTestId("findings-view-cve")).toBeDisabled();
  await severity.selectOption("high");
  await expect(page).toHaveURL(`${root}/findings?severity=high`);
  await expect(table).toContainText("High open finding");
  await expect(table).not.toContainText("Critical open finding");
  await expect(page.getByTestId("findings-view-cve")).toBeDisabled();

  await page.getByTestId("finding-state-tabs").getByRole("button", { name: /Accepted/ }).click();
  await expect(page).toHaveURL(`${root}/findings?severity=high&lifecycle=accepted`);
  await expect(table).not.toContainText("High open finding");

  await page.goBack();
  await expect(page).toHaveURL(`${root}/findings?severity=high`);
  await expect(table).toContainText("High open finding");
  await page.goBack();
  await expect(page).toHaveURL(`${root}/findings?severity=critical`);
  await expect(severity).toHaveValue("critical");
  await expect(table).toContainText("Critical open finding");
  await page.goForward();
  await expect(severity).toHaveValue("high");
  await expect(table).toContainText("High open finding");
});

test("all-lifecycle bookmarks and saved views still show every state", async ({ page }) => {
  await page.goto(`${root}/findings?lifecycle=all`);
  const table = page.getByTestId("findings-table");
  await expect(table).toContainText("Critical open finding");
  await expect(table).toContainText("Critical accepted finding");
  await expect(page.getByRole("button", { name: "Remove lifecycle filter" }).locator("..")).toContainText("lifecycle:all");
  await page.getByRole("button", { name: "Remove lifecycle filter" }).click();
  await expect(page).toHaveURL(`${root}/findings`);
  await expect(table).not.toContainText("Critical accepted finding");
});
