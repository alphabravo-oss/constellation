import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const root = `/clusters/${clusterId}`;
const seenAt = "2026-09-26T12:00:00Z";
const deployment = (name: string, namespace: string, riskScore: number) => ({
  id: `${namespace}-${name}`,
  namespace,
  name,
  kind: "Deployment",
  risk_score: riskScore,
  risk_factors: {},
  finding_count: 1,
  critical_count: 1,
  high_count: 0,
  last_seen_at: seenAt,
});
const deployments = [
  deployment("frontend", "default", 70),
  deployment("api-service", "default", 90),
  deployment("frontend-canary", "payments", 30),
];

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
          findings_by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
          findings_total: 1,
          open_findings: 1,
          accepted_risks: 0,
          recent_activity: [],
          posture: {
            security_score: 70,
            score_breakdown: {},
            vulns_by_location: {},
            vuln_signals: {},
            hardening: {},
            enforcement: {},
            cves_by_mode: {},
            exposed_by_mode: {},
            top_vulnerable: [{ namespace: "default", name: "frontend", critical: 2, high: 1 }],
          },
        };
        break;
      case "/deployments":
        body = {
          deployments: deployments.filter((row) => !url.searchParams.has("namespace") || row.namespace === url.searchParams.get("namespace")),
        };
        break;
      default:
        await route.fulfill({ status: 404, json: { error: `Unmocked ${path}` } });
        return;
    }
    await route.fulfill({ json: body });
  });
});

test("Dashboard link filters deployment rows and search follows browser history", async ({ page }) => {
  await page.goto(`${root}/dashboard`);
  const dashboardLink = page.getByTestId("dashboard-page").getByRole("link", { name: /^frontend default 2C 1H$/ });
  await expect(dashboardLink).toHaveAttribute("href", `${root}/deployments?q=frontend`);

  const deploymentRequest = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/deployments");
  await dashboardLink.click();
  expect(new URL((await deploymentRequest).url()).searchParams.get("cluster_id")).toBe(clusterId);
  await expect(page).toHaveURL(`${root}/deployments?q=frontend`);

  const search = page.getByTestId("deployment-search");
  const rows = page.getByTestId("deployment-row");
  await expect(search).toHaveValue("frontend");
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("default/frontend");
  await expect(rows.last()).toContainText("payments/frontend-canary");
  await expect(page.getByTestId("deployments-summary").locator(".text-display").first()).toHaveText("2");

  await search.fill("API");
  await expect(page).toHaveURL(`${root}/deployments?q=API`);
  await expect(search).toHaveValue("API");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("default/api-service");
  await expect(page.getByTestId("deployments-summary").locator(".text-display").first()).toHaveText("1");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export CSV" }).click();
  const csv = readFileSync(await (await download).path(), "utf8");
  expect(csv).toContain("api-service");
  expect(csv).not.toContain("frontend");

  await page.goBack();
  await expect(page).toHaveURL(`${root}/deployments?q=frontend`);
  await expect(search).toHaveValue("frontend");
  await expect(rows).toHaveCount(2);

  await page.goForward();
  await expect(page).toHaveURL(`${root}/deployments?q=API`);
  await expect(search).toHaveValue("API");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("default/api-service");
});

test("name search filters namespace-scoped server results", async ({ page }) => {
  await page.goto(`${root}/deployments?q=frontend`);
  await expect(page.getByTestId("deployment-row")).toHaveCount(2);

  const namespaceRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/deployments" && url.searchParams.get("namespace") === "payments";
  });
  await page.getByTestId("namespace-filter").fill("payments");
  expect(new URL((await namespaceRequest).url()).searchParams.get("cluster_id")).toBe(clusterId);
  await expect(page.getByTestId("deployment-search")).toHaveValue("frontend");
  await expect(page.getByTestId("deployment-row")).toHaveCount(1);
  await expect(page.getByTestId("deployment-row")).toContainText("payments/frontend-canary");

  await page.getByTestId("deployment-search").fill("api");
  await expect(page.getByTestId("deployment-row")).toHaveCount(0);
  await expect(page.getByTestId("deployments-table")).toContainText("No deployments match this search.");

  await page.getByTestId("deployment-search").fill("");
  await expect(page).toHaveURL(`${root}/deployments`);
  await expect(page.getByTestId("deployment-row")).toHaveCount(1);
  await expect(page.getByTestId("deployment-row")).toContainText("payments/frontend-canary");
});
