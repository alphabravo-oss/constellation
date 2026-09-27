import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const otherClusterId = "22222222-2222-4222-8222-222222222222";
const root = `/clusters/${clusterId}`;
const seenNodeRequests: URL[] = [];

function node(name: string, openVulns: number) {
  return {
    node: name,
    cluster_id: clusterId,
    open_vulns: openVulns,
    critical_vulns: openVulns,
    high_vulns: 0,
    medium_vulns: 0,
    low_vulns: 0,
    runtime_agent_status: "missing",
    scan_status: "missing",
    package_count: 0,
    container_count: 0,
    process_count: 0,
    cis_failed: 0,
    last_seen_at: "2026-09-26T12:00:00Z",
  };
}

test.beforeEach(async ({ page }) => {
  seenNodeRequests.length = 0;
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    let body: unknown;
    switch (path) {
      case "/auth/me":
        body = { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] };
        break;
      case "/clusters":
        body = { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }, { id: otherClusterId, name: "Other cluster", state: "connected" }] };
        break;
      case "/dashboard/summary":
        body = {
          findings_by_severity: { critical: 3, high: 0, medium: 0, low: 0, info: 0 },
          findings_total: 3,
          open_findings: 3,
          accepted_risks: 0,
          recent_activity: [],
          posture: { security_score: 60, score_breakdown: {}, vulns_by_location: { host: 4, image: 0 }, vuln_signals: {}, hardening: {}, enforcement: {}, cves_by_mode: {}, exposed_by_mode: {}, top_vulnerable: [] },
        };
        break;
      case `/clusters/${clusterId}/nodes`: {
        seenNodeRequests.push(url);
        const offset = Number(url.searchParams.get("offset"));
        const filtered = url.searchParams.get("host_cves") === "open";
        const items = filtered
          ? offset === 0 ? [node("host-cve-a", 2), node("host-cve-b", 1)] : [node("host-cve-c", 1)]
          : [node("host-cve-a", 2), node("host-compliance-only", 0)];
        body = { cluster_id: clusterId, items, summary: {}, total: filtered ? 3 : 2, limit: 100, offset };
        break;
      }
      case "/findings":
        body = { findings: [] };
        break;
      default:
        await route.fulfill({ status: 404, json: { error: `Unmocked ${path}` } });
        return;
    }
    await route.fulfill({ json: body });
  });
});

test("Host CVEs tile opens a cluster-scoped, paged node filter", async ({ page }) => {
  await page.goto(`${root}/dashboard`);
  const tile = page.getByTestId("dashboard-page").locator("a").filter({ has: page.getByText("Host CVEs", { exact: true }) }).first();
  await expect(tile).toHaveAttribute("href", `${root}/nodes?risk=host-cves`);
  await tile.click();

  await expect(page).toHaveURL(`${root}/nodes?risk=host-cves`);
  await expect(page.getByTestId("node-risk-filter")).toHaveValue("host-cves");
  await expect(page.getByTestId("nodes-page-count")).toHaveText("Showing 2 of 3 nodes");
  await expect(page.getByTestId("nodes-table")).toContainText("host-cve-a");
  await expect(page.getByTestId("nodes-table")).not.toContainText("host-compliance-only");
  expect(seenNodeRequests[0].pathname).toBe(`/api/v1/clusters/${clusterId}/nodes`);
  expect(seenNodeRequests[0].searchParams.get("host_cves")).toBe("open");
  expect(seenNodeRequests[0].searchParams.get("offset")).toBe("0");

  await page.getByTestId("nodes-load-more").click();
  await expect(page.getByTestId("nodes-page-count")).toHaveText("Showing 3 of 3 nodes");
  await expect(page.getByTestId("nodes-table")).toContainText("host-cve-c");
  await expect(page.getByTestId("nodes-load-more")).toHaveCount(0);
  expect(seenNodeRequests[1].searchParams.get("offset")).toBe("2");
  expect(seenNodeRequests.every((url) => url.pathname === `/api/v1/clusters/${clusterId}/nodes`)).toBe(true);
});

test("risk selector and browser history restore the host filter", async ({ page }) => {
  await page.goto(`${root}/nodes?risk=host-cves`);
  await expect(page.getByTestId("nodes-page-count")).toHaveText("Showing 2 of 3 nodes");

  await page.getByTestId("node-risk-filter").selectOption("all");
  await expect(page).toHaveURL(`${root}/nodes`);
  await expect(page.getByTestId("nodes-table")).toContainText("host-compliance-only");
  await expect(page.getByTestId("nodes-page-count")).toHaveText("Showing 2 of 2 nodes");

  await page.goBack();
  await expect(page).toHaveURL(`${root}/nodes?risk=host-cves`);
  await expect(page.getByTestId("node-risk-filter")).toHaveValue("host-cves");
  await expect(page.getByTestId("nodes-table")).not.toContainText("host-compliance-only");
});
