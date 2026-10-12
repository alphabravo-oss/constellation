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
        const matching = filtered
          ? [node("host-cve-a", 2), node("host-cve-b", 1), ...Array.from({ length: 98 }, (_, index) => node(`host-cve-peer-${index}`, 1)), node("host-cve-c", 1)]
          : [node("host-cve-a", 2), node("host-compliance-only", 0)];
        const items = matching.slice(offset, offset + 100);
        body = {
          cluster_id: clusterId, items, total: matching.length, limit: 100, offset, has_more: offset + items.length < matching.length,
          q: url.searchParams.get("q") || "", agent: url.searchParams.get("agent") || "", risk: url.searchParams.get("risk") || "", host_cves: filtered ? "open" : "",
          sort: url.searchParams.get("sort") || "seen", order: url.searchParams.get("order") || "desc",
          summary: { nodes: matching.length, runtime_agent_healthy: 0, runtime_agent_stale: 0, runtime_agent_missing: matching.length, scan_completed: 0, scan_gaps: matching.length, critical_vulns: matching.reduce((total, item) => total + item.critical_vulns, 0), high_vulns: 0, cis_failed: 0 },
        };
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

test("Host CVEs link keeps its finding scope and the node cohort supports server pages", async ({ page }) => {
  await page.goto(`${root}/dashboard`);
  const tile = page.getByTestId("dashboard-page").locator("a").filter({ has: page.getByText("Host CVEs", { exact: true }) }).first();
  await expect(tile).toHaveAttribute("href", `${root}/findings?view=instances&kind=vulnerability&lifecycle=open&target_type=host`);
  // Nodes remains a distinct legacy cohort: one node per source-cluster target.
  await page.goto(`${root}/nodes?risk=host-cves`);

  await expect(page).toHaveURL(`${root}/nodes?risk=host-cves`);
  await expect(page.getByTestId("node-risk-filter")).toHaveValue("host-cves");
  await expect(page.getByText("101 nodes match the server filters; 100 on this page.", { exact: false })).toBeVisible();
  await expect(page.getByTestId("nodes-table")).toContainText("host-cve-a");
  await expect(page.getByTestId("nodes-table")).not.toContainText("host-compliance-only");
  expect(seenNodeRequests[0].pathname).toBe(`/api/v1/clusters/${clusterId}/nodes`);
  expect(seenNodeRequests[0].searchParams.get("host_cves")).toBe("open");
  expect(seenNodeRequests[0].searchParams.get("offset")).toBe("0");

  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByText("101 nodes match the server filters; 1 on this page.", { exact: false })).toBeVisible();
  await expect(page.getByTestId("nodes-table")).toContainText("host-cve-c");
  await expect(page.getByRole("button", { name: "Next", exact: true })).toBeDisabled();
  expect(seenNodeRequests[1].searchParams.get("offset")).toBe("100");
  expect(seenNodeRequests.every((url) => url.pathname === `/api/v1/clusters/${clusterId}/nodes`)).toBe(true);
});

test("risk selector and browser history restore the host filter", async ({ page }) => {
  await page.goto(`${root}/nodes?risk=host-cves`);
  await expect(page.getByText("101 nodes match the server filters; 100 on this page.", { exact: false })).toBeVisible();

  await page.getByTestId("node-risk-filter").selectOption("all");
  await expect(page).toHaveURL(`${root}/nodes`);
  await expect(page.getByTestId("nodes-table")).toContainText("host-compliance-only");
  await expect(page.getByText("2 nodes match the server filters; 2 on this page.", { exact: false })).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(`${root}/nodes?risk=host-cves`);
  await expect(page.getByTestId("node-risk-filter")).toHaveValue("host-cves");
  await expect(page.getByTestId("nodes-table")).not.toContainText("host-compliance-only");
});
