import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const root = `/clusters/${clusterId}`;

const deny = {
  from: "default/frontend",
  to: "default/database",
  bytes: 4096,
  packets: 4,
  edges: 1,
  last_seen: "2026-09-26T12:00:00Z",
  severity: 8,
  verdict: "deny",
  apps: ["postgres"],
};

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
          findings_by_severity: { critical: 3, high: 4, medium: 1, low: 0, info: 0 },
          findings_total: 9,
          open_findings: 8,
          accepted_risks: 1,
          recent_activity: [],
          posture: {
            security_score: 42,
            score_breakdown: {},
            vulns_by_location: { image: 2, host: 1 },
            vuln_signals: { fixable: 3 },
            hardening: { privileged: 1, run_as_root: 2, exposed: 1 },
            enforcement: {},
            cves_by_mode: {},
            exposed_by_mode: {},
            top_vulnerable: [{ namespace: "default", name: "frontend", critical: 2, high: 1 }],
          },
        };
        break;
      case "/findings":
        body = { findings: [] };
        break;
      case "/network/exposure":
        body = { ingress: [{ workload: "default/frontend", namespace: "default", name: "frontend", external_peers: 2, protocols: ["TCP"], ports: [443], sessions: 4, critical: 2, high: 1, risk_score: 70, policy_mode: "monitor" }], egress: [] };
        break;
      case "/network/conversations":
        body = { conversations: url.searchParams.get("verdict") === "deny" ? [deny] : [deny, { ...deny, from: "default/worker", verdict: "allow" }], nodes: [], node_kinds: {}, edges: [], window_hours: 24 };
        break;
      case "/network/map":
        body = { workloads: [], flows: [], summary: { deny_capable_cni: false } };
        break;
      case "/components":
        body = { components: [], rollups: [] };
        break;
      case "/system-health/clusters/" + clusterId:
        body = { heartbeats: [] };
        break;
      case "/federation/state":
        body = { state: "standalone" };
        break;
      case "/cve/bundle":
        body = { available: false };
        break;
      case "/cve/stats":
        body = { total: 0, kev_listed: 0, epss_gt_50: 0 };
        break;
      case "/compliance/summary":
        body = { frameworks: [] };
        break;
      case "/runtime/overview":
        body = { summary: { alerts: 2, blocks: 1 }, subsystems: [], rules: [], recent_events: [], workloads: [] };
        break;
      default:
        await route.fulfill({ status: 404, json: { error: `Unmocked ${path}` } });
        return;
    }
    await route.fulfill({ json: body });
  });
  await page.goto(`${root}/dashboard`);
  await expect(page.getByTestId("dashboard-page")).toBeVisible();
});

test("all metric tiles keep cluster scope and link to their source pages", async ({ page }) => {
  const dashboard = page.getByTestId("dashboard-page");
  const destinations: Array<[string, string]> = [
    ["Critical", "/findings?severity=critical"],
    ["High", "/findings?severity=high"],
    ["Open", "/findings"],
    ["Accepted", "/findings?lifecycle=accepted"],
    ["Compliance", "/compliance"],
    ["Runtime · 24h", "/runtime"],
    ["Image CVEs", "/findings"],
    ["Host CVEs", "/nodes?risk=host-cves"],
    ["Fixable now", "/findings"],
    ["Privileged", "/deployments"],
    ["Run as root", "/deployments"],
    ["Exposed WLs", "/network"],
  ];
  for (const [label, destination] of destinations) {
    await expect(dashboard.locator("a").filter({ has: page.getByText(label, { exact: true }) }).first()).toHaveAttribute("href", `${root}${destination}`);
  }
  for (const role of ["controller", "enforcer", "scanner", "admission", "discoverer"]) {
    await expect(dashboard.getByTestId(`dashboard-component-link-${role}`).locator("a")).toHaveAttribute("href", `${root}/components?role=${role}`);
  }
  await expect(dashboard.getByTestId("dashboard-scanner-freshness")).toHaveAttribute("href", "/settings/scanner");
});

test("panel links preserve the source, time window, and supported filters", async ({ page }) => {
  const dashboard = page.getByTestId("dashboard-page");
  await expect(dashboard.getByRole("link", { name: /view conversations/i })).toHaveAttribute("href", `${root}/network?tab=conversations&hours=24&verdict=deny`);
  await expect(dashboard.getByTestId("dashboard-network-denies").getByRole("link")).toHaveAttribute("href", `${root}/network?tab=conversations&hours=24&verdict=deny&workload=default%2Ffrontend`);
  await expect(dashboard.getByRole("link", { name: /default\/frontend/ }).first()).toHaveAttribute("href", `${root}/deployments?q=frontend`);
  await expect(dashboard.getByRole("link", { name: /^frontend default 2C 1H$/ })).toHaveAttribute("href", `${root}/deployments?q=frontend`);
  await expect(dashboard.getByRole("link", { name: /view all/i })).toHaveAttribute("href", `${root}/findings`);
  await expect(dashboard.getByRole("link", { name: /Open CVE DB/i })).toHaveAttribute("href", "/cve");
});

test("component role and denied conversation links activate source filters", async ({ page }) => {
  await page.getByTestId("dashboard-component-link-scanner").locator("a").click();
  await expect(page).toHaveURL(`${root}/components?role=scanner`);
  await expect(page.getByTestId("component-nv-role-scanner")).toHaveClass(/border-primary/);

  await page.goto(`${root}/dashboard`);
  const filteredRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/network/conversations"
      && url.searchParams.get("cluster_id") === clusterId
      && url.searchParams.get("hours") === "24"
      && url.searchParams.get("verdict") === "deny";
  });
  await page.getByTestId("dashboard-network-denies").getByRole("link").click();
  await filteredRequest;
  await expect(page.getByTestId("network-workspace-tab-conversations")).toHaveAttribute("data-state", "active");
  await expect(page.getByTestId("network-window-select")).toHaveValue("24");
  await expect(page.getByTestId("network-verdict-select")).toHaveValue("deny");
  await expect(page.getByTestId("network-conversations-table")).toContainText("default/frontend");
});

test("network-denies header requests denied conversations for 24 hours", async ({ page }) => {
  const filteredRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/network/conversations"
      && url.searchParams.get("cluster_id") === clusterId
      && url.searchParams.get("hours") === "24"
      && url.searchParams.get("verdict") === "deny";
  });
  await page.getByRole("link", { name: /view conversations/i }).click();
  await filteredRequest;
  await expect(page.getByTestId("network-workspace-tab-conversations")).toHaveAttribute("data-state", "active");
  await expect(page.getByTestId("network-conversations-table")).toContainText("default/frontend");
});
