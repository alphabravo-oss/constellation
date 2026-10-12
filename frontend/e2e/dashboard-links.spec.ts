import { expect, test, type Page } from "@playwright/test";

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
            top_vulnerable: [{ id: "deployment-frontend", namespace: "default", name: "frontend", critical: 2, high: 1 }],
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
        body = { conversations: url.searchParams.get("verdict_group") === "blocked" ? [deny] : [deny, { ...deny, from: "default/worker", verdict: "allow" }], nodes: [], node_kinds: {}, edges: [], window_hours: 24 };
        break;
      case "/network/map":
        body = { workloads: [], flows: [], summary: { deny_capable_cni: false } };
        break;
      case "/components":
        body = { components: [], rollups: [] };
        break;
      case "/system-health":
      case "/system-health/clusters/" + clusterId:
        body = { heartbeats: [] };
        break;
      case "/clusters/" + clusterId + "/platform-facts":
        body = { cluster_id: clusterId, cluster_name: "Test cluster", distro: "kubernetes", status: "missing", findings_summary: { open: 0, critical: 0, high: 0, medium: 0, low: 0 }, findings: [] };
        break;
      case "/scan/status":
        body = { scanned: 0, scheduled: 0, scanning: 0, failed: 0 };
        break;
      case "/scan/scanner":
        body = { scanners: [] };
        break;
      case "/dashboard/events-timeline":
        body = { events_timeline: [] };
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

async function selectDashboardTab(page: Page, value: string, label: string) {
  await page.getByRole("tab", { name: label, exact: true }).click();
  await expect(page).toHaveURL(`${root}/dashboard?tab=${value}`);
  await expect(page.getByRole("tab", { name: label, exact: true })).toHaveAttribute("data-state", "active");
}

test("all metric tiles keep cluster scope and link to their source pages", async ({ page }) => {
  const dashboard = page.getByTestId("dashboard-page");
  const destinations: Array<[string, string]> = [
    ["Critical", "/findings?severity=critical&lifecycle=open"],
    ["High", "/findings?severity=high&lifecycle=open"],
    ["Open", "/findings?view=instances&lifecycle=open"],
    ["Accepted", "/findings?lifecycle=accepted"],
    ["Compliance", "/compliance"],
    ["Runtime · 24h", "/runtime?tab=evidence&hours=24"],
    ["Image CVEs", "/findings?view=instances&kind=vulnerability&lifecycle=open"],
    ["Host CVEs", "/nodes?risk=host-cves"],
    ["Fixable now", "/findings?view=instances&kind=vulnerability&lifecycle=open&fixable=true"],
    ["Privileged facts", "/deployments?hide_platform=false"],
    ["Root facts", "/deployments?hide_platform=false"],
    ["Exposure facts", "/deployments?hide_platform=false"],
  ];
  const summary = dashboard.getByTestId("dashboard-summary");
  for (const [label, destination] of destinations.slice(0, 4)) {
    await expect(summary.locator("a").filter({ has: page.getByText(label, { exact: true }) })).toHaveAttribute("href", `${root}${destination}`);
  }
  await selectDashboardTab(page, "posture", "Posture");
  await dashboard.locator("summary").filter({ hasText: "Additional posture metrics" }).click();
  for (const [label, destination] of destinations.slice(4)) {
    const link = dashboard.locator("a").filter({ has: page.getByText(label, { exact: true }) });
    await expect(link).toBeVisible();
    await expect(link).toHaveAttribute("href", `${root}${destination}`);
  }
  await selectDashboardTab(page, "operations", "Operations");
  for (const role of ["controller", "enforcer", "scanner", "admission", "discoverer"]) {
    await expect(dashboard.getByTestId(`dashboard-component-link-${role}`).locator("a")).toHaveAttribute("href", `${root}/components?role=${role}`);
  }
  await expect(dashboard.getByTestId("dashboard-scanner-freshness")).toHaveAttribute("href", "/settings/scanner");
});

test("panel links preserve the source, time window, and supported filters", async ({ page }) => {
  const dashboard = page.getByTestId("dashboard-page");
  await expect(dashboard.getByRole("link", { name: /view all/i })).toHaveAttribute("href", `${root}/findings?view=instances&lifecycle=open`);
  await selectDashboardTab(page, "network", "Network");
  await expect(dashboard.getByRole("link", { name: /view conversations/i })).toHaveAttribute("href", `${root}/network?tab=conversations&hours=24&verdict_group=blocked&hide_platform=false`);
  await expect(dashboard.getByTestId("dashboard-network-denies").getByRole("link")).toHaveAttribute("href", `${root}/network?tab=conversations&hours=24&verdict_group=blocked&from=default%2Ffrontend&to=default%2Fdatabase&hide_platform=false`);
  await expect(dashboard.getByRole("link", { name: /default\/frontend/ }).first()).toHaveAttribute("href", `${root}/network?tab=conversations&hours=168&from=external&to=default%2Ffrontend&hide_platform=false`);
  await expect(dashboard.getByRole("link", { name: /^frontend default 2C 1H$/ })).toHaveAttribute("href", `${root}/deployments/deployment-frontend`);
  await selectDashboardTab(page, "trends", "Trends");
  await expect(dashboard.getByRole("link", { name: /Open CVE DB/i })).toHaveAttribute("href", "/cve");
});

test("component role and denied conversation links activate source filters", async ({ page }) => {
  await selectDashboardTab(page, "operations", "Operations");
  await page.getByTestId("dashboard-component-link-scanner").locator("a").click();
  await expect(page).toHaveURL(`${root}/components?role=scanner`);
  await expect(page.getByTestId("component-nv-role-scanner")).toHaveClass(/border-primary/);

  await page.goto(`${root}/dashboard?tab=network`);
  await expect(page.getByRole("tab", { name: "Network", exact: true })).toHaveAttribute("data-state", "active");
  const filteredRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/network/conversations"
      && url.searchParams.get("cluster_id") === clusterId
      && url.searchParams.get("hours") === "24"
      && url.searchParams.get("verdict_group") === "blocked"
      && url.searchParams.get("from") === "default/frontend"
      && url.searchParams.get("to") === "default/database";
  });
  await page.getByTestId("dashboard-network-denies").getByRole("link").click();
  await filteredRequest;
  await expect(page.getByTestId("network-workspace-tab-conversations")).toHaveAttribute("data-state", "active");
  await expect(page.getByTestId("network-window-select")).toHaveValue("24");
  await expect(page.getByRole("combobox", { name: "Conversation outcome" })).toHaveValue("blocked");
  await expect(page.getByRole("textbox", { name: "Conversation from" })).toHaveValue("default/frontend");
  await expect(page.getByRole("textbox", { name: "Conversation to" })).toHaveValue("default/database");
  await expect(page.getByTestId("network-conversations-table")).toContainText("default/frontend");
});

test("network-denies header requests both denied and blocked conversations for 24 hours", async ({ page }) => {
  await selectDashboardTab(page, "network", "Network");
  const filteredRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/network/conversations"
      && url.searchParams.get("cluster_id") === clusterId
      && url.searchParams.get("hours") === "24"
      && url.searchParams.get("verdict_group") === "blocked";
  });
  await page.getByRole("link", { name: /view conversations/i }).click();
  await filteredRequest;
  await expect(page.getByTestId("network-workspace-tab-conversations")).toHaveAttribute("data-state", "active");
  await expect(page.getByTestId("network-conversations-table")).toContainText("default/frontend");
});
