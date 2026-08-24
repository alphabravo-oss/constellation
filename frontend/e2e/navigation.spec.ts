import { test, expect, type Page } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

const CLUSTER_ROUTES: { label: string; heading: RegExp }[] = [
  { label: "Dashboard",      heading: /Posture|Security|Dashboard/i },
  { label: "NeuVector Switchboard", heading: /^NeuVector Switchboard$/i },
  { label: "Findings",       heading: /^Findings$/i },
  { label: "Assets",         heading: /^Assets$/i },
  { label: "Compliance",     heading: /^Compliance$/i },
  { label: "Exceptions",     heading: /Vulnerability Exceptions/i },
  { label: "Network Map",    heading: /^Network/i },
  { label: "Runtime",        heading: /^Runtime$/i },
  { label: "Response Rules", heading: /Response Rules/i },
  { label: "Policy Center",  heading: /^Policy Center$/i },
  { label: "Policies",       heading: /^Policies$/i },
  { label: "Audit Log",      heading: /Audit/i },
];

const ORG_ROUTES: { label: string; heading: RegExp }[] = [
  { label: "Clusters",       heading: /^Clusters$/i },
  { label: "CVE Database",   heading: /CVE/i },
  { label: "Posture",        heading: /^Posture$/i },
  { label: "Federation",     heading: /Federation/i },
  { label: "Settings",       heading: /^Settings$/i },
];

async function clickNav(page: Page, linkLabel: string) {
  const nav = page.locator('aside[aria-label="Primary"] nav').first();
  await nav.waitFor({ state: "visible" });
  await nav.getByRole("link", { name: linkLabel, exact: true }).first().click();
}

test.describe("Cluster sidebar navigation — routes", () => {
  for (const { label, heading } of CLUSTER_ROUTES) {
    test(`opens ${label}`, async ({ page }) => {
      await page.goto("/dashboard");
      await page.waitForURL(/\/clusters\/[^/]+\/dashboard/);
      await clickNav(page, label);
      await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible({ timeout: 5000 });
    });
  }
});

test("NeuVector Switchboard exposes primary mapped links", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForURL(/\/clusters\/[^/]+\/dashboard/);
  await clickNav(page, "NeuVector Switchboard");
  await expect(page.getByTestId("neuvector-switchboard")).toBeVisible();

  for (const area of [
    "workloads-services",
    "hosts",
    "components",
    "network-activity",
    "policy",
    "security-risks",
    "events-notifications",
    "settings",
  ]) {
    await expect(page.getByTestId(`neuvector-map-${area}`)).toBeVisible();
  }

  await expect(page.getByTestId("neuvector-map-link-workloads-services-workloads")).toHaveAttribute("href", /\/deployments$/);
  await expect(page.getByTestId("neuvector-map-link-components-scanner-sources")).toHaveAttribute("href", "/settings/scanner");
  await expect(page.getByTestId("neuvector-map-link-network-activity-sessions")).toHaveAttribute("href", /\/network\?tab=sessions$/);
  await expect(page.getByTestId("neuvector-map-link-network-activity-pcap")).toHaveAttribute("href", /\/network\?tab=pcap$/);
  await expect(page.getByTestId("neuvector-map-link-policy-admission")).toHaveAttribute("href", /\/admission$/);
  await expect(page.getByTestId("neuvector-map-link-settings-effective-config")).toHaveAttribute("href", "/settings/effective-config");
  await expect(page.getByTestId("neuvector-map-link-settings-api-reference")).toHaveAttribute("href", "/openapi.json");
  await expect(page.getByTestId("neuvector-map-link-events-notifications-integrations")).toHaveAttribute("href", "/settings/integrations");
});

test("Dashboard exposes operator health and scanner freshness links", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForURL(/\/clusters\/[^/]+\/dashboard/);

  await expect(page.getByTestId("dashboard-operator-strip")).toBeVisible();
  await expect(page.getByTestId("dashboard-component-health")).toContainText(/Controllers/i);
  await expect(page.getByTestId("dashboard-component-link-controller").locator("a")).toHaveAttribute("href", /\/components\?role=controller$/);
  await expect(page.getByTestId("dashboard-component-link-enforcer").locator("a")).toHaveAttribute("href", /\/components\?role=enforcer$/);
  await expect(page.getByTestId("dashboard-component-link-scanner").locator("a")).toHaveAttribute("href", /\/components\?role=scanner$/);
  await expect(page.getByTestId("dashboard-component-link-admission").locator("a")).toHaveAttribute("href", /\/components\?role=admission$/);
  await expect(page.getByTestId("dashboard-component-link-discoverer").locator("a")).toHaveAttribute("href", /\/components\?role=discoverer$/);
  await expect(page.getByTestId("dashboard-scanner-freshness")).toContainText(/Scanner DB/i);
  await expect(page.getByTestId("dashboard-scanner-freshness")).toHaveAttribute("href", "/settings/scanner");
  await expect(page.getByTestId("dashboard-network-denies")).toBeVisible();
});

test("Network Activity exposes NeuVector-style workspace tabs", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForURL(/\/clusters\/[^/]+\/dashboard/);
  await clickNav(page, "Network Map");
  await expect(page.getByRole("heading", { name: /^Network Activity$/i })).toBeVisible();

  for (const tab of ["map", "conversations", "sessions", "pcap", "rules", "threats"]) {
    await expect(page.getByTestId(`network-workspace-tab-${tab}`)).toBeVisible();
  }

  await page.getByTestId("network-workspace-tab-sessions").click();
  await expect(page.getByTestId("network-workspace-panel-sessions")).toBeVisible();
  await page.getByTestId("network-workspace-tab-pcap").click();
  await expect(page.getByTestId("network-workspace-panel-pcap")).toBeVisible();
});

test("Scanner and registry pages expose operator queue visibility", async ({ page }) => {
  await page.goto("/settings/scanner");
  await expect(page.getByRole("heading", { name: /^Scanner & CVE Sources$/i })).toBeVisible();
  await expect(page.getByTestId("scanner-operator-summary")).toBeVisible();
  await expect(page.getByTestId("scanner-queue-metrics")).toBeVisible();
  await expect(page.getByTestId("scanner-recent-jobs")).toBeVisible();
  await expect(page.getByTestId("scanner-workers")).toBeVisible();

  await page.goto("/dashboard");
  await page.waitForURL(/\/clusters\/[^/]+\/dashboard/);
  await clickNav(page, "Registries");
  await expect(page.getByRole("heading", { name: /^Container Registries$/i })).toBeVisible();
  await expect(page.getByTestId("registry-operator-summary")).toBeVisible();
  await expect(page.getByTestId("registries-page")).toContainText("Scan jobs");
});

test("Components page exposes NeuVector role filters and version drift matrix", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForURL(/\/clusters\/[^/]+\/dashboard/);
  const clusterID = page.url().match(/\/clusters\/([^/]+)\//)?.[1];
  expect(clusterID).toBeTruthy();

  await page.goto(`/clusters/${clusterID}/components`);
  await expect(page.getByRole("heading", { name: /^Components$/i })).toBeVisible();
  await expect(page.getByTestId("component-nv-role-filters")).toContainText(/Controllers/i);
  await expect(page.getByTestId("component-version-matrix")).toBeVisible();
  await expect(page.getByTestId("component-version-matrix")).toContainText(/Version Drift/i);
});

test("NeuVector route aliases redirect to Constellation destinations", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForURL(/\/clusters\/[^/]+\/dashboard/);
  const clusterID = page.url().match(/\/clusters\/([^/]+)\//)?.[1];
  expect(clusterID).toBeTruthy();

  const clusterAliases: Array<{ from: string; to: RegExp }> = [
    { from: "agents", to: new RegExp(`/clusters/${clusterID}/components\\?role=enforcer$`) },
    { from: "network-activity", to: new RegExp(`/clusters/${clusterID}/network$`) },
    { from: "events", to: new RegExp(`/clusters/${clusterID}/timeline$`) },
    { from: "incidents", to: new RegExp(`/clusters/${clusterID}/timeline\\?tab=incident$`) },
    { from: "admission-control", to: new RegExp(`/clusters/${clusterID}/admission$`) },
    { from: "registry", to: new RegExp(`/clusters/${clusterID}/registries$`) },
    { from: "vulnerability-profiles", to: new RegExp(`/clusters/${clusterID}/vuln-profiles$`) },
    { from: "system-config", to: /\/settings\/effective-config$/ },
    { from: "vulndb", to: /\/settings\/scanner$/ },
  ];

  for (const alias of clusterAliases) {
    await page.goto(`/clusters/${clusterID}/${alias.from}`);
    await page.waitForURL(alias.to);
  }

  const orgAliases: Array<{ from: string; to: RegExp }> = [
    { from: "notifications", to: /\/settings\/integrations$/ },
    { from: "sysconfig", to: /\/settings\/effective-config$/ },
  ];

  for (const alias of orgAliases) {
    await page.goto(`/${alias.from}`);
    await page.waitForURL(alias.to);
  }
});

test("Admission Control exposes rules, criteria, and profile rollout panels", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForURL(/\/clusters\/[^/]+\/dashboard/);
  await clickNav(page, "Admission Control");
  await expect(page.getByRole("heading", { name: /^Admission Control$/i })).toBeVisible();

  await expect(page.getByTestId("admission-summary")).toBeVisible();
  await expect(page.getByTestId("admission-state-panel")).toBeVisible();
  await expect(page.getByTestId("admission-rule-table")).toBeVisible();
  await expect(page.getByTestId("admission-options-catalog")).toBeVisible();
  await expect(page.getByTestId("admission-profile-templates")).toBeVisible();
  await expect(page.getByTestId("admission-profile-templates")).toContainText(/Rules/i);

  await page.getByRole("button", { name: /^Preview$/i }).click();
  await expect(page.getByTestId("admission-profile-preview")).toBeVisible();
  await expect(page.getByTestId("admission-profile-preview")).toContainText(/monitor|enforce/i);
});

test.describe("Org sidebar navigation — routes", () => {
  for (const { label, heading } of ORG_ROUTES) {
    test(`opens ${label}`, async ({ page }) => {
      await page.goto("/clusters");
      await clickNav(page, label);
      await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible({ timeout: 5000 });
    });
  }
});

test("Settings hub links to System Health and Access Control", async ({ page }) => {
  await page.goto("/settings");
  await page.getByRole("link", { name: /System Health/i }).click();
  await expect(page.getByRole("heading", { name: /System Health/i })).toBeVisible();
  await page.goto("/settings");
  await page.getByRole("link", { name: /Access Control/i }).click();
  await expect(page.getByRole("heading", { name: /Access Control/i })).toBeVisible();
  await page.goto("/settings");
  await page.getByRole("link", { name: /Effective Config/i }).click();
  await expect(page.getByRole("heading", { name: /Effective Config/i })).toBeVisible();
  await page.goto("/settings");
  await expect(page.getByRole("link", { name: /API Reference/i })).toHaveAttribute("href", "/openapi.json");
});

test("Effective Config exposes source, diff, and applied revision panels", async ({ page }) => {
  await page.goto("/settings/effective-config");
  await expect(page.getByRole("heading", { name: /^Effective Config$/i })).toBeVisible();
  await expect(page.getByTestId("effective-config-source-summary")).toBeVisible();
  await expect(page.getByTestId("effective-config-default-diff")).toBeVisible();
  await expect(page.getByTestId("effective-config-applied-revisions")).toBeVisible();
});

test("Migration Imports exposes readiness, recommended actions, and report export", async ({ page }) => {
  await page.goto("/settings/migration");
  await expect(page.getByRole("heading", { name: /^Migration Imports$/i })).toBeVisible();
  await expect(page.getByTestId("migration-switch-readiness")).toBeVisible();
  await expect(page.getByTestId("migration-readiness-checklist")).toBeVisible();
  await expect(page.getByTestId("migration-recommended-actions")).toBeVisible();
  await expect(page.getByTestId("migration-report-panel")).toBeVisible();
  await expect(page.getByTestId("migration-report-export")).toBeVisible();
});

test("theme toggle switches dark <-> light", async ({ page }) => {
  await page.goto("/dashboard");
  const html = page.locator("html");
  const before = await html.getAttribute("class");
  // The header toggle has aria-label "Switch to light theme" or "Switch to dark theme".
  await page.getByRole("button", { name: /Switch to (light|dark) theme/i }).click();
  await expect(html).not.toHaveAttribute("class", before ?? "");
});

test("logout returns to /auth/login", async ({ page }) => {
  await page.goto("/dashboard");
  // The user menu trigger shows the user email; clicking it opens a dropdown
  // with a "Sign out" item.
  await page.getByTestId("user-menu-trigger").click();
  await page.getByRole("menuitem", { name: /Sign out/i }).click();
  await expect(page).toHaveURL(/\/auth\/login/);
});
