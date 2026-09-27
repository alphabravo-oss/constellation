import { expect, test, type Page } from "@playwright/test";

const CLUSTER_ID = "11111111-1111-4111-8111-111111111111";
const SCOPES = ["Organization", "Platform", "Integrations", "Cluster"];

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("constellation.sidebar.collapsed", "0"));
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: CLUSTER_ID, name: "Test cluster", state: "connected" }] } });
    } else {
      await route.fulfill({ status: 404, json: { error: "No fixture" } });
    }
  });
});

async function expectScopeOrder(page: Page) {
  const scopes = page.locator('aside[aria-label="Primary"] nav[aria-label="Scopes"] > [role="group"]');
  await expect(scopes).toHaveCount(4);
  expect(await scopes.evaluateAll((elements) => elements.map((element) => element.getAttribute("aria-label")))).toEqual(SCOPES);
}

test("scope navigation keeps the same order and canonical routes", async ({ page }) => {
  await page.goto("/clusters");
  await expectScopeOrder(page);

  const nav = page.locator('aside[aria-label="Primary"] nav[aria-label="Scopes"]');
  const organization = nav.getByRole("group", { name: "Organization", exact: true });
  await organization.getByRole("button", { name: "Organization" }).click();
  await expect(organization.getByRole("link", { name: "CVE Database" })).toHaveAttribute("href", "/cve");
  await expect(organization.getByRole("link", { name: "Access Control" })).toHaveAttribute("href", "/settings/access");
  await expect(organization.getByRole("link", { name: "API Tokens" })).toHaveAttribute("href", "/settings/api-tokens");

  const platform = nav.getByRole("group", { name: "Platform", exact: true });
  await platform.getByRole("button", { name: "Platform" }).click();
  await expect(platform.getByRole("link", { name: "Settings" })).toHaveAttribute("href", "/settings");

  const integrations = nav.getByRole("group", { name: "Integrations", exact: true });
  await integrations.getByRole("button", { name: "Integrations" }).click();
  await expect(integrations.getByRole("link", { name: "Integrations & Routing" })).toHaveAttribute("href", "/settings/integrations");
  await expect(integrations.getByRole("link", { name: "Connectors" })).toHaveAttribute("href", "/settings/connectors");
  await integrations.getByRole("link", { name: "Integrations & Routing" }).click();
  await expect(page).toHaveURL("/settings/integrations");
  await expectScopeOrder(page);

  await page.goto("/settings");
  const settingsScopes = page.locator('main section[aria-label]');
  await expect(settingsScopes).toHaveCount(4);
  expect(await settingsScopes.evaluateAll((elements) => elements.map((element) => element.getAttribute("aria-label")))).toEqual(SCOPES);
  await expect(page.getByRole("region", { name: "Cluster" }).getByRole("link", { name: /Connect a cluster/ })).toHaveAttribute("href", "/settings/clusters/new");

  await page.goto("/settings/api-tokens");
  await expect(organization.getByRole("button", { name: "Organization" })).toHaveAttribute("aria-expanded", "true");
  await expect(organization.getByRole("link", { name: "API Tokens" })).toHaveAttribute("aria-current", "page");

  await page.goto(`/clusters/${CLUSTER_ID}/dashboard`);
  await expectScopeOrder(page);
  const cluster = nav.getByRole("group", { name: "Cluster", exact: true });
  await expect(cluster.getByRole("button", { name: "Cluster", exact: true })).toHaveAttribute("aria-expanded", "true");
  await expect(cluster.getByRole("link", { name: "Clusters" })).toHaveAttribute("href", "/clusters");
  await expect(cluster.getByRole("button", { name: "Switch cluster" })).toBeVisible();
  await expect(cluster.getByRole("link", { name: "Dashboard" })).toHaveAttribute("href", `/clusters/${CLUSTER_ID}/dashboard`);
  await expect(cluster.getByRole("link", { name: "Dashboard" })).toHaveAttribute("aria-current", "page");
  await cluster.getByRole("link", { name: "Clusters" }).click();
  await expect(page).toHaveURL("/clusters");
});

test("scope accordions and collapsed links work by keyboard", async ({ page }) => {
  await page.goto(`/clusters/${CLUSTER_ID}/dashboard`);
  const nav = page.locator('aside[aria-label="Primary"] nav[aria-label="Scopes"]');
  const organization = nav.getByRole("group", { name: "Organization", exact: true });
  const organizationButton = organization.getByRole("button", { name: "Organization" });
  await organizationButton.focus();
  await page.keyboard.press("Enter");
  await expect(organizationButton).toHaveAttribute("aria-expanded", "true");
  await organization.getByRole("link", { name: "Posture" }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL("/posture");
  await expect(organization.getByRole("link", { name: "Posture" })).toHaveAttribute("aria-current", "page");

  await page.getByRole("button", { name: "Collapse sidebar" }).click();
  await expectScopeOrder(page);
  await expect(nav.getByRole("link", { name: "Posture" })).toBeVisible();
  await nav.getByRole("link", { name: "Clusters" }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL("/clusters");
});

test("command palette lists navigation scopes in sidebar order", async ({ page }) => {
  await page.goto(`/clusters/${CLUSTER_ID}/dashboard`);
  await expectScopeOrder(page);
  await page.keyboard.press("ControlOrMeta+k");
  const palette = page.getByRole("dialog", { name: "Command palette" });
  await expect(palette).toBeVisible();
  const headings = palette.locator("[cmdk-group-heading]");
  await expect(headings).toContainText(SCOPES);
});
