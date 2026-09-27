import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [] } });
    } else if (path === "/api-tokens") {
      await route.fulfill({ json: { tokens: [] } });
    } else if (path === "/system-health") {
      await route.fulfill({ json: { summary: { healthy: 0, degraded: 0, drift: 0, stale: 0, crashlooping: 0 }, heartbeats: [], version_drift: [], crashloop_history: [], incidents: [], remediation_actions: [] } });
    } else if (path === "/support/bundle/jobs") {
      await route.fulfill({ json: { items: [] } });
    } else if (path === "/repository-scan-attestation-trust-policies") {
      await route.fulfill({ json: { policies: [] } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });
});

test("org health navigation opens its canonical settings page", async ({ page }) => {
  await page.goto("/clusters");
  const healthLink = page.getByRole("link", { name: "System Health" });
  await expect(healthLink).toHaveAttribute("href", "/settings/health");
  await healthLink.click();
  await expect(page).toHaveURL("/settings/health");
  await expect(page.getByTestId("system-health-page")).toBeVisible();

  await page.goto("/system-health?tab=components&source=bookmark#heartbeats");
  await expect(page).toHaveURL("/settings/health?tab=components&source=bookmark#heartbeats");
  await expect(page.getByTestId("system-health-page")).toBeVisible();
});

test("generic health opens platform health; cluster sensor health stays distinct", async ({ page }) => {
  const clusterId = "11111111-1111-4111-8111-111111111111";
  await page.route("**/api/v1/clusters", async (route) => {
    await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
  });

  await page.goto("/health?source=bookmark#sensors");
  await expect(page).toHaveURL("/settings/health?source=bookmark#sensors");
  await expect(page.getByTestId("system-health-page")).toBeVisible();

  await page.goto(`/clusters/${clusterId}/health?source=bookmark#sensors`);
  await expect(page).toHaveURL(`/clusters/${clusterId}/health?source=bookmark#sensors`);
  await expect(page.getByTestId("cluster-health-panel")).toBeVisible();

  await page.goto(`/clusters/${clusterId}/system-health?tab=components#heartbeats`);
  await expect(page).toHaveURL("/settings/health?tab=components#heartbeats");
  await expect(page.getByTestId("system-health-page")).toBeVisible();
});

test("settings hub links to the canonical token and attestation pages", async ({ page }) => {
  await page.goto("/settings");
  for (const { label, path, pageId } of [
    { label: "API Tokens", path: "/settings/api-tokens", pageId: "api-tokens-page" },
    { label: "Attestation Trust", path: "/settings/attestation-trust", pageId: "attestation-trust-page" },
  ]) {
    const link = page.getByRole("link", { name: new RegExp(`^${label}`) });
    await expect(link).toHaveAttribute("href", path);
    await link.click();
    await expect(page).toHaveURL(path);
    await expect(page.getByTestId(pageId)).toBeVisible();
    await page.goto("/settings");
  }
});

test("flat settings aliases retain paths, queries, and fragments", async ({ page }) => {
  for (const [alias, canonical] of [
    ["/tokens?sort=name#list", "/settings/api-tokens?sort=name#list"],
    ["/tokens/new?source=bookmark#name", "/settings/api-tokens/new?source=bookmark#name"],
    ["/attestation-trust?enabled=true#policies", "/settings/attestation-trust?enabled=true#policies"],
    ["/attestation-trust/new?source=bookmark#policy", "/settings/attestation-trust/new?source=bookmark#policy"],
    ["/attestation-trust/policy-1?tab=trust#identity", "/settings/attestation-trust/policy-1?tab=trust#identity"],
    ["/access-control/users/new?source=bookmark#user", "/settings/access/users/new?source=bookmark#user"],
    ["/integrations/receivers/new?source=bookmark#receiver", "/settings/integrations/receivers/new?source=bookmark#receiver"],
    ["/attestation/new?source=bookmark#policy", "/settings/attestation-trust/new?source=bookmark#policy"],
    ["/settings/tokens/new?source=bookmark#name", "/settings/api-tokens/new?source=bookmark#name"],
    ["/settings/attestation/new?source=bookmark#policy", "/settings/attestation-trust/new?source=bookmark#policy"],
    ["/settings/access-control/users/new?source=bookmark#user", "/settings/access/users/new?source=bookmark#user"],
    ["/settings/notifications/receivers/new?source=bookmark#receiver", "/settings/integrations/receivers/new?source=bookmark#receiver"],
    ["/settings/system-health?tab=components#heartbeats", "/settings/health?tab=components#heartbeats"],
  ]) {
    await page.goto(alias);
    await expect(page).toHaveURL(canonical);
  }

  await page.goto("/tokens/new");
  await expect(page.getByRole("heading", { name: "Create API token" })).toBeVisible();
  await page.goto("/attestation-trust/new");
  await expect(page.getByTestId("attestation-trust-editor")).toBeVisible();
});

test("cluster-scoped settings bookmarks resolve to the same settings home", async ({ page }) => {
  const clusterId = "11111111-1111-4111-8111-111111111111";
  await page.route("**/api/v1/clusters", async (route) => {
    await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
  });

  for (const [alias, canonical] of [
    [`/clusters/${clusterId}/settings`, "/settings"],
    [`/clusters/${clusterId}/tokens/new?source=bookmark#name`, "/settings/api-tokens/new?source=bookmark#name"],
    [`/clusters/${clusterId}/attestation-trust/new?source=bookmark#policy`, "/settings/attestation-trust/new?source=bookmark#policy"],
  ]) {
    await page.goto(alias);
    await expect(page).toHaveURL(canonical);
  }
});
