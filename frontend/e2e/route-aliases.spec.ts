import { expect, test } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    } else if (path === "/runtime-dlp-rules") {
      await route.fulfill({ json: { rules: [] } });
    } else if (path === "/runtime-signatures") {
      await route.fulfill({ json: { signatures: [] } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });
});

test("login alias keeps the return path", async ({ page }) => {
  await page.goto("/login?returnTo=%2Fclusters%2Fexample%2Fdashboard#signin");
  await expect(page).toHaveURL(/\/auth\/login\?returnTo=%2Fclusters%2Fexample%2Fdashboard#signin$/);
  await expect(page.getByRole("heading", { name: "Sign in to Constellation" })).toBeVisible();
});

test("DLP and WAF aliases land on canonical pages and forms", async ({ page }) => {
  for (const { alias, canonical, pageId, editorId } of [
    { alias: "dlp", canonical: "runtime-dlp", pageId: "runtime-dlp-page", editorId: "runtime-dlp-editor" },
    { alias: "waf", canonical: "runtime-signatures", pageId: "runtime-signatures-page", editorId: "runtime-signatures-editor" },
  ]) {
    await page.goto(`/clusters/${clusterId}/${alias}?view=all#rules`);
    await expect(page).toHaveURL(`/clusters/${clusterId}/${canonical}?view=all#rules`);
    await expect(page.getByTestId(pageId)).toBeVisible();

    await page.goto(`/clusters/${clusterId}/${alias}/new?source=bookmark#editor`);
    await expect(page).toHaveURL(`/clusters/${clusterId}/${canonical}/new?source=bookmark#editor`);
    await expect(page.getByTestId(editorId)).toBeVisible();
  }
});

test("legacy and settings aliases retain deep paths, filters, and fragments", async ({ page }) => {
  const routes = [
    [`/services/deployment-1?tab=pods#details`, `/clusters/${clusterId}/deployments/deployment-1?tab=pods#details`],
    [`/clusters/${clusterId}/hosts/node-1?tab=risks#details`, `/clusters/${clusterId}/nodes/node-1?tab=risks#details`],
    [`/clusters/${clusterId}/controllers?sort=name#inventory`, `/clusters/${clusterId}/components?sort=name&role=controller#inventory`],
    [`/clusters/${clusterId}/controllers?role=scanner#inventory`, `/clusters/${clusterId}/components?role=controller#inventory`],
    ["/coverage?tab=controls#summary", "/posture?tab=controls#summary"],
    [`/clusters/${clusterId}/incidents?range=24h#events`, `/clusters/${clusterId}/timeline?range=24h&tab=incident#events`],
    [`/clusters/${clusterId}/incidents?tab=activity#events`, `/clusters/${clusterId}/timeline?tab=incident#events`],
  ];
  for (const [alias, canonical] of routes) {
    await page.goto(alias);
    await expect(page).toHaveURL(canonical);
  }
});
