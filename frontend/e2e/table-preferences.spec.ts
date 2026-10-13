import { expect, test, type Locator, type Page } from "@playwright/test";
import { login } from "./utils";
import { inventoryAt, inventoryCluster, inventoryMetadata, mockInventoryEndpoints } from "./fixtures/inventory-contracts";
import { dashboardEvidence, evidenceRoot } from "./fixtures/dashboard-evidence";

async function layoutAction(page: Page, table: Locator, column: string, action: string) {
  const trigger = table.getByRole("button", { name: "Column layout", exact: true });
  await trigger.focus();
  await page.keyboard.press("Enter");
  const submenu = page.getByRole("menuitem", { name: new RegExp(`^${column}( · pinned (left|right))?$`) });
  await submenu.focus();
  await page.keyboard.press("ArrowRight");
  const item = page.getByRole("menuitem", { name: action, exact: true });
  await item.focus();
  await page.keyboard.press("Enter");
  await expect(trigger).toBeFocused();
}

test("table preferences isolate reported user and tenant identities, migrate stale columns, and preserve active URL filters", async ({ page }) => {
  let identity = { org_id: "org-a", user_id: "user-a" };
  await mockInventoryEndpoints(page, {
    "/assets": (url, route) => route.fulfill({ json: {
      ...inventoryMetadata(url, 1, { images: 1, workloads: 0, critical_high: 0, open_findings: 0, signed_images: 1, unsigned_images: 0, signature_unknown: 0, with_sbom: 0, missing_sbom: 1, ai: 0 }, "risk"),
      assets: [{ id: "asset-a", cluster_id: inventoryCluster, kind: "image", name: "registry.example.test/app:1", labels: {}, platform_role: "", ai_workload: false, criticality: "high", finding_count: 0, critical_findings: 0, high_findings: 0, open_findings: 0, sbom_count: 0, image_signed: true, first_seen_at: inventoryAt, last_seen_at: inventoryAt }],
    } }),
  });
  // This verifies browser preference namespacing, not server authorization.
  await page.route("**/api/v1/auth/me", route => route.fulfill({ json: { ...identity, email: "operator@example.test", roles: ["GlobalAdmin"] } }));
  await page.goto(`/clusters/${inventoryCluster}/assets?criticality=high&sort=asset&order=asc`);
  const table = page.getByTestId("assets-table");
  await expect(table.locator("tbody tr").first()).toBeVisible();
  const route = page.url();
  const key = `constellation.table.${JSON.stringify(["org-a", "user-a", "assets"])}.v1`;
  await page.evaluate(key => localStorage.setItem(key, JSON.stringify({ density: "compact", hiddenColumnIds: ["removed-column", "criticality"], columnOrder: ["removed-column", "risk", "risk"], columnWidths: { risk: 999999, "removed-column": 99 }, columnPinning: { start: ["removed-column"], end: ["risk", "risk"] } })), key);
  await page.reload();
  const assertRestored = async () => {
    await expect(table.getByRole("button", { name: "compact density" })).toHaveAttribute("aria-pressed", "true");
    await expect(table.getByRole("separator", { name: "Resize Risk", exact: true })).toHaveAttribute("aria-valuenow", "280");
    await expect(table.locator('th[data-column-id="criticality"]')).toHaveCount(0);
    await expect(table.locator("thead th[data-column-id]").last()).toHaveAttribute("data-column-id", "risk");
    await expect(page.getByTestId("asset-criticality-filter")).toHaveValue("high");
    await expect(page).toHaveURL(route);
  };
  await assertRestored();
  const saved = await page.evaluate(key => JSON.parse(localStorage.getItem(key)!), key);
  expect(saved.hiddenColumnIds).not.toContain("removed-column");
  expect(saved.columnOrder).toEqual(["risk"]);
  expect(saved.columnWidths).toEqual({ risk: 280 });
  expect(saved.columnPinning).toEqual({ start: [], end: ["risk"] });
  for (const other of [{ org_id: "org-a", user_id: "user-b" }, { org_id: "org-b", user_id: "user-a" }]) {
    identity = other;
    await page.reload();
    await expect(table.getByRole("button", { name: "cozy density" })).toHaveAttribute("aria-pressed", "true");
    await expect(table.locator('th[data-column-id="criticality"]')).toBeVisible();
    await expect(table.locator('th[data-column-id="risk"]')).not.toHaveCSS("position", "sticky");
    await expect(page.getByTestId("asset-criticality-filter")).toHaveValue("high");
  }
  identity = { org_id: "org-a", user_id: "user-a" };
  await page.reload();
  await assertRestored();
  await table.getByRole("button", { name: "Columns", exact: true }).click();
  await page.getByRole("menuitem", { name: "Reset table preferences", exact: true }).press("Enter");
  await expect(table.getByRole("button", { name: "cozy density" })).toHaveAttribute("aria-pressed", "true");
  await expect(table.locator('th[data-column-id="criticality"]')).toBeVisible();
  await expect(page.getByTestId("asset-criticality-filter")).toHaveValue("high");
  await expect(page).toHaveURL(route);
});

async function expectAligned(table: Locator) {
  const errors = await table.locator("table").evaluate(element => {
    const headers = [...element.querySelectorAll<HTMLElement>("thead th[data-column-id]")];
    const row = element.querySelector("tbody tr");
    if (!row) return ["No evidence row"];
    return headers.flatMap(header => {
      const cell = row.querySelector<HTMLElement>(`td[data-column-id="${header.dataset.columnId}"]`);
      if (!cell) return [`Missing ${header.dataset.columnId}`];
      const head = header.getBoundingClientRect(), body = cell.getBoundingClientRect();
      return Math.abs(head.x - body.x) > 1 || Math.abs(head.width - body.width) > 1
        || window.getComputedStyle(header).textAlign !== window.getComputedStyle(cell).textAlign
        ? [`Misaligned ${header.dataset.columnId}`] : [];
    });
  });
  expect(errors).toEqual([]);
}

for (const entry of [
  { route: "assets", testId: "assets-table", column: "Risk", columnId: "risk", hidden: "Criticality", hiddenId: "criticality" },
  { route: "nodes", testId: "nodes-table", column: "Operating system", columnId: "os", hidden: "Packages", hiddenId: "packages" },
  { route: "components", testId: "component-inventory-table", column: "Build", columnId: "build", hidden: "Runtime", hiddenId: "runtime" },
  { route: "deployments", testId: "deployments-table", column: "Risk", columnId: "risk", hidden: "Risk factors", hiddenId: "factors" },
  { route: "audit", testId: "audit-page", column: "Actor", columnId: "actor", hidden: "Target", hiddenId: "target" },
]) {
  test(`${entry.route} preserves keyboard table preferences and resets them without changing filters`, async ({ page }) => {
    if (entry.route === "deployments") {
      await dashboardEvidence().install(page);
      await page.goto(`${evidenceRoot}/deployments?risk_fact=privileged&context=keep`);
    } else if (entry.route === "audit") {
      await mockInventoryEndpoints(page, {
        "/audit/events": (_url, response) => response.fulfill({ json: { events: [{ id: 1, event_id: "1", action: "auth.login.local", actor_id: "operator", target_kind: "cluster", target_id: inventoryCluster, prev_hash: "previous", chain_hash: "hidden-chain", at: inventoryAt }], has_more: false } }),
      });
      await page.goto(`/clusters/${inventoryCluster}/audit?action=auth.login.local&context=keep`);
    } else if (entry.route === "nodes") {
      // The seeded cluster may have no host observations. Use an explicit row
      // so alignment checks exercise cells, rather than the empty-state colspan.
      await mockInventoryEndpoints(page, {
        [`/clusters/${inventoryCluster}/nodes`]: (url, response) => response.fulfill({ json: {
          cluster_id: inventoryCluster, limit: 100, offset: 0, total: 1, has_more: false,
          q: "", agent: "", risk: "", host_cves: "", sort: url.searchParams.get("sort"), order: url.searchParams.get("order"),
          summary: { nodes: 1, runtime_agent_healthy: 0, runtime_agent_stale: 0, runtime_agent_missing: 1, scan_completed: 0, scan_gaps: 1, critical_vulns: 0, high_vulns: 0, cis_failed: 0 },
          items: [{ node: "host-with-evidence", cluster_id: inventoryCluster, runtime_agent_status: "missing", scan_status: "missing", open_vulns: 0, critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0, package_count: 12, container_count: 2, process_count: 3, cis_failed: 0, last_seen_at: inventoryAt }],
        } }),
      });
      await page.goto(`/clusters/${inventoryCluster}/nodes`);
    } else {
      await login(page);
      await page.goto(`/${entry.route}`);
    }
    const table = page.getByTestId(entry.testId);
    await expect(table.locator("tbody td[data-column-id]").first()).toBeVisible();
    const route = page.url();
    const initialOrder = await table.locator("thead th[data-column-id]").evaluateAll(headers => headers.map(header => header.getAttribute("data-column-id")));
    const resize = table.getByRole("separator", { name: `Resize ${entry.column}`, exact: true });
    const width = Number(await resize.getAttribute("aria-valuenow"));
    const maximum = Number(await resize.getAttribute("aria-valuemax"));
    await resize.focus();
    await page.keyboard.press("ArrowRight");
    const expectedWidth = String(Math.min(width + 16, maximum));
    await expect(resize).toHaveAttribute("aria-valuenow", expectedWidth);
    await expect(page).toHaveURL(route);
    await layoutAction(page, table, entry.column, "Move right");
    const movedOrder = await table.locator("thead th[data-column-id]").evaluateAll(headers => headers.map(header => header.getAttribute("data-column-id")));
    expect(movedOrder).not.toEqual(initialOrder);
    await layoutAction(page, table, entry.column, "Pin right");
    await expect(table.locator(`th[data-column-id="${entry.columnId}"]`)).toHaveCSS("position", "sticky");
    await table.getByRole("button", { name: "comfy density" }).click();
    await table.getByRole("button", { name: "Columns", exact: true }).click();
    await page.getByRole("menuitemcheckbox", { name: entry.hidden, exact: true }).press("Space");
    await page.keyboard.press("Escape");
    await expect(table.locator(`th[data-column-id="${entry.hiddenId}"]`)).toHaveCount(0);
    await page.reload();
    await expect(table.getByRole("button", { name: "comfy density" })).toHaveAttribute("aria-pressed", "true");
    await expect(resize).toHaveAttribute("aria-valuenow", expectedWidth);
    await expect(table.locator("thead th[data-column-id]").last()).toHaveAttribute("data-column-id", entry.columnId);
    await expect(table.locator(`th[data-column-id="${entry.hiddenId}"]`)).toHaveCount(0);
    await expectAligned(table);
    await page.setViewportSize({ width: 640, height: 800 });
    const scroll = table.getByRole("region");
    await scroll.focus();
    await page.keyboard.press("End");
    expect(await scroll.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await expectAligned(table);
    await page.setViewportSize({ width: 1280, height: 720 });
    await table.getByRole("button", { name: "Columns", exact: true }).click();
    await page.getByRole("menuitem", { name: "Reset table preferences", exact: true }).press("Enter");
    await expect(table.locator(`th[data-column-id="${entry.hiddenId}"]`)).toBeVisible();
    await expect(table.getByRole("button", { name: "comfy density" })).toHaveAttribute("aria-pressed", "false");
    await expect.poll(() => table.locator("thead th[data-column-id]").evaluateAll(headers => headers.map(header => header.getAttribute("data-column-id")))).toEqual(initialOrder);
    await expect(page).toHaveURL(route);
    await expectAligned(table);
  });
}
