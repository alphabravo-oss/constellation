import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";

const clusterId = "11111111-1111-4111-8111-111111111111";
const at = "2026-09-26T12:00:00Z";

async function mockInventory(page: Page, endpoint: string, payload: unknown | ((url: URL) => unknown)) {
  const requests: URL[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    } else if (path === endpoint) {
      requests.push(url);
      await route.fulfill({ json: typeof payload === "function" ? payload(url) : payload });
    } else {
      await route.fulfill({ status: 404, json: { error: `Unexpected request: ${path}` } });
    }
  });
  return requests;
}

test("assets render 100 rows per page from a 250-row scoped response", async ({ page }) => {
  const inventory = Array.from({ length: 250 }, (_, index) => ({
    id: `asset-${index + 1}`,
    kind: "image",
    name: `asset-${String(index + 1).padStart(3, "0")}`,
    labels: {},
    ai_workload: false,
    criticality: "low",
    finding_count: 0,
    critical_findings: 0,
    high_findings: 0,
    open_findings: 0,
    sbom_count: 0,
    image_signed: true,
    first_seen_at: at,
    last_seen_at: at,
  }));
  const requests = await mockInventory(page, "/assets", { assets: inventory, limit: 250, offset: 0, has_more: false });
  await page.goto(`/clusters/${clusterId}/assets`);

  const table = page.getByTestId("assets-table");
  await expect(table.getByTestId("asset-row")).toHaveCount(100);
  await expect(page.getByTestId("assets-table-page-scope")).toContainText("1–100 of 250 matching loaded rows");
  await expect(page.getByTestId("assets-table-page-scope")).toContainText("Server fetch limit: 250 rows (250 loaded)");
  await table.getByRole("button", { name: "Next" }).click();
  await expect(table.getByTestId("asset-row")).toHaveCount(100);
  await expect(page.getByTestId("assets-table-page-scope")).toContainText("101–200 of 250 matching loaded rows");
  await table.getByRole("button", { name: "Next" }).click();
  await expect(table.getByTestId("asset-row")).toHaveCount(50);
  await expect(table).toContainText("asset-250");
  await expect(table.getByRole("button", { name: "Next" })).toBeDisabled();
  expect(requests).toHaveLength(1);
  expect(requests[0].searchParams.get("limit")).toBe("250");
  expect(requests[0].searchParams.get("cluster_id")).toBe(clusterId);
});

test("assets continue beyond the first server page and label incomplete CSV", async ({ page }) => {
  const inventory = Array.from({ length: 251 }, (_, index) => ({
    id: `asset-${index + 1}`,
    kind: "image",
    name: `asset-${String(index + 1).padStart(3, "0")}`,
    labels: {},
    ai_workload: false,
    criticality: "low",
    finding_count: 0,
    critical_findings: 0,
    high_findings: 0,
    open_findings: 0,
    sbom_count: 0,
    image_signed: true,
    first_seen_at: at,
    last_seen_at: at,
  }));
  const requests = await mockInventory(page, "/assets", (url: URL) => {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    return { assets: inventory.slice(offset, offset + 250), limit: 250, offset, has_more: offset + 250 < inventory.length };
  });
  await page.goto(`/clusters/${clusterId}/assets`);
  await expect(page.getByTestId("assets-incomplete-notice")).toContainText("250 loaded assets");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export loaded rows CSV" }).click();
  expect((await downloadPromise).suggestedFilename()).toBe("constellation-assets-loaded-only.csv");
  await page.getByRole("button", { name: "Load more assets" }).click();
  await expect(page.getByTestId("assets-incomplete-notice")).toHaveCount(0);
  await expect(page.getByTestId("assets-summary")).toContainText("251");
  expect(requests.map((url) => url.searchParams.get("offset"))).toEqual(["0", "250"]);
});

test("deployments page and search beyond the old cap with platform filtering before LIMIT", async ({ page }) => {
  const inventory = Array.from({ length: 805 }, (_, index) => ({
    id: `deployment-${index + 1}`,
    namespace: index < 200 ? "custom-install" : "apps",
    name: index < 200 ? `platform-${index + 1}` : `workload-${String(index - 199).padStart(3, "0")}`,
    kind: "Deployment",
    platform_role: index < 200 ? "core" : undefined,
    labels: {}, risk_score: index < 200 ? 99 : 0, risk_factors: {}, finding_count: 0,
    critical_count: 0, high_count: 0, first_seen_at: at, last_seen_at: at,
  }));
  const requests = await mockInventory(page, "/deployments", (url: URL) => {
    const query = (url.searchParams.get("q") ?? "").toLowerCase();
    const base = inventory.filter((row) => !query || row.name.toLowerCase().includes(query));
    const matching = base.filter((row) => url.searchParams.get("hide_platform") !== "true" || !row.platform_role);
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 100);
    return { deployments: matching.slice(offset, offset + limit), total: matching.length, limit, offset, has_more: offset + limit < matching.length, platform_count: base.filter((row) => row.platform_role).length, summary: { total: matching.length, at_risk: matching.filter((row) => row.risk_score >= 60).length, finding_count: 0, critical_count: 0, high_count: 0 } };
  });
  await page.goto(`/clusters/${clusterId}/deployments`);
  const table = page.getByTestId("deployments-table");
  await expect(table.getByTestId("deployment-row")).toHaveCount(100);
  await expect(page.getByTestId("deployment-page-scope")).toContainText("1–100 of 605 matching deployments");
  await expect(page.getByTestId("platform-visibility-toggle")).toContainText("200");
  await expect(table).not.toContainText("platform-");
  await expect(page.getByTestId("deployments-table-page-scope")).toHaveCount(0);
  expect(requests[0].searchParams.get("limit")).toBe("100");
  expect(requests[0].searchParams.get("cluster_id")).toBe(clusterId);
  expect(requests[0].searchParams.get("hide_platform")).toBe("true");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByTestId("deployment-page-scope")).toContainText("101–200 of 605");
  expect(requests.at(-1)?.searchParams.get("offset")).toBe("100");
  await page.getByTestId("deployment-search").fill("workload-605");
  await expect(table.getByTestId("deployment-row")).toHaveCount(1);
  await expect(table).toContainText("workload-605");
  await expect(page.getByTestId("deployment-page-scope")).toContainText("1–1 of 1 matching deployments");
  expect(requests.at(-1)?.searchParams.get("q")).toBe("workload-605");
  expect(requests.at(-1)?.searchParams.get("offset")).toBe("0");
});

test("image scans page a full 500-row server response without hiding the cap", async ({ page }) => {
  const inventory = Array.from({ length: 500 }, (_, index) => ({
    id: `image-${index + 1}`,
    image_ref: `registry.example.test/app:${index + 1}`,
    image_ref_normalized: `registry.example.test/app:${index + 1}`,
    image_repository: "registry.example.test/app",
    image_tag: String(index + 1),
    image_digest: `sha256:${index + 1}`,
    scanner_profile: "default",
    source_type: "registry",
    severity_counts: {},
    max_risk_score: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    finding_count: 0,
    impacted_count: 0,
    package_count: 0,
    last_scanned_at: at,
  }));
  const requests = await mockInventory(page, "/image-scan-results", { image_scan_results: inventory, limit: 500, offset: 0 });
  await page.goto(`/clusters/${clusterId}/images`);

  const table = page.getByTestId("image-scans-table");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await expect(table).toContainText("Server fetch limit: 500 rows (500 loaded)");
  await table.getByRole("button", { name: "Next" }).click();
  await expect(table).toContainText("Showing 101–200 of 500 matching loaded rows");
  expect(requests).toHaveLength(1);
  expect(requests[0].searchParams.get("limit")).toBe("500");
  expect(requests[0].searchParams.get("cluster_id")).toBe(clusterId);
});

test("findings select the visible page while CSV preserves all matching loaded rows", async ({ page }) => {
  const inventory = Array.from({ length: 250 }, (_, index) => ({
    id: `finding-${index + 1}`,
    title: `finding-title-${String(index + 1).padStart(3, "0")}`,
    severity: "high",
    lifecycle: "open",
    kind: "vulnerability",
    asset_id: `asset-${index + 1}`,
    risk_score: 0,
    last_seen_at: at,
  }));
  const requests = await mockInventory(page, "/findings", {
    findings: inventory,
    limit: 500,
    offset: 0,
    lifecycle_counts: { open: 250, triaged: 0, in_progress: 0, accepted: 0, suppressed: 0 },
  });
  await page.goto(`/clusters/${clusterId}/findings?severity=high`);

  const table = page.getByTestId("findings-table");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await expect(page.getByTestId("findings-table-page-scope")).toContainText("Server fetch limit: 500 rows (250 loaded)");
  await table.getByRole("checkbox", { name: "Select all" }).check();
  await expect(table.locator("tbody input[type=checkbox]:checked")).toHaveCount(100);
  await table.getByRole("button", { name: "Next" }).click();
  await expect(table.locator("tbody input[type=checkbox]:checked")).toHaveCount(0);
  await expect(page.getByTestId("findings-table-page-scope")).toContainText("101–200 of 250 matching loaded rows");

  const downloadPromise = page.waitForEvent("download");
  await table.getByRole("button", { name: "Export CSV" }).click();
  const download = await downloadPromise;
  const csv = await readFile(await download.path(), "utf8");
  expect(csv.trim().split("\n")).toHaveLength(251);
  expect(csv).toContain("finding-title-101");
  expect(csv).toContain("finding-title-001");
  expect(csv).toContain("finding-title-201");
  const listRequests = requests.filter((url) => url.searchParams.get("limit") === "500");
  expect(listRequests).toHaveLength(1);
  expect(listRequests[0].searchParams.get("cluster_id")).toBe(clusterId);
  expect(listRequests[0].searchParams.get("q")).toBe("severity:high");
});

test("serverless and repository inventories disclose their capped 500-row batches", async ({ page }) => {
  const serverless = Array.from({ length: 500 }, (_, index) => ({
    id: `function-${index + 1}`,
    function_ref: `arn:aws:lambda:test:function:${index + 1}`,
    function_name: `function-${index + 1}`,
    provider: "aws",
    region: "test",
    source_type: "inventory",
    package_count: 0,
    open_findings: 0,
    critical_findings: 0,
    high_findings: 0,
    last_seen_at: at,
  }));
  const functionsRequests = await mockInventory(page, "/serverless-functions", { serverless_functions: serverless, limit: 500, offset: 0 });
  await page.goto(`/clusters/${clusterId}/serverless`);
  const functionsTable = page.getByTestId("serverless-table");
  await expect(functionsTable.locator("tbody tr")).toHaveCount(100);
  await expect(functionsTable).toContainText("Server fetch limit: 500 rows (500 loaded)");
  expect(functionsRequests[0].searchParams.get("limit")).toBe("500");

  const repositories = Array.from({ length: 500 }, (_, index) => ({
    id: `repository-${index + 1}`,
    repository_ref: `repo-${index + 1}`,
    source_type: "git",
    package_count: 0,
    open_findings: 0,
    critical_findings: 0,
    high_findings: 0,
    last_seen_at: at,
  }));
  const repositoryRequests = await mockInventory(page, "/repository-scans", { repository_scans: repositories, limit: 500, offset: 0 });
  await page.goto(`/clusters/${clusterId}/repositories`);
  const repositoryTable = page.getByTestId("repository-table");
  await expect(repositoryTable.locator("tbody tr")).toHaveCount(100);
  await expect(repositoryTable).toContainText("Server fetch limit: 500 rows (500 loaded)");
  expect(repositoryRequests[0].searchParams.get("limit")).toBe("500");
});

test("finding asset groups page rather than rendering hundreds of tables", async ({ page }) => {
  const inventory = Array.from({ length: 150 }, (_, index) => ({
    id: `finding-${index + 1}`,
    title: `finding-title-${index + 1}`,
    severity: "high",
    lifecycle: "open",
    kind: "vulnerability",
    asset_id: `asset-${index + 1}`,
    risk_score: 0,
    last_seen_at: at,
  }));
  await mockInventory(page, "/findings", { findings: inventory, limit: 500, offset: 0, lifecycle_counts: { open: 150 } });
  await page.goto(`/clusters/${clusterId}/findings?severity=high`);
  await page.getByRole("button", { name: "Asset", exact: true }).first().click();

  await expect(page.getByTestId("findings-group-scope")).toContainText("groups 1–100 of 150");
  await expect(page.locator("main details")).toHaveCount(100);
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByTestId("findings-group-scope")).toContainText("groups 101–150 of 150");
  await expect(page.locator("main details")).toHaveCount(50);
});
