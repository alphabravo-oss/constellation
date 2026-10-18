import { expect, test, type Page, type Locator } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { inventoryAt as at, inventoryCluster as clusterId, inventoryMetadata, mockInventoryEndpoints, fulfillInventoryCSV } from "./fixtures/inventory-contracts";
async function mockInventory(page: Page, endpoint: string, payload: unknown | ((url: URL) => unknown)) {
    return mockInventoryEndpoints(page, { [endpoint]: (url, route) => route.fulfill({ json: typeof payload === "function" ? payload(url) : payload }) });
}
const asset = (index: number) => ({ id: `asset-${index + 1}`, cluster_id: clusterId, kind: "image", name: `asset-${String(index + 1).padStart(3, "0")}`, labels: {}, platform_role: "", ai_workload: false, criticality: "low", finding_count: 0, critical_findings: 0, high_findings: 0, open_findings: 0, sbom_count: 0, image_signed: true, first_seen_at: at, last_seen_at: at });
const assetSummary = (total: number) => ({ total, images: total, workloads: 0, critical_high: 0, open_findings: 0, signed_images: total, unsigned_images: 0, signature_unknown: 0, with_sbom: 0, missing_sbom: total, ai: 0 });
const finding = (index: number) => ({ id: `finding-${index + 1}`, row_id: `finding-${index + 1}:${(Date.parse(at) / 1000).toFixed(6)}`, revision: "1", source_cluster_id: clusterId, target_cluster_id: null, cluster_id: clusterId, title: `finding-title-${String(index + 1).padStart(3, "0")}`, severity: "high", lifecycle: "open", kind: "vulnerability", asset_id: `asset-${index + 1}`, risk_score: 0, first_seen_at: at, last_seen_at: at, platform_role: "" });
const counts = (total: number) => ({ open: total, triaged: 0, in_progress: 0, accepted: 0, suppressed: 0, resolved: 0 });
test("assets render 100 rows on each server page with full matching summaries", async ({ page }) => {
    const inventory = Array.from({ length: 250 }, (_, i) => asset(i));
    const requests = await mockInventory(page, "/assets", (url: URL) => { const meta = inventoryMetadata(url, inventory.length, assetSummary(inventory.length), "risk"); return { assets: inventory.slice(meta.offset, meta.offset + meta.limit), ...meta }; });
    await page.goto(`/clusters/${clusterId}/assets`);
    const table = page.getByTestId("assets-table");
    await expect(table.getByTestId("asset-row")).toHaveCount(100);
    await expect(page.getByTestId("assets-page-scope")).toContainText("Showing 1–100");
    await expect(page.getByTestId("assets-page-scope")).toContainText("250 matching assets");
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await expect(table.getByTestId("asset-row")).toHaveCount(100);
    await expect(page.getByTestId("assets-page-scope")).toContainText("101–200");
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await expect(table.getByTestId("asset-row")).toHaveCount(50);
    await expect(table).toContainText("asset-250");
    await expect(page.getByRole("button", { name: "Next", exact: true })).toBeDisabled();
    expect(requests.map(url => url.searchParams.get("offset"))).toEqual(["0", "100", "200"]);
    expect(requests.every(url => url.searchParams.get("limit") === "100" && url.searchParams.get("cluster_id") === clusterId)).toBe(true);
});
test("assets full matching CSV discloses its 100,000-row cap independently of page CSV", async ({ page }) => {
    const total = 100005;
    const inventory = [
        ...Array.from({ length: total }, (_, i) => ({ ...asset(i), name: `kept-asset-${String(i + 1).padStart(6, "0")}`, criticality: "high" })),
        { ...asset(total), id: "excluded-search", name: "unrelated-image", criticality: "high" },
        { ...asset(total + 1), id: "excluded-kind", name: "kept-node", kind: "node", criticality: "high" },
        { ...asset(total + 2), id: "excluded-criticality", name: "kept-low", criticality: "low" },
        { ...asset(total + 3), id: "excluded-cluster", name: "kept-foreign", criticality: "high", cluster_id: "22222222-2222-4222-8222-222222222222" },
    ];
    const matching = (url: URL) => {
        const search = (url.searchParams.get("search") ?? "").toLowerCase();
        const rows = inventory.filter(row =>
            (!url.searchParams.has("cluster_id") || row.cluster_id === url.searchParams.get("cluster_id")) &&
            (!search || row.name.toLowerCase().includes(search)) &&
            (!url.searchParams.has("kind") || row.kind === url.searchParams.get("kind")) &&
            (!url.searchParams.has("criticality") || row.criticality === url.searchParams.get("criticality")));
        if (url.searchParams.get("sort") === "asset") rows.sort((left, right) => left.name.localeCompare(right.name));
        if (url.searchParams.get("order") === "desc") rows.reverse();
        return rows;
    };
    const requests = await mockInventoryEndpoints(page, {
        "/assets": (url, route) => {
            const rows = matching(url);
            const meta = inventoryMetadata(url, rows.length, assetSummary(rows.length), "risk");
            return route.fulfill({ json: { assets: rows.slice(meta.offset, meta.offset + meta.limit), ...meta } });
        },
        "/assets.csv": (url, route) => {
            const rows = matching(url);
            return fulfillInventoryCSV(route, "ID,Name\n" + rows.slice(0, 100000).map(row => `${row.id},${row.name}`).join("\n"), rows.length, "constellation-assets.csv");
        },
    });
    await page.goto(`/clusters/${clusterId}/assets?page=2&q=kept&kind=image&criticality=high&sort=asset&order=asc`);
    await expect(page.getByTestId("assets-page-scope")).toContainText("101–200 of 100005");
    const full = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export matching assets CSV", exact: true }).click();
    const downloaded = await full;
    const csv = await readFile(await downloaded.path(), "utf8");
    const exportedRows = csv.trim().split("\n");
    expect(exportedRows).toHaveLength(100001);
    expect(exportedRows[1]).toBe("asset-1,kept-asset-000001");
    expect(exportedRows.at(-1)).toBe("asset-100000,kept-asset-100000");
    expect(csv).not.toContain("excluded-");
    await expect(page.getByRole("status")).toContainText("Exported 100000 of 100005");
    await expect(page.getByRole("status")).toContainText("100,000-row limit was reached");
    const current = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export this page CSV", exact: true }).click();
    const pageCSV = await readFile(await (await current).path(), "utf8");
    expect(pageCSV.trim().split("\n")).toHaveLength(101);
    expect(pageCSV).toContain("kept-asset-000101");
    expect(pageCSV).not.toContain("kept-asset-000001");
    expect(pageCSV).not.toContain("excluded-");
    const exported = requests.find(url => url.pathname === "/api/v1/assets.csv")!;
    expect(Object.fromEntries(exported.searchParams)).toEqual({ cluster_id: clusterId, search: "kept", kind: "image", criticality: "high", sort: "asset", order: "asc" });
    expect(exported.searchParams.has("limit")).toBe(false);
    expect(exported.searchParams.has("offset")).toBe(false);
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
test("image scans use server continuation and full metadata beyond the former 500-row cap", async ({ page }) => {
    const inventory = Array.from({ length: 805 }, (_, i) => ({ id: `image-${i + 1}`, image_ref: `registry.example.test/app:${i + 1}`, image_ref_normalized: `registry.example.test/app:${i + 1}`, image_repository: "registry.example.test/app", image_tag: String(i + 1), image_digest: `sha256:${i + 1}`, scanner_profile: "default", source_type: "registry", engine_status: { syft: "succeeded", trivy: "succeeded", grype: "succeeded" }, severity_counts: {}, max_risk_score: 0, critical_count: 0, high_count: 0, medium_count: 0, finding_count: 0, impacted_count: 1, package_count: 0, last_scanned_at: at }));
    const requests = await mockInventory(page, "/image-scan-results", (url: URL) => { const meta = inventoryMetadata(url, 805, { packages: 0, findings: 0, critical_high: 0, exposed: 805, local: 0, stale: 0, incomplete: 0 }); return { image_scan_results: inventory.slice(meta.offset, meta.offset + meta.limit), ...meta }; });
    await page.goto(`/clusters/${clusterId}/images?page=9`);
    const table = page.getByTestId("image-scans-table");
    await expect(table.locator("tbody tr")).toHaveCount(5);
    await expect(table.locator('a[href$="/images/image-805"]')).toBeVisible();
    await expect(page.getByTestId("scan-inventory-continuation")).toContainText("805 records match the server filters");
    await page.getByRole("button", { name: "Prev", exact: true }).click();
    await expect(table.locator("tbody tr")).toHaveCount(100);
    expect(requests.at(-1)?.searchParams.get("offset")).toBe("700");
    expect(requests[0].searchParams.get("limit")).toBe("100");
    expect(requests[0].searchParams.get("cluster_id")).toBe(clusterId);
});
test("findings select only the server page while full filtered CSV spans every matching instance", async ({ page }) => {
    const inventory = Array.from({ length: 250 }, (_, i) => finding(i));
    const requests = await mockInventoryEndpoints(page, { "/findings": (url, route) => { const limit = Number(url.searchParams.get("limit") ?? 100), offset = Number(url.searchParams.get("offset") ?? 0); return route.fulfill({ json: { findings: inventory.slice(offset, offset + limit), total: 250, limit, offset, has_more: offset + limit < 250, lifecycle_counts: counts(250) } }); }, "/findings.csv": (_url, route) => route.fulfill({ contentType: "text/csv", body: "id,title\n" + inventory.map(f => `${f.id},${f.title}`).join("\n") }) });
    await page.goto(`/clusters/${clusterId}/findings?view=instances&severity=high`);
    const table = page.getByTestId("findings-table");
    await expect(table.locator("tbody tr")).toHaveCount(100);
    await table.getByRole("checkbox", { name: "Select all", exact: true }).check();
    await expect(table.locator("tbody input[type=checkbox]:checked")).toHaveCount(100);
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await expect(table.locator("tbody tr")).toHaveCount(100);
    await expect(table.locator("tbody input[type=checkbox]:checked")).toHaveCount(0);
    const current = page.waitForEvent("download");
    await table.getByRole("button", { name: "Export this page CSV", exact: true }).click();
    const currentCSV = await readFile(await (await current).path(), "utf8");
    expect(currentCSV.trim().split("\n")).toHaveLength(101);
    expect(currentCSV).toContain("finding-title-101");
    expect(currentCSV).not.toContain("finding-title-001");
    const full = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export filtered instances CSV", exact: true }).click();
    const csv = await readFile(await (await full).path(), "utf8");
    expect(csv.trim().split("\n")).toHaveLength(251);
    expect(csv).toContain("finding-title-001");
    expect(csv).toContain("finding-title-250");
    const lists = requests.filter(url => url.pathname === "/api/v1/findings" && url.searchParams.get("limit") === "100" && url.searchParams.get("q") === "severity:high");
    expect(lists.map(url => url.searchParams.get("offset"))).toEqual(["0", "100"]);
    expect(lists.every(url => url.searchParams.get("cluster_id") === clusterId)).toBe(true);
    const exported = requests.find(url => url.pathname === "/api/v1/findings.csv")!;
    expect(exported.searchParams.get("q")).toBe("severity:high");
    expect(exported.searchParams.get("offset")).toBe("0");
    expect(exported.searchParams.get("limit")).toBe("100000");
});
test("serverless and repository inventories expose full matching totals and tail pages beyond 500", async ({ page }) => {
    const functions = Array.from({ length: 805 }, (_, i) => ({ id: `function-${i + 1}`, function_ref: `arn:aws:lambda:test:function:${i + 1}`, function_name: `function-${i + 1}`, provider: "aws", region: "test", source_type: "inventory", package_count: 0, open_findings: 0, critical_findings: 0, high_findings: 0, last_seen_at: at }));
    const repos = Array.from({ length: 805 }, (_, i) => ({ id: `repository-${i + 1}`, repository_ref: `repo-${i + 1}`, source_type: "git", package_count: 0, open_findings: 0, critical_findings: 0, high_findings: 0, last_seen_at: at }));
    const requests = await mockInventoryEndpoints(page, { "/serverless-functions": (url, route) => { const meta = inventoryMetadata(url, 805, { packages: 0, findings: 0, critical_high: 0, scanned: 0, role_risks: 0, providers: 1, regions: 1 }); return route.fulfill({ json: { serverless_functions: functions.slice(meta.offset, meta.offset + meta.limit), ...meta } }); }, "/repository-scans": (url, route) => { const meta = inventoryMetadata(url, 805, { packages: 0, findings: 0, critical_high: 0, with_evidence: 0, active_jobs: 0, stale_evidence: 0, attestations: 0, trusted_attestations: 0, unverified_attestations: 0, branches: 0, workflows: 0 }); return route.fulfill({ json: { repository_scans: repos.slice(meta.offset, meta.offset + meta.limit), ...meta } }); } });
    await page.goto(`/clusters/${clusterId}/serverless?page=9`);
    const functionsTable = page.getByTestId("serverless-table");
    await expect(functionsTable.locator("tbody tr")).toHaveCount(5);
    await expect(functionsTable).toContainText("function-805");
    await expect(page.getByTestId("scan-inventory-continuation")).toContainText("805 records match the server filters");
    await page.goto(`/clusters/${clusterId}/repositories?page=9`);
    const repoTable = page.getByTestId("repository-table");
    await expect(repoTable.locator("tbody tr")).toHaveCount(5);
    await expect(repoTable).toContainText("repo-805");
    await expect(page.getByTestId("scan-inventory-continuation")).toContainText("805 records match the server filters");
    expect(requests.every(url => url.searchParams.get("limit") === "100" && url.searchParams.get("offset") === "800")).toBe(true);
});
test("finding asset grouping reflects only the current server page and follows server continuation", async ({ page }) => {
    const inventory = Array.from({ length: 150 }, (_, i) => finding(i));
    await mockInventory(page, "/findings", (url: URL) => { const offset = Number(url.searchParams.get("offset") ?? 0), limit = Number(url.searchParams.get("limit") ?? 100); return { findings: inventory.slice(offset, offset + limit), total: 150, limit, offset, has_more: offset + limit < 150, lifecycle_counts: counts(150) }; });
    await page.goto(`/clusters/${clusterId}/findings?view=instances&severity=high&group=asset`);
    await expect(page.getByTestId("findings-group-scope")).toContainText("100 groups from 100 instances");
    await expect(page.locator("main details")).toHaveCount(100);
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await expect(page.getByTestId("findings-group-scope")).toContainText("50 groups from 50 instances");
    await expect(page.locator("main details")).toHaveCount(50);
    await expect(page).toHaveURL(/page=2/);
});

async function revealImageDigest(area: Locator, digest: string) {
    const disclosure = area.locator("details").filter({ has: area.page().getByText("Show digest", { exact: true }) }).filter({ has: area.page().locator("code", { hasText: digest }) });
    await expect(disclosure.locator("code")).toBeHidden();
    await disclosure.locator("summary").click();
    await expect(disclosure.locator("code")).toBeVisible();
    await expect(disclosure.locator("code")).toHaveText(digest);
}

test("image scan names keep digests hidden across inventory, preview and detail until requested", async ({ page }) => {
    const digest = `sha256:${"c".repeat(64)}`;
    const layerDigest = `sha256:${"d".repeat(64)}`, diffID = `sha256:${"e".repeat(64)}`, bundleHash = `sha256:${"f".repeat(64)}`;
    const named = "registry.example.test/team/app:v2";
    const inventory = ["tagged", "reference-with-digest", "digest-only"].map((kind, index) => ({
        id: `identity-${index}`, image_ref: kind === "digest-only" ? digest : `${named}@${digest}`,
        image_ref_normalized: kind === "digest-only" ? digest : `${named}@${digest}`,
        image_repository: kind === "tagged" ? "registry.example.test/team/app" : kind === "digest-only" ? digest : "",
        image_tag: kind === "tagged" ? "v2" : "", image_digest: digest, source_ref: `${named}@${digest}`, vulndb_bundle_hash: bundleHash,
        scanner_profile: "default", source_type: "registry", engine_status: { syft: "succeeded", trivy: "succeeded", grype: "succeeded" },
        severity_counts: {}, max_risk_score: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0,
        finding_count: 0, impacted_count: 1, package_count: 1, layer_count: 1, secret_count: 0, file_risk_count: 1, image_signed: false,
        first_seen_at: at, updated_at: at, last_scanned_at: at,
    }));
    const requests = await mockInventory(page, "/image-scan-results", (url: URL) => ({ image_scan_results: inventory, ...inventoryMetadata(url, 3, { packages: 3, findings: 0, critical_high: 0, exposed: 3, local: 2, stale: 0, incomplete: 0 }) }));
    await page.route("**/api/v1/image-scan-results/**", async route => {
        const path = new URL(route.request().url()).pathname;
        const record = inventory.find(item => path === `/api/v1/image-scan-results/${item.id}` || path.startsWith(`/api/v1/image-scan-results/${item.id}/`));
        if (!record) return route.fulfill({ status: 404, json: { error: "Unexpected image fixture request" } });
        const artifact = path.slice(`/api/v1/image-scan-results/${record.id}`.length);
        const payloads: Record<string, unknown> = {
            "": { image_scan_result: record, findings: [], impacted_workloads: [{ cluster_id: clusterId, deployment_id: "deployment", workload_id: "pod", namespace: "apps", name: "api", kind: "Deployment", image_ref: record.image_ref, image_ref_normalized: record.image_ref_normalized, risk_score: 0, finding_count: 0, critical_count: 0, high_count: 0, last_seen_at: at }] },
            "/packages": { image_scan_result_id: record.id, package_layers: [{ layer_index: 4, layer_digest: layerDigest, package_count: 1, packages: [{ name: "owned-package" }] }], layer_package_count: 1 },
            "/layers": { image_scan_result_id: record.id, layer_metadata: { layers: [{ index: 4, digest: layerDigest, diff_id: diffID, command: "RUN apk add curl" }] } },
            "/file-risks": { image_scan_result_id: record.id, file_risk: { findings: [{ path: "/owned/file", layer_index: 4, layer_digest: layerDigest }] } },
            "/config-checks": { image_scan_result_id: record.id, config_checks: { checks: [] } },
        };
        return route.fulfill(artifact in payloads ? { json: payloads[artifact] } : { status: 404, json: { error: "Unexpected image artifact request" } });
    });
    for (const [index, record] of inventory.entries()) {
        const expected = index === 2 ? "Unnamed image" : named;
        await page.goto(`/clusters/${clusterId}/images?selected=${record.id}&image_digest=${encodeURIComponent(digest)}&q=${encodeURIComponent(digest)}`);
        const table = page.getByTestId("image-scans-table");
        await expect(table.locator("tbody tr")).toHaveCount(3);
        expect(await table.innerText()).not.toContain("sha256:");
        const row = table.locator("tbody tr").filter({ has: page.locator(`a[href$="/images/${record.id}"]`) });
        await expect(row.locator(`a[href$="/images/${record.id}"]`)).toHaveText(expected);
        await revealImageDigest(row, digest);
        await page.locator("summary").filter({ hasText: /^Selected image summary$/ }).click();
        const preview = page.getByTestId("image-scan-preview");
        await expect(preview.getByRole("heading", { level: 2 })).toHaveText(expected);
        expect(await preview.innerText()).not.toContain("sha256:");
        await revealImageDigest(preview, digest);
        await revealImageDigest(preview, bundleHash);
        await preview.getByRole("link", { name: "Full Details", exact: true }).click();
        const detail = page.getByTestId("image-scan-detail-page");
        await expect(detail.getByRole("heading", { level: 1 })).toHaveText(expected);
        expect(await detail.innerText()).not.toContain("sha256:");
        await page.getByRole("tab", { name: "Identity and exports", exact: true }).click();
        expect(await detail.innerText()).not.toContain("sha256:");
        await revealImageDigest(detail, digest);
        await revealImageDigest(detail, bundleHash);
        const raw = detail.locator("details").filter({ has: page.getByText("Raw image reference", { exact: true }) });
        await expect(raw.locator("code")).toBeHidden();
        await raw.locator("summary").click();
        await expect(raw.locator("code")).toBeVisible();
        await expect(raw.locator("code")).toHaveText(record.image_ref);
        await page.getByRole("tab", { name: /^Affected workloads/ }).click();
        const workloads = page.getByTestId("image-scan-workloads");
        await expect(workloads.locator('td[data-column-id="image"] span').first()).toHaveText(expected);
        expect(await workloads.innerText()).not.toContain("sha256:");
        await revealImageDigest(workloads, digest);
        await page.getByRole("tab", { name: "Scan evidence", exact: true }).click();
        const evidence = page.getByTestId("image-scan-artifact-evidence");
        await expect(evidence).toContainText("owned-package");
        await expect(evidence).toContainText("Layer 4");
        expect(await evidence.innerText()).not.toContain("sha256:");
        await revealImageDigest(evidence, layerDigest);
        await page.getByRole("tab", { name: "File risks", exact: true }).click();
        await expect(evidence).toContainText("/owned/file");
        expect(await evidence.innerText()).not.toContain("sha256:");
        await revealImageDigest(evidence, layerDigest);
        await page.getByRole("tab", { name: "Layers", exact: true }).click();
        await expect(evidence).toContainText("RUN apk add curl");
        await expect(evidence).toContainText("Layer 4");
        expect(await evidence.innerText()).not.toContain("sha256:");
        await revealImageDigest(evidence, layerDigest);
        await revealImageDigest(evidence, diffID);
    }
    expect(requests.every(url => url.searchParams.get("q") === digest && url.searchParams.get("image_digest") === digest && url.searchParams.get("cluster_id") === clusterId)).toBe(true);
});
