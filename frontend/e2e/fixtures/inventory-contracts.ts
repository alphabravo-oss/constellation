import { expect, type Page, type Route } from "@playwright/test";
import { assetEvidenceCluster, assetEvidenceID } from "./asset-evidence";
export const inventoryCluster = "11111111-1111-4111-8111-111111111111";
export const inventoryAt = "2026-10-12T12:00:00Z";
export function inventoryMetadata(url: URL, total: number, summary: Record<string, number>, defaultSort = "scan", defaultOrder = "desc") {
    const limit = Number(url.searchParams.get("limit") ?? "100"), offset = Number(url.searchParams.get("offset") ?? "0");
    return { total, summary: { ...summary, total }, limit, offset, has_more: offset + limit < total, sort: url.searchParams.get("sort") ?? defaultSort, order: url.searchParams.get("order") ?? defaultOrder };
}
export async function mockInventoryEndpoints(page: Page, handlers: Record<string, (url: URL, route: Route) => Promise<void> | void>) {
    const requests: URL[] = [];
    await page.route("**/api/v1/**", async (route) => {
        const url = new URL(route.request().url()), path = url.pathname.replace(/^\/api\/v1/, "");
        if (path === "/auth/me")
            return route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
        if (path === "/clusters")
            return route.fulfill({ json: { clusters: [{ id: inventoryCluster, name: "Test cluster", state: "connected" }] } });
        const handler = handlers[path];
        if (handler) {
            requests.push(url);
            await handler(url, route);
        }
        else
            await route.fulfill({ status: 404, json: { error: `Unexpected request: ${path}` } });
    });
    return requests;
}
export async function fulfillInventoryCSV(route: Route, body: string, total: number, filename: string, limit = 100000) {
    await route.fulfill({ contentType: "text/csv; charset=utf-8", headers: { "content-disposition": `attachment; filename="${filename}"`, "x-export-total": String(total), "x-export-limit": String(limit), "x-export-truncated": String(total > limit) }, body });
}
// Add the current paged evidence endpoint without changing the acceptance fixture.
export async function installAssetFindingInventory(page: Page) {
    await page.route(new RegExp(`/api/v1/assets/${assetEvidenceID}/findings(?:\\?.*)?$`), async (route) => {
        const url = new URL(route.request().url());
        expect(url.searchParams.get("cluster_id")).toBe(assetEvidenceCluster);
        const offset = Number(url.searchParams.get("offset") ?? "0");
        await route.fulfill({ json: { asset_id: assetEvidenceID, cluster_id: assetEvidenceCluster, items: offset ? [] : [{ id: "finding-fixture", row_id: `asset:finding-fixture:${(Date.parse(inventoryAt) / 1000).toFixed(6)}`, first_seen_at: inventoryAt, revision: "1", source_cluster_id: assetEvidenceCluster, target_cluster_id: null, title: "glibc heap overflow", kind: "vulnerability", external_id: "CVE-fixture", severity: "high", risk_score: 70, lifecycle: "open", source: "asset", last_seen_at: inventoryAt, platform_role: "" }], total: 1, summary: { total: 1, critical: 0, high: 1, open: 1, asset_findings: 1, image_scan_findings: 0 }, limit: 100, offset, has_more: false, sort: url.searchParams.get("sort") ?? "risk", order: url.searchParams.get("order") ?? "desc", q: url.searchParams.get("q") ?? "", severity: url.searchParams.get("severity") ?? "", lifecycle: url.searchParams.get("lifecycle") ?? "", source: url.searchParams.get("source") ?? "" } });
    });
}
