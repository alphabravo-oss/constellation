import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { parseCSV } from "./fixtures/dashboard-cohorts";

const cluster = "11111111-1111-4111-8111-111111111111";
async function fixture(page: Page) {
  const requests: URL[] = [];
  let unavailable = false;
  const rows = Array.from({ length: 205 }, (_, index) => ({ id: index + 1, event_id: String(index + 1), action: "auth.login.local", at: "2026-10-12T01:02:03.123456Z", actor_id: `actor-${index + 1}`, target_kind: "cluster", target_id: cluster, prev_hash: "previous", chain_hash: `hidden-chain-${index + 1}` }));
  await page.route("**/api/v1/**", async route => {
    expect(route.request().method()).toBe("GET");
    const url = new URL(route.request().url()), path = url.pathname.replace(/^\/api\/v1/, ""), p = url.searchParams;
    if (path === "/auth/me") return route.fulfill({ json: { org_id: "org", user_id: "operator", email: "operator@example.test", roles: ["GlobalAdmin"] } });
    if (path === "/clusters") return route.fulfill({ json: { clusters: [{ id: cluster, name: "Audit cluster", state: "connected" }] } });
    if (path === "/audit/events" || path === "/audit/events.csv") {
      requests.push(url);
      if (unavailable) return route.fulfill({ status: 503, json: { error: "Audit source unavailable" } });
      expect(p.get("cluster_id")).toBe(cluster);
      expect(p.get("action")).toBe("auth.login.local");
      expect(p.get("framework")).toBe("nist-800-53"); expect(p.get("control")).toBe("AC-2");
      if (path.endsWith(".csv")) {
        expect(p.has("offset")).toBe(false); expect(p.has("limit")).toBe(false);
        return route.fulfill({ contentType: "text/csv", headers: { "X-Export-Rows": "205", "X-Export-Limit": "100000", "X-Export-Truncated": "false" }, body: "event_id,at,action,chain_hash\n" + rows.map(row => `${row.event_id},${row.at},${row.action},${row.chain_hash}`).join("\n") });
      }
      const limit = Number(p.get("limit")), offset = Number(p.get("offset"));
      return route.fulfill({ json: { events: rows.slice(offset, offset + limit), limit, offset, has_more: offset + limit < rows.length } });
    }
    return route.fulfill({ status: 404, json: { error: `Unexpected fixture request ${path}` } });
  });
  return { requests, setUnavailable: (value: boolean) => { unavailable = value; } };
}
const target = `/clusters/${cluster}/audit?action=auth.login.local&framework=nist-800-53&control=AC-2&page=2&context=keep#evidence`;

test("Audit filters survive paging/history and matching CSV includes all pages while hashes require disclosure", async ({ page }) => {
  const state = await fixture(page);
  await page.goto(target);
  const table = page.getByTestId("audit-page").locator("table");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await expect(table).toContainText("actor-101"); await expect(table).not.toContainText("hidden-chain-");
  await expect(page.getByRole("textbox", { name: "Exact action" })).toHaveValue("auth.login.local");
  const pending = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export matching CSV", exact: true }).click();
  const path = await (await pending).path(); expect(path).not.toBeNull();
  const csv = parseCSV(await readFile(path!, "utf8"));
  expect(csv).toHaveLength(206); expect(new Set(csv.slice(1).map(row => row[0])).size).toBe(205);
  expect(csv[1]).toContain("2026-10-12T01:02:03.123456Z");
  await expect(page.getByRole("status")).toContainText("Exported all 205 matching records across pages");
  await page.getByRole("button", { name: "Columns", exact: true }).click();
  await page.getByRole("menuitemcheckbox", { name: "Chain Hash", exact: true }).click();
  await page.keyboard.press("Escape"); await expect(table).toContainText("hidden-chain-101");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(5); await expect(table).toContainText("actor-205");
  await page.goBack(); await expect(table).toContainText("actor-101");
  await page.reload(); await expect(table).toContainText("hidden-chain-101");
  expect(new URL(page.url()).searchParams.get("context")).toBe("keep"); expect(new URL(page.url()).hash).toBe("#evidence");
  expect(state.requests.some(url => url.pathname.endsWith(".csv"))).toBe(true);
});

test("Audit failed refresh withholds cached rows and exports until Retry recovers", async ({ page }) => {
  const state = await fixture(page); await page.goto(target);
  await expect(page.getByRole("button", { name: "Export matching CSV", exact: true })).toBeEnabled();
  state.setUnavailable(true); await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByText("Audit evidence unavailable", { exact: true })).toBeVisible();
  await expect(page.getByTestId("audit-page").locator("table")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Export matching CSV", exact: true })).toHaveCount(0);
  state.setUnavailable(false); await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByRole("button", { name: "Export matching CSV", exact: true })).toBeEnabled();
  await expect(page.getByTestId("audit-page").locator("tbody tr")).toHaveCount(100);
});
