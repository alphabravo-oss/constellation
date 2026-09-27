import { expect, test, type Page } from "@playwright/test";

const clusterId = "11111111-1111-4111-8111-111111111111";
const at = "2026-09-26T12:00:00Z";

async function mockPagedEvents(page: Page, rowCount: number) {
  const requests: URL[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    } else if (path === "/audit/events" || path === "/security/timeline") {
      requests.push(url);
      const offset = Number(url.searchParams.get("offset"));
      const limit = Number(url.searchParams.get("limit"));
      const indexes = Array.from({ length: Math.max(0, Math.min(limit, rowCount - offset)) }, (_, index) => offset + index);
      if (path === "/audit/events") {
        await route.fulfill({ json: {
          events: indexes.map((index) => ({ id: index + 1, action: `audit-action-${index + 1}`, prev_hash: "previous", chain_hash: "abcdef0123456789", at })),
          limit, offset, has_more: offset + limit < rowCount,
        } });
      } else {
        await route.fulfill({ json: {
          items: indexes.map((index) => ({ source: "runtime_event", id: String(index + 1), severity: "high", title: `timeline-event-${index + 1}`, at, cluster_id: clusterId })),
          limit, offset, has_more: offset + limit < rowCount, from: at, to: at,
        } });
      }
    } else {
      await route.fulfill({ status: 404, json: { error: `Unexpected request: ${path}` } });
    }
  });
  return requests;
}

function expectScopedPages(requests: URL[], path: string) {
  const matching = requests.filter((url) => url.pathname === `/api/v1${path}`);
  expect(matching.map((url) => [url.searchParams.get("limit"), url.searchParams.get("offset")])).toEqual([
    ["100", "0"], ["100", "100"],
  ]);
  expect(matching.every((url) => url.searchParams.get("cluster_id") === clusterId)).toBe(true);
}

test("audit shows the cap and fetches the next tenant-scoped page", async ({ page }) => {
  const requests = await mockPagedEvents(page, 101);
  await page.goto(`/clusters/${clusterId}/audit`);

  await expect(page.getByTestId("audit-page-scope")).toHaveText("Showing audit events 1–100 on page 1. More pages available.");
  await expect(page.getByTestId("audit-page").locator("tbody tr")).toHaveCount(100);
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByTestId("audit-page-scope")).toHaveText("Showing audit events 101–101 on page 2. No more pages.");
  await expect(page.getByTestId("audit-page").locator("tbody tr")).toHaveCount(1);
  await expect(page.getByTestId("audit-page").locator("tbody tr")).toContainText("audit-action-101");
  await expect(page.getByRole("button", { name: "Next" })).toBeDisabled();
  expectScopedPages(requests, "/audit/events");
});

test("timeline shows the cap and fetches the next tenant-scoped page", async ({ page }) => {
  const requests = await mockPagedEvents(page, 101);
  await page.goto(`/clusters/${clusterId}/timeline`);

  await expect(page.getByTestId("timeline-page-scope")).toHaveText("Showing timeline events 1–100 on page 1. More pages available.");
  await expect(page.getByTestId("timeline-event-row")).toHaveCount(100);
  await expect(page.getByRole("button", { name: "Export current page CSV" })).toBeEnabled();
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByTestId("timeline-page-scope")).toHaveText("Showing timeline events 101–101 on page 2. No more pages.");
  await expect(page.getByTestId("timeline-event-row")).toHaveCount(1);
  await expect(page.getByTestId("timeline-event-row")).toContainText("timeline-event-101");
  await expect(page.getByRole("button", { name: "Next" })).toBeDisabled();
  expectScopedPages(requests, "/security/timeline");
});

test("a single audit page still states its scope", async ({ page }) => {
  const requests = await mockPagedEvents(page, 1);
  await page.goto(`/clusters/${clusterId}/audit`);

  await expect(page.getByTestId("audit-page-scope")).toHaveText("Showing audit events 1–1 on page 1. No more pages.");
  await expect(page.getByRole("button", { name: "Next" })).toHaveCount(0);
  expect(requests).toHaveLength(1);
  expect(requests[0].searchParams.get("cluster_id")).toBe(clusterId);
});
