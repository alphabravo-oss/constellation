import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { captureEvidence, installSecondaryInventory, secondaryCluster, streamEvidence, streamFrom, streamTo } from "./fixtures/inventory-network-secondary";

// Strict CSV reader so raw tuple IDs and commas are checked as actual cells.
function csvRows(csv: string): string[][] {
  const records: string[][] = []; let row: string[] = [], cell = "", quoted = false;
  for (let i = 0; i < csv.length; i++) {
    const char = csv[i];
    if (char === '"') { if (quoted && csv[i + 1] === '"') { cell += '"'; i++; } else quoted = !quoted; }
    else if (!quoted && char === ",") { row.push(cell); cell = ""; }
    else if (!quoted && char === "\n") { row.push(cell.replace(/\r$/, "")); records.push(row); row = []; cell = ""; }
    else cell += char;
  }
  if (cell || row.length) { row.push(cell); records.push(row); }
  return records;
}

test("Network stream inventory continues the exact directed pair and exports every matching tuple", async ({ page }) => {
  const rows = Array.from({ length: 250 }, (_, index) => streamEvidence(index + 1));
  const requests = await installSecondaryInventory(page, [...rows, streamEvidence(251, { from: "foreign/agent" }), streamEvidence(252, { to: "other/api" })], []);
  const query = new URLSearchParams({ tab: "conversations", hours: "168", namespace: "prod", hide_platform: "false", inspect_from: streamFrom, inspect_to: streamTo, context: "dashboard" });
  await page.goto(`/clusters/${secondaryCluster}/network?${query}#evidence`);
  const view = page.getByTestId("network-streams-inventory"), table = view.locator("table");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await expect(view).toContainText("250 matching aggregate streams");
  await expect(table.locator("tbody tr").first()).toContainText("APP-0250");
  await table.getByRole("button", { name: "Port", exact: true }).click();
  await expect(table.locator('th[data-column-id="port"]')).toHaveAttribute("aria-sort", "descending");
  await table.getByRole("button", { name: "Port", exact: true }).click();
  await expect(table.locator('th[data-column-id="port"]')).toHaveAttribute("aria-sort", "ascending");
  await expect(table.locator("tbody tr").first()).toContainText("APP-0001");
  await view.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await expect(table.locator("tbody tr").first()).toContainText("APP-0101");
  await expect(page).toHaveURL(/stream_page=2/);
  const pageDownloading = page.waitForEvent("download");
  await view.getByRole("button", { name: "Export page CSV", exact: true }).click();
  const current = csvRows(await readFile(await (await pageDownloading).path(), "utf8"));
  expect(current).toHaveLength(101);
  expect(current[1][current[0].indexOf("Application")]).toBe("APP-0101");
  expect(current[1][current[0].indexOf("from_platform_role")]).toBe("core");
  expect(current[1][current[0].indexOf("to_platform_role")]).toBe("");
  const fullDownloading = page.waitForEvent("download");
  await view.getByRole("button", { name: "Export matching CSV", exact: true }).click();
  const full = csvRows(await readFile(await (await fullDownloading).path(), "utf8"));
  expect(full).toHaveLength(251);
  expect(full[1][full[0].indexOf("Application")]).toBe("APP-0001");
  expect(full.at(-1)![full[0].indexOf("Application")]).toBe("APP-0250");
  expect(full.slice(1).every(row => row[full[0].indexOf("From")] === streamFrom && row[full[0].indexOf("To")] === streamTo && row[full[0].indexOf("from_platform_role")] === "core")).toBe(true);
  expect(JSON.parse(full[1][full[0].indexOf("Aggregate tuple ID")])).toEqual(["tcp", "app-0001", 40001, "allow"]);
  const exported = requests.find(url => url.pathname.endsWith("/streams.csv"))!;
  expect(exported.searchParams.get("cluster_id")).toBe(secondaryCluster);
  expect(exported.searchParams.get("from")).toBe(streamFrom);
  expect(exported.searchParams.get("to")).toBe(streamTo);
  expect(exported.searchParams.get("namespace")).toBe("prod");
  expect(exported.searchParams.get("hours")).toBe("168");
  expect(exported.searchParams.get("sort")).toBe("port");
  expect(exported.searchParams.get("order")).toBe("asc");
  expect(exported.searchParams.get("hide_platform")).toBe("false");
  expect(exported.searchParams.has("limit")).toBe(false);
  expect(exported.searchParams.has("offset")).toBe(false);
  await page.goBack();
  await expect(table.locator("tbody tr").first()).toContainText("APP-0001");
  await page.goForward();
  await expect(table.locator("tbody tr").first()).toContainText("APP-0101");
  await view.getByLabel("Stream protocol filter", { exact: true }).fill("udp");
  await expect(view).toContainText("125 matching aggregate streams");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  expect(new URL(page.url()).searchParams.has("stream_page")).toBe(false);
  await view.getByLabel("Search streams", { exact: true }).fill("APP-0250");
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText("APP-0250");
  await expect(view).toContainText("1 matching aggregate streams");
  const filteredDownloading = page.waitForEvent("download");
  await view.getByRole("button", { name: "Export matching CSV", exact: true }).click();
  const filtered = csvRows(await readFile(await (await filteredDownloading).path(), "utf8"));
  expect(filtered).toHaveLength(2);
  expect(filtered[1][filtered[0].indexOf("Protocol")]).toBe("UDP");
  expect(filtered[1][filtered[0].indexOf("Application")]).toBe("APP-0250");
  expect(requests.at(-1)?.searchParams.get("q")).toBe("APP-0250");
  expect(requests.at(-1)?.searchParams.get("protocol")).toBe("udp");
  expect(new URL(page.url()).searchParams.get("context")).toBe("dashboard");
  expect(new URL(page.url()).hash).toBe("#evidence");
});

test("Network capture inventory pages all owned requests and preserves unknown measurements in CSV", async ({ page }) => {
  const rows = Array.from({ length: 305 }, (_, index) => captureEvidence(index + 1));
  const core = Array.from({ length: 5 }, (_, index) => captureEvidence(306 + index, { workload: `operations/agent-${index + 1}`, namespace: "operations", platform_role: "core" }));
  const requests = await installSecondaryInventory(page, [], [...rows, ...core, captureEvidence(311, { org_id: "foreign", workload: "prod/foreign" }), captureEvidence(312, { cluster_id: "22222222-2222-4222-8222-222222222222", workload: "prod/sibling" })]);
  await page.goto(`/clusters/${secondaryCluster}/network?tab=pcap&hide_platform=false&context=dashboard#captures`);
  const view = page.getByTestId("network-pcap-tab"), table = page.getByTestId("network-pcap-table");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await expect(view).toContainText("310 matching capture requests");
  await table.getByRole("button", { name: "Workload", exact: true }).click();
  await expect(table.locator('th[data-column-id="workload"]')).toHaveAttribute("aria-sort", "descending");
  await table.getByRole("button", { name: "Workload", exact: true }).click();
  await expect(table.locator('th[data-column-id="workload"]')).toHaveAttribute("aria-sort", "ascending");
  const unknown = table.locator("tbody tr").filter({ hasText: "prod/app-0001" });
  await expect(unknown).toBeVisible();
  const ids = await table.locator("thead th").evaluateAll(elements => elements.map(element => element.getAttribute("data-column-id")));
  expect(ids).toEqual(expect.arrayContaining(["packets", "bytes"]));
  await expect(unknown.locator("td").nth(ids.indexOf("packets"))).toHaveText("Not reported");
  await expect(unknown.locator("td").nth(ids.indexOf("bytes"))).toHaveText("Not reported");
  await expect(unknown.getByTestId("network-pcap-download")).toBeEnabled();
  await view.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table.locator("tbody tr").first()).toContainText("prod/app-0096");
  await expect(page).toHaveURL(/pcap_page=2/);
  const currentDownloading = page.waitForEvent("download");
  await table.getByRole("button", { name: "Export page CSV", exact: true }).click();
  const current = csvRows(await readFile(await (await currentDownloading).path(), "utf8"));
  expect(current).toHaveLength(101);
  expect(current[1][current[0].indexOf("Workload")]).toBe("prod/app-0096");
  const fullDownloading = page.waitForEvent("download");
  await view.getByRole("button", { name: "Export matching CSV", exact: true }).click();
  const full = csvRows(await readFile(await (await fullDownloading).path(), "utf8"));
  expect(full).toHaveLength(311);
  expect(full.slice(1).filter(row => row[full[0].indexOf("platform_role")] === "core")).toHaveLength(5);
  expect(full.slice(1).some(row => ["prod/foreign", "prod/sibling"].includes(row[full[0].indexOf("Workload")]))).toBe(false);
  const missing = full.find(row => row[full[0].indexOf("Workload")] === "prod/app-0001")!;
  expect(missing[full[0].indexOf("Packets")]).toBe("");
  expect(missing[full[0].indexOf("File bytes")]).toBe("");
  await page.goBack();
  await expect(table.locator("tbody tr").filter({ hasText: "operations/agent-1" })).toBeVisible();
  await page.goForward();
  await expect(table.locator("tbody tr").first()).toContainText("prod/app-0096");
  await view.getByLabel("Capture namespace filter", { exact: true }).fill("prod");
  await expect(view).toContainText("305 matching capture requests");
  await view.getByLabel("Capture node filter", { exact: true }).fill("node-a");
  await view.getByLabel("Capture status filter", { exact: true }).selectOption("completed");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await expect(table.locator("tbody tr").first()).toContainText("prod/app-0001");
  expect(new URL(page.url()).searchParams.has("pcap_page")).toBe(false);
  const filteredDownloading = page.waitForEvent("download");
  await view.getByRole("button", { name: "Export matching CSV", exact: true }).click();
  expect(csvRows(await readFile(await (await filteredDownloading).path(), "utf8"))).toHaveLength(306);
  const exported = requests.filter(url => url.pathname.endsWith("/inventory.csv")).at(-1)!;
  expect(Object.fromEntries(exported.searchParams)).toEqual({ cluster_id: secondaryCluster, namespace: "prod", node: "node-a", status: "completed", hide_platform: "false", sort: "workload", order: "asc" });
  await view.getByLabel("Search captures", { exact: true }).fill("app-0305");
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText("prod/app-0305");
  await expect(view).toContainText("1 matching capture requests");
  const requestHref = await view.getByTestId("network-pcap-new").getAttribute("href");
  const requestURL = new URL(requestHref!, page.url());
  expect(requestURL.pathname).toBe(`/clusters/${secondaryCluster}/network/pcap/new`);
  expect(requestURL.searchParams.get("context")).toBe("dashboard");
  expect(requestURL.hash).toBe("#captures");
  expect(JSON.parse(requestURL.searchParams.get("network_view")!).pcap_filters).toEqual(expect.objectContaining({ q: "app-0305", namespace: "prod", node: "node-a", status: "completed" }));
});
