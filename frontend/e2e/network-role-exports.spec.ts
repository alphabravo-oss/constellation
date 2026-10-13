import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { streamCSV, streamEvidence, streamInventory } from "./fixtures/inventory-network-secondary";
import { conversation, conversationInventory, networkCSV, networkFixtureCluster as clusterId, notificationThreats, sessionInventory, threatInventory } from "./fixtures/network-inventory";

test("conversation table CSV retains endpoint roles and cluster-scoped visibility", async ({ page }) => {
  const requested: URL[] = [];
  const pairs = [
    conversation("custom-install/agent", "payments/app", { from_platform_role: "core" }),
    conversation("kube-system/legacy", "payments/app", { from_platform_role: "core" }),
    conversation("constellation-api/customer", "payments/app", { from_platform_role: "", to_platform_role: "" }),
    conversation("custom-install/ambiguous", "payments/app"),
  ];
  const streams = pairs.map((pair, index) => streamEvidence(index + 1, { from: pair.from, to: pair.to, from_platform_role: pair.from_platform_role ?? "", to_platform_role: pair.to_platform_role ?? "" }));
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url()), path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    else if (path === "/clusters") await route.fulfill({ json: { clusters: [{ id: clusterId, name: "Test cluster", state: "connected" }] } });
    else if (path === "/groups") await route.fulfill({ json: { groups: [] } });
    else if (path === "/network/map") { requested.push(url); await route.fulfill({ json: { summary: { window_hours: 24, selected_cluster_id: clusterId, workloads: 0, flows: 0 }, workloads: [], flows: [], recent_flows: [] } }); }
    else if (path === "/network/conversations") { requested.push(url); await route.fulfill({ json: conversationInventory(url, pairs) }); }
    else if (path === "/network/conversations.csv") { requested.push(url); await networkCSV(route, url, "conversations", pairs); }
    else if (path === "/network/conversations/streams") { requested.push(url); await route.fulfill({ json: streamInventory(url, streams) }); }
    else if (path === "/network/conversations/streams.csv") { requested.push(url); await streamCSV(route, url, streams); }
    else if (path === "/network/sessions") { requested.push(url); await route.fulfill({ json: sessionInventory(url, []) }); }
    else if (path === "/runtime-threats") await route.fulfill({ json: url.searchParams.has("cluster_id") ? threatInventory(url, []) : notificationThreats(url) });
    else if (path === "/network/policies/lifecycle") { requested.push(url); await route.fulfill({ json: { summary: { selected_cluster_id: clusterId, total: 0, ready: 0, discover: 0, monitor: 0, protect: 0, rollback_ready: 0, pending_approval: 0 }, items: [] } }); }
    else if (path === "/policies/dpi-threats") await route.fulfill({ json: { cluster_id: clusterId, weak_tls_enabled: false } });
    else await route.fulfill({ status: 404, json: { error: `Unexpected fixture request ${path}` } });
  });
  await page.goto(`/clusters/${clusterId}/network?tab=conversations`);
  const view = page.getByTestId("network-conversations-tab"), table = page.getByTestId("network-conversations-table");
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await expect(table).toContainText("constellation-api/customer");
  await expect(table).toContainText("custom-install/ambiguous");
  await expect(table).not.toContainText("custom-install/agent");
  await expect(table).not.toContainText("kube-system/legacy");
  expect(requested.map(url => url.pathname)).toEqual(expect.arrayContaining(["/api/v1/network/map", "/api/v1/network/conversations", "/api/v1/network/policies/lifecycle"]));
  expect(requested.every(url => url.searchParams.get("cluster_id") === clusterId)).toBe(true);
  expect(requested.some(url => url.pathname.endsWith("/network/conversations") && url.searchParams.get("hide_platform") === "true")).toBe(true);

  await page.getByTestId("platform-visibility-toggle").click();
  await expect(table.locator("tbody tr")).toHaveCount(4);
  await expect(table).toContainText("custom-install/agent");
  await expect(table).toContainText("kube-system/legacy");
  const pageDownload = page.waitForEvent("download");
  await page.getByTestId("network-conversations-table-export-csv").click();
  const pageCSV = readFileSync(await (await pageDownload).path(), "utf8");
  const lines = pageCSV.trim().split(/\r?\n/);
  expect(lines[0]).toContain("from_platform_role");
  expect(lines[0]).toContain("to_platform_role");
  expect(lines.find(line => line.includes("custom-install/agent"))).toContain("core");
  expect(lines.find(line => line.includes("kube-system/legacy"))).toContain("core");
  expect(lines.find(line => line.includes("custom-install/ambiguous"))).not.toContain("core");
  expect(lines).toHaveLength(5);
  const matchingDownload = page.waitForEvent("download");
  await view.getByRole("button", { name: "Export matching CSV", exact: true }).click();
  expect(readFileSync(await (await matchingDownload).path(), "utf8").trim().split(/\r?\n/)).toHaveLength(5);
  expect(requested.some(url => url.pathname.endsWith("/network/conversations.csv") && url.searchParams.get("hide_platform") === "false" && url.searchParams.get("cluster_id") === clusterId)).toBe(true);

  await table.locator("tbody tr").filter({ hasText: "custom-install/agent" }).click();
  const streamView = page.getByTestId("network-streams-inventory");
  await expect(streamView.locator("tbody tr")).toHaveCount(1);
  await expect(streamView.locator("tbody tr")).toContainText("core");
  const streamDownloading = page.waitForEvent("download");
  await streamView.getByRole("button", { name: "Export page CSV", exact: true }).click();
  const streamPageCSV = readFileSync(await (await streamDownloading).path(), "utf8");
  expect(streamPageCSV.split(/\r?\n/)[0]).toContain("from_platform_role");
  expect(streamPageCSV.split(/\r?\n/)[0]).toContain("to_platform_role");
  expect(streamPageCSV.trim().split(/\r?\n/)).toHaveLength(2);
  expect(streamPageCSV.trim().split(/\r?\n/)[1]).toContain("core");
  const streamFullDownloading = page.waitForEvent("download");
  await streamView.getByRole("button", { name: "Export matching CSV", exact: true }).click();
  const streamFullCSV = readFileSync(await (await streamFullDownloading).path(), "utf8");
  expect(streamFullCSV).toContain("custom-install/agent");
  expect(streamFullCSV.trim().split(/\r?\n/)).toHaveLength(2);
  const streamed = requested.find(url => url.pathname.endsWith("/streams.csv"))!;
  expect(streamed.searchParams.get("cluster_id")).toBe(clusterId);
  expect(streamed.searchParams.get("from")).toBe("custom-install/agent");
  expect(streamed.searchParams.get("to")).toBe("payments/app");
  expect(streamed.searchParams.get("hide_platform")).toBe("false");
  expect(streamed.searchParams.has("limit")).toBe(false);
  expect(streamed.searchParams.has("offset")).toBe(false);

  await table.locator("tbody tr").filter({ hasText: "custom-install/ambiguous" }).click();
  await expect(streamView.locator("tbody tr")).toHaveCount(1);
  await expect(streamView.locator("tbody tr")).not.toContainText("core");
  const unknownDownloading = page.waitForEvent("download");
  await streamView.getByRole("button", { name: "Export page CSV", exact: true }).click();
  const unknownCSV = readFileSync(await (await unknownDownloading).path(), "utf8");
  expect(unknownCSV.trim().split(/\r?\n/)).toHaveLength(2);
  expect(unknownCSV.split(/\r?\n/)[0]).toContain("from_platform_role");
  expect(unknownCSV.split(/\r?\n/)[1]).not.toContain("core");
});
