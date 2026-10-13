/* global Storage, DOMException */
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { expectRestoredFilters, savedViewCluster, savedViewsFixture, savedViewSnapshot, savedViewStorageKey, savedViewURL, saveNamedView, storedViews } from "./fixtures/inventory-network-saved-views";

for (const action of ["Save", "Cancel"] as const) {
  test(`Network dedicated ${action} preserves the exact snapshot and return context through history`, async ({ page }) => {
    const { identity } = await savedViewsFixture(page);
    await page.goto(savedViewURL());
    await expectRestoredFilters(page);
    const returnURL = page.url();
    await page.getByTestId("network-saved-view-save").click();
    await expect(page.getByRole("heading", { name: "Save network view", exact: true })).toBeVisible();
    await expect(page.getByTestId("network-view-snapshot")).toBeHidden();
    await page.locator("summary").filter({ hasText: "Advanced: captured filters" }).click();
    expect(JSON.parse(await page.getByTestId("network-view-snapshot").innerText())).toEqual(savedViewSnapshot);
    expect(new URL(page.url()).pathname).toBe(`/clusters/${savedViewCluster}/network/views/new`);
    await page.getByLabel(/^View name/).fill("Exact session evidence");
    await page.getByRole("button", { name: action, exact: true }).click();
    await expect(page).toHaveURL(returnURL);
    await expectRestoredFilters(page);
    expect(await storedViews(page, identity)).toEqual(action === "Save" ? [expect.objectContaining({ id: expect.any(String), name: "Exact session evidence", cluster_id: savedViewCluster, filters: savedViewSnapshot })] : []);
    await page.goBack();
    await expect(page.getByRole("heading", { name: "Save network view", exact: true })).toBeVisible();
    expect(JSON.parse(new URL(page.url()).searchParams.get("network_view")!)).toEqual(savedViewSnapshot);
    await page.goForward();
    await expect(page).toHaveURL(returnURL);
    await expectRestoredFilters(page);
  });
}

test("Network Apply restores persisted filters while organization and user views remain isolated", async ({ page }) => {
  const { identity, requests } = await savedViewsFixture(page);
  const originalOwner = { ...identity };
  await page.goto(savedViewURL());
  await expectRestoredFilters(page);
  await saveNamedView(page, "Operator A sessions");
  const persisted = await storedViews(page, identity);
  await page.goto(`/clusters/${savedViewCluster}/network?tab=conversations&hours=24&context=other#review`);
  await expect(page.getByTestId("network-window-select")).toHaveValue("24");
  await page.getByTestId("network-saved-view-select").selectOption({ label: "Operator A sessions" });
  await page.getByTestId("network-saved-view-apply").click();
  await expectRestoredFilters(page);
  const applied = new URL(page.url());
  expect(applied.searchParams.get("context")).toBe("other");
  expect(applied.hash).toBe("#review");
  expect(applied.searchParams.has("session_page")).toBe(false);
  // The form captures live local state, not merely the restored URL parameter.
  await page.getByTestId("network-saved-view-save").click();
  await page.locator("summary").filter({ hasText: "Advanced: captured filters" }).click();
  expect(JSON.parse(await page.getByTestId("network-view-snapshot").innerText())).toEqual(savedViewSnapshot);
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(applied.toString());
  await expect.poll(() => requests.some(url => url.pathname.endsWith("/network/sessions") && url.searchParams.get("protocol") === "tcp" && url.searchParams.get("application") === "7" && url.searchParams.get("port") === "443" && url.searchParams.get("peer") === "10.0.0.2" && url.searchParams.get("workload") === "prod/api" && url.searchParams.get("node") === "node-a")).toBe(true);
  await page.reload();
  await expectRestoredFilters(page);
  await expect(page.getByTestId("network-saved-view-select").locator("option", { hasText: "Operator A sessions" })).toHaveCount(1);
  identity.org_id = "org-b";
  await page.reload();
  await expect(page.getByTestId("network-saved-view-select").locator("option")).toHaveCount(1);
  await expect(page.getByTestId("network-saved-view-apply")).toBeDisabled();
  await saveNamedView(page, "Organization B sessions");
  expect(await storedViews(page, originalOwner)).toEqual(persisted);
  expect((await storedViews(page, identity)).map(view => view.name)).toEqual(["Organization B sessions"]);
  identity.org_id = originalOwner.org_id;
  identity.user_id = "operator-b";
  await page.reload();
  await expect(page.getByTestId("network-saved-view-select").locator("option")).toHaveCount(1);
  await expect(page.getByTestId("network-saved-view-export")).toBeDisabled();
  Object.assign(identity, originalOwner);
  await page.reload();
  await expect(page.getByTestId("network-saved-view-select").locator("option", { hasText: "Operator A sessions" })).toHaveCount(1);
  await expect(page.getByTestId("network-saved-view-select").locator("option", { hasText: "Organization B sessions" })).toHaveCount(0);
});

test("Network JSON export/import round trip previews rejected records and retains existing views", async ({ page }) => {
  const { identity } = await savedViewsFixture(page);
  await page.goto(savedViewURL());
  await expectRestoredFilters(page);
  await saveNamedView(page, "Exported sessions");
  const original = await storedViews(page, identity);
  const downloading = page.waitForEvent("download");
  await page.getByTestId("network-saved-view-export").click();
  const download = await downloading;
  expect(download.suggestedFilename()).toBe(`constellation-network-activity-views-${savedViewCluster}.json`);
  const text = await readFile(await download.path(), "utf8");
  const bundle = JSON.parse(text);
  expect(bundle).toEqual({ schema_version: 2, kind: "constellation.networkActivity.savedViews", cluster_id: savedViewCluster, exported_at: expect.any(String), views: original });
  expect(Number.isNaN(Date.parse(bundle.exported_at))).toBe(false);
  const returnURL = page.url();
  await page.getByTestId("network-saved-view-import").click();
  await expect(page.getByRole("heading", { name: "Import network views", exact: true })).toBeVisible();
  await page.getByLabel("Saved-view JSON file", { exact: true }).setInputFiles({ name: "views.json", mimeType: "application/json", buffer: Buffer.from(text) });
  await expect(page.getByRole("status")).toContainText("1 valid view; 0 rejected records");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page).toHaveURL(returnURL);
  expect(await storedViews(page, identity)).toEqual(original);
  await page.getByTestId("network-saved-view-import").click();
  await page.getByLabel("JSON contents", { exact: true }).fill("{");
  await expect(page.getByText("Choose a valid JSON saved-view file.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  const unsupported = JSON.stringify({ ...bundle, schema_version: 99 });
  await page.getByLabel("JSON contents", { exact: true }).fill(unsupported);
  await expect(page.getByText("The saved-view bundle kind or schema version is unsupported.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  await expect(page.getByLabel("JSON contents", { exact: true })).toHaveValue(unsupported);
  const mixed = { ...bundle, views: [...bundle.views, { ...bundle.views[0], id: "malformed", filters: { ...savedViewSnapshot, hours: 0 } }, null] };
  await page.getByLabel("JSON contents", { exact: true }).fill(JSON.stringify(mixed));
  await expect(page.getByRole("status")).toContainText("1 valid view; 2 rejected records");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page).toHaveURL(returnURL);
  const imported = await storedViews(page, identity);
  expect(imported).toHaveLength(2);
  expect(imported[0]).toEqual(original[0]);
  expect(new Set(imported.map(view => view.id)).size).toBe(2);
  expect(imported.every(view => view.name === "Exported sessions" && view.cluster_id === savedViewCluster && JSON.stringify(view.filters) === JSON.stringify(original[0].filters))).toBe(true);
  expect(imported.some(view => view.id === "malformed")).toBe(false);
  await page.evaluate(({ key, views, invalid }) => localStorage.setItem(key, JSON.stringify([...views, invalid, null])), { key: savedViewStorageKey(identity), views: imported, invalid: mixed.views[1] });
  await page.reload();
  await expect(page.getByTestId("network-saved-views").getByRole("alert")).toContainText("2 saved view records were rejected");
  await expect(page.getByTestId("network-saved-view-select").locator("option")).toHaveCount(3);
  const sanitizedDownload = page.waitForEvent("download");
  await page.getByTestId("network-saved-view-export").click();
  const sanitized = JSON.parse(await readFile(await (await sanitizedDownload).path(), "utf8"));
  expect(sanitized.views).toEqual(imported);
});

for (const mode of ["new", "import"] as const) {
  test(`Network ${mode} storage failure preserves its draft and never claims Save success`, async ({ page }) => {
    const { identity } = await savedViewsFixture(page);
    await page.goto(savedViewURL());
    await expectRestoredFilters(page);
    await page.getByTestId(mode === "new" ? "network-saved-view-save" : "network-saved-view-import").click();
    const draft = JSON.stringify([{ id: "import-draft", name: "Preserved import", cluster_id: savedViewCluster, saved_at: "2026-10-13T00:00:00Z", filters: savedViewSnapshot }]);
    if (mode === "new") await page.getByLabel(/^View name/).fill("Preserved name");
    else await page.getByLabel("JSON contents", { exact: true }).fill(draft);
    const formURL = page.url();
    await page.evaluate(() => {
      const original = Storage.prototype.setItem;
      Object.defineProperty(window, "restoreNetworkViewStorage", { configurable: true, value: () => { Storage.prototype.setItem = original; } });
      Storage.prototype.setItem = function (key, value) {
        if (key.includes("network-activity:saved-views")) throw new DOMException("Storage quota exceeded", "QuotaExceededError");
        original.call(this, key, value);
      };
    });
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByText("Saved views could not be stored in this browser. Check browser storage and try again.", { exact: true })).toBeVisible();
    await expect(page).toHaveURL(formURL);
    await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Saved", exact: true })).toHaveCount(0);
    if (mode === "new") await expect(page.getByLabel(/^View name/)).toHaveValue("Preserved name");
    else await expect(page.getByLabel("JSON contents", { exact: true })).toHaveValue(draft);
    expect(await page.evaluate(key => localStorage.getItem(key), savedViewStorageKey(identity))).toBeNull();
    await page.evaluate(() => Reflect.get(window, "restoreNetworkViewStorage")());
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByTestId("network-saved-view-select").locator("option", { hasText: mode === "new" ? "Preserved name" : "Preserved import" })).toHaveCount(1);
    const stored = await storedViews(page, identity);
    expect(stored).toHaveLength(1);
    expect(stored[0].filters).toEqual(savedViewSnapshot);
  });
}
