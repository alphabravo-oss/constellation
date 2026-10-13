import { expect, test, type Page } from "@playwright/test";
import { inventoryCluster, mockInventoryEndpoints } from "./fixtures/inventory-contracts";

async function installViewsFixture(page: Page) {
  let identity = { org_id: "org-a", user_id: "user-a" };
  await mockInventoryEndpoints(page, {
    "/findings": (url, route) => route.fulfill({ json: { findings: [], total: 0, has_more: false, limit: 100, offset: Number(url.searchParams.get("offset") || 0), lifecycle_counts: { open: 0, triaged: 0, in_progress: 0, accepted: 0, suppressed: 0, resolved: 0 } } }),
    "/findings/by-cve": (_url, route) => route.fulfill({ json: { cves: [], total: 0, limit: 100, offset: 0 } }),
    "/security/timeline": (url, route) => route.fulfill({ json: { items: [], total: 0, has_more: false, limit: 100, offset: Number(url.searchParams.get("offset") || 0), from: url.searchParams.get("from") || "2026-10-10T00:00:00Z", to: url.searchParams.get("to") || "2026-10-12T00:00:00Z" } }),
  });
  await page.route("**/api/v1/auth/me", route => route.fulfill({ json: { ...identity, email: "operator@example.test", roles: ["GlobalAdmin"] } }));
  return (next: typeof identity) => { identity = next; };
}

const contexts = [
  { kind: "findings", query: "view=instances&severity=high&lifecycle=open", filter: "severity", value: "high" },
  { kind: "timeline", query: "tab=event&namespace=prod&severity=high&from=2026-10-10T00%3A00%3A00Z&to=2026-10-12T00%3A00%3A00Z", filter: "namespace", value: "prod" },
];

for (const entry of contexts) {
  test(`${entry.kind} named views preserve context, keyboard access and operator isolation`, async ({ page }) => {
    const setIdentity = await installViewsFixture(page);
    const origin = `/clusters/${inventoryCluster}/${entry.kind}`;
    await page.goto(`${origin}?${entry.query}&page=2&selected=keep&context=keep#evidence`);
    const initial = new URL(page.url());
    const expectReturnContext = async () => {
      await expect.poll(() => new URL(page.url()).pathname).toBe(origin);
      const url = new URL(page.url());
      expect(Object.fromEntries(url.searchParams)).toEqual(Object.fromEntries(initial.searchParams));
      expect(url.hash).toBe(initial.hash);
    };
    await page.getByRole("button", { name: "Save view", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/${entry.kind}/views/new\\?`));
    const name = page.getByRole("textbox", { name: /^View name/ });
    await name.fill("Canceled view");
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await expectReturnContext();
    await expect(page.getByRole("button", { name: "Views (0)", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Save view", exact: true }).click();
    await name.fill("Investigation view");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expectReturnContext();

    const views = page.getByRole("button", { name: "Views (1)", exact: true });
    await views.focus();
    await page.keyboard.press("ArrowDown");
    const apply = page.getByRole("menuitem", { name: "Apply view Investigation view", exact: true });
    await expect(apply).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu", { name: "Saved views" })).toHaveCount(0);
    await expect(views).toBeFocused();
    await page.keyboard.press("ArrowDown");
    await expect(apply).toBeFocused();
    await page.keyboard.press("End");
    await expect(page.getByRole("menuitem", { name: "Delete view Investigation view", exact: true })).toBeFocused();
    await page.keyboard.press("Home");
    await expect(apply).toBeFocused();
    await page.keyboard.press("Enter");
    await expect.poll(() => new URL(page.url()).searchParams.has("page")).toBe(false);
    expect(new URL(page.url()).searchParams.get(entry.filter)).toBe(entry.value);
    expect(new URL(page.url()).searchParams.get("context")).toBe("keep");
    await page.goBack();
    await expectReturnContext();
    await page.reload();
    await expect(views).toBeVisible();
    // Only the browser's reported identity changes: this checks local preference
    // isolation, not API authorization, which has independent acceptance tests.
    for (const identity of [{ org_id: "org-a", user_id: "user-b" }, { org_id: "org-b", user_id: "user-a" }]) {
      setIdentity(identity);
      await page.reload();
      await expect(page.getByRole("button", { name: "Views (0)", exact: true })).toBeVisible();
    }
    setIdentity({ org_id: "org-a", user_id: "user-a" });
    await page.reload();
    await views.focus();
    await page.keyboard.press("ArrowDown");
    await expect(apply).toBeFocused();
    await page.keyboard.press("End");
    await expect(page.getByRole("menuitem", { name: "Delete view Investigation view", exact: true })).toBeFocused();
    await page.keyboard.press("Enter");
    const emptyViews = page.getByRole("button", { name: "Views (0)", exact: true });
    await expect(emptyViews).toBeFocused();
    await page.reload();
    await emptyViews.click();
    await expect(page.getByRole("menuitem", { name: "No saved views" })).toBeVisible();
  });

  test(`${entry.kind} saved-view write failure retains the named draft until storage recovers`, async ({ page }) => {
    await installViewsFixture(page);
    await page.goto(`/clusters/${inventoryCluster}/${entry.kind}?${entry.query}`);
    await page.getByRole("button", { name: "Save view", exact: true }).click();
    const name = page.getByRole("textbox", { name: /^View name/ });
    await name.fill("Recoverable view");
    await page.evaluate(() => {
      const original = window.Storage.prototype.setItem;
      window.Storage.prototype.setItem = function (key, value) {
        if (key.startsWith("constellation.operator.")) throw new window.DOMException("Storage quota exceeded", "QuotaExceededError");
        return original.call(this, key, value);
      };
      Object.defineProperty(window, "restoreSavedViewStorage", { value: () => { window.Storage.prototype.setItem = original; }, configurable: true });
    });
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByText("Saved views could not be stored in this browser.", { exact: false })).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`/${entry.kind}/views/new\\?`));
    await expect(name).toHaveValue("Recoverable view");
    await page.evaluate(() => Reflect.get(window, "restoreSavedViewStorage")());
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("button", { name: "Views (1)", exact: true })).toBeVisible();
  });
}
