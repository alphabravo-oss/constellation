import { expect, test, type Page } from "@playwright/test";
import {
  resourceSavedViewFixture,
  savedViewCases,
} from "./fixtures/resource-saved-views";

async function storedViews(page: Page, kind: string) {
  return page.evaluate((inventory) => {
    const key = `constellation.operator.${JSON.stringify(["org-resource", "user-resource", `constellation.${inventory}.views.v1`])}`;
    return JSON.parse(localStorage.getItem(key) ?? "[]");
  }, kind);
}

for (const definition of savedViewCases) {
  test(`${definition.kind}: dedicated saved view preserves Cancel, scoped filters, Apply reset, history and owner isolation`, async ({
    page,
  }) => {
    const fixture = resourceSavedViewFixture(definition.kind);
    await fixture.install(page);
    await page.goto(fixture.initial);
    const controls = page.getByTestId(
      `${definition.kind}-saved-views-controls`,
    );
    const saveView = controls.getByRole("button", {
      name: `Save ${definition.label} view`,
      exact: true,
    });
    const table =
      definition.kind === "deployments"
        ? page.getByTestId("deployments-page").locator("table")
        : page.getByTestId(definition.table).locator("table");
    await expect(table.locator("tbody tr")).toHaveCount(100);
    await expect(table.locator("tbody tr").first()).toContainText(
      "needle-0101",
    );
    const expectReturned = async () => {
      if (definition.kind === "scanner") {
        await expect(page.getByTestId("scan-job-detail-drawer")).toBeVisible();
        await expect(page.getByRole("dialog")).toContainText(
          "registry.test/needle-0101:stable",
        );
      } else {
        await expect(saveView).toBeEnabled();
        if (definition.kind === "assets")
          await expect(page.getByTestId("asset-preview")).toContainText(
            "registry.test/needle-0101:stable",
          );
      }
    };
    await expectReturned();
    const original = new URL(page.url());
    const openForm = async () => {
      // Scanner selection is a modal read-only inspector. Its dedicated form
      // remains deep-linkable with the selected job as exact return context.
      if (definition.kind === "scanner")
        await page.goto(
          `${fixture.base}/views/new${original.search}${original.hash}`,
        );
      else await saveView.click();
    };
    await openForm();
    await expect(
      page.getByTestId("resource-saved-view-form-page"),
    ).toBeVisible();
    expect(new URL(page.url()).pathname).toBe(`${fixture.base}/views/new`);
    expect(new URL(page.url()).search).toBe(original.search);
    expect(new URL(page.url()).hash).toBe(original.hash);
    await page.getByLabel(/^View name/).fill("Canceled draft");
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await expectReturned();
    expect(new URL(page.url()).pathname).toBe(original.pathname);
    expect(new URL(page.url()).search).toBe(original.search);
    expect(new URL(page.url()).hash).toBe(original.hash);
    expect(await storedViews(page, definition.kind)).toEqual([]);
    await expect(table.locator("tbody tr").first()).toContainText(
      "needle-0101",
    );

    await openForm();
    await page.getByLabel(/^View name/).fill("Exact needle view");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expectReturned();
    expect(new URL(page.url()).search).toBe(original.search);
    expect(new URL(page.url()).hash).toBe(original.hash);
    const saved = await storedViews(page, definition.kind);
    expect(saved).toHaveLength(1);
    expect(saved[0]).toMatchObject({
      schema: 1,
      inventory: definition.kind,
      name: "Exact needle view",
      filters: definition.filters,
    });
    expect(saved[0].filters.page).toBeUndefined();
    expect(saved[0].filters.selected).toBeUndefined();
    await page.reload();
    await expectReturned();
    if (definition.kind === "scanner")
      await page
        .getByRole("button", { name: "Close drawer", exact: true })
        .click();
    await expect(saveView).toBeEnabled();
    await expect(
      controls.getByRole("button", { name: "Views (1)", exact: true }),
    ).toBeVisible();

    // The alternate deep link has a different page and selection. Apply is a
    // soft navigation; Back/Forward must restore that exact URL and server page.
    const alternative = new URL(page.url());
    alternative.searchParams.set("q", "other");
    await page.goto(alternative.href);
    await expect(table.locator("tbody tr").first()).toContainText("other-0101");
    await controls
      .getByRole("button", { name: "Views (1)", exact: true })
      .click();
    await page
      .getByRole("menuitem", {
        name: "Apply view Exact needle view",
        exact: true,
      })
      .click();
    await expect(table.locator("tbody tr").first()).toContainText(
      "needle-0001",
    );
    const applied = new URL(page.url());
    for (const [key, value] of Object.entries(definition.filters))
      expect(applied.searchParams.get(key)).toBe(value);
    expect(applied.searchParams.has("page")).toBe(false);
    expect(applied.searchParams.has("selected")).toBe(false);
    expect(applied.searchParams.getAll("context")).toEqual([
      "return-proof",
      "second-value",
    ]);
    expect(applied.hash).toBe("#retained-context");
    if (definition.kind === "runtime") {
      expect(applied.searchParams.has("event")).toBe(false);
      expect(applied.searchParams.has("event_at")).toBe(false);
    }
    const expectedChips: Record<string, string[]> = {
      assets: [
        "Search: needle",
        "Kind: image",
        "Criticality: high",
        "AI workload: true",
        "Sort: asset",
        "Direction: asc",
      ],
      deployments: [
        "Search: needle",
        "Namespace: prod",
        "Strongest group mode: protect",
        "Recorded workload fact: host_network",
        "Platform role: none",
        "Platform components: Shown",
      ],
      runtime: [
        "Search: needle",
        "Kind: exec",
        "Source: runtime-agent",
        "Minimum severity: high",
        "Verdict: alert",
        "Workload contains: prod/needle",
        "Namespace: prod",
        "Node: 44444444-4444-4444-8444-444444444444",
        "At or after: 2026-01-01T00:00:00.123456789Z",
        "Before: 2030-01-01T02:00:00.987654321+02:00",
        "Sort: at",
        "Direction: asc",
      ],
      scanner: [
        "Search: needle",
        "Status: failed",
        "Target type: image",
        "Cluster ID: 11111111-1111-4111-8111-111111111111",
        "Registry ID: 33333333-3333-4333-8333-333333333333",
        "Sort: target",
        "Direction: asc",
      ],
    };
    for (const chip of expectedChips[definition.kind])
      await expect(
        controls.locator('[aria-label="Active inventory filters"]'),
      ).toContainText(chip);
    await page.goBack();
    await expect(table.locator("tbody tr").first()).toContainText("other-0101");
    expect(new URL(page.url()).search).toBe(alternative.search);
    expect(new URL(page.url()).hash).toBe(alternative.hash);
    await page.goForward();
    await expect(table.locator("tbody tr").first()).toContainText(
      "needle-0001",
    );
    expect(new URL(page.url()).search).toBe(applied.search);
    await page.reload();
    await expect(table.locator("tbody tr").first()).toContainText(
      "needle-0001",
    );

    for (const [org, user] of [
      ["org-resource", "different-user"],
      ["different-org", "user-resource"],
    ]) {
      fixture.changeOwner(org, user);
      await page.reload();
      await expect(saveView).toBeEnabled();
      await expect(
        controls.getByRole("button", { name: "Views (0)", exact: true }),
      ).toBeVisible();
      expect(await storedViews(page, definition.kind)).toEqual(saved);
    }
    fixture.changeOwner("org-resource", "user-resource");
    await page.reload();
    await expect(
      controls.getByRole("button", { name: "Views (1)", exact: true }),
    ).toBeVisible();
    expect(
      fixture.requests.some((url) => url.searchParams.get("offset") === "100"),
    ).toBe(true);
    expect(
      fixture.requests.some(
        (url) =>
          url.searchParams.get("offset") === "0" &&
          (url.searchParams.get("q") ?? url.searchParams.get("search")) ===
            "needle",
      ),
    ).toBe(true);
  });
}
