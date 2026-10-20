import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import { backupFixture } from "./fixtures/backup-inventory";

test("Backup history continues beyond 50 with full matching CSV and the independent owned latest success", async ({
  page,
}) => {
  const fixture = backupFixture();
  await fixture.install(page);
  await page.goto("/settings/backup?page=13&context=review");
  const history = page.getByTestId("backup-history"),
    status = page.getByTestId("backup-status");
  await expect(history.locator("tbody tr")).toHaveCount(7);
  await expect(
    page.getByText("1,207 matching backup runs · 7 on page 13", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(status).toContainText("2021");
  await expect(status).toContainText("Owned backup signer");
  await expect(status).toContainText("s3://owned/archive/latest.tar.gz");
  await expect(history).not.toContainText("Foreign signer");
  await expect(history).not.toContainText("Unowned legacy signer");
  expect(
    fixture.requests.some(
      (url) =>
        url.searchParams.get("offset") === "1200" &&
        url.searchParams.get("limit") === "100",
    ),
  ).toBe(true);
  const pageDownloading = page.waitForEvent("download");
  await history
    .getByRole("button", { name: "Export this page metadata CSV", exact: true })
    .click();
  expect(
    (await readFile(await (await pageDownloading).path(), "utf8"))
      .trim()
      .split(/\r?\n/),
  ).toHaveLength(8);
  const downloading = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export matching CSV", exact: true })
    .click();
  const csv = await readFile(await (await downloading).path(), "utf8");
  expect(csv.trim().split(/\r?\n/)).toHaveLength(1208);
  expect(csv).toContain(fixture.latest.id);
  expect(csv.split(/\r?\n/)[0]).toContain("sha256");
  expect(csv).toContain(fixture.latest.sha256!);
  expect(csv).toContain("2021-01-01T00:00:01.123456Z");
  expect(csv).not.toContain(fixture.foreign.id);
  expect(csv).not.toContain(fixture.unowned.id);
  await page
    .getByLabel("Backup status", { exact: true })
    .selectOption("failed");
  await expect(history.locator("tbody tr")).toHaveCount(100);
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("status") === "failed" &&
      !url.searchParams.has("page") &&
      url.searchParams.get("context") === "review",
  );
  await expect(status).toContainText("Owned backup signer");
  await page
    .getByLabel("Search backup history", { exact: true })
    .fill("NEEDLE%_");
  await expect(history.locator("tbody tr")).toHaveCount(1);
  await expect(history.locator("tbody tr")).toContainText("failed");
  await expect(status).toContainText("2021");
  const filteredDownloading = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export matching CSV", exact: true })
    .click();
  const filteredCSV = await readFile(
    await (await filteredDownloading).path(),
    "utf8",
  );
  expect(filteredCSV.trim().split(/\r?\n/)).toHaveLength(2);
  expect(filteredCSV).not.toContain(fixture.latest.id);
  expect(filteredCSV).toContain("needle%_literal");
  const request = fixture.requests
    .filter((url) => url.pathname.endsWith(".csv"))
    .at(-1)!;
  expect(request.searchParams.get("q")).toBe("needle%_");
  expect(request.searchParams.get("status")).toBe("failed");
  expect(request.searchParams.get("sort")).toBe("when");
  expect(request.searchParams.get("order")).toBe("desc");
  expect(request.searchParams.has("offset")).toBe(false);
});

test("Backup history server sort, signature filters and Back restore URL scope and full-cohort results", async ({
  page,
}) => {
  const fixture = backupFixture();
  await fixture.install(page);
  await page.goto("/settings/backup?context=review");
  const history = page.getByTestId("backup-history");
  await expect(history.locator("tbody tr")).toHaveCount(100);
  await history.getByRole("button", { name: "Size", exact: true }).click();
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("sort") === "size" &&
      url.searchParams.get("order") === "desc",
  );
  await expect(history.locator("tbody tr").first()).toContainText(
    "Owned backup signer",
  );
  await page
    .getByLabel("Backup signature", { exact: true })
    .selectOption("true");
  await expect(history.locator("tbody tr")).toHaveCount(1);
  await expect(history).toContainText("Owned backup signer");
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("signed") === "true" &&
      url.searchParams.get("sort") === "size" &&
      url.searchParams.get("context") === "review",
  );
  await page.goBack();
  await expect(
    page.getByLabel("Backup signature", { exact: true }),
  ).toHaveValue("all");
  await expect(history.locator("tbody tr")).toHaveCount(100);
  await page.goBack();
  await expect(page).toHaveURL("/settings/backup?context=review");
  await expect(
    history.locator('thead th[data-column-id="when"]'),
  ).toHaveAttribute("aria-sort", "descending");
  await expect(history.locator("tbody tr").first()).not.toContainText(
    "Owned backup signer",
  );
});

test("Failed Backup refresh withholds cached history, latest-success KPIs and exports until Retry succeeds", async ({
  page,
}) => {
  const fixture = backupFixture();
  await fixture.install(page);
  await page.goto("/settings/backup?status=failed&context=review");
  const history = page.getByTestId("backup-history"),
    status = page.getByTestId("backup-status");
  await expect(history.locator("tbody tr")).toHaveCount(100);
  await expect(status).toContainText("Owned backup signer");
  fixture.fail();
  await page
    .getByRole("button", { name: "Refresh history", exact: true })
    .click();
  await expect(
    page.getByText("Backup history is unavailable or could not be refreshed.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(history).toHaveCount(0);
  await expect(status).not.toContainText("Owned backup signer");
  await expect(status).toContainText("unavailable");
  await expect(
    page.getByRole("button", { name: "Export matching CSV", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", {
      name: "Export this page metadata CSV",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.getByText("No backup runs match these filters or page.", {
      exact: true,
    }),
  ).toHaveCount(0);
  fixture.recover();
  await page
    .getByRole("button", { name: "Retry history", exact: true })
    .click();
  await expect(history.locator("tbody tr")).toHaveCount(100);
  await expect(status).toContainText("Owned backup signer");
  await expect(
    page.getByRole("button", { name: "Export matching CSV", exact: true }),
  ).toBeEnabled();
  await expect(page).toHaveURL("/settings/backup?status=failed&context=review");
});
