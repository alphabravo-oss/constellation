import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import {
  networkRuleFixture,
  ruleCluster,
  ruleRoot,
  tailPair,
} from "./fixtures/network-rule-inventory";

test("Network Rules continues the full cohort beyond 3000, server-sorts and exports matching records across pages", async ({
  page,
}) => {
  const fixture = networkRuleFixture();
  await fixture.install(page);
  await page.goto(`${ruleRoot}?page=53&context=dashboard`);
  const table = page.getByTestId("network-rules-table");
  await expect(table.locator("tbody tr")).toHaveCount(5);
  await expect(
    page.getByText("5,205 matching rules", { exact: true }),
  ).toBeVisible();
  await expect(table).toContainText(tailPair.from);
  expect(
    fixture.requests.some(
      (url) =>
        url.searchParams.get("offset") === "5200" &&
        url.searchParams.get("limit") === "100",
    ),
  ).toBe(true);
  const pageDownloading = page.waitForEvent("download");
  await table
    .getByRole("button", { name: "Export page CSV", exact: true })
    .click();
  const pageCSV = await readFile(await (await pageDownloading).path(), "utf8");
  expect(pageCSV.trim().split(/\r?\n/)).toHaveLength(6);
  const allDownloading = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export matching CSV", exact: true })
    .click();
  const allCSV = await readFile(await (await allDownloading).path(), "utf8");
  expect(allCSV.trim().split(/\r?\n/)).toHaveLength(5206);
  expect(allCSV.split(/\r?\n/)[0]).toContain("from_platform_role");
  expect(
    allCSV.split(/\r?\n/).find((row) => row.includes(tailPair.from)),
  ).toContain("core");
  await page
    .getByLabel("Search network rules", { exact: true })
    .fill("tail qualification marker");
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText(tailPair.from);
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("q") === "tail qualification marker" &&
      !url.searchParams.has("page") &&
      url.searchParams.get("context") === "dashboard",
  );
  const filteredDownloading = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export matching CSV", exact: true })
    .click();
  expect(
    (await readFile(await (await filteredDownloading).path(), "utf8"))
      .trim()
      .split(/\r?\n/),
  ).toHaveLength(2);
  const exportURL = fixture.requests
    .filter((url) => url.pathname.endsWith(".csv"))
    .at(-1)!;
  expect(exportURL.searchParams.get("q")).toBe("tail qualification marker");
  expect(exportURL.searchParams.has("offset")).toBe(false);
  await page.getByLabel("Search network rules", { exact: true }).fill("");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await table.getByRole("button", { name: "Matches", exact: true }).click();
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("sort") === "matches" &&
      url.searchParams.get("order") === "desc",
  );
  await expect(table.locator("tbody tr").first()).toContainText(tailPair.from);
  await page.goBack();
  await expect(
    page.getByLabel("Sort network rules", { exact: true }),
  ).toHaveValue("evaluation");
  await expect(table.locator("tbody tr").first()).toContainText("team/app-1");
  expect(fixture.writes).toEqual([]);
});

for (const action of ["Save changes", "Cancel"] as const) {
  test(`Tail endpoint-pair authoring ${action} preserves filtered return context and exact stored rule identity`, async ({
    page,
  }) => {
    const fixture = networkRuleFixture();
    await fixture.install(page);
    await page.goto(
      `${ruleRoot}?q=tail+qualification+marker&context=risk&status=enabled`,
    );
    const table = page.getByTestId("network-rules-table");
    await expect(table.locator("tbody tr")).toHaveCount(1);
    const returnURL = page.url();
    await table
      .getByRole("link", {
        name: `Edit rule from ${tailPair.from} to ${tailPair.to}`,
        exact: true,
      })
      .click();
    await expect(
      page.getByRole("heading", { name: "Edit network rule", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByLabel("From (source)", { exact: false }),
    ).toHaveValue(tailPair.from);
    await expect(
      page.getByLabel("To (destination)", { exact: false }),
    ).toHaveValue(tailPair.to);
    await expect(
      page.getByLabel("From (source)", { exact: false }),
    ).toBeDisabled();
    expect(
      fixture.requests.some(
        (url) =>
          url.searchParams.get("from") === tailPair.from &&
          url.searchParams.get("to") === tailPair.to &&
          url.searchParams.get("limit") === "1",
      ),
    ).toBe(true);
    await expect(
      page.locator("summary").filter({ hasText: "Advanced" }),
    ).toBeVisible();
    await page
      .getByLabel("Comment", { exact: true })
      .fill("tail qualification marker · reviewed candidate draft");
    await page.getByLabel("Action", { exact: false }).selectOption("deny");
    await page.getByRole("button", { name: action, exact: true }).click();
    await expect(page).toHaveURL(returnURL);
    await expect(table.locator("tbody tr")).toHaveCount(1);
    expect(fixture.writes).toEqual(
      action === "Cancel"
        ? []
        : [
            expect.objectContaining({
              from: tailPair.from,
              to: tailPair.to,
              comment: "tail qualification marker · reviewed candidate draft",
              action: "deny",
              disable: false,
              priority: 5205,
            }),
          ],
    );
    expect(fixture.rows.slice(0, 5204).every((row) => !row.comment)).toBe(true);
    expect(fixture.rows[5204].action).toBe(
      action === "Cancel" ? "allow" : "deny",
    );
    await page.goBack();
    await expect(
      page.getByRole("heading", { name: "Edit network rule", exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(page).toHaveURL(returnURL);
  });
}

test("Lifecycle tuple preview shows returned custom-install and unknown roles without changing candidate identity", async ({
  page,
}) => {
  const fixture = networkRuleFixture();
  await fixture.install(page);
  await page.goto(
    `/clusters/${ruleCluster}/network?tab=rules&workload=payments/api&hide_platform=false`,
  );
  const tuples = page.getByTestId("network-policy-tuple-preview");
  await expect(tuples).not.toBeVisible();
  await page
    .locator("summary")
    .filter({ hasText: "Advanced: candidate and observed tuples" })
    .click();
  await expect(tuples.locator("tbody tr")).toHaveCount(2);
  await expect(
    tuples.locator("tbody tr").filter({ hasText: tailPair.from }),
  ).toContainText("Core");
  await expect(
    tuples.locator("tbody tr").filter({ hasText: "10.0.0.9" }),
  ).toContainText("Unclassified");
  const downloading = page.waitForEvent("download");
  await tuples
    .getByRole("button", { name: "Export returned tuple preview", exact: true })
    .click();
  const csv = await readFile(await (await downloading).path(), "utf8");
  expect(csv.split(/\r?\n/)[0]).toContain("Platform role");
  expect(
    csv.split(/\r?\n/).find((row) => row.includes(tailPair.from)),
  ).toContain("core");
  expect(
    csv.split(/\r?\n/).find((row) => row.includes("10.0.0.9")),
  ).not.toContain("core");
  expect(fixture.policy.candidate_hash).toBe("stable-candidate");
  expect(fixture.writes).toEqual([]);
});
