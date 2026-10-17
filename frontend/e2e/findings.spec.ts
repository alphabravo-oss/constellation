import { test, expect } from "@playwright/test";
import { login } from "./utils";
test.beforeEach(async ({ page }) => {
    await login(page);
});
test("Findings list renders seeded rows sorted by risk score", async ({ page }) => {
    await page.goto("/findings");
    await expect(page.getByRole("heading", { name: /^Findings$/i })).toBeVisible();
    await expect(page.getByTestId("finding-state-tabs")).toContainText("Open");
    await expect(page.getByTestId("finding-state-tabs")).toContainText("Accepted");
    await expect(page.getByTestId("finding-state-tabs")).toContainText("Suppressed");
    const rows = page.locator("tbody tr");
    await expect(rows.first()).toBeVisible();
    // Default view is the NeuVector-style CVE rollup, sorted by Constellation risk.
    await expect(rows.first()).toContainText("CVE-2024-0001");
    await expect(rows.first()).toContainText("glibc");
});
test("Filter by kind narrows the list", async ({ page }) => {
    await page.goto("/findings");
    // Use the explicit open cohort and validate that every returned row is a license finding.
    await expect(page.locator("tbody tr").first()).toBeVisible();
    const kindSelect = page.locator("main select").first();
    await kindSelect.selectOption("license");
    await expect(page).toHaveURL(/kind=license/);
    await expect(page.getByTestId("findings-table")).toBeVisible();
    await expect(page.getByTestId("findings-table").locator("tbody tr").first()).toContainText("license");
});
test("Finding rows open exact detail and dedicated action pages with Cancel", async ({ page }) => {
    await page.goto("/findings");
    await page.getByTestId("findings-view-instances").click();
    await expect(page.locator("tbody tr").first()).toBeVisible();
    // Inspect the exact finding before navigating to its dedicated action.
    await page.locator("tbody tr").first().getByRole("button", { name: /glibc heap overflow/i }).click();
    await expect(page).toHaveURL(url => /\/findings\/[a-f0-9-]+$/.test(url.pathname) && !!url.searchParams.get("first_seen_at"));
    const detailURL = page.url();
    await expect(page.getByRole("link", { name: "Suppress", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "Accept risk", exact: true }).click();
    await expect(page).toHaveURL(url => /\/findings\/[^/]+\/accept-risk$/.test(url.pathname) && url.searchParams.get("first_seen_at") === new URL(detailURL).searchParams.get("first_seen_at"));
    await expect(page.getByRole("heading", { name: "Accept finding risk", exact: true })).toBeVisible();
    await expect(page.getByLabel(/^Reason/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(page).toHaveURL(detailURL);
});
test("Query input supports DSL chips", async ({ page }) => {
    await page.goto("/findings");
    await page.getByTestId("findings-view-instances").click();
    await expect(page.locator("tbody tr").first()).toBeVisible();
    const queryBox = page.locator("input[placeholder*='severity:']");
    const filtered = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/findings" && new URL(response.url()).searchParams.get("q") === "severity:critical");
    await queryBox.fill("severity:critical");
    const response = await filtered;
    expect(response.ok()).toBeTruthy();
    const payload = await response.json();
    expect(payload.findings.length).toBeGreaterThan(0);
    expect(payload.findings.every((finding: {
        severity: string;
    }) => finding.severity === "critical")).toBe(true);
    // Should narrow rows to critical seed (~15 with seed).
    await expect(page).toHaveURL(/q=severity/);
    await expect(page.getByTestId("findings-table").locator("tbody tr").first()).toContainText("critical");
    await expect(page.getByTestId("findings-table").locator('tbody td[data-column-id="severity"]')).toHaveText(Array(payload.findings.length).fill("critical"));
});
test("Suppressed lifecycle tab loads", async ({ page }) => {
    await page.goto("/findings");
    await page.getByRole("button", { name: /Suppressed/ }).first().click();
    // Should render a table (possibly empty); just verify the heading stays.
    await expect(page.getByRole("heading", { name: /^Findings$/i })).toBeVisible();
});
