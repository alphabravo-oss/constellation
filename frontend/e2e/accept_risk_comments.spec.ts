import { test, expect, type Page } from "@playwright/test";
import { login } from "./utils";
test.beforeEach(async ({ page }) => {
    await login(page);
});
// Select a row from the completed filtered response: the old CVE table can remain
// visible briefly while the Kind control switches to the instance view.
async function openFindingOfKind(page: Page, kind: "ml-model" | "compliance") {
    await page.goto("/findings");
    const filtered = page.waitForResponse((response) => {
        const url = new URL(response.url());
        return url.pathname === "/api/v1/findings" && url.searchParams.get("kind") === kind && response.request().method() === "GET";
    });
    await page.getByLabel("Kind").selectOption(kind);
    const response = await filtered;
    expect(response.ok()).toBeTruthy();
    const { findings } = await response.json();
    const finding = findings.find((item: {
        lifecycle: string;
    }) => item.lifecycle === "open");
    expect(finding, `seeded open ${kind} finding`).toBeTruthy();
    await page.locator("tbody tr").filter({ has: page.getByText(finding.title, { exact: true }) }).first().click();
    await expect(page).toHaveURL(url => url.pathname.endsWith(`/findings/${finding.id}`) && url.searchParams.get("first_seen_at") === finding.first_seen_at);
    return finding;
}
// Use an open ML finding untouched by the suppression tests.
test("Accept risk form records rationale + expiry", async ({ page }) => {
    const finding = await openFindingOfKind(page, "ml-model");
    await expect(page.getByRole("link", { name: /^Accept risk$/i })).toBeVisible();
    await page.getByRole("link", { name: /^Accept risk$/i }).click();
    await expect(page).toHaveURL(url => url.pathname.endsWith(`/findings/${finding.id}/accept-risk`) && url.searchParams.get("first_seen_at") === finding.first_seen_at);
    await expect(page.getByTestId("finding-action-form-page")).toBeVisible();
    await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
    await page.getByLabel(/^Reason/).fill("compensating control: vendor patch ETA 30 days");
    const expiry = new Date(Date.now() + 14 * 86400000);
    const local = new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    await page.getByLabel(/^Expiry \(local time\)/).fill(local);
    const saved = page.waitForResponse(response => response.request().method() === "POST" && /\/finding-instances\/[^/]+\/accept-risk$/.test(new URL(response.url()).pathname));
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page).toHaveURL(url => url.pathname.endsWith(`/findings/${finding.id}`) && url.searchParams.get("first_seen_at") === finding.first_seen_at);
    const acceptance = await saved;
    expect(acceptance.ok()).toBeTruthy();
    expect(new URL(acceptance.url()).searchParams.get("first_seen_at")).toBe(finding.first_seen_at);
    expect(await acceptance.json()).toMatchObject({ id: finding.id, first_seen_at: finding.first_seen_at });
    expect(acceptance.request().postDataJSON()).toMatchObject({ reviewed_revision: finding.revision, reason: "compensating control: vendor patch ETA 30 days", accepted_until: new Date(local).toISOString() });
    await expect(page.getByTestId("finding-exception-link")).toContainText("Accepted");
});
test("Comment thread accepts and renders a new comment", async ({ page }) => {
    const finding = await openFindingOfKind(page, "compliance");
    await expect(page.getByTestId("comments-section")).toBeVisible();
    const body = `e2e-test comment ${Date.now()}`;
    await page.getByRole("link", { name: "Add comment", exact: true }).click();
    await expect(page).toHaveURL(url => url.pathname.endsWith(`/findings/${finding.id}/comments/new`) && url.searchParams.get("first_seen_at") === finding.first_seen_at);
    await page.getByLabel(/^Comment/).fill(body);
    const saved = page.waitForResponse(response => response.request().method() === "POST" && new URL(response.url()).pathname === `/api/v1/finding-instances/${finding.id}/comments`);
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page).toHaveURL(url => url.pathname.endsWith(`/findings/${finding.id}`) && url.searchParams.get("first_seen_at") === finding.first_seen_at);
    const comment = await saved;
    expect(comment.ok()).toBeTruthy();
    expect(new URL(comment.url()).searchParams.get("first_seen_at")).toBe(finding.first_seen_at);
    expect(comment.request().postDataJSON()).toMatchObject({ body, reviewed_revision: finding.revision });
    await expect(page.getByTestId("comment-item").last()).toContainText(body, { timeout: 5000 });
});
