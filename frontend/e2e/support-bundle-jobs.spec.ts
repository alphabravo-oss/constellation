import { expect, test } from "@playwright/test";
import { login } from "./utils";

test("queues a persisted support bundle and downloads it when ready", async ({ page }) => {
  test.setTimeout(180_000);
  await login(page);
  await page.goto("/settings/health");
  await expect(page.getByRole("heading", { name: "System Health" })).toBeVisible();

  const createdResponse = page.waitForResponse((response) =>
    response.url().endsWith("/api/v1/support/bundle/jobs") && response.request().method() === "POST",
  );
  await page.getByTestId("system-health-support-bundle").click();
  const response = await createdResponse;
  expect(response.status()).toBe(202);
  const created = await response.json() as { id: string; status: string };
  expect(created.id).toBeTruthy();
  expect(["queued", "running", "ready"]).toContain(created.status);

  const row = page.getByTestId(`support-bundle-job-${created.id}`);
  await expect(page.getByTestId("system-health-bundle-jobs")).toBeVisible();
  await expect(row).toBeVisible({ timeout: 15_000 });

  await page.reload();
  await expect(page.getByTestId("system-health-bundle-jobs")).toBeVisible();
  await expect(row).toBeVisible({ timeout: 15_000 });
  await expect(row.getByText("ready", { exact: true })).toBeVisible({ timeout: 120_000 });

  const downloadPromise = page.waitForEvent("download");
  await page.getByTestId(`support-bundle-download-${created.id}`).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^constellation-support-bundle-.*\.json$/);
  const stream = await download.createReadStream();
  expect(stream).not.toBeNull();
  const chunks: Buffer[] = [];
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
  const bundle = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  expect(bundle.bundle_id).toBeTruthy();
  expect(bundle.redaction.applied).toBe(true);
  expect(bundle.sections).toBeTruthy();

  await row.getByRole("link", { name: "Audit history" }).click();
  await expect(page).toHaveURL(new RegExp(`/audit\\?support_bundle_job_id=${created.id}`));
  await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible();
  await expect(page.getByTestId("audit-page")).toContainText(created.id.slice(0, 12));
});
