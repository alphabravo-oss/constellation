import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { dashboardEvidence, evidenceCluster, evidenceRoot } from "./fixtures/dashboard-evidence";

test("Dashboard downloads HTML for the selected cluster and surfaces a report-source failure", async ({ page }) => {
  await dashboardEvidence().install(page);
  let failed = false, downloads = 0;
  page.on("download", () => { downloads++; });
  await page.route("**/api/v1/reports/executive.html?**", async route => {
    expect(route.request().method()).toBe("GET");
    expect(new URL(route.request().url()).searchParams.get("cluster_id")).toBe(evidenceCluster);
    if (failed) return route.fulfill({ status: 503, json: { error: "Report source unavailable" } });
    return route.fulfill({ contentType: "text/html; charset=utf-8", headers: { "x-report-org-id": "org", "x-report-cluster-id": evidenceCluster, "content-disposition": 'attachment; filename="cluster-evidence.html"' }, body: "<!doctype html><title>Cluster evidence</title><p>Retained evidence for the selected cluster.</p>" });
  });
  await page.goto(`${evidenceRoot}/dashboard`);
  const button = page.getByRole("button", { name: "Download report (HTML)", exact: true });
  await expect(button).toBeEnabled();
  const pending = page.waitForEvent("download"); await button.click(); const download = await pending;
  expect(download.suggestedFilename()).toBe("cluster-evidence.html");
  const path = await download.path(); expect(path).not.toBeNull(); expect(await readFile(path!, "utf8")).toContain("<title>Cluster evidence</title>");
  await expect(button).toBeEnabled(); failed = true; await button.click();
  await expect(page.getByRole("alert").filter({ hasText: "Report download failed" })).toBeVisible();
  expect(downloads).toBe(1);
});
