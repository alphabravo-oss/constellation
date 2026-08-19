import { test, expect } from "@playwright/test";
import { login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Assets inventory exposes risk rollups, filters, and inspection preview", async ({ page }) => {
  await page.goto("/assets");
  await expect(page.getByTestId("assets-summary")).toContainText("Critical / High");
  await expect(page.getByTestId("assets-table")).toBeVisible();
  await expect(page.getByTestId("asset-posture-chip").first()).toBeVisible();
  await expect(page.getByTestId("asset-preview")).toContainText("Supply chain posture");
  await expect(page.getByTestId("asset-preview")).toContainText("Signature");

  await page.getByTestId("asset-kind-filter").selectOption("image");
  await page.getByTestId("asset-search").fill("ghcr.io/demo/api");
  await expect(page.getByTestId("asset-row")).toHaveCount(1);
  await expect(page.getByTestId("asset-preview")).toContainText("ghcr.io/demo/api");
  await expect(page.getByTestId("asset-preview")).toContainText("SBOMs");
});

test("Asset detail exposes image, findings, and SBOM context", async ({ page }) => {
  await page.goto("/assets");
  await expect(page.getByTestId("assets-table")).toBeVisible();
  await page.getByTestId("asset-row").filter({ hasText: "ghcr.io/demo/api" }).getByRole("link").click();
  await expect(page.getByRole("heading", { name: "ghcr.io/demo/api" })).toBeVisible();
  await expect(page.getByTestId("asset-image-card")).toContainText("ghcr.io");
  await expect(page.getByTestId("asset-findings")).toContainText("glibc heap overflow");
  await expect(page.getByTestId("asset-sbom-card")).toContainText("spdx-2.3");
  await expect(page.getByTestId("image-acceptance-card")).toContainText("none");

  const until = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  await page.getByTestId("image-accept-rationale").fill("Compensating runtime controls are active");
  await page.getByTestId("image-accept-until").fill(until);
  await page.getByTestId("image-accept-submit").click();
  await expect(page.getByTestId("image-acceptance-card")).toContainText("active");
  await expect(page.getByTestId("image-acceptance-card")).toContainText("Compensating runtime controls are active");

  await page.getByTestId("image-accept-revoke").click();
  await expect(page.getByTestId("image-acceptance-card")).toContainText("revoked");
});
