import { test, expect } from "@playwright/test";
import { getAuthToken, login } from "./utils";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("Assets API exposes real continuation across bounded pages", async ({ page }) => {
  const token = await getAuthToken(page);
  const api = process.env.VITE_API_URL ?? "http://localhost:18080";
  const headers = { Authorization: `Bearer ${token}` };
  const firstResponse = await page.request.get(`${api}/api/v1/assets?limit=1&offset=0`, { headers });
  expect(firstResponse.status()).toBe(200);
  const first = await firstResponse.json();
  expect(first).toMatchObject({ limit: 1, offset: 0, has_more: true });
  expect(first.assets).toHaveLength(1);

  const secondResponse = await page.request.get(`${api}/api/v1/assets?limit=1&offset=1`, { headers });
  expect(secondResponse.status()).toBe(200);
  const second = await secondResponse.json();
  expect(second).toMatchObject({ limit: 1, offset: 1 });
  expect(second.assets).toHaveLength(1);
  expect(second.assets[0].id).not.toBe(first.assets[0].id);
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
  const created = page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname.endsWith("/image-acceptances"));
  await page.getByTestId("image-accept-submit").click();
  expect((await created).status()).toBe(201);
  await expect(page.getByTestId("image-acceptance-card")).toContainText("active");
  await expect(page.getByTestId("image-acceptance-card")).toContainText("Compensating runtime controls are active");

  const revoked = page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname.endsWith("/revoke"));
  await page.getByTestId("image-accept-revoke").click();
  expect((await revoked).status()).toBe(200);
  await expect(page.getByTestId("image-acceptance-card")).toContainText("revoked");
});
