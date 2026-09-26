import { randomUUID } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { CREDS } from "./utils";

const API = process.env.VITE_API_URL ?? "http://localhost:18080";
const credentials = {
  email: process.env.MIGRATION_E2E_EMAIL ?? CREDS.email,
  password: process.env.MIGRATION_E2E_PASSWORD ?? CREDS.password,
};

type Preview = {
  import_id: string;
  summary: { create: number; update: number; unchanged: number; vulnerability_profiles: number; registries: number };
  vulnerability_profiles: Array<{ name: string; diff_action: string }>;
  registries: Array<{ name: string; diff_action: string; credentials_required: boolean }>;
};

async function preview(page: Page): Promise<Preview> {
  const responsePromise = page.waitForResponse((response) => response.url().endsWith("/migration/preview") && response.request().method() === "POST");
  await page.getByTestId("migration-preview-submit").click();
  const response = await responsePromise;
  expect(response.ok()).toBe(true);
  const result = await response.json() as Preview;
  await expect(page.getByTestId("migration-import-id")).toHaveText(result.import_id);
  return result;
}

async function apply(page: Page, importId: string) {
  const responsePromise = page.waitForResponse((response) => response.url().endsWith(`/migration/imports/${importId}:apply`));
  await page.getByTestId("migration-import-apply-active").click();
  const response = await responsePromise;
  expect(response.ok()).toBe(true);
  expect((await response.json()).status).toBe("partial_applied");
  await expect(page.getByTestId("migration-import-history").locator("tbody tr").filter({ hasText: importId })).toContainText("partial applied");
}

async function rollback(page: Page, importId: string) {
  const responsePromise = page.waitForResponse((response) => response.url().endsWith(`/migration/imports/${importId}:rollback`));
  await page.getByTestId(`migration-import-rollback-${importId}`).click();
  expect((await responsePromise).ok()).toBe(true);
  await expect(page.getByTestId("migration-import-history").locator("tbody tr").filter({ hasText: importId })).toContainText("rolled back");
}

for (const inputMethod of ["paste", "upload"] as const) {
  test(`remaining NeuVector families: ${inputMethod}, partial apply, unchanged and update previews, bundle and rollback`, async ({ page }) => {
    test.setTimeout(120_000);
    const headers = { "X-Constellation-Client": "browser", Origin: new URL(API).origin };
    const loginResponse = await page.request.post(`${API}/api/v1/auth/login`, {
      data: credentials,
      headers,
    });
    expect(loginResponse.status()).toBe(200);
    expect(await loginResponse.json()).not.toHaveProperty("token");
    const suffix = randomUUID();
    const profileName = `mig-remaining-profile-${suffix}`;
    const registryName = `mig-remaining-registry-${suffix}`;
    const rejectedName = `mig-rejected-${suffix}`;
    const secret = `MIG-REDACT-${suffix}`;
    const appliedImports: string[] = [];
    const makeExport = (updated = false) => JSON.stringify({
      vulnerability_profiles: [
        { name: profileName, entries: [{ name: updated ? "CVE-2026-5678" : "CVE-2026-1234" }] },
        { name: rejectedName, entries: [{ name: "_RecentVulnWithoutFix", days: 30, domains: ["production"] }] },
      ],
      registries: [{
        name: registryName, registry_type: "Docker Registry",
        registry: "https://registry.example.test",
        username: secret, password: secret,
      }],
      tokens: [{ name: secret, value: secret }],
    });
    const loadExport = async (content: string) => {
      if (inputMethod === "upload") {
        await page.getByTestId("migration-export-upload").setInputFiles({
          name: `remaining-${suffix}.json`, mimeType: "application/json", buffer: Buffer.from(content),
        });
        await expect(page.getByTestId("migration-export-input")).toHaveValue(content);
      } else {
        await page.getByTestId("migration-export-input").fill(content);
      }
    };
    const liveRows = async () => {
      const [profilesResponse, registriesResponse] = await Promise.all([
        page.request.get(`${API}/api/v1/vuln-profiles`, { headers }),
        page.request.get(`${API}/api/v1/registries`, { headers }),
      ]);
      expect(profilesResponse.ok()).toBe(true);
      expect(registriesResponse.ok()).toBe(true);
      const profiles = (await profilesResponse.json()).profiles as Array<{ id: string; name: string; entries: Array<{ name: string; action: string }> }>;
      const registries = (await registriesResponse.json()).registries as Array<{ id: string; name: string; endpoint: string; auth_kind: string; scan_cadence: string }>;
      expect(profiles.some((profile) => profile.name === rejectedName)).toBe(false);
      return {
        profile: profiles.find((profile) => profile.name === profileName),
        registry: registries.find((registry) => registry.name === registryName),
      };
    };
    try {
      await page.goto("/settings/migration");
      await loadExport(makeExport());
      const initial = await preview(page);
      expect(initial.summary).toMatchObject({ vulnerability_profiles: 1, registries: 1, create: 2, update: 0, unchanged: 0 });
      await expect(page.getByTestId("migration-preview-vulnerability-profile")).toHaveCount(1);
      await expect(page.getByTestId("migration-preview-vulnerability-profile")).toContainText(profileName);
      await expect(page.getByTestId("migration-preview-registry")).toHaveCount(1);
      await expect(page.getByTestId("migration-preview-registries")).toContainText(/reissue/i);
      await expect(page.getByTestId("migration-preview-unsupported")).toContainText("REDACTED");
      await expect(page.getByTestId("migration-preview-result")).not.toContainText(secret);
      expect(JSON.stringify(initial)).not.toContain(secret);
      appliedImports.push(initial.import_id);
      await apply(page, initial.import_id);
      const originalRows = await liveRows();
      expect(originalRows.profile?.entries).toEqual([expect.objectContaining({ name: "CVE-2026-1234", action: "suppress" })]);
      expect(originalRows.registry).toMatchObject({ endpoint: "https://registry.example.test", auth_kind: "none", scan_cadence: "manual" });
      const repeated = await preview(page);
      expect(repeated.summary).toMatchObject({ create: 0, update: 0, unchanged: 2 });
      expect(repeated.vulnerability_profiles[0].diff_action).toBe("unchanged");
      expect(repeated.registries[0].diff_action).toBe("unchanged");
      await expect(page.getByTestId("migration-preview-vulnerability-profiles")).toContainText("unchanged");
      await expect(page.getByTestId("migration-preview-registries")).toContainText("unchanged");
      const downloadPromise = page.waitForEvent("download");
      await page.getByTestId(`migration-import-rollback-bundle-${initial.import_id}`).click();
      const download = await downloadPromise;
      expect(download.suggestedFilename()).toBe(`constellation-migration-rollback-${initial.import_id}.json`);
      const stream = await download.createReadStream();
      expect(stream).not.toBeNull();
      const chunks: Buffer[] = [];
      for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
      const bundleText = Buffer.concat(chunks).toString("utf8");
      expect(bundleText).not.toContain(secret);
      expect(JSON.parse(bundleText)).toMatchObject({ vulnerability_profiles: expect.any(Array), registries: expect.any(Array) });
      await loadExport(makeExport(true));
      const updated = await preview(page);
      expect(updated.summary).toMatchObject({ create: 0, update: 1, unchanged: 1 });
      expect(updated.vulnerability_profiles[0].diff_action).toBe("update");
      expect(updated.registries[0].diff_action).toBe("unchanged");
      expect(await liveRows()).toEqual(originalRows);
      const historyResponse = await page.request.get(`${API}/api/v1/migration/imports`, { headers });
      expect(historyResponse.ok()).toBe(true);
      expect(await historyResponse.text()).not.toContain(secret);
      await rollback(page, initial.import_id);
      expect(await liveRows()).toEqual({ profile: undefined, registry: undefined });
      await loadExport(makeExport());
      const afterRollback = await preview(page);
      expect(afterRollback.summary).toMatchObject({ create: 2, update: 0, unchanged: 0 });
      await expect(page.getByTestId("migration-import-history")).not.toContainText(/undefined|NaN/);
    } finally {
      for (const importId of appliedImports.reverse()) {
        const response = await page.request.post(`${API}/api/v1/migration/imports/${importId}:rollback`, { headers });
        expect(response.ok(), `cleanup rollback ${importId}`).toBe(true);
      }
    }
  });
}
