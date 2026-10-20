import { expect, test } from "@playwright/test";
import { login } from "./utils";

const apiBase = process.env.VITE_API_URL ?? "http://localhost:18080";
const metadata = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></IDPSSODescriptor></EntityDescriptor>';

test("saved SAML metadata passes a live scoped connection check", async ({ page }) => {
  const token = await login(page);
  const authorization = { Authorization: `Bearer ${token}` };
  const created = await page.request.post(`${apiBase}/api/v1/auth-servers`, {
    headers: authorization,
    data: {
      type: "saml",
      name: `playwright-saml-${Date.now()}`,
      enabled: false,
      auth_order: 100,
      config: { idp_metadata_xml: metadata, acs_url: "https://app.example.test/acs" },
      role_mapping: { rules: {}, default: "viewer" },
    },
  });
  expect(created.status()).toBe(201);
  const provider = await created.json() as { id: string };

  try {
    await page.goto(`/settings/access/sso/${provider.id}`);
    await expect(page.getByRole("heading", { name: "Edit authentication provider" })).toBeVisible();
    await page.getByRole("button", { name: "Test saved connection" }).click();
    await expect(page.getByRole("status")).toHaveText("Saved SAML connection passed.");
  } finally {
    const removed = await page.request.delete(`${apiBase}/api/v1/auth-servers/${provider.id}`, { headers: authorization });
    expect(removed.ok()).toBeTruthy();
  }
});
