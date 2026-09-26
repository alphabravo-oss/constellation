import { expect, test } from "@playwright/test";

test("saved LDAP, SAML, and OIDC providers expose bounded connection checks", async ({ page }) => {
  const requests: string[] = [];
  const providers = ["ldap", "saml", "oidc"].map((type) => ({
    id: type, type, name: `${type.toUpperCase()} provider`, enabled: true, auth_order: 0,
    config: type === "ldap" ? { url: "ldaps://directory.example.test", bind_password: "[redacted]" }
      : type === "oidc" ? { issuer_url: "https://id.example.test", client_secret: "[redacted]" }
        : { entity_id: "urn:example:provider", sp_key_pem: "[redacted]" },
    role_mapping: { rules: {}, default: "Analyst" }, revision: 1,
  }));
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [] } });
    } else if (path === "/auth-servers" && request.method() === "GET") {
      await route.fulfill({ json: { auth_servers: providers } });
    } else if (/^\/auth-servers\/(ldap|saml|oidc)\/test$/.test(path)) {
      expect(request.method()).toBe("POST");
      expect(request.postData()).toBeNull();
      const type = path.split("/")[2];
      requests.push(type);
      await route.fulfill(type === "ldap"
        ? { status: 422, json: { ok: false, type, message: "connection failed" } }
        : { json: { ok: true, type } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });

  for (const type of ["ldap", "saml", "oidc"]) {
    await page.goto(`/settings/access/sso/${type}`);
    await expect(page.getByRole("heading", { name: "Edit authentication provider" })).toBeVisible();
    await expect(page.getByText("Connection test uses the last saved provider settings")).toBeVisible();
    await page.getByRole("button", { name: "Test saved connection" }).click();
    if (type === "ldap") await expect(page.getByRole("alert")).toHaveText("connection failed");
    else await expect(page.getByRole("status")).toContainText(`${type.toUpperCase()} connection passed`);
  }
  expect(requests).toEqual(["ldap", "saml", "oidc"]);
});
